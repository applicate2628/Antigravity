use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;

// Pinning the proxy addresses into the hosts file.
//
// This is the fallback for the case NRPT cannot serve: with a VPN up, Windows
// sends the NRPT query through the tunnel no matter what the routing table says
// (see `split_route`), so the resolver answers with genuine Google addresses and
// the region gate fires again. `dns_client` gets the substituted address over
// the ISP link instead, and writing it here takes the DNS layer out of the loop
// entirely - both the Go language server and the Electron shell read this file.
//
// Only written while a tunnel is up. Without one the NRPT rules do the same job
// and stay correct as the proxy rotates addresses, which a static file does not.

const BEGIN: &str = "# AG_UNLOCKER_HOSTS_BEGIN";
const END: &str = "# AG_UNLOCKER_HOSTS_END";

#[cfg(windows)]
fn checked_hosts_path() -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "kernel32")]
    unsafe extern "system" { fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32; }
    let size = unsafe { GetSystemDirectoryW(std::ptr::null_mut(), 0) };
    if size == 0 { return Err("Windows system directory is unavailable".into()); }
    let mut path = vec![0u16; size as usize];
    let read = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), size) };
    if read == 0 || read >= size { return Err("Windows system directory changed while reading".into()); }
    let path = PathBuf::from(std::ffi::OsString::from_wide(&path[..read as usize]));
    Ok(path.join("drivers").join("etc").join("hosts"))
}

#[cfg(all(windows, test))]
pub fn hosts_path() -> PathBuf { checked_hosts_path().expect("Windows system directory") }

fn render_block(entries: &[(String, Ipv4Addr)]) -> String {
    // The markers carry the canaries: unlike the binary, this file is readable
    // on a victim machine without access to the tool that wrote it.
    let mut out = format!(
        "{} {} {}\r\n",
        BEGIN,
        crate::canary::STATIC_CANARY,
        crate::canary::RELEASE_TOKEN
    );
    for (host, ip) in entries {
        out.push_str(&format!("{} {}\r\n", ip, host));
    }
    out.push_str(END);
    out.push_str("\r\n");
    out
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Span { body: String, separator: bool }

fn marked_span(existing: &str) -> Result<Option<std::ops::Range<usize>>, String> {
    let mut offset = 0;
    let mut start = None;
    let mut complete = None;
    for line in existing.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed == BEGIN || trimmed.strip_prefix(BEGIN).is_some_and(|suffix| suffix.starts_with(' ')) {
            if start.is_some() || complete.is_some() { return Err("hosts: duplicate or nested product markers".into()); }
            start = Some(offset);
        } else if trimmed == END {
            let first = start.take().ok_or("hosts: unmatched product end marker")?;
            complete = Some(first..offset + line.len());
        } else if start.is_some() {
            let mut fields = trimmed.split_whitespace();
            if fields.next().and_then(|ip| ip.parse::<Ipv4Addr>().ok()).is_none()
                || !fields.next().is_some_and(|host| crate::dns::core_namespaces().contains(&host))
                || fields.next().is_some() {
                return Err("hosts: unrelated or malformed entry in product block".into());
            }
        }
        offset += line.len();
    }
    if start.is_some() { return Err("hosts: unmatched product begin marker".into()); }
    Ok(complete)
}

/// A marker locates bytes but never authorizes their update or removal.
fn replace_block(existing: &str, owned: Option<&Span>, block: Option<&str>) -> Result<(String, Option<Span>), String> {
    let (start, end, separator) = match (marked_span(existing)?, owned) {
        (None, None) => (existing.len(), existing.len(), !existing.is_empty() && !existing.ends_with('\n')),
        (Some(span), Some(owned)) if existing[span.clone()] == owned.body => {
            let start = if owned.separator {
                let Some(start) = span.start.checked_sub(2) else { return Err("hosts: owned separator absent".into()); };
                if existing.as_bytes().get(start..span.start) != Some(b"\r\n") {
                    return Err("hosts: owned separator changed".into());
                }
                if block.is_none() && span.end < existing.len() {
                    return Err("hosts: foreign lines now depend on the inserted separator; contents preserved".into());
                }
                start
            } else { span.start };
            (start, span.end, owned.separator)
        }
        _ => return Err("hosts: marker and durable owned postimage differ; contents preserved".into()),
    };
    let mut out = existing[..start].to_string();
    let next = block.map(|body| Span { body: body.to_owned(), separator });
    if let Some(span) = &next {
        if span.separator { out.push_str("\r\n"); }
        out.push_str(&span.body);
    }
    out.push_str(&existing[end..]);
    Ok((out, next))
}

#[cfg(windows)]
fn rewrite(writer: &crate::dns::machine_state::Writer, block: Option<&str>, check_only: bool) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Owned { identity: (u32, u32, u32), span: Span }
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pending { identity: (u32, u32, u32), before: String, after_digest: String, next: Option<Owned> }
    #[derive(Default, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Journal { owned: Option<Owned>, pending: Option<Pending> }
    fn save(writer: &crate::dns::machine_state::Writer, journal: &Journal) -> Result<(), String> {
        writer.store_hosts(&serde_json::to_vec(journal).map_err(|e| format!("hosts recovery receipt: {e}"))?,
            journal.owned.is_some() || journal.pending.is_some())
    }
    let mut journal: Journal = match writer.read_hosts()? {
        Some(raw) => serde_json::from_slice(&raw).map_err(|e| format!("hosts recovery receipt invalid: {e}"))?,
        None => Journal::default(),
    };
    let path = checked_hosts_path()?;
    let mut file = match fs::OpenOptions::new().read(true).write(true).share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && block.is_none()
            && journal.pending.is_none() && journal.owned.is_none() => return if check_only { Ok(()) }
                else { writer.clear_empty_hosts_indicator() },
        Err(error) => return Err(format!("hosts: cannot hold original for update: {error}")),
    };
    let metadata = file.metadata().map_err(|e| format!("hosts: metadata: {e}"))?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("hosts: target is not an ordinary file".into());
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 || info.nNumberOfLinks != 1 {
        return Err("hosts: held single-file identity unavailable".into());
    }
    let identity = (info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow);
    let mut existing = String::new();
    file.read_to_string(&mut existing).map_err(|e| format!("hosts: original contents unreadable: {e}"))?;
    if let Some(pending) = journal.pending.take() {
        if pending.identity != identity || (pending.before != existing
            && pending.after_digest != hex::encode(Sha256::digest(existing.as_bytes()))) {
            return Err("hosts: recovery required; current contents and protected original are preserved".into());
        }
        if pending.before != existing { journal.owned = pending.next; }
        if !check_only { save(writer, &journal)?; }
    }
    if journal.owned.as_ref().is_some_and(|owned| owned.identity != identity) {
        return Err("hosts: owned file identity changed; contents preserved".into());
    }
    let (updated, next) = replace_block(&existing, journal.owned.as_ref().map(|owned| &owned.span), block)?;
    if check_only || updated == existing {
        if !check_only && journal.owned.is_none() { writer.clear_empty_hosts_indicator()?; }
        return Ok(());
    }

    fn receive(file: &mut fs::File, bytes: &[u8]) -> std::io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(0))?;
        let mut actual = Vec::new();
        file.read_to_end(&mut actual)?;
        if actual != bytes { return Err(std::io::Error::other("hosts readback mismatch")); }
        Ok(())
    }

    let next = next.map(|span| Owned { identity, span });
    journal.pending = Some(Pending { identity, before: existing,
        after_digest: hex::encode(Sha256::digest(updated.as_bytes())), next: next.clone() });
    save(writer, &journal)?;
    if let Err(primary) = receive(&mut file, updated.as_bytes()) {
        let pending = journal.pending.take().expect("persisted hosts effect");
        return match receive(&mut file, pending.before.as_bytes()) {
            Ok(()) => match save(writer, &journal) {
                Ok(()) => Err(format!("hosts: {primary}; original bytes restored")),
                Err(receipt) => Err(format!("hosts: {primary}; original bytes restored; receipt failure: {receipt}")),
            },
            Err(rollback) => Err(format!("hosts: {primary}; original bytes could not be restored: {rollback}")),
        };
    }
    journal.owned = next;
    journal.pending = None;
    save(writer, &journal)
}

#[cfg(windows)]
pub fn write_entries(writer: &crate::dns::machine_state::Writer, entries: &[(String, Ipv4Addr)]) -> Result<(), String> {
    if entries.is_empty() {
        return remove_entries(writer);
    }
    rewrite(writer, Some(&render_block(entries)), false)
}

#[cfg(windows)]
pub fn remove_entries(writer: &crate::dns::machine_state::Writer) -> Result<(), String> {
    rewrite(writer, None, false)
}

#[cfg(windows)]
pub(crate) fn check_update(writer: &crate::dns::machine_state::Writer) -> Result<(), String> {
    rewrite(writer, None, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<(String, Ipv4Addr)> {
        vec![(
            "cloudcode-pa.googleapis.com".to_string(),
            Ipv4Addr::new(87, 228, 47, 204),
        )]
    }

    #[test]
    fn foreign_lines_survive_untouched() {
        let original = "127.0.0.1 localhost\r\n# a comment\r\n10.0.0.1 intranet\r\n";
        let (written, owned) = replace_block(original, None, Some(&render_block(&entries()))).unwrap();
        assert!(written.starts_with(original));
        assert!(written.contains("87.228.47.204 cloudcode-pa.googleapis.com"));
        assert_eq!(replace_block(&written, owned.as_ref(), None).unwrap().0, original);
    }

    #[test]
    fn rewriting_replaces_instead_of_appending() {
        let base = "127.0.0.1 localhost\r\n";
        let (once, owned) = replace_block(base, None, Some(&render_block(&entries()))).unwrap();
        let (twice, _) = replace_block(&once, owned.as_ref(), Some(&render_block(&entries()))).unwrap();
        assert_eq!(once, twice);
        assert_eq!(twice.matches(BEGIN).count(), 1);
    }

    #[test]
    fn a_file_without_a_trailing_newline_still_gets_a_clean_block() {
        let original = "127.0.0.1 localhost";
        let (written, owned) = replace_block(original, None, Some(&render_block(&entries()))).unwrap();
        assert!(written.contains("localhost\r\n# AG_UNLOCKER_HOSTS_BEGIN"));
        assert_eq!(replace_block(&written, owned.as_ref(), None).unwrap().0, original);
    }

    #[test]
    fn an_empty_file_gains_only_the_block() {
        let (written, owned) = replace_block("", None, Some(&render_block(&entries()))).unwrap();
        assert!(written.starts_with(BEGIN));
        assert_eq!(replace_block(&written, owned.as_ref(), None).unwrap().0, "");
    }

    #[test]
    fn an_unterminated_block_does_not_eat_the_rest_of_the_file() {
        let broken = format!("127.0.0.1 localhost\r\n{} x\r\n1.2.3.4 stray\r\n", BEGIN);
        assert!(replace_block(&broken, None, None).is_err());
    }

    #[test]
    fn marker_without_exact_owned_postimage_cannot_be_overwritten_or_removed() {
        let block = render_block(&entries());
        assert!(replace_block(&block, None, None).is_err());
        assert!(replace_block(&block, None, Some(&block)).is_err());
        let (written, owned) = replace_block("", None, Some(&block)).unwrap();
        let changed = written.replace("87.228.47.204", "192.0.2.53");
        assert!(replace_block(&changed, owned.as_ref(), None).is_err());
    }

    #[test]
    fn foreign_append_prevents_removing_its_line_separator() {
        let original = "127.0.0.1 localhost";
        let (mut written, owned) = replace_block(original, None, Some(&render_block(&entries()))).unwrap();
        written.push_str("192.0.2.53 foreign.invalid\r\n");
        assert!(replace_block(&written, owned.as_ref(), None).is_err());
    }

    #[test]
    fn the_block_carries_the_release_canary() {
        let block = render_block(&entries());
        assert!(block.contains(crate::canary::RELEASE_TOKEN));
        assert!(block.trim_end().ends_with(END));
    }
}
