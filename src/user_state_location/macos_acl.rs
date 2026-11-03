//! Descriptor-only Darwin file-security receiving. This is not a path query.
//! The native declarations and inode64 alias follow the received target SDK.

use std::ffi::c_void;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::ptr;
use super::macos::{check_acl_entry, MacPrivateAccessPurpose};

type NativeFileSec = *mut c_void;
type NativeAcl = *mut c_void;
const FILESEC_ACL: libc::c_int = 5;

extern "C" {
    fn filesec_init() -> NativeFileSec;
    fn filesec_free(value: NativeFileSec);
    fn filesec_get_property(value: NativeFileSec, property: libc::c_int, result: *mut c_void) -> libc::c_int;
    #[cfg_attr(target_arch = "x86_64", link_name = "fstatx_np$INODE64")]
    fn fstatx_np(fd: libc::c_int, stat: *mut libc::stat, security: NativeFileSec) -> libc::c_int;
    fn acl_free(value: *mut c_void) -> libc::c_int;
    fn acl_valid(value: NativeAcl) -> libc::c_int;
    fn acl_get_entry(value: NativeAcl, which: libc::c_int, entry: *mut *mut c_void) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut libc::c_int) -> libc::c_int;
    fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> libc::c_int;
    fn acl_get_flagset_np(value: *mut c_void, flags: *mut *mut c_void) -> libc::c_int;
    fn acl_get_flag_np(flags: *mut c_void, flag: libc::c_int) -> libc::c_int;
    fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> libc::c_int;
}

struct FileSecurity(NativeFileSec);
impl Drop for FileSecurity {
    fn drop(&mut self) { unsafe { filesec_free(self.0) } }
}

/// The ACL returned by FILESEC_ACL is a separately owned native copy.
pub(super) struct ReceivedAcl(NativeAcl);
impl ReceivedAcl {
    pub(super) fn as_ptr(&self) -> NativeAcl { self.0 }
    pub(super) fn finish(mut self) -> Result<(), String> {
        let value = std::mem::replace(&mut self.0, ptr::null_mut());
        native_status("free ACL", unsafe { acl_free(value) })
    }
}
impl Drop for ReceivedAcl {
    fn drop(&mut self) {
        if !self.0.is_null() { unsafe { acl_free(self.0); } }
    }
}

// A directory's child changes can change its link count; for a regular private
// file the single-link constraint remains part of its identity admission.
fn stable_links(is_directory: bool, before: u64, after: u64) -> bool {
    is_directory || (before == 1 && after == 1)
}

fn same_descriptor(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    (before.is_dir() || before.is_file()) && before.dev() == after.dev() && before.ino() == after.ino()
        && before.mode() == after.mode() && before.uid() == after.uid()
        && stable_links(before.is_dir(), before.nlink(), after.nlink())
}

fn same_native_descriptor(before: &std::fs::Metadata, stat: &libc::stat) -> bool {
    (before.is_dir() || before.is_file()) && stat.st_dev as u64 == before.dev() && stat.st_ino == before.ino()
        && u32::from(stat.st_mode) == before.mode() && stat.st_uid == before.uid()
        && stable_links(before.is_dir(), before.nlink(), u64::from(stat.st_nlink))
}

/// Only a successful fstatx on the same object followed by FILESEC_ACL's
/// ENOENT means NoACL. In particular an fstatx failure never means absence.
pub(super) fn receive_acl(file: &File) -> Result<Option<ReceivedAcl>, String> {
    let before = file.metadata().map_err(|error| format!("state descriptor metadata: {error}"))?;
    let security = unsafe { filesec_init() };
    if security.is_null() { return Err(format!("filesec_init: {}", std::io::Error::last_os_error())); }
    let security = FileSecurity(security);
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    native_status("fstatx_np", unsafe { fstatx_np(file.as_raw_fd(), stat.as_mut_ptr(), security.0) })?;
    let stat = unsafe { stat.assume_init() };
    let after = file.metadata().map_err(|error| format!("state descriptor recheck: {error}"))?;
    if !same_descriptor(&before, &after) || !same_native_descriptor(&before, &stat) {
        return Err("state descriptor changed during file-security query".into());
    }
    let mut acl: NativeAcl = ptr::null_mut();
    let result = unsafe { filesec_get_property(security.0, FILESEC_ACL, (&mut acl as *mut NativeAcl).cast()) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) { Ok(None) }
            else { Err(format!("FILESEC_ACL: {error}")) };
    }
    if result != 0 { return Err(format!("FILESEC_ACL: unexpected status {result}")); }
    // SDK sys/fcntl.h: _FILESEC_REMOVE_ACL is the sentinel (void *)1;
    // neither it nor NULL is an owned ACL allocation.
    if acl.is_null() || acl as usize == 1 { return Err("FILESEC_ACL returned an invalid ACL on success".into()); }
    Ok(Some(ReceivedAcl(acl)))
}

fn native_error(stage: &str) -> String { format!("{stage}: {}", std::io::Error::last_os_error()) }
fn native_status(stage: &str, code: libc::c_int) -> Result<(), String> {
    match code { 0 => Ok(()), -1 => Err(native_error(stage)), _ => Err(format!("{stage}: unexpected status {code}")) }
}

fn flags_of(object: *mut c_void, known: u32) -> Result<u32, String> {
    let mut flags = ptr::null_mut();
    native_status("ACL flags", unsafe { acl_get_flagset_np(object, &mut flags) })?;
    if flags.is_null() { return Err("ACL returned a null flag set".into()); }
    // Apple Libc's public query accepts a combined mask. The received native
    // probe establishes bit-preserving complement queries, not acl_valid, as
    // the complete unknown-flag check.
    match unsafe { acl_get_flag_np(flags, (!known) as libc::c_int) } {
        0 => {}, 1 => return Err("ACL has unknown flags".into()),
        -1 => return Err(native_error("ACL unknown flags")),
        code => return Err(format!("ACL unknown flags: unexpected status {code}")),
    }
    let mut result = 0;
    for bit in (0..u32::BITS).map(|shift| 1u32 << shift).filter(|bit| known & bit != 0) {
        match unsafe { acl_get_flag_np(flags, bit as libc::c_int) } {
            0 => {}, 1 => result |= bit,
            -1 => return Err(native_error("ACL flag")),
            code => return Err(format!("ACL flag: unexpected status {code}")),
        }
    }
    Ok(result)
}

fn current_owner_uuid(uid: libc::uid_t) -> Result<[u8; 16], String> {
    // Membership mapping alone can synthesize an identity for a missing UID.
    // The reentrant account lookup makes account existence an explicit input.
    let hint = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = if hint > 0 { hint as usize } else { 1024 };
    loop {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(size).map_err(|error| format!("account lookup allocation: {error}"))?;
        buffer.resize(size, 0u8);
        let mut value = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut received = ptr::null_mut();
        let code = unsafe { libc::getpwuid_r(uid, value.as_mut_ptr(), buffer.as_mut_ptr().cast(), buffer.len(), &mut received) };
        if code == libc::ERANGE {
            size = size.checked_mul(2).ok_or("account lookup buffer overflow")?;
            continue;
        }
        if code != 0 { return Err(format!("account lookup: {}", std::io::Error::from_raw_os_error(code))); }
        if received.is_null() { return Err("current user account is unavailable".into()); }
        break;
    }
    let mut uuid = [0u8; 16];
    let code = unsafe { mbr_uid_to_uuid(uid, uuid.as_mut_ptr()) };
    if code != 0 { return Err(format!("account identity mapping: {}", std::io::Error::from_raw_os_error(code))); }
    Ok(uuid)
}

fn check_acl(acl: &ReceivedAcl, purpose: MacPrivateAccessPurpose, owner: &[u8; 16], root: Option<&[u8; 16]>) -> Result<(), String> {
    let acl = acl.as_ptr();
    native_status("ACL validity", unsafe { acl_valid(acl) })?;
    let global_flags = flags_of(acl, (1 << 0) | (1 << 17))?;
    if global_flags & 1 != 0 { return Err("ACL uses deferred inheritance".into()); }
    let mut which = 0; // ACL_FIRST_ENTRY, then ACL_NEXT_ENTRY
    loop {
        let mut entry = ptr::null_mut();
        let result = unsafe { acl_get_entry(acl, which, &mut entry) };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            // Only NEXT on an established real entry has a qualified target
            // end-of-sequence. A separately allocated empty ACL remains held.
            if which == -1 && error.raw_os_error() == Some(libc::EINVAL) { return Ok(()); }
            return Err(format!("ACL entry: {error}"));
        }
        if result != 0 { return Err(format!("ACL entry: unexpected status {result}")); }
        if entry.is_null() { return Err("ACL returned a null entry".into()); }
        let mut tag = 0;
        native_status("ACL tag", unsafe { acl_get_tag_type(entry, &mut tag) })?;
        let mut rights = 0u64;
        native_status("ACL permissions", unsafe { acl_get_permset_mask_np(entry, &mut rights) })?;
        let flags = flags_of(entry, (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8))?;
        let qualifier = unsafe { acl_get_qualifier(entry) };
        if qualifier.is_null() { return Err(native_error("ACL qualifier")); }
        let mut identity = [0u8; 16];
        unsafe { ptr::copy_nonoverlapping(qualifier.cast::<u8>(), identity.as_mut_ptr(), identity.len()); }
        let trusted = &identity == owner || root.is_some_and(|root| &identity == root);
        let evaluation = check_acl_entry(purpose, tag, trusted, rights, flags).map_err(|error| error.to_string());
        let free_result = native_status("free ACL qualifier", unsafe { acl_free(qualifier) });
        match (evaluation, free_result) {
            (Err(first), Err(free)) => return Err(format!("{first}; {free}")),
            (Err(error), _) | (_, Err(error)) => return Err(error),
            _ => {},
        }
        which = -1;
    }
}

/// Assess the opened state directory or lock, preserving identity and mode;
/// callers independently correlate the anchored directory entry before/after.
pub(crate) fn assess_private_access(file: &File, purpose: MacPrivateAccessPurpose) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| format!("private object metadata: {error}"))?;
    let uid = unsafe { libc::geteuid() };
    let namespace = purpose == MacPrivateAccessPurpose::NamespaceAncestor;
    if uid == 0 || (!namespace && metadata.uid() != uid) || (namespace && metadata.uid() != uid && metadata.uid() != 0) {
        return Err("object has an unsupported owner".into());
    }
    let mode = metadata.mode();
    match purpose {
        MacPrivateAccessPurpose::StateDirectory if !metadata.is_dir() || mode & 0o022 != 0 => return Err("unsafe state directory access".into()),
        MacPrivateAccessPurpose::WriterLock if !metadata.is_file() || metadata.nlink() != 1 || mode & 0o077 != 0 => return Err("unsafe private file access".into()),
        MacPrivateAccessPurpose::StateFile if !metadata.is_file() || metadata.nlink() != 1 || mode & 0o022 != 0 => return Err("unsafe state file access".into()),
        // A caller that accepts a trusted-owner sticky shared ancestor must also
        // bind the selected root/current-user-owned child before proceeding.
        MacPrivateAccessPurpose::NamespaceAncestor if !metadata.is_dir()
            || (mode & 0o022 != 0 && mode & 0o1000 == 0) => return Err("unsafe namespace ancestor access".into()),
        _ => {},
    }
    let result = match receive_acl(file) {
        Err(error) => Err(error),
        Ok(None) => Ok(()),
        Ok(Some(acl)) => {
            let result = current_owner_uuid(uid).and_then(|owner| {
                let root = if namespace { Some(current_owner_uuid(0)?) } else { None };
                check_acl(&acl, purpose, &owner, root.as_ref())
            });
            combine_recheck(result, acl.finish())
        }
    };
    let after = match file.metadata() {
        Ok(after) => after,
        Err(error) => return combine_recheck(result, Err(format!("private object recheck: {error}"))),
    };
    if !same_descriptor(&metadata, &after) {
        return combine_recheck(result, Err("private object changed".into()));
    }
    combine_recheck(result, Ok(()))
}

fn combine_recheck(first: Result<(), String>, recheck: Result<(), String>) -> Result<(), String> {
    match (first, recheck) {
        (Err(first), Err(later)) => Err(format!("{first}; {later}")),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{combine_recheck, same_descriptor, stable_links};

    #[test]
    fn directory_child_change_is_safe_but_regular_hardlink_is_not() {
        use std::os::unix::fs::DirBuilderExt;
        struct OwnedDir { path: std::path::PathBuf, active: bool }
        impl Drop for OwnedDir {
            fn drop(&mut self) {
                if self.active {
                    let _ = std::fs::remove_file(self.path.join("second"));
                    let _ = std::fs::remove_file(self.path.join("first"));
                    let _ = std::fs::remove_dir(&self.path);
                }
            }
        }
        let path = std::env::temp_dir().join(format!("ag-writer-object-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).expect("create exclusively owned test directory");
        let mut owned = OwnedDir { path, active: true };
        let directory = std::fs::File::open(&owned.path).expect("open owned directory");
        let before = directory.metadata().expect("directory before child");
        std::fs::write(owned.path.join("first"), b"owned fixture").expect("create owned child");
        let after = directory.metadata().expect("directory after child");
        assert!(same_descriptor(&before, &after));
        assert!(stable_links(true, 2, 3));
        let first = std::fs::File::open(owned.path.join("first")).expect("open owned regular file");
        let single = first.metadata().expect("single-link metadata");
        std::fs::hard_link(owned.path.join("first"), owned.path.join("second")).expect("create owned hardlink");
        let linked = first.metadata().expect("hardlink metadata");
        assert!(!same_descriptor(&single, &linked));
        assert!(!same_descriptor(&linked, &linked));
        std::fs::remove_file(owned.path.join("second")).expect("remove owned hardlink");
        std::fs::remove_file(owned.path.join("first")).expect("remove owned child");
        std::fs::remove_dir(&owned.path).expect("remove owned test directory");
        owned.active = false;
    }

    #[test]
    fn final_recheck_preserves_prior_assessment_and_cleanup_failure() {
        let result = combine_recheck(Err("ACL denied; free ACL failed".into()), Err("private object recheck failed".into())).unwrap_err();
        assert!(result.contains("ACL denied; free ACL failed"));
        assert!(result.contains("private object recheck failed"));
        assert!(combine_recheck(Ok(()), Err("private object recheck failed".into())).is_err());
        assert!(combine_recheck(Err("ACL denied".into()), Ok(())).is_err());
        assert!(combine_recheck(Ok(()), Ok(())).is_ok());
    }
}
