use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::utils::powershell;
#[cfg(target_os = "windows")]
use crate::utils::{CommandOutcome, CommandObservation};

#[cfg(target_os = "windows")]
fn receive_command(outcome: &CommandOutcome, observation: CommandObservation) -> Result<(), String> {
    match observation {
        CommandObservation::Complete if outcome.complete() && outcome.releasable() && outcome.exit().is_some_and(|status| status.success()) => Ok(()),
        CommandObservation::NotStarted => Err("environment helper did not start; actual failure retained".into()),
        CommandObservation::Complete => Err("environment command failed or status is unknown; effect may be partial".into()),
        CommandObservation::Deadline => Err("environment command deadline expired; effect may be partial".into()),
        CommandObservation::Failed => Err("environment command failed; effect may be partial".into()),
        CommandObservation::Pending => Err("environment command remains pending; effect may be partial".into()),
    }
}

// Which CloudCode host the client talks to, and why that is the whole fix.
//
// The region gate lives on the CloudCode API. `cloudcode-pa.googleapis.com` was
// substituted by the unblock resolvers until they dropped it, and their proxies
// refuse it by SNI, so that host cannot be reached through a permitted region
// any more (kb/dns.md). `daily-cloudcode-pa.googleapis.com` is the *same
// service* - its 401 names `service: cloudcode-pa.googleapis.com` - it is still
// substituted by geohide.ru, and geohide's proxy accepts its SNI. So the fix is
// to send the client at the host that still has a route.
//
// Nothing here patches a binary. Each surface already has a supported way to
// choose the endpoint:
//
// - Desktop passes `--cloud_code_endpoint https://daily-cloudcode-pa...` as a
//   literal in app.asar. Already on the working host; nothing to do.
// - IDE builds the argument from `getCloudCodeUrl()`, which returns
//   `cloudCodeUrlOverride` first if the `jetski.cloudCodeUrl` setting is set,
//   and otherwise the production host for any account without GCP terms - i.e.
//   every ordinary user. That setting is what we write.
// - CLI reads the `CLOUD_CODE_URL` environment variable ("UpdateEndpointURL
//   called with CLOUD_CODE_URL: %q" in agy.exe).
//
// Being configuration rather than a patch matters twice over: an app update
// cannot silently undo it the way it undoes the binary rename (G2), and a
// revert is a key removal rather than a byte-level restore.

/// The CloudCode host that still has a substituted route.
pub const DAILY_ENDPOINT: &str = "https://daily-cloudcode-pa.googleapis.com";

/// IDE setting that overrides the CloudCode base URL.
pub const IDE_SETTING: &str = "jetski.cloudCodeUrl";

/// Environment variable the CLI reads for the same purpose.
pub const CLI_ENV_VAR: &str = "CLOUD_CODE_URL";

/// What a run did, so the caller can say it out loud rather than change the
/// user's configuration silently.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The setting was written or corrected.
    Applied,
    /// Already pointing at the right host.
    AlreadySet,
}

/// Where the IDE keeps its user settings.
///
/// Derived from `product.json` rather than hardcoded: the folder is named after
/// `nameShort`, so a rebranded or renamed build still resolves correctly.
pub fn ide_settings_path(install: &Path) -> Option<PathBuf> {
    let product = if install.join("Contents").join("Resources").join("app").join("product.json").exists() {
        install.join("Contents").join("Resources").join("app").join("product.json")
    } else {
        install.join("resources").join("app").join("product.json")
    };
    let text = fs::read_to_string(product).ok()?;
    let name = Regex::new(r#""nameShort"\s*:\s*"([^"]+)""#)
        .ok()?
        .captures(&text)?
        .get(1)?
        .as_str()
        .to_string();
    // The user-config root is `%APPDATA%` on Windows, `~/Library/Application Support` on macOS,
    // and `~/.config` on Linux - the same VS Code layout underneath (`<root>/<nameShort>/User/settings.json`).
    #[cfg(target_os = "windows")]
    let root = PathBuf::from(std::env::var("APPDATA").ok()?);
    #[cfg(target_os = "macos")]
    let root = PathBuf::from(std::env::var("HOME").ok()?).join("Library").join("Application Support");
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    let root = {
        // An empty XDG_CONFIG_HOME (elevation can pass it through blank) is "unset",
        // not a relative root - fall back to ~/.config in that case.
        match std::env::var("XDG_CONFIG_HOME") {
            Ok(xdg) if !xdg.is_empty() => PathBuf::from(xdg),
            _ => PathBuf::from(std::env::var("HOME").ok()?).join(".config"),
        }
    };
    Some(root.join(name).join("User").join("settings.json"))
}

/// Rewrites `key` to `value`, leaving every other byte of the file alone.
///
/// A settings file is JSONC - comments and trailing commas are legal - and it
/// is the user's, not ours. Parsing and re-serialising would silently drop
/// their comments and reorder their keys, so this edits the text in place, the
/// same rule `hosts_pin` follows for the hosts file.
///
/// Unused since 2.11.0 removed the endpoint override (D11); kept because it is
/// the write half of the pair `remove_key` belongs to, its eight tests are what
/// pin that JSONC discipline (I18), and restoring an override - or writing any
/// other IDE setting - would otherwise start by rewriting it from scratch.
/// Delete it if a release passes with nothing needing to write a settings key.
#[allow(dead_code)]
fn upsert_key(text: &str, key: &str, value: &str) -> Result<String, String> {
    let existing = Regex::new(&format!(r#""{}"\s*:\s*"[^"]*""#, regex::escape(key)))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    let entry = format!("\"{}\": \"{}\"", key, value);

    if existing.is_match(text) {
        return Ok(existing.replace(text, entry.as_str()).into_owned());
    }
    if text.trim().is_empty() {
        return Ok(format!("{{\n    {}\n}}\n", entry));
    }

    let cut = text
        .rfind('}')
        .ok_or_else(|| "settings.json без закрывающей скобки".to_string())?;
    let head = text[..cut].trim_end();
    let mut out = String::with_capacity(text.len() + entry.len() + 8);
    out.push_str(head);
    // An empty object needs no separator; anything else does, unless the user
    // already left a trailing comma.
    if !head.ends_with('{') && !head.ends_with(',') {
        out.push(',');
    }
    out.push_str("\n    ");
    out.push_str(&entry);
    out.push('\n');
    out.push_str(&text[cut..]);
    Ok(out)
}

/// Drops `key`, taking the separating comma with it so the file stays valid.
fn remove_key(text: &str, key: &str) -> Result<String, String> {
    let escaped = regex::escape(key);
    // As a later entry it carries a comma in front of it; as the only or first
    // entry, the comma (if any) follows.
    let trailing = Regex::new(&format!(r#",\s*"{}"\s*:\s*"[^"]*""#, escaped))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    if trailing.is_match(text) {
        return Ok(trailing.replace(text, "").into_owned());
    }
    let alone = Regex::new(&format!(r#""{}"\s*:\s*"[^"]*"\s*,?\s*"#, escaped))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    Ok(alone.replace(text, "").into_owned())
}

// `apply_ide`/`apply_cli` were deleted in 2.11.0 together with the policy they
// served: the client is no longer pushed onto `daily-cloudcode-pa`, because the
// host it picks for itself is routed now (see `main::process_install`). The two
// `remove_*` below stay, and are called from menu 1 as well as the undo paths -
// a machine patched by an earlier build still carries the override, and nothing
// else would ever take it back off.

/// Takes our override back out of the IDE's settings.
///
/// Scoped to **our** value, the same rule `remove_cli` follows. Before 2.11.0
/// this stripped the key whatever it held, which was harmless while only we ever
/// wrote it; now that menu 1 calls it on every run, a user who points
/// `jetski.cloudCodeUrl` somewhere themselves would have it silently deleted on
/// the next patch. Deleting somebody's own configuration is the worse of the two
/// failures (G20), so a value we did not write is left alone.
pub fn remove_ide(install: &Path) -> Result<(), String> {
    let Some(path) = ide_settings_path(install) else {
        return Ok(());
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(());
    };
    if !text.contains(DAILY_ENDPOINT) {
        return Ok(());
    }
    let updated = remove_key(&text, IDE_SETTING)?;
    fs::write(&path, updated).map_err(|e| format!("не записать {}: {}", path.display(), e))
}

/// Removes the variable, but only when it still holds the value we wrote: a
/// user (or another tool) may have pointed it somewhere themselves.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn remove_cli() -> Result<(), String> {
    if current_cli_endpoint().as_deref() != Some(DAILY_ENDPOINT) {
        return Ok(());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn remove_cli() -> Result<(), String> {
    let (home, _guard) = crate::instances::acquire_proxy_environment_writer()?;
    let live = mac_launch_value(CLI_ENV_VAR)?;
    let mut receipt = MacEnvironmentReceipt::default();
    let owns = |value: &str| value == DAILY_ENDPOINT;
    let profiles = mac_profile_preflight(&home, CLI_ENV_VAR, None, owns, &mut receipt)?;
    if live.as_deref() == Some(DAILY_ENDPOINT) {
        if !receipt.record_launch_write(mac_write_launch_value(CLI_ENV_VAR, Some(DAILY_ENDPOINT), None, || Ok(()))) {
            return receipt.finish().map(|_| ());
        }
    }
    mac_publish_profiles(&home, profiles, || Ok(()), || Ok(()), &mut receipt);
    receipt.finish().map(|_| ())
}

#[cfg(target_os = "windows")]
pub fn remove_cli(owner: &mut CommandOutcome) -> Result<(), String> {
    if current_cli_endpoint(owner)?.as_deref() != Some(DAILY_ENDPOINT) { return Ok(()); }
    let script = format!("[Environment]::SetEnvironmentVariable('{}',$null,'User')", CLI_ENV_VAR);
    let receipt = powershell(owner, &script);
    receive_command(owner, receipt)?;
    drop(std::mem::take(owner));
    Ok(())
}

/// The variable that points the language server at the local gate proxy.
///
/// **Not** `HTTPS_PROXY`. It is a private name that only the patched binaries
/// read, because `patch_binary` renames the lower-case literal in their
/// `httpproxy.getEnvAny("HTTPS_PROXY", "https_proxy")` to exactly this. The full
/// argument is on `patch_binary::PROXY_VAR_NEW`; the short version is that the
/// variable has to be user-wide (nothing spawns the language server for us) and
/// a user-wide `HTTPS_PROXY` put every program on the machine through
/// `127.0.0.1:53129`. Same reach for the language server, no reach at all for
/// anything else.
pub const PROXY_ENV_VAR: &str = crate::patch_binary::PROXY_VAR_NEW;

/// What builds up to `2.11.0_4` wrote into the User environment, and what every
/// machine upgrading from one still carries. Windows and Linux remove known
/// legacy values through `remove_legacy_proxy_env` (I45).
///
/// `HTTPS_PROXY` doubles as the name a *user's own* proxy lives under, which is
/// why removal is value-scoped and why `foreign_proxy` still reads it.
pub const LEGACY_PROXY_ENV_VAR: &str = "HTTPS_PROXY";
pub const NO_PROXY_ENV_VAR: &str = "NO_PROXY";
/// Node keeps its own bundled trust store and does not read the Windows one, so
/// installing the CA as a system root is not enough: Antigravity's extension
/// host is Node, it calls the gate host itself, and it answered `self signed
/// certificate in certificate chain` until this was set. Points at the same
/// per-machine CA that is already in the user's root store, so it widens nothing
/// that was not already trusted.
pub const NODE_CA_ENV_VAR: &str = "NODE_EXTRA_CA_CERTS";
/// The companion `NO_PROXY` those builds wrote, kept only so the value can be
/// recognised as ours and taken back off.
///
/// Nothing writes it any more, and nothing needs to: `httpproxy.useProxy`
/// bypasses `localhost` and every loopback address unconditionally, in the
/// library, so the one thing this value protected - the language server's own
/// gRPC on `127.0.0.1` - was never at risk. It existed for the Node side, which
/// only ever saw it because the variable was user-wide.
const NO_PROXY_VALUE: &str = "127.0.0.1,localhost,::1";

/// Points the patched language server at the local proxy.
///
/// Still a user-wide variable - the language server is launched by the IDE, not
/// by us, so there is no parent process to inject an environment into, and
/// Windows has no per-image environment. What changed in `2.11.0_5` is the
/// *name*: `PROXY_ENV_VAR` is read by nothing but the binaries this tool has
/// patched, so the breadth that used to be the cost of the design is gone. A
/// leftover from the old scheme is taken off in the same step, since a machine
/// upgrading passes through here and through no undo path.
#[cfg(target_os = "windows")]
pub fn apply_proxy(owner: &mut CommandOutcome, url: &str, ca_path: &str) -> Result<Outcome, String> {
    let migrated = remove_legacy_proxy_env(owner, url)?;
    if current_env(owner, PROXY_ENV_VAR)?.as_deref() == Some(url) {
        return Ok(if migrated {
            Outcome::Applied
        } else {
            Outcome::AlreadySet
        });
    }
    set_env(owner, PROXY_ENV_VAR, Some(url))?;
    // The relay route terminates no TLS and installs no CA, so it needs no
    // `NODE_EXTRA_CA_CERTS`; only the legacy carrier route passes a real path.
    if !ca_path.is_empty() {
        set_env(owner, NODE_CA_ENV_VAR, Some(ca_path))?;
    }
    Ok(Outcome::Applied)
}

/// Takes the user-wide `HTTPS_PROXY`/`NO_PROXY` of builds up to `2.11.0_4` back
/// off, and only when the values are the ones this tool wrote.
///
/// This is the migration that has to happen on *every* path a machine can take
/// out of an old build: menu 1 (via `apply_proxy`), the relay's
/// `ensure_proxy_env`, and both undo paths. Skipping it would leave the exact
/// state the owner asked to be rid of - and, worse, one naming a port that the
/// new scheme still binds, so it would keep silently working and nobody would
/// notice the whole machine was still routed through loopback.
///
/// `Ok(true)` when something came off. A value that is not ours is never
/// touched: `HTTPS_PROXY` is also where a user's own proxy lives (I45).
#[cfg(target_os = "windows")]
pub fn remove_legacy_proxy_env(owner: &mut CommandOutcome, url: &str) -> Result<bool, String> {
    let proxy = current_env(owner, LEGACY_PROXY_ENV_VAR)?;
    let no_proxy = current_env(owner, NO_PROXY_ENV_VAR)?;
    let (drop_proxy, drop_no_proxy) = legacy_removals(
        proxy.as_deref(),
        no_proxy.as_deref(),
        url,
    );
    let mut removed = false;
    if drop_proxy {
        set_env(owner, LEGACY_PROXY_ENV_VAR, None)?;
        removed = true;
    }
    if drop_no_proxy {
        set_env(owner, NO_PROXY_ENV_VAR, None)?;
        removed = true;
    }
    Ok(removed)
}

/// Which of the two legacy variables this tool may take off, given what they
/// currently hold. Pure, so the one rule that can destroy a user's configuration
/// is testable without an environment.
///
/// `NO_PROXY` goes **only alongside** ours, and that condition is the whole
/// safety of this step. It carries no address to recognise, so the only evidence
/// it is ours is the exact value - and `127.0.0.1,localhost,::1` is an entirely
/// ordinary thing for someone to set for themselves. Since `_5` this runs on the
/// *patch* path and at every relay start, not only on an undo, so an
/// unconditional match would delete that user's variable, and delete it again
/// after every reboot they re-set it. Our `HTTPS_PROXY` sitting beside it is the
/// evidence that the pair was written by an older build of this tool.
fn legacy_removals(https: Option<&str>, no_proxy: Option<&str>, url: &str) -> (bool, bool) {
    let drop_proxy = https.is_some_and(|v| is_ours_on_any_port(v, url));
    (drop_proxy, drop_proxy && no_proxy == Some(NO_PROXY_VALUE))
}

/// macOS leaves the standard proxy environment under the user's control.
#[cfg(target_os = "macos")]
pub fn remove_legacy_proxy_env(_url: &str) -> Result<bool, String> {
    Ok(false)
}

/// Linux keeps the persistent half in the drop-in file, which `apply_proxy`
/// rewrites in place - so upgrading drops the old names from the next session by
/// itself. What survives is the *running* user manager, which an older build
/// filled with `systemctl --user set-environment`, and which would otherwise keep
/// the whole session pointed at loopback until the user logs out.
///
/// Value-scoped, unlike the blanket unset `remove_proxy` does: this runs on the
/// patch path, where a `https_proxy` the user exported for themselves is none of
/// our business.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn remove_legacy_proxy_env(url: &str) -> Result<bool, String> {
    use std::process::Command;
    let Ok(out) = Command::new("systemctl")
        .args(["--user", "show-environment"])
        .output()
    else {
        return Ok(false);
    };
    let env = String::from_utf8_lossy(&out.stdout);
    let mut removed = false;
    for name in [
        LEGACY_PROXY_ENV_VAR,
        "https_proxy",
        NO_PROXY_ENV_VAR,
        "no_proxy",
    ] {
        let prefix = format!("{}=", name);
        let Some(value) = env
            .lines()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .map(str::trim)
        else {
            continue;
        };
        // `NO_PROXY` only once one of ours has already been recognised, for the
        // reason spelled out in the Windows arm: the value is a plausible thing
        // for a user to have set. The proxy names come first in the list, so
        // `removed` is already decided by the time it is reached.
        let ours = if name.eq_ignore_ascii_case(NO_PROXY_ENV_VAR) {
            removed && value == NO_PROXY_VALUE
        } else {
            is_ours_on_any_port(value, url)
        };
        if !ours {
            continue;
        }
        // `.success()`, not `.is_ok()`: the latter is true for any process that
        // merely started, so a failed unset would be reported as a removal.
        if Command::new("systemctl")
            .args(["--user", "unset-environment", name])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            removed = true;
        }
    }
    Ok(removed)
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MacProxyAction { Enable, Disable, Relay, Watchdog, Foreign }

#[cfg(any(target_os = "macos", test))]
fn mac_private_proxy(value: &str) -> bool {
    value.rsplit_once(':').and_then(|(_, port)| port.parse::<u16>().ok())
        .is_some_and(|port| port != 0 && crate::proxy::url_at(port) == value)
}

#[cfg(test)]
fn mac_profile_replacement(bytes: &[u8], wanted: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    mac_managed_profile_replacement(bytes, PROXY_ENV_VAR, wanted, mac_private_proxy)
}

#[cfg(any(target_os = "macos", test))]
fn mac_managed_profile_replacement(bytes: &[u8], name: &str, wanted: Option<&str>, owned_value: impl Fn(&str) -> bool)
    -> Result<Option<Vec<u8>>, String>
{
    let start_marker = format!("# [{name}_START]");
    // Records that the one preceding LF was added to an unterminated line.
    let joined_marker = format!("# [{name}_START_JOIN_LF]");
    let end_marker = format!("# [{name}_END]");
    let prefix = format!("export {name}=\"");
    let reserved_markers = [format!("{name}_START"), format!("{name}_END")];

    let mut lines = bytes.split_inclusive(|byte| *byte == b'\n');
    let bare_len = |line: &[u8]| {
        if line.ends_with(b"\r\n") { line.len() - 2 }
        else if line.ends_with(b"\n") { line.len() - 1 } else { line.len() }
    };
    let mut position = 0;
    let mut owned = None;
    while let Some(line) = lines.next() {
        let start = position;
        position += line.len();
        let marker = &line[..bare_len(line)];
        if marker == start_marker.as_bytes() || marker == joined_marker.as_bytes() {
            if owned.is_some() { return Err(format!("повторный блок {name}")); }
            let export = lines.next().ok_or_else(|| format!("незавершённый блок {name}"))?;
            let close = lines.next().ok_or_else(|| format!("незавершённый блок {name}"))?;
            let export_end = bare_len(export);
            let value = export[..export_end].strip_prefix(prefix.as_bytes()).and_then(|value| value.strip_suffix(b"\""))
                .and_then(|value| std::str::from_utf8(value).ok()).filter(|value| owned_value(value))
                .ok_or_else(|| format!("содержимое блока {name} не принадлежит программе"))?;
            if &close[..bare_len(close)] != end_marker.as_bytes() || !close.ends_with(b"\n") {
                return Err(format!("неверная граница блока {name}"));
            }
            position += export.len() + close.len();
            let joined = marker == joined_marker.as_bytes();
            if joined && (start < 2 || bytes[start - 2] == b'\n' || position != bytes.len()) {
                return Err(format!("не подтверждён добавленный разделитель {name}"));
            }
            owned = Some((start - usize::from(joined), position, joined, value));
        } else if marker.trim_ascii_start().starts_with(b"#") {
            if reserved_markers.iter().any(|tag| marker.windows(tag.len()).any(|part| part == tag.as_bytes())) {
                return Err(format!("неподтверждённая отметка блока {name}"));
            }
        } else if marker.windows(name.len()).enumerate().any(|(at, part)| {
            if part != name.as_bytes() { return false; }
            if at != 0 && (marker[at - 1].is_ascii_alphanumeric() || matches!(marker[at - 1], b'_' | b'$')) { return false; }
            let tail = marker[at + name.len()..].trim_ascii_start();
            tail.starts_with(b"=") || tail.starts_with(b"+=") || tail.starts_with(b"[")
        }) {
            return Err(format!("стороннее присваивание {name} вне управляемого блока"));
        }
    }

    if owned.map(|(_, _, _, value)| value) == wanted { return Ok(None); }
    let (start, end, joined) = owned.map(|(start, end, joined, _)| (start, end, joined))
        .unwrap_or((bytes.len(), bytes.len(), !bytes.is_empty() && !bytes.ends_with(b"\n")));
    let mut replacement = bytes[..start].to_vec();
    if let Some(value) = wanted {
        if !owned_value(value) { return Err(format!("неверное значение {name}")); }
        if joined { replacement.push(b'\n'); }
        replacement.extend(if joined { joined_marker.as_bytes() } else { start_marker.as_bytes() });
        replacement.push(b'\n');
        replacement.extend(prefix.as_bytes());
        replacement.extend(value.as_bytes());
        replacement.extend(b"\"\n");
        replacement.extend(end_marker.as_bytes());
        replacement.push(b'\n');
    }
    replacement.extend(&bytes[end..]);
    Ok(Some(replacement))
}

#[cfg(target_os = "macos")]
fn mac_proxy_check_cancel(cancel: Option<&std::sync::atomic::AtomicBool>) -> Result<(), String> {
    if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst)) {
        return Err("Изменение локального прокси отменено.".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn mac_proxy_wish(settings: &crate::settings::Settings) -> Result<Option<bool>, String> {
    use crate::settings::TransportWish::{Inactive, Set, Unspecified};
    Ok(match settings.checked_transport_effects()?.local_proxy {
        Set(value) => Some(value),
        Inactive | Unspecified => None,
    })
}

#[cfg(target_os = "macos")]
fn mac_saved_proxy_intent(cancel: Option<&std::sync::atomic::AtomicBool>) -> Result<Option<bool>, String> {
    mac_proxy_check_cancel(cancel)?;
    match crate::settings::read() {
        crate::settings::Read::Parsed(settings) => mac_proxy_wish(&settings),
        crate::settings::Read::Missing => Ok(None),
        _ => Err("Сохранённая настройка локального прокси не подтверждена.".into()),
    }
}

#[cfg(target_os = "macos")]
fn mac_launch_value(name: &str) -> Result<Option<String>, String> {
    let output = std::process::Command::new("/bin/launchctl").args(["getenv", name])
        .output().map_err(|error| format!("launchctl getenv: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!("launchctl getenv: {}", output.status));
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|error| format!("launchctl getenv: {error}"))?;
    let value = text.strip_suffix('\n').unwrap_or(text);
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

#[cfg(target_os = "macos")]
pub(crate) fn checked_mac_foreign_proxy(ours: &str) -> Result<bool, String> {
    let mut foreign = false;
    for name in [LEGACY_PROXY_ENV_VAR, "https_proxy"] {
        let live = mac_launch_value(name).map_err(|error| format!("{name}: {error}"))?;
        foreign |= live.as_deref().is_some_and(|value| !value.trim().is_empty() && !is_our_proxy_value(value, ours));
        if let Some(value) = std::env::var_os(name) {
            foreign |= value.to_str().is_none_or(|value| !value.trim().is_empty() && !is_our_proxy_value(value, ours));
        }
    }
    Ok(foreign || antigravity_proxy_setting(ours).is_some())
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug)]
enum MacLaunchWriteFailure { Rejected(String), Unconfirmed(String) }

#[cfg(any(target_os = "macos", test))]
impl MacLaunchWriteFailure {
    fn detail(&self) -> &str {
        match self { Self::Rejected(error) | Self::Unconfirmed(error) => error }
    }
}

#[cfg(any(target_os = "macos", test))]
fn mac_checked_launch_write(before: Option<&str>, wanted: Option<&str>,
    mut read: impl FnMut() -> Result<Option<String>, String>, recheck: impl FnOnce() -> Result<(), String>,
    write: impl FnOnce() -> Result<(), String>) -> Result<bool, MacLaunchWriteFailure>
{
    use MacLaunchWriteFailure::{Rejected, Unconfirmed};
    if read().map_err(Rejected)?.as_deref() != before { return Err(Rejected("окружение launchd изменилось".into())); }
    recheck().map_err(Rejected)?;
    if before == wanted { return Ok(false); }
    write().map_err(Rejected)?;
    if read().map_err(Unconfirmed)?.as_deref() != wanted {
        return Err(Unconfirmed("новое окружение launchd не совпадает с запрошенным".into()));
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn mac_write_launch_value(name: &str, before: Option<&str>, wanted: Option<&str>, recheck: impl FnOnce() -> Result<(), String>)
    -> Result<bool, MacLaunchWriteFailure>
{
    mac_checked_launch_write(before, wanted, || mac_launch_value(name), recheck, || {
        let mut command = std::process::Command::new("/bin/launchctl");
        if let Some(value) = wanted { command.args(["setenv", name, value]); }
        else { command.args(["unsetenv", name]); }
        let output = command.output().map_err(|error| format!("изменение среды launchd: {error}"))?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(format!("изменение среды launchd: {}", output.status));
        }
        Ok(())
    })
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacEnvironmentReceipt {
    changed: Vec<&'static str>,
    errors: Vec<String>,
    launchd_unconfirmed: bool,
}

#[cfg(target_os = "macos")]
impl MacEnvironmentReceipt {
    fn record(&mut self, surface: &'static str, result: Result<bool, String>) {
        match result {
            Ok(true) => self.changed.push(surface),
            Ok(false) => {},
            Err(error) => self.errors.push(format!("{surface}: {error}")),
        }
    }

    fn note_launch_write(&mut self, result: &Result<bool, MacLaunchWriteFailure>) {
        match result {
            Ok(true) => self.changed.push("launchd"),
            Err(MacLaunchWriteFailure::Unconfirmed(_)) => self.launchd_unconfirmed = true,
            _ => {},
        }
    }

    fn record_launch_write(&mut self, result: Result<bool, MacLaunchWriteFailure>) -> bool {
        self.note_launch_write(&result);
        if let Err(error) = result {
            self.record("launchd", Err(error.detail().into()));
            false
        } else { true }
    }

    fn finish(mut self) -> Result<bool, String> {
        if self.launchd_unconfirmed {
            self.errors.push("Команда launchd выполнена; изменение могло произойти, итоговое значение не подтверждено.".into());
        }
        if self.errors.is_empty() { return Ok(!self.changed.is_empty()); }
        if !self.changed.is_empty() {
            self.errors.push(format!("Изменены и проверены: {}", self.changed.join(", ")));
        }
        Err(self.errors.join("; "))
    }
}

#[cfg(target_os = "macos")]
const MAC_SHELL_PROFILES: [(&str, &str); 2] = [
    (".zprofile", ".zprofile.agunlocker-stage"), (".zshrc", ".zshrc.agunlocker-stage"),
];

#[cfg(target_os = "macos")]
struct MacProfileEdit { before: Option<Vec<u8>>, replacement: Vec<u8> }

#[cfg(target_os = "macos")]
impl MacProfileEdit {
    fn checked_replacement(self, current: Option<&[u8]>) -> Result<Option<Vec<u8>>, String> {
        if self.before.as_deref() == current { Ok(Some(self.replacement)) }
        else { Err("профиль изменился после начальной проверки".into()) }
    }
}

#[cfg(target_os = "macos")]
fn mac_profile_preflight(home: &Path, variable: &str, wanted: Option<&str>, owned_value: impl Fn(&str) -> bool,
    receipt: &mut MacEnvironmentReceipt) -> Result<[Option<MacProfileEdit>; 2], String>
{
    let mut edits = [None, None];
    for (index, (name, stage)) in MAC_SHELL_PROFILES.into_iter().enumerate() {
        let mut conflict = None;
        crate::background::edit_owned_macos_file(home, name, stage, false, |bytes| {
            if bytes.is_none() && (index != 0 || wanted.is_none()) { return Ok(None); }
            match mac_managed_profile_replacement(bytes.unwrap_or_default(), variable, wanted, &owned_value) {
                Ok(Some(replacement)) => edits[index] = Some(MacProfileEdit { before: bytes.map(<[u8]>::to_vec), replacement }),
                Ok(None) => {},
                Err(error) => conflict = Some(error),
            }
            Ok(None)
        }, || Ok(()), || Ok(())).map_err(|error| format!("{name}: {error}"))?;
        if let Some(error) = conflict { receipt.record(name, Err(error)); }
    }
    Ok(edits)
}

#[cfg(target_os = "macos")]
fn mac_publish_profiles(home: &Path, edits: [Option<MacProfileEdit>; 2],
    recheck: impl Fn() -> Result<(), String>, finish: impl FnOnce() -> Result<(), String>,
    receipt: &mut MacEnvironmentReceipt)
{
    let [profile, rc] = edits;
    let mut zshrc = false;
    let next = || {
        let (name, stage) = MAC_SHELL_PROFILES[1];
        if let Some(edit) = rc {
            zshrc = crate::background::edit_owned_macos_file(home, name, stage, true,
                |bytes| edit.checked_replacement(bytes), &recheck, finish)
                .map_err(|error| format!("{name}: {error}"))?;
            Ok(())
        } else { finish() }
    };
    let (name, stage) = MAC_SHELL_PROFILES[0];
    if let Some(edit) = profile {
        receipt.record(name, crate::background::edit_owned_macos_file(home, name, stage, true,
            |bytes| edit.checked_replacement(bytes), &recheck, next));
    } else if let Err(error) = next() { receipt.errors.push(error); }
    receipt.record(MAC_SHELL_PROFILES[1].0, Ok(zshrc));
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(crate) enum MacProxyFailure { LegacyUnbound, Failed(String) }

#[cfg(target_os = "macos")]
impl std::fmt::Display for MacProxyFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LegacyUnbound => formatter.write_str("Каталог настроек прежней службы не подтверждён; её окружение сохранено."),
            Self::Failed(error) => formatter.write_str(error),
        }
    }
}

#[cfg(target_os = "macos")]
impl From<String> for MacProxyFailure {
    fn from(error: String) -> Self { Self::Failed(error) }
}

#[cfg(target_os = "macos")]
impl From<&str> for MacProxyFailure {
    fn from(error: &str) -> Self { Self::Failed(error.into()) }
}

#[cfg(target_os = "macos")]
pub(crate) fn reconcile_mac_proxy(action: MacProxyAction, cancel: Option<&std::sync::atomic::AtomicBool>)
    -> Result<bool, String>
{
    attempt_mac_proxy(action, cancel).map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
pub(crate) fn attempt_mac_proxy(action: MacProxyAction, cancel: Option<&std::sync::atomic::AtomicBool>)
    -> Result<bool, MacProxyFailure>
{
    use crate::background::ProxyEnvironmentProfile::LegacyUnbound;
    use MacProxyAction::{Disable, Enable, Foreign, Relay, Watchdog};

    mac_proxy_check_cancel(cancel)?;
    let (home, _guard) = crate::instances::acquire_proxy_environment_writer()?;
    let Some(saved) = mac_saved_proxy_intent(cancel)? else {
        return if matches!(action, Enable | Disable) { Err("Сохранённый выбор локального прокси отсутствует.".into()) }
            else { Ok(false) };
    };
    if (action == Enable && !saved) || (action == Disable && saved) {
        return Err("Сохранённая настройка локального прокси изменилась.".into());
    }
    let port = crate::proxy::port();
    let url = crate::proxy::url_at(port);
    let foreign = (action == Foreign || (saved && matches!(action, Enable | Relay))) && checked_mac_foreign_proxy(&url)?;
    if action == Foreign && !foreign { return Err("Сторонний прокси больше не подтверждён.".into()); }
    let enabling = saved && matches!(action, Enable | Relay) && !foreign;
    if enabling && (port == 0 || !crate::background::owned_proxy_listener_at(port)?) {
        return if action == Relay { Ok(false) } else { Err("Локальный прокси не отвечает.".into()) };
    }
    let wanted = enabling.then_some(url.as_str());
    let mut receipt = MacEnvironmentReceipt::default();
    let live = mac_launch_value(PROXY_ENV_VAR)?;
    let edits = mac_profile_preflight(&home, PROXY_ENV_VAR, wanted, mac_private_proxy, &mut receipt)?;
    let live_owned = live.as_deref().is_some_and(mac_private_proxy);
    if live.is_some() && !live_owned {
        receipt.record("launchd", Err("Стороннее значение AG_LS_PROXY сохранено.".into()));
    }
    if enabling && !receipt.errors.is_empty() { return receipt.finish().map_err(Into::into); }
    if !enabling && !live_owned && edits.iter().all(Option::is_none) {
        if action == Enable && foreign { receipt.errors.push("В системе задан свой прокси; выбор сохранён.".into()); }
        return receipt.finish().map_err(Into::into);
    }
    if !enabling && crate::background::check_proxy_environment_profile(&home)? == LegacyUnbound {
        return Err(MacProxyFailure::LegacyUnbound);
    }
    if action == Watchdog && saved && crate::proxy::checked_listener_answers()? { return Ok(false); }
    let recheck = || -> Result<(), String> {
        if mac_saved_proxy_intent(cancel)? != Some(saved) { return Err("Сохранённая настройка локального прокси изменилась.".into()); }
        if enabling && (crate::proxy::port() != port || !crate::background::owned_proxy_listener_at(port)?) {
            return Err("Слушатель локального прокси изменился.".into());
        }
        if action == Watchdog && saved && crate::proxy::checked_listener_answers()? {
            return Err("Слушатель локального прокси восстановлен.".into());
        }
        if !enabling && crate::background::check_proxy_environment_profile(&home)? == LegacyUnbound {
            return Err(MacProxyFailure::LegacyUnbound.to_string());
        }
        if (enabling || foreign) && checked_mac_foreign_proxy(&url)? != foreign {
            return Err("Сторонняя настройка прокси изменилась; изменение остановлено.".into());
        }
        Ok(())
    };
    if !enabling && live_owned {
        if !receipt.record_launch_write(mac_write_launch_value(PROXY_ENV_VAR, live.as_deref(), None, recheck)) {
            return receipt.finish().map_err(Into::into);
        }
    }
    let mut launch_write = None;
    mac_publish_profiles(&home, edits, recheck, || {
        if enabling {
            let result = mac_write_launch_value(PROXY_ENV_VAR, live.as_deref(), wanted, recheck);
            let error = result.as_ref().err().map(|error| format!("launchd: {}", error.detail()));
            launch_write = Some(result);
            if let Some(error) = error { return Err(error); }
        } else {
            recheck()?;
            let expected = live.as_deref().filter(|_| !live_owned);
            if mac_launch_value(PROXY_ENV_VAR)?.as_deref() != expected {
                return Err("launchd: среда локального прокси изменилась".into());
            }
        }
        Ok(())
    }, &mut receipt);
    if let Some(result) = &launch_write { receipt.note_launch_write(result); }
    if action == Enable && foreign { receipt.errors.push("В системе задан свой прокси; выбор сохранён.".into()); }
    receipt.finish().map_err(Into::into)
}

/// The Linux path uses **two** mechanisms so the language server the IDE spawns
/// sees the proxy: a `~/.config/environment.d` drop-in makes it survive a reboot,
/// and `systemctl --user set-environment` sets it in the running user manager, so
/// a freshly-launched app inherits it **without a full re-login** - the user only
/// has to quit and reopen Antigravity.
///
/// Both carry `PROXY_ENV_VAR` and nothing else now. The drop-in used to export
/// `HTTPS_PROXY`/`https_proxy`/`NO_PROXY`/`no_proxy`, which is session-wide on
/// Linux exactly as the User environment is machine-wide on Windows - every
/// shell, every `curl`, every package manager through `127.0.0.1:53129`. The
/// private name reaches the patched binaries and nothing else; rewriting the
/// file in place is also what retires the old names on an upgrade.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn apply_proxy(url: &str, _ca_path: &str) -> Result<Outcome, String> {
    use std::process::Command;
    let path = environment_d_path()?;
    let body = format!(
        "# Antigravity Unlocker — гейт-хосты через локальный прокси. Переменную\n\
         # читает только пропатченный language server. Удалите файл, чтобы\n\
         # отключить.\n\
         {k}={u}\n",
        k = PROXY_ENV_VAR,
        u = url,
    );
    let already = fs::read_to_string(&path).ok().as_deref() == Some(body.as_str());
    let migrated = remove_legacy_proxy_env(url).unwrap_or(false);
    if already && !migrated {
        return Ok(Outcome::AlreadySet);
    }
    if !already {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
        }
        fs::write(&path, &body).map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    }
    // Immediate effect for newly-launched apps in this session (best-effort).
    Command::new("systemctl")
        .args([
            "--user",
            "set-environment",
            &format!("{}={}", PROXY_ENV_VAR, url),
        ])
        .status()
        .ok();
    Ok(Outcome::Applied)
}

/// `~/.config/environment.d/ag-unlocker.conf`, honouring `XDG_CONFIG_HOME`.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn environment_d_path() -> Result<PathBuf, String> {
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.is_empty() => PathBuf::from(x),
        _ => PathBuf::from(std::env::var("HOME").map_err(|_| "HOME не задан".to_string())?)
            .join(".config"),
    };
    Ok(base.join("environment.d").join("ag-unlocker.conf"))
}

/// Removes them, but only while they still hold what we wrote - a user may have
/// a proxy of their own, and taking that away would be worse than any bug here.
#[cfg(target_os = "windows")]
pub fn remove_proxy(owner: &mut CommandOutcome, url: &str, ca_path: &str) -> Result<(), String> {
    // Preserve the first uncertain effect and stop dependent mutations until
    // the containing owner has received the outcome.

    // Unconditional, unlike everything else here: `PROXY_ENV_VAR` is a name only
    // this tool ever writes, so any value under it is ours whatever port it
    // names. That matters for the day the listener moves off 53129 (P26) - a
    // value-scoped removal would leave the old one behind forever.
    if current_env(owner, PROXY_ENV_VAR)?.is_some() {
        set_env(owner, PROXY_ENV_VAR, None)?;
    }
    // The user-wide variables of builds up to `2.11.0_4`, value-scoped because
    // `HTTPS_PROXY` is also where a user's own proxy lives.
    remove_legacy_proxy_env(owner, url)?;
    clear_node_ca(owner, ca_path)?;

    Ok(())
}

/// Linux: delete the `environment.d` drop-in and unset the live session vars.
/// Only ever removes our own file (the path is ours by construction) and our own
/// variable; the standard names an older build exported are unset by value, so a
/// proxy the user set another way survives the revert.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn remove_proxy(url: &str, _ca_path: &str) -> Result<(), String> {
    use std::process::Command;
    if let Ok(path) = environment_d_path() {
        if fs::remove_file(&path).is_ok() {
            // Measured (WSL, systemd user manager): a variable the environment.d
            // generator loaded at the last reload survives `unset-environment`,
            // so every program started afterwards still got the address of a
            // proxy that is gone. A reload re-reads environment.d without our file.
            Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status()
                .ok();
        }
    }
    Command::new("systemctl")
        .args(["--user", "unset-environment", PROXY_ENV_VAR])
        .status()
        .ok();
    remove_legacy_proxy_env(url).ok();
    Ok(())
}

/// A proxy the user set up themselves, which this tool must not get in front of.
///
/// Two places one can live. `HTTPS_PROXY` in the User or Machine environment is
/// still what the patched language server reads *first* - the rename left that
/// literal alone precisely so this keeps working - and `http.proxy` in
/// Antigravity's own `settings.json` is what the Node side reads, with the
/// language server's inheritance of it **unverified** (P25), so it is respected
/// as a statement of intent either way. A value naming our own listener is not
/// foreign (a leftover from a build that wrote `HTTPS_PROXY` itself); anything
/// else is, and the answer says where it was found.
///
/// Since `2.11.0_5` this is the **only** thing keeping a user's own proxy in
/// front of ours. The first draft assumed lookup order would do it - `HTTPS_PROXY`
/// is the first argument of `getEnvAny` - and the probe measured the opposite:
/// with both variables set the patched server takes ours
/// (`patch_binary::PROXY_VAR_NEW`). So every caller that could write ours has to
/// ask this first and remove ours when the answer is `Some`, and every one does.
#[derive(Clone, PartialEq, Eq)]
pub struct ForeignProxy {
    pub value: String,
    pub found_in: String,
}

/// The user's own proxy, if they configured one anywhere the client would read.
#[cfg(target_os = "windows")]
pub fn foreign_proxy(owner: &mut CommandOutcome, ours: &str) -> Result<Option<ForeignProxy>, String> {
    for scope in ["User", "Machine"] {
        if let Some(value) = current_env_in(owner, LEGACY_PROXY_ENV_VAR, scope)? {
            if !is_ours_on_any_port(&value, ours) {
                return Ok(Some(ForeignProxy {
                    value,
                    found_in: format!("переменная среды {} ({})", LEGACY_PROXY_ENV_VAR, scope),
                }));
            }
        }
    }
    Ok(antigravity_proxy_setting(ours))
}

#[cfg(target_os = "macos")]
pub fn foreign_proxy(ours: &str) -> Option<ForeignProxy> {
    use std::process::Command;
    for name in [LEGACY_PROXY_ENV_VAR, "https_proxy"] {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim().to_string();
            if !value.is_empty() && !is_our_proxy_value(&value, ours) {
                return Some(ForeignProxy {
                    value,
                    found_in: format!("переменная среды {}", name),
                });
            }
        }
        if let Ok(out) = Command::new("launchctl").args(["getenv", name]).output() {
            if out.status.success() {
                let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !value.is_empty() && !is_our_proxy_value(&value, ours) {
                    return Some(ForeignProxy {
                        value,
                        found_in: format!("launchctl getenv {}", name),
                    });
                }
            }
        }
    }
    antigravity_proxy_setting(ours)
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn foreign_proxy(ours: &str) -> Option<ForeignProxy> {
    for name in [LEGACY_PROXY_ENV_VAR, "https_proxy"] {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim().to_string();
            if !value.is_empty() && !is_ours_on_any_port(&value, ours) {
                return Some(ForeignProxy {
                    value,
                    found_in: format!("переменная среды {}", name),
                });
            }
        }
    }
    if let Some(found) = session_manager_proxy(ours) {
        return Some(found);
    }
    antigravity_proxy_setting(ours)
}

/// `HTTPS_PROXY`/`https_proxy` as the systemd user manager holds it - what a
/// `environment.d` drop-in or a `systemctl --user set-environment` leaves behind,
/// and what every app launched from the desktop inherits.
#[cfg(not(target_os = "windows"))]
fn session_manager_proxy(ours: &str) -> Option<ForeignProxy> {
    use std::process::Command;
    let out = Command::new("systemctl")
        .args(["--user", "show-environment"])
        .output()
        .ok()?;
    let env = String::from_utf8_lossy(&out.stdout);
    for name in [LEGACY_PROXY_ENV_VAR, "https_proxy"] {
        let prefix = format!("{}=", name);
        let Some(value) = env
            .lines()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .map(str::trim)
        else {
            continue;
        };
        if !value.is_empty() && !is_ours_on_any_port(value, ours) {
            return Some(ForeignProxy {
                value: value.to_string(),
                found_in: format!("{} в сессии systemd --user", name),
            });
        }
    }
    None
}

/// `http.proxy` from the `settings.json` of every Antigravity product under the
/// user's profile. Product folders are matched by prefix, so a rebranded build
/// and the Desktop app - which ships no loose `product.json` for
/// `ide_settings_path` to read - are both covered.
fn antigravity_proxy_setting(ours: &str) -> Option<ForeignProxy> {
    let root = profile_root()?;
    let entries = fs::read_dir(&root).ok()?;
    for entry in entries.flatten().take(64) {
        let name = entry.file_name();
        if !name
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("antigravity")
        {
            continue;
        }
        let path = entry.path().join("User").join("settings.json");
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if let Some(value) = proxy_setting_in(&text) {
            if !is_ours_on_any_port(&value, ours) {
                return Some(ForeignProxy {
                    value,
                    found_in: format!(
                        "http.proxy в {}",
                        crate::utils::mask_path(&path.to_string_lossy())
                    ),
                });
            }
        }
    }
    None
}

/// The `http.proxy` value in a settings file, if it is set to something.
///
/// Textual, like every other look at this file (I18), and line-wise so a
/// commented-out setting - JSONC allows them, and a user trying things out leaves
/// them - is not read as a live one. A URL contains `//` too, which is why the
/// test is "the line starts with a comment", not "the line contains one".
fn proxy_setting_in(text: &str) -> Option<String> {
    let re = Regex::new(r#""http\.proxy"\s*:\s*"([^"]*)""#).ok()?;
    text.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .find_map(|l| {
            re.captures(l)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().trim().to_string())
        })
        .filter(|v| !v.is_empty())
}

#[cfg(target_os = "windows")]
fn profile_root() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn profile_root() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn profile_root() -> Option<PathBuf> {
    match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.is_empty() => Some(PathBuf::from(x)),
        _ => std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config")),
    }
}

/// Puts the proxy variable back on our listener when it has gone missing and
/// nothing of the user's has taken its place. The relay calls this at start: the
/// watchdog takes the variable off when the listener is dead for a while, and
/// this is the other half - the listener is back, so the route is too. A variable
/// already pointing here, or a proxy the user set themselves, is left exactly as
/// it is.
///
/// On platforms with legacy migration, this also checks for an old user-wide
/// `HTTPS_PROXY` when the private variable is already current.
///
/// **The foreign check comes first, and that order is load bearing.** The patched
/// server prefers our variable over the user's `HTTPS_PROXY` when both are set
/// (measured - see `patch_binary::PROXY_VAR_NEW`), so a user who configures a
/// proxy *after* being patched would silently keep going through ours. Menu 1
/// catches that only if they run it again; this runs at every relay start, which
/// is every boot, so at worst they are back on their own proxy after a restart.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn ensure_proxy_env(ours: &str) -> Result<Outcome, String> {
    if foreign_proxy(ours).is_some() {
        // Theirs, not ours - and ours would win over it, so it has to go.
        remove_proxy(ours, "")?;
        return Ok(Outcome::AlreadySet);
    }
    if current_env(PROXY_ENV_VAR).is_some_and(|v| is_our_proxy_value(&v, ours)) {
        // On Linux, an old user-wide pair may still need cleanup after a reboot.
        return match remove_legacy_proxy_env(ours) {
            Ok(true) => Ok(Outcome::Applied),
            _ => Ok(Outcome::AlreadySet),
        };
    }
    apply_proxy(ours, "")
}

#[cfg(target_os = "windows")]
pub fn ensure_proxy_env(owner: &mut CommandOutcome, ours: &str) -> Result<Outcome, String> {
    if foreign_proxy(owner, ours)?.is_some() {
        remove_proxy(owner, ours, "")?;
        return Ok(Outcome::AlreadySet);
    }
    if current_env(owner, PROXY_ENV_VAR)?.is_some_and(|value| is_our_proxy_value(&value, ours)) {
        return Ok(if remove_legacy_proxy_env(owner, ours)? { Outcome::Applied } else { Outcome::AlreadySet });
    }
    apply_proxy(owner, ours, "")
}

/// Takes our proxy variable off. `Ok(true)` when there was one and it was
/// removed, `Ok(false)` when there was nothing of ours.
///
/// The watchdog's primitive: it must never touch a value the user set. That is
/// now true by the *name* - `PROXY_ENV_VAR` is written by nothing else - where it
/// used to rest on matching the value under a shared name.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn remove_proxy_if_ours(url: &str, ca_path: &str) -> Result<bool, String> {
    if current_env(PROXY_ENV_VAR).is_none() {
        // Linux can still have a legacy pair without the private variable.
        return remove_legacy_proxy_env(url);
    }
    remove_proxy(url, ca_path).map(|()| true)
}
#[cfg(target_os = "windows")]
pub fn remove_proxy_if_ours(owner: &mut CommandOutcome, url: &str, ca_path: &str) -> Result<bool, String> {
    if current_env(owner, PROXY_ENV_VAR)?.is_none() { return remove_legacy_proxy_env(owner, url); }
    remove_proxy(owner, url, ca_path).map(|()| true)
}
#[cfg(target_os = "windows")]
fn current_env_in(owner: &mut CommandOutcome, name: &str, scope: &str) -> Result<Option<String>, String> {
    let receipt = powershell(owner, &format!(
        "[Environment]::GetEnvironmentVariable('{}','{}')",
        name, scope
    ));
    receive_command(owner, receipt)?;
    let value = String::from_utf8_lossy(owner.stdout()).trim().to_string();
    drop(std::mem::take(owner));
    Ok((!value.is_empty()).then_some(value))
}

/// Whether an `HTTPS_PROXY` value is one this tool wrote.
///
/// Compared on the **address**, not on the exact string. A value that has been
/// through a settings dialog, a shell or another tool's rewrite can differ from
/// what we wrote by a trailing slash or the case of the scheme and still be
/// ours - and an exact comparison used to bail on that, leaving the variable
/// pointing at a port that no longer answers.
///
/// Safe because the address is loopback and a fixed port that only this tool
/// listens on: a proxy the user chose for themselves never names it. Their own
/// value is left alone, which matters more than removing ours.
/// Ours at all: the listener's current address, or the default port it had
/// before the relay had to move it (`proxy::port`). For "is it someone else's"
/// and "may we take it off" - a value naming the old port is still ours to
/// remove, never a foreign proxy to stand aside for. "Is it ours *and still
/// current*" is `is_our_proxy_value`.
fn is_ours_on_any_port(value: &str, url: &str) -> bool {
    is_our_proxy_value(value, url) || is_our_proxy_value(value, &crate::proxy::default_url())
}

fn is_our_proxy_value(value: &str, url: &str) -> bool {
    let strip = |s: &str| {
        s.trim()
            .trim_end_matches('/')
            .to_ascii_lowercase()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string()
    };
    let ours = strip(url);
    // Equality, not `contains`: a test caught `socks5://127.0.0.1:53129x`
    // passing a substring check, and `…:531290` would have too. Removing a
    // proxy that is not ours is the worse of the two failures here.
    !ours.is_empty() && strip(value) == ours
}

/// Drops `NODE_EXTRA_CA_CERTS` if it still holds `ca_path`, leaving a value the
/// user set themselves alone.
///
/// Separate from `remove_proxy` because an *upgrade* has to drop the old CA
/// without turning the proxy off: a machine coming from the carrier route
/// (<= 2.9.1_27) already has `HTTPS_PROXY` pointing here, so `apply_proxy`
/// returns `AlreadySet` and never reaches this. Leaving it behind would keep
/// every Node process on the machine trusting a CA nothing uses any more -
/// harmless today, and exactly the kind of leftover that is impossible to
/// explain a year from now.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn clear_node_ca(ca_path: &str) -> Result<(), String> {
    if current_env(NODE_CA_ENV_VAR).as_deref() == Some(ca_path) {
        set_env(NODE_CA_ENV_VAR, None)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn clear_node_ca(owner: &mut CommandOutcome, ca_path: &str) -> Result<(), String> {
    if current_env(owner, NODE_CA_ENV_VAR)?.as_deref() == Some(ca_path) { set_env(owner, NODE_CA_ENV_VAR, None)?; }
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_env(owner: &mut CommandOutcome, name: &str, value: Option<&str>) -> Result<(), String> {
    let literal = match value {
        Some(v) => format!("'{}'", v),
        None => "$null".to_string(),
    };
    let script = format!(
        "[Environment]::SetEnvironmentVariable('{}',{},'User')",
        name, literal
    );
    let receipt = powershell(owner, &script);
    receive_command(owner, receipt)?;
    drop(std::mem::take(owner));
    Ok(())
}

/// Persisting a per-user environment variable for GUI-launched processes on
/// Linux has no single mechanism (systemd `environment.d`, `~/.profile`,
/// `~/.pam_environment` all reach different launchers), so it is deferred with
/// the proxy carrier that needs it. Removal is a trivial success - there is
/// nothing of ours in a persistent store to take out - while a request to *set*
/// one is refused honestly rather than silently doing nothing.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn set_env(name: &str, value: Option<&str>) -> Result<(), String> {
    match value {
        None => Ok(()),
        Some(_) => Err(format!(
            "{} на Linux пока не задаётся (нужен свой прокси-слой порта)",
            name
        )),
    }
}

#[cfg(target_os = "windows")]
fn current_env(owner: &mut CommandOutcome, name: &str) -> Result<Option<String>, String> {
    let receipt = powershell(owner, &format!(
        "[Environment]::GetEnvironmentVariable('{}','User')",
        name
    ));
    receive_command(owner, receipt)?;
    let value = String::from_utf8_lossy(owner.stdout()).trim().to_string();
    drop(std::mem::take(owner));
    Ok((!value.is_empty()).then_some(value))
}

#[cfg(target_os = "macos")]
fn current_env(name: &str) -> Option<String> {
    use std::process::Command;
    if let Ok(out) = Command::new("launchctl").args(["getenv", name]).output() {
        if out.status.success() {
            let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    if let Ok(val) = std::env::var(name) {
        let val = val.trim().to_string();
        if !val.is_empty() {
            return Some(val);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let path = PathBuf::from(home).join(".zprofile");
    let text = fs::read_to_string(path).ok()?;
    let prefix = format!("export {}=\"", name);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            if let Some(val) = rest.strip_suffix('"') {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// On Linux reads the process environment, the systemd user manager session,
/// or the persistent environment.d drop-in.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn current_env(name: &str) -> Option<String> {
    if let Ok(v) = std::env::var(name) {
        let trimmed = v.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    if let Ok(out) = std::process::Command::new("systemctl")
        .args(["--user", "show-environment"])
        .output()
    {
        let env_str = String::from_utf8_lossy(&out.stdout);
        let prefix = format!("{}=", name);
        if let Some(val) = env_str.lines().find_map(|l| l.strip_prefix(&prefix)) {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    if let Ok(path) = environment_d_path() {
        if let Ok(content) = fs::read_to_string(&path) {
            let prefix = format!("{}=", name);
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') {
                    continue;
                }
                if let Some(val) = trimmed.strip_prefix(&prefix) {
                    let val_trimmed = val.trim().to_string();
                    if !val_trimmed.is_empty() {
                        return Some(val_trimmed);
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn current_cli_endpoint(owner: &mut CommandOutcome) -> Result<Option<String>, String> {
    let receipt = powershell(owner, &format!(
        "[Environment]::GetEnvironmentVariable('{}','User')",
        CLI_ENV_VAR
    ));
    receive_command(owner, receipt)?;
    let value = String::from_utf8_lossy(owner.stdout()).trim().to_string();
    drop(std::mem::take(owner));
    Ok((!value.is_empty()).then_some(value))
}

#[cfg(target_os = "macos")]
fn current_cli_endpoint() -> Option<String> {
    current_env(CLI_ENV_VAR)
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn current_cli_endpoint() -> Option<String> {
    None
}

/// The value of our proxy variable as the user environment has it right now.
/// Read-only; `None` when it is not set.
#[allow(dead_code)]
#[cfg(not(target_os = "windows"))]
pub fn proxy_env_value() -> Option<String> {
    current_env(PROXY_ENV_VAR)
}
#[cfg(target_os = "windows")]
pub fn proxy_env_value(owner: &mut CommandOutcome) -> Result<Option<String>, String> { current_env(owner, PROXY_ENV_VAR) }

/// True when the variable is set AND names our own local listener rather than
/// something the user configured themselves.
#[allow(dead_code)]
#[cfg(not(target_os = "windows"))]
pub fn proxy_env_is_ours() -> bool {
    let ours = crate::proxy::proxy_url();
    proxy_env_value().is_some_and(|v| is_our_proxy_value(&v, &ours))
}
#[cfg(target_os = "windows")]
pub fn proxy_env_is_ours(owner: &mut CommandOutcome) -> Result<bool, String> {
    let ours = crate::proxy::proxy_url();
    Ok(proxy_env_value(owner)?.is_some_and(|v| is_our_proxy_value(&v, &ours)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_launch_write_distinguishes_successful_command_from_failed_readback() {
        let value = crate::proxy::url_at(53129);
        for (before, wanted) in [(None, Some(value.as_str())), (Some(value.as_str()), None)] {
            for mismatch in [false, true] {
                let command_completed = std::cell::Cell::new(false);
                let result = mac_checked_launch_write(before, wanted, || {
                    if !command_completed.get() || mismatch { return Ok(before.map(str::to_owned)); }
                    Err("synthetic readback failure".into())
                }, || Ok(()), || { command_completed.set(true); Ok(()) });
                assert!(command_completed.get());
                assert!(matches!(result, Err(MacLaunchWriteFailure::Unconfirmed(_))));
            }
        }
    }

    #[test]
    fn mac_profile_round_trip_preserves_crlf_bytes_and_an_unterminated_tail() {
        let value = crate::proxy::url_at(53129);
        for before in [b"".as_slice(), b"safe\r\n\xff\r\n", b"safe\r\n\xff tail", b"bare carriage\r"] {
            let after = mac_profile_replacement(before, Some(&value)).unwrap().unwrap();
            assert!(after.starts_with(before));
            assert_eq!(mac_profile_replacement(&after, Some(&value)).unwrap(), None);
            assert_eq!(mac_profile_replacement(&after, None).unwrap().as_deref(), Some(before));
        }
    }

    #[test]
    fn mac_profile_rejects_malformed_duplicate_and_foreign_blocks() {
        let value = crate::proxy::url_at(53129);
        let owned = mac_profile_replacement(b"", Some(&value)).unwrap().unwrap();
        let duplicate = [owned.as_slice(), owned.as_slice()].concat();
        for conflict in [b"# [AG_LS_PROXY_START]\nexport OTHER=keep\n".as_slice(),
            b" #[AG_LS_PROXY_END]\n", b"# [AG_LS_PROXY_START]\nexport AG_LS_PROXY=\"http://example.invalid:1\"\n# [AG_LS_PROXY_END]\n",
            duplicate.as_slice()] {
            assert!(mac_profile_replacement(conflict, None).is_err());
            assert!(mac_profile_replacement(conflict, Some(&value)).is_err());
        }
    }

    #[test]
    fn mac_profile_updates_only_the_qualified_block_in_place() {
        let before_url = crate::proxy::url_at(53129);
        let next_url = crate::proxy::url_at(53130);
        let block = mac_profile_replacement(b"", Some(&before_url)).unwrap().unwrap();
        let before = [b"prefix\r\n".as_slice(), block.as_slice(), b"suffix\xff"].concat();
        let after = mac_profile_replacement(&before, Some(&next_url)).unwrap().unwrap();
        assert!(after.starts_with(b"prefix\r\n"));
        assert!(after.ends_with(b"suffix\xff"));
        assert_eq!(mac_profile_replacement(&after, None).unwrap().as_deref(), Some(b"prefix\r\nsuffix\xff".as_slice()));
    }

    #[test]
    fn mac_profile_never_overrides_an_outside_assignment() {
        let value = crate::proxy::url_at(53129);
        for assignment in [b"AG_LS_PROXY=\"mine\"\r\n".as_slice(),
            b"export  AG_LS_PROXY=mine\n", b"typeset -x AG_LS_PROXY+=mine\n"] {
            assert!(mac_profile_replacement(assignment, Some(&value)).is_err());
        }
        let harmless = b"# AG_LS_PROXY=example\r\nprintf '%s' \"$AG_LS_PROXY\"";
        let appended = mac_profile_replacement(harmless, Some(&value)).unwrap().unwrap();
        assert_eq!(mac_profile_replacement(&appended, None).unwrap().as_deref(), Some(harmless.as_slice()));
    }

    #[test]
    fn mac_cli_cleanup_removes_only_its_legacy_endpoint_block() {
        let block = format!("# [{CLI_ENV_VAR}_START]\nexport {CLI_ENV_VAR}=\"{DAILY_ENDPOINT}\"\n# [{CLI_ENV_VAR}_END]\n");
        let before = [b"preserve\r\n".as_slice(), block.as_bytes(), b"\xff tail"].concat();
        assert_eq!(mac_managed_profile_replacement(&before, CLI_ENV_VAR, None, |value| value == DAILY_ENDPOINT)
            .unwrap().as_deref(), Some(b"preserve\r\n\xff tail".as_slice()));
        let malformed = b"# [CLOUD_CODE_URL_START]\nexport OTHER=preserve\n";
        assert!(mac_managed_profile_replacement(malformed, CLI_ENV_VAR, None, |value| value == DAILY_ENDPOINT).is_err());
    }

    /// The user's own `http.proxy` is read as intent: set means set, empty or
    /// commented out means nothing, and a URL's own `//` is not a comment.
    #[test]
    fn a_proxy_setting_is_found_only_when_it_is_live_and_non_empty() {
        assert_eq!(
            proxy_setting_in(r#"{ "http.proxy": "http://10.0.0.1:3128", "x": 1 }"#).as_deref(),
            Some("http://10.0.0.1:3128")
        );
        assert_eq!(
            proxy_setting_in("{\n    \"http.proxy\" : \"socks5://h:1080\"\n}").as_deref(),
            Some("socks5://h:1080")
        );
        assert_eq!(proxy_setting_in(r#"{ "http.proxy": "" }"#), None);
        assert_eq!(
            proxy_setting_in(r#"{ "http.proxyStrictSSL": "yes" }"#),
            None
        );
        assert_eq!(
            proxy_setting_in("{\n    // \"http.proxy\": \"http://old:3128\",\n    \"a\": 1\n}"),
            None,
            "a commented-out setting is not a setting"
        );
        assert_eq!(proxy_setting_in("{}"), None);
    }

    /// Our own listener in the settings file is not a foreign proxy.
    #[test]
    fn our_own_listener_in_settings_is_not_foreign() {
        let ours = "http://127.0.0.1:53129";
        let value = proxy_setting_in(r#"{ "http.proxy": "http://127.0.0.1:53129/" }"#).unwrap();
        assert!(is_our_proxy_value(&value, ours));
        let value = proxy_setting_in(r#"{ "http.proxy": "http://127.0.0.1:8080" }"#).unwrap();
        assert!(!is_our_proxy_value(&value, ours));
    }

    /// The bug users hit: a revert that left `HTTPS_PROXY` naming a port it had
    /// just deleted, so nothing on the machine could reach the network. Part of
    /// it was an exact string comparison - a value that had been through a
    /// settings dialog or another tool came back with a trailing slash or a
    /// different case and was not recognised as ours.
    #[test]
    fn our_proxy_value_is_recognised_however_it_was_written_back() {
        let url = "http://127.0.0.1:53129";
        for shape in [
            "http://127.0.0.1:53129",
            "http://127.0.0.1:53129/",
            "HTTP://127.0.0.1:53129",
            "  http://127.0.0.1:53129  ",
            "127.0.0.1:53129",
            "https://127.0.0.1:53129",
        ] {
            assert!(
                is_our_proxy_value(shape, url),
                "should be ours: {:?}",
                shape
            );
        }
    }

    /// `NO_PROXY` is the one variable this tool can delete without being able to
    /// recognise it: the value is all there is, and `127.0.0.1,localhost,::1` is
    /// something a user may well have set. Since `_5` the migration runs on the
    /// patch path and at every relay start, so an unconditional match would take
    /// it off a machine that had never run this tool - and again after every
    /// reboot they put it back. It goes only in company.
    #[test]
    fn no_proxy_is_only_removed_beside_a_proxy_value_of_ours() {
        let url = "http://127.0.0.1:53129";
        let ours = Some("http://127.0.0.1:53129");
        let theirs = Some("http://corp.example:3128");
        let np = Some(NO_PROXY_VALUE);

        // The pair an older build wrote: both go.
        assert_eq!(legacy_removals(ours, np, url), (true, true));
        // Never used this tool, but happens to have that NO_PROXY: nothing goes.
        assert_eq!(legacy_removals(None, np, url), (false, false));
        // Their own proxy plus that NO_PROXY: still nothing.
        assert_eq!(legacy_removals(theirs, np, url), (false, false));
        // Ours, but a NO_PROXY they changed: only ours goes.
        assert_eq!(
            legacy_removals(ours, Some("127.0.0.1,corp.example"), url),
            (true, false)
        );
        // Ours alone.
        assert_eq!(legacy_removals(ours, None, url), (true, false));
    }

    /// The other half, and the more important one: a proxy the user chose for
    /// themselves must survive our revert untouched. Removing someone else's
    /// proxy is a worse failure than leaving ours behind.
    #[test]
    fn a_proxy_the_user_chose_is_never_removed() {
        let url = "http://127.0.0.1:53129";
        for theirs in [
            "http://127.0.0.1:1371",
            "http://proxy.example.com:8080",
            "http://10.0.0.1:53129",
            "socks5://127.0.0.1:53129x",
            "",
        ] {
            assert!(
                !is_our_proxy_value(theirs, url),
                "must be left alone: {:?}",
                theirs
            );
        }
    }

    const REAL: &str = "{\n    \"workbench.colorTheme\": \"Solarized Dark\",\n    \"securecoder.enabled\": true\n}";

    #[test]
    fn the_key_is_added_and_the_rest_kept_byte_for_byte() {
        let out = upsert_key(REAL, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert!(
            out.contains("\"jetski.cloudCodeUrl\": \"https://daily-cloudcode-pa.googleapis.com\"")
        );
        // Every line the user had must survive, unchanged apart from the comma
        // that now separates it from ours.
        assert!(out.contains("\"workbench.colorTheme\": \"Solarized Dark\""));
        assert!(out.contains("\"securecoder.enabled\": true"));
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
    }

    #[test]
    fn writing_twice_changes_nothing_the_second_time() {
        let once = upsert_key(REAL, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        let twice = upsert_key(&once, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert_eq!(once, twice);
    }

    /// A value the user (or an older build) left behind must be corrected, not
    /// duplicated - two entries for one key is invalid JSON.
    #[test]
    fn a_stale_value_is_replaced_not_duplicated() {
        let stale = REAL.replace(
            "\"securecoder.enabled\": true",
            "\"securecoder.enabled\": true,\n    \"jetski.cloudCodeUrl\": \"https://cloudcode-pa.googleapis.com\"",
        );
        let out = upsert_key(&stale, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert_eq!(out.matches(IDE_SETTING).count(), 1);
        assert!(out.contains(DAILY_ENDPOINT));
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
    }

    #[test]
    fn an_empty_or_missing_file_becomes_a_valid_object() {
        for text in ["", "   \n"] {
            let out = upsert_key(text, IDE_SETTING, DAILY_ENDPOINT).expect("created");
            let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid json");
            assert_eq!(parsed[IDE_SETTING], DAILY_ENDPOINT);
        }
    }

    #[test]
    fn an_empty_object_gets_no_stray_comma() {
        let out = upsert_key("{}", IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
            "{}",
            out
        );
        assert!(!out.contains("{,"));
    }

    /// The user's own trailing comma is legal JSONC and must not produce two.
    #[test]
    fn a_trailing_comma_is_not_doubled() {
        let out =
            upsert_key("{\n    \"a\": \"b\",\n}", IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        assert!(!out.contains(",,"), "{}", out);
    }

    #[test]
    fn a_file_without_a_closing_brace_is_refused() {
        assert!(upsert_key("not json at all", IDE_SETTING, DAILY_ENDPOINT).is_err());
    }

    #[test]
    fn removal_restores_valid_json_without_our_key() {
        for original in [REAL, "{}", "{\n    \"a\": \"b\"\n}"] {
            let with = upsert_key(original, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
            let without = remove_key(&with, IDE_SETTING).expect("removed");
            assert!(!without.contains(IDE_SETTING), "{}", without);
            assert!(
                serde_json::from_str::<serde_json::Value>(&without).is_ok(),
                "{}",
                without
            );
        }
    }

    /// Removing ours must not take the user's settings with it.
    #[test]
    fn removal_keeps_everything_else() {
        let with = upsert_key(REAL, IDE_SETTING, DAILY_ENDPOINT).expect("edited");
        let without = remove_key(&with, IDE_SETTING).expect("removed");
        let parsed: serde_json::Value = serde_json::from_str(&without).expect("valid json");
        assert_eq!(parsed["workbench.colorTheme"], "Solarized Dark");
        assert_eq!(parsed["securecoder.enabled"], true);
    }

    #[test]
    fn removing_a_key_that_is_not_there_is_a_no_op() {
        assert_eq!(remove_key(REAL, IDE_SETTING).expect("no-op"), REAL);
    }

    /// The endpoint has to be the host that is actually still substituted; the
    /// production one is exactly what stopped working.
    #[test]
    fn the_endpoint_is_the_daily_host() {
        assert!(DAILY_ENDPOINT.starts_with("https://daily-cloudcode-pa."));
        assert!(!DAILY_ENDPOINT.contains("sandbox"));
    }

    /// Against the real install. It used to also assert that the build still
    /// reads `jetski.cloudCodeUrl`; nothing writes that key since 2.11.0, so the
    /// question left is the one `remove_ide` depends on - does the path resolve
    /// to the folder the IDE actually reads, so an override left by an earlier
    /// build is found and taken out.
    #[test]
    #[ignore = "needs a real Antigravity IDE install; run with --ignored"]
    fn finds_the_real_ide_settings_file() {
        let install = PathBuf::from(std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA"))
            .join("Programs")
            .join("Antigravity IDE");
        if !install.exists() {
            println!("no IDE install at {}", install.display());
            return;
        }
        let path = ide_settings_path(&install).expect("settings path");
        println!("settings: {} (exists: {})", path.display(), path.exists());
        assert!(
            path.ends_with("User\\settings.json"),
            "unexpected shape: {}",
            path.display()
        );
    }

    #[test]
    #[ignore = "reads live environment and requires creator-owned command containment"]
    fn proxy_env_queries_run_without_panic() {
        #[cfg(target_os = "windows")]
        {
            let mut owner = CommandOutcome::default();
            let _ = proxy_env_value(&mut owner);
            let _ = proxy_env_is_ours(&mut owner);
        }
        #[cfg(not(target_os = "windows"))]
        { let _ = proxy_env_value(); let _ = proxy_env_is_ours(); }
    }
}
