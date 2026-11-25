use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crate::dns;
use crate::dns_client;
use crate::egress;
use crate::gate;
use crate::loopback;
use crate::ls_log;
use crate::net;
use crate::proxy;
use crate::resolvers::{self, Verdict};
use crate::routes;
use crate::upstream;

// A loopback DNS relay, so the answers stay fresh.
//
// Pinning the substituted address into `hosts` works but breaks its own
// contract: xbox-dns answers with **TTL 60**, i.e. it explicitly reserves the
// right to move the address every minute, and a static file holds it forever.
//
// Instead the NRPT rules point at this listener, which relays the query - raw
// bytes, never parsed - to xbox-dns over the ISP link via IP_UNICAST_IF, and
// relays the answer back verbatim. Windows then caches it for exactly the TTL
// the resolver asked for and comes back when it expires, so a rotated address is
// picked up within a minute with no file to go stale. It behaves identically
// with and without a VPN: without one the ISP link is the default path anyway.
//
// Verified before building: the Windows DNS client does send NRPT queries to a
// 127.0.0.0/8 nameserver (a probe rule delivered the question to a listener on
// 127.0.0.53:53).
//
// UDP only, deliberately. Relaying verbatim means a truncated answer would need
// a TCP listener as well, but the routed names answer with a single A record in
// well under 100 bytes, so TC is never set. If that ever changes, Windows falls
// back to the next nameserver in the rule rather than failing outright.

/// Where the NRPT rules point. Any 127.0.0.0/8 address works; .53 keeps it
/// recognisable and clear of anything bound to 127.0.0.1.
pub const LISTEN_IP: &str = "127.0.0.53";
pub const LISTEN_PORT: u16 = 53;

/// What generation of relay this build ships.
///
/// Separate from the product version on purpose: the relay is installed once,
/// by an administrator, and then keeps running across reboots from
/// `%ProgramData%` - so a user can be running a months-old relay under a fresh
/// unlocker and never be told. The unlocker compares this against what the
/// installed relay wrote and says so.
///
/// **Bump this whenever the relay's own behaviour changes** - the loop, the
/// resolver logic it carries, the warm loop, the watchdog. A pure UI or patcher
/// change does not need it. Never decrease it: the comparison is "older than",
/// and a version that goes backwards asks every user to reinstall.
///
/// 1 = first versioned relay: answer cache + warm loop.
/// 2 = a non-substituted answer can no longer pin the client for its own TTL.
/// 3 = carries the fallback proxy (`proxy.rs`) alongside the DNS relay.
/// 4 = the proxy no longer answers a socket the client has not spoken on.
/// 5 = identity and telemetry hosts are tunnelled, never intercepted.
/// 6 = liveness is re-probed on the warm loop, so a dead address is dropped
///     within seconds instead of being advertised for ten minutes.
/// 7 = a provider choice is only remembered when it actually substituted.
/// 8 = the race log is client-only, so it stops eating its own log budget.
/// 9 = the warm loop gets a generous liveness budget; the client path stays tight.
/// 10 = `enable()` verifies the relay came up instead of trusting the task.
/// 11 = liveness is measured by the TLS handshake, not just the connection.
/// 12 = the fallback route picks its upstream by measured handshake latency.
/// 13 = the byte pump is non-blocking, so it stops adding its own latency.
/// 14-16 = no separate entries were kept for these.
/// 17 = the proxy carries the gate hosts through the cert-free relay route.
/// 18 = the TLS-terminating carrier route is gone with its CA, and the warm loop
///     no longer measures upstreams (there is one relay, nothing to choose).
/// 19 = idle relayed tunnels are closed before they go stale, the relay is
///     benched when it stops carrying, teardown is logged and lines are stamped.
/// 20 = a relay that cuts tunnels at the handshake counts as failing (bytes
///     moved, so "carried nothing" missed it), and the bench backs off.
/// 21 = the relay leg asks for `cloudcode-pa` instead of `daily-`, which costs
///     it a second proxy hop: 2.14 s median down to 0.22 s, and no variance.
/// 22 = the route is checked by a probe on the warm loop instead of by someone's
///     request, and a burst of in-flight failures no longer lengthens the bench.
/// 23 = every child process it shells out to is bounded, so a hung helper can no
///     longer stop it dead.
/// 27 = routes are ordered by measured speed (`routes`), the client's own log is
///     tailed for the region 400 (`ls_log`) and answered by forcing substitution
///     back on and penalising the route it came through, and the direct route
///     fails inside a budget instead of hanging on the OS connect timeout.
/// 28 = it writes down what it is doing (`gate.json`): the leader route, the
///     forced-substitution deadline, the stand-down verdict, and what it did
///     about the last region 400. Without this generation the window can see
///     the refusal in the client's log but nothing about the answer, so the
///     bump is what tells the user their service is too old to report (S48).
/// 29 = the DoH provider keeps its connections (`doh::Pool`) instead of opening
///     one per query, and each address resumes its own TLS session. dns-ai.ru
///     measured 1.06 queries per connection and its CPU going to handshakes;
///     the relay is where those queries come from, so it is what has to change.
///     Same generation: a third dns-ai.ru node (msk1) in the walk.
/// 30 = carries the gate hosts itself on every network (2.14.0_1): answers them
///     with its own loopback addresses (`loopback`), so a client started before
///     the proxy variable is routed too (G50); pins its own connections to the
///     ISP link while a VPN holds the default route, DoH included (N25, P13);
///     ranks routes by the model answers they carried, not only by speed, and
///     closes a refused route's tunnels (`routes`); watches the client logs
///     every two seconds, the CLI's included; answers AAAA/HTTPS for the gate
///     hosts with nothing (P40); and no longer stands down for a VPN while that
///     door is up (D25) - the VPN is a route of its own. xbox-dns.ru is out of
///     the pool.
/// 31 = its watchdog patches a fresh install too, not only one an update
///     reverted: gated on auto-patch minus a patch declined by hand instead of
///     on the user having patched once (D27), re-scanning for installs every
///     10 s instead of 5 min, the user's own paths included. An older relay
///     leaves a newly installed Antigravity unpatched with auto-patch on.
/// 32 = says what keeps its listeners down (a program holding the port, a
///     port Windows reserved, security software refusing it - `portcheck`),
///     retries them every minute, moves the local proxy off a port it cannot
///     have (P26), and reports when nothing on the internet answers it
///     (`gate::Report::{blockers, reached_at, started_at, exe}`, P53). An older
///     relay leaves a user with `os error 10013` in its log and a 400 on screen.
/// 33 = its own UDP `:53` is retried and diagnosed like the other two listeners
///     instead of killing the process (`serve_dns_forever`), so a machine where
///     something holds port 53 still gets the door, the proxy, the exits and
///     the auto-patch; a refusal no longer benches - or even disconnects - a
///     route that carried a model answer in the last ninety seconds
///     (`routes::Blamed::Proven`), the first bench is two minutes rather than
///     ten, a region bench orders a route instead of removing it from the table
///     for every kind alike, and a route that fails its probe is kept back
///     until one succeeds. An older relay drops the working route mid-answer
///     and thrashes between benched ones.
/// 37 = a refusal the table declines to hold against a route no longer costs it
///     its place in the order either (`routes::bad_at` split from
///     `refused_at`, G76), the connection a refusal arrived on is named in the
///     log and closed when it is not the one carrying the answer, and the log
///     says which host was refused and how many answers were held back. An
///     older relay swaps the gate route away from the one that is answering
///     every fifteen seconds and cannot say whether a route half-works.
/// 39 = a live gate tunnel the client spoke into and got nothing back from
///     benches its route (`routes::SILENT_STEPS`), and a passing probe no
///     longer lets it back in front - only a model answer does. An older relay
///     keeps sending every connection to a built-in exit that opens and then
///     carries nothing, and never tries the DNS route behind it.
/// 40 = the user's own proxy gives way while benched (region 400, silent
///     tunnel, failed open) instead of staying first regardless. An older
///     relay answers a region 400 through the user's proxy by cutting its
///     tunnels and sending the retry straight back into it. Same generation:
///     the user's proxy no longer has its exit region traced on the warm loop
///     (nor when it is added) - the region-400 watch stands it down instead.
/// 41 = the third DoH node of dns-ai moved to a new address. An older relay
///     keeps dialling the withdrawn one and loses a third of the DoH walk.
/// 42 = dns-ai's two dead IPv4 nodes replaced by the live ones, its IPv6 pair
///     added, and an address that fails sits out of the DoH walk for a while
///     (`doh::plan`). An older relay still spends 2.5 s of every walk on two
///     dead addresses - the slow start of the 400 bypass.
/// 46 = the Windows watchdog receives changed WSL Desktop archives through the
///     installation owner; older background images do not contain this path.
/// 47 = the managed Windows carrier receives an immutable transport profile
///     and publishes its actual instance/configuration-bound channel report.
/// 48 = host-qualified DNS candidates and bound per-connection recovery.
pub const RELAY_VERSION: u32 = 48;

/// Written where an unelevated relay can write and an unelevated unlocker can
/// read. Absent means a relay from before versioning, i.e. older than anything.
const VERSION_FILE: &str = "relay.version";

/// Closes the console Windows hands a console subsystem process. Without this
/// the scheduled task leaves an empty black window on screen for as long as the
/// relay lives, which is forever. Everything it has to say goes to the log file
/// anyway, so losing stdout costs nothing.
#[cfg(target_os = "windows")]
pub fn detach_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn FreeConsole() -> i32;
    }
    unsafe {
        FreeConsole();
    }
}

#[cfg(not(target_os = "windows"))]
pub fn detach_console() {}

/// Log prefix for what the answer turned out to be. `substituted` is the only
/// one that means the region gate is actually being defeated for that name;
/// `PASSTHROUGH` shouts because it is the failure the old `ok` used to hide.
fn verdict_tag(v: Verdict) -> &'static str {
    match v {
        Verdict::Substituted => "substituted",
        Verdict::Sibling => "sibling",
        Verdict::Passthrough => "PASSTHROUGH",
        Verdict::Unknown => "ok",
    }
}

/// How long a *detected* interface is trusted. Long on purpose: detection
/// shells out to PowerShell, and an interface that dies is caught by
/// `invalidate_interface()` on the first failed relay, so re-probing on a timer
/// buys nothing and only spawns processes on the user's machine.
const EGRESS_TTL: Duration = Duration::from_secs(30 * 60);
/// How long a *failed* detection is remembered. Short, because it is usually
/// the network not being up yet at logon - but not zero, or a machine with no
/// physical egress at all would spawn a probe per query.
const EGRESS_RETRY: Duration = Duration::from_secs(30);
/// How often the relay re-asks whether a tunnel is carrying the machine.
///
/// Its own clock, and deliberately far shorter than `EGRESS_TTL`: an interface
/// index changes when hardware does, but a VPN is something the user toggles
/// mid-session, and that answer decides whether the relay substitutes at all
/// (G26). Costs one PowerShell spawn per interval and never runs on the query
/// path - a client waits on nothing here. Four minutes rather than fifteen
/// seconds because being late merely means a few minutes of the old, slightly
/// longer route; it breaks nothing.
const VPN_CHECK_EVERY: Duration = Duration::from_secs(4 * 60);
const LOG_LIMIT_BYTES: u64 = 64 * 1024;

/// Interface index, when it was learned, and how long that answer is good for.
static EGRESS_CACHE: Mutex<Option<(u32, Instant, Duration)>> = Mutex::new(None);

/// The log lives under the user profile, not next to the exe: the relay runs
/// unelevated, and the directory an administrator installed it into is not
/// writable for it.
#[cfg(target_os = "windows")]
pub fn log_dir() -> PathBuf {
    PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default()).join(crate::user_state_location::WINDOWS_STATE_LEAF)
}

#[cfg(not(target_os = "windows"))]
fn current_directory() -> Result<PathBuf, String> {
    std::env::current_dir().map_err(|error| format!("Рабочий каталог недоступен: {error}"))
}

#[cfg(any(not(target_os = "windows"), test))]
fn absolute_user_path(path: PathBuf, cwd: impl FnOnce() -> Result<PathBuf, String>) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path);
    }
    // Service definitions need an absolute path. Do not simplify `..` and
    // change how the filesystem walks a preceding symlink.
    Ok(cwd()?.join(path))
}

#[cfg(any(not(target_os = "windows"), test))]
fn resolve_unix_home(
    home: Option<std::ffi::OsString>,
    account_home: impl FnOnce() -> Option<PathBuf>,
) -> Result<PathBuf, String> {
    match home.filter(|home| !home.is_empty()) {
        Some(home) => Ok(PathBuf::from(home)),
        None => account_home().filter(|path| path.is_absolute())
            .ok_or_else(|| "Домашний каталог пользователя недоступен".into()),
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn unix_user_home() -> Result<PathBuf, String> {
    resolve_unix_home(std::env::var_os("HOME"), std::env::home_dir)
}

#[cfg(any(not(target_os = "windows"), test))]
fn resolve_unix_directory(
    explicit: Option<&str>,
    suffix: &str,
    home: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    match explicit.filter(|path| !path.is_empty()) {
        // Keep relative paths relative until filesystem I/O. The process can
        // still access its working directory after that directory is renamed.
        Some(path) => Ok(PathBuf::from(path)),
        None => home().map(|home| home.join(suffix)),
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) const UNIX_DATA_SUFFIX: &str = ".local/share";

#[cfg(not(target_os = "windows"))]
pub(crate) fn unix_data_home() -> Result<PathBuf, String> {
    resolve_unix_directory(std::env::var("XDG_DATA_HOME").ok().as_deref(), UNIX_DATA_SUFFIX, unix_user_home)
}

#[cfg(target_os = "macos")]
pub(crate) fn unix_launch_paths() -> Result<(PathBuf, PathBuf), String> {
    // HOME and XDG_DATA_HOME are serialized together for the new process.
    // Resolve any relative values against the same per-operation directory.
    let directory = std::cell::OnceCell::new();
    let cwd = || directory.get_or_init(current_directory).clone();
    let home = unix_user_home()?;
    let data = resolve_unix_directory(
        std::env::var("XDG_DATA_HOME").ok().as_deref(),
        UNIX_DATA_SUFFIX,
        || Ok(home.clone()),
    )?;
    Ok((absolute_user_path(home, &cwd)?, absolute_user_path(data, &cwd)?))
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub(crate) fn unix_config_home() -> Result<PathBuf, String> {
    resolve_unix_directory(std::env::var("XDG_CONFIG_HOME").ok().as_deref(), ".config", unix_user_home)
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub(crate) fn unix_service_path(path: PathBuf) -> Result<PathBuf, String> {
    absolute_user_path(path, current_directory)
}

pub(crate) fn checked_log_dir() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    { Ok(log_dir()) }
    #[cfg(not(target_os = "windows"))]
    { unix_data_home().map(|home| home.join("agunlocker")) }
}

const LOG_FILE: &str = "forwarder.log";

#[cfg(all(target_os = "windows", test))]
pub fn log_path() -> PathBuf {
    log_dir().join(LOG_FILE)
}

pub(crate) fn checked_log_path() -> Result<PathBuf, String> {
    checked_log_dir().map(|dir| dir.join(LOG_FILE))
}

#[cfg(target_os = "windows")]
pub fn version_path() -> PathBuf {
    log_dir().join(VERSION_FILE)
}

/// Records which relay generation is in place. Called both by the installer and
/// by the relay itself at startup: the installer's write is what makes the
/// answer correct the moment an upgrade finishes, and the relay's write is what
/// keeps it honest if the exe ever gets there some other way.
#[cfg(not(target_os = "windows"))]
pub fn record_version() {
    let dir = match checked_log_dir() {
        Ok(dir) => dir,
        Err(error) => { eprintln!("Каталог данных службы недоступен: {error}"); return; }
    };
    fs::create_dir_all(&dir).ok();
    fs::write(dir.join(VERSION_FILE), RELAY_VERSION.to_string()).ok();
}

/// Startup keeps serving DNS if only its diagnostic generation stamp failed;
/// the error is visible through the existing relay log and standard error.
#[cfg(target_os = "windows")]
pub fn record_version() {
    use crate::windows_coordinator::windows_installation as owner;
    let source = match crate::gate::prepare_runtime_metadata(owner::UserMetadataField::RelayVersionProjection) {
        Ok(source) => source,
        Err(error) => { let message = format!("relay generation metadata failed: {error}"); eprintln!("{message}"); log(&message); return; }
    };
    let actual = match owner::publish_user_metadata(owner::UserMetadataField::RelayVersionProjection,
        &version_path(), RELAY_VERSION.to_string().as_bytes()) {
        Err(error) => Err(crate::gate::retain_runtime_metadata_failure(error, source.clone())),
        Ok(mut publication) => match crate::gate::recheck_runtime_metadata_source(&source) {
            Err(cause) => Err(crate::gate::retain_runtime_metadata_failure(publication.into_failure("scalar-image-recheck", cause, true, false), source.clone())),
            Ok(()) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| publication.settle())) {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(cause)) => Err(crate::gate::retain_runtime_metadata_failure(publication.into_failure("scalar-settlement", cause, false, false), source.clone())),
            Err(payload) => {
                let failure = publication.into_failure("scalar-settlement-unwind", "scalar settlement unwound".into(), true, false);
                let message = crate::gate::retain_runtime_metadata_failure(failure, source);
                eprintln!("relay generation metadata failed: {message}");
                log(&message);
                std::panic::resume_unwind(payload)
            }
            },
        },
    };
    if let Err(error) = actual {
        let message = format!("relay generation metadata failed: {error}");
        eprintln!("{message}");
        log(&message);
    }
}

/// The relay generation currently installed. `0` for a relay old enough not to
/// have written one - which is exactly the case worth reporting.
pub fn installed_version() -> u32 {
    let raw = checked_log_dir().ok().and_then(|dir| fs::read_to_string(dir.join(VERSION_FILE)).ok());
    parse_version(raw.as_deref())
}

/// Anything unreadable counts as the oldest possible relay: the file is written
/// by us and never edited, so a value that will not parse means something else
/// wrote it, and "reinstall" is the right answer to that too.
fn parse_version(raw: Option<&str>) -> u32 {
    raw.and_then(|s| parse_version_checked(s).ok()).unwrap_or(0)
}

fn parse_version_checked(raw: &str) -> Result<u32, String> {
    raw.trim().parse().map_err(|e| format!("invalid relay version: {e}"))
}

/// Fresh version evidence: only an absent version file means a pre-versioned relay.
#[cfg(not(target_os = "windows"))]
pub(crate) fn checked_installed_version() -> Result<u32, String> {
    match fs::read_to_string(checked_log_dir()?.join(VERSION_FILE)) {
        Ok(raw) => parse_version_checked(&raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(format!("read relay version: {e}")),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn checked_installed_version_observation() -> Result<Option<u32>, String> {
    match fs::read_to_string(version_path()) {
        Ok(raw) => parse_version_checked(&raw).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read relay version: {error}")),
    }
}
#[cfg(target_os = "windows")]
pub(crate) fn checked_installed_version() -> Result<u32, String> {
    checked_installed_version_observation().map(|value| value.unwrap_or(0))
}

/// Local wall-clock `HH:MM:SS` for a log line.
///
/// Local, not UTC: the only reader is a user comparing the log against the moment
/// their editor showed an error, and asking them to do timezone arithmetic on a
/// bug report is how a report becomes useless. Empty where there is no local
/// clock to read (`utils::local_clock`), which costs a stamp rather than a line.
fn stamp() -> String {
    crate::utils::local_clock().map_or_else(String::new, |c| c.hms())
}

/// Best-effort logging: a background process with no console is otherwise
/// impossible to diagnose. Truncated rather than rotated - nothing here is
/// worth keeping across sessions.
///
/// Every line is stamped. Without it a log says what happened but never *when*,
/// so a torn connection cannot be lined up against the error the user saw - which
/// is precisely the question a bug report asks.
fn log(line: &str) {
    // Never from a test. The file is the *installed* relay's log, and a unit test
    // exercising `health` or `routes` used to append lines like «тест отложен на
    // 5 мин» to it on the developer's machine - which the window's «Сохранить
    // отчёт» now puts in a support file (G18's other half).
    if cfg!(test) {
        return;
    }
    let (note, write_line) = collapse_repeat(line);
    if note.is_none() && !write_line {
        return;
    }
    let path = match checked_log_path() {
        Ok(path) => path,
        Err(error) => { eprintln!("Журнал службы недоступен: {error}"); return; }
    };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).ok();
    }
    if fs::metadata(&path).map_or(false, |m| m.len() > LOG_LIMIT_BYTES) {
        fs::remove_file(&path).ok();
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        // One write per line. `writeln!` with arguments issues a write per
        // piece, and an append is atomic only per write, so two threads (or two
        // processes) logging at once interleaved into lines like
        // «16:48:2616:48:26 PASSTHROUGH … PASSTHROUGH …» - seen in reports from
        // both platforms.
        let at = stamp();
        let mut entry = String::new();
        if let Some(note) = note {
            entry.push_str(&format!("{} {}\n", at, note));
        }
        if write_line {
            entry.push_str(&format!("{} {}\n", at, line));
        }
        f.write_all(entry.as_bytes()).ok();
    }
}

/// How long a line has to repeat within to be counted rather than written.
const REPEAT_WINDOW: Duration = Duration::from_secs(30);
/// …and how many repeats are counted before the tally is written anyway, so a
/// problem repeating forever is never silent.
const REPEAT_RUN: u32 = 50;

/// Collapses a run of one identical line into a count.
///
/// The log holds 64 KB and the report shows its last 60 lines, so a burst of
/// one message costs exactly the minutes a report is about: a field report
/// (2026-09-21) spent fifteen of its sixty visible lines on the same
/// «напрямую …: имя не разрешается» inside a single second, and the route
/// switch that followed was off the top of it.
///
/// Returns the tally line to write first, if any, and whether `line` itself is
/// written. The *first* of a run always goes out at once - the news is that it
/// happened, and a delayed first line is a log that lies about when.
fn collapse_repeat(line: &str) -> (Option<String>, bool) {
    static RUN: Mutex<Option<(String, u32, Instant)>> = Mutex::new(None);
    let tally = |n: u32| format!("↑ то же самое ещё {} раз", n);
    let Ok(mut g) = RUN.lock() else {
        return (None, true);
    };
    let same = g
        .as_ref()
        .is_some_and(|(prev, _, at)| prev == line && at.elapsed() < REPEAT_WINDOW);
    if same {
        let mut flush = None;
        if let Some((_, n, at)) = g.as_mut() {
            *n += 1;
            *at = Instant::now();
            if *n >= REPEAT_RUN {
                flush = Some(tally(*n));
                *n = 0;
            }
        }
        return (flush, false);
    }
    let held = g.as_ref().map_or(0, |(_, n, _)| *n);
    *g = Some((line.to_string(), 0, Instant::now()));
    ((held > 0).then(|| tally(held)), true)
}

/// The only way a failed start can be reported: the console is gone by then.
pub fn log_fatal(message: &str) {
    log(&format!("fatal: {}", message));
}

#[cfg(windows)]
pub(crate) fn log_gate_failure(message: &str) {
    log(&format!("gate report persistence failed: {message}"));
}

/// The proxy shares the relay's log - it runs in the same process, and one file
/// is what makes a resolve and the connection that followed it readable together.
pub fn log_proxy(message: &str) {
    log(&format!("proxy        {}", message));
}

/// Who answered a race that produced no substitution, and whether a reference
/// was available to judge it. Only logged on that path: it is the one where the
/// interesting question is which provider was missing, and it is rare enough
/// that a line per occurrence is affordable.
pub fn log_race(name: &str, heard: &[&str], had_reference: bool) {
    log(&format!(
        "race         {} heard [{}]{}",
        name,
        heard.join(", "),
        if had_reference { "" } else { " (no reference)" }
    ));
}

fn invalidate_interface() {
    if let Ok(mut c) = EGRESS_CACHE.lock() {
        *c = None;
    }
}

enum IspObservation { Cached(u32), Unsupported, Command(crate::command_lifetime::PendingCommand), Unavailable(String) }

fn prepare_isp_interface(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> IspObservation {
    if cfg!(target_os = "macos") {
        return IspObservation::Cached(net::pin_interface());
    }
    if egress::observation_support() == egress::ObservationSupport::Unsupported {
        return IspObservation::Unsupported;
    }
    if let Ok(cache) = EGRESS_CACHE.lock() {
        if let Some((idx, at, good_for)) = *cache {
            if at.elapsed() < good_for {
                return IspObservation::Cached(idx);
            }
        }
    }
    match root.begin("ISP observation") {
        Ok(call) => IspObservation::Command(call),
        Err(error) => IspObservation::Unavailable(error),
    }
}

fn receive_isp_interface(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, observation: IspObservation) -> u32 {
    // 0 means "use the routing table" - the right degradation when there is no
    // physical egress to name, but a poor thing to remember for long: at logon
    // the network is often simply not up yet, and caching the miss would leave
    // half an hour of unsubstituted answers.
    let (idx, good_for) = match observation {
        IspObservation::Cached(idx) => return idx,
        IspObservation::Unsupported => return 0,
        IspObservation::Command(call) => match call.with_result(egress::detect) {
            Ok(Some(eg)) => (eg.if_index, EGRESS_TTL),
            Ok(None) => (0, EGRESS_RETRY),
            Err(error) => { log(&format!("наблюдение интерфейса недоступно: {error}")); (0, EGRESS_RETRY) },
        },
        IspObservation::Unavailable(error) => { log(&format!("наблюдение интерфейса недоступно: {error}")); (0, EGRESS_RETRY) },
    };
    root.receive();
    if let Ok(mut cache) = EGRESS_CACHE.lock() {
        *cache = Some((idx, Instant::now(), good_for));
    }
    idx
}

fn isp_interface(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> u32 {
    receive_isp_interface(root, prepare_isp_interface(root))
}

/// Relays one query and reports which provider answered and whether that answer
/// was actually substituted.
///
/// The choice is no longer a constant. A provider can drop a name from its
/// list without any error - the query still resolves, just to the genuine
/// Google address - so every provider is asked at once and compared against a
/// reference resolver that substitutes nothing. See `resolvers`.
fn relay(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, observation: IspObservation, query: &[u8]) -> Option<(Vec<u8>, &'static str, resolvers::Verdict)> {
    relay_with_work(root, observation, query, None).expect("legacy resolver launch behavior")
}

fn relay_with_work(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, observation: IspObservation, query: &[u8], work: Option<&resolvers::ResolverWork>)
    -> Result<Option<(Vec<u8>, &'static str, resolvers::Verdict)>, String> {
    let if_index = receive_isp_interface(root, observation);
    let resolved = match work { Some(work) => resolvers::resolve_best_owned(query, if_index, work)?, None => resolvers::resolve_best(query, if_index) };
    match resolved {
        Some(hit) => Ok(Some(hit)),
        None => {
            // Nobody answered: the interface may have gone away under us, so
            // the next query re-detects instead of retrying a dead one.
            invalidate_interface();
            Ok(None)
        }
    }
}

/// How often the routed names are re-resolved in the background.
///
/// Half the substituted TTL, so an entry is always well inside the window the
/// answer cache will serve it from and a client query never finds it expired.
/// Cheap: four names, one upstream query each, once every quarter minute.
pub(crate) const WARM_EVERY: Duration = Duration::from_secs(15);

/// Keeps a vetted answer ready for every routed name, forever.
///
/// The relay has about a second to answer before Windows asks the next
/// nameserver in the NRPT rule - which is a provider's own resolver, handing
/// out addresses that nothing has checked for liveness. A cold resolution does
/// not reliably fit in that second (race, then a liveness probe, and a provider
/// that goes quiet costs the whole timeout), and it does not have to: doing the
/// work on a timer instead means the client's query is answered from memory.
/// How often the user's own proxy, the built-in exits and the direct route are
/// re-timed while healthy. Rare, because a working route needs no supervision
/// and each probe is a real request. The relay is deliberately kept off this
/// clock - see the warm loop below for why.
const PROBE_HEALTHY_EVERY: Duration = Duration::from_secs(2 * 60);

/// Where the relay asks the routing table to send a packet, to notice a tunnel
/// coming up or going down between the full scans. Any public address works;
/// this one is only ever used as a route lookup, never contacted.
const ROUTE_PROBE_DEST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(8, 8, 8, 8);

/// How often the tunnel's exit country is re-read while a VPN stays up. A
/// VPN client can switch servers without the route table noticing anything.
const VPN_EXIT_EVERY: Duration = Duration::from_secs(30 * 60);

/// The tunnel's exit country, as last measured; empty when unknown.
static VPN_EXIT_COUNTRY: Mutex<String> = Mutex::new(String::new());
static MEASURING_EXIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Reads where the tunnel comes out - Cloudflare's trace over the default
/// route, which is the tunnel - and decides whether the `Vpn` route may be
/// offered. On a thread: it is a real HTTPS request, and the warm pass has
/// budgets of its own.
fn measure_vpn_exit() {
    use std::sync::atomic::Ordering;
    #[cfg(target_os = "macos")]
    let Some(generation) = routes::mac_vpn_generation() else { return; };
    if MEASURING_EXIT.swap(true, Ordering::SeqCst) {
        return;
    }
    let spawned = thread::Builder::new()
        .name("vpn-exit".to_string())
        .spawn(move || {
            let exit = upstream::machine_exit();
            let (country, permitted) = match &exit {
                Some((_, loc)) => (loc.clone(), Some(!upstream::region_is_blocked(loc))),
                None => (String::new(), None),
            };
            let publish = || {
                proxy::set_vpn_exit(permitted);
                if let Ok(mut c) = VPN_EXIT_COUNTRY.lock() {
                    *c = country.clone();
                }
            };
            #[cfg(target_os = "macos")]
            let received = routes::receive_mac_vpn_exit(generation, publish);
            #[cfg(not(target_os = "macos"))]
            let received = if net::tunnel_up() { publish(); true } else { false };
            if received {
                log(&match permitted {
                    Some(true) => format!(
                        "VPN выходит в {} — его можно использовать как маршрут",
                        country
                    ),
                    Some(false) => format!(
                        "VPN выходит в {} — там ошибка 400, этот маршрут не используется",
                        country
                    ),
                    None => "страну выхода VPN узнать не удалось".to_string(),
                });
            }
            MEASURING_EXIT.store(false, Ordering::SeqCst);
        });
    if spawned.is_err() {
        MEASURING_EXIT.store(false, Ordering::SeqCst);
    }
}

fn vpn_exit_country() -> String {
    VPN_EXIT_COUNTRY
        .lock()
        .map(|c| c.clone())
        .unwrap_or_default()
}

/// A fingerprint of the network the route table's evidence belongs to: which
/// adapter is the ISP link, which one the default route leaves through, and
/// whether that is a tunnel. Never 0 - that is the table's "not set yet".
fn network_fingerprint(isp: u32, best: Option<u32>, tunnel: bool) -> u64 {
    1 + ((isp as u64) << 33) + ((best.unwrap_or(0) as u64) << 1) + tunnel as u64
}

/// One bounded unit on the existing maintenance owner. The route owner retains
/// the cursor/queue, while the resolver owns the actual source witness.
fn maintain_dns_candidate_step(if_index: u32, allow_missing_defaults: bool, work: Option<&resolvers::ResolverWork>) -> Result<bool, String> {
    let policy = || if allow_missing_defaults { resolvers::DnsMissingPolicy::LegacyDefaults } else { resolvers::DnsMissingPolicy::RequireSettings };
    maintain_dns_candidate_step_with(if_index, allow_missing_defaults, work,
        || resolvers::current_witness(policy()), resolvers::current_candidates,
        resolvers::discover_next, proxy::probe_dns_candidate, log_proxy)
}

fn candidate_probe_outcome(result: &Result<proxy::CandidateProbe, String>) -> String {
    match result {
        Ok(proxy::CandidateProbe::Reachable(_)) => "reachable".to_string(),
        Ok(proxy::CandidateProbe::Refused) => "refused".to_string(),
        Err(error) => format!("failed: {error}"),
    }
}

#[cfg(target_os = "macos")]
fn observe_mac_egress(
    root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>,
    previous: &mut Option<crate::command_lifetime::PendingCommand>,
) -> Result<Option<crate::netif::MacRelayEgress>, String> {
    if previous.as_ref().is_some_and(crate::command_lifetime::PendingCommand::pending) {
        return Ok(None);
    }
    let (observation, command) = root.call_with_outcome("Mac relay egress observation", |owner| {
        egress::detect_mac_relay(owner, ROUTE_PROBE_DEST)
    })?;
    root.receive();
    *previous = command.pending().then_some(command);
    observation
}

fn maintain_dns_candidate_step_with<W, K, D, P, L>(if_index: u32, allow_missing_defaults: bool, work: Option<&resolvers::ResolverWork>,
    current_witness: W, current_candidates: K, discover: D, probe: P, report: L) -> Result<bool, String>
where
    W: Fn() -> Result<resolvers::DnsSourceWitness, resolvers::DnsSourceError>,
    K: Fn(&resolvers::DnsSourceWitness) -> Result<Vec<resolvers::DnsCandidate>, resolvers::DnsSourceError>,
    D: Fn(&resolvers::DnsSourceWitness, &str, &mut resolvers::DnsDiscoveryCursor, u32, Duration, Option<&resolvers::ResolverWork>) -> Result<resolvers::DiscoveryStep, resolvers::DnsSourceError>,
    P: Fn(&str, Ipv4Addr, u32, Duration) -> Result<proxy::CandidateProbe, String>,
    L: Fn(&str),
{
    if work.is_some_and(resolvers::ResolverWork::is_cancelled) { return Err("DNS candidate maintenance cancelled before step".into()); }
    let witness = match current_witness() {
        Ok(witness) => witness,
        Err(error) => { routes::suspend_dns_maintenance(); return Err(format!("DNS source settings unavailable: {error:?}")); }
    };
    for host in crate::gate_hosts::public_dns_hosts() {
        routes::begin_dns_maintenance(host, &witness, allow_missing_defaults)?;
    }
    let host = routes::dns_maintenance_host()?;
    let generation = routes::begin_dns_maintenance(host, &witness, allow_missing_defaults)?;
    let known = match current_candidates(&witness) {
        Ok(known) => known,
        Err(error) => { routes::suspend_dns_maintenance(); return Err(format!("DNS source snapshot unavailable: {error:?}")); }
    };
    if !routes::seed_dns_candidates(host, generation, known)? { return Ok(routes::dns_has_pending_maintenance()); }
    match routes::take_dns_maintenance(host, generation)? {
        Some(routes::DnsMaintenanceWork::Discover(mut cursor)) => {
            let result = discover(&witness, host, &mut cursor, if_index, proxy::DIRECT_OPEN_BUDGET, work);
            let exhausted = matches!(&result, Ok(step) if matches!(step.state, resolvers::DiscoveryState::Exhausted))
                || matches!(&result, Err(resolvers::DnsSourceError::NoReference | resolvers::DnsSourceError::Deadline));
            if !routes::receive_dns_discovery(host, generation, cursor, exhausted)? { return Ok(routes::dns_has_pending_maintenance()); }
            match result {
                Ok(step) => {
                    let fresh = match current_witness() {
                        Ok(fresh) => fresh,
                        Err(error) => { routes::suspend_dns_maintenance(); return Err(format!("DNS settings unavailable after discovery: {error:?}")); }
                    };
                    if fresh == witness { routes::seed_dns_candidates(host, generation, step.candidates)?; }
                }
                Err(resolvers::DnsSourceError::NoAnswer) => report("DNS candidate source did not answer; next source remains pending"),
                Err(resolvers::DnsSourceError::SourceTimeout) => report("DNS candidate source timed out; next source remains pending"),
                Err(resolvers::DnsSourceError::NoReference) => report("DNS candidate reference unavailable; no source proof was recorded"),
                Err(resolvers::DnsSourceError::Deadline) => report("DNS candidate discovery step reached its deadline"),
                Err(error) => { routes::abandon_dns_maintenance(host, generation); return Err(format!("DNS source discovery failed: {error:?}")); }
            }
        }
        Some(routes::DnsMaintenanceWork::Probe(candidate)) => {
            if work.is_some_and(resolvers::ResolverWork::is_cancelled) { return Err("DNS candidate maintenance cancelled before probe".into()); }
            match resolvers::source_is_current(&candidate, &witness) {
                Ok(true) => {}
                Ok(false) => return Ok(routes::dns_has_pending_maintenance()),
                Err(error) => { routes::suspend_dns_maintenance(); return Err(format!("DNS candidate source check failed: {error:?}")); }
            }
            let result = probe(host, candidate.ip, if_index, proxy::DIRECT_OPEN_BUDGET);
            if work.is_some_and(resolvers::ResolverWork::is_cancelled) {
                let outcome = candidate_probe_outcome(&result);
                return Err(format!("DNS candidate probe completed after cancellation: {outcome}"));
            }
            let fresh = match current_witness() {
                Ok(fresh) => fresh,
                Err(error) => { routes::suspend_dns_maintenance(); return Err(format!("DNS settings unavailable after probe: {error:?}")); }
            };
            let current = match resolvers::source_is_current(&candidate, &fresh) {
                Ok(current) => current,
                Err(error) => { routes::suspend_dns_maintenance(); return Err(format!("DNS candidate source check failed after probe: {error:?}")); }
            };
            if fresh == witness && current {
                if work.is_some_and(resolvers::ResolverWork::is_cancelled) { return Err("DNS candidate maintenance cancelled before publication".into()); }
                if let Err(error) = &result { report(&format!("DNS candidate qualification failed: {error}")); }
                let outcome = candidate_probe_outcome(&result);
                let publish = || routes::publish_dns_candidate(host, generation, candidate, result);
                match work {
                    Some(work) => match work.with_open(publish) {
                        Ok(publication) => { publication?; }
                        Err(error) => return Err(format!("DNS candidate probe completed before publication was rejected: {outcome}; {error}")),
                    },
                    None => { publish()?; }
                }
            }
        }
        Some(routes::DnsMaintenanceWork::Complete) => routes::finish_dns_maintenance(host, generation),
        None => return Err("DNS maintenance cursor is already owned".into()),
    }
    Ok(routes::dns_has_pending_maintenance())
}

fn warm_forever(root: std::sync::Arc<crate::command_lifetime::CommandLifetime>) {
    routes::register_dns_maintenance_thread();
    let mut since_upstream = PROBE_HEALTHY_EVERY;
    let mut since_exits = PROBE_HEALTHY_EVERY;
    let mut since_direct = PROBE_HEALTHY_EVERY;
    let mut since_vpn = VPN_CHECK_EVERY;
    let mut since_exit_check = Duration::ZERO;
    let mut last_best: Option<u32> = None;
    let mut tunnel_observed = None;
    let mut command_result = Ok(());
    let mut next_regular = Instant::now() + WARM_EVERY;
    #[cfg(target_os = "macos")]
    let (mut next_mac_observation, mut mac_probe) = (Instant::now(), None);
    loop {
        if root.receive_role_result(&mut command_result) {
            if let Err(error) = &command_result { log_proxy(&format!("результат команды службы: {error}")); }
        }
        // One small record per pass, for a window that is another process and
        // can otherwise only read the log meant for a person (P29). **First** in
        // the pass, not last: a pass opens with a PowerShell VPN check and runs
        // several probes with budgets of their own, so written at the end the
        // file would not exist for the first tens of seconds of the relay's life
        // - which is exactly when a user has just switched the bypass on and is
        // watching the window. The leader is the one the last pass settled on,
        // which is the one in force right now.
        let exit_country = vpn_exit_country();
        gate::publish(gate::Now {
            route: routes::leader().map(|k| k.label()),
            forced_for: resolvers::substitution_forced_for(),
            stood_down: resolvers::tunnel_carries_client(),
            loopback: loopback::active(),
            tunnel: tunnel_observed,
            vpn_exit: if tunnel_observed == Some(true) { &exit_country } else { "" },
            routes: routes::rows(|k| proxy::route_usable(k, ROUTE_PROBE_HOST)),
        });
        #[cfg(target_os = "macos")]
        if Instant::now() >= next_mac_observation {
            let observation = match observe_mac_egress(&root, &mut mac_probe) {
                Ok(observation) => observation,
                Err(error) => { log(&format!("наблюдение интерфейса macOS недоступно: {error}")); None },
            };
            let observed_tunnel = observation.as_ref().map(crate::netif::MacRelayEgress::tunnel);
            match routes::set_mac_egress(observation) {
                Ok(changed) => {
                    tunnel_observed = observed_tunnel;
                    if changed {
                        resolvers::invalidate_witnessed_candidates();
                        if let Ok(mut country) = VPN_EXIT_COUNTRY.lock() { country.clear(); }
                        log_proxy("сеть изменилась — что работает, выясняется заново");
                    }
                    if tunnel_observed == Some(true) && proxy::vpn_exit().is_none() {
                        measure_vpn_exit();
                        since_exit_check = Duration::ZERO;
                    }
                }
                Err(error) => {
                    routes::suspend_dns_maintenance();
                    tunnel_observed = None;
                    log_proxy(&format!("состояние интерфейса macOS недоступно: {error}"));
                }
            }
            // Bounded candidate maintenance can make multiple passes without
            // sleeping. Observe on the regular warm cadence, never per candidate.
            next_mac_observation = Instant::now() + WARM_EVERY;
        }
        // One syscall, every pass: where the default route goes now. A change
        // is a VPN coming up or going down, or a different network - worth the
        // full scan right away rather than on the four-minute clock.
        let best = net::best_interface(ROUTE_PROBE_DEST);
        if best != last_best {
            if last_best.is_some() {
                invalidate_interface();
            }
            last_best = best;
            since_vpn = VPN_CHECK_EVERY;
        }
        // First, because everything below depends on it: when a tunnel carries
        // the client the relay stops substituting and answers as the tunnel's
        // own resolver would. The rules cannot be removed from here - the task
        // runs at `RunLevel Limited` and NRPT needs an administrator - so the
        // relay changes what it *answers* instead, which needs no privilege and
        // reaches the same place. Menu 1 removes the rules outright on the next
        // elevated run (`dns::refresh_pinned_hosts`).
        if since_vpn >= VPN_CHECK_EVERY && egress::observation_support() == egress::ObservationSupport::Supported {
            // A tunnel holding the default route no longer takes the bypass down
            // (D25): the client's gate connections come to us on loopback, so the
            // tunnel can only ever catch *our* connections - and those are pinned
            // to the ISP link while it is up, the same way every resolver query
            // already was (I4). The user's VPN is still used, as a route of its
            // own (`routes::Kind::Vpn`), whenever it exits somewhere the gate
            // does not apply.
            let update = (|| -> Result<(), String> {
            let eg = root.call("VPN observation", egress::detect)??;
            let tunnel = eg.as_ref().is_some_and(|e| e.vpn_active);
            tunnel_observed = Some(tunnel);
            let was = net::tunnel_up();
            // The stand-down survives for exactly one case: the loopback door is
            // down, so the client dials Google itself, and it is measured inside
            // the tunnel. Then the tunnel is its only way out, and a substituted
            // address reached from the tunnel's exit is refused by the RU-only
            // providers (N25) - so the relay answers as the tunnel would (D13's
            // old rule, now the fallback D25 leaves in place).
            let (stand_down, _) = if tunnel && !loopback::active() {
                root.call("VPN client observation", |owner| egress::vpn_verdict(owner, eg.as_ref()))??
            } else {
                (false, egress::ClientEgress::Unknown)
            };
            net::set_pin_interface(match &eg { Some(e) if tunnel => e.if_index, _ => 0 });
            if stand_down != resolvers::tunnel_carries_client() {
                log(if stand_down {
                    "Antigravity ходит через VPN мимо обхода — адреса отдаются как у VPN"
                } else {
                    "подмена адресов снова включена"
                });
            }
            resolvers::set_vpn_active(stand_down);
            if tunnel != was {
                log(if tunnel {
                    "VPN поднят — соединения службы с сервисами разблокировки идут мимо него, через провайдера"
                } else {
                    "VPN отключён"
                });
            }
            if tunnel && (!was || proxy::vpn_exit().is_none()) {
                measure_vpn_exit();
                since_exit_check = Duration::ZERO;
            }
            if !tunnel {
                proxy::set_vpn_exit(None);
                if let Ok(mut c) = VPN_EXIT_COUNTRY.lock() {
                    c.clear();
                }
            }
            Ok(())
            })();
            if let Err(error) = update { tunnel_observed = None; log(&format!("наблюдение VPN недоступно: {error}")); }
            since_vpn = Duration::ZERO;
        }
        if net::tunnel_up() && since_exit_check >= VPN_EXIT_EVERY {
            measure_vpn_exit();
            since_exit_check = Duration::ZERO;
        }
        let egress = isp_interface(&root);
        // Not while the ISP interface is unknown: `isp_interface` answers 0 for
        // half a minute after a failed detection, and taking that for a new
        // network wiped every bench - and put back first the route the gate had
        // just refused - twice per hiccup.
        if !cfg!(target_os = "macos") && egress != 0 && routes::set_context(network_fingerprint(egress, best, net::tunnel_up())) {
            log_proxy("сеть изменилась — что работает, выясняется заново");
        }
        let candidate_pending = match maintain_dns_candidate_step(egress, true, None) {
            Ok(pending) => pending,
            Err(error) => { log_proxy(&format!("DNS candidate maintenance: {error}")); false }
        };
        // Every bounded candidate step returns through this loop's report and
        // observation pass; regular health work still runs on its existing clock.
        if candidate_pending && Instant::now() < next_regular { continue; }
        // The client logs are watched on a thread of their own every two
        // seconds (`watch_client_logs`), not here: a refusal costs the user
        // every request until it is answered, and a warm pass is fifteen
        // seconds plus its probes.
        // Candidate preparation owns this serial path. Ordinary DNS remains
        // on demand; an unrelated full warm/ensure must not delay heartbeat.
        // The relay is somebody else's server, so it is the one route we never
        // probe on a timer. A health check every two minutes, from every machine
        // running this tool, is precisely the `handshake_completed` beacon a relay
        // operator can count and attribute (kb/rivals.md) - and the "considerate
        // guest" rule the built-in exits follow just below applies with far more
        // force to a route we do not own. Left unmeasured, the route table already
        // treats it as a last resort (an unmeasured route sorts after every
        // measured one); it is touched unbidden only to lift a bench a real
        // failure set, so a transient fault is not made permanent.
        if proxy::relay_is_benched() {
            proxy::probe_relay();
        }
        // The user's own proxy is checked the same way and for the same reason:
        // it must be stood down before a request meets it, and picked back up
        // the moment it works again - which is what they asked for when they
        // gave us one.
        match upstream::capture_own() {
            Ok(Some(own)) if own.is_benched() || since_upstream >= PROBE_HEALTHY_EVERY => {
                let _ = own.probe(false);
                since_upstream = Duration::ZERO;
            }
            Err(error) => log_proxy(&format!("own proxy observation failed: {error}")),
            _ => (),
        }
        // The built-in exits are checked on the same clock in *both* states, and
        // that is the one place this deviates from the rule above. Probing a
        // benched route every pass is right when the alternative is the seven-second
        // DNS route; these sit above the relay, so what a slower revival costs is a
        // route that is merely quicker - and the cost of the other choice is a
        // connection every fifteen seconds, from every machine running this tool,
        // to somebody's free proxy. Being a considerate guest is what keeps the
        // route working at all.
        if since_exits >= PROBE_HEALTHY_EVERY {
            proxy::probe_exits();
            crate::group::probe_health();
            since_exits = Duration::ZERO;
        }
        // The direct route is timed on the same clock as the others, so the
        // route table compares like with like. Not more often while penalised:
        // a region penalty is a clock, and no measurement shortens it.
        if since_direct >= PROBE_HEALTHY_EVERY {
            proxy::probe_vpn();
            since_direct = Duration::ZERO;
        }
        routes::refresh_leader(|k| proxy::route_usable(k, ROUTE_PROBE_HOST));
        next_regular = Instant::now() + WARM_EVERY;
        let elapsed = if !candidate_pending {
            let started = Instant::now();
            thread::park_timeout(WARM_EVERY);
            started.elapsed()
        } else { WARM_EVERY };
        since_upstream += elapsed;
        since_exits += elapsed;
        since_direct += elapsed;
        since_vpn += elapsed;
        since_exit_check += elapsed;
    }
}

/// How often the client logs are looked at. Two seconds: a user who sees the
/// error and presses "send" again should find the route already switched.
const LOG_WATCH_EVERY: Duration = Duration::from_secs(2);

/// The one place the region 400 and the model answer are written down is the
/// client's own log (`ls_log`). Looked at every two seconds; reading a file's
/// tail when it has not grown costs one `metadata`.
fn watch_client_logs(root: std::sync::Arc<crate::command_lifetime::CommandLifetime>) {
    loop {
        thread::sleep(LOG_WATCH_EVERY);
        root.receive();
        // The user switched their own proxy off: its open tunnels go too. A pooled
        // client connection would otherwise keep using it for as long as it lives.
        match upstream::capture_own() {
            Ok(None) => { if let Err(error) = routes::cut_absent_own() { log_proxy(&error); } },
            Err(error) => log_proxy(&format!("own proxy observation failed: {error}")),
            Ok(Some(_)) => (),
        }
        let hits = ls_log::poll();
        if !hits.is_empty() {
            answer_log(&root, &hits);
        }
    }
}

/// The name the route table is refreshed against: the gate host the IDE uses.
const ROUTE_PROBE_HOST: &str = "daily-cloudcode-pa.googleapis.com";

/// Answers what the client logs say: a refusal benches the route that carried
/// it and closes its tunnels, an answer proves the route that carried it.
///
/// The older of the two is handled first, so a pass that saw a refusal and then
/// an answer on the route that replaced it ends with the right route proven -
/// and one that saw an answer and then a refusal ends with it benched.
///
/// Nothing is attributed on a guess: `routes::attribute` names the route whose
/// gate tunnel was open around the line's own stamp, and with none open the
/// refusal is one the client made without us (it dialled Google itself), which
/// no route switch can help with - so the DNS layer re-races instead, the only
/// lever that reaches such a client.
#[cfg(test)]
pub(crate) fn test_answer_log(hits: &[(std::path::PathBuf, ls_log::Tally)]) {
    let root = std::sync::Arc::new(crate::command_lifetime::CommandLifetime::default());
    answer_log(&root, hits);
    root.close_admission();
    assert!(matches!(root.receive(), crate::command_lifetime::Receiving::Ready));
}

fn answer_log(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, hits: &[(std::path::PathBuf, ls_log::Tally)]) {
    let signals: Vec<_> = hits.iter().flat_map(|(_, tally)| tally.direct_signals.iter().cloned()).collect();
    for effect in routes::receive_direct_batch(&signals) {
        match effect {
            routes::DirectBatchEffect::NoAction(reason) => log_proxy(&format!("Direct: событие не применено: {reason}")),
            routes::DirectBatchEffect::StateChanged => {}
            routes::DirectBatchEffect::Protected => log_proxy("Direct: защищённый поток сохранён"),
            routes::DirectBatchEffect::AlreadyClosed => log_proxy("Direct: исходное соединение уже закрыто"),
            routes::DirectBatchEffect::Shutdown { client, upstream } => {
                let describe = |side| match side {
                    routes::ShutdownSide::Succeeded => "shutdown подтверждён".to_string(),
                    routes::ShutdownSide::Missing => "удерживаемый сокет отсутствует".to_string(),
                    routes::ShutdownSide::Failed(error) => format!("ошибка shutdown: {error}"),
                };
                log_proxy(&format!("Direct: клиент: {}; сервер: {}", describe(client), describe(upstream)));
            }
        }
    }
    let mut refusals = 0usize;
    let mut answers = 0usize;
    let mut refused_ago: Option<Duration> = None;
    let mut answered_ago: Option<Duration> = None;
    let mut refused_host: Option<String> = None;
    let mut answered_host: Option<String> = None;
    let mut refused_endpoint: Option<ls_log::EndpointEvent> = None;
    let mut answered_endpoint: Option<ls_log::EndpointEvent> = None;
    let mut drops = 0usize;
    let mut dropped_ago: Option<Duration> = None;
    let mut dropped_host: Option<String> = None;
    for (path, t) in hits {
        let file = path
            .file_name()
            .map_or_else(String::new, |f| f.to_string_lossy().into_owned());
        if t.refusals > 0 {
            // The host, when the log named one: a refusal about a name we do
            // not route at all is a different story from one on a gate host,
            // and the line said neither (three field reports, 2026-09-21).
            log_proxy(&format!(
                "региональный отказ x{} в {}{} — Antigravity упёрся в гейт",
                t.refusals,
                file,
                t.refused_host
                    .as_deref()
                    .map_or_else(String::new, |h| format!(" ({h})"))
            ));
        }
        refusals += t.refusals;
        answers += t.answers;
        drops += t.drops;
        if t.dropped_ago.is_some() && newest(dropped_ago, t.dropped_ago) == t.dropped_ago {
            dropped_host = t.dropped_host.clone();
        }
        dropped_ago = newest(dropped_ago, t.dropped_ago);
        if t.refused_ago.is_some() && newest(refused_ago, t.refused_ago) == t.refused_ago {
            refused_host = t.refused_host.clone();
        }
        if t.answered_ago.is_some() && newest(answered_ago, t.answered_ago) == t.answered_ago {
            answered_host = t.answered_host.clone();
        }
        refused_ago = newest(refused_ago, t.refused_ago);
        answered_ago = newest(answered_ago, t.answered_ago);
        ls_log::merge_endpoint_event(&mut refused_endpoint, t.refused_endpoint.clone());
        ls_log::merge_endpoint_event(&mut answered_endpoint, t.answered_endpoint.clone());
    }
    let refused_endpoint_host = refused_endpoint.as_ref().filter(|event| Some(event.age) == refused_ago).and_then(|event| event.host.as_deref());
    let answered_endpoint_host = answered_endpoint.as_ref().filter(|event| Some(event.age) == answered_ago).and_then(|event| event.host.as_deref());
    // Only an event that can be placed in time is acted on. A line whose stamp
    // will not parse, or one older than the tunnels are remembered, would be
    // pinned on whatever route is open *now* - and bench a route that never saw
    // it (review finding before 2.14.0_1).
    let when = |ago: Option<Duration>| {
        ago.filter(|a| *a <= routes::TUNNEL_MEMORY)
            .and_then(|a| Instant::now().checked_sub(a))
    };
    let refusal = (refusals > 0).then(|| when(refused_ago)).flatten();
    let answer = (answers > 0).then(|| when(answered_ago)).flatten();
    let drop = (drops > 0).then(|| when(dropped_ago)).flatten();
    match (refusal, answer) {
        (Some(r), Some(a)) if a < r => {
            on_answers(answers, a, answered_host.as_deref(), answered_endpoint_host);
            on_refusals(root, refusals, r, refused_host.as_deref(), refused_endpoint_host);
        }
        (r, a) => {
            if let Some(r) = r {
                on_refusals(root, refusals, r, refused_host.as_deref(), refused_endpoint_host);
            }
            if let Some(a) = a {
                on_answers(answers, a, answered_host.as_deref(), answered_endpoint_host);
            }
        }
    }
    // After the answers and refusals: an answer older than the drop must not
    // wipe the streak the drop is about to add to.
    if let Some(d) = drop {
        on_drops(drops, d, dropped_host.as_deref(), answer.is_some_and(|a| a > d));
    }
}

/// Consecutive failed generation attempts the connection died under, with no
/// model answer between. Reset by an answer.
static DROP_STREAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A drop this many attempts in a row moves the route; fewer is the client's
/// own retry (4 s later) doing what it should.
pub(crate) const DROP_BENCH_AT: usize = 2;

/// The connection died under a generation request (EOF): once, the client's
/// own retry is the right answer - a pooled connection reaped, a backend
/// restart - and the same route is fine. Twice in a row with no answer in
/// between, the route is accepting the connection and closing on the request,
/// and retrying on it is what kept a client failing for twenty minutes
/// (2026-10-10): it is put behind the others, and the next dial goes elsewhere.
fn on_drops(count: usize, at: Instant, host: Option<&str>, answered_after: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    let carried = match routes::receive_log_feedback(at, host, None, None) {
        routes::LogFeedback::Direct { .. } => { log_proxy("обрыв Direct не меняет общий рейтинг без достоверной привязки к адресу"); return; }
        routes::LogFeedback::Ambiguous => { log_proxy("обрыв не отнесён к неоднозначному маршруту"); return; }
        routes::LogFeedback::Other(carried) => carried,
    };
    if answered_after {
        if let Some((routes::Kind::Own, tunnel)) = carried {
            if routes::own_attributed_drops(tunnel, 0, true).is_none() {
                log_proxy("обрыв отнесён к устаревшему или непроверенному собственному прокси");
            }
        } else { DROP_STREAK.store(0, Relaxed); }
        return;
    }
    let streak = if let Some((routes::Kind::Own, tunnel)) = carried {
        let Some(value) = routes::own_attributed_drops(tunnel, count, false) else {
            log_proxy("обрыв отнесён к устаревшему или непроверенному собственному прокси");
            return;
        };
        value
    } else { DROP_STREAK.fetch_add(count, Relaxed) + count };
    let label = carried.map_or("не наш", |(k, _)| k.label());
    if streak < DROP_BENCH_AT {
        log_proxy(&format!(
            "обрыв соединения при ответе модели (маршрут «{label}») — первый, повтор клиента идёт тем же путём"
        ));
        return;
    }
    let Some((kind, tunnel)) = carried else {
        log_proxy(&format!(
            "обрыв соединения при ответе модели {streak} раз подряд, но не через наш маршрут — переключать нечего"
        ));
        return;
    };
    let Some(result) = routes::bench_dropping_attributed(kind, tunnel) else {
        log_proxy("обрыв отнесён к устаревшему или непроверенному собственному прокси; текущий маршрут не изменён");
        return;
    };
    match result {
        Some(bench) => log_proxy(&format!(
            "маршрут «{}» рвёт соединение при ответе модели {streak} раз подряд — отложен на {} мин, следующее соединение пойдёт другим",
            kind.label(),
            bench.as_secs() / 60
        )),
        None => log_proxy(&format!(
            "обрыв соединения при ответе модели {streak} раз подряд по «{}», но маршрут уже отложен или недавно отвечал — не тронут",
            kind.label()
        )),
    }
}

fn newest(a: Option<Duration>, b: Option<Duration>) -> Option<Duration> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// One line about the connection a refusal came in on: the fact that decides
/// whether changing the route could possibly help.
///
/// Same connection as the one carrying an answer → the backend is turning
/// single requests down and every road leads to the same place. A sibling →
/// this is one pooled connection that went bad while another works, and closing
/// it is what makes the client dial a fresh one (D26). The log could not tell
/// the two apart, and three field reports (2026-09-21) turn on exactly that:
/// a route answering and refusing in the same minute, over and over.
fn connection_note(kind: routes::Kind, id: u64, shape: Option<routes::Shape>) -> String {
    let Some(s) = shape else {
        return format!("региональный отказ по соединению #{} «{}»", id, kind.label());
    };
    let open = routes::open_counts();
    let others: Vec<String> = routes::ALL
        .iter()
        .zip(open)
        .filter(|(_, n)| *n > 0)
        .map(|(k, n)| format!("{} {}", k.label(), n))
        .collect();
    let what = match s.answered_ago {
        Some(ago) => format!(
            "то же соединение, по которому шёл ответ ({} с назад, {} КБ)",
            ago.as_secs(),
            s.to_client / 1024
        ),
        None => format!(
            "ответов не нёс, открыто {} с, {} КБ",
            s.age.as_secs(),
            s.to_client / 1024
        ),
    };
    format!(
        "региональный отказ по соединению #{} «{}»: {}; открыто: {}",
        id,
        kind.label(),
        what,
        others.join(", ")
    )
}

fn on_refusals(_root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, count: usize, at: Instant, host: Option<&str>, endpoint_host: Option<&str>) {
    let carried = match routes::receive_log_feedback(at, host, endpoint_host, Some(false)) {
        routes::LogFeedback::Direct { .. } => {
            let action = "события Direct рассмотрены по отдельным записям; результат закрытия указан в журнале";
            log_proxy(action);
            gate::record_episode(count as u32, action.into(), None);
            return;
        }
        routes::LogFeedback::Ambiguous => {
            gate::record_episode(count as u32, "отказ не отнесён к неоднозначному маршруту".into(), None);
            return;
        }
        routes::LogFeedback::Other(carried) => carried,
    };
    let mut acted: Vec<String> = Vec::new();
    match carried {
        Some((kind, tunnel)) => {
            let shape = routes::tunnel_shape(tunnel);
            log_proxy(&connection_note(kind, tunnel, shape));
            let Some(blamed) = routes::blame_attributed(kind, tunnel) else {
                log_proxy("отказ отнесён к устаревшему или непроверенному собственному прокси; текущий маршрут не изменён");
                gate::record_episode(count as u32, "текущий маршрут не изменён: привязка прокси не получена".into(), Some(kind.label()));
                return;
            };
            // A route-wide bench is not enough for the group: the same server
            // would be picked again when it ends. Bench the server itself.
            if matches!(kind, routes::Kind::Group)
                && matches!(
                    blamed,
                    routes::Blamed::Benched(_) | routes::Blamed::AlreadyBenched
                )
            {
                crate::group::bench_current_server();
            }
            match blamed {
                routes::Blamed::Benched(penalty) => {
                    log_proxy(&format!(
                        "маршрут «{}» нёс региональный отказ — отложен на {}, его соединения закрыты",
                        kind.label(),
                        human_minutes(penalty)
                    ));
                    acted.push(format!(
                        "маршрут «{}» отложен на {}, следующее соединение пойдёт другим",
                        kind.label(),
                        human_minutes(penalty)
                    ));
                }
                // The route answered a moment ago, so the refusal is about the
                // request or about a connection the client made without us -
                // not about the road. Leaving its sockets alone is the point:
                // an answer arrives as a stream, and cutting them is how a user
                // loses one halfway through.
                routes::Blamed::Proven(ago) => {
                    log_proxy(&format!(
                        "маршрут «{}» нёс региональный отказ, но ответ модели был {} с назад — оставлен как есть",
                        kind.label(),
                        ago.as_secs()
                    ));
                    acted.push(format!(
                        "по «{}» модель отвечала {} с назад — маршрут и его соединения не тронуты",
                        kind.label(),
                        ago.as_secs()
                    ));
                }
                routes::Blamed::AlreadyBenched => {
                    acted.push(format!(
                        "соединения через «{}» закрыты — повтор пойдёт другим путём",
                        kind.label()
                    ));
                }
                // A tunnel that carried an answer is still open on this route,
                // so the answer is still coming through it. The route is not
                // touched at all, and nothing is on a clock: it ends when the
                // client closes (D32).
                routes::Blamed::Streaming { idle, to_client } => {
                    log_proxy(&format!(
                        "маршрут «{}» нёс региональный отказ, но по нему идёт ответ модели ({} КБ, байты {} с назад) — не тронут",
                        kind.label(),
                        to_client / 1024,
                        idle.as_secs()
                    ));
                    // The route is protected, and so is the connection carrying
                    // the answer. The connection the refusal actually arrived
                    // on is protected only when it is that same one. For a
                    // sibling D26 still holds, narrowed to it alone: closing it
                    // makes the client dial again, and the new connection is
                    // offered the table afresh, while the answer in flight
                    // never notices.
                    let same = shape.is_some_and(|s| s.answered_ago.is_some());
                    if same && shape.is_some_and(|s| s.idle < Duration::from_millis(1500)) {
                        acted.push(format!(
                            "по «{}» прямо сейчас идёт ответ модели — соединение #{} не тронуто",
                            kind.label(),
                            tunnel
                        ));
                    } else if routes::cut_refused_tunnel(tunnel) {
                        log_proxy(&format!(
                            "соединение #{} «{}» закрыто после регионального отказа — повтор пойдёт чистым маршрутом",
                            tunnel,
                            kind.label()
                        ));
                        acted.push(format!(
                            "отказавшее соединение #{} по «{}» закрыто, следующий запрос пойдёт чистым маршрутом",
                            tunnel,
                            kind.label()
                        ));
                    } else {
                        acted.push(format!(
                            "по «{}» сейчас идёт ответ модели — маршрут и его соединения не тронуты",
                            kind.label()
                        ));
                    }
                }
            }
        }
        // The client reached Google without us, from inside a tunnel the relay
        // was standing down for: that tunnel exits somewhere blocked, so the
        // substituted address is sent back through it for a while (D15's rule,
        // alive where the loopback door is down).
        None if resolvers::vpn_is_active() => {
            resolvers::force_substitution(FORCE_SUBSTITUTE_FOR);
            log("VPN-выход не снимает гейт — подмена включена принудительно на 30 мин");
            acted.push(
                "ваш VPN не снимает блокировку — подмена адресов включена поверх туннеля на 30 мин"
                    .to_string(),
            );
        }
        None => {
            // The client reached Google without us. The only lever that reaches
            // it is what the name resolves to, so that is re-raced now.
            resolvers::forget_names(dns::core_namespaces());
            for name in dns::core_namespaces() { routes::request_dns_refresh(name); }
            log("Antigravity обратился к Google мимо обхода — адреса подбираются заново");
            acted.push(
                "Antigravity обратился к Google мимо обхода — адреса подбираются заново"
                    .to_string(),
            );
        }
    }
    gate::record_episode(
        count as u32,
        acted.join("; "),
        carried.map(|(k, _)| k.label()),
    );
}

fn on_answers(count: usize, at: Instant, host: Option<&str>, endpoint_host: Option<&str>) {
    let (carried, direct_handled) = match routes::receive_log_feedback(at, host, endpoint_host, Some(true)) {
        routes::LogFeedback::Direct { applied, tunnel } => (applied.then_some((routes::Kind::Direct, tunnel)), true),
        routes::LogFeedback::Ambiguous => (None, true),
        routes::LogFeedback::Other(carried) => (carried, false),
    };
    if !direct_handled {
        if let Some((routes::Kind::Own, tunnel)) = carried {
            if routes::own_attributed_drops(tunnel, 0, true).is_none() {
                log_proxy("ответ отнесён к устаревшему или непроверенному собственному прокси");
            }
        } else { DROP_STREAK.store(0, std::sync::atomic::Ordering::Relaxed); }
    }
    if let Some((kind, tunnel)) = carried.filter(|_| !direct_handled) {
        if !routes::credit_attributed(kind, tunnel) {
            log_proxy("ответ отнесён к устаревшему или непроверенному собственному прокси; текущий маршрут не изменён");
        }
        // The tunnel as well as the route: while *it* is open the answer is
        // still arriving, and nothing is allowed to bench or cut it (D32).
        routes::credit_tunnel(tunnel);
        // A model answer is the one thing that settles whether the relay works,
        // so it clears the relay's dud streak and lifts any bench: a client fans
        // out several gate tunnels and the short ancillary ones the relay closes
        // early otherwise read as an outage and park a working relay on the slow
        // route (no-op in a build without the relay module).
        if kind == routes::Kind::Relay {
            crate::proxy::note_relay_answer();
        }
    }
    // One line a minute at most: a user in a long session produces an answer
    // every few seconds, and the log is 64 KB. What is held back is *counted*,
    // not dropped - a report showing one answer a minute while the user was
    // getting a dozen made the refusals look like the whole story - and a
    // change of route always prints, because that is the event worth seeing.
    struct AnswerLine {
        at: Option<Instant>,
        held: usize,
        route: Option<&'static str>,
    }
    static LAST_LINE: Mutex<AnswerLine> = Mutex::new(AnswerLine {
        at: None,
        held: 0,
        route: None,
    });
    let label = carried.map_or("не наш", |(k, _)| k.label());
    let mut lines: Vec<(usize, &'static str)> = Vec::new();
    if let Ok(mut g) = LAST_LINE.lock() {
        // A change of route ends the old line first: what was held back came
        // through the route it came through, and printing it under the new one
        // would credit a road that carried none of it.
        if let Some(prev) = g.route.filter(|prev| *prev != label) {
            if g.held > 0 {
                lines.push((std::mem::take(&mut g.held), prev));
            }
            g.at = None;
        }
        g.held += count;
        if g.at.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            g.at = Some(Instant::now());
            lines.push((std::mem::take(&mut g.held), label));
        }
        g.route = Some(label);
    }
    for (held, route) in lines {
        log_proxy(&format!(
            "модель ответила (x{}) — маршрут «{}»",
            held, route
        ));
    }
    gate::record_answer(carried.map(|(k, _)| k.label()));
}

/// How long one refusal through a tunnel the relay stood down for keeps
/// substitution forced on (D15, the fallback D25 leaves for a closed door).
const FORCE_SUBSTITUTE_FOR: Duration = Duration::from_secs(30 * 60);

/// «10 мин», «1 ч», «6 ч».
fn human_minutes(d: Duration) -> String {
    let mins = d.as_secs() / 60;
    if mins >= 60 && mins % 60 == 0 {
        format!("{} ч", mins / 60)
    } else {
        format!("{} мин", mins)
    }
}

/// How long the proxy listener is given to appear before the route is treated as
/// absent. Covers `proxy::bind_listener`'s own retries (15 s) with room to spare.
pub(crate) const PROXY_START_BUDGET: Duration = Duration::from_secs(30);

/// Runs until killed, and never returns.
///
/// The DNS listener is started **last and separately** (`serve_dns_forever`),
/// and a port it cannot take is no longer the end of the process. It used to
/// be: `run` bound `127.0.0.53:53` first and returned the error, `main` logged
/// it as fatal and exited 1. A field report (2026-09-20) showed what that costs
/// - something on that machine had held UDP `:53` for a day, so every start
/// died within seconds, and with it went the gate hosts' door, the local proxy,
/// the built-in exits, the route table, the region-400 watch and the auto-patch
/// watchdog. Not one of those needs port 53. That user had a working bypass
/// available the whole time and got nothing.
#[cfg(windows)]
enum WindowsCarrierStartup {
    Legacy,
    Explicit { settings: crate::settings::Settings, requirements: crate::settings::TransportRequirements },
}

enum DnsQueryFailure { Cancelled, NoAnswer, Io(std::io::Error), Resolver(String) }

fn answer_dns_query(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, query: &[u8],
    out: &UdpSocket, from: SocketAddr, observation: Option<IspObservation>, cancelled: Option<&std::sync::atomic::AtomicBool>, work: Option<&resolvers::ResolverWork>)
    -> Result<usize, DnsQueryFailure> {
    let stopped = || cancelled.is_some_and(|value| value.load(std::sync::atomic::Ordering::Acquire));
    if stopped() { return Err(DnsQueryFailure::Cancelled); }
    let name = dns_client::question_name(query).unwrap_or_else(|| "?".to_string());
    if let Some(reply) = own_answer(query, &name) {
        if stopped() { return Err(DnsQueryFailure::Cancelled); }
        return out.send_to(&reply, from).map_err(DnsQueryFailure::Io);
    }
    let observation = observation.unwrap_or_else(|| prepare_isp_interface(root));
    match relay_with_work(root, observation, query, work).map_err(DnsQueryFailure::Resolver)? {
        Some((reply, provider, verdict)) => {
            if stopped() { return Err(DnsQueryFailure::Cancelled); }
            let sent = out.send_to(&reply, from).map_err(DnsQueryFailure::Io);
            log(&format!("{:<12} {} [{}]", verdict_tag(verdict), name, provider));
            sent
        }
        None => { log(&format!("fail         {name}")); Err(DnsQueryFailure::NoAnswer) }
    }
}

#[cfg(windows)]
struct CarrierWake(thread::Thread);
#[cfg(windows)]
impl Drop for CarrierWake { fn drop(&mut self) { self.0.unpark(); } }

#[cfg(windows)]
struct DnsBinding { address: SocketAddr, valid: std::sync::atomic::AtomicBool }

#[cfg(windows)]
enum DnsListenerFailure { Bind { address: SocketAddr, error: std::io::Error }, Receive(std::io::Error), Worker(std::io::Error) }

#[cfg(windows)]
struct DnsChannel {
    address: SocketAddr,
    socket: Option<UdpSocket>,
    binding: Option<std::sync::Arc<DnsBinding>>,
    next_bind: Instant,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    wake: thread::Thread,
    workers: Vec<DnsWorker>,
    completed: Vec<thread::Result<Result<usize, DnsQueryFailure>>>,
    retired_resolvers: Vec<std::sync::Arc<resolvers::ResolverWork>>,
    receive_errors: u32,
    #[cfg(test)]
    fixture_query_gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}

#[cfg(windows)]
struct DnsWorker {
    handle: Option<thread::JoinHandle<Result<usize, DnsQueryFailure>>>,
    resolver: std::sync::Arc<resolvers::ResolverWork>,
}

#[cfg(windows)]
impl DnsChannel {
    fn new(address: SocketAddr, cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>, wake: thread::Thread) -> Self {
        Self { address, socket: None, binding: None, next_bind: Instant::now(), cancelled, wake,
            workers: Vec::new(), completed: Vec::new(), retired_resolvers: Vec::new(), receive_errors: 0,
            #[cfg(test)] fixture_query_gate: None }
    }
    fn close_listener(&mut self) {
        self.socket.take();
        if let Some(binding) = self.binding.take() { binding.valid.store(false, std::sync::atomic::Ordering::Release); }
        for worker in &self.workers { worker.resolver.cancel(); }
        for work in &self.retired_resolvers { work.cancel(); }
    }
    fn poll(&mut self, root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> Result<proxy::ListenerStep, DnsListenerFailure> {
        if self.cancelled.load(std::sync::atomic::Ordering::Acquire) { self.close_listener(); return Ok(proxy::ListenerStep::Stopped); }
        if self.socket.is_none() {
            if Instant::now() < self.next_bind { return Ok(proxy::ListenerStep::Idle); }
            let socket = UdpSocket::bind(self.address).and_then(|socket| { socket.set_nonblocking(true)?; Ok(socket) });
            let socket = match socket {
                Ok(socket) => socket,
                Err(error) => { self.next_bind = Instant::now() + proxy::REBIND_EVERY;
                    return Err(DnsListenerFailure::Bind { address: self.address, error }); }
            };
            let address = match socket.local_addr() {
                Ok(address) => address,
                Err(error) => { self.next_bind = Instant::now() + proxy::REBIND_EVERY; return Err(DnsListenerFailure::Receive(error)); }
            };
            if self.cancelled.load(std::sync::atomic::Ordering::Acquire) { return Ok(proxy::ListenerStep::Stopped); }
            self.socket = Some(socket);
            self.receive_errors = 0;
            self.binding = Some(std::sync::Arc::new(DnsBinding { address, valid: std::sync::atomic::AtomicBool::new(true) }));
            return Ok(proxy::ListenerStep::Progress);
        }
        let mut query = [0u8; 4096];
        let socket = self.socket.as_ref().expect("owned DNS socket");
        let (length, from) = match socket.recv_from(&mut query) {
            Ok(value) => { self.receive_errors = 0; value },
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => return Ok(proxy::ListenerStep::Idle),
            Err(error) => {
                self.receive_errors += 1;
                if self.receive_errors >= RECV_ERRORS_BEFORE_REBIND {
                    self.close_listener(); self.next_bind = Instant::now() + proxy::REBIND_EVERY;
                }
                return Err(DnsListenerFailure::Receive(error));
            }
        };
        if length < 12 { return Ok(proxy::ListenerStep::Progress); }
        if self.cancelled.load(std::sync::atomic::Ordering::Acquire) { self.close_listener(); return Ok(proxy::ListenerStep::Stopped); }
        let out = socket.try_clone().map_err(DnsListenerFailure::Worker)?;
        let query = query[..length].to_vec();
        self.workers.try_reserve(1).map_err(|error| DnsListenerFailure::Worker(std::io::Error::other(error)))?;
        let root = root.clone();
        let cancelled = self.cancelled.clone();
        let wake = self.wake.clone();
        if self.cancelled.load(std::sync::atomic::Ordering::Acquire) { self.close_listener(); return Ok(proxy::ListenerStep::Stopped); }
        let resolver = std::sync::Arc::new(resolvers::ResolverWork::with_cancellation(wake.clone(), self.cancelled.clone()));
        let position = self.workers.len();
        self.workers.push(DnsWorker { handle: None, resolver: resolver.clone() });
        #[cfg(test)]
        let fixture_query_gate = self.fixture_query_gate.take();
        let started = thread::Builder::new().spawn(move || {
            let _wake = CarrierWake(wake);
            #[cfg(test)]
            if let Some((started, release)) = fixture_query_gate {
                if started.send(()).is_err() || release.recv().is_err() { return Err(DnsQueryFailure::Cancelled); }
            }
            answer_dns_query(&root, &query, &out, from, None, Some(&cancelled), Some(&resolver))
        });
        match started {
            Ok(handle) => self.workers[position].handle = Some(handle),
            Err(error) => { self.workers.pop(); return Err(DnsListenerFailure::Worker(error)); }
        }
        Ok(proxy::ListenerStep::Progress)
    }
    fn receive_finished(&mut self) -> Result<Vec<thread::Result<Result<usize, DnsQueryFailure>>>, String> {
        self.completed.try_reserve(self.workers.len()).map_err(|error| error.to_string())?;
        self.retired_resolvers.try_reserve(self.workers.len()).map_err(|error| error.to_string())?;
        let mut index = 0;
        while index < self.workers.len() {
            if self.workers[index].handle.as_ref().is_some_and(|handle| handle.is_finished()) {
                let mut worker = self.workers.swap_remove(index);
                let outcome = worker.handle.take().expect("finished DNS worker").join();
                self.retired_resolvers.push(worker.resolver);
                self.completed.push(outcome);
            }
            else { index += 1; }
        }
        Ok(std::mem::take(&mut self.completed))
    }
    fn receive_resolvers_into(&mut self, terminals: &mut Vec<resolvers::ResolverTerminal>) -> Result<(), String> {
        for worker in &self.workers { worker.resolver.receive_into(terminals)?; }
        for work in &self.retired_resolvers { work.receive_into(terminals)?; }
        self.retired_resolvers.retain(|work| work.has_unreceived());
        Ok(())
    }
    fn has_unreceived(&self) -> bool { !self.workers.is_empty() || !self.completed.is_empty() || self.retired_resolvers.iter().any(|work| work.has_unreceived()) }
}

#[cfg(windows)]
struct DnsProbe {
    binding: std::sync::Arc<DnsBinding>,
    handle: thread::JoinHandle<Result<(), String>>,
}

/// A proof belongs to one received bind, not merely to a reusable port number.
#[cfg(windows)]
struct TcpBinding {
    address: SocketAddr,
    instance: gate::TransportInstance,
    valid: std::sync::atomic::AtomicBool,
}

#[cfg(windows)]
struct SystemEnvironment {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ready: Mutex<Option<std::sync::Arc<TcpBinding>>>,
}

#[cfg(windows)]
struct ProtocolProbe {
    binding: std::sync::Arc<TcpBinding>,
    handle: thread::JoinHandle<std::io::Result<()>>,
}

#[cfg(windows)]
fn binding_is_current(proof: &std::sync::Arc<TcpBinding>, current: Option<&std::sync::Arc<TcpBinding>>,
    address: Option<SocketAddr>, cancelled: bool) -> bool {
    !cancelled && proof.valid.load(std::sync::atomic::Ordering::Acquire)
        && current.is_some_and(|current| std::sync::Arc::ptr_eq(current, proof)) && address == Some(proof.address)
}

/// These are the actual acquired values, kept outside every receiving catch.
#[cfg(windows)]
struct ExplicitTransportCarrier {
    listener: Option<proxy::TransportListener>,
    dns: Option<DnsChannel>,
    dns_probe: Option<DnsProbe>,
    dns_probe_result: Option<thread::Result<Result<(), String>>>,
    dns_probe_receipt: Result<(), String>,
    dns_completed: Vec<thread::Result<Result<usize, DnsQueryFailure>>>,
    dns_results: Vec<Result<usize, String>>,
    dns_blocker: Option<gate::Blocker>,
    dns_listener_failure: Option<DnsListenerFailure>,
    next_dns_probe: Instant,
    aliases: Option<loopback::AliasListeners>,
    alias_completed: Vec<thread::Result<std::io::Result<proxy::SpliceOutcome>>>,
    alias_results: Vec<Result<(u64, u64), String>>,
    alias_failure: Option<loopback::AliasFailure>,
    alias_blocker: Option<gate::Blocker>,
    warming: Option<thread::JoinHandle<Result<(), String>>>,
    warm_resolver: Option<std::sync::Arc<resolvers::ResolverWork>>,
    resolver_completed: Vec<resolvers::ResolverTerminal>,
    resolver_results: Vec<String>,
    warm_result: Option<thread::Result<Result<(), String>>>,
    warm_receipt: Result<(), String>,
    next_warm: Instant,
    next_private_probe: Instant,
    workers: proxy::ConnectionWorkers,
    report: gate::TransportReport,
    binding: Option<std::sync::Arc<TcpBinding>>,
    probe: Option<ProtocolProbe>,
    probe_result: Option<thread::Result<std::io::Result<()>>>,
    probe_receipt: Result<(), String>,
    environment: std::sync::Arc<SystemEnvironment>,
    maintainer: Option<thread::JoinHandle<Result<(), String>>>,
    maintainer_result: Option<thread::Result<Result<(), String>>>,
    completed: Vec<thread::Result<Result<proxy::ConnectionSuccess, proxy::ConnectionFailure>>>,
    request_results: Vec<Result<(), String>>,
    listener_failure: Option<proxy::ListenerFailure>,
    blocker: Option<gate::Blocker>,
    publication: Result<(), String>,
    metadata_receiving: Result<(), String>,
    role_result: Result<(), String>,
    terminal_error: Option<String>,
    panics: Vec<Box<dyn std::any::Any + Send>>,
    next_publish: Instant,
    next_probe: Instant,
    dirty: bool,
}

#[cfg(windows)]
impl ExplicitTransportCarrier {
    fn receive_terminal_error(&mut self, error: String) {
        self.terminal_error = Some(match self.terminal_error.take() {
            Some(original) => format!("{original}; {error}"), None => error,
        });
    }
    fn invalidate_binding(&mut self) {
        use std::sync::atomic::Ordering;
        if let Some(binding) = self.binding.take() { binding.valid.store(false, Ordering::Release); }
        if let Some(probe) = &self.probe { probe.binding.valid.store(false, Ordering::Release); }
        let mut ready = self.environment.ready.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(binding) = ready.take() { binding.valid.store(false, Ordering::Release); }
        drop(ready);
        if let Some(aliases) = &mut self.aliases { aliases.close_listeners(); }
    }

    fn cancel(&mut self) {
        self.invalidate_binding();
        self.environment.cancelled.store(true, std::sync::atomic::Ordering::Release);
        self.workers.request_cancel();
        if let Some(dns) = &mut self.dns { dns.close_listener(); }
        if let Some(work) = &self.warm_resolver { work.cancel(); }
    }

    fn receive_dns(&mut self) -> Result<(), String> {
        if let Some(dns) = &mut self.dns {
            if self.dns_completed.is_empty() { self.dns_completed = dns.receive_finished()?; }
        }
        self.dns_results = self.dns_completed.iter().map(|result| match result {
            Ok(Ok(sent)) => Ok(*sent),
            Ok(Err(DnsQueryFailure::Cancelled)) => Err("DNS query cancelled".into()),
            Ok(Err(DnsQueryFailure::NoAnswer)) => Err("DNS query received no upstream answer".into()),
            Ok(Err(DnsQueryFailure::Io(error))) => Err(format!("DNS reply send: {}", io_failure_facts(error))),
            Ok(Err(DnsQueryFailure::Resolver(error))) => Err(format!("DNS resolver: {error}")),
            Err(_) => Err("DNS query worker unwound; original payload retained".into()),
        }).collect();
        let mut panics = Vec::new();
        for result in self.dns_completed.drain(..) { if let Err(payload) = result { panics.push(payload); } }
        if !panics.is_empty() { self.panics.append(&mut panics); self.cancel(); }
        if self.dns_probe.as_ref().is_some_and(|probe| probe.handle.is_finished()) {
            let probe = self.dns_probe.take().expect("finished DNS probe");
            self.dns_probe_result = Some(probe.handle.join());
            self.dns_probe_receipt = match self.dns_probe_result.as_ref().expect("owned DNS probe result") {
                Ok(value) => value.clone(),
                Err(_) => Err("DNS protocol worker unwound; original payload retained".into()),
            };
            let current = self.dns.as_ref().and_then(|dns| dns.binding.as_ref())
                .is_some_and(|current| std::sync::Arc::ptr_eq(current, &probe.binding))
                && probe.binding.valid.load(std::sync::atomic::Ordering::Acquire)
                && !self.environment.cancelled.load(std::sync::atomic::Ordering::Acquire);
            if current {
                self.report.observed.dns = match &self.dns_probe_receipt {
                    Ok(()) => { self.dns_blocker = None; self.dns_listener_failure = None; gate::CapabilityObservation::Ready },
                    Err(error) => gate::CapabilityObservation::Failed(error.clone()),
                };
                self.dirty = true;
            }
            self.next_dns_probe = Instant::now() + WARM_EVERY;
            if let Some(Err(payload)) = self.dns_probe_result.take() { self.panics.push(payload); self.cancel(); }
        }
        Ok(())
    }

    fn poll_dns_step(&mut self, root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> Result<proxy::ListenerStep, String> {
        let mut step = proxy::ListenerStep::Idle;
        if let Some(dns) = &mut self.dns {
            match dns.poll(root) {
                Ok(proxy::ListenerStep::Progress) => step = proxy::ListenerStep::Progress,
                Ok(proxy::ListenerStep::Stopped) => {},
                Ok(proxy::ListenerStep::Idle) => {},
                Err(error) => {
                    self.dns_listener_failure = Some(error);
                    let (message, blocker) = match self.dns_listener_failure.as_ref().expect("owned DNS listener failure") {
                        DnsListenerFailure::Bind { address, error } => (format!("DNS bind: {}", io_failure_facts(error)),
                            Some(crate::portcheck::Cause::Other.blocker("dns", *address, error))),
                        DnsListenerFailure::Receive(error) => (format!("DNS receive: {}", io_failure_facts(error)), None),
                        DnsListenerFailure::Worker(error) => (format!("DNS query worker: {}", io_failure_facts(error)), None),
                    };
                    self.report.observed.dns = gate::CapabilityObservation::Failed(message);
                    self.dns_blocker = blocker;
                    self.dirty = true;
                }
            }
        }
        self.receive_dns()?;
        Ok(step)
    }

    fn has_unreceived(&self) -> bool {
        self.workers.has_unreceived() || self.probe.is_some() || self.maintainer.is_some()
            || self.dns_probe.is_some() || self.dns.as_ref().is_some_and(DnsChannel::has_unreceived)
            || self.aliases.as_ref().is_some_and(loopback::AliasListeners::has_unreceived)
            || self.warming.is_some()
            || !self.completed.is_empty() || !self.dns_completed.is_empty() || !self.alias_completed.is_empty()
            || self.probe_result.is_some() || self.dns_probe_result.is_some() || self.warm_result.is_some()
            || self.maintainer_result.is_some()
            || self.warm_resolver.as_ref().is_some_and(|work| work.has_unreceived()) || !self.resolver_completed.is_empty()
    }

    fn receive_resolvers(&mut self) -> Result<(), String> {
        self.workers.receive_resolvers_into(&mut self.resolver_completed)?;
        if let Some(dns) = &mut self.dns { dns.receive_resolvers_into(&mut self.resolver_completed)?; }
        if let Some(work) = &self.warm_resolver { work.receive_into(&mut self.resolver_completed)?; }
        let previous_panics = self.panics.len();
        resolvers::receive_terminals(&mut self.resolver_completed, &mut self.resolver_results, &mut self.panics)?;
        if self.panics.len() != previous_panics { self.cancel(); }
        if self.warming.is_none() && self.warm_resolver.as_ref().is_some_and(|work| !work.has_unreceived()) { self.warm_resolver = None; }
        Ok(())
    }

    fn receive_aliases(&mut self) -> Result<(), String> {
        if let Some(aliases) = &mut self.aliases {
            if self.alias_completed.is_empty() { self.alias_completed = aliases.receive_finished()?; }
        }
        self.alias_results = self.alias_completed.iter().map(|result| match result {
            Err(_) => Err("alias worker unwound; original payload retained".into()),
            Ok(Err(error)) => Err(format!("alias open/protocol/splice setup: {}; {error}", io_failure_facts(error))),
            Ok(Ok(outcome)) => receive_splice_facts(outcome),
        }).collect();
        let mut panics = Vec::new();
        for result in self.alias_completed.drain(..) {
            match result {
                Err(payload) => panics.push(payload),
                Ok(Err(_)) => {},
                Ok(Ok(outcome)) => {
                    match outcome.client_to_upstream {
                        Err(payload) => panics.push(payload),
                        Ok(direction) => if let Err(payload) = direction.copy { panics.push(payload); },
                    }
                    if let Err(payload) = outcome.upstream_to_client { panics.push(payload); }
                }
            }
        }
        if !panics.is_empty() { self.panics.append(&mut panics); self.cancel(); }
        Ok(())
    }

    fn receive_workers(&mut self) -> Result<(), String> {
        // Keep the entire native result batch before any classification allocates.
        if self.completed.is_empty() { self.completed = self.workers.receive_finished()?; }
        let received = self.completed.iter().map(|result| match result {
            Ok(Ok(proxy::ConnectionSuccess::NoTransfer)) => Ok(()),
            Ok(Ok(proxy::ConnectionSuccess::LegacyPrivate)) => Err("legacy private transfer returned without a typed receipt".into()),
            Ok(Ok(proxy::ConnectionSuccess::Tcp(outcome))) => receive_splice_facts(outcome).map(|_| ()),
            Ok(Err(error)) => Err(connection_failure_facts(error)),
            Err(_) => Err("connection worker unwound; original payload retained".into()),
        }).collect::<Vec<_>>();
        self.request_results = received;
        // Every request has now reached its own actual result receiver. A failed
        // upstream request does not change the local proxy protocol's health.
        for result in &self.request_results {
            if let Err(error) = result { log_proxy(error); }
        }
        let mut panics = Vec::new();
        for result in self.completed.drain(..) {
            match result {
                Err(payload) => panics.push(payload),
                Ok(Ok(proxy::ConnectionSuccess::Tcp(outcome))) => {
                    match outcome.client_to_upstream {
                        Err(payload) => panics.push(payload),
                        Ok(direction) => if let Err(payload) = direction.copy { panics.push(payload); },
                    }
                    if let Err(payload) = outcome.upstream_to_client { panics.push(payload); }
                }
                _ => (),
            }
        }
        if !panics.is_empty() { self.panics.append(&mut panics); self.cancel(); }
        Ok(())
    }

    fn receive_probe(&mut self) {
        if !self.probe.as_ref().is_some_and(|probe| probe.handle.is_finished()) { return; }
        let probe = self.probe.take().expect("finished protocol probe");
        self.probe_result = Some(probe.handle.join());
        self.probe_receipt = match self.probe_result.as_ref().expect("received probe") {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("local proxy protocol: {}", io_failure_facts(error))),
            Err(_) => Err("local proxy protocol worker unwound; original payload retained".into()),
        };
        self.next_probe = Instant::now() + WARM_EVERY;
        let current = binding_is_current(&probe.binding, self.binding.as_ref(), self.listener.as_ref().and_then(|listener| listener.bound_addr()),
            self.workers.cancellation_token().is_cancelled());
        if current {
            self.report.observed.tcp_proxy = match self.probe_result.as_ref().expect("received probe") {
                Ok(Ok(())) => gate::CapabilityObservation::Ready,
                Ok(Err(error)) => gate::CapabilityObservation::Failed(format!("local proxy protocol: {}", io_failure_facts(error))),
                Err(_) => gate::CapabilityObservation::Failed("local proxy protocol worker unwound".into()),
            };
            self.dirty = true;
        }
        if let Some(Err(payload)) = self.probe_result.take() { self.panics.push(payload); self.cancel(); }
    }

    fn poll(&mut self, root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> Result<proxy::ListenerStep, String> {
        if root.receive_role_result(&mut self.role_result) {
            if let Err(error) = &self.role_result { log_proxy(error); }
        }
        let mut command_panics = root.take_panics();
        if !command_panics.is_empty() { self.panics.append(&mut command_panics); self.cancel(); }
        let mut listener_failed = false;
        let mut step = match self.listener.as_mut().map(|listener| listener.poll(&mut self.workers)).unwrap_or(Ok(proxy::ListenerStep::Idle)) {
            Ok(step) => step,
            Err(error) => {
                self.listener_failure = Some(error);
                listener_failed = true;
                self.invalidate_binding();
                let failure = self.listener_failure.as_ref().expect("owned listener error");
                self.blocker = match failure {
                    proxy::ListenerFailure::Bind { address, error } | proxy::ListenerFailure::Configure { address, error } =>
                        Some(crate::portcheck::Cause::Other.blocker("proxy", *address, error)),
                    _ => None,
                };
                self.report.observed.tcp_proxy = gate::CapabilityObservation::Failed(listener_failure_facts(failure));
                self.dirty = true;
                // Accept/worker-owner failures cannot spin indefinitely on the
                // same listener. Bind/configure retains its scheduled retry.
                if matches!(failure, proxy::ListenerFailure::Accept(_) | proxy::ListenerFailure::WorkerStart(_) | proxy::ListenerFailure::Owner(_)) {
                    let received = listener_failure_facts(failure);
                    self.receive_terminal_error(received);
                    self.cancel();
                }
                proxy::ListenerStep::Idle
            }
        };
        if step == proxy::ListenerStep::Stopped {
            self.invalidate_binding();
            let stopped = gate::CapabilityObservation::Failed("owned listener stopped".into());
            if self.report.observed.tcp_proxy != stopped {
                self.report.observed.tcp_proxy = stopped;
                self.dirty = true;
            }
        }
        if let Some(address) = self.listener.as_ref().and_then(|listener| listener.bound_addr()) {
            if self.binding.as_ref().is_some_and(|binding| binding.address != address) { self.invalidate_binding(); }
            if self.binding.is_none() && !listener_failed && !self.workers.cancellation_token().is_cancelled() {
                self.binding = Some(std::sync::Arc::new(TcpBinding { address, instance: self.report.instance.clone(),
                    valid: std::sync::atomic::AtomicBool::new(true) }));
                self.next_probe = Instant::now();
                self.report.observed.tcp_proxy = gate::CapabilityObservation::Starting;
                self.blocker = None;
                self.dirty = true;
            }
        } else if self.binding.is_some() { self.invalidate_binding(); }
        self.receive_probe();
        if self.probe.is_none() && Instant::now() >= self.next_probe && !matches!(self.report.observed.tcp_proxy, gate::CapabilityObservation::Ready)
            && !self.workers.cancellation_token().is_cancelled() {
            if let Some(binding) = self.binding.clone() {
                let address = binding.address;
                // The caller's actual listener keeps accepting while this
                // synchronous one-second protocol observation runs.
                let handle = thread::Builder::new().name("local-proxy-protocol".into()).spawn(move ||
                    proxy::protocol_answers_at(address, Duration::from_secs(1)));
                match handle {
                    Ok(handle) => self.probe = Some(ProtocolProbe { binding, handle }),
                    Err(error) => { self.receive_terminal_error(format!("protocol worker start: {}", io_failure_facts(&error))); self.cancel(); }
                }
            }
        }
        self.receive_workers()?;
        if self.poll_dns_step(root)? == proxy::ListenerStep::Progress { step = proxy::ListenerStep::Progress; }
        if self.dns_probe.is_none() && Instant::now() >= self.next_dns_probe
            && !matches!(self.report.observed.dns, gate::CapabilityObservation::Ready)
            && !self.environment.cancelled.load(std::sync::atomic::Ordering::Acquire) {
            if let Some(binding) = self.dns.as_ref().and_then(|dns| dns.binding.clone()) {
                let server = match binding.address.ip() { std::net::IpAddr::V4(server) => server,
                    _ => return Err("DNS channel did not receive its IPv4 listener".into()) };
                let wake = thread::current();
                let handle = thread::Builder::new().name("local-dns-protocol".into()).spawn(move || {
                    let _wake = CarrierWake(wake);
                    dns_client::probe_local_gate_dns(server, dns::core_namespaces()[0])
                });
                match handle {
                    Ok(handle) => self.dns_probe = Some(DnsProbe { binding, handle }),
                    Err(error) => { self.receive_terminal_error(format!("DNS protocol worker start: {}", io_failure_facts(&error))); self.cancel(); }
                }
            }
        }
        if let Some(aliases) = &mut self.aliases {
            let upstream = self.binding.as_ref().filter(|binding| binding.valid.load(std::sync::atomic::Ordering::Acquire))
                .filter(|_| matches!(self.report.observed.tcp_proxy, gate::CapabilityObservation::Ready)).map(|binding| binding.address);
            let previous = self.report.observed.dns_alias.clone();
            match aliases.poll(upstream) {
                Ok(proxy::ListenerStep::Progress) => { step = proxy::ListenerStep::Progress; self.alias_blocker = None; self.alias_failure = None; },
                Ok(_) => {},
                Err(error) => self.alias_failure = Some(error),
            }
            if let Some(error) = self.alias_failure.as_ref() {
                let (cause, blocker) = match error {
                    loopback::AliasFailure::Bind { address, error } | loopback::AliasFailure::Accept { address, error } =>
                        (format!("DNS alias bind/accept: {}", io_failure_facts(error)), Some(crate::portcheck::Cause::Other.blocker("door", *address, error))),
                    loopback::AliasFailure::Worker(error) => (format!("DNS alias worker: {}", io_failure_facts(error)), None),
                };
                self.alias_blocker = blocker;
                self.report.observed.dns_alias = gate::CapabilityObservation::Failed(cause);
            } else if self.environment.cancelled.load(std::sync::atomic::Ordering::Acquire) {
                self.report.observed.dns_alias = gate::CapabilityObservation::Failed("owned alias listeners stopped".into());
            } else if aliases.bound() && upstream.is_some() { self.report.observed.dns_alias = gate::CapabilityObservation::Ready; }
            else { self.report.observed.dns_alias = gate::CapabilityObservation::Starting; }
            if previous != self.report.observed.dns_alias { self.dirty = true; }
        }
        self.receive_aliases()?;
        if self.warming.as_ref().is_some_and(|work| work.is_finished()) {
            self.warm_result = Some(self.warming.take().expect("finished configured maintenance").join());
            self.warm_receipt = match self.warm_result.as_ref().expect("owned maintenance result") {
                Ok(value) => value.clone(),
                Err(_) => Err("configured maintenance unwound; original payload retained".into()),
            };
            if self.warm_receipt.is_err() { log_proxy("selected configured maintenance failed; actual result retained"); }
            if routes::dns_has_pending_maintenance() { self.next_warm = Instant::now(); }
            if let Some(Err(payload)) = self.warm_result.take() { self.panics.push(payload); self.cancel(); }
        }
        let active = self.report.active_config;
        if active.profile == crate::settings::TransportProfile::ExistingConfigured && self.warming.is_none() && self.warm_resolver.is_none()
            && (Instant::now() >= self.next_warm || routes::dns_has_pending_maintenance()) && !self.environment.cancelled.load(std::sync::atomic::Ordering::Acquire) {
            let commands = root.clone();
            let cancelled = self.environment.cancelled.clone();
            let wake = thread::current();
            let resolver = std::sync::Arc::new(resolvers::ResolverWork::with_cancellation(wake.clone(), cancelled.clone()));
            self.warm_resolver = Some(resolver.clone());
            let probe_private = active.tcp_proxy && Instant::now() >= self.next_private_probe;
            let handle = thread::Builder::new().name("configured-maintenance".into()).spawn(move || {
                let _wake = CarrierWake(wake);
                if cancelled.load(std::sync::atomic::Ordering::Acquire) { return Ok(()); }
                // The profile/credentials belong to this pass, never to the
                // process lifetime. System never enters this capture path.
                let profile = proxy::DesiredRouteProfile::capture_for_work(active).map_err(|error| open_failure_facts(&error))?;
                let _candidate_pending = if active.tcp_proxy && !cancelled.load(std::sync::atomic::Ordering::Acquire) {
                    let interface = isp_interface(&commands);
                    maintain_dns_candidate_step(interface, false, Some(&resolver))?
                } else { false };
                if active.dns && !active.tcp_proxy {
                    let interface = isp_interface(&commands);
                    if !cancelled.load(std::sync::atomic::Ordering::Acquire) { resolvers::warm_owned(dns::core_namespaces(), interface, &resolver)?; }
                }
                if probe_private && !cancelled.load(std::sync::atomic::Ordering::Acquire) { profile.probe_selected()?; }
                Ok(())
            });
            match handle {
                Ok(handle) => self.warming = Some(handle),
                Err(error) => { self.receive_terminal_error(format!("configured maintenance start: {}", io_failure_facts(&error))); self.cancel(); }
            }
            self.next_warm = Instant::now() + WARM_EVERY;
            if probe_private { self.next_private_probe = Instant::now() + PROBE_HEALTHY_EVERY; }
        }
        self.receive_resolvers()?;
        if self.environment.cancelled.load(std::sync::atomic::Ordering::Acquire) && self.report.active_config.dns {
            let stopped = gate::CapabilityObservation::Failed("owned DNS listener stopped".into());
            if self.report.observed.dns != stopped { self.report.observed.dns = stopped; self.dirty = true; }
        }
        if (self.dirty && self.publication.is_ok()) || Instant::now() >= self.next_publish {
            self.publication = gate::publish_transport(&self.report, self.blocker.as_ref(), self.dns_blocker.as_ref(), self.alias_blocker.as_ref());
            self.next_publish = Instant::now() + WARM_EVERY;
            self.dirty = false;
            if self.publication.is_ok() && matches!(self.report.observed.tcp_proxy, gate::CapabilityObservation::Ready) {
                *self.environment.ready.lock().unwrap_or_else(|error| error.into_inner()) = self.binding.clone();
            } else {
                // A private in-memory proof cannot replace protected receiving.
                let mut ready = self.environment.ready.lock().unwrap_or_else(|error| error.into_inner());
                if let Some(binding) = ready.take() { binding.valid.store(false, std::sync::atomic::Ordering::Release); }
                drop(ready);
                if self.publication.is_err() {
                    self.invalidate_binding();
                    if self.report.active_config.tcp_proxy {
                        self.report.observed.tcp_proxy = gate::CapabilityObservation::Failed("protected transport publication unreceived".into());
                    }
                }
            }
        }
        if self.maintainer.as_ref().is_some_and(|worker| worker.is_finished()) {
            self.maintainer_result = Some(self.maintainer.take().expect("finished environment maintainer").join());
            match self.maintainer_result.take().expect("received environment result") {
                Ok(Ok(())) => {},
                Ok(Err(error)) => { self.receive_terminal_error(error); self.cancel(); },
                Err(payload) => { self.panics.push(payload); self.cancel(); },
            }
        }
        if self.environment.cancelled.load(std::sync::atomic::Ordering::Acquire)
            && self.listener.as_ref().and_then(|listener| listener.bound_addr()).is_none()
            && self.dns.as_ref().map_or(true, |dns| dns.socket.is_none())
            && self.aliases.as_ref().map_or(true, |aliases| !aliases.bound()) { step = proxy::ListenerStep::Stopped; }
        if step == proxy::ListenerStep::Stopped && !self.has_unreceived() {
            self.metadata_receiving = gate::finish_runtime_metadata();
        }
        Ok(step)
    }
}

#[cfg(windows)]
fn io_failure_facts(error: &std::io::Error) -> String { format!("{:?}/{:?}", error.kind(), error.raw_os_error()) }

#[cfg(windows)]
fn receive_splice_facts(outcome: &proxy::SpliceOutcome) -> Result<(u64, u64), String> {
    let copy = |value: &thread::Result<std::io::Result<u64>>| match value {
        Ok(Ok(bytes)) => format!("bytes={bytes}"),
        Ok(Err(error)) => io_failure_facts(error),
        Err(_) => "unwound; original payload retained".into(),
    };
    let shutdown = |value: &std::io::Result<()>| value.as_ref().err().map(io_failure_facts);
    let upstream = match &outcome.client_to_upstream {
        Ok(direction) => format!("{}; shutdown={:?}", copy(&direction.copy), shutdown(&direction.shutdown)),
        Err(_) => "worker unwound; original payload retained".into(),
    };
    if let (Ok(direction), Ok(Ok(to_client))) = (&outcome.client_to_upstream, &outcome.upstream_to_client) {
        if let Ok(Ok(to_upstream)) = &direction.copy {
            if direction.shutdown.is_ok() && outcome.client_shutdown_write.is_ok() && outcome.client_shutdown_both.is_ok() {
                return Ok((*to_upstream, *to_client));
            }
        }
    }
    Err(format!("alias splice: client_to_upstream={upstream}; upstream_to_client={}; client_shutdown_write={:?}; client_shutdown_both={:?}",
        copy(&outcome.upstream_to_client), shutdown(&outcome.client_shutdown_write), shutdown(&outcome.client_shutdown_both)))
}

#[cfg(windows)]
fn open_failure_facts(error: &proxy::route_session::OpenFailure) -> String {
    use proxy::route_session::OpenFailure;
    match error {
        OpenFailure::Cancelled => "cancelled".into(),
        OpenFailure::Deadline => "deadline".into(),
        OpenFailure::Unavailable(detail) => format!("unavailable; private_detail_present={}", detail.is_some()),
        OpenFailure::DeniedTarget => "target denied".into(),
        OpenFailure::UnsupportedPrivateRoutes => "private route unsupported".into(),
        OpenFailure::Resolution(error) => format!("resolution failed: {}", io_failure_facts(error)),
        OpenFailure::ResolutionLate { cancelled, error } => format!("resolution late; cancelled={cancelled}; error={}", io_failure_facts(error)),
    }
}

#[cfg(windows)]
fn connection_failure_facts(error: &proxy::ConnectionFailure) -> String {
    use proxy::route_session::CommitCause;
    match error {
        proxy::ConnectionFailure::Open(error) => format!("proxy request open failed: {}", open_failure_facts(error)),
        proxy::ConnectionFailure::Transfer(error) => format!("proxy request transfer failed: {}", io_failure_facts(error)),
        proxy::ConnectionFailure::Commit(error) => {
            let cause = match &error.error {
                CommitCause::Boundary(error) => open_failure_facts(error),
                CommitCause::InvalidDirectPeer => "direct peer invalid".into(),
                CommitCause::Io(error) => io_failure_facts(error),
            };
            let shutdown = |result: &std::io::Result<()>| result.as_ref().err().map(io_failure_facts);
            format!("proxy request commit failed: bytes={}; cause={cause}; client_shutdown={:?}; upstream_shutdown={:?}",
                error.bytes_written, shutdown(&error.client_shutdown), shutdown(&error.upstream_shutdown))
        }
    }
}

#[cfg(windows)]
fn listener_failure_facts(error: &proxy::ListenerFailure) -> String {
    match error {
        proxy::ListenerFailure::Bind { error, .. } => format!("proxy bind: {}", io_failure_facts(error)),
        proxy::ListenerFailure::Configure { error, .. } => format!("proxy socket configuration: {}", io_failure_facts(error)),
        proxy::ListenerFailure::Accept(error) => format!("proxy accept: {}", io_failure_facts(error)),
        proxy::ListenerFailure::WorkerStart(error) => format!("proxy worker start: {}", io_failure_facts(error)),
        proxy::ListenerFailure::Owner(_) => "proxy listener owner not received".into(),
    }
}

#[cfg(windows)]
fn receive_system_environment_observation(observed: &crate::background::TransportBackgroundObservation,
    binding: &TcpBinding, active: crate::settings::ActiveTransportConfig) -> Result<(), String> {
    receive_system_environment_facts(observed.expected, observed.instance.as_ref(),
        matches!(&observed.tcp_proxy, crate::background::TransportChannelObservation::Received(gate::CapabilityObservation::Ready)),
        observed.tcp_proxy_port, binding, active)
}

#[cfg(windows)]
fn receive_system_environment_facts(expected: crate::settings::ActiveTransportConfig, instance: Option<&gate::TransportInstance>,
    tcp_ready: bool, port: Option<u16>, binding: &TcpBinding, active: crate::settings::ActiveTransportConfig) -> Result<(), String> {
    if expected != active { return Err("qualified transport configuration changed".into()); }
    let instance = instance.ok_or("qualified transport instance is unknown")?;
    if instance.pid != binding.instance.pid || instance.creation_time != binding.instance.creation_time {
        return Err("qualified transport belongs to a different carrier instance".into());
    }
    if !tcp_ready || port != Some(binding.address.port()) {
        return Err("qualified same-instance TCP protocol and port are not ready".into());
    }
    Ok(())
}

#[cfg(windows)]
fn system_environment_binding_current(state: &SystemEnvironment, binding: &std::sync::Arc<TcpBinding>) -> bool {
    if state.cancelled.load(std::sync::atomic::Ordering::Acquire)
        || !binding.valid.load(std::sync::atomic::Ordering::Acquire) { return false; }
    let ready = state.ready.lock().unwrap_or_else(|error| error.into_inner());
    ready.as_ref().is_some_and(|current| std::sync::Arc::ptr_eq(current, binding))
}

#[cfg(windows)]
fn maintain_system_proxy_environment(root: std::sync::Arc<crate::command_lifetime::CommandLifetime>,
    state: std::sync::Arc<SystemEnvironment>, active: crate::settings::ActiveTransportConfig) -> Result<(), String> {
    if !active.client_proxy { return Ok(()); }
    let mut pending: Option<crate::command_lifetime::PendingCommand> = None;
    let mut pending_binding: Option<std::sync::Arc<TcpBinding>> = None;
    let mut operation_result: Result<(), String> = Ok(());
    let mut last_binding: Option<std::sync::Arc<TcpBinding>> = None;
    let mut next_observe = Instant::now();
    loop {
        root.receive();
        if pending.as_ref().is_some_and(|command| command.pending()) {
            thread::park_timeout(proxy::PUMP_MAX_SLEEP);
            continue;
        }
        if let Some(command) = pending.take() {
            // This is the same attempted environment operation's actual late
            // result. A late exit zero cannot erase its original timeout.
            operation_result = command.failure().map_or(Ok(()), Err);
            if let Some(binding) = pending_binding.take() {
                let receiving = gate::recheck_transport_instance(&binding.instance).and_then(|_| {
                    if system_environment_binding_current(&state, &binding) { Ok(()) }
                    else { Err("late environment action settled after its binding changed; effects remain unconfirmed".into()) }
                });
                if let Err(error) = receiving {
                    operation_result = Err(match operation_result { Ok(()) => error, Err(original) => format!("{original}; {error}") });
                }
            }
            if operation_result.is_err() { log_proxy("system proxy environment result failed; actual command facts retained by its receiver"); }
        }
        if state.cancelled.load(std::sync::atomic::Ordering::Acquire) { return operation_result; }
        let binding = state.ready.lock().unwrap_or_else(|error| error.into_inner()).clone();
        let Some(binding) = binding.filter(|binding| system_environment_binding_current(&state, binding)) else {
            thread::park_timeout(proxy::PUMP_MAX_SLEEP);
            continue;
        };
        let changed = !last_binding.as_ref().is_some_and(|last| std::sync::Arc::ptr_eq(last, &binding));
        if !changed && Instant::now() < next_observe {
            thread::park_timeout(proxy::PUMP_MAX_SLEEP);
            continue;
        }
        last_binding = Some(binding.clone());
        next_observe = Instant::now() + proxy::REBIND_EVERY;
        // The full existing receiver preserves TaskSet/EnginePID/report/native
        // listener checks. It runs here while the carrier continues accepting.
        let qualified = crate::background::observe_background_for_transport(&state.cancelled, None, active)
            .and_then(|observed| receive_system_environment_observation(&observed, &binding, active));
        if let Err(error) = qualified {
            operation_result = Err(error);
            log_proxy("system proxy environment held: task, instance or channel qualification is unknown");
            continue;
        }
        if !system_environment_binding_current(&state, &binding) { continue; }
        gate::recheck_transport_instance(&binding.instance)?;
        let url = proxy::url_at(binding.address.port());
        let applied = match root.call_with_outcome("system proxy environment", |outcome| {
            if !system_environment_binding_current(&state, &binding) { return Err("system proxy binding changed before environment action".into()); }
            gate::recheck_transport_instance(&binding.instance)?;
            crate::endpoint::ensure_proxy_env(outcome, &url)
        }) {
            Ok((value, command)) => {
                if command.pending() { pending_binding = Some(binding.clone()); pending = Some(command); }
                value
            },
            Err(error) => Err(error),
        };
        operation_result = applied.map(|_| ());
        if pending.is_some() { continue; }
        // Receive actual effects before claiming a still-current activation.
        // An invalidated post-check is explicit partial/unconfirmed state; no
        // guessed rollback or command replay follows it.
        let after = gate::recheck_transport_instance(&binding.instance).and_then(|_| {
            if !system_environment_binding_current(&state, &binding) { return Err("environment action returned after its transport binding changed; effects may be partial".into()); }
            crate::background::observe_background_for_transport(&state.cancelled, None, active)
                .and_then(|observed| receive_system_environment_observation(&observed, &binding, active))
        });
        if let Err(error) = after {
            operation_result = Err(match operation_result { Ok(()) => error, Err(original) => format!("{original}; post-action receiving: {error}") });
        }
        if operation_result.is_err() { log_proxy("system proxy environment action failed or remains unconfirmed; original result retained"); }
    }
}

#[cfg(windows)]
fn run_explicit_transport(root: std::sync::Arc<crate::command_lifetime::CommandLifetime>, settings: crate::settings::Settings,
    requirements: crate::settings::TransportRequirements) -> Result<(), String> {
    let active = requirements.active_config;
    active.validate()?;
    let received = settings.transport_requirements()?;
    if received.active_config != active || received.carrier != requirements.carrier {
        return Err("explicit carrier configuration differs from its captured settings".into());
    }
    if !requirements.carrier { return Ok(()); }
    // Both profiles reach this same owner. System's disabled DNS/aliases and
    // private work never enter the legacy unconditional startup below.
    loopback::receive_transport_config(active)?;
    let report = gate::transport_started(active)?;
    let listener = if active.tcp_proxy { Some(proxy::TransportListener::new(settings, active, 0)?) } else { None };
    let environment = std::sync::Arc::new(SystemEnvironment { cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)), ready: Mutex::new(None) });
    let dns = active.dns.then(|| DnsChannel::new(listen_addr(), environment.cancelled.clone(), thread::current()));
    let aliases = if active.dns_alias { Some(loopback::AliasListeners::new(active, environment.cancelled.clone(), thread::current())?) } else { None };
    let mut owner = ExplicitTransportCarrier { listener, dns, dns_probe: None, dns_probe_result: None, dns_probe_receipt: Ok(()),
        dns_completed: Vec::new(), dns_results: Vec::new(), dns_blocker: None, dns_listener_failure: None, next_dns_probe: Instant::now(),
        aliases, alias_completed: Vec::new(), alias_results: Vec::new(), alias_failure: None, alias_blocker: None,
        warming: None, warm_resolver: None, resolver_completed: Vec::new(), resolver_results: Vec::new(),
        warm_result: None, warm_receipt: Ok(()), next_warm: Instant::now(), next_private_probe: Instant::now(),
        workers: proxy::ConnectionWorkers::default(), report, binding: None,
        probe: None, probe_result: None, probe_receipt: Ok(()), environment, maintainer: None, maintainer_result: None,
        completed: Vec::new(), request_results: Vec::new(), listener_failure: None, blocker: None,
        publication: Ok(()), metadata_receiving: Ok(()), role_result: Ok(()), terminal_error: None, panics: Vec::new(),
        next_publish: Instant::now(), next_probe: Instant::now(), dirty: true };
    owner.workers.register_current_thread()?;
    if active.profile == crate::settings::TransportProfile::ExistingConfigured { routes::register_dns_maintenance_thread(); }
    if active.client_proxy {
        let state = owner.environment.clone();
        let commands = root.clone();
        owner.maintainer = Some(thread::Builder::new().name("proxy-environment".into())
            .spawn(move || maintain_system_proxy_environment(commands, state, active)).map_err(|error| io_failure_facts(&error))?);
    }
    loop {
        // The real owners remain outside the catch. A panic requests supported
        // cancellation, then receives only: it never replays service startup.
        let tick = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.poll(&root)));
        let step = match tick {
            Ok(Ok(step)) => step,
            Ok(Err(error)) => { owner.receive_terminal_error(error); owner.cancel(); proxy::ListenerStep::Idle },
            Err(payload) => { owner.panics.push(payload); owner.cancel(); proxy::ListenerStep::Idle },
        };
        if step == proxy::ListenerStep::Stopped && !owner.has_unreceived() && owner.metadata_receiving.is_ok() {
            routes::unregister_dns_maintenance_thread();
            if !owner.panics.is_empty() { std::panic::resume_unwind(owner.panics.remove(0)); }
            return owner.terminal_error.map_or(owner.role_result, Err).and(owner.publication);
        }
        if step != proxy::ListenerStep::Progress {
            let deadline = if owner.environment.cancelled.load(std::sync::atomic::Ordering::Acquire) { None } else {
                owner.listener.as_ref().and_then(|listener| listener.next_bind_deadline())
                .into_iter().chain(owner.dns.as_ref().filter(|dns| dns.socket.is_none()).map(|dns| dns.next_bind))
                .chain(owner.aliases.as_ref().filter(|_| matches!(owner.report.observed.tcp_proxy, gate::CapabilityObservation::Ready))
                    .and_then(|aliases| aliases.next_bind_deadline())).min()
            };
            let wait = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(proxy::PUMP_MAX_SLEEP).min(proxy::PUMP_MAX_SLEEP);
            thread::park_timeout(wait);
        }
    }
}

#[cfg(windows)]
fn receive_carrier_startup(intent: crate::settings::TransportIntent) -> Result<WindowsCarrierStartup, String> {
    use crate::settings::TransportIntent;
    match intent {
        TransportIntent::Legacy(_) => Ok(WindowsCarrierStartup::Legacy),
        TransportIntent::Explicit { settings, requirements } => {
            requirements.active_config.validate()?;
            Ok(WindowsCarrierStartup::Explicit { settings, requirements })
        }
        TransportIntent::Missing => Err("carrier startup requires committed transport intent".into()),
        TransportIntent::Broken(error) => Err(format!("carrier transport intent was not received: {error}")),
    }
}

pub fn run(root: std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> Result<(), String> {
    #[cfg(windows)]
    {
        // One checked committed snapshot precedes every carrier effect. A new
        // instance, never a later cache reload, owns either explicit profile.
        match receive_carrier_startup(crate::settings::checked_transport_intent())? {
            WindowsCarrierStartup::Explicit { settings, requirements } => return run_explicit_transport(root, settings, requirements),
            WindowsCarrierStartup::Legacy => crate::watchdog::start(root.clone()),
        }
    }
    // Detect once up front. Otherwise the first query pays for a cold probe,
    // which is long enough that Windows gives up on us and falls back to the
    // direct resolvers - and then caches that unsubstituted answer for its full
    // TTL, so one slow startup is felt for minutes.
    log(&format!("egress: if{}", isp_interface(&root)));
    record_version();
    // Before any listener is tried: from here on the window can tell this
    // process from its own watchdog by the age of what it writes (P54).
    gate::note_started();
    { let root = root.clone(); thread::spawn(move || warm_forever(root)); }
    // The proxy variable is user-wide and must never outlive the listener it
    // names, so the watchdog takes it off when the listener is dead for a while
    // (G20). This is the other half: the listener is up, so the route is back.
    // Off the startup path - it is a PowerShell call - and never in front of a
    // proxy the user set themselves.
    //
    // "Is up", not "is coming up": this used to run the moment the relay started,
    // which is a promise about a socket that had not been bound yet. When the bind
    // then failed - the port is inside Windows' dynamic range, so it can be taken
    // (G31) - the variable was restored anyway and the watchdog took it back off
    // ninety seconds later, every logon, and everything proxy-aware on the machine
    // spent that window with no network.
    spawn_proxy_env_maintainer(root.clone());

    // The fallback route lives in this process because it needs the same two
    // things the relay already has: the ISP interface, and the resolver pool
    // that knows which provider is substituting right now. It only ever carries
    // traffic that is actually pointed at it, so starting it here costs a
    // listening socket and nothing else.
    let egress = isp_interface(&root);
    let proxy_root = root.clone();
    thread::spawn(move || {
        if let Err(e) = proxy::run(&proxy_root, egress) {
            log_proxy(&format!("not started: {}", e));
        }
    });
    // The gate hosts' own door (`loopback`). If it cannot be bound the relay
    // keeps answering with substituted addresses, exactly as before.
    let loopback_root = root.clone();
    thread::spawn(move || {
        if let Err(e) = loopback::run(&loopback_root) {
            log_proxy(&format!("локальные адреса гейт-хостов не заняты: {}", e));
        }
    });
    { let root = root.clone(); thread::spawn(move || watch_client_logs(root)); }

    serve_dns_forever(root)
}

/// The Linux service entry point: runs the local CONNECT proxy route as a
/// background service without a port-53 DNS listener.
///
/// It maintains gate.json, the resolver pool, client log watching, and the
/// proxy environment variable, then serves the local proxy on 127.0.0.1:53129.
pub fn run_proxy_service(root: std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> Result<(), String> {
    log_proxy("служба обхода (локальный прокси) запущена");
    record_version();
    gate::note_started();
    { let root = root.clone(); thread::spawn(move || warm_forever(root)); }
    { let root = root.clone(); thread::spawn(move || watch_client_logs(root)); }
    spawn_proxy_env_maintainer(root.clone());
    proxy::run(&root, 0)
}

fn spawn_proxy_env_maintainer(root: std::sync::Arc<crate::command_lifetime::CommandLifetime>) {
    thread::spawn(move || {
        let var = crate::endpoint::PROXY_ENV_VAR;
        #[cfg(windows)]
        let mut pending: Option<crate::command_lifetime::PendingCommand> = None;
        #[cfg(windows)]
        let mut environment_result: Result<(), String> = Ok(());
        #[cfg(not(windows))]
        let legacy = crate::endpoint::remove_legacy_proxy_env(&proxy::proxy_url());
        #[cfg(not(windows))]
        match legacy {
            Ok(true) => log_proxy("снята прежняя общесистемная HTTPS_PROXY"),
            Ok(false) => {}
            Err(e) => log_proxy(&format!("прежняя HTTPS_PROXY не снята: {}", e)),
        }
        #[cfg(not(target_os = "macos"))]
        let mut waiting_said = false;
        loop {
            // The port that answered is the one named: the proxy may have moved
            // while this waited (P26), and only our own listener counts - not a
            // program of someone else's answering on the default port.
            root.receive();
            #[cfg(windows)]
            if pending.as_ref().is_some_and(|receipt| receipt.pending()) {
                thread::sleep(proxy::REBIND_EVERY);
                continue;
            }
            #[cfg(windows)]
            if let Some(command) = pending.take() {
                // This exact environment operation receives its later facts
                // before its pending value can be forgotten or reconciled anew.
                environment_result = command.failure().map_or(Ok(()), Err);
                if let Err(error) = &environment_result { log_proxy(&format!("поздний результат изменения среды: {error}")); }
            }
            #[cfg(target_os = "macos")]
            match crate::endpoint::reconcile_mac_proxy(crate::endpoint::MacProxyAction::Relay, None) {
                Ok(true) => log_proxy(&format!("{}: среда локального прокси обновлена", var)),
                Ok(false) => {},
                Err(error) => log_proxy(&format!("{}: среда локального прокси не подтверждена: {error}", var)),
            }
            #[cfg(not(target_os = "macos"))]
            {
            let received_listener = proxy::wait_for_our_listener(&root, PROXY_START_BUDGET);
            let port = match received_listener {
                Ok(Some(port)) => port,
                Err(error) => {
                    log_proxy(&format!("{} не изменена: получение собственного слушателя завершилось ошибкой: {}", var, error));
                    return;
                }
                Ok(None) => {
                // It keeps trying (`proxy::run`, P53): an antivirus exception
                // or a closed program frees the port without a restart, and the
                // variable follows the listener up - still only once it answers.
                // Said once per outage, not once a minute: this log is 64 KB.
                if !waiting_said {
                    log_proxy(&format!(
                        "{} не выставлена: локальный прокси не поднялся",
                        var
                    ));
                    waiting_said = true;
                }
                    continue;
                }
            };
            waiting_said = false;
            let url = proxy::url_at(port);
            if crate::settings::local_proxy_wanted() {
                // `ensure_proxy_env` asks `foreign_proxy` first, so a proxy the
                // user set themselves still outranks ours (D19, I52, G33).
                #[cfg(windows)]
                let applied = match root.call_with_outcome("proxy environment", |owner| crate::endpoint::ensure_proxy_env(owner, &url)) {
                    Ok((value, receipt)) => { if receipt.pending() { pending = Some(receipt); } value },
                    Err(error) => Err(error),
                };
                #[cfg(not(windows))]
                let applied = crate::endpoint::ensure_proxy_env(&url);
                #[cfg(windows)]
                { environment_result = applied.as_ref().map(|_| ()).map_err(Clone::clone); }
                match applied {
                    Ok(crate::endpoint::Outcome::Applied) => {
                        log_proxy(&format!("{} снова указывает на локальный прокси", var))
                    }
                    Ok(crate::endpoint::Outcome::AlreadySet) => {}
                    Err(e) => log_proxy(&format!("{} не восстановлена: {}", var, e)),
                }
            } else {
                #[cfg(windows)]
                let ours = match root.call_with_outcome("proxy environment observation", crate::endpoint::proxy_env_is_ours) {
                    Ok((value, receipt)) => { if receipt.pending() { pending = Some(receipt); } value },
                    Err(error) => Err(error),
                };
                #[cfg(not(windows))]
                let ours: Result<bool, String> = Ok(crate::endpoint::proxy_env_is_ours());
                let ours = match ours { Ok(value) => value, Err(error) => { log_proxy(&format!("состояние прокси неизвестно: {error}")); thread::sleep(proxy::REBIND_EVERY); continue; } };
                if ours {
                // Off in the settings and still set. `remove_proxy` judges each
                // variable on its own: `PROXY_ENV_VAR` is a name only this tool
                // writes, and the legacy pair is removed by value, so a proxy of
                // the user's own is never taken off here.
                #[cfg(windows)]
                let removed = match root.call_with_outcome("remove proxy environment", |owner| crate::endpoint::remove_proxy(owner, &url, "")) {
                    Ok((value, receipt)) => { if receipt.pending() { pending = Some(receipt); } value },
                    Err(error) => Err(error),
                };
                #[cfg(not(windows))]
                let removed = crate::endpoint::remove_proxy(&url, "");
                #[cfg(windows)]
                { environment_result = removed.as_ref().map(|_| ()).map_err(Clone::clone); }
                match removed {
                    Ok(()) => log_proxy(&format!(
                        "{} снята: локальный прокси выключен в настройках",
                        var
                    )),
                    Err(e) => log_proxy(&format!("{} не снята: {}", var, e)),
                }
                }
            }
            }
            thread::sleep(proxy::REBIND_EVERY);
        }
    });
}

/// Where the NRPT rules send their queries, as an address to bind and to
/// diagnose. `LISTEN_IP` is a literal and always parses; the fallback only
/// exists so a typo in it could never panic the relay.
fn listen_addr() -> SocketAddr {
    SocketAddr::from((
        LISTEN_IP.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::LOCALHOST),
        LISTEN_PORT,
    ))
}

/// How many `recv_from` failures in a row mean the socket is gone rather than
/// one exchange having gone wrong.
///
/// Windows surfaces an ICMP port-unreachable for an answer we already sent as
/// `WSAECONNRESET` on the *next* receive, so single errors are ordinary and are
/// skipped, as they always were. Sixty-four of them with not one query in
/// between is a socket worth dropping and taking again.
const RECV_ERRORS_BEFORE_REBIND: u32 = 64;

/// Holds `127.0.0.53:53` and answers on it, for as long as the process lives.
///
/// A port that cannot be had is diagnosed (`portcheck`), published for the
/// window's card (`gate::set_blocker`) and tried again every minute, the same
/// way the local proxy and the door already do. Unlike those two it cannot move
/// to another port: the NRPT rules name an address and Windows sends DNS to
/// port 53 or nowhere. Meanwhile the NRPT rules list this address *first* and
/// the substituting providers after it, so a Windows client falls through to
/// them on its own - the layer degrades to slow rather than to nothing.
fn serve_dns_forever(root: std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> ! {
    let addr = listen_addr();
    let mut said: Option<crate::gate::Blocker> = None;
    loop {
        root.receive();
        let sock = match UdpSocket::bind(addr) {
            Ok(sock) => {
                if said.take().is_some() {
                    log("порт DNS-релея освободился");
                    gate::set_blocker("dns", None);
                }
                sock
            }
            Err(e) => {
                let cause = match root.call("DNS port diagnosis", |owner| crate::portcheck::diagnose_on(owner, addr, &e, crate::portcheck::Proto::Udp)) {
                    Ok(Ok(value)) => value,
                    Ok(Err(error)) | Err(error) => { log(&format!("диагностика DNS порта недоступна: {error}")); crate::portcheck::Cause::Other }
                };
                let blocker = cause.blocker("dns", addr, &e);
                // Once per distinct cause: the retry is a minute, the log is 64 KB.
                if said.as_ref() != Some(&blocker) {
                    log(&format!(
                        "не занять {} — {} ({}{})",
                        blocker.addr,
                        blocker.error,
                        blocker.cause,
                        if blocker.by.is_empty() {
                            String::new()
                        } else {
                            format!(": {}", blocker.by)
                        }
                    ));
                    said = Some(blocker.clone());
                }
                // Every try, so the record never goes stale under the card.
                gate::set_blocker("dns", Some(blocker));
                thread::sleep(proxy::REBIND_EVERY);
                continue;
            }
        };
        log(&format!("start: {}:{}", LISTEN_IP, LISTEN_PORT));
        // A client that was running before us is on answers that predate our
        // rules, and nothing else tells it otherwise (G75). Here and not a line
        // earlier: the socket is bound, so a re-ask reaches us.
        if crate::dns::flush_client_cache() {
            log("кэш DNS-клиента по гейт-именам сброшен — клиент спросит заново");
        }
        let up = Instant::now();
        serve_queries(&root, &sock);
        drop(sock);
        log("DNS-сокет перестал принимать запросы — занимаем заново");
        // Never in a tight loop: a socket that did not last a minute is not one
        // an immediate retry will fix, so it waits out the same clock a failed
        // bind does.
        if up.elapsed() < proxy::REBIND_EVERY {
            thread::sleep(proxy::REBIND_EVERY);
        }
    }
}

/// Answers queries on `sock` until it stops taking them.
fn serve_queries(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, sock: &UdpSocket) {
    let mut buf = [0u8; 4096];
    let mut misses = 0u32;
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(v) => {
                misses = 0;
                v
            }
            Err(_) => {
                misses += 1;
                if misses >= RECV_ERRORS_BEFORE_REBIND {
                    return;
                }
                continue;
            }
        };
        // Anything shorter than a header is not a query worth relaying.
        if n < 12 {
            continue;
        }
        let query = buf[..n].to_vec();
        let out = match sock.try_clone() {
            Ok(s) => s,
            Err(_) => continue,
        };
        // One thread per query: the volume is a handful per minute, and a slow
        // upstream must not stall the queries behind it.
        let observation = prepare_isp_interface(root);
        let root = root.clone();
        thread::spawn(move || {
            let _ = answer_dns_query(&root, &query, &out, from, Some(observation), None, None);
        });
    }
}

/// The answer the relay gives a gate host itself instead of relaying anyone's.
///
/// A record: the loopback listener's address for that host, while it is up
/// (`loopback`). AAAA, SVCB and HTTPS: an empty answer, always - every provider
/// answers AAAA with Google's own IPv6 or with nothing, and an IPv6 client
/// handed the former dials the gate from the blocked region with the whole
/// layer "working" (P40); an HTTPS record can carry address hints of its own.
/// Anything else is relayed as before.
fn own_answer(query: &[u8], name: &str) -> Option<Vec<u8>> {
    if !proxy::is_gate_host(name) {
        return None;
    }
    match dns_client::question_type(query)? {
        1 => {
            let ip = loopback::answer_for(name)?;
            note_loopback(name);
            dns_client::synth_reply(query, Some(ip), loopback::ANSWER_TTL)
        }
        28 | 64 | 65 => dns_client::synth_reply(query, None, loopback::ANSWER_TTL),
        _ => None,
    }
}

/// Logs that a gate host is being answered with our own address - once, and
/// again only after it has not been for a while, so a client re-asking every
/// thirty seconds does not fill the 64 KB log.
fn note_loopback(name: &str) {
    static LAST: Mutex<Option<std::collections::HashMap<String, Instant>>> = Mutex::new(None);
    let due = LAST
        .lock()
        .map(|mut g| {
            let map = g.get_or_insert_with(std::collections::HashMap::new);
            let key = name.to_ascii_lowercase();
            let due = map
                .get(&key)
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(30 * 60));
            if due {
                map.insert(key, Instant::now());
            }
            due
        })
        .unwrap_or(false);
    if due {
        log(&format!("loopback     {} [наш маршрут]", name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_state_paths_use_explicit_xdg_and_keep_relative_components() {
        let cwd = std::env::temp_dir().join("synthetic launch");
        let explicit = cwd.join("state");
        let no_home = || panic!("explicit XDG does not need HOME");
        let no_cwd = || panic!("absolute XDG does not need the working directory");
        assert_eq!(
            resolve_unix_directory(explicit.to_str(), ".local/share", no_home).unwrap(),
            explicit
        );
        let old_relative = PathBuf::from("link").join("..").join("state");
        assert_eq!(
            resolve_unix_directory(old_relative.to_str(), ".local/share", no_home).unwrap(),
            old_relative
        );
        assert_eq!(
            absolute_user_path(old_relative.clone(), || Ok(cwd.clone())).unwrap(),
            cwd.join(&old_relative)
        );
        assert_eq!(absolute_user_path(explicit.clone(), no_cwd).unwrap(), explicit);
        assert!(absolute_user_path(PathBuf::from("state"), || Err("cwd unavailable".into())).is_err());
        for unset in [None, Some("")] {
            assert_eq!(
                resolve_unix_directory(unset, ".local/share", || Ok(cwd.clone())).unwrap(),
                cwd.join(".local/share")
            );
            assert!(resolve_unix_directory(unset, ".local/share", || Err("home unavailable".into())).is_err());
        }
    }

    #[test]
    fn unix_home_uses_native_account_only_for_unset_or_empty_environment() {
        use std::ffi::OsString;

        let cwd = std::env::temp_dir().join("synthetic launch");
        let account = cwd.join("account");
        let no_account = || panic!("explicit HOME does not need account lookup");
        for absent in [None, Some(OsString::new())] {
            assert_eq!(resolve_unix_home(absent, || Some(account.clone())).unwrap(), account);
        }
        for invalid in [None, Some(PathBuf::new()), Some(PathBuf::from("relative"))] {
            assert!(resolve_unix_home(None, || invalid).is_err());
        }
        assert_eq!(resolve_unix_home(Some("home".into()), no_account).unwrap(), PathBuf::from("home"));
        assert_eq!(resolve_unix_home(Some(account.clone().into_os_string()), no_account).unwrap(), account);
    }

    #[cfg(unix)]
    #[test]
    fn legacy_relative_xdg_keeps_existing_state_through_symlink_and_parent_step() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().canonicalize().unwrap()
            .join(format!("ag-relative-state-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let cwd = root.join("launch");
        let physical = root.join("physical");
        let home = root.join("home");
        let existing = physical.join("state/agunlocker");
        let default = home.join(UNIX_DATA_SUFFIX).join("agunlocker");
        for path in [&cwd, &existing, &default, &physical.join("child")] {
            fs::create_dir_all(path).unwrap();
        }
        symlink(physical.join("child"), cwd.join("link")).unwrap();
        fs::write(existing.join("settings.json"), b"existing").unwrap();
        fs::write(default.join("settings.json"), b"default").unwrap();

        let non_unicode = OsString::from_vec(vec![0xff]);
        let native_home = resolve_unix_home(Some(non_unicode.clone()), || panic!("explicit HOME does not need account lookup"));
        let unavailable = resolve_unix_directory(None, UNIX_DATA_SUFFIX, || Err("home unavailable".into()));
        let selected = resolve_unix_directory(Some("link/../state"), UNIX_DATA_SUFFIX, || Ok(home.clone())).unwrap();
        let legacy_bytes = fs::read(cwd.join(selected).join("agunlocker/settings.json")).unwrap();
        let default_bytes = fs::read(default.join("settings.json")).unwrap();
        let wrong_created = cwd.join("state").exists();
        fs::remove_dir_all(root).unwrap();

        assert_eq!(native_home.unwrap(), PathBuf::from(non_unicode));
        assert!(unavailable.is_err());
        assert_eq!(legacy_bytes, b"existing");
        assert_eq!(default_bytes, b"default");
        assert!(!wrong_created);
    }

    #[cfg(unix)]
    #[test]
    fn relative_state_follows_a_renamed_working_directory() {
        const NAME: &str = "dns_forwarder::tests::relative_state_follows_a_renamed_working_directory";
        const CHILD_ROOT: &str = "AG_RELATIVE_STATE_RENAME_FIXTURE";
        const ORIGINAL: &[u8] = b"original fixture settings";
        const SUCCESSOR: &[u8] = b"successor fixture settings";
        const UPDATED: &[u8] = b"updated original fixture settings";

        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            let launch = root.join("launch");
            let moved = root.join("moved");
            let relative = "relative/agunlocker";
            assert_eq!(root.parent(), Some(std::env::temp_dir().canonicalize().unwrap().as_path()));
            assert_eq!(std::env::current_dir().unwrap(), launch);
            let selected = checked_log_dir().unwrap().join("settings.json");
            assert_eq!(fs::read(&selected).unwrap(), ORIGINAL);

            fs::rename(&launch, &moved).unwrap();
            let successor = launch.join(relative);
            fs::create_dir_all(&successor).unwrap();
            fs::write(successor.join("settings.json"), SUCCESSOR).unwrap();

            assert_eq!(fs::read(&selected).unwrap(), ORIGINAL);
            fs::write(&selected, UPDATED).unwrap();
            assert_eq!(fs::read(successor.join("settings.json")).unwrap(), SUCCESSOR);
            return;
        }

        let root = std::env::temp_dir().canonicalize().unwrap()
            .join(format!("ag-state-cwd-rename-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let launch = root.join("launch");
        let state = launch.join("relative/agunlocker");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("settings.json"), ORIGINAL).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME])
            .current_dir(&launch)
            .env("XDG_DATA_HOME", "relative")
            .env(CHILD_ROOT, &root)
            .output().unwrap();
        let moved = fs::read(root.join("moved/relative/agunlocker/settings.json"));
        let successor = fs::read(state.join("settings.json"));
        fs::remove_dir_all(root).unwrap();

        assert!(child.status.success(), "{}{}", String::from_utf8_lossy(&child.stdout), String::from_utf8_lossy(&child.stderr));
        assert_eq!(moved.unwrap(), UPDATED);
        assert_eq!(successor.unwrap(), SUCCESSOR);
    }

    #[test]
    #[ignore = "isolated process: owns candidate route state and local sockets"]
    fn candidate_maintenance_publishes_first_while_later_probe_is_held() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;
        let _lease = routes::lease_test_dns_state().unwrap();
        let witness = resolvers::test_source_witness();
        let first = resolvers::test_source_candidate(Ipv4Addr::new(8, 8, 8, 8), &witness);
        let second = resolvers::test_source_candidate(Ipv4Addr::new(1, 1, 1, 1), &witness);
        let hosts: Vec<_> = crate::gate_hosts::public_dns_hosts().collect();
        for _ in &hosts {
            maintain_dns_candidate_step_with(0, true, None, || Ok(witness.clone()),
                |_| Ok(vec![first.clone(), second.clone()]),
                |_, _, _, _, _, _| Ok(resolvers::DiscoveryStep { candidates: Vec::new(), state: resolvers::DiscoveryState::Exhausted }),
                |_, _, _, _| Ok(proxy::CandidateProbe::Reachable(Duration::from_millis(1))), |_| {}).unwrap();
        }
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_witness = witness.clone();
        let worker_first = first.clone();
        let worker_second = second.clone();
        let worker = thread::spawn(move || maintain_dns_candidate_step_with(0, true, None,
            || Ok(worker_witness.clone()), |_| Ok(vec![worker_first.clone(), worker_second.clone()]),
            |_, _, _, _, _, _| Ok(resolvers::DiscoveryStep { candidates: Vec::new(), state: resolvers::DiscoveryState::Exhausted }),
            |_, _, _, _| {
                let _ = started_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(5)).map_err(|error| error.to_string())?;
                Ok(proxy::CandidateProbe::Reachable(Duration::from_millis(1)))
            }, |_| {}));
        let started = started_rx.recv_timeout(Duration::from_secs(2));
        let selected = matches!(routes::dns_selection(hosts[0], &witness), Ok(routes::DnsSelection::Ready(ref items)) if items.iter().any(|(admission, _)| admission.ip == first.ip));
        // The local address is an explicit fixture mapping, not the public
        // candidate's network identity; the checked production connector runs.
        let transferred = if started.is_ok() && selected {
            (|| -> Result<bool, String> {
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| error.to_string())?;
                let address = listener.local_addr().map_err(|error| error.to_string())?;
                let mut sender = crate::proxy::connect_fixture_addrs(vec![address], Duration::from_secs(1))?;
                sender.write_all(b"ok").map_err(|error| error.to_string())?;
                let (mut receiver, _) = listener.accept().map_err(|error| error.to_string())?;
                receiver.set_read_timeout(Some(Duration::from_secs(1))).map_err(|error| error.to_string())?;
                let mut bytes = [0; 2];
                receiver.read_exact(&mut bytes).map_err(|error| error.to_string())?;
                Ok(&bytes == b"ok")
            })()
        } else { Ok(false) };
        let held = !worker.is_finished();
        let release = release_tx.send(());
        let result = worker.join();
        assert!(started.is_ok() && selected && held && release.is_ok());
        assert!(matches!(transferred, Ok(true)));
        assert!(matches!(result, Ok(Ok(_))));
    }

    #[test]
    #[ignore = "isolated process: owns candidate route state"]
    fn owned_probe_cancelled_while_held_cannot_publish() {
        use std::sync::mpsc;
        let _lease = routes::lease_test_dns_state().unwrap();
        let witness = resolvers::test_source_witness();
        let candidate = resolvers::test_source_candidate(Ipv4Addr::new(8, 8, 8, 8), &witness);
        let work = std::sync::Arc::new(resolvers::ResolverWork::new(thread::current()));
        let worker_work = work.clone();
        let worker_witness = witness.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || maintain_dns_candidate_step_with(0, true, Some(&worker_work),
            || Ok(worker_witness.clone()), |_| Ok(vec![candidate.clone()]),
            |_, _, _, _, _, _| Ok(resolvers::DiscoveryStep { candidates: Vec::new(), state: resolvers::DiscoveryState::Exhausted }),
            |_, _, _, _| {
                let _ = started_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(5)).map_err(|error| error.to_string())?;
                Ok(proxy::CandidateProbe::Reachable(Duration::from_millis(1)))
            }, |_| {}));
        let started = started_rx.recv_timeout(Duration::from_secs(2));
        work.cancel();
        let release = release_tx.send(());
        let result = worker.join();
        let status = routes::dns_selection("cloudcode-pa.googleapis.com", &witness);
        assert!(started.is_ok() && release.is_ok() && !work.has_unreceived());
        assert!(matches!(result, Ok(Err(ref error)) if error.contains("after cancellation: reachable")));
        assert!(!matches!(status, Ok(routes::DnsSelection::Ready(_))));
    }

    #[test]
    #[ignore = "isolated process: owns candidate route state"]
    fn cancelled_owned_probe_never_publishes_success() {
        use std::sync::mpsc;
        let _lease = routes::lease_test_dns_state().unwrap();
        let witness = resolvers::test_source_witness();
        let candidate = resolvers::test_source_candidate(Ipv4Addr::new(8, 8, 8, 8), &witness);
        let work = std::sync::Arc::new(resolvers::ResolverWork::new(thread::current()));
        let owned_work = work.clone();
        let worker_witness = witness.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || maintain_dns_candidate_step_with(0, true, Some(&owned_work),
            || Ok(worker_witness.clone()), |_| Ok(vec![candidate.clone()]),
            |_, _, _, _, _, _| Ok(resolvers::DiscoveryStep { candidates: Vec::new(), state: resolvers::DiscoveryState::Exhausted }),
            |_, _, _, _| {
                let _ = started_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(5)).map_err(|error| error.to_string())?;
                Ok(proxy::CandidateProbe::Reachable(Duration::from_millis(1)))
            }, |_| {}));
        let started = started_rx.recv_timeout(Duration::from_secs(2));
        work.cancel();
        let release = release_tx.send(());
        let result = worker.join();
        let state = routes::dns_selection("cloudcode-pa.googleapis.com", &witness);
        let no_children = !work.has_unreceived();
        assert!(started.is_ok() && release.is_ok() && no_children);
        assert!(matches!(result, Ok(Err(ref message)) if message.contains("after cancellation: reachable")));
        assert!(!matches!(state, Ok(routes::DnsSelection::Ready(_))));
    }

    #[test]
    #[ignore = "isolated process: owns candidate route state"]
    fn candidate_maintenance_exhausts_failed_sources_without_inventing_routes() {
        use std::cell::{Cell, RefCell};
        let _lease = routes::lease_test_dns_state().unwrap();
        let witness = resolvers::test_source_witness();
        let candidate = resolvers::test_source_candidate(Ipv4Addr::new(8, 8, 8, 8), &witness);
        let hosts: Vec<_> = crate::gate_hosts::public_dns_hosts().collect();
        let timeout_once = Cell::new(true);
        let reports = RefCell::new(Vec::new());
        let mut pending = true;
        for _ in 0..(hosts.len() * 4 + 1) {
            pending = maintain_dns_candidate_step_with(0, true, None, || Ok(witness.clone()),
                |_| Ok(vec![candidate.clone()]),
                |_, _, _, _, _, _| if timeout_once.replace(false) { Err(resolvers::DnsSourceError::SourceTimeout) }
                    else { Ok(resolvers::DiscoveryStep { candidates: Vec::new(), state: resolvers::DiscoveryState::Exhausted }) },
                |_, _, _, _| Err("synthetic probe timeout".into()), |message| reports.borrow_mut().push(message.to_owned())).unwrap();
            if !pending { break; }
        }
        assert!(!pending);
        assert!(reports.borrow().iter().any(|message| message.contains("source timed out")));
        for host in hosts { assert!(matches!(routes::dns_selection(host, &witness).unwrap(), routes::DnsSelection::NoEligible)); }
    }
    use std::net::Ipv4Addr;

    #[cfg(windows)]
    struct ExplicitOracleOwner(ExplicitTransportCarrier);
    #[cfg(windows)]
    impl ExplicitOracleOwner {
        fn new(active: crate::settings::ActiveTransportConfig, listener: Option<proxy::TransportListener>, dns: Option<DnsChannel>) -> Self {
            use std::sync::{Arc, atomic::AtomicBool};
            Self(ExplicitTransportCarrier { listener, dns, dns_probe: None, dns_probe_result: None,
                dns_probe_receipt: Ok(()), dns_completed: Vec::new(), dns_results: Vec::new(), dns_blocker: None,
                dns_listener_failure: None, next_dns_probe: Instant::now(), workers: proxy::ConnectionWorkers::default(),
                aliases: None, alias_completed: Vec::new(), alias_results: Vec::new(), alias_failure: None, alias_blocker: None,
                warming: None, warm_resolver: None, resolver_completed: Vec::new(), resolver_results: Vec::new(),
                warm_result: None, warm_receipt: Ok(()), next_warm: Instant::now(), next_private_probe: Instant::now(),
                report: gate::TransportReport { schema: 1, instance: gate::TransportInstance { pid: 7, creation_time: 11 },
                    active_config: active, observed: gate::TransportCapabilities { dns: gate::CapabilityObservation::Starting,
                        tcp_proxy: gate::CapabilityObservation::Starting, dns_alias: gate::CapabilityObservation::Disabled } },
                binding: None, probe: None, probe_result: None, probe_receipt: Ok(()),
                environment: Arc::new(SystemEnvironment { cancelled: Arc::new(AtomicBool::new(false)), ready: Mutex::new(None) }),
                maintainer: None, maintainer_result: None, completed: Vec::new(), request_results: Vec::new(),
                listener_failure: None, blocker: None, publication: Ok(()), metadata_receiving: Ok(()), role_result: Ok(()),
                terminal_error: None, panics: Vec::new(), next_publish: Instant::now(), next_probe: Instant::now(), dirty: false })
        }
        fn settle(&mut self) -> Result<(), String> {
            self.0.cancel();
            if let Some(listener) = &mut self.0.listener { let _ = listener.poll(&mut self.0.workers); }
            let mut first_error = None;
            while self.0.has_unreceived() {
                for result in [self.0.receive_dns(), self.0.receive_workers(), self.0.receive_aliases()] {
                    if let Err(error) = result { if first_error.is_none() { first_error = Some(error); } }
                }
                if self.0.has_unreceived() { thread::yield_now(); }
            }
            match first_error { Some(error) => Err(error), None => Ok(()) }
        }
    }
    #[cfg(windows)]
    impl Drop for ExplicitOracleOwner { fn drop(&mut self) { let _ = self.settle(); } }

    #[cfg(windows)]
    fn explicit_oracle_config(dns: bool, tcp_proxy: bool) -> crate::settings::ActiveTransportConfig {
        crate::settings::ActiveTransportConfig { profile: crate::settings::TransportProfile::ExistingConfigured,
            dns, tcp_proxy, client_proxy: false, dns_alias: false }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "opt-in Windows synthetic loopback DNS reply benchmark"]
    fn single_worker_loopback_dns_reply_benchmark() {
        use std::sync::{atomic::{AtomicBool, Ordering}, mpsc};
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::{GetCurrentThread, GetThreadTimes}};

        // Keep measured worker CPU above the accounting granularity while
        // retaining unique transaction IDs. Timeout bounds abandoned I/O.
        const WARMUP_QUERIES: usize = 512;
        const MEASURED_QUERIES: usize = 32_768;
        const IO_TIMEOUT: Duration = Duration::from_secs(2);
        const ANSWER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 42);
        const RESPONSE_HEADER_AFTER_ID: [u8; 10] = [0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        // Question-name pointer, A, IN, TTL 60, four bytes, 127.0.0.42.
        const RESPONSE_ANSWER: [u8; 16] = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 42];

        fn worker_cpu_ticks() -> std::io::Result<(u64, u64)> {
            let mut creation = FILETIME::default();
            let mut exit = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            if unsafe { GetThreadTimes(GetCurrentThread(), &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let ticks = |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
            Ok((ticks(kernel), ticks(user)))
        }

        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind benchmark responder");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind benchmark driver");
        server.connect(client.local_addr().unwrap()).expect("connect responder to fixture peer");
        client.connect(server.local_addr().unwrap()).expect("connect driver to fixture peer");
        for socket in [&server, &client] {
            socket.set_read_timeout(Some(IO_TIMEOUT)).expect("bound benchmark receive");
            socket.set_write_timeout(Some(IO_TIMEOUT)).expect("bound benchmark send");
        }

        let cancelled = AtomicBool::new(false);
        let (start_tx, start_rx) = mpsc::channel();
        let (correct, elapsed, kernel, user) = thread::scope(|scope| {
            let worker_cancelled = &cancelled;
            let worker = scope.spawn(move || -> Result<(Duration, u64, u64), String> {
                let mut query = [0; 512];
                let mut serve = |count| -> Result<(), String> {
                    for _ in 0..count {
                        if worker_cancelled.load(Ordering::Relaxed) { return Err("benchmark driver stopped".into()); }
                        let bytes = server.recv(&mut query).map_err(|error| format!("responder receive: {error}"))?;
                        let reply = dns_client::synth_reply(&query[..bytes], Some(ANSWER), 60)
                            .ok_or("responder rejected a fixture query")?;
                        if server.send(&reply).map_err(|error| format!("responder send: {error}"))? != reply.len() {
                            return Err("responder sent a partial datagram".into());
                        }
                    }
                    Ok(())
                };
                serve(WARMUP_QUERIES)?;
                start_rx.recv_timeout(IO_TIMEOUT).map_err(|error| format!("measurement start: {error}"))?;
                let (kernel_start, user_start) = worker_cpu_ticks().map_err(|error| format!("worker CPU start: {error}"))?;
                let started = Instant::now();
                serve(MEASURED_QUERIES)?;
                let elapsed = started.elapsed();
                let (kernel_end, user_end) = worker_cpu_ticks().map_err(|error| format!("worker CPU end: {error}"))?;
                Ok((elapsed, kernel_end.checked_sub(kernel_start).ok_or("worker kernel CPU clock regressed")?,
                    user_end.checked_sub(user_start).ok_or("worker user CPU clock regressed")?))
            });

            let driver = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<usize, String> {
                let mut reply = [0; 512];
                let mut exchange = |transactions: std::ops::Range<usize>| -> Result<usize, String> {
                    let mut correct = 0;
                    for index in transactions {
                        let id = u16::try_from(index).map_err(|_| "fixture transaction ID overflow")?;
                        let query = dns_client::build_query("reply-bench.test", id);
                        if client.send(&query).map_err(|error| format!("query {id} send: {error}"))? != query.len() {
                            return Err(format!("query {id} sent a partial datagram"));
                        }
                        let bytes = client.recv(&mut reply).map_err(|error| format!("query {id} receive: {error}"))?;
                        let response = &reply[..bytes];
                        if response.len() != query.len() + RESPONSE_ANSWER.len() || response[..2] != id.to_be_bytes()
                            || response[2..12] != RESPONSE_HEADER_AFTER_ID
                            || response[12..query.len()] != query[12..]
                            || response[query.len()..] != RESPONSE_ANSWER {
                            return Err(format!("query {id} did not receive the exact fixture DNS response"));
                        }
                        correct += 1;
                    }
                    Ok(correct)
                };
                exchange(0..WARMUP_QUERIES)?;
                start_tx.send(()).map_err(|error| format!("signal measurement start: {error}"))?;
                exchange(WARMUP_QUERIES..WARMUP_QUERIES + MEASURED_QUERIES)
            }));
            if !matches!(&driver, Ok(Ok(_))) { cancelled.store(true, Ordering::Relaxed); }
            drop(start_tx);
            drop(client);
            let worker = worker.join();
            match (driver, worker) {
                (Ok(Ok(correct)), Ok(Ok((elapsed, kernel, user)))) => (correct, elapsed, kernel, user),
                (Err(payload), _) => std::panic::resume_unwind(payload),
                (driver, worker) => panic!("DNS benchmark failed; driver={driver:?}, worker={worker:?}"),
            }
        });
        assert_eq!(correct, MEASURED_QUERIES);
        assert!(!elapsed.is_zero());
        println!("DNS_SINGLE_WORKER_BENCH {}", serde_json::json!({
            "schema": 1, "warmupQueries": WARMUP_QUERIES, "correctReplies": correct,
            "elapsedNs": elapsed.as_nanos(), "workerKernel100ns": kernel, "workerUser100ns": user,
            "workerCpu100ns": kernel + user, "repliesPerSecond": correct as f64 / elapsed.as_secs_f64(),
        }));
    }

    #[cfg(windows)]
    #[test]
    fn finite_dns_aaaa_owns_socket_worker_and_receipt() {
        use std::sync::{Arc, atomic::AtomicBool};
        let root = Arc::new(crate::command_lifetime::CommandLifetime::default());
        let cancelled = Arc::new(AtomicBool::new(false));
        let dns = DnsChannel::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), cancelled.clone(), thread::current());
        let mut fixture = ExplicitOracleOwner::new(explicit_oracle_config(true, false), None, Some(dns));
        // Cancellation and query-result receiving happen before any assertion,
        // including when a fixture step fails or unwinds.
        std::sync::Arc::get_mut(&mut fixture.0.environment).expect("fixture environment is unique before launch").cancelled = cancelled;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(Vec<u8>, usize), String> {
            let dns = fixture.0.dns.as_mut().ok_or("DNS fixture absent")?;
            if !matches!(dns.poll(&root), Ok(proxy::ListenerStep::Progress)) { return Err("DNS ephemeral bind failed".into()); }
            let server = dns.binding.as_ref().ok_or("DNS binding absent")?.address;
            let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| error.to_string())?;
            client.set_read_timeout(Some(Duration::from_secs(3))).map_err(|error| error.to_string())?;
            let mut query = dns_client::build_query("daily-cloudcode-pa.googleapis.com", 9);
            let n = query.len(); query[n - 3] = 28;
            client.send_to(&query, server).map_err(|error| error.to_string())?;
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match fixture.0.dns.as_mut().unwrap().poll(&root) {
                    Ok(proxy::ListenerStep::Progress) if fixture.0.dns.as_ref().unwrap().has_unreceived() => break,
                    Ok(_) => (), Err(_) => return Err("DNS receive/worker start failed".into()),
                }
                if Instant::now() >= deadline { return Err("DNS query was not received".into()); }
                thread::yield_now();
            }
            let mut bytes = [0u8; 512];
            let (n, peer) = client.recv_from(&mut bytes).map_err(|error| error.to_string())?;
            if peer != server { return Err("DNS reply peer changed".into()); }
            if n < 12 || bytes[..2] != query[..2] || bytes[2] & 0x80 == 0 || bytes[3] & 0x0f != 0 || bytes[6] != 0 || bytes[7] != 0 {
                return Err("DNS response transaction, flags or answer count mismatch".into());
            }
            loop {
                fixture.0.receive_dns()?;
                if !fixture.0.dns_results.is_empty() { break; }
                if Instant::now() >= deadline { return Err("DNS worker receipt missing".into()); }
                thread::yield_now();
            }
            let sent = fixture.0.dns_results[0].as_ref().map_err(|error| error.clone())?;
            Ok((bytes[..n].to_vec(), *sent))
        }));
        let settled = fixture.settle();
        let (reply, sent) = result.expect("fixture unwound").expect("actual DNS operation");
        settled.expect("owned DNS worker settlement");
        assert_eq!(sent, reply.len());
        assert_eq!(dns_client::question_type(&reply), Some(28));
        assert!(dns_client::answer_addrs(&reply).is_empty());
        assert!(!fixture.0.has_unreceived());
    }

    #[cfg(windows)]
    #[test]
    fn finite_dns_cancel_retains_held_query_until_release_and_receiving() {
        use std::sync::{Arc, mpsc, atomic::AtomicBool};
        struct Release(Option<mpsc::Sender<()>>);
        impl Drop for Release { fn drop(&mut self) { if let Some(tx) = self.0.take() { let _ = tx.send(()); } } }
        let root = Arc::new(crate::command_lifetime::CommandLifetime::default());
        let cancelled = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut dns = DnsChannel::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), cancelled.clone(), thread::current());
        dns.fixture_query_gate = Some((started_tx, release_rx));
        let mut fixture = ExplicitOracleOwner::new(explicit_oracle_config(true, false), None, Some(dns));
        std::sync::Arc::get_mut(&mut fixture.0.environment).expect("fixture environment is unique before launch").cancelled = cancelled;
        let mut release = Release(Some(release_tx));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<bool, String> {
            let dns = fixture.0.dns.as_mut().ok_or("DNS fixture absent")?;
            if !matches!(dns.poll(&root), Ok(proxy::ListenerStep::Progress)) { return Err("DNS bind failed".into()); }
            let server = dns.binding.as_ref().ok_or("DNS binding absent")?.address;
            let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| error.to_string())?;
            let mut query = dns_client::build_query("daily-cloudcode-pa.googleapis.com", 19);
            let n = query.len(); query[n - 3] = 28;
            client.send_to(&query, server).map_err(|error| error.to_string())?;
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match fixture.0.dns.as_mut().unwrap().poll(&root) {
                    Ok(proxy::ListenerStep::Progress) if fixture.0.dns.as_ref().unwrap().has_unreceived() => break,
                    Ok(_) => (), Err(_) => return Err("DNS query worker was not started".into()),
                }
                if Instant::now() >= deadline { return Err("DNS query not received".into()); }
                thread::yield_now();
            }
            started_rx.recv_timeout(Duration::from_secs(3)).map_err(|error| error.to_string())?;
            fixture.0.cancel();
            fixture.0.receive_dns()?;
            Ok(fixture.0.has_unreceived() && fixture.0.dns_results.is_empty())
        }));
        if let Some(tx) = release.0.take() { let _ = tx.send(()); }
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut cancelled_result = None;
        while fixture.0.dns.as_ref().is_some_and(DnsChannel::has_unreceived) && Instant::now() < deadline {
            if let Err(error) = fixture.0.receive_dns() { cancelled_result = Some(Err(error)); break; }
            if let Some(value) = fixture.0.dns_results.first() { cancelled_result = Some(value.clone()); }
            thread::yield_now();
        }
        let settled = fixture.settle();
        let held = result.expect("fixture unwound").expect("held DNS observation");
        settled.expect("held DNS worker settlement");
        assert!(held, "cancel cannot declare a blocked query worker settled");
        assert!(matches!(cancelled_result, Some(Err(ref error)) if error == "DNS query cancelled"));
        assert!(!fixture.0.has_unreceived());
    }

    #[cfg(windows)]
    #[test]
    fn occupied_udp_preserves_actual_tcp_405_and_independent_receiving() {
        use std::io::Read;
        use std::sync::{Arc, atomic::AtomicBool};
        let root = Arc::new(crate::command_lifetime::CommandLifetime::default());
        let blocked = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let dns = DnsChannel::new(blocked.local_addr().unwrap(), cancelled.clone(), thread::current());
        let (listener, address) = proxy::tests::fixture_transport_listener();
        let mut fixture = ExplicitOracleOwner::new(explicit_oracle_config(true, true), Some(listener), Some(dns));
        std::sync::Arc::get_mut(&mut fixture.0.environment).expect("fixture environment is unique before launch").cancelled = cancelled;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(bool, Vec<u8>, bool), String> {
            fixture.0.poll_dns_step(&root)?;
            let dns_failed = matches!(&fixture.0.report.observed.dns, gate::CapabilityObservation::Failed(cause) if cause.starts_with("DNS bind:"));
            let mut client = std::net::TcpStream::connect(address).map_err(|error| error.to_string())?;
            client.set_read_timeout(Some(Duration::from_secs(3))).map_err(|error| error.to_string())?;
            client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").map_err(|error| error.to_string())?;
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let listener = fixture.0.listener.as_mut().ok_or("TCP listener absent")?;
                match listener.poll(&mut fixture.0.workers).map_err(|_| "TCP listener poll failed")? {
                    proxy::ListenerStep::Progress => break,
                    proxy::ListenerStep::Stopped => return Err("TCP listener stopped".into()),
                    proxy::ListenerStep::Idle => (),
                }
                if Instant::now() >= deadline { return Err("TCP request not accepted".into()); }
                thread::yield_now();
            }
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).map_err(|error| error.to_string())?;
            let mut received = false;
            while Instant::now() < deadline {
                fixture.0.receive_workers()?;
                if !fixture.0.request_results.is_empty() { received = fixture.0.request_results[0].is_ok(); break; }
                thread::yield_now();
            }
            Ok((dns_failed, reply, received))
        }));
        let settled = fixture.settle();
        let (dns_failed, reply, tcp_received) = result.expect("fixture unwound").expect("independent TCP operation");
        settled.expect("independent worker settlement");
        assert!(dns_failed, "occupied owned UDP must be independently reported");
        assert!(reply.starts_with(b"HTTP/1.1 405 "));
        assert!(tcp_received, "actual TCP worker completion must be received");
        assert!(!fixture.0.has_unreceived());
    }

    #[cfg(windows)]
    #[test]
    fn finite_alias_accept_splice_and_panic_preserve_worker_custody() {
        use std::io::Read;
        use std::sync::{Arc, mpsc, atomic::{AtomicBool, AtomicUsize, Ordering}};
        fn io_step(step: &str, error: &std::io::Error) -> String {
            format!("{step}: kind={:?} raw={:?}: {error}", error.kind(), error.raw_os_error())
        }
        struct Release(Option<mpsc::Sender<()>>);
        impl Drop for Release { fn drop(&mut self) { if let Some(tx) = self.0.take() { let _ = tx.send(()); } } }
        let first = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|error| panic!("{}", io_step("bind first alias", &error)));
        let second = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|error| panic!("{}", io_step("bind second alias", &error)));
        let alias_address = first.local_addr().unwrap_or_else(|error| panic!("{}", io_step("first alias address", &error)));
        let upstream = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap_or_else(|error| panic!("{}", io_step("bind upstream", &error)));
        upstream.set_nonblocking(true).unwrap_or_else(|error| panic!("{}", io_step("set upstream listener nonblocking", &error)));
        let upstream_address = upstream.local_addr().unwrap_or_else(|error| panic!("{}", io_step("upstream address", &error)));
        let cancelled = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let (held_started_tx, held_started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let (panic_tx, panic_rx) = mpsc::channel();
        let opener = {
            let calls = calls.clone();
            Arc::new(move |_: &'static str, address: SocketAddr, stopped: &AtomicBool| -> std::io::Result<std::net::TcpStream> {
                match calls.fetch_add(1, Ordering::SeqCst) {
                    0 => std::net::TcpStream::connect(address).map_err(|error| {
                        std::io::Error::new(error.kind(), io_step("opener upstream connect", &error))
                    }),
                    1 => {
                        held_started_tx.send(()).map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                        release_rx.lock().unwrap().recv().map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                        if stopped.load(Ordering::Acquire) { Err(std::io::ErrorKind::Interrupted.into()) }
                        else { std::net::TcpStream::connect(address).map_err(|error| {
                            std::io::Error::new(error.kind(), io_step("released opener upstream connect", &error))
                        }) }
                    }
                    _ => {
                        let original: Box<dyn std::any::Any + Send> = Box::new(147u64);
                        let pointer = original.as_ref() as *const _ as *const () as usize;
                        let _ = panic_tx.send(pointer);
                        std::panic::resume_unwind(original)
                    }
                }
            })
        };
        let aliases = loopback::AliasListeners::fixture(vec![("fixture-a", first), ("fixture-b", second)],
            cancelled.clone(), thread::current(), opener).unwrap_or_else(|error| panic!("{}", io_step("create alias fixture", &error)));
        let mut fixture = ExplicitOracleOwner::new(explicit_oracle_config(true, true), None, None);
        std::sync::Arc::get_mut(&mut fixture.0.environment).expect("fixture environment is unique before launch").cancelled = cancelled;
        fixture.0.aliases = Some(aliases);
        let mut release = Release(Some(release_tx));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<((u64, u64), bool, usize), String> {
            let accept = |fixture: &mut ExplicitOracleOwner| -> Result<(), String> {
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    let step = fixture.0.aliases.as_mut().ok_or("alias owner absent")?.poll(Some(upstream_address))
                        .map_err(|failure| match failure {
                            loopback::AliasFailure::Bind { address, error } => io_step(&format!("alias bind {address}"), &error),
                            loopback::AliasFailure::Accept { address, error } => io_step(&format!("alias accept {address}"), &error),
                            loopback::AliasFailure::Worker(error) => io_step("alias worker start/configure", &error),
                        })?;
                    if step == proxy::ListenerStep::Progress { return Ok(()); }
                    if step == proxy::ListenerStep::Stopped { return Err("alias owner stopped".into()); }
                    if Instant::now() >= deadline { return Err("alias accept timeout".into()); }
                    thread::yield_now();
                }
            };
            let mut client = std::net::TcpStream::connect(alias_address).map_err(|error| io_step("client connect alias", &error))?;
            client.set_read_timeout(Some(Duration::from_secs(3))).map_err(|error| io_step("client read timeout", &error))?;
            client.write_all(b"ping").map_err(|error| io_step("client write ping", &error))?;
            client.shutdown(std::net::Shutdown::Write).map_err(|error| io_step("client shutdown write", &error))?;
            accept(&mut fixture)?;
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut peer = loop {
                match upstream.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::yield_now(),
                    Err(error) => return Err(io_step("upstream accept", &error)),
                }
            };
            peer.set_nonblocking(false).map_err(|error| io_step("accepted upstream set blocking", &error))?;
            peer.set_read_timeout(Some(Duration::from_secs(3))).map_err(|error| io_step("upstream peer read timeout", &error))?;
            let mut ping = [0; 4]; peer.read_exact(&mut ping).map_err(|error| io_step("upstream peer read ping", &error))?;
            if &ping != b"ping" { return Err("alias upstream payload changed".into()); }
            peer.write_all(b"pong").map_err(|error| io_step("upstream peer write pong", &error))?;
            peer.shutdown(std::net::Shutdown::Write).map_err(|error| io_step("upstream peer shutdown write", &error))?;
            let mut pong = [0; 4]; client.read_exact(&mut pong).map_err(|error| io_step("client read pong", &error))?;
            if &pong != b"pong" { return Err("alias client payload changed".into()); }
            let completed = loop {
                fixture.0.receive_aliases()?;
                if let Some(value) = fixture.0.alias_results.first() { break value.clone()?; }
                if Instant::now() >= deadline { return Err("alias splice not received".into()); }
                thread::yield_now();
            };
            let _held_client = std::net::TcpStream::connect(alias_address).map_err(|error| io_step("held client connect alias", &error))?;
            accept(&mut fixture)?;
            held_started_rx.recv_timeout(Duration::from_secs(3)).map_err(|error| error.to_string())?;
            let _panic_client = std::net::TcpStream::connect(alias_address).map_err(|error| io_step("panic client connect alias", &error))?;
            accept(&mut fixture)?;
            let original = panic_rx.recv_timeout(Duration::from_secs(3)).map_err(|error| error.to_string())?;
            let deadline = Instant::now() + Duration::from_secs(3);
            while fixture.0.panics.is_empty() {
                fixture.0.receive_aliases()?;
                if Instant::now() >= deadline { return Err("alias panic not received".into()); }
                thread::yield_now();
            }
            let held = fixture.0.has_unreceived() && fixture.0.environment.cancelled.load(Ordering::Acquire)
                && fixture.0.aliases.as_ref().is_some_and(|aliases| !aliases.bound());
            Ok((completed, held, original))
        }));
        if let Some(tx) = release.0.take() { let _ = tx.send(()); }
        let settled = fixture.settle();
        let (counts, held, original) = result.expect("fixture unwound").expect("actual alias operations");
        settled.expect("alias worker settlement");
        assert_eq!(counts, (4, 4));
        assert!(held, "panic cancellation must not abandon the held alias worker");
        assert_eq!(fixture.0.panics.len(), 1);
        assert_eq!(fixture.0.panics[0].as_ref() as *const _ as *const () as usize, original);
        assert_eq!(fixture.0.panics[0].downcast_ref::<u64>(), Some(&147));
        assert!(!fixture.0.has_unreceived());
    }

    #[cfg(windows)]
    #[test]
    fn system_carrier_receives_worker_error_and_original_panic_without_another_client() {
        use std::sync::{Arc, mpsc, atomic::{AtomicBool, AtomicUsize, Ordering}};
        let (listener, _) = proxy::tests::fixture_transport_listener();
        let active = crate::settings::ActiveTransportConfig { profile: crate::settings::TransportProfile::SystemTcp,
            dns: false, tcp_proxy: true, client_proxy: true, dns_alias: false };
        // Only fixture data is supplied here. The actual production receiver
        // below needs neither CurrentImage nor a real Gate publisher/settings.
        let mut owner = ExplicitTransportCarrier { listener: Some(listener), dns: None, dns_probe: None, dns_probe_result: None,
            dns_probe_receipt: Ok(()), dns_completed: Vec::new(), dns_results: Vec::new(), dns_blocker: None,
            dns_listener_failure: None, next_dns_probe: Instant::now(), workers: proxy::ConnectionWorkers::default(),
            aliases: None, alias_completed: Vec::new(), alias_results: Vec::new(), alias_failure: None, alias_blocker: None,
            warming: None, warm_resolver: None, resolver_completed: Vec::new(), resolver_results: Vec::new(),
            warm_result: None, warm_receipt: Ok(()), next_warm: Instant::now(), next_private_probe: Instant::now(),
            report: gate::TransportReport { schema: 1, instance: gate::TransportInstance { pid: 7, creation_time: 11 },
                active_config: active, observed: gate::TransportCapabilities { dns: gate::CapabilityObservation::Disabled,
                    tcp_proxy: gate::CapabilityObservation::Starting, dns_alias: gate::CapabilityObservation::Disabled } },
            binding: None, probe: None, probe_result: None, probe_receipt: Ok(()),
            environment: Arc::new(SystemEnvironment { cancelled: Arc::new(AtomicBool::new(false)), ready: Mutex::new(None) }),
            maintainer: None, maintainer_result: None, completed: Vec::new(), request_results: Vec::new(),
            listener_failure: None, blocker: None, publication: Ok(()), metadata_receiving: Ok(()),
            role_result: Ok(()), terminal_error: None, panics: Vec::new(), next_publish: Instant::now(),
            next_probe: Instant::now(), dirty: true };
        // No client ever connects to this ephemeral listener. Directly enter
        // the exact receiver called by ExplicitTransportCarrier::poll, avoiding only
        // that method's independent native publisher/maintainer responsibilities.
        assert_eq!(owner.listener.as_mut().unwrap().poll(&mut owner.workers).unwrap(), proxy::ListenerStep::Idle);
        // Exercise an actual failed TCP splice through the same carrier receiver.
        let pair = || -> std::io::Result<(std::net::TcpStream, std::net::TcpStream)> {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let first = std::net::TcpStream::connect(listener.local_addr()?)?;
            let (second, _) = listener.accept()?;
            Ok((first, second))
        };
        let (mut client_peer, client) = pair().unwrap();
        let (upstream, upstream_peer) = pair().unwrap();
        upstream.shutdown(std::net::Shutdown::Write).unwrap();
        upstream_peer.shutdown(std::net::Shutdown::Write).unwrap();
        client_peer.write_all(b"fixture").unwrap();
        client_peer.shutdown(std::net::Shutdown::Write).unwrap();
        proxy::tests::fixture_spawn_native_transfer(&mut owner.workers, client, upstream).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            owner.receive_workers().unwrap();
            if !owner.request_results.is_empty() { break; }
            assert!(Instant::now() < until);
            thread::park_timeout(proxy::PUMP_MAX_SLEEP);
        }
        assert!(owner.request_results[0].is_err(), "actual shutdown/write failure must reach the carrier");
        // A real unwind payload is inserted into a synthetic splice receipt to
        // exercise nested custody independently of the native socket error.
        let payload = thread::spawn(|| std::panic::panic_any(91u64)).join().unwrap_err();
        let payload_id = payload.as_ref() as *const _ as *const () as usize;
        let receipt = proxy::SpliceOutcome {
            client_to_upstream: Ok(proxy::SpliceDirection { copy: Err(payload), shutdown: Ok(()) }),
            upstream_to_client: Ok(Ok(0)), client_shutdown_write: Ok(()), client_shutdown_both: Ok(()),
        };
        proxy::tests::fixture_spawn_outcome(&mut owner.workers, receipt).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while owner.panics.is_empty() {
            owner.receive_workers().unwrap();
            assert!(Instant::now() < until);
            thread::park_timeout(proxy::PUMP_MAX_SLEEP);
        }
        let nested = owner.panics.pop().unwrap();
        assert_eq!(nested.as_ref() as *const _ as *const () as usize, payload_id);
        assert_eq!(nested.downcast_ref::<u64>(), Some(&91));
        // This fixture continues with a fresh listener and cancellation token.
        owner.listener = Some(proxy::tests::fixture_transport_listener().0);
        owner.workers = proxy::ConnectionWorkers::default();
        owner.workers.register_current_thread().unwrap();
        owner.environment.cancelled.store(false, std::sync::atomic::Ordering::Release);
        let calls = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)]);
        let held_cancelled = Arc::new(AtomicBool::new(false));
        let (held_start_tx, held_start_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (native_tx, native_rx) = mpsc::channel();
        let (panic_tx, panic_rx) = mpsc::channel();
        let mut receipts = Vec::new();
        let mut original_panic = None;
        let mut native_facts = None;
        let mut held_observed = false;
        // Keep first failures as values. Release and receive the held worker
        // before assertions, including when setup or an observation fails.
        let first = (|| -> Result<(), String> {
            let held_calls = calls.clone();
            let held_cancelled = held_cancelled.clone();
            proxy::tests::fixture_spawn_connection(&mut owner.workers, move |cancelled| {
                held_calls[0].fetch_add(1, Ordering::SeqCst);
                held_start_tx.send(()).map_err(|_| proxy::ConnectionFailure::Transfer(std::io::ErrorKind::BrokenPipe.into()))?;
                release_rx.recv().map_err(|_| proxy::ConnectionFailure::Transfer(std::io::ErrorKind::BrokenPipe.into()))?;
                held_cancelled.store(cancelled.load(Ordering::Acquire), Ordering::Release);
                Ok(())
            }).map_err(|error| error.to_string())?;
            held_start_rx.recv_timeout(Duration::from_secs(5)).map_err(|error| error.to_string())?;
            let error_calls = calls.clone();
            proxy::tests::fixture_spawn_connection(&mut owner.workers, move |_| {
                error_calls[1].fetch_add(1, Ordering::SeqCst);
                match std::net::TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), Duration::from_secs(1)) {
                    Err(error) => {
                        native_tx.send((error.kind(), error.raw_os_error())).expect("fixture owns native error receiver");
                        Err(proxy::ConnectionFailure::Transfer(error))
                    }
                    Ok(stream) => { drop(stream); Ok(()) }
                }
            }).map_err(|error| error.to_string())?;
            let panic_calls = calls.clone();
            proxy::tests::fixture_spawn_connection(&mut owner.workers, move |_| {
                panic_calls[2].fetch_add(1, Ordering::SeqCst);
                let payload = std::panic::catch_unwind(|| std::panic::panic_any(73u64)).unwrap_err();
                let address = payload.as_ref() as *const _ as *const () as usize;
                panic_tx.send(address).expect("fixture owns panic identity receiver");
                std::panic::resume_unwind(payload)
            }).map_err(|error| error.to_string())?;
            native_facts = Some(native_rx.recv_timeout(Duration::from_secs(5)).map_err(|error| error.to_string())?);
            original_panic = Some(panic_rx.recv_timeout(Duration::from_secs(5)).map_err(|error| error.to_string())?);
            let until = Instant::now() + Duration::from_secs(5);
            while receipts.len() < 2 {
                owner.receive_workers()?;
                receipts.append(&mut owner.request_results);
                if receipts.len() < 2 {
                    if Instant::now() >= until { return Err("carrier did not receive the two terminal workers".into()); }
                    thread::park_timeout(proxy::PUMP_MAX_SLEEP);
                }
            }
            let stopped = owner.listener.as_mut().unwrap().poll(&mut owner.workers).map_err(|error| format!("fixture listener: {error:?}"))?;
            held_observed = stopped == proxy::ListenerStep::Stopped && owner.listener.as_ref().unwrap().bound_addr().is_none()
                && owner.workers.outstanding() == 1 && owner.workers.has_unreceived() && owner.completed.is_empty()
                && owner.panics.len() == 1 && owner.environment.cancelled.load(Ordering::Acquire)
                && owner.workers.cancellation_token().is_cancelled();
            Ok(())
        })();
        let released = release_tx.send(());
        let mut settling = Ok(());
        while owner.workers.has_unreceived() {
            match owner.receive_workers() {
                Ok(()) => receipts.append(&mut owner.request_results),
                Err(error) => { if settling.is_ok() { settling = Err(error); } }
            }
            if owner.workers.has_unreceived() {
                // Both channel release and the native connect budget are
                // finite. An observation failure never detaches these handles;
                // the outer test runner retains its own execution timeout.
                thread::park_timeout(proxy::PUMP_MAX_SLEEP);
            }
        }
        // Every assertion follows the supported release/actual receiving pass.
        first.unwrap();
        released.unwrap();
        settling.unwrap();
        assert!(held_observed, "terminal receiving must not drop the held worker");
        assert!(held_cancelled.load(Ordering::Acquire));
        assert_eq!(calls.iter().map(|count| count.load(Ordering::SeqCst)).collect::<Vec<_>>(), vec![1, 1, 1]);
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts.iter().filter(|result| result.is_ok()).count(), 1);
        let (kind, code) = native_facts.unwrap();
        assert!(receipts.iter().filter_map(|result| result.as_ref().err()).any(|error|
            error.starts_with("proxy request transfer failed:") && error.contains(&format!("{kind:?}/{code:?}"))));
        assert!(receipts.iter().filter_map(|result| result.as_ref().err()).any(|error| error.contains("worker unwound")));
        assert_eq!(owner.panics.len(), 1);
        let payload = &owner.panics[0];
        assert_eq!(payload.as_ref() as *const _ as *const () as usize, original_panic.unwrap());
        assert_eq!(payload.downcast_ref::<u64>(), Some(&73));
        assert_eq!(owner.workers.outstanding(), 0);
        assert!(!owner.workers.has_unreceived());
        owner.receive_workers().unwrap();
        assert!(owner.request_results.is_empty(), "completed requests must not be delivered twice");
        assert_eq!(owner.panics.len(), 1, "receiving an empty batch must preserve the original panic");
    }

    #[cfg(windows)]
    #[test]
    fn system_carrier_startup_preserves_explicit_disabled_and_unknown_inputs() {
        use crate::settings::{TransportIntent, TransportProfile, TransportChoice, Settings};
        let intent = |settings: Settings| {
            let requirements = settings.transport_requirements().unwrap();
            TransportIntent::Explicit { settings, requirements }
        };
        let mut system = Settings::default();
        system.select_system_tcp().unwrap();
        assert!(matches!(receive_carrier_startup(intent(system.clone())).unwrap(), WindowsCarrierStartup::Explicit { requirements, .. }
            if requirements.active_config.profile == TransportProfile::SystemTcp && requirements.active_config.client_proxy));
        system.set_transport_choice(TransportChoice::LocalProxy(false)).unwrap();
        let root = std::sync::Arc::new(crate::command_lifetime::CommandLifetime::default());
        run_explicit_transport(root.clone(), system.clone(), system.transport_requirements().unwrap()).unwrap();
        let mut configured = Settings::default();
        configured.select_existing_configured(true, false, false, false, false).unwrap();
        assert!(matches!(receive_carrier_startup(intent(configured.clone())).unwrap(), WindowsCarrierStartup::Explicit { requirements, .. }
            if requirements.active_config.profile == TransportProfile::ExistingConfigured && requirements.active_config.dns
                && !requirements.active_config.tcp_proxy && !requirements.active_config.dns_alias));
        configured.select_existing_configured(false, false, false, true, false).unwrap();
        assert!(matches!(receive_carrier_startup(intent(configured.clone())).unwrap(), WindowsCarrierStartup::Explicit { requirements, .. }
            if requirements.active_config.tcp_proxy && !requirements.active_config.client_proxy && !requirements.active_config.dns_alias));
        configured.select_existing_configured(false, false, false, false, false).unwrap();
        // Both real all-off core paths return before CurrentImage, Gate, a
        // listener, a maintainer or native effects can be acquired.
        run_explicit_transport(root, configured.clone(), configured.transport_requirements().unwrap()).unwrap();
        assert!(receive_carrier_startup(TransportIntent::Missing).is_err());
        assert!(receive_carrier_startup(TransportIntent::Broken("synthetic read failure".into())).is_err());
        assert!(matches!(receive_carrier_startup(TransportIntent::Legacy(Settings::default())).unwrap(), WindowsCarrierStartup::Legacy));
    }

    #[cfg(windows)]
    #[test]
    fn alias_splice_receiving_preserves_both_directions_shutdowns_and_original_panic() {
        let payload = std::panic::catch_unwind(|| std::panic::panic_any(147u64)).unwrap_err();
        let address = payload.as_ref() as *const _ as *const () as usize;
        let outcome = proxy::SpliceOutcome {
            client_to_upstream: Ok(proxy::SpliceDirection { copy: Err(payload), shutdown: Err(std::io::Error::from_raw_os_error(10038)) }),
            upstream_to_client: Ok(Err(std::io::Error::from_raw_os_error(10054))),
            client_shutdown_write: Err(std::io::Error::from_raw_os_error(10061)),
            client_shutdown_both: Err(std::io::Error::from_raw_os_error(10053)),
        };
        let facts = receive_splice_facts(&outcome).unwrap_err();
        for code in ["10038", "10054", "10061", "10053"] { assert!(facts.contains(code)); }
        assert!(facts.contains("unwound"));
        let payload = outcome.client_to_upstream.as_ref().unwrap().copy.as_ref().unwrap_err();
        assert_eq!(payload.as_ref() as *const _ as *const () as usize, address);
        assert_eq!(payload.downcast_ref::<u64>(), Some(&147));
        let complete = proxy::SpliceOutcome { client_to_upstream: Ok(proxy::SpliceDirection { copy: Ok(Ok(17)), shutdown: Ok(()) }),
            upstream_to_client: Ok(Ok(29)), client_shutdown_write: Ok(()), client_shutdown_both: Ok(()) };
        assert_eq!(receive_splice_facts(&complete).unwrap(), (17, 29));
    }

    #[cfg(windows)]
    #[test]
    fn system_protocol_proof_is_invalid_after_retirement_even_if_port_is_reused() {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        let address: SocketAddr = "127.0.0.1:23456".parse().unwrap();
        let binding = || Arc::new(TcpBinding { address, instance: gate::TransportInstance { pid: 7, creation_time: 11 }, valid: AtomicBool::new(true) });
        let old = binding();
        assert!(binding_is_current(&old, Some(&old), Some(address), false));
        old.valid.store(false, Ordering::Release);
        assert!(!binding_is_current(&old, Some(&old), Some(address), false));
        let replacement = binding();
        assert!(!binding_is_current(&old, Some(&replacement), Some(address), false));
        assert!(!binding_is_current(&replacement, Some(&replacement), Some(address), true));
        assert!(!binding_is_current(&replacement, Some(&replacement), None, false));
    }

    #[cfg(windows)]
    #[test]
    fn system_environment_requires_same_received_instance_configuration_protocol_and_port() {
        use crate::settings::{ActiveTransportConfig, TransportProfile};
        let active = ActiveTransportConfig { profile: TransportProfile::SystemTcp, dns: false, tcp_proxy: true, client_proxy: true, dns_alias: false };
        let binding = TcpBinding { address: "127.0.0.1:23456".parse().unwrap(),
            instance: gate::TransportInstance { pid: 7, creation_time: 11 }, valid: std::sync::atomic::AtomicBool::new(true) };
        let instance = &binding.instance;
        assert!(receive_system_environment_facts(active, Some(instance), true, Some(23456), &binding, active).is_ok());
        assert!(receive_system_environment_facts(active, None, true, Some(23456), &binding, active).is_err());
        let replaced = gate::TransportInstance { creation_time: 12, ..instance.clone() };
        assert!(receive_system_environment_facts(active, Some(&replaced), true, Some(23456), &binding, active).is_err());
        assert!(receive_system_environment_facts(active, Some(instance), false, Some(23456), &binding, active).is_err());
        assert!(receive_system_environment_facts(active, Some(instance), true, None, &binding, active).is_err());
        assert!(receive_system_environment_facts(active, Some(instance), true, Some(23457), &binding, active).is_err());
        let changed = ActiveTransportConfig { tcp_proxy: false, ..active };
        assert!(receive_system_environment_facts(changed, Some(instance), true, Some(23456), &binding, active).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn system_request_receiving_preserves_late_native_facts_without_private_target_text() {
        let late = proxy::ConnectionFailure::Open(proxy::route_session::OpenFailure::ResolutionLate {
            cancelled: true, error: std::io::Error::from_raw_os_error(11001),
        });
        let facts = connection_failure_facts(&late);
        assert!(facts.contains("cancelled=true"));
        assert!(facts.contains("11001"));
        let private = proxy::ConnectionFailure::Open(proxy::route_session::OpenFailure::Unavailable(Some("synthetic-private-hop".into())));
        let facts = connection_failure_facts(&private);
        assert!(facts.contains("private_detail_present=true"));
        assert!(!facts.contains("synthetic-private-hop"));
        let commit = proxy::ConnectionFailure::Commit(proxy::route_session::CommitFailure {
            bytes_written: 9, error: proxy::route_session::CommitCause::Boundary(proxy::route_session::OpenFailure::Deadline),
            client_shutdown: Err(std::io::Error::from_raw_os_error(10038)), upstream_shutdown: Ok(()),
        });
        let facts = connection_failure_facts(&commit);
        assert!(facts.contains("bytes=9"));
        assert!(facts.contains("deadline"));
        assert!(facts.contains("10038"));
        assert!(facts.contains("upstream_shutdown=None"));
    }

    #[test]
    fn a_gate_hosts_aaaa_and_https_questions_get_an_empty_answer() {
        for qtype in [28u8, 64, 65] {
            let mut q = dns_client::build_query("daily-cloudcode-pa.googleapis.com", 9);
            let n = q.len();
            q[n - 3] = qtype;
            let r = own_answer(&q, "daily-cloudcode-pa.googleapis.com").expect("answered");
            assert!(dns_client::answer_addrs(&r).is_empty(), "qtype {qtype}");
            assert_eq!(dns_client::question_type(&r), Some(qtype as u16));
        }
        // Not a gate host: relayed as before.
        let mut q = dns_client::build_query("storage.googleapis.com", 9);
        let n = q.len();
        q[n - 3] = 28;
        assert!(own_answer(&q, "storage.googleapis.com").is_none());
    }

    #[test]
    fn the_network_fingerprint_is_never_the_unset_value_and_tells_networks_apart() {
        let a = network_fingerprint(27, Some(27), false);
        let b = network_fingerprint(27, Some(55), true);
        let c = network_fingerprint(27, Some(27), true);
        assert_ne!(a, 0);
        assert_ne!(network_fingerprint(0, None, false), 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, network_fingerprint(27, Some(27), false));
    }

    #[test]
    fn a_penalty_reads_in_minutes_or_hours() {
        assert_eq!(human_minutes(Duration::from_secs(600)), "10 мин");
        assert_eq!(human_minutes(Duration::from_secs(3600)), "1 ч");
        assert_eq!(human_minutes(Duration::from_secs(6 * 3600)), "6 ч");
        assert_eq!(human_minutes(Duration::from_secs(90 * 60)), "90 мин");
    }

    /// Everything the version check does hangs off this: a relay that predates
    /// versioning leaves no file, and it must read as older than this build
    /// rather than as "no relay" or as a parse error nobody handles.
    #[test]
    fn an_unreadable_version_is_the_oldest_one() {
        assert_eq!(parse_version(None), 0);
        assert_eq!(parse_version(Some("")), 0);
        assert_eq!(parse_version(Some("не число")), 0);
        assert_eq!(parse_version(Some(" 7 \r\n")), 7);
        assert_eq!(parse_version_checked(" 7 \r\n").unwrap(), 7);
        assert!(parse_version_checked("").is_err());
        assert!(parse_version_checked("not a number").is_err());
        assert!(parse_version(None) < RELAY_VERSION);
    }

    /// The warm loop only exists to beat the ~1 s Windows waits before asking
    /// the next NRPT nameserver, so it has to refresh well inside the window the
    /// answer cache serves from.
    #[test]
    fn warming_runs_more_often_than_an_answer_goes_stale() {
        assert!(WARM_EVERY < resolvers::ANSWER_TTL);
    }

    /// A burst of one message must not eat the sixty lines a report shows.
    /// The first of a run goes out at once; the rest are counted and the count
    /// is written the moment anything else is logged.
    #[test]
    fn a_run_of_one_line_is_collapsed_into_a_count() {
        let line = "напрямую X: имя не разрешается";
        // The first is written, with nothing held back before it.
        assert_eq!(collapse_repeat(line), (None, true));
        for _ in 0..14 {
            assert_eq!(collapse_repeat(line), (None, false), "a repeat was written");
        }
        // Something else ends the run and carries the tally.
        let (note, write) = collapse_repeat("что-то другое");
        assert!(write);
        assert_eq!(note.as_deref(), Some("↑ то же самое ещё 14 раз"));
        // …and the next line after that has nothing to report.
        assert_eq!(collapse_repeat("третья"), (None, true));

        // And a run that never ends is never silent: the tally is written every
        // `REPEAT_RUN`, so a problem repeating for an hour is still visible.
        // One test and not two: `collapse_repeat` keeps one run per process,
        // and two tests would race for it.
        let line = "бесконечное";
        assert_eq!(collapse_repeat(line), (None, true));
        for _ in 0..(REPEAT_RUN - 1) {
            assert_eq!(collapse_repeat(line), (None, false));
        }
        let (note, write) = collapse_repeat(line);
        assert!(!write, "the repeat itself is still not written");
        assert_eq!(note.as_deref(), Some("↑ то же самое ещё 50 раз"));
        // The counter restarted, so the next line ends a fresh run.
        assert_eq!(collapse_repeat(line), (None, false));
        assert_eq!(
            collapse_repeat("иное").0.as_deref(),
            Some("↑ то же самое ещё 1 раз")
        );
    }

    #[test]
    fn the_listener_address_is_loopback() {
        let ip: Ipv4Addr = LISTEN_IP.parse().expect("valid address");
        assert!(ip.is_loopback());
        // Not .1: something else on the machine may already own it.
        assert_ne!(ip, Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn a_detected_interface_is_cached_and_droppable() {
        invalidate_interface();
        assert!(EGRESS_CACHE.lock().unwrap().is_none());
        if let Ok(mut c) = EGRESS_CACHE.lock() {
            *c = Some((17, Instant::now(), EGRESS_TTL));
        }
        // Served from the cache: no detection runs, so no process is spawned.
        let root = std::sync::Arc::new(crate::command_lifetime::CommandLifetime::default());
        assert_eq!(isp_interface(&root), 17);
        invalidate_interface();
        assert!(EGRESS_CACHE.lock().unwrap().is_none());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires outer creator Job and private U04_FIXTURE_EXE/U04_FIXTURE_DIR"]
    fn cold_service_scope_does_not_block_cached_query_and_survives_worker_panic() {
        let executable = std::path::PathBuf::from(std::env::var_os("U04_FIXTURE_EXE").expect("absolute actor"));
        let parent = std::path::PathBuf::from(std::env::var_os("U04_FIXTURE_DIR").expect("private fixture"));
        let directory = parent.join("service-crate-command");
        std::fs::create_dir(&directory).unwrap();
        let root = std::sync::Arc::new(crate::command_lifetime::CommandLifetime::default());
        let command = root.begin("cold service fixture").unwrap();
        let child_directory = directory.clone();
        let worker = thread::spawn(move || command.with_result::<()>(|outcome| {
            let prepared = crate::utils::PreparedExec::fixture_absolute(&executable).unwrap()
                .args(["--fixture", "effect"]).arg(child_directory.as_os_str());
            let observed = crate::utils::bounded_output(outcome, prepared, Duration::from_secs(60));
            assert_eq!(observed, crate::utils::CommandObservation::Complete);
            panic!("original service callback panic");
        }));
        let until = Instant::now() + Duration::from_secs(4);
        while !directory.join("prefix-flushed").exists() && Instant::now() < until { thread::yield_now(); }
        assert!(directory.join("prefix-flushed").exists());
        *EGRESS_CACHE.lock().unwrap() = Some((17, Instant::now(), EGRESS_TTL));
        assert_eq!(isp_interface(&root), 17);
        assert!(!worker.is_finished());
        {
            use std::io::Write;
            let mut release = std::fs::OpenOptions::new().write(true).create_new(true).open(directory.join("release")).unwrap();
            release.write_all(b"release").unwrap();
            release.sync_all().unwrap();
        }
        assert!(worker.join().unwrap().is_err());
        assert!(matches!(root.receive(), crate::command_lifetime::Receiving::Ready));
        assert!(root.take_failures().iter().any(|error| error.contains("capture_eof=true")));
        assert_eq!(root.take_panics().len(), 1);
        invalidate_interface();
    }

    /// An expired entry must not be served - that is what makes the short retry
    /// after a failed detection actually retry.
    #[test]
    fn an_expired_entry_is_not_served() {
        invalidate_interface();
        if let Ok(mut c) = EGRESS_CACHE.lock() {
            // Learned long ago, and only ever good for a moment.
            *c = Some((17, Instant::now() - Duration::from_secs(60), EGRESS_RETRY));
        }
        let stale = EGRESS_CACHE
            .lock()
            .unwrap()
            .map(|(_, at, good_for)| at.elapsed() >= good_for);
        assert_eq!(stale, Some(true));
        invalidate_interface();
    }

    /// A failed detection has to be forgotten quickly: at logon it usually just
    /// means the network is not up yet.
    #[test]
    fn a_failed_detection_is_remembered_only_briefly() {
        assert!(EGRESS_RETRY < EGRESS_TTL);
        assert!(EGRESS_RETRY <= Duration::from_secs(60));
    }

    /// Relays a real query end to end through the running upstream, and prints
    /// the verdict for every routed name.
    ///
    /// Needs a live network and the VPN OFF: through a tunnel every provider
    /// sees a foreign client and substitutes nothing, so every verdict comes
    /// back `Passthrough` and the run says nothing about the providers.
    ///
    /// The verdict is the assertion that matters now. The old version only
    /// checked that bytes came back - which stayed true through the whole
    /// outage that motivated `resolvers`, because an unsubstituted answer is
    /// still a perfectly well-formed answer.
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn relays_a_real_query() {
        let id: u16 = 0x4242;
        let mut substituted = Vec::new();

        for name in [
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "antigravity-unleash.goog",
        ] {
            let mut query = vec![];
            query.extend_from_slice(&id.to_be_bytes());
            query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            for label in name.split('.') {
                query.push(label.len() as u8);
                query.extend_from_slice(label.as_bytes());
            }
            query.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);

            let root = std::sync::Arc::new(crate::command_lifetime::CommandLifetime::default());
            let (reply, provider, verdict) = relay(&root, prepare_isp_interface(&root), &query).expect("a provider answered");
            assert_eq!(&reply[0..2], &id.to_be_bytes(), "id must be echoed");
            assert_eq!(
                dns_client::question_name(&reply).as_deref(),
                Some(name),
                "the reply must answer the question we asked"
            );
            assert!(
                u16::from_be_bytes([reply[6], reply[7]]) > 0,
                "{} came back with no answer",
                name
            );
            println!(
                "{:<38} {:?} via {:<12} {:?}",
                name,
                verdict,
                provider,
                dns_client::answer_addrs(&reply)
            );
            if verdict == Verdict::Substituted {
                substituted.push(name);
            }
        }

        // Not an assertion on any single name: which names a provider proxies
        // is theirs to change, and this test exists to report that, not to fail
        // on it. But if nothing at all is substituted, either the VPN is up or
        // every provider has dropped the whole list - both worth failing on.
        assert!(
            !substituted.is_empty(),
            "no routed name is substituted by any provider - VPN up, or the \
             providers dropped every name"
        );
        println!("substituted: {:?}", substituted);
    }
}
