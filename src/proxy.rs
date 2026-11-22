use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection};

use crate::routes;
use crate::upstream;
use crate::utils::no_window;

pub(crate) mod route_session;
mod dns_probe;

// The fallback route: unblock the traffic instead of the name.
//
// The DNS layer can only help with a name some provider still substitutes, and
// it cannot help with how slow that provider's proxy is. `cloudcode-pa` is
// substituted by nobody (S9), and `daily-cloudcode-pa` only by geohide, which
// has been measured taking 1.4-14.8 s over a TLS handshake xbox does in 249 ms
// (P6). So this is a second route, working at the traffic level rather than at
// the name.
//
// It is a loopback CONNECT proxy and nothing else. A gate host goes through the
// authenticated relay in the private `relay` module - a CONNECT tunnel whose TLS
// stays end to end with Google, so no certificate of ours is anywhere near it.
// Everything else, *including* every other `*.googleapis.com`, is a raw byte
// tunnel: sign-in, token refresh and every other program on the machine keep
// exactly the TLS they had before this tool existed.
//
// It used to terminate the client's TLS with a CA generated on this machine and
// carry blocked names in under an SNI the unblock proxies accept - they are
// SNI-whitelisted forwarders (N13), but Google's frontend routes
// `*.googleapis.com` on the HTTP **Host** header, so a carrier SNI reaches the
// right backend. That whole route is gone: the relay reaches the same backends
// with no CA at all, and intercepting the rest black-screened the Desktop app
// with `BadCertificate`. The CA helpers below survive for one purpose - removing
// a certificate an older version installed. Measurements: kb/dns.md.

/// Loopback only. The port is stable because the proxy variable is a static
/// string in the user's environment - an ephemeral port would need rewriting on
/// every relay start, and would be wrong for any process that read it earlier.
pub const LISTEN_IP: &str = "127.0.0.1";
/// The port the proxy starts on, and keeps for as long as it can have it.
pub const DEFAULT_PORT: u16 = 53129;
/// Where it moves when it cannot (P26). 53129 is inside Windows' dynamic range
/// (49152-65535), which is where Hyper-V, WSL 2 and Docker reserve ports and
/// where every outgoing connection borrows one; these sit below it, where
/// neither happens on a default Windows.
const FALLBACK_PORTS: [u16; 6] = [43129, 44129, 45129, 46129, 47129, 48129];

/// The port this process bound, 0 until it has (the relay's own answer).
static PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

/// The file the relay records a moved port in, beside `settings.json` - the one
/// place the window (another process, as the same user) and the relay agree on.
/// Absent while the proxy is on `DEFAULT_PORT`.
fn port_file() -> Result<PathBuf, String> {
    crate::dns_forwarder::checked_log_dir().map(|dir| dir.join("proxy_port"))
}

/// The port the local proxy listens on: the one this process bound, else the
/// one the relay recorded, else the default. Everything that names the proxy -
/// the variable, the door's hop, the egress probe - asks this.
pub fn port() -> u16 {
    match PORT.load(std::sync::atomic::Ordering::Relaxed) {
        0 => port_file().ok()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|p| *p != 0)
            .unwrap_or(DEFAULT_PORT),
        p => p,
    }
}

/// Takes `port` as this machine's, in this process and on disk.
fn adopt(port: u16) {
    PORT.store(port, std::sync::atomic::Ordering::Relaxed);
    // Never from a test: the file is the real user's, and the relay reads it.
    if cfg!(test) {
        return;
    }
    let path = match port_file() {
        Ok(path) => path,
        Err(error) => { eprintln!("Не удалось записать порт прокси: {error}"); return; }
    };
    if port == DEFAULT_PORT {
        fs::remove_file(path).ok();
    } else {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).ok();
        }
        fs::write(path, port.to_string()).ok();
    }
}

/// The URL the variable held before any move - still ours, never a foreign
/// proxy to stand aside for (`endpoint::is_ours_on_any_port`).
pub fn default_url() -> String {
    format!("http://{}:{}", LISTEN_IP, DEFAULT_PORT)
}

/// Common name of the certificate authority older versions generated on this
/// machine. Nothing creates one any more; the name is kept so the three helpers
/// below can find and remove one that is still installed.
const CA_NAME: &str = "AG Unlocker local CA";

// The fast relay route's whole method - host, CONNECT-with-credential logic and
// the credential itself - lives in the gitignored `src/relay.rs`, compiled in
// only under `cfg(relay)` (set by build.rs when that file and `.relay_key` are
// both present). A build from the public source has neither, compiles the stub
// below, and runs the DNS route. `relay_available()` is the only symbol the rest
// of the crate needs; everything else stays private to that module.
#[cfg(relay)]
#[path = "relay.rs"]
mod relay;
// `relay_available` is used inside this module (`relay::relay_available()`); it is
// no longer re-exported because 2.11.0_1 stopped turning the carrier on from
// `main` by default (kb/rivals.md). `#[allow(unused_imports)]` keeps the stub
// build (cfg(not(relay))) honest without a second cfg arm.
#[cfg(relay)]
pub use relay::{note_answer as note_relay_answer, probe_relay, relay_is_benched};

#[cfg(not(relay))]
pub fn relay_available() -> bool {
    false
}

/// No relay route to check in a build that has no relay module.
#[cfg(not(relay))]
pub fn probe_relay() {}

#[cfg(not(relay))]
pub fn relay_is_benched() -> bool {
    false
}

/// No relay route to credit in a build that has no relay module.
#[cfg(not(relay))]
pub fn note_relay_answer() {}

// The built-in exits - third-party CONNECT proxies that already egress in a
// permitted region - live in the gitignored `src/exits.rs` with their address
// list in `.exits`, compiled in only under `cfg(exits)`. Same arrangement as the
// relay, for a different reason: the method here is not secret (it is the plain
// CONNECT `upstream.rs` already speaks in public source), the addresses are, and
// only because naming somebody else's free proxy in a public repository is how it
// stops being one.
#[cfg(exits)]
#[path = "exits.rs"]
mod exits;
#[cfg(exits)]
pub use exits::probe_health as probe_exits;

/// No built-in exits to check in a build that has no exits module.
#[cfg(not(exits))]
pub fn probe_exits() {}

// The byte pump's timings, the upstream handshake and `would_block` below are
// the primitives the private relay module is built on, and its only users. A
// public build has no such module, so each is marked dead-code-allowed under
// `cfg(not(relay))` - a clone should compile without a wall of warnings, and
// silencing them one by one is honest about *why* they look unused.

/// How long the byte pump sleeps when both directions are idle. It starts at the
/// minimum and doubles to the maximum, so an active connection never sleeps and
/// an idle one costs a wakeup every 50 ms.
#[cfg_attr(not(relay), allow(dead_code))]
pub(crate) const PUMP_MIN_SLEEP: Duration = Duration::from_millis(1);
#[cfg_attr(not(relay), allow(dead_code))]
pub(crate) const PUMP_MAX_SLEEP: Duration = Duration::from_millis(50);
/// How long a freshly accepted socket may stay silent before it is dropped.
/// Long, because a pooling client legitimately opens sockets before it has
/// anything to send; bounded, so an abandoned one does not hold a thread.
const REQUEST_IDLE: Duration = Duration::from_secs(120);

/// Proxy status lines, kept as named constants rather than written inline.
///
/// The CRLF pairs in them are load-bearing and easy to lose: a tool that
/// normalises line endings turns the escape into a bare newline, rustc accepts
/// that without a word, and the result is a response no HTTP client will parse.
/// `status_lines_are_crlf_terminated` is what stops that reaching a release.
pub const RESP_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const RESP_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
const RESP_NOT_ALLOWED: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n";

// Cleanup only, from here to `untrust_ca`. Up to 2.9.1_27 the fallback route
// terminated TLS and needed a per-machine CA; the relay route replaced it and
// needs none, so nothing here creates or signs anything. What is left finds the
// old certificate and takes it out, because a machine that ran an earlier build
// still has a root certificate in its user store and both undo paths (menu 4 and
// menu 5) have to remove it. Delete these only once no installed build can still
// have one.

/// Where an older build kept its CA. Beside the relay's log rather than beside
/// its exe: the relay runs unelevated and cannot write into the directory an
/// administrator installed it into (the same reason the log is there).
pub fn ca_dir() -> PathBuf {
    PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_default()).join(crate::user_state_location::WINDOWS_STATE_LEAF)
}

pub fn ca_cert_path() -> PathBuf {
    ca_dir().join("ca.pem")
}

fn ca_key_path() -> PathBuf {
    ca_dir().join("ca.key")
}

/// The proxy URL that goes into the environment of the processes being routed.
pub fn proxy_url() -> String {
    url_at(port())
}

/// The URL naming the proxy on `port`.
pub fn url_at(port: u16) -> String {
    format!("http://{}:{}", LISTEN_IP, port)
}

/// Waits up to `budget` for **our** proxy to answer, and says on which port -
/// the one a variable written after this has to name (I53).
///
/// The port is read again on every try: the relay can move it while this waits
/// (P26), and a URL built from the port read before the wait named the one it
/// had just left - a dead port in `AG_LS_PROXY` that the watchdog, asking about
/// the new one, would never take back off. "Ours": in the relay, the listener
/// this process bound; elsewhere on Windows, a listener owned by the relay's exe,
/// because somebody else's program on the default port answers too and naming it
/// would route Antigravity into it. Linux has no table to ask, and there the
/// proxy never moves.
pub fn wait_for_our_listener(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, budget: Duration) -> Result<Option<u16>, String> {
    let deadline = Instant::now() + budget;
    loop {
        let p = port();
        if ours_answers(root, p)? {
            return Ok(Some(p));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(POLL_FOR_LISTENER);
    }
}

fn ours_answers(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, port: u16) -> Result<bool, String> {
    if bound() {
        // The relay asking about itself: `PORT` is set before `PROXY_BOUND`.
        return Ok(PORT.load(std::sync::atomic::Ordering::Relaxed) == port);
    }
    #[cfg(target_os = "macos")]
    return crate::background::owned_proxy_listener_at(port);
    #[cfg(not(target_os = "macos"))]
    if !answers_at(addr_at(port)) {
        return Ok(false);
    }
    #[cfg(windows)]
    {
        let relay = crate::background::installed_exe()?;
        let mine = std::env::current_exe().ok();
        let names: Vec<String> = [Some(relay), mine]
            .into_iter()
            .flatten()
            .filter_map(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase())
            })
            .collect();
        // A name that cannot be read is given the benefit of the doubt: the
        // relay writes the variable itself anyway, and a refusal here would
        // only keep the window from doing it too.
        let observed = root.call("proxy listener identity", |owner| crate::portcheck::listener_image(owner, addr_at(port)))??;
        return Ok(observed.is_some_and(|n| names.contains(&n.to_ascii_lowercase())));
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    Ok(true)
}

/// The address the listener holds, as a `SocketAddr`. The IP is a literal in
/// this file, so it cannot fail.
pub(crate) fn listen_addr() -> std::net::SocketAddr {
    addr_at(port())
}

fn addr_at(port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::from((LISTEN_IP.parse::<Ipv4Addr>().unwrap(), port))
}

/// Whether something accepts connections on the proxy's address right now.
///
/// This is the one precondition for `HTTPS_PROXY` naming this port. The variable
/// is user-wide, so a value pointing at a socket nobody holds does not merely
/// leave Antigravity unrouted - it takes every proxy-aware program on the machine
/// with it, the language server's own OAuth call included (G31). Nothing may set
/// that variable without asking this first.
pub fn listener_answers() -> bool {
    #[cfg(target_os = "macos")]
    { return checked_listener_answers().unwrap_or(false); }
    #[cfg(not(target_os = "macos"))]
    answers_at(listen_addr())
}

#[cfg(target_os = "macos")]
pub(crate) fn checked_listener_answers() -> Result<bool, String> {
    crate::background::owned_proxy_listener_at(port())
}

/// The check above, with the address given: the product asks about its own port,
/// and a test needs one nothing else on the machine can be holding. Waiting for
/// the listener to come up is `wait_for_our_listener`, which re-reads the port.
///
/// A refused connection means no listener and must read as `false`. Spelled out
/// because the version this replaces answered `true` on its own parse failure, so
/// a mistake there would have hidden a dead proxy rather than reported one.
pub(crate) fn answers_at(addr: std::net::SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
}

/// Probe the existing local HTTP refusal contract after the caller has
/// independently qualified the listener's task, process and ownership.
pub(crate) fn protocol_answers_at(addr: std::net::SocketAddr, budget: Duration) -> io::Result<()> {
    if !addr.ip().is_loopback() || budget.is_zero() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "local proxy probe requires loopback and a nonzero budget"));
    }
    let deadline = Instant::now().checked_add(budget)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy probe deadline overflow"))?;
    let left = || deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "proxy probe deadline"));
    let mut stream = TcpStream::connect_timeout(&addr, left()?)?;
    let mut request = &b"GET / HTTP/1.1\r\n\r\n"[..];
    while !request.is_empty() {
        stream.set_write_timeout(Some(left()?))?;
        match stream.write(request) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "proxy probe write returned zero")),
            Ok(n) => request = &request[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let mut response = vec![0; RESP_NOT_ALLOWED.len()];
    let mut received = 0;
    while received < response.len() {
        stream.set_read_timeout(Some(left()?))?;
        match stream.read(&mut response[received..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "proxy refusal response incomplete")),
            Ok(n) => received += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    left()?;
    if response != RESP_NOT_ALLOWED {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected proxy refusal response"));
    }
    Ok(())
}

#[cfg(test)]
fn wait_at(addr: std::net::SocketAddr, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if answers_at(addr) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(POLL_FOR_LISTENER);
    }
}

pub(crate) const POLL_FOR_LISTENER: Duration = Duration::from_millis(250);

/// Takes the CA back out of the trust store and deletes its key.
///
/// Deliberately best-effort and idempotent: revert must not stop half way and
/// leave a root certificate behind, so every step runs even if an earlier one
/// found nothing to do.
pub fn untrust_ca() {
    let mut cmd = std::process::Command::new("certutil");
    cmd.args(["-user", "-delstore", "Root", CA_NAME]);
    no_window(&mut cmd).output().ok();
    fs::remove_file(ca_cert_path()).ok();
    fs::remove_file(ca_key_path()).ok();
}

// There used to be a `ca_is_trusted()` here, to decide whether `untrust_ca` had
// anything to do. It was the gate on the revert, and the gate is what let a
// machine come out of a revert with its proxy variables still set. `untrust_ca`
// is idempotent and costs one `certutil` call, so asking first bought nothing
// and could only ever skip work that needed doing.

/// The same client configuration, for the resolver's handshake probe.
///
/// Shared deliberately: the probe has to negotiate what the real connection will
/// negotiate, or it measures something the client never does.
pub fn probe_config() -> Arc<ClientConfig> {
    upstream_config()
}

fn upstream_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

/// What to put in a `CONNECT` to the proxy at `proxy_host` for `host`.
///
/// The name, except for a gate host through a proxy on this machine or the
/// local network while the loopback door is up: that proxy would resolve the
/// name through the system resolver, get our own loopback address, and dial
/// back into us (a loop with no end). It gets genuine Google's address instead
/// (`resolvers::genuine_a`), or the name when none is known.
pub fn connect_target(proxy_host: &str, host: &str) -> String {
    connect_target_with(proxy_host, host, crate::loopback::active, crate::resolvers::genuine_a)
}

fn connect_target_with<A, R>(proxy_host: &str, host: &str, active: A, genuine_a: R) -> String
where
    A: FnOnce() -> bool,
    R: FnOnce(&str) -> Vec<std::net::Ipv4Addr>,
{
    if !is_gate_host(host) || !active() || !is_local_host(proxy_host) {
        return host.to_string();
    }
    genuine_a(host)
        .first()
        .map_or_else(|| host.to_string(), |ip| ip.to_string())
}

/// A host on this machine or on a private network - where a proxy resolves
/// names the way this machine does.
fn is_local_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified(),
        // A name: a machine on the LAN by its hostname resolves like we do, and
        // a public proxy by name resolves remotely. Only the first loops, and a
        // bare single-label name is the shape it comes in.
        Err(_) => !h.contains('.'),
    }
}

/// The two region-gated CloudCode endpoints - the only names that ever need a
/// route other than a plain direct tunnel. Everything else reaches genuine
/// Google unaided, so it is never sent through anybody's proxy.
///
/// Every route shares the same gate-host policy.
pub fn is_gate_host(host: &str) -> bool {
    crate::gate_hosts::is_gate_host(host)
}

/// A credential-bearing route may only be opened for this target class.
pub(crate) struct GateTarget443<'a> {
    host: &'a str,
}

impl<'a> GateTarget443<'a> {
    pub(crate) fn new(host: &'a str, port: u16) -> Option<Self> {
        (port == 443 && is_gate_host(host)).then_some(Self { host })
    }

    pub(crate) fn host(&self) -> &str {
        self.host
    }
}

/// The settings and separately owned credentials captured for one gate request.
/// Health remains live; configuration is not reread during this request.
pub(crate) enum DesiredRouteProfile {
    System,
    Configured { settings: crate::settings::Settings, own: Option<Arc<upstream::OwnContext>>, group: Option<crate::group_key::GroupKey> },
}

impl DesiredRouteProfile {
    fn dns_allow_missing_defaults(&self) -> bool {
        matches!(self, Self::Configured { settings, .. } if matches!(settings.transport_profile, crate::settings::TransportProfileSetting::Absent))
    }
    pub(crate) fn capture_for_work(active: crate::settings::ActiveTransportConfig) -> Result<Self, route_session::OpenFailure> {
        Self::capture(Some(active))
    }

    pub(crate) fn probe_selected(&self) -> Result<(), String> {
        if let Self::Configured { settings, own, group } = self {
            if settings.own_proxy_enabled {
                let endpoint = own.as_ref().ok_or("configured own proxy unavailable")?;
                endpoint.probe(false)?;
            }
            if settings.group_proxy {
                let key = group.as_ref().ok_or("configured group key unavailable")?;
                crate::group::probe_health_for(key)?;
            }
        }
        Ok(())
    }

    fn capture(active: Option<crate::settings::ActiveTransportConfig>) -> Result<Self, route_session::OpenFailure> {
        use crate::settings::{TransportIntent, TransportProfile};
        if let Some(config) = active {
            config.validate().map_err(|error| route_session::OpenFailure::Unavailable(Some(error)))?;
            if config.profile == TransportProfile::SystemTcp {
                if !cfg!(windows) {
                    return Err(route_session::OpenFailure::Unavailable(Some("system transport is not yet admitted on this platform".into())));
                }
                if !config.tcp_proxy {
                    return Err(route_session::OpenFailure::Unavailable(Some("invalid active system transport".into())));
                }
                return Ok(Self::System);
            }
        }
        let expected = match (active, crate::settings::checked_transport_intent()) {
            (None, TransportIntent::Legacy(settings)) => settings,
            (Some(config), TransportIntent::Explicit { settings, requirements })
                if config.profile == TransportProfile::ExistingConfigured && requirements.active_config == config => settings,
            _ => return Err(route_session::OpenFailure::Unavailable(Some("transport intent or active configuration is unreceived".into()))),
        };
        Self::capture_configured(expected)
    }

    pub(crate) fn capture_explicit(settings: crate::settings::Settings, active: crate::settings::ActiveTransportConfig) -> Result<Self, route_session::OpenFailure> {
        active.validate().map_err(|error| route_session::OpenFailure::Unavailable(Some(error)))?;
        if !active.tcp_proxy {
            return Err(route_session::OpenFailure::Unavailable(Some("TCP transport is not selected".into())));
        }
        let expected = settings.transport_requirements().map_err(|error| route_session::OpenFailure::Unavailable(Some(error)))?;
        if expected.active_config != active {
            return Err(route_session::OpenFailure::Unavailable(Some("active transport differs from the received snapshot".into())));
        }
        if active.profile == crate::settings::TransportProfile::SystemTcp {
            if !cfg!(windows) { return Err(route_session::OpenFailure::Unavailable(Some("system transport is not yet admitted on this platform".into()))); }
            return Ok(Self::System);
        }
        Self::capture_configured(settings)
    }

    fn capture_configured(expected: crate::settings::Settings) -> Result<Self, route_session::OpenFailure> {
        let (settings, group) = crate::group::capture_route_profile();
        if !same_route_snapshot(&expected, &settings) {
            return Err(route_session::OpenFailure::Unavailable(Some("route settings changed during capture".into())));
        }
        let own = if settings.own_proxy_enabled {
            upstream::capture_own().map_err(|e| route_session::OpenFailure::Unavailable(Some(e)))?
        } else { None };
        Ok(Self::Configured { settings, own, group })
    }

    fn usable(&self, kind: routes::Kind, host: &str) -> bool {
        let Self::Configured { settings, own, group } = self else { return kind == routes::Kind::Direct; };
        match kind {
            routes::Kind::Own => settings.own_proxy_enabled
                && own.as_ref().is_some_and(|own| own.usable()),
            routes::Kind::Group => settings.group_proxy
                && crate::group::bound_key_usable(group.as_ref()),
            routes::Kind::Exits => settings.builtin_exits && exits_available(),
            routes::Kind::Relay => relay_usable(),
            routes::Kind::Direct => dns_candidate_potential(host, self.dns_allow_missing_defaults()),
            routes::Kind::Vpn => vpn_usable(),
        }
    }

    fn order(&self, host: &str) -> Vec<routes::Kind> {
        let Self::Configured { settings, .. } = self else { return vec![routes::Kind::Direct]; };
        routes::order_for_profile(
            &settings.debug_route,
            settings.own_proxy_at > settings.group_key_at,
            |kind| self.usable(kind, host),
        )
    }

    fn allows_direct(&self) -> bool {
        match self {
            Self::System => true,
            Self::Configured { settings, .. } => settings.debug_route.trim().is_empty() || settings.debug_route.trim().eq_ignore_ascii_case("direct"),
        }
    }
}

fn same_route_snapshot(a: &crate::settings::Settings, b: &crate::settings::Settings) -> bool {
    a.transport_profile == b.transport_profile && a.dns == b.dns && a.local_proxy == b.local_proxy
        && a.builtin_exits == b.builtin_exits && a.group_proxy == b.group_proxy
        && a.own_proxy_enabled == b.own_proxy_enabled && a.debug_route == b.debug_route
        && a.own_proxy_at == b.own_proxy_at && a.group_key_at == b.group_key_at
        && a.group_key == b.group_key && a.own_proxy == b.own_proxy
}

/// Sends a gate host through the user's own proxy, when they gave us one and it
/// is currently working. `Err` hands the client back untouched for the next
/// route to try - nothing has been said to it yet.
///
/// Health is judged by the warm loop's probe, not by what happens here, with one
/// exception: a proxy that will not even accept the `CONNECT` is unambiguously
/// down and says so immediately. Everything subtler - accepting tunnels and
/// cutting them at the handshake, which is exactly how the relay failed - is left
/// to the probe, because "bytes moved" is not the same question as "it worked"
/// and reading it that way once already let an outage run.
fn try_own_proxy(client: TcpStream, host: &str, port: u16, up: &Arc<upstream::OwnContext>,
                 deadline: Instant, cancelled: &std::sync::atomic::AtomicBool) -> Result<Result<ConnectionSuccess, ConnectionFailure>, TcpStream> {
    if port != 443 || !is_gate_host(host) || cancelled.load(std::sync::atomic::Ordering::Acquire) {
        return Err(client);
    }
    let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()) else {
        return Err(client);
    };
    let upstream_sock = match upstream::open_with_cancellation(up.endpoint(), host, port, left.min(upstream::LIVE_OPEN_BUDGET), Some(cancelled)) {
        Ok(sock) => sock,
        Err(why) => {
            // The route's name, never its address: this log goes into the report
            // users paste into a public chat, and the address carries their login
            // and their server. The window shows which proxy it is.
            crate::dns_forwarder::log_proxy(&format!("свой прокси: {}", why));
            up.note_open_failure();
            return Err(client);
        }
    };
    if cancelled.load(std::sync::atomic::Ordering::Acquire) || Instant::now() >= deadline {
        drop(upstream_sock);
        return Err(client);
    }
    routes::bind_serving_own(Arc::clone(up));
    let opened = route_session::OpenedRoute::Tcp { socket: upstream_sock, kind: Some(routes::Kind::Own), direct_proof: None };
    Ok(route_session::commit(opened, client, Vec::new(), host, route_session::FrontendEof::NativeCompatible, deadline, cancelled)
        .map_err(ConnectionFailure::Commit).and_then(|committed| committed.transfer_native().map_err(ConnectionFailure::Transfer)))
}

/// Longest the direct route may spend connecting to a gate host before the next
/// route deserves the client. Spread across every address the name resolves to,
/// so a black-holing first address does not spend it all (G7).
pub(crate) const DIRECT_OPEN_BUDGET: Duration = Duration::from_secs(4);
/// The same for a host that has no other route: long enough for a slow edge,
/// short enough that an abandoned socket does not hold a thread for Windows'
/// own 21 s per address.
const TUNNEL_OPEN_BUDGET: Duration = Duration::from_secs(10);

/// The substituted address of a gate host, from the provider pool, and the
/// interface to reach it through.
///
/// Linux too, although it has no DNS layer: the pool is this process's own
/// code, not the relay's. It used to take the system resolver there, which on
/// most machines answers with Google itself - the region gate, from a Russian
/// address - so once the exits and the relay were benched, "напрямую" was a
/// route to 400s that the log called «the DNS route».
struct DnsOpened {
    socket: TcpStream,
    admission: routes::DnsAdmission,
    candidate: crate::resolvers::DnsCandidate,
    witness: crate::resolvers::DnsSourceWitness,
    allow_missing_defaults: bool,
}

enum CandidateOpenError { Denied, Failure(String) }
impl From<String> for CandidateOpenError { fn from(error: String) -> Self { Self::Failure(error) } }
impl From<&str> for CandidateOpenError { fn from(error: &str) -> Self { Self::Failure(error.into()) } }

fn dns_candidate_potential(host: &str, allow_missing_defaults: bool) -> bool {
    let Ok(witness) = crate::resolvers::current_witness(dns_missing_policy(allow_missing_defaults)) else { return false; };
    matches!(routes::dns_selection(host, &witness), Ok(routes::DnsSelection::Ready(_)) | Ok(routes::DnsSelection::Pending))
}

fn dns_missing_policy(allow_missing_defaults: bool) -> crate::resolvers::DnsMissingPolicy {
    if allow_missing_defaults { crate::resolvers::DnsMissingPolicy::LegacyDefaults }
    else { crate::resolvers::DnsMissingPolicy::RequireSettings }
}

fn open_qualified_dns(host: &str, deadline: Instant, cancelled: &std::sync::atomic::AtomicBool,
    checks: Option<&route_session::DirectChecks<'_>>, allow_missing_defaults: bool, maximum: Duration) -> Result<DnsOpened, CandidateOpenError> {
    use std::sync::atomic::Ordering;
    if !crate::gate_hosts::is_public_dns_target(host, 443) { return Err(CandidateOpenError::Denied); }
    loop {
        if cancelled.load(Ordering::Acquire) { return Err("DNS candidate request cancelled".into()); }
        let left = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()).ok_or("DNS candidate deadline expired")?;
        let witness = crate::resolvers::current_witness(dns_missing_policy(allow_missing_defaults)).map_err(|_| "DNS source settings unavailable")?;
        match routes::dns_selection(host, &witness)? {
            routes::DnsSelection::Pending => {
                if !routes::dns_maintenance_pending(host, &witness) { routes::request_dns_refresh(host); }
                routes::wait_dns_change(left.min(PUMP_MAX_SLEEP))?;
            }
            routes::DnsSelection::NoEligible => return Err("no qualified DNS candidate".into()),
            routes::DnsSelection::Ready(items) => {
                let mut valid = Vec::new();
                let mut has_current_source = false;
                for (admission, candidate) in items {
                    if !crate::resolvers::is_public_v4(admission.ip) { continue; }
                    if !crate::resolvers::source_is_current(&candidate, &witness).map_err(|error| format!("DNS source check failed: {error:?}"))? { continue; }
                    has_current_source = true;
                    let address = std::net::SocketAddr::from((admission.ip, 443));
                    if checks.is_none_or(|checks| (checks.address)(address)) { valid.push((admission, candidate)); }
                }
                if valid.is_empty() {
                    if has_current_source { return Err(CandidateOpenError::Denied); }
                    if !routes::dns_maintenance_pending(host, &witness) { routes::request_dns_refresh(host); }
                    routes::wait_dns_change(left.min(PUMP_MAX_SLEEP))?;
                    continue;
                }
                let addresses = valid.iter().map(|(admission, _)| std::net::SocketAddr::from((admission.ip, 443))).collect();
                let open_budget = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()).ok_or("DNS candidate deadline expired")?.min(maximum);
                let connection = connect_addrs_checked(addresses, open_budget, crate::net::pin_interface(),
                    |address| {
                        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline || !checks.is_none_or(|checks| (checks.address)(address)) { return false; }
                        let Some((admission, candidate)) = valid.iter().find(|(admission, _)| address == std::net::SocketAddr::from((admission.ip, 443))) else { return false; };
                        let Ok(fresh) = crate::resolvers::current_witness(dns_missing_policy(allow_missing_defaults)) else { return false; };
                        fresh == witness && matches!(crate::resolvers::source_is_current(candidate, &fresh), Ok(true))
                            && routes::dns_admission_current(host, *admission, &fresh)
                    },
                    |address, socket| socket.peer_addr().is_ok_and(|peer| peer == address && checks.is_none_or(|checks| (checks.peer)(address, peer))));
                let socket = match connection {
                    Ok(socket) => socket,
                    Err(error) => {
                        let fresh = crate::resolvers::current_witness(dns_missing_policy(allow_missing_defaults)).map_err(|_| "DNS source settings unavailable")?;
                        if fresh != witness || !valid.iter().any(|(_, candidate)| matches!(crate::resolvers::source_is_current(candidate, &fresh), Ok(true))) {
                            return Err("DNS candidate source changed while opening".into());
                        }
                        return Err(error.into());
                    }
                };
                let peer = socket.peer_addr().map_err(|_| "DNS candidate peer unavailable")?;
                let (admission, candidate) = valid.into_iter().find(|(admission, _)| peer == std::net::SocketAddr::from((admission.ip, 443)))
                    .ok_or("DNS candidate peer mismatch")?;
                let fresh = crate::resolvers::current_witness(dns_missing_policy(allow_missing_defaults)).map_err(|_| "DNS source settings unavailable")?;
                let source_current = crate::resolvers::source_is_current(&candidate, &fresh).map_err(|error| format!("DNS source check failed after opening: {error:?}"))?;
                if fresh != witness || !source_current ||
                    !routes::dns_admission_current(host, admission, &fresh) || cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err("DNS candidate eligibility changed while opening".into());
                }
                return Ok(DnsOpened { socket, admission, candidate, witness: fresh, allow_missing_defaults });
            }
        }
    }
}

/// Legacy helper: system lookup is synchronous and may exceed `budget`; the
/// socket budget starts only after lookup. System transport uses the checked
/// caller deadline instead.
/// Walks `addrs` inside `budget`, a slice each, leaving through `pin` when it is
/// not 0.
fn connect_addrs(
    addrs: Vec<std::net::SocketAddr>,
    budget: Duration,
    pin: u32,
) -> Result<TcpStream, String> {
    connect_addrs_checked(addrs, budget, pin, |_| true, |_, _| true)
}

fn connect_addrs_checked(
    addrs: Vec<std::net::SocketAddr>,
    budget: Duration,
    pin: u32,
    allow: impl Fn(std::net::SocketAddr) -> bool,
    peer_allowed: impl Fn(std::net::SocketAddr, &TcpStream) -> bool,
) -> Result<TcpStream, String> {
    connect_addrs_checked_with(addrs, budget, pin, allow, peer_allowed, crate::net::connect)
}

fn connect_addrs_checked_with(
    mut addrs: Vec<std::net::SocketAddr>,
    budget: Duration,
    pin: u32,
    allow: impl Fn(std::net::SocketAddr) -> bool,
    peer_allowed: impl Fn(std::net::SocketAddr, &TcpStream) -> bool,
    mut connect: impl FnMut(std::net::SocketAddr, Duration, u32) -> io::Result<TcpStream>,
) -> Result<TcpStream, String> {
    let deadline = Instant::now() + budget;
    if addrs.is_empty() {
        return Err("имя не разрешается".to_string());
    }
    // IPv4 first. Every substituted address is IPv4 - the providers' proxies
    // are - while an AAAA answer for the same name is genuine Google, and on a
    // machine with global IPv6 the resolver may list it first. Connecting there
    // would reach the gate from the blocked region with the DNS layer "working".
    addrs.sort_by_key(|a| a.is_ipv6());
    // A slice per address, at least a second each, so three addresses get a
    // real attempt inside a four-second budget.
    let slice = (budget / addrs.len().max(1) as u32).max(Duration::from_secs(1));
    let mut last = "время вышло".to_string();
    for addr in addrs {
        if !allow(addr) {
            continue;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match connect(addr, slice.min(left), pin) {
            Ok(sock) => {
                if peer_allowed(addr, &sock) {
                    return Ok(sock);
                }
                last = "адрес соединения не прошёл проверку".to_string();
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("не подключиться: {}", last))
}

#[cfg(test)]
pub(crate) fn connect_fixture_addrs(addrs: Vec<std::net::SocketAddr>, budget: Duration) -> Result<TcpStream, String> {
    connect_addrs_checked(addrs, budget, 0, |addr| addr.ip().is_loopback(),
        |addr, stream| stream.peer_addr().ok() == Some(addr))
}

/// What the relay found out about the tunnel's exit: `Some(true)` for a
/// country the gate lets through, `Some(false)` for one it does not, `None`
/// before anything was measured. The `Vpn` row is only offered on `Some(true)`:
/// a tunnel exiting in Russia would hand the first request of every session to
/// the gate.
static VPN_EXIT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub fn set_vpn_exit(permitted: Option<bool>) {
    let v = match permitted {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    VPN_EXIT.store(v, std::sync::atomic::Ordering::Relaxed);
}

pub fn vpn_exit() -> Option<bool> {
    match VPN_EXIT.load(std::sync::atomic::Ordering::Relaxed) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

fn vpn_usable() -> bool {
    crate::net::tunnel_up() && vpn_exit() == Some(true)
}

/// Whether `kind` is worth offering the next gate connection to. The route
/// table orders; this says who is in the running at all.
///
/// A region bench (`routes::is_penalised`) is deliberately **not** asked about
/// here, for any route. It is an ordering signal - `order_with` puts benched
/// routes last, soonest-to-expire first - and answering it here as well took
/// four of the five kinds out of the table altogether, leaving that branch to
/// run for `Exits` alone. A field report showed what the asymmetry costs: with
/// every other route benched out of existence, the table fell through to a
/// relay that carried nothing, while the benched built-in exit - the only one
/// answering - stayed in only because its arm never asked. Being last is the
/// punishment; disappearing is not.
///
/// What is asked about here is whether the route exists at all on this machine
/// right now: a proxy the user has not given us, a tunnel that is not up, a
/// pool with nothing in it, a name the DNS layer is not substituting.
pub fn route_usable(kind: routes::Kind, host: &str) -> bool {
    match kind {
        routes::Kind::Own => upstream::available(),
        routes::Kind::Group => crate::settings::group_proxy_enabled() && crate::group::available(),
        // The window's switch, checked at the one place the route is offered
        // from. Off means the route is simply not usable, which the table
        // already knows how to deal with - it is the same answer an exit that
        // failed its probe gives.
        routes::Kind::Exits => crate::settings::builtin_exits_enabled() && exits_available(),
        routes::Kind::Relay => relay_usable(),
        routes::Kind::Direct => direct_usable(host),
        routes::Kind::Vpn => vpn_usable(),
    }
}

/// The displayed Direct capability requires a current qualified source.
fn direct_usable(host: &str) -> bool {
    let Ok(witness) = crate::resolvers::current_witness(crate::resolvers::DnsMissingPolicy::LegacyDefaults) else { return false; };
    match routes::dns_selection(host, &witness) {
        Ok(routes::DnsSelection::Ready(items)) => items.iter().any(|(_, candidate)|
            matches!(crate::resolvers::source_is_current(candidate, &witness), Ok(true))),
        _ => false,
    }
}

#[cfg(exits)]
pub(crate) fn exits_available() -> bool {
    exits::available()
}

#[cfg(not(exits))]
pub(crate) fn exits_available() -> bool {
    false
}

#[cfg(relay)]
fn relay_usable() -> bool {
    relay::relay_available() && !relay::relay_is_benched()
}

#[cfg(not(relay))]
fn relay_usable() -> bool {
    // The stub says false; asked through it so a public build keeps the one
    // symbol the rest of the crate is written against.
    relay_available()
}

/// The host the VPN-route probe asks for: the one the IDE actually uses, so
/// the row measures the path a request takes.
const VPN_PROBE_HOST: &str = "daily-cloudcode-pa.googleapis.com";
/// Longest the probe's own request may take once connected.
const DIRECT_PROBE_BUDGET: Duration = Duration::from_secs(15);

pub(crate) enum CandidateProbe { Reachable(Duration), Refused }

fn classify_candidate_response(status: u16, body: &[u8], elapsed: Duration) -> Result<CandidateProbe, String> {
    if crate::ls_log::is_region_refusal(body) { return Ok(CandidateProbe::Refused); }
    match status {
        200..=299 | 401 | 403 | 404 => Ok(CandidateProbe::Reachable(elapsed)),
        _ => Err(format!("candidate HTTP status {status}")),
    }
}

struct CandidateProbeSocket { socket: TcpStream, deadline: Instant }
impl CandidateProbeSocket {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::new(ErrorKind::TimedOut, "candidate probe deadline"))
    }
}
impl Read for CandidateProbeSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buf)
    }
}
impl Write for CandidateProbeSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> { self.socket.flush() }
}

pub(crate) fn probe_dns_candidate(host: &str, ip: Ipv4Addr, pin: u32, budget: Duration) -> Result<CandidateProbe, String> {
    if !crate::gate_hosts::is_public_dns_target(host, 443) || !crate::resolvers::is_public_v4(ip) {
        return Err("candidate target or address denied".into());
    }
    let started = Instant::now();
    let deadline = started.checked_add(budget).ok_or("candidate deadline overflow")?;
    let left = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()).ok_or("candidate deadline expired")?;
    let address = std::net::SocketAddr::from((ip, 443));
    let socket = crate::net::connect(address, left, pin).map_err(|error| format!("candidate connect failed: {error}"))?;
    if socket.peer_addr().map_err(|_| "candidate peer unavailable")? != address { return Err("candidate peer mismatch".into()); }
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    let server = rustls::pki_types::ServerName::try_from(name.clone()).map_err(|_| "invalid candidate target")?;
    let mut tls = ClientConnection::new(probe_config(), server).map_err(|_| "candidate TLS setup failed")?;
    let mut socket = CandidateProbeSocket { socket, deadline };
    let mut stream = rustls::Stream::new(&mut tls, &mut socket);
    write!(stream, "POST /v1internal:loadCodeAssist HTTP/1.1\r\nHost: {name}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n{{}}")
        .map_err(|_| "candidate TLS or request failed")?;
    let response = dns_probe::read_response(&mut stream)?;
    socket.remaining().map_err(|_| "candidate deadline expired")?;
    classify_candidate_response(response.status, &response.body, started.elapsed())
}

/// Times the user's VPN as a route, the same request as the others. Only while
/// a tunnel holds the default route and exits somewhere usable; otherwise the
/// row is simply unmeasured.
pub fn probe_vpn() {
    if !crate::net::tunnel_up() || vpn_exit() != Some(true) {
        routes::record_failure(routes::Kind::Vpn);
        return;
    }
    let started = Instant::now();
    let addrs: Vec<_> = crate::resolvers::genuine_a(VPN_PROBE_HOST)
        .into_iter()
        .map(|a| std::net::SocketAddr::from((a, 443)))
        .collect();
    let outcome = connect_addrs(addrs, DIRECT_OPEN_BUDGET, 0).and_then(probe_request);
    match outcome {
        Ok(()) => routes::record(routes::Kind::Vpn, started.elapsed()),
        Err(why) => {
            routes::probe_failed(routes::Kind::Vpn);
            crate::dns_forwarder::log_proxy(&format!("через VPN не отвечает: {}", why));
        }
    }
}

/// One small request over an open socket: TLS to the gate host, a `GET`, an
/// HTTP answer. What every route is timed by.
fn probe_request(mut sock: TcpStream) -> Result<(), String> {
    sock.set_read_timeout(Some(DIRECT_PROBE_BUDGET)).ok();
    sock.set_write_timeout(Some(DIRECT_PROBE_BUDGET)).ok();
    let name =
        rustls::pki_types::ServerName::try_from(VPN_PROBE_HOST).map_err(|e| e.to_string())?;
    let mut tls = ClientConnection::new(probe_config(), name).map_err(|e| e.to_string())?;
    let mut stream = rustls::Stream::new(&mut tls, &mut sock);
    let req = format!(
        "GET /v1internal:probe HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        VPN_PROBE_HOST
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("рукопожатие: {}", e))?;
    let mut buf = [0u8; 64];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("ответа нет: {}", e))?;
    if n > 0 && buf.starts_with(b"HTTP/") {
        Ok(())
    } else {
        Err("ответ не похож на HTTP".to_string())
    }
}

/// `CONNECT host:port HTTP/1.1` and the headers after it, up to the blank line.
///
/// Returns the target. Anything that is not a CONNECT is refused rather than
/// guessed at: this proxy exists for one client and one method.
fn read_connect(sock: &mut TcpStream) -> Request {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8 * 1024 {
            return Request::Malformed;
        }
        match sock.read(&mut byte) {
            // The client hung up, or never spoke inside REQUEST_IDLE. Neither is
            // a request to refuse, and answering one is worse than silence: a
            // pooling client - Node opens proxy sockets before it has anything
            // to send - would find a status line where its CONNECT response
            // belongs. That was the whole of "Proxy connection ended before
            // receiving CONNECT response": a 10 s timeout writing 405 into a
            // socket the client had not used yet.
            Ok(0) | Err(_) => return Request::Gone,
            Ok(_) => head.push(byte[0]),
        }
    }
    match parse_connect(&String::from_utf8_lossy(&head)) {
        Some((host, port)) => Request::Connect(host, port),
        None => Request::Malformed,
    }
}

/// What arrived on a freshly accepted socket.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Connect(String, u16),
    /// Something that is not a CONNECT. Answered, because the client is there.
    Malformed,
    /// Nothing arrived. Closed in silence, because there is nobody to answer.
    Gone,
}

fn parse_connect(head: &str) -> Option<(String, u16)> {
    crate::connect_wire::decode_request(head).map(|request| (request.host, request.port))
}

#[cfg_attr(not(relay), allow(dead_code))]
pub(crate) fn would_block(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

/// Raw byte tunnel, for everything this proxy has no business decrypting.
fn tunnel(client: TcpStream, host: &str, port: u16, deadline: Instant,
          cancelled: &std::sync::atomic::AtomicBool) -> Result<ConnectionSuccess, ConnectionFailure> {
    tunnel_with_lookup(client, host, deadline, cancelled, || (host, port).to_socket_addrs().map(|items| items.collect()))
}

fn tunnel_with_lookup(mut client: TcpStream, host: &str, deadline: Instant,
          cancelled: &std::sync::atomic::AtomicBool,
          lookup: impl FnOnce() -> io::Result<Vec<std::net::SocketAddr>>) -> Result<ConnectionSuccess, ConnectionFailure> {
    let upstream = match route_session::open_os_with_lookup(deadline, cancelled, None, TUNNEL_OPEN_BUDGET, lookup) {
        Ok(upstream) => upstream,
        Err(error) => { respond_gateway_if_live(&mut client, deadline, cancelled); return Err(ConnectionFailure::Open(error)); }
    };
    let opened = route_session::OpenedRoute::Tcp { socket: upstream, kind: None, direct_proof: None };
    let committed = route_session::commit(opened, client, Vec::new(), host, route_session::FrontendEof::NativeCompatible, deadline, cancelled)
        .map_err(ConnectionFailure::Commit)?;
    committed.transfer_native().map_err(ConnectionFailure::Transfer)
}

/// A writer that records what it actually handed on, for the tunnel's own
/// activity stamp.
///
/// The *writer* and not the reader: bytes read from one socket may still be
/// sitting in this process, and a tunnel is carrying only what the far end has
/// taken. It costs `io::copy`'s fd-to-fd specialisation on Linux, which is a
/// trade this tunnel can afford - it moves a token stream, not a file.
pub(crate) struct Marked<'a, W: Write> {
    pub(crate) inner: &'a mut W,
    pub(crate) activity: Option<&'a routes::Activity>,
    pub(crate) to_client: bool,
}

impl<W: Write> Write for Marked<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            if let Some(a) = self.activity {
                if self.to_client {
                    a.to_client(n as u64);
                } else {
                    a.to_upstream(n as u64);
                }
            }
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Moves raw bytes between two sockets until one of them ends.
///
/// Split out of `tunnel` because a tunnel through the user's proxy is the same
/// splice with a socket that was opened differently - and a second copy of the
/// teardown discipline below would be a second place to get it wrong.
pub(crate) struct SpliceDirection {
    pub(crate) copy: std::thread::Result<io::Result<u64>>,
    pub(crate) shutdown: io::Result<()>,
}

pub(crate) struct SpliceOutcome {
    pub(crate) client_to_upstream: std::thread::Result<SpliceDirection>,
    pub(crate) upstream_to_client: std::thread::Result<io::Result<u64>>,
    pub(crate) client_shutdown_write: io::Result<()>,
    pub(crate) client_shutdown_both: io::Result<()>,
}

pub(crate) fn splice(client: TcpStream, upstream: TcpStream) {
    let _ = splice_received(client, upstream);
}

pub(crate) fn splice_received(mut client: TcpStream, mut upstream: TcpStream) -> io::Result<SpliceOutcome> {
    // A tunnel sets its own idle policy, whatever the two sockets were carrying
    // when they got here - the accept loop's silence limit on one, a CONNECT
    // reply budget on the other. Neither is a tunnel policy, and a stray one is
    // not harmless: `upstream::open`'s ten-second reply budget rode into the
    // splice and killed every pooled connection at 10.3 s of silence. `io::copy`
    // reads a timeout as the end of the stream, so the tunnel simply closed; the
    // language server saw its pooled connection die on the next write and
    // reconnected, over and over - 35 tunnels in 25 seconds, which is what a long
    // hang on "Authenticating" looks like from this side. Only the relay route
    // escaped it, because it pumps its own sockets (I37).
    //
    // None, rather than a reaper: expiring an idle tunnel is a real policy with a
    // real risk of cutting a live stream (P4), and it belongs with the payload
    // clock in the relay's pump, not smuggled in as a socket option.
    for s in [&client, &upstream] {
        s.set_read_timeout(None)?;
        s.set_write_timeout(None)?;
    }
    let mut client_w = client.try_clone()?;
    let mut upstream_w = upstream.try_clone()?;
    // Raw bytes need no shared TLS state, so the simple two-thread shape works
    // here even though the intercepted path cannot use it.
    //
    // A gate tunnel's upstream is handed to the route table, so a refused
    // route's tunnels can be closed on *both* sides (`routes::blame`, D26):
    // closing only the client side left the other direction in a blocking read
    // on an idle Google connection until Google closed it, minutes later (G52).
    routes::attach_upstream(&upstream);
    // What the tunnel is carrying, and when it last carried anything. The route
    // table reads it to tell an answer still streaming from a pooled connection
    // the client keeps feeding refused requests (D32). `None` for every tunnel
    // that is not a gate tunnel - `splice` carries those too.
    let activity = routes::serving_activity();
    let up_activity = activity.clone();
    let up = thread::Builder::new().spawn(move || {
        let moved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut sink = Marked {
                inner: &mut upstream_w,
                activity: up_activity.as_deref(),
                to_client: false,
            };
            io::copy(&mut client, &mut sink)
        }));
        let shutdown = match &moved {
            // The client finished sending. Pass the half-close on rather than
            // tearing the socket down: a client that half-closes still wants
            // the answer, and the upstream closing its side in turn is what
            // ends the other direction.
            Ok(Ok(_)) => upstream_w.shutdown(std::net::Shutdown::Write),
            // Broken, or cut from outside: nobody will read anything more.
            _ => upstream_w.shutdown(std::net::Shutdown::Both),
        };
        SpliceDirection { copy: moved, shutdown }
    })?;
    let moved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut sink = Marked {
            inner: &mut client_w,
            activity: activity.as_deref(),
            to_client: true,
        };
        io::copy(&mut upstream, &mut sink)
    }));
    // FIN first, and only then the full shutdown that releases the thread still
    // reading from this socket. Going straight to `Both` closes it with whatever
    // the client had already sent still unread, and Windows answers unread bytes
    // with RST - which a pooling client reports as "An existing connection was
    // forcibly closed by the remote host" instead of quietly reconnecting.
    let client_shutdown_write = client_w.shutdown(std::net::Shutdown::Write);
    thread::sleep(PUMP_MAX_SLEEP);
    let client_shutdown_both = client_w.shutdown(std::net::Shutdown::Both);
    let client_to_upstream = up.join();
    Ok(SpliceOutcome { client_to_upstream, upstream_to_client: moved, client_shutdown_write, client_shutdown_both })
}

/// Longest one candidate address may take - connect *and* TLS together - before
/// the next one deserves the rest of the budget.
///
/// Sized so a pool of several is actually walked: the relay's whole-route budget
/// is 8 s, and at this slice three addresses get a real attempt instead of one
/// black-holing address consuming almost all of it.
#[cfg_attr(not(relay), allow(dead_code))]
pub const UPSTREAM_PROBE_BUDGET: Duration = Duration::from_millis(2500);

/// Drives `conn` to a completed handshake over `sock` before `deadline`, or gives
/// up.
///
/// Blocking with timeouts on purpose: this runs before the client has been told
/// anything, so waiting here is honest, and the alternative - discovering a dead
/// upstream halfway through a tunnel - has no way back.
#[cfg_attr(not(relay), allow(dead_code))]
fn handshake(
    conn: &mut ClientConnection,
    sock: &mut TcpStream,
    deadline: Instant,
) -> Result<(), String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("таймаут".to_string());
    }
    sock.set_nonblocking(false).ok();
    // The socket timeouts come from the caller's deadline, not from a constant of
    // our own. A fixed six seconds here is not a local decision: it is spent out of
    // whatever budget the caller is holding, and one address that completes TCP and
    // then black-holes TLS ate almost all of the relay pool's eight seconds, so the
    // address that actually worked was never reached (G7, one layer up).
    sock.set_read_timeout(Some(left)).ok();
    sock.set_write_timeout(Some(left)).ok();
    while conn.is_handshaking() {
        if Instant::now() >= deadline {
            return Err("таймаут".to_string());
        }
        if conn.wants_write() {
            conn.write_tls(sock).map_err(|e| e.to_string())?;
        }
        if conn.wants_read() {
            match conn.read_tls(sock) {
                Ok(0) => return Err("апстрим закрыл соединение".to_string()),
                Ok(_) => conn.process_new_packets().map_err(|e| e.to_string())?,
                Err(e) => return Err(e.to_string()),
            };
        }
    }
    Ok(())
}

/// Tries the fast relay route for a gate host, else hands the client straight
/// back so `serve` uses the direct tunnel. The only place the private relay
/// module is touched: a build compiled from the public source has no such module
/// (`cfg(not(relay))`) and always falls through to the DNS route.
#[cfg(relay)]
fn try_relay_route(client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    if port == 443 && relay::relay_available() && is_gate_host(host) {
        relay::relay_tunnel(client, host, port)
    } else {
        Err(client)
    }
}

#[cfg(not(relay))]
fn try_relay_route(client: TcpStream, _host: &str, _port: u16) -> Result<(), TcpStream> {
    Err(client)
}

fn try_group(client: TcpStream, target: &GateTarget443<'_>, key: &crate::group_key::GroupKey,
             deadline: Instant, cancelled: &std::sync::atomic::AtomicBool) -> Result<Result<ConnectionSuccess, ConnectionFailure>, TcpStream> {
    let Some(opened) = crate::group::open_group(target, key, deadline, cancelled) else { return Err(client) };
    Ok(route_session::commit(route_session::OpenedRoute::Group(opened), client, Vec::new(), target.host(), route_session::FrontendEof::NativeCompatible, deadline, cancelled)
        .map_err(ConnectionFailure::Commit).and_then(|committed| committed.transfer_native().map_err(ConnectionFailure::Transfer)))
}

#[cfg(any(relay, exits))]
fn try_captured_direct(client: TcpStream, target: &GateTarget443<'_>, deadline: Instant,
                       cancelled: &std::sync::atomic::AtomicBool, vpn: bool, resolver: Option<&crate::resolvers::ResolverWork>, allow_missing_defaults: bool) -> Result<Result<ConnectionSuccess, ConnectionFailure>, (TcpStream, route_session::OpenFailure)> {
    let opened = match route_session::open_configured_direct(target, deadline, cancelled, None, vpn, resolver, allow_missing_defaults) {
        Ok(opened) => opened,
        Err(error) => return Err((client, error)),
    };
    Ok(route_session::commit(opened, client, Vec::new(), target.host(), route_session::FrontendEof::NativeCompatible, deadline, cancelled)
        .map_err(ConnectionFailure::Commit).and_then(|committed| committed.transfer_native().map_err(ConnectionFailure::Transfer)))
}

/// Tries the built-in exits for a gate host, else hands the client straight back.
/// The only place the private exits module is touched; a build from the public
/// source has no such module and falls through to the relay and the DNS route.
#[cfg(exits)]
fn try_builtin_exit(client: TcpStream, host: &str, port: u16) -> Result<(), TcpStream> {
    if port == 443 && is_gate_host(host) && exits::available() {
        exits::tunnel(client, host, port)
    } else {
        Err(client)
    }
}

#[cfg(not(exits))]
fn try_builtin_exit(client: TcpStream, _host: &str, _port: u16) -> Result<(), TcpStream> {
    Err(client)
}

fn serve(client: TcpStream, if_index: u32) {
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let _ = serve_with_transport(client, if_index, None, &cancelled, None);
}

pub(crate) enum ConnectionSuccess { NoTransfer, Tcp(SpliceOutcome), LegacyPrivate }

pub(crate) enum ConnectionFailure {
    Open(route_session::OpenFailure),
    Commit(route_session::CommitFailure),
    Transfer(io::Error),
}

fn serve_with_transport(mut client: TcpStream, _if_index: u32,
                        active: Option<crate::settings::ActiveTransportConfig>,
                        cancelled: &std::sync::atomic::AtomicBool, resolver: Option<&crate::resolvers::ResolverWork>) -> Result<ConnectionSuccess, ConnectionFailure> {
    if active.is_some_and(|config| config.profile == crate::settings::TransportProfile::ExistingConfigured) && resolver.is_none() {
        return Err(ConnectionFailure::Open(route_session::OpenFailure::Unavailable(Some("configured request resolver owner was not received".into()))));
    }
    client.set_read_timeout(Some(REQUEST_IDLE)).ok();
    let (host, port) = match read_connect(&mut client) {
        Request::Connect(host, port) => (host, port),
        Request::Malformed => {
            client.write_all(RESP_NOT_ALLOWED).ok();
            return Ok(ConnectionSuccess::NoTransfer);
        }
        Request::Gone => return Ok(ConnectionSuccess::NoTransfer),
    };
    let profile = match DesiredRouteProfile::capture(active) {
        Ok(profile) => profile,
        Err(error) => { let _ = client.write_all(RESP_BAD_GATEWAY); return Err(ConnectionFailure::Open(error)); }
    };

    // Four routes for a gate host, each handing the client back untouched if it
    // cannot serve it, in the order the route table puts them (routes.rs):
    //
    //   - the user's own proxy, when they gave us one, always first. They typed
    //     it in by hand, it is theirs rather than a third party we chose for
    //     them, and silently overriding what somebody configured is not a speed
    //     optimisation.
    //   - the rest by measured speed: a plain direct tunnel to the address the
    //     DNS layer substituted (0.28 s when last measured), a built-in exit -
    //     somebody else's CONNECT proxy in a permitted region, which lifts the
    //     gate outright (S25) - and the relay, cert-free but revocable.
    //
    // The table, not a fixed ladder, because the ladder was a guess about speed
    // that the measurements contradicted (kb/rivals.md Fact 3); and a route
    // that just carried a region 400 goes to the back (ls_log). Nothing is
    // decided before `200 Connection Established` goes out, so falling from
    // one to the next costs the client nothing (I35), and a tunnel already
    // open keeps its route whatever the table says next.
    if port == 443 && is_gate_host(&host) {
        let _gate = routes::begin_gate_connection(&client, &host);
        return serve_gate(client, &host, port, &profile, cancelled, resolver);
    }

    // This public-only purpose does not construct a credential-bearing gate
    // target and cannot enter Own, Group or WSL route admission.
    if crate::gate_hosts::is_public_dns_target(&host, port) && !is_gate_host(&host) {
        if matches!(&profile, DesiredRouteProfile::System) {
            return tunnel(client, &host, port, Instant::now() + TUNNEL_OPEN_BUDGET, cancelled);
        }
        let _gate = routes::begin_gate_connection(&client, &host);
        return serve_public_dns(client, &host, &profile, cancelled);
    }

    // Everything that is not a gate host is a plain direct tunnel - including
    // every other `*.googleapis.com` (e.g. `storage.googleapis.com`, which the
    // Desktop app loads at startup). The proxy terminates no TLS and holds no CA:
    // MITMing those hosts with a certificate no client trusts is exactly what
    // black-screened the Desktop app with `BadCertificate`. The gate hosts are
    // reached cert-free through the routes above; nothing here needs a CA.
    client.set_read_timeout(None).ok();
    tunnel(client, &host, port, Instant::now() + TUNNEL_OPEN_BUDGET, cancelled)
}

fn serve_public_dns(mut client: TcpStream, host: &str, profile: &DesiredRouteProfile,
    cancelled: &std::sync::atomic::AtomicBool) -> Result<ConnectionSuccess, ConnectionFailure> {
    let deadline = Instant::now() + TUNNEL_OPEN_BUDGET;
    if !profile.allows_direct() {
        respond_gateway_if_live(&mut client, deadline, cancelled);
        return Err(ConnectionFailure::Open(route_session::OpenFailure::Unavailable(Some("forced route is unavailable for public DNS target".into()))));
    }
    let opened = match open_qualified_dns(host, deadline, cancelled, None, profile.dns_allow_missing_defaults(), TUNNEL_OPEN_BUDGET) {
        Ok(opened) => opened,
        Err(error) => {
            respond_gateway_if_live(&mut client, deadline, cancelled);
            let failure = if cancelled.load(std::sync::atomic::Ordering::Acquire) { route_session::OpenFailure::Cancelled }
                else if Instant::now() >= deadline { route_session::OpenFailure::Deadline }
                else { match error { CandidateOpenError::Denied => route_session::OpenFailure::DeniedTarget,
                    CandidateOpenError::Failure(error) => route_session::OpenFailure::Unavailable(Some(error)) } };
            return Err(ConnectionFailure::Open(failure));
        }
    };
    if !routes::bind_serving_dns(opened.admission, opened.candidate, opened.witness, opened.allow_missing_defaults) {
        respond_gateway_if_live(&mut client, deadline, cancelled);
        return Err(ConnectionFailure::Open(route_session::OpenFailure::Unavailable(Some("DNS serving context missing".into()))));
    }
    let route = route_session::OpenedRoute::Tcp { socket: opened.socket, kind: Some(routes::Kind::Direct), direct_proof: None };
    let committed = route_session::commit(route, client, Vec::new(), host, route_session::FrontendEof::NativeCompatible, deadline, cancelled)
        .map_err(ConnectionFailure::Commit)?;
    committed.transfer_native().map_err(ConnectionFailure::Transfer)
}

/// The most one gate connection may spend walking routes that fail to open.
/// Once this budget is spent, the routes that failed have stepped aside
/// (`routes::stumble`), so the client's retry goes straight to one that opens.
const GATE_OPEN_BUDGET: Duration = Duration::from_secs(12);

fn respond_gateway_if_live(client: &mut TcpStream, deadline: Instant, cancelled: &std::sync::atomic::AtomicBool) {
    let mut written = 0;
    let _ = route_session::write_response(client, RESP_BAD_GATEWAY, &mut written,
        |socket| {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) { return Err(io::Error::other("cancelled")); }
            let left = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline"))?;
            socket.set_write_timeout(Some(left))
        },
        |_| Ok(()), |error| error);
}

/// Walks the route table for one gate connection.
#[cfg(any(relay, exits))]
fn serve_gate(client: TcpStream, host: &str, port: u16, profile: &DesiredRouteProfile, cancelled: &std::sync::atomic::AtomicBool, resolver: Option<&crate::resolvers::ResolverWork>) -> Result<ConnectionSuccess, ConnectionFailure> {
    let started = Instant::now();
    let mut client = client;
    let Some(target) = GateTarget443::new(host, port) else { let _ = client.write_all(RESP_BAD_GATEWAY); return Err(ConnectionFailure::Open(route_session::OpenFailure::DeniedTarget)); };
    let deadline = started + GATE_OPEN_BUDGET;
    if matches!(profile, DesiredRouteProfile::System) {
        match route_session::open_captured_route(&target, deadline, cancelled, None, profile, resolver) {
            Ok(opened) => { let committed = route_session::commit(opened, client, Vec::new(), host, route_session::FrontendEof::NativeCompatible, deadline, cancelled).map_err(ConnectionFailure::Commit)?; return committed.transfer_native().map_err(ConnectionFailure::Transfer); }
            Err(error) => { respond_gateway_if_live(&mut client, deadline, cancelled); return Err(ConnectionFailure::Open(error)); }
        }
    }
    let DesiredRouteProfile::Configured { own, group, .. } = profile else { unreachable!() };
    let mut tried_direct = false;
    let mut direct_error = None;
    for kind in profile.order(host) {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) || started.elapsed() >= GATE_OPEN_BUDGET {
            break;
        }
        let attempt = match kind {
            routes::Kind::Own => match own.as_ref() { Some(up) => try_own_proxy(client, host, port, up, deadline, cancelled), None => Err(client) },
            routes::Kind::Group => match group.as_ref() { Some(key) => try_group(client, &target, key, deadline, cancelled), None => Err(client) },
            routes::Kind::Exits => try_builtin_exit(client, host, port).map(|()| Ok(ConnectionSuccess::LegacyPrivate)),
            routes::Kind::Relay => try_relay_route(client, host, port).map(|()| Ok(ConnectionSuccess::LegacyPrivate)),
            routes::Kind::Direct => {
                tried_direct = true;
                match try_captured_direct(client, &target, deadline, cancelled, false, resolver, profile.dns_allow_missing_defaults()) {
                    Ok(result) => Ok(result), Err((client, error)) => { direct_error = Some(error); Err(client) }
                }
            }
            routes::Kind::Vpn => match try_captured_direct(client, &target, deadline, cancelled, true, resolver, profile.dns_allow_missing_defaults()) {
                Ok(result) => Ok(result), Err((client, error)) => { direct_error = Some(error); Err(client) }
            },
        };
        client = match attempt {
            Ok(result) => return result,
            // Failed before any `200`: not the gate, just a route that would not
            // open. Out of the way of the next few connections.
            Err(returned) => {
                if kind == routes::Kind::Own {
                    if let Some(own) = own.as_ref() { own.if_current(|| routes::stumble(kind)); }
                } else { routes::stumble(kind); }
                returned
            }
        };
    }
    // A last direct attempt is permitted only when the captured policy did not
    // force a different route. A forced or invalid route cannot expand here.
    if !tried_direct && profile.allows_direct() && !cancelled.load(std::sync::atomic::Ordering::Acquire) && started.elapsed() < GATE_OPEN_BUDGET {
        client = match try_captured_direct(client, &target, deadline, cancelled, false, resolver, profile.dns_allow_missing_defaults()) {
            Ok(result) => return result,
            Err((client, error)) => { direct_error = Some(error); client },
        };
    }
    let failure = if cancelled.load(std::sync::atomic::Ordering::Acquire) {
        route_session::OpenFailure::Cancelled
    } else if Instant::now() >= deadline {
        route_session::OpenFailure::Deadline
    } else {
        direct_error.unwrap_or(route_session::OpenFailure::Unavailable(None))
    };
    respond_gateway_if_live(&mut client, deadline, cancelled);
    Err(ConnectionFailure::Open(failure))
}

#[cfg(not(any(relay, exits)))]
fn serve_gate(mut client: TcpStream, host: &str, port: u16, profile: &DesiredRouteProfile, cancelled: &std::sync::atomic::AtomicBool, resolver: Option<&crate::resolvers::ResolverWork>) -> Result<ConnectionSuccess, ConnectionFailure> {
    let Some(target) = GateTarget443::new(host, port) else {
        let _ = client.write_all(RESP_BAD_GATEWAY);
        return Err(ConnectionFailure::Open(route_session::OpenFailure::DeniedTarget));
    };
    let deadline = Instant::now() + GATE_OPEN_BUDGET;
    let opened = match route_session::open_captured_route(&target, deadline, cancelled, None, profile, resolver) {
        Ok(opened) => opened,
        Err(error) => {
            respond_gateway_if_live(&mut client, deadline, cancelled);
            return Err(ConnectionFailure::Open(error));
        }
    };
    let committed = route_session::commit(opened, client, Vec::new(), host, route_session::FrontendEof::NativeCompatible, deadline, cancelled).map_err(ConnectionFailure::Commit)?;
    committed.transfer_native().map_err(ConnectionFailure::Transfer)
}

/// Whether the proxy's listener is bound. The loopback listener hands its
/// connections to this one, so it is only worth answering DNS with a loopback
/// address while both are up.
static PROXY_BOUND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn bound() -> bool {
    PROXY_BOUND.load(std::sync::atomic::Ordering::Relaxed)
}

/// How long a taken port is given to come free, and how often it is retried.
/// Fifteen seconds: long enough for somebody's ephemeral socket to close, short
/// enough that a permanently reserved port is reported while the user is still
/// looking at the menu.
const BIND_TRIES: u32 = 6;
const BIND_RETRY_WAIT: Duration = Duration::from_secs(3);

/// Takes the fixed port, retrying while something else holds it.
///
/// 53129 is inside Windows' **default dynamic port range** (49152-65535), so it
/// can be sitting in somebody's ephemeral client socket at the moment the relay
/// starts - a race that resolves itself in seconds. It can also be inside a range
/// Hyper-V/WSL/Docker has reserved (`netsh int ipv4 show excludedportrange`),
/// which never resolves; the retries cost 15 s and the log line then says which
/// of the two it was. Either way the caller must not claim the route: without a
/// listener the `HTTPS_PROXY` naming it breaks the machine's proxy-aware traffic
/// (G31), which is why the variable is only set once this has succeeded.
///
/// Since `2.15.0_2` a port that cannot be had is diagnosed (`portcheck`) and,
/// unless the refusal is security software's (which follows this program to any
/// port), the proxy moves to one outside the dynamic range and records it
/// (`adopt`), so the variable written after it names the port that answers.
fn bind_listener(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> Result<TcpListener, crate::gate::Blocker> {
    bind_from(root, port(), &FALLBACK_PORTS)
}

fn bind_from(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, first: u16, fallbacks: &[u16]) -> Result<TcpListener, crate::gate::Blocker> {
    let mut failed: Option<(std::io::Error, crate::portcheck::Cause)> = None;
    for attempt in 0..BIND_TRIES {
        match TcpListener::bind(addr_at(first)) {
            Ok(listener) => {
                if attempt > 0 {
                    crate::dns_forwarder::log_proxy(&format!(
                        "порт {} освободился с {}-й попытки",
                        first,
                        attempt + 1
                    ));
                }
                adopt(first);
                return Ok(listener);
            }
            Err(e) => {
                // Looked at once: which of the causes it is does not change
                // between tries, and the look costs a `netsh`.
                let cause = match failed.take() {
                    Some((_, cause)) => cause,
                    None => match root.call("proxy port diagnosis", |owner| crate::portcheck::diagnose(owner, addr_at(first), &e)) {
                        Ok(Ok(cause)) => cause,
                        Ok(Err(error)) | Err(error) => { crate::dns_forwarder::log_proxy(&format!("диагностика порта недоступна: {error}")); crate::portcheck::Cause::Other }
                    },
                };
                // A reservation or another program's listener does not go away
                // in fifteen seconds; a borrowed ephemeral port does.
                let lasting = matches!(
                    cause,
                    crate::portcheck::Cause::Reserved | crate::portcheck::Cause::Held(_)
                );
                failed = Some((e, cause));
                if lasting {
                    break;
                }
                if attempt + 1 < BIND_TRIES {
                    thread::sleep(BIND_RETRY_WAIT);
                }
            }
        }
    }
    let Some((err, cause)) = failed else {
        unreachable!("BIND_TRIES is not zero")
    };
    if cause.another_port_helps() {
        for other in fallbacks.iter().copied().filter(|p| *p != first) {
            if let Ok(listener) = TcpListener::bind(addr_at(other)) {
                crate::dns_forwarder::log_proxy(&format!(
                    "порт {} недоступен ({}) — локальный прокси перенесён на {}",
                    first, err, other
                ));
                adopt(other);
                return Ok(listener);
            }
        }
    }
    Err(cause.blocker("proxy", addr_at(first), &err))
}

/// How often a listener that could not be bound is tried again. A user who adds
/// the antivirus exception or closes the program holding the port gets the
/// bypass back within a minute, without a restart (P53).
pub const REBIND_EVERY: Duration = Duration::from_secs(60);

/// Runs the proxy until the process ends. Never returns while the socket holds;
/// while it cannot be had, says why (`gate::set_blocker`) and keeps trying.
pub fn run(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, if_index: u32) -> Result<(), String> {
    let mut said: Option<crate::gate::Blocker> = None;
    let listener = loop {
        root.receive();
        match bind_listener(root) {
            Ok(listener) => {
                if said.is_some() {
                    crate::dns_forwarder::log_proxy(&format!(
                        "локальный прокси поднялся на порту {}",
                        port()
                    ));
                    crate::gate::set_blocker("proxy", None);
                }
                break listener;
            }
            Err(blocker) => {
                // Logged when the reason changes, not every minute.
                if said.as_ref() != Some(&blocker) {
                    crate::dns_forwarder::log_proxy(&format!(
                        "not started: не занять {} — {} ({})",
                        blocker.addr,
                        blocker.error,
                        match blocker.cause.as_str() {
                            "held" if !blocker.by.is_empty() =>
                                format!("порт занят программой {}", blocker.by),
                            "held" => "порт занят другой программой".to_string(),
                            "reserved" => "порт зарезервирован Windows".to_string(),
                            "denied" => "доступ запрещён — антивирус или файрвол".to_string(),
                            _ => "причина не определена".to_string(),
                        }
                    ));
                    said = Some(blocker.clone());
                }
                // Written every try, not only on a change: the record is dropped
                // as stale after `gate::STALE_AFTER`, and on Linux this is the
                // only thing that writes it - the card would go while the
                // problem stayed.
                crate::gate::set_blocker("proxy", Some(blocker));
                thread::sleep(REBIND_EVERY);
            }
        }
    };
    PROXY_BOUND.store(true, std::sync::atomic::Ordering::Relaxed);
    // Costs a loopback socket and nothing else: no key is generated, nothing is
    // put in a trust store, and a client that never points at this port never
    // notices it is here.

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        thread::spawn(move || serve(stream, if_index));
    }
    Ok(())
}

/// The carrier retains this value across listener return and must receive its
/// finished handles. Dropping it is not evidence that any worker settled.
#[derive(Default)]
pub(crate) struct ConnectionWorkers {
    active: Vec<ConnectionWorker>,
    completed: Vec<thread::Result<Result<ConnectionSuccess, ConnectionFailure>>>,
    retired_resolvers: Vec<Arc<crate::resolvers::ResolverWork>>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    carrier_thread: Arc<OnceLock<thread::Thread>>,
}

struct ConnectionWorker {
    handle: Option<thread::JoinHandle<Result<ConnectionSuccess, ConnectionFailure>>>,
    resolver: Option<Arc<crate::resolvers::ResolverWork>>,
}

#[derive(Clone)]
pub(crate) struct ConnectionCancellation {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    carrier_thread: Arc<OnceLock<thread::Thread>>,
}

impl ConnectionCancellation {
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.carrier_thread.get() { thread.unpark(); }
    }
    pub(crate) fn is_cancelled(&self) -> bool { self.cancelled.load(std::sync::atomic::Ordering::Acquire) }
}

struct WorkerWake(Arc<OnceLock<thread::Thread>>);
impl Drop for WorkerWake {
    fn drop(&mut self) {
        if let Some(thread) = self.0.get() { thread.unpark(); }
    }
}

impl ConnectionWorkers {
    pub(crate) fn request_cancel(&self) {
        self.cancellation_token().cancel();
        for worker in &self.active { if let Some(work) = &worker.resolver { work.cancel(); } }
        for work in &self.retired_resolvers { work.cancel(); }
    }
    pub(crate) fn cancellation_token(&self) -> ConnectionCancellation {
        ConnectionCancellation { cancelled: self.cancelled.clone(), carrier_thread: self.carrier_thread.clone() }
    }
    pub(crate) fn register_current_thread(&self) -> Result<(), String> {
        let current = thread::current();
        let _ = self.carrier_thread.set(current.clone());
        if self.carrier_thread.get().is_some_and(|thread| thread.id() == current.id()) { Ok(()) }
        else { Err("connection owner used by a different carrier thread".into()) }
    }
    pub(crate) fn outstanding(&self) -> usize { self.active.len() }
    pub(crate) fn has_unreceived(&self) -> bool { !self.active.is_empty() || !self.completed.is_empty() || self.retired_resolvers.iter().any(|work| work.has_unreceived()) }
    fn spawn(&mut self, work: impl FnOnce(Arc<std::sync::atomic::AtomicBool>) -> Result<ConnectionSuccess, ConnectionFailure> + Send + 'static) -> io::Result<()> {
        self.spawn_with_resolver(None, move |cancelled, _| work(cancelled))
    }
    fn spawn_with_resolver(&mut self, resolver: Option<Arc<crate::resolvers::ResolverWork>>,
        work: impl FnOnce(Arc<std::sync::atomic::AtomicBool>, Option<Arc<crate::resolvers::ResolverWork>>) -> Result<ConnectionSuccess, ConnectionFailure> + Send + 'static) -> io::Result<()> {
        self.active.try_reserve(1).map_err(io::Error::other)?;
        if resolver.is_some() { self.retired_resolvers.try_reserve(1).map_err(io::Error::other)?; }
        let cancelled = self.cancelled.clone();
        let wake = self.carrier_thread.clone();
        let position = self.active.len();
        self.active.push(ConnectionWorker { handle: None, resolver: resolver.clone() });
        let started = thread::Builder::new().spawn(move || {
            let _wake = WorkerWake(wake);
            work(cancelled, resolver)
        });
        match started {
            Ok(handle) => self.active[position].handle = Some(handle),
            Err(error) => {
                if let Some(work) = self.active.pop().and_then(|entry| entry.resolver) { self.retired_resolvers.push(work); }
                return Err(error);
            }
        }
        Ok(())
    }
    fn collect_finished(&mut self) -> Result<(), String> {
        self.completed.try_reserve(self.active.len()).map_err(|error| error.to_string())?;
        self.retired_resolvers.try_reserve(self.active.len()).map_err(|error| error.to_string())?;
        let mut index = 0;
        while index < self.active.len() {
            if self.active[index].handle.as_ref().is_some_and(|handle| handle.is_finished()) {
                let mut worker = self.active.swap_remove(index);
                let outcome = worker.handle.take().expect("finished connection worker").join();
                if let Some(work) = worker.resolver { self.retired_resolvers.push(work); }
                self.completed.push(outcome);
            } else { index += 1; }
        }
        Ok(())
    }
    pub(crate) fn receive_finished(&mut self) -> Result<Vec<thread::Result<Result<ConnectionSuccess, ConnectionFailure>>>, String> {
        self.collect_finished()?;
        Ok(std::mem::take(&mut self.completed))
    }
    pub(crate) fn receive_resolvers_into(&mut self, terminals: &mut Vec<crate::resolvers::ResolverTerminal>) -> Result<(), String> {
        for worker in &self.active { if let Some(work) = &worker.resolver { work.receive_into(terminals)?; } }
        for work in &self.retired_resolvers { work.receive_into(terminals)?; }
        self.retired_resolvers.retain(|work| work.has_unreceived());
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerStep { Progress, Idle, Stopped }

#[derive(Debug)]
pub(crate) enum ListenerFailure {
    Bind { address: std::net::SocketAddr, error: io::Error },
    Configure { address: std::net::SocketAddr, error: io::Error },
    Accept(io::Error),
    WorkerStart(io::Error),
    Owner(String),
}

/// One nonblocking listener and its bind schedule, owned by the carrier loop.
pub(crate) struct TransportListener {
    active: crate::settings::ActiveTransportConfig,
    if_index: u32,
    listener: Option<TcpListener>,
    bound: Option<std::net::SocketAddr>,
    initial_port: u16,
    candidate_port: u16,
    next_fallback: usize,
    next_bind: Instant,
    owner: Option<ConnectionCancellation>,
    stopped: bool,
}

impl TransportListener {
    pub(crate) fn new(settings: crate::settings::Settings, active: crate::settings::ActiveTransportConfig, if_index: u32) -> Result<Self, String> {
        active.validate()?;
        if !cfg!(windows) || !active.tcp_proxy {
            return Err("transport listener is unavailable or not required".into());
        }
        DesiredRouteProfile::capture_explicit(settings, active).map_err(|error| match error {
            route_session::OpenFailure::Unavailable(Some(cause)) => cause,
            _ => "captured transport profile unavailable".into(),
        })?;
        let initial_port = port();
        Ok(Self { active, if_index, listener: None, bound: None, initial_port,
            candidate_port: initial_port, next_fallback: 0, next_bind: Instant::now(),
            owner: None, stopped: false })
    }

    pub(crate) fn bound_addr(&self) -> Option<std::net::SocketAddr> { self.bound }
    pub(crate) fn next_bind_deadline(&self) -> Option<Instant> {
        (!self.stopped && self.listener.is_none()).then_some(self.next_bind)
    }

    fn schedule_after_bind_failure(&mut self, in_use: bool) {
        if in_use {
            while let Some(&candidate) = FALLBACK_PORTS.get(self.next_fallback) {
                self.next_fallback += 1;
                if candidate != self.initial_port {
                    self.candidate_port = candidate;
                    self.next_bind = Instant::now();
                    return;
                }
            }
        }
        self.candidate_port = self.initial_port;
        self.next_fallback = 0;
        self.next_bind = Instant::now() + REBIND_EVERY;
    }

    fn stop(&mut self) -> ListenerStep {
        let was_bound = self.listener.take().is_some();
        self.bound = None;
        if was_bound { PROXY_BOUND.store(false, std::sync::atomic::Ordering::Relaxed); }
        self.stopped = true;
        ListenerStep::Stopped
    }

    pub(crate) fn poll(&mut self, workers: &mut ConnectionWorkers) -> Result<ListenerStep, ListenerFailure> {
        workers.register_current_thread().map_err(ListenerFailure::Owner)?;
        let token = workers.cancellation_token();
        if let Some(owner) = &self.owner {
            if !Arc::ptr_eq(&owner.cancelled, &token.cancelled) {
                return Err(ListenerFailure::Owner("listener worker owner changed".into()));
            }
        } else {
            self.owner = Some(token.clone());
        }
        if self.stopped { return Ok(ListenerStep::Stopped); }
        if token.is_cancelled() { return Ok(self.stop()); }
        if self.listener.is_none() {
            if Instant::now() < self.next_bind { return Ok(ListenerStep::Idle); }
            let address = addr_at(self.candidate_port);
            let listener = match TcpListener::bind(address) {
                Ok(listener) => listener,
                Err(error) => {
                    self.schedule_after_bind_failure(error.kind() == io::ErrorKind::AddrInUse);
                    return Err(ListenerFailure::Bind { address, error });
                }
            };
            if let Err(error) = listener.set_nonblocking(true) {
                self.schedule_after_bind_failure(false);
                return Err(ListenerFailure::Configure { address, error });
            }
            let bound = match listener.local_addr() {
                Ok(bound) => bound,
                Err(error) => {
                    self.schedule_after_bind_failure(false);
                    return Err(ListenerFailure::Configure { address, error });
                }
            };
            if token.is_cancelled() { return Ok(self.stop()); }
            adopt(bound.port());
            self.bound = Some(bound);
            self.listener = Some(listener);
            PROXY_BOUND.store(true, std::sync::atomic::Ordering::Relaxed);
            return Ok(ListenerStep::Progress);
        }
        let (stream, _) = match self.listener.as_ref().expect("bound listener").accept() {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(ListenerStep::Idle),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                return if token.is_cancelled() { Ok(self.stop()) } else { Ok(ListenerStep::Idle) };
            }
            Err(error) => return Err(ListenerFailure::Accept(error)),
        };
        if token.is_cancelled() { return Ok(self.stop()); }
        let address = self.bound.expect("bound address");
        stream.set_nonblocking(false).map_err(|error| ListenerFailure::Configure { address, error })?;
        if token.is_cancelled() { return Ok(self.stop()); }
        let active = self.active;
        let if_index = self.if_index;
        let resolver = (active.profile == crate::settings::TransportProfile::ExistingConfigured).then(||
            Arc::new(crate::resolvers::ResolverWork::with_cancellation(thread::current(), workers.cancelled.clone())));
        workers.spawn_with_resolver(resolver, move |cancelled, resolver| serve_with_transport(stream, if_index, Some(active), &cancelled, resolver.as_deref()))
            .map_err(ListenerFailure::WorkerStart)?;
        Ok(ListenerStep::Progress)
    }
}

impl Drop for TransportListener {
    fn drop(&mut self) {
        if self.listener.is_some() { PROXY_BOUND.store(false, std::sync::atomic::Ordering::Relaxed); }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[test]
    fn candidate_response_distinguishes_transport_and_region_refusal() {
        use super::*;
        assert!(matches!(classify_candidate_response(401, br#"{"error":"unauthenticated"}"#, Duration::ZERO), Ok(CandidateProbe::Reachable(_))));
        assert!(matches!(classify_candidate_response(403, br#"{"reason":"UNSUPPORTED_LOCATION"}"#, Duration::ZERO), Ok(CandidateProbe::Refused)));
        assert!(matches!(classify_candidate_response(403, br#"{"reason":"LOCATION_NOT_ELIGIBLE"}"#, Duration::ZERO), Ok(CandidateProbe::Refused)));
        assert!(matches!(classify_candidate_response(400, b"user location is not supported", Duration::ZERO), Ok(CandidateProbe::Refused)));
        assert!(classify_candidate_response(503, b"busy", Duration::ZERO).is_err());
    }

    #[test]
    fn checked_connector_timeout_then_real_live_peer_and_single_failure() {
        use super::*;
        use std::io::{Read, Write};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let live = listener.local_addr().unwrap();
        let reserved = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP)).unwrap();
        reserved.bind(&std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into()).unwrap();
        let timed_out = reserved.local_addr().unwrap().as_socket().unwrap();
        let mut attempted = Vec::new();
        let mut socket = connect_addrs_checked_with(vec![timed_out, live], Duration::from_secs(3), 0,
            |addr| addr.ip().is_loopback(), |addr, stream| stream.peer_addr().ok() == Some(addr),
            |addr, budget, pin| {
                attempted.push(addr);
                if addr == timed_out { Err(io::Error::new(io::ErrorKind::TimedOut, "fixture timeout")) }
                else { crate::net::connect(addr, budget, pin) }
            }).unwrap();
        socket.write_all(b"ok").unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        accepted.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut bytes = [0; 2];
        accepted.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
        assert_eq!(attempted, vec![timed_out, live]);
        let failure = connect_addrs_checked_with(vec![timed_out], Duration::from_secs(2), 0,
            |_| true, |_, _| true,
            |_, _, _| Err(io::Error::new(io::ErrorKind::TimedOut, "fixture timeout"))).unwrap_err();
        assert!(failure.contains("fixture timeout"));
        let mut empty_attempts = 0;
        let empty = connect_addrs_checked_with(Vec::new(), Duration::from_secs(2), 0,
            |_| true, |_, _| true, |_, _, _| {
                empty_attempts += 1;
                Err(io::Error::other("unexpected attempt"))
            });
        assert!(empty.is_err());
        assert_eq!(empty_attempts, 0);
    }

    #[test]
    fn unavailable_forced_route_returns_http_502_and_typed_failure() {
        use super::*;
        use std::io::Read;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let (client, _) = listener.accept().unwrap();
        let mut settings = crate::settings::Settings::default();
        settings.debug_route = "own".into();
        settings.own_proxy_enabled = false;
        let profile = DesiredRouteProfile::Configured { settings, own: None, group: None };
        let worker = thread::spawn(move || {
            serve_gate(client, "cloudcode-pa.googleapis.com", 443, &profile,
                &std::sync::atomic::AtomicBool::new(false), None)
        });
        let mut response = vec![0; RESP_BAD_GATEWAY.len()];
        let read = peer.read_exact(&mut response);
        let outcome = worker.join();
        assert!(read.is_ok());
        assert_eq!(response, RESP_BAD_GATEWAY);
        assert!(matches!(outcome, Ok(Err(ConnectionFailure::Open(route_session::OpenFailure::Unavailable(None))))));
    }

    #[test]
    fn checked_connector_tries_live_alternative_and_reports_single_bad_address() {
        use super::*;
        use socket2::{Domain, Protocol, Socket, Type};
        use std::io::{Read, Write};

        let reserved = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        reserved.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into()).unwrap();
        let bad = reserved.local_addr().unwrap().as_socket().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let live = listener.local_addr().unwrap();
        let attempt = thread::spawn(move || -> Result<(), String> {
            let mut socket = connect_fixture_addrs(vec![bad, live], Duration::from_secs(3))?;
            socket.write_all(b"ok").map_err(|error| error.to_string())
        });
        let until = Instant::now() + Duration::from_secs(4);
        let mut received = false;
        while Instant::now() < until {
            if let Ok((mut socket, _)) = listener.accept() {
                let _ = socket.set_read_timeout(Some(Duration::from_secs(1)));
                let mut bytes = [0; 2];
                received = socket.read_exact(&mut bytes).is_ok() && &bytes == b"ok";
                break;
            }
            thread::park_timeout(Duration::from_millis(10));
        }
        let joined = attempt.join();
        let failure = connect_fixture_addrs(vec![bad], Duration::from_secs(2));
        assert!(joined.unwrap().is_ok() && received);
        assert!(failure.is_err());
    }

    #[test]
    #[ignore = "isolated process: owns loopback sockets and connection worker"]
    fn non_gate_late_lookup_is_received_without_open_or_success_response() {
        use super::*;
        use std::sync::mpsc;
        for fail in [false, true] {
            let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            target.set_nonblocking(true).unwrap();
            let address = target.local_addr().unwrap();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let (client, _) = listener.accept().unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let mut workers = ConnectionWorkers::default();
            workers.register_current_thread().unwrap();
            workers.spawn(move |cancelled| tunnel_with_lookup(client, "fixture.invalid",
                Instant::now() + Duration::from_secs(5), &cancelled, || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    if fail { Err(io::Error::other("owned late lookup")) } else { Ok(vec![address]) }
                })).unwrap();
            started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            workers.request_cancel();
            release_tx.send(()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let result = loop {
                if let Some(result) = workers.receive_finished().unwrap().pop() { break result; }
                assert!(Instant::now() < deadline);
                thread::park_timeout(PUMP_MAX_SLEEP);
            };
            if fail {
                assert!(matches!(result, Ok(Err(ConnectionFailure::Open(route_session::OpenFailure::ResolutionLate { cancelled: true, error }))) if error.to_string() == "owned late lookup"));
            } else {
                assert!(matches!(result, Ok(Err(ConnectionFailure::Open(route_session::OpenFailure::Cancelled)) )));
            }
            let mut received = Vec::new();
            peer.read_to_end(&mut received).unwrap();
            assert!(received.is_empty());
            assert_eq!(target.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
            assert!(!workers.has_unreceived());
        }
    }
    pub(crate) fn fixture_transport_listener() -> (super::TransportListener, std::net::SocketAddr) {
        use super::*;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        (TransportListener { active: crate::settings::ActiveTransportConfig { profile: crate::settings::TransportProfile::SystemTcp, client_proxy: true, tcp_proxy: true, dns: false, dns_alias: false }, if_index: 0, listener: Some(listener), bound: Some(address),
            initial_port: address.port(), candidate_port: address.port(), next_fallback: 0,
            next_bind: Instant::now(), owner: None, stopped: false }, address)
    }

    pub(crate) fn fixture_spawn_connection(workers: &mut super::ConnectionWorkers,
        work: impl FnOnce(std::sync::Arc<std::sync::atomic::AtomicBool>) -> Result<(), super::ConnectionFailure> + Send + 'static)
        -> std::io::Result<()> {
        workers.spawn(move |cancelled| work(cancelled).map(|()| super::ConnectionSuccess::NoTransfer))
    }

    #[cfg(windows)]
    pub(crate) fn fixture_spawn_native_transfer(workers: &mut super::ConnectionWorkers,
        client: std::net::TcpStream, upstream: std::net::TcpStream) -> std::io::Result<()> {
        workers.spawn(move |_| super::splice_received(client, upstream)
            .map(super::ConnectionSuccess::Tcp).map_err(super::ConnectionFailure::Transfer))
    }

    #[cfg(windows)]
    pub(crate) fn fixture_spawn_outcome(workers: &mut super::ConnectionWorkers,
        outcome: super::SpliceOutcome) -> std::io::Result<()> {
        workers.spawn(move |_| Ok(super::ConnectionSuccess::Tcp(outcome)))
    }

    #[test]
    fn finite_listener_receives_protocol_and_stops_on_token() {
        use super::*;
        let (mut listener, address) = fixture_transport_listener();
        let mut workers = ConnectionWorkers::default();
        assert!(matches!(listener.poll(&mut workers), Ok(ListenerStep::Idle)));
        let probe = thread::spawn(move || protocol_answers_at(address, Duration::from_secs(2)));
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.poll(&mut workers).unwrap() {
                ListenerStep::Progress => break,
                ListenerStep::Idle => { assert!(Instant::now() < until); thread::yield_now(); }
                ListenerStep::Stopped => panic!("listener stopped before accept"),
            }
        }
        probe.join().unwrap().unwrap();
        loop {
            let results = workers.receive_finished().unwrap();
            if !results.is_empty() {
                assert!(matches!(&results[0], Ok(Ok(ConnectionSuccess::NoTransfer))));
                break;
            }
            assert!(Instant::now() < until);
            thread::yield_now();
        }
        let cancel = workers.cancellation_token();
        cancel.cancel();
        assert!(matches!(listener.poll(&mut workers), Ok(ListenerStep::Stopped)));
        assert!(!workers.has_unreceived());
    }

    #[test]
    fn cancellation_stops_during_bind_delay_without_waiting() {
        use super::*;
        let (mut listener, _) = fixture_transport_listener();
        listener.listener.take(); listener.bound = None;
        listener.next_bind = Instant::now() + REBIND_EVERY;
        let mut workers = ConnectionWorkers::default();
        assert!(matches!(listener.poll(&mut workers), Ok(ListenerStep::Idle)));
        workers.cancellation_token().cancel();
        assert!(matches!(listener.poll(&mut workers), Ok(ListenerStep::Stopped)));
    }

    #[test]
    fn bind_failure_is_received_and_cancel_remains_responsive() {
        use super::*;
        let (mut listener, address) = fixture_transport_listener();
        let occupied = listener.listener.take().unwrap();
        listener.bound = None;
        listener.next_bind = Instant::now();
        let mut workers = ConnectionWorkers::default();
        match listener.poll(&mut workers) {
            Err(ListenerFailure::Bind { address: actual, error }) => {
                assert_eq!(actual, address);
                assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            }
            _ => panic!("the occupied fixture must return its actual bind failure"),
        }
        assert!(listener.next_bind_deadline().is_some());
        workers.cancellation_token().cancel();
        assert!(matches!(listener.poll(&mut workers), Ok(ListenerStep::Stopped)));
        drop(occupied);
    }

    #[test]
    fn listener_stops_while_lookup_worker_remains_owned() {
        use super::*;
        use std::sync::mpsc;
        let (mut listener, _) = fixture_transport_listener();
        let mut workers = ConnectionWorkers::default();
        assert!(matches!(listener.poll(&mut workers), Ok(ListenerStep::Idle)));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        workers.spawn(move |cancelled| {
            route_session::resolve_system_with(Instant::now() + Duration::from_secs(5), &cancelled, || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Err(io::Error::other("synthetic lookup"))
            }).map(|_| ConnectionSuccess::NoTransfer).map_err(ConnectionFailure::Open)
        }).unwrap();
        started_rx.recv().unwrap();
        workers.cancellation_token().cancel();
        assert!(matches!(listener.poll(&mut workers), Ok(ListenerStep::Stopped)));
        assert_eq!(workers.outstanding(), 1);
        assert!(workers.receive_finished().unwrap().is_empty());
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut results = workers.receive_finished().unwrap();
            if let Some(result) = results.pop() {
                assert!(matches!(result, Ok(Err(ConnectionFailure::Open(route_session::OpenFailure::ResolutionLate { cancelled: true, .. })) )));
                break;
            }
            assert!(Instant::now() < deadline);
            thread::park_timeout(PUMP_MAX_SLEEP);
        }
        assert!(!workers.has_unreceived());
    }

    #[test]
    fn worker_terminal_wakes_carrier_without_new_client() {
        use super::*;
        use std::sync::mpsc;
        let mut workers = ConnectionWorkers::default();
        workers.register_current_thread().unwrap();
        let (start_tx, start_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        workers.spawn(move |_| {
            start_tx.send(()).unwrap(); release_rx.recv().unwrap();
            Err(ConnectionFailure::Open(route_session::OpenFailure::Unavailable(None)))
        }).unwrap();
        start_rx.recv().unwrap();
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut results = workers.receive_finished().unwrap();
            if let Some(result) = results.pop() {
                assert!(matches!(result, Ok(Err(ConnectionFailure::Open(route_session::OpenFailure::Unavailable(None))))));
                break;
            }
            assert!(Instant::now() < deadline);
            thread::park_timeout(PUMP_MAX_SLEEP);
        }
        assert!(!workers.has_unreceived());
    }

    #[test]
    fn cancellation_wake_before_park_is_not_lost() {
        use super::*;
        let workers = ConnectionWorkers::default();
        workers.register_current_thread().unwrap();
        let token = workers.cancellation_token();
        let sender = thread::spawn(move || token.cancel());
        sender.join().unwrap();
        let before = Instant::now();
        thread::park_timeout(Duration::from_secs(2));
        assert!(before.elapsed() < Duration::from_secs(1), "pre-park notification was not received");
        assert!(workers.cancellation_token().is_cancelled());
    }
    #[test]
    fn protocol_probe_distinguishes_tcp_accept_from_actual_refusal() {
        use super::*;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let fake = thread::spawn(move || { let (_stream, _) = listener.accept().unwrap(); });
        assert!(protocol_answers_at(addr, Duration::from_secs(2)).is_err());
        fake.join().unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let actual = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve(stream, 0);
        });
        assert!(protocol_answers_at(addr, Duration::from_secs(2)).is_ok());
        actual.join().unwrap();
    }
    #[test]
    fn retained_worker_receives_cancelled_late_lookup_without_open() {
        use super::*;
        use std::sync::{atomic::{AtomicUsize, Ordering}, mpsc};
        for fail in [false, true] {
            let mut workers = ConnectionWorkers::default();
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let opened = Arc::new(AtomicUsize::new(0));
            let observed = opened.clone();
            workers.spawn(move |cancelled| {
                let result = route_session::resolve_system_with(Instant::now() + Duration::from_secs(5), &cancelled, || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    if fail { Err(io::Error::other("synthetic late lookup")) }
                    else { Ok(vec!["192.0.2.1:443".parse().unwrap()]) }
                });
                match result {
                    Ok(_) => { observed.fetch_add(1, Ordering::SeqCst); Ok(ConnectionSuccess::NoTransfer) }
                    Err(error) => Err(ConnectionFailure::Open(error)),
                }
            }).unwrap();
            started_rx.recv().unwrap();
            assert_eq!(workers.outstanding(), 1);
            workers.request_cancel();
            release_tx.send(()).unwrap();
            let until = Instant::now() + Duration::from_secs(5);
            let result = loop {
                let mut received = workers.receive_finished().unwrap();
                if let Some(value) = received.pop() { break value; }
                assert!(Instant::now() < until, "owned worker still pending");
                thread::yield_now();
            };
            assert_eq!(opened.load(Ordering::SeqCst), 0);
            if fail {
                assert!(matches!(result, Ok(Err(ConnectionFailure::Open(route_session::OpenFailure::ResolutionLate { cancelled: true, error }))) if error.to_string() == "synthetic late lookup"));
            } else {
                assert!(matches!(result, Ok(Err(ConnectionFailure::Open(route_session::OpenFailure::Cancelled)))));
            }
            assert!(!workers.has_unreceived());
        }
    }
    #[test]
    fn non_gate_tunnel_keeps_response_and_raw_bidirectional_bytes() {
        use super::*;
        use std::net::Shutdown;

        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        origin_listener.set_nonblocking(true).unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let client_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut peer = TcpStream::connect(client_listener.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(4))).unwrap();
        let (client, _) = client_listener.accept().unwrap();
        let server = thread::spawn(move || -> io::Result<Vec<u8>> {
            let deadline = Instant::now() + Duration::from_secs(4);
            let mut stream = loop {
                match origin_listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                    Err(e) => return Err(e),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(4)))?;
            stream.set_write_timeout(Some(Duration::from_secs(4)))?;
            let mut input = Vec::new();
            stream.read_to_end(&mut input)?;
            stream.write_all(b"answer")?;
            stream.shutdown(Shutdown::Write)?;
            Ok(input)
        });
        let proxy = match thread::Builder::new().spawn(move || tunnel(client, "127.0.0.1", origin_port, Instant::now() + TUNNEL_OPEN_BUDGET, &std::sync::atomic::AtomicBool::new(false))) {
            Ok(handle) => handle,
            Err(error) => { let _ = server.join(); panic!("proxy fixture spawn failed: {error}"); }
        };
        let mut response = vec![0; RESP_ESTABLISHED.len()];
        let header = peer.read_exact(&mut response);
        let sent = peer.write_all(b"request").and_then(|_| peer.shutdown(Shutdown::Write));
        let mut body = Vec::new();
        let read = peer.read_to_end(&mut body);
        let origin = server.join();
        let proxy = proxy.join();
        header.unwrap(); sent.unwrap(); read.unwrap();
        assert_eq!(response, RESP_ESTABLISHED);
        assert_eq!(body, b"answer");
        assert_eq!(origin.unwrap().unwrap(), b"request");
        assert!(matches!(proxy.unwrap(), Ok(ConnectionSuccess::Tcp(_))));
    }

    #[test]
    fn credential_gate_requires_both_host_and_port() {
        assert!(super::GateTarget443::new("cloudcode-pa.googleapis.com", 443).is_some());
        assert!(super::GateTarget443::new("cloudcode-pa.googleapis.com", 80).is_none());
        assert!(super::GateTarget443::new("example.com", 443).is_none());
    }

    #[test]
    fn connect_target_lazy_rewrite_oracle() {
        let host = "CLOUDCODE-PA.GOOGLEAPIS.COM.";
        let trace = std::cell::RefCell::new(Vec::new());
        let result = connect_target_with("127.0.0.1", host, || { trace.borrow_mut().push("active"); true }, |name| {
            assert_eq!(name, host);
            trace.borrow_mut().push("resolve");
            vec![std::net::Ipv4Addr::new(203, 0, 113, 9), std::net::Ipv4Addr::new(192, 0, 2, 1)]
        });
        assert_eq!(result, "203.0.113.9");
        assert_eq!(*trace.borrow(), ["active", "resolve"]);
        assert_eq!(connect_target_with("localhost", host, || true, |_| vec![]), host);
        assert_eq!(connect_target_with("localhost", "example.com", || panic!("active on non-gate"), |_| panic!("resolve on non-gate")), "example.com");
        assert_eq!(connect_target_with("localhost", host, || false, |_| panic!("resolve while inactive")), host);
        assert_eq!(connect_target_with("203.0.113.1", host, || true, |_| panic!("resolve for nonlocal proxy")), host);
    }
    #[test]
    fn marked_writer_counts_both_directions() {
        use super::*;

        let activity = routes::Activity::default();
        let mut written = Vec::new();
        Marked { inner: &mut written, activity: Some(&activity), to_client: true }.write_all(b"answer").unwrap();
        Marked { inner: &mut written, activity: Some(&activity), to_client: false }.write_all(b"ask").unwrap();
        assert_eq!(activity.bytes(), (6, 3));
        assert!(activity.idle().is_some());

    }
    use super::*;

    /// The listener check must answer about the socket, and a refused connection
    /// must read as "no listener".
    ///
    /// This is the gate in front of `HTTPS_PROXY` (G31, I53). The helper it
    /// replaces returned `true` when it could not parse its own URL, i.e. it
    /// reported a dead proxy as a live one - the exact direction of error that
    /// leaves a user-wide variable pointing at nothing.
    #[test]
    fn a_socket_nobody_holds_reads_as_no_listener() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral port");
        let addr = listener.local_addr().expect("addr");

        assert!(answers_at(addr), "a bound port must answer");
        assert!(
            wait_at(addr, Duration::from_secs(1)),
            "waiting on a bound port must return at once"
        );

        drop(listener);
        assert!(!answers_at(addr), "a closed port must not answer");
    }

    /// And it must keep looking for the whole budget rather than deciding on one
    /// probe: the port can be held for a few seconds by somebody's ephemeral
    /// socket while `bind_listener` retries it.
    #[test]
    fn waiting_for_a_listener_that_never_comes_costs_the_budget_and_says_no() {
        // Port 1, not an ephemeral one just released: the OS hands those out
        // again, and any other test in this process that binds a listener while
        // this one is waiting made it fail for a reason that has nothing to do
        // with what it tests. Nothing listens on tcpmux on Windows.
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));

        let budget = Duration::from_millis(600);
        let started = Instant::now();
        assert!(!wait_at(addr, budget));
        assert!(
            started.elapsed() >= budget,
            "gave up after {:?}, before the budget was spent",
            started.elapsed()
        );
    }

    /// A status line that lost its carriage returns is still valid Rust and
    /// still compiles - it just produces a response no HTTP client accepts.
    /// Written as raw byte values so no tool can normalise the test itself.
    #[test]
    fn status_lines_are_crlf_terminated() {
        for line in [RESP_ESTABLISHED, RESP_BAD_GATEWAY, RESP_NOT_ALLOWED] {
            assert_eq!(&line[line.len() - 4..], &[13u8, 10, 13, 10], "{:?}", line);
            assert!(!line[..line.len() - 4].contains(&10u8), "{:?}", line);
        }
    }

    /// A tunnel must not be closed by a budget that was only ever meant to bound
    /// the CONNECT handshake.
    ///
    /// The regression this pins: `upstream::open` left its ten-second reply budget
    /// on the socket it returned, `splice` handed that socket to `io::copy`, and a
    /// timeout reads as end-of-stream - so every tunnel through the user's own
    /// proxy or a built-in exit died at 10.3 s of silence. A pooling client
    /// reconnects on the failed reuse, which showed up as a long hang on
    /// "Authenticating" and 35 tunnels in 25 seconds in the log.
    ///
    /// Sixteen seconds of silence, comfortably past the old ten, then the tunnel
    /// is used - a live client would fail here, not at the handshake.
    ///
    ///     cargo test an_idle_tunnel_outlives_the_connect_budget -- --ignored --nocapture
    #[test]
    #[ignore = "holds a tunnel open for 16 s against a real route; needs a live network"]
    fn an_idle_tunnel_outlives_the_connect_budget() {
        use rustls::pki_types::ServerName;
        use rustls::ClientConnection;
        use std::net::TcpListener;

        const HOST: &str = "daily-cloudcode-pa.googleapis.com";
        const IDLE: Duration = Duration::from_secs(16);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accepted");
            serve(sock, 0);
        });

        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(
                format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes(),
            )
            .expect("sent CONNECT");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(client.read(&mut byte).expect("reply"), 1, "proxy hung up");
            head.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&head).contains(" 200"));

        let name = ServerName::try_from(HOST).expect("name");
        let mut tls = ClientConnection::new(probe_config(), name).expect("tls");
        let mut stream = rustls::Stream::new(&mut tls, &mut client);
        // Complete the handshake before going quiet, so the silence is measured on
        // an established tunnel - which is the state a pooled connection sits in.
        stream.flush().ok();

        thread::sleep(IDLE);

        stream
            .write_all(
                format!(
                    "GET /v1internal:probe HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("the tunnel was closed under an idle client");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).expect("no answer after idling");
        assert!(
            buf[..n].starts_with(b"HTTP/"),
            "not an HTTP answer: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
        println!(
            "tunnel survived {} s idle and still carried a request",
            IDLE.as_secs()
        );
    }

    #[test]
    fn reads_the_connect_target() {
        assert_eq!(
            parse_connect(
                "CONNECT jetski-webchannel.googleapis.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"
            ),
            Some(("jetski-webchannel.googleapis.com".to_string(), 443))
        );
        assert_eq!(
            parse_connect("connect example.com:8443 HTTP/1.1\r\n\r\n"),
            Some(("example.com".to_string(), 8443))
        );
        assert_eq!(
            parse_connect("CONNECT [::1]:443 HTTP/1.1\r\n\r\n"),
            Some(("::1".to_string(), 443))
        );
    }

    /// The bug the IDE actually hit. A client that opens a proxy socket and has
    /// not spoken yet must be closed in silence: answering it puts a status line
    /// where its CONNECT response belongs, and the client reports only "Proxy
    /// connection ended before receiving CONNECT response".
    #[test]
    fn a_socket_that_says_nothing_is_closed_without_an_answer() {
        use std::net::TcpListener;

        fn ask(send: Option<&'static [u8]>) -> Request {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            let writer = thread::spawn(move || {
                let mut c = TcpStream::connect(addr).unwrap();
                match send {
                    Some(bytes) => {
                        c.write_all(bytes).unwrap();
                        // Held open so the read cannot end on the socket closing
                        // instead of on the request being complete.
                        thread::sleep(Duration::from_millis(200));
                    }
                    None => drop(c),
                }
            });
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let got = read_connect(&mut sock);
            writer.join().ok();
            got
        }

        assert_eq!(ask(None), Request::Gone);
        assert_eq!(
            ask(Some(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
            Request::Malformed
        );
        assert_eq!(
            ask(Some(
                b"CONNECT a.googleapis.com:443 HTTP/1.1\r\nHost: a\r\n\r\n"
            )),
            Request::Connect("a.googleapis.com".to_string(), 443)
        );
    }

    /// Anything that is not a CONNECT is refused rather than guessed at.
    #[test]
    fn a_non_connect_request_is_refused() {
        assert_eq!(parse_connect("GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_connect("CONNECT nohost HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_connect("CONNECT :443 HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_connect(""), None);
    }

    #[test]
    fn a_proxy_on_this_machine_or_the_lan_is_local_and_a_public_one_is_not() {
        for h in [
            "127.0.0.1",
            "localhost",
            "192.168.1.10",
            "10.0.0.2",
            "[::1]",
            "mybox",
        ] {
            assert!(is_local_host(h), "{h}");
        }
        for h in ["proxy.example.com", "203.0.113.5", "8.8.8.8"] {
            assert!(!is_local_host(h), "{h}");
        }
        // Not a gate host, or no loopback door: the name, always.
        assert_eq!(connect_target("127.0.0.1", "example.com"), "example.com");
        if !crate::loopback::active() {
            assert_eq!(
                connect_target("127.0.0.1", "daily-cloudcode-pa.googleapis.com"),
                "daily-cloudcode-pa.googleapis.com"
            );
        }
    }

    #[test]
    fn the_proxy_url_is_loopback() {
        assert!(proxy_url().starts_with("http://127.0.0.1:"));
    }

    /// P26: a port another program listens on is left at once - no fifteen
    /// seconds of retries for a holder that will not leave - and the proxy
    /// takes the next one, which becomes the port everything names.
    /// Windows only: on Linux the proxy never moves (`another_port_helps`).
    #[cfg(windows)]
    #[test]
    #[ignore = "requires outer creator Job for command/reader settlement"]
    fn a_held_port_moves_the_proxy_to_the_next_one_at_once() {
        let holder = TcpListener::bind("127.0.0.1:0").unwrap();
        let held = holder.local_addr().unwrap().port();
        let free = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let started = Instant::now();
        let root = std::sync::Arc::new(crate::command_lifetime::CommandLifetime::default());
        let got = bind_from(&root, held, &[free]).expect("moved to the free port");
        assert_eq!(got.local_addr().unwrap().port(), free);
        assert_eq!(port(), free);
        assert!(proxy_url().ends_with(&format!(":{free}")));
        assert!(started.elapsed() < BIND_RETRY_WAIT, "retried a held port");
    }

    /// With nowhere to go the failure is reported, naming who holds the port.
    #[test]
    #[cfg_attr(windows, ignore = "requires outer creator Job for command/reader settlement")]
    fn a_held_port_with_nowhere_to_go_says_who_holds_it() {
        let holder = TcpListener::bind("127.0.0.1:0").unwrap();
        let held = holder.local_addr().unwrap().port();
        let root = std::sync::Arc::new(crate::command_lifetime::CommandLifetime::default());
        let b = bind_from(&root, held, &[]).err().expect("nothing to move to");
        assert_eq!(b.what, "proxy");
        if cfg!(windows) {
            assert_eq!(b.cause, "held");
        }
        assert!(b.addr.ends_with(&format!(":{held}")));
    }
}
