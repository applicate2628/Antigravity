//! The gate hosts, answered with a loopback address and carried from there.
//!
//! Until 2.14.0_1 the only way the route table ever saw a gate connection was
//! the private proxy variable (`AG_LS_PROXY`, S42) - and an environment
//! variable reaches a process only when it starts. A user who switched the
//! bypass on while Antigravity was open (the ordinary order: patch, launch,
//! then the 400, then this window) had a language server that never asked our
//! proxy for anything, so none of the adaptive part touched their traffic: it
//! dialled Google itself, from wherever the routing table sent it, and the
//! window described a proxy nobody used (G50).
//!
//! DNS reaches a running process on its very next lookup. So while this is up,
//! the relay answers each gate host with an address of its own here, and a
//! connection to it is carried by exactly the route table a `CONNECT` through
//! the proxy variable is: the client's connection never leaves the machine,
//! which also means no VPN can catch it (N25 from the client's side).
//!
//! No TLS is terminated (I27). Each host gets its own loopback address, so the
//! host is known from the address the client dialled and not one byte of its
//! handshake has to be read: the listener hands the socket to the local proxy
//! as a `CONNECT` and splices. The client's TLS goes to Google untouched, and its
//! certificate check is against Google's own certificate.
//!
//! If the listeners cannot be bound - something else holds one of the
//! addresses - the relay simply keeps answering with the substituted addresses
//! it always did.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// One loopback address per gate host. `127.65.71.x` - "A", "G" - to stay clear
/// of `127.0.0.1` and of the relay's own `127.0.0.53`.
pub const HOSTS: [(&str, Ipv4Addr); 2] = [
    ("cloudcode-pa.googleapis.com", Ipv4Addr::new(127, 65, 71, 1)),
    (
        "daily-cloudcode-pa.googleapis.com",
        Ipv4Addr::new(127, 65, 71, 2),
    ),
];

pub(crate) const PORT: u16 = 443;

/// How long a client's loopback answer may live in its cache. Short, because it
/// is also how long a client keeps dialling a dead listener if the relay stops:
/// after that Windows asks the rule's next nameserver and gets the substituted
/// address the old way.
pub const ANSWER_TTL: u32 = 30;

static BOUND: AtomicBool = AtomicBool::new(false);
#[cfg(windows)]
static ACTIVE_TRANSPORT: std::sync::OnceLock<crate::settings::ActiveTransportConfig> = std::sync::OnceLock::new();

/// The serving carrier supplies this once from its checked immutable config.
/// Legacy callers that have no new active config keep their existing behavior.
#[cfg(windows)]
pub(crate) fn receive_transport_config(config: crate::settings::ActiveTransportConfig) -> Result<(), String> {
    config.validate()?;
    if let Some(active) = ACTIVE_TRANSPORT.get() {
        if *active != config { return Err("DNS-alias transport changed within one carrier instance".into()); }
        return Ok(());
    }
    ACTIVE_TRANSPORT.set(config).map_err(|_| "DNS-alias transport was concurrently initialized".into())
}

fn alias_advertising_allowed(bound: bool, proxy_bound: bool, proxy_wanted: bool, dns_alias: Option<bool>) -> bool {
    dns_alias != Some(false) && bound && proxy_bound && proxy_wanted
}

/// Connections accepted here that have not had their `200` yet. A cap, not a
/// tuning knob: any loop that runs back through this door - a proxy or VPN
/// client resolving a gate host through the system resolver and dialling what
/// it got - shows up as this number climbing without bound, and the cap is what
/// breaks it. Ordinary use is a handful; the CLI opens about ten at once.
static OPENING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const MAX_OPENING: usize = 64;

/// The address a client should be given for `host`, when the listeners are up
/// and the local proxy is wanted. `None` means "answer the old way".
pub fn answer_for(host: &str) -> Option<Ipv4Addr> {
    if !active() {
        return None;
    }
    let host = host.trim_end_matches('.');
    HOSTS
        .iter()
        .find(|(h, _)| h.eq_ignore_ascii_case(host))
        .map(|(_, ip)| *ip)
}

/// Whether gate connections are being taken here right now.
///
/// Tied to the «Локальный прокси» switch: a user who turned the local proxy off
/// asked for Antigravity not to go through it, and this is the same proxy by a
/// different door.
pub fn active() -> bool {
    #[cfg(windows)]
    let active = ACTIVE_TRANSPORT.get();
    #[cfg(windows)]
    let dns_alias = active.map(|config| config.dns_alias);
    #[cfg(not(windows))]
    let dns_alias = None;
    #[cfg(windows)]
    let client_proxy = active.map(|config| config.client_proxy).unwrap_or_else(crate::settings::local_proxy_wanted);
    #[cfg(not(windows))]
    let client_proxy = crate::settings::local_proxy_wanted();
    alias_advertising_allowed(BOUND.load(Ordering::Relaxed), crate::proxy::bound(), client_proxy, dns_alias)
}

/// Binds every listener, then serves them until the process ends. While they
/// cannot be bound it says why (`gate::set_blocker`, the window turns it into
/// what to do - P53) and tries again every `proxy::REBIND_EVERY`, so the door
/// opens by itself once the user has closed the program on `:443` or added the
/// antivirus exception. Returns only if the listeners stop.
pub fn run(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> Result<(), String> {
    #[cfg(windows)]
    if ACTIVE_TRANSPORT.get().is_some_and(|config| !config.dns_alias) { return Ok(()); }
    let mut said: Option<crate::gate::Blocker> = None;
    let listeners = loop {
        root.receive();
        match bind_all(root) {
            Ok(listeners) => {
                if said.is_some() {
                    crate::dns_forwarder::log_proxy("локальные адреса гейт-хостов заняты");
                    crate::gate::set_blocker("door", None);
                }
                break listeners;
            }
            Err(blocker) => {
                if said.as_ref() != Some(&blocker) {
                    crate::dns_forwarder::log_proxy(&format!(
                        "локальные адреса гейт-хостов не заняты: не занять {}: {} ({}{})",
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
                crate::gate::set_blocker("door", Some(blocker));
                thread::sleep(crate::proxy::REBIND_EVERY);
            }
        }
    };
    BOUND.store(true, Ordering::Relaxed);
    let mut handles = Vec::new();
    for (host, listener) in listeners {
        handles.push(thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || hop(stream, host));
            }
        }));
    }
    for h in handles {
        h.join().ok();
    }
    BOUND.store(false, Ordering::Relaxed);
    Err("слушатели остановились".to_string())
}

#[cfg(windows)]
pub(crate) enum AliasFailure {
    Bind { address: SocketAddr, error: std::io::Error },
    Accept { address: SocketAddr, error: std::io::Error },
    Worker(std::io::Error),
}

#[cfg(windows)]
pub(crate) struct AliasListeners {
    listeners: Vec<(&'static str, TcpListener)>,
    next_bind: Instant,
    next_listener: usize,
    cancelled: std::sync::Arc<AtomicBool>,
    wake: thread::Thread,
    workers: Vec<thread::JoinHandle<std::io::Result<crate::proxy::SpliceOutcome>>>,
    completed: Vec<thread::Result<std::io::Result<crate::proxy::SpliceOutcome>>>,
    #[cfg(test)]
    fixture_opener: Option<std::sync::Arc<dyn Fn(&'static str, SocketAddr, &AtomicBool) -> std::io::Result<TcpStream> + Send + Sync>>,
}

#[cfg(windows)]
struct AliasWake(thread::Thread);
#[cfg(windows)]
impl Drop for AliasWake { fn drop(&mut self) { self.0.unpark(); } }

#[cfg(windows)]
impl AliasListeners {
    pub(crate) fn new(active: crate::settings::ActiveTransportConfig, cancelled: std::sync::Arc<AtomicBool>, wake: thread::Thread) -> Result<Self, String> {
        active.validate()?;
        if !active.dns_alias { return Err("alias owner requires a requested alias capability".into()); }
        Ok(Self { listeners: Vec::new(), next_bind: Instant::now(), next_listener: 0, cancelled, wake,
            workers: Vec::new(), completed: Vec::new(),
            #[cfg(test)] fixture_opener: None })
    }
    /// Test-only owned sockets and opener; never binds production alias ports.
    #[cfg(test)]
    pub(crate) fn fixture(listeners: Vec<(&'static str, TcpListener)>, cancelled: std::sync::Arc<AtomicBool>,
        wake: thread::Thread, opener: std::sync::Arc<dyn Fn(&'static str, SocketAddr, &AtomicBool) -> std::io::Result<TcpStream> + Send + Sync>) -> std::io::Result<Self> {
        if listeners.len() != HOSTS.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "fixture requires every alias listener")); }
        for (_, listener) in &listeners { listener.set_nonblocking(true)?; }
        Ok(Self { listeners, next_bind: Instant::now(), next_listener: 0, cancelled, wake,
            workers: Vec::new(), completed: Vec::new(), fixture_opener: Some(opener) })
    }
    pub(crate) fn bound(&self) -> bool { self.listeners.len() == HOSTS.len() }
    pub(crate) fn close_listeners(&mut self) {
        self.listeners.clear();
        BOUND.store(false, Ordering::Release);
    }
    pub(crate) fn next_bind_deadline(&self) -> Option<Instant> { (!self.bound()).then_some(self.next_bind) }
    pub(crate) fn poll(&mut self, upstream: Option<SocketAddr>) -> Result<crate::proxy::ListenerStep, AliasFailure> {
        if self.cancelled.load(Ordering::Acquire) { self.close_listeners(); return Ok(crate::proxy::ListenerStep::Stopped); }
        let Some(upstream) = upstream else { self.close_listeners(); return Ok(crate::proxy::ListenerStep::Idle); };
        if !self.bound() {
            if Instant::now() < self.next_bind { return Ok(crate::proxy::ListenerStep::Idle); }
            let mut listeners = Vec::with_capacity(HOSTS.len());
            for (host, ip) in HOSTS {
                let address = SocketAddr::from((ip, PORT));
                let listener = TcpListener::bind(address).and_then(|listener| { listener.set_nonblocking(true)?; Ok(listener) });
                match listener {
                    Ok(listener) => listeners.push((host, listener)),
                    Err(error) => { self.close_listeners(); self.next_bind = Instant::now() + crate::proxy::REBIND_EVERY;
                        return Err(AliasFailure::Bind { address, error }); }
                }
            }
            if self.cancelled.load(Ordering::Acquire) { return Ok(crate::proxy::ListenerStep::Stopped); }
            self.listeners = listeners;
            BOUND.store(true, Ordering::Release);
            return Ok(crate::proxy::ListenerStep::Progress);
        }
        for _ in 0..self.listeners.len() {
            let index = self.next_listener % self.listeners.len();
            self.next_listener = (index + 1) % self.listeners.len();
            let (host, listener) = &self.listeners[index];
            let address = match listener.local_addr() {
                Ok(address) => address,
                Err(error) => { self.close_listeners(); self.next_bind = Instant::now() + crate::proxy::REBIND_EVERY;
                    return Err(AliasFailure::Worker(error)); }
            };
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => continue,
                Err(error) => { self.close_listeners(); self.next_bind = Instant::now() + crate::proxy::REBIND_EVERY;
                    return Err(AliasFailure::Accept { address, error }); }
            };
            if self.cancelled.load(Ordering::Acquire) { self.close_listeners(); return Ok(crate::proxy::ListenerStep::Stopped); }
            if let Err(error) = stream.set_nonblocking(false) {
                self.close_listeners(); self.next_bind = Instant::now() + crate::proxy::REBIND_EVERY;
                return Err(AliasFailure::Worker(error));
            }
            if let Err(error) = self.workers.try_reserve(1) {
                self.close_listeners(); self.next_bind = Instant::now() + crate::proxy::REBIND_EVERY;
                return Err(AliasFailure::Worker(std::io::Error::other(error)));
            }
            let host = *host;
            let cancelled = self.cancelled.clone();
            let wake = self.wake.clone();
            #[cfg(test)]
            let fixture_opener = self.fixture_opener.clone();
            let handle = thread::Builder::new().spawn(move || {
                let _wake = AliasWake(wake);
                #[cfg(test)]
                let up = match fixture_opener { Some(open) => open(host, upstream, &cancelled)?, None => open_counted_hop(host, upstream, Some(&cancelled))? };
                #[cfg(not(test))]
                let up = open_counted_hop(host, upstream, Some(&cancelled))?;
                if cancelled.load(Ordering::Acquire) { return Err(std::io::ErrorKind::Interrupted.into()); }
                crate::proxy::splice_received(stream, up)
            });
            let handle = match handle {
                Ok(handle) => handle,
                Err(error) => { self.close_listeners(); self.next_bind = Instant::now() + crate::proxy::REBIND_EVERY;
                    return Err(AliasFailure::Worker(error)); }
            };
            self.workers.push(handle);
            return Ok(crate::proxy::ListenerStep::Progress);
        }
        Ok(crate::proxy::ListenerStep::Idle)
    }
    pub(crate) fn receive_finished(&mut self) -> Result<Vec<thread::Result<std::io::Result<crate::proxy::SpliceOutcome>>>, String> {
        self.completed.try_reserve(self.workers.len()).map_err(|error| error.to_string())?;
        let mut index = 0;
        while index < self.workers.len() {
            if self.workers[index].is_finished() { self.completed.push(self.workers.swap_remove(index).join()); }
            else { index += 1; }
        }
        Ok(std::mem::take(&mut self.completed))
    }
    pub(crate) fn has_unreceived(&self) -> bool { !self.workers.is_empty() || !self.completed.is_empty() }
}

#[cfg(windows)]
impl Drop for AliasListeners { fn drop(&mut self) { BOUND.store(false, Ordering::Release); } }

/// Every listener or none: a door open for one gate host and shut for the other
/// would send half of Antigravity's calls somewhere else.
fn bind_all(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>) -> Result<Vec<(&'static str, TcpListener)>, crate::gate::Blocker> {
    let mut listeners = Vec::with_capacity(HOSTS.len());
    for (host, ip) in HOSTS {
        listeners.push((host, bind(root, ip)?));
    }
    Ok(listeners)
}

/// A few tries, because a port held for a moment at logon frees itself.
fn bind(root: &std::sync::Arc<crate::command_lifetime::CommandLifetime>, ip: Ipv4Addr) -> Result<TcpListener, crate::gate::Blocker> {
    let addr = SocketAddr::from((ip, PORT));
    let mut last = None;
    for attempt in 0..3 {
        match TcpListener::bind(addr) {
            Ok(l) => return Ok(l),
            Err(e) => {
                last = Some(e);
                if attempt < 2 {
                    thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }
    let err = last.expect("three attempts were made");
    let cause = match root.call("loopback port diagnosis", |owner| crate::portcheck::diagnose(owner, addr, &err)) {
        Ok(Ok(cause)) => cause,
        Ok(Err(error)) | Err(error) => { crate::dns_forwarder::log_proxy(&format!("диагностика адреса недоступна: {error}")); crate::portcheck::Cause::Other }
    };
    Err(cause.blocker("door", addr, &err))
}

/// Longest the local proxy may take to pick a route and say `200`. Its routes
/// fail inside budgets of their own (4 s direct, 8 s relay), and walking all of
/// them in the worst case is what this has to cover.
const ROUTE_BUDGET: Duration = Duration::from_secs(30);

/// Carries one client connection: asks the local proxy for a tunnel to `host`,
/// then moves bytes. The client's first bytes - its TLS ClientHello - wait in
/// the socket buffer meanwhile and go through with everything else.
fn hop(client: TcpStream, host: &'static str) {
    let up = open_hop(host);
    if let Some(up) = up {
        crate::proxy::splice(client, up);
    }
}

/// Asks the local proxy for a tunnel to `host`; `None` when it refused.
fn open_hop(host: &'static str) -> Option<TcpStream> {
    open_counted_hop(host, crate::proxy::listen_addr(), None).ok()
}

fn open_counted_hop(host: &'static str, address: SocketAddr, cancelled: Option<&AtomicBool>) -> std::io::Result<TcpStream> {
    struct Opening;
    impl Drop for Opening { fn drop(&mut self) { OPENING.fetch_sub(1, Ordering::SeqCst); } }
    let previous = OPENING.fetch_add(1, Ordering::SeqCst);
    let _opening = Opening;
    if previous >= MAX_OPENING { return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "alias opening capacity reached")); }
    open_hop_at(host, address, cancelled)
}

fn open_hop_at(host: &'static str, address: SocketAddr, cancelled: Option<&AtomicBool>) -> std::io::Result<TcpStream> {
    let check = || if cancelled.is_some_and(|value| value.load(Ordering::Acquire)) {
        Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
    } else { Ok(()) };
    check()?;
    let mut up = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    up.set_read_timeout(Some(ROUTE_BUDGET))?;
    up.set_write_timeout(Some(ROUTE_BUDGET))?;
    check()?;
    up.write_all(
        format!("CONNECT {host}:{PORT} HTTP/1.1\r\nHost: {host}:{PORT}\r\n\r\n").as_bytes(),
    )?;
    let mut head = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 4096 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "local proxy reply header exceeds its existing limit"));
        }
        check()?;
        match up.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            Ok(_) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Err(error) => return Err(error),
        }
    }
    // Every route refused: closing the client's connection is the answer. It
    // retries, and its next connection is offered to the table again.
    check()?;
    if status_is_200(&head) { Ok(up) }
    else {
        let first = head.split(|byte| *byte == b'\n').next().unwrap_or_default();
        let status = String::from_utf8_lossy(first).split_whitespace().nth(1).and_then(|code| code.parse::<u16>().ok());
        Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, format!("local proxy refused the alias tunnel; status={status:?}")))
    }
}

fn status_is_200(head: &[u8]) -> bool {
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let text = String::from_utf8_lossy(line);
    text.split_whitespace().nth(1) == Some("200")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicitly_disabled_dns_alias_is_inert_even_with_ready_tcp() {
        assert!(!alias_advertising_allowed(true, true, true, Some(false)));
        assert!(alias_advertising_allowed(true, true, true, None));
        assert!(alias_advertising_allowed(true, true, true, Some(true)));
        assert!(!alias_advertising_allowed(true, true, false, Some(true)));
    }

    #[test]
    fn each_gate_host_has_its_own_loopback_address() {
        for (host, ip) in HOSTS {
            assert!(ip.is_loopback(), "{host}");
            assert!(
                crate::proxy::is_gate_host(host),
                "{host} is not a gate host"
            );
            assert_ne!(ip, Ipv4Addr::LOCALHOST);
            assert_ne!(ip, Ipv4Addr::new(127, 0, 0, 53), "the relay's own");
        }
        assert_ne!(HOSTS[0].1, HOSTS[1].1);
    }

    #[test]
    fn only_a_200_opens_the_tunnel() {
        assert!(status_is_200(
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        ));
        assert!(!status_is_200(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"));
        assert!(!status_is_200(b""));
        assert!(!status_is_200(b"garbage"));
    }

    /// Nothing is answered with a loopback address while the listeners are down,
    /// whatever the name: the relay must fall back to the old answer.
    #[test]
    fn no_listener_no_loopback_answer() {
        if !BOUND.load(Ordering::Relaxed) {
            assert_eq!(answer_for("daily-cloudcode-pa.googleapis.com"), None);
        }
        assert_eq!(answer_for("example.com"), None);
    }
}
