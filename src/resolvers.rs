use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::dns_client;
use rustls::pki_types::ServerName;
use rustls::ClientConnection;

/// A parent retains this work before its outer query/open/warm worker starts.
/// The receiver thread is supplied by that actual parent, not guessed here.
pub(crate) struct ResolverWork {
    state: Mutex<ResolverWorkState>,
    cancelled: ResolverCancellation,
    receiver: thread::Thread,
    #[cfg(test)]
    fixture: Option<Arc<ResolverFixture>>,
    #[cfg(test)]
    force_expired_after_attempt: bool,
    #[cfg(test)]
    legacy_settings: Option<crate::settings::Settings>,
    #[cfg(test)]
    legacy_input_observer: Option<Arc<dyn Fn(usize, &[u8], &DnsSourceWitness) + Send + Sync>>,
}

#[derive(Clone)]
struct ResolverCancellation { local: Arc<AtomicBool>, parent: Option<Arc<AtomicBool>> }
impl ResolverCancellation {
    fn is_cancelled(&self) -> bool { self.local.load(Ordering::Acquire) || self.parent.as_ref().is_some_and(|parent| parent.load(Ordering::Acquire)) }
}

#[cfg(test)]
struct ResolverFixture {
    provider: Arc<dyn Fn(usize, &[u8]) -> Option<Vec<u8>> + Send + Sync>,
    reference: Arc<dyn Fn(Ipv4Addr, &[u8]) -> Result<Vec<u8>, String> + Send + Sync>,
    liveness: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>,
    learning: Option<Arc<dyn Fn() + Send + Sync>>,
}

struct ResolverWorkState { closed: bool, entries: Vec<ResolverEntry> }
struct ResolverEntry { kind: ResolverChildKind, thread: Option<thread::ThreadId>, state: ResolverEntryState }
enum ResolverEntryState {
    Reserved,
    Running(Option<thread::JoinHandle<ResolverChildResult>>),
    Finished(Option<thread::Result<ResolverChildResult>>),
    StartFailed(Option<std::io::Error>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolverChildKind {
    Liveness(IpAddr), Provider(usize), Reference(Ipv4Addr), ControlProvider(usize), ControlReference(Ipv4Addr),
}

/// Packets/errors stay in private receiving state; no Debug transcript is exposed.
pub(crate) enum ResolverObservation {
    Reply(Vec<u8>), NoAnswer, Error(String), Reachable(bool), Cancelled,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolverDelivery { Sent, NoMessage, ReceiverGone, Cancelled }
pub(crate) struct ResolverChildResult {
    pub(crate) observation: ResolverObservation,
    pub(crate) delivery: ResolverDelivery,
    pub(crate) cancelled: bool,
}
pub(crate) enum ResolverTermination {
    StartFailed(std::io::Error),
    Finished(thread::Result<ResolverChildResult>),
}
pub(crate) struct ResolverTerminal {
    pub(crate) kind: ResolverChildKind,
    pub(crate) thread: Option<thread::ThreadId>,
    /// Owner cancellation sampled at transfer; not physical-completion proof.
    pub(crate) cancelled: bool,
    pub(crate) result: ResolverTermination,
}

struct ResolverWake(thread::Thread);
impl Drop for ResolverWake { fn drop(&mut self) { self.0.unpark(); } }

impl ResolverWork {
    pub(crate) fn new(receiver: thread::Thread) -> Self {
        Self::new_inner(receiver, None)
    }
    pub(crate) fn with_cancellation(receiver: thread::Thread, parent: Arc<AtomicBool>) -> Self {
        Self::new_inner(receiver, Some(parent))
    }
    fn new_inner(receiver: thread::Thread, parent: Option<Arc<AtomicBool>>) -> Self {
        Self { state: Mutex::new(ResolverWorkState { closed: false, entries: Vec::new() }),
            cancelled: ResolverCancellation { local: Arc::new(AtomicBool::new(false)), parent }, receiver,
            #[cfg(test)] fixture: None, #[cfg(test)] force_expired_after_attempt: false,
            #[cfg(test)] legacy_settings: None, #[cfg(test)] legacy_input_observer: None }
    }
    pub(crate) fn cancel(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        self.cancelled.local.store(true, Ordering::Release);
        drop(state);
        self.receiver.unpark();
    }
    pub(crate) fn is_cancelled(&self) -> bool { self.cancelled.is_cancelled() }
    /// Admit a short in-memory publication while serialized with `cancel`.
    /// The closure must not perform I/O or re-enter this `ResolverWork`. When it
    /// takes a routes-state lock, the order is work state then routes state.
    /// A separate parent cancellation flag is sampled at entry; only `cancel`
    /// itself is serialized with this guard.
    pub(crate) fn with_open<T>(&self, operation: impl FnOnce() -> T) -> Result<T, String> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed || self.is_cancelled() {
            return Err("resolver work admission is closed; launched children remain owned".into());
        }
        let result = operation();
        drop(state);
        Ok(result)
    }
    fn check_open(&self) -> Result<(), String> {
        if self.is_cancelled() { Err("resolver work cancelled; launched children remain owned".into()) } else { Ok(()) }
    }
    fn spawn(&self, kind: ResolverChildKind, operation: impl FnOnce(&ResolverCancellation) -> ResolverChildResult + Send + 'static) -> Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed || self.is_cancelled() { return Err("resolver work admission is closed; launched children remain owned".into()); }
        state.entries.try_reserve(1).map_err(|error| error.to_string())?;
        let index = state.entries.len();
        state.entries.push(ResolverEntry { kind, thread: None, state: ResolverEntryState::Reserved });
        let cancelled = self.cancelled.clone();
        let receiver = self.receiver.clone();
        let started = thread::Builder::new().spawn(move || {
            let _wake = ResolverWake(receiver);
            if cancelled.is_cancelled() {
                return ResolverChildResult { observation: ResolverObservation::Cancelled,
                    delivery: ResolverDelivery::Cancelled, cancelled: true };
            }
            let mut result = operation(&cancelled);
            result.cancelled = cancelled.is_cancelled();
            result
        });
        match started {
            Ok(handle) => {
                let id = handle.thread().id();
                state.entries[index].state = ResolverEntryState::Running(Some(handle));
                state.entries[index].thread = Some(id);
                Ok(())
            }
            Err(error) => {
                state.entries[index].state = ResolverEntryState::StartFailed(Some(error));
                Err("resolver child did not start; actual launch error retained".into())
            }
        }
    }
    /// Join only actual finished handles. Joined terminals remain owed here.
    pub(crate) fn poll_finished(&self) -> Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        for entry in &mut state.entries {
            if let ResolverEntryState::Running(handle) = &mut entry.state {
                if handle.as_ref().is_some_and(|handle| handle.is_finished()) {
                    let result = handle.take().expect("finished resolver handle").join();
                    entry.state = ResolverEntryState::Finished(Some(result));
                }
            }
        }
        Ok(())
    }
    /// Transfer terminals to the real parent's retained buffer before its
    /// fallible interpretation. Transfer alone is not semantic receiving.
    pub(crate) fn receive_finished(&self) -> Result<Vec<ResolverTerminal>, String> {
        let mut result = Vec::new();
        self.receive_into(&mut result)?;
        Ok(result)
    }
    /// Append directly into an already retained parent buffer. Capacity is
    /// reserved before any owned terminal leaves this work.
    pub(crate) fn receive_into(&self, result: &mut Vec<ResolverTerminal>) -> Result<(), String> {
        self.poll_finished()?;
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        result.try_reserve(state.entries.len()).map_err(|error| error.to_string())?;
        for entry in &mut state.entries {
            let terminal = match &mut entry.state {
                ResolverEntryState::Finished(value) => value.take().map(ResolverTermination::Finished),
                ResolverEntryState::StartFailed(value) => value.take().map(ResolverTermination::StartFailed),
                _ => None,
            };
            if let Some(terminal) = terminal {
                result.push(ResolverTerminal { kind: entry.kind, thread: entry.thread, cancelled: self.is_cancelled(), result: terminal });
            }
        }
        state.entries.retain(|entry| !matches!(entry.state, ResolverEntryState::Finished(None) | ResolverEntryState::StartFailed(None)));
        Ok(())
    }
    pub(crate) fn has_unreceived(&self) -> bool {
        !self.state.lock().unwrap_or_else(|error| error.into_inner()).entries.is_empty()
    }
}

fn check_resolver_work(work: Option<&ResolverWork>) -> Result<(), String> { work.map_or(Ok(()), ResolverWork::check_open) }

/// The legacy adapter intentionally keeps its old detached-thread behavior.
/// Explicit configured callers always supply an externally retained work.
fn launch_resolver(work: Option<&ResolverWork>, kind: ResolverChildKind,
    operation: impl FnOnce(&ResolverCancellation) -> ResolverChildResult + Send + 'static) -> Result<(), String> {
    if let Some(work) = work { return work.spawn(kind, operation); }
    thread::spawn(move || operation(&ResolverCancellation { local: Arc::new(AtomicBool::new(false)), parent: None }));
    Ok(())
}

fn deliver_resolver<T>(sender: &mpsc::Sender<T>, value: T, cancelled: &ResolverCancellation) -> ResolverDelivery {
    if cancelled.is_cancelled() { return ResolverDelivery::Cancelled; }
    match sender.send(value) { Ok(()) => ResolverDelivery::Sent, Err(_) => ResolverDelivery::ReceiverGone }
}

/// Receive the actual private terminal batch into its parent's current result.
/// Normal losing replies/no-answer/closed receivers are observations, not a
/// reason to revoke the already selected winner or authorize another route.
pub(crate) fn receive_terminals(terminals: &mut Vec<ResolverTerminal>, facts: &mut Vec<String>,
    panics: &mut Vec<Box<dyn std::any::Any + Send>>) -> Result<(), String> {
    let received = terminals.iter().map(|terminal| {
        let kind = match terminal.kind {
            ResolverChildKind::Liveness(_) => "liveness", ResolverChildKind::Provider(_) => "provider",
            ResolverChildKind::Reference(_) => "reference", ResolverChildKind::ControlProvider(_) => "control-provider",
            ResolverChildKind::ControlReference(_) => "control-reference",
        };
        let result = match &terminal.result {
            ResolverTermination::StartFailed(error) => format!("start={:?}/{:?}", error.kind(), error.raw_os_error()),
            ResolverTermination::Finished(Err(_)) => "unwound; original payload retained".into(),
            ResolverTermination::Finished(Ok(result)) => {
                let observation = match &result.observation {
                    ResolverObservation::Reply(reply) => format!("reply_bytes={}", reply.len()),
                    ResolverObservation::NoAnswer => "no answer".into(),
                    ResolverObservation::Error(error) => format!("error={error}"),
                    ResolverObservation::Reachable(value) => format!("reachable={value}"),
                    ResolverObservation::Cancelled => "cancelled before operation".into(),
                };
                let delivery = match result.delivery {
                    ResolverDelivery::Sent => "sent", ResolverDelivery::NoMessage => "no-message",
                    ResolverDelivery::ReceiverGone => "receiver-gone", ResolverDelivery::Cancelled => "cancelled",
                };
                format!("{observation}; delivery={delivery}; child_cancelled={}", result.cancelled)
            }
        };
        format!("resolver {kind}; thread={:?}; owner_cancelled={}; {result}", terminal.thread, terminal.cancelled)
    }).collect::<Vec<_>>();
    panics.try_reserve(terminals.len()).map_err(|error| error.to_string())?;
    *facts = received;
    for terminal in terminals.drain(..) {
        if let ResolverTermination::Finished(Err(payload)) = terminal.result { panics.push(payload); }
    }
    Ok(())
}

// Choosing an unblock resolver at query time instead of trusting one forever.
//
// Why this module exists: on 2026-08-24 xbox-dns.ru silently dropped
// `cloudcode-pa.googleapis.com` from the list of names it substitutes. Measured
// over a raw socket, it answers that name with the genuine Google address
// (172.217.x, TTL 300) while still substituting `generativelanguage` to its
// proxy (87.228.47.204, TTL 60). comss.one and geohide.ru had done the same.
// Nothing in the tool noticed: the relay forwarded, the NRPT rules applied, the
// answer arrived - it was simply not a substituted answer any more.
//
// A single hardcoded resolver cannot detect that, so the relay now asks every
// provider at once and, in parallel, a reference resolver that is known NOT to
// substitute anything. An answer equal to the reference is a passthrough, and
// the next provider is tried; an answer that differs is a real substitution.
// When a provider re-adds a name, or a new provider is added below, it starts
// being used with no code change and no release.

/// How a provider is reached.
///
/// The distinction is not cosmetic: `v4`/`v6` are also what an NRPT rule lists
/// as fallback nameservers (I5, I22), and Windows can only be pointed at a
/// plain resolver. A DoH endpoint answers no UDP query at all, so putting one
/// in a rule would hand a name a nameserver that never replies. That is
/// enforced structurally - a `Doh` provider carries **empty** `v4`/`v6`, so
/// `fallback_v4`, `all_v6` and `substituting_addrs` all skip it without needing
/// to know about transports - and asserted by `a_doh_provider_is_never_offered_
/// as_a_nameserver`.
pub enum Transport {
    /// Plain DNS on UDP:53, queried over a socket pinned to the ISP interface.
    Udp,
    /// DNS-over-HTTPS. Reachable only through the relay, never by Windows.
    Doh(&'static crate::doh::Endpoint),
    /// The user's own DNS server(s), captured from `settings.custom_dns` with
    /// the selected providers. Like a DoH provider it carries empty `v4`/`v6`:
    /// the addresses are not ours to put into an NRPT rule, only the relay asks.
    Custom,
}

/// The user's own DNS servers: IPv4 literals split on whitespace, commas and
/// semicolons. Loopback, unspecified and multicast addresses are dropped - the
/// relay itself listens on 127.0.0.53, and pointing it at itself would loop.
pub fn parse_custom_dns(text: &str) -> Vec<Ipv4Addr> {
    parse_custom_dns_input(text).0
}

/// A nonblank setting must supply at least one server and every token must be valid.
/// Repeated addresses are kept once, in first occurrence order.
pub(crate) fn parse_custom_dns_setting(text: &str) -> Option<Vec<Ipv4Addr>> {
    let (servers, all_valid) = parse_custom_dns_input(text);
    (all_valid && !servers.is_empty()).then_some(servers)
}

fn parse_custom_dns_input(text: &str) -> (Vec<Ipv4Addr>, bool) {
    let mut servers = Vec::new();
    let mut all_valid = true;
    for part in text
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|part| !part.is_empty())
    {
        match part.parse::<Ipv4Addr>() {
            Ok(ip) if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() => {
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
            _ => all_valid = false,
        }
    }
    (servers, all_valid)
}

/// One unblock service. Addresses are tried in order; the first that answers
/// speaks for the provider, so a dead front-end does not cost it the race.
pub struct Provider {
    pub name: &'static str,
    pub v4: &'static [&'static str],
    pub v6: &'static [&'static str],
    pub transport: Transport,
}

/// Services that substitute Google/AI endpoints for clients they geolocate to a
/// blocked region. All three were verified to answer over plain UDP:53 and to
/// front a real SNI proxy (see kb/dns.md); their lists differ and change
/// without notice, which is exactly why the choice is made per query.
/// The provider names, in pool order, for the window's per-provider switches.
///
/// Names only. The addresses stay where they are: a switch list is a new place
/// for them to be read out of, and what a user needs in order to turn one off is
/// the name they already see in the log line.
pub fn provider_names() -> Vec<&'static str> {
    PROVIDERS.iter().map(|p| p.name).collect()
}

fn provider_index(name: &str) -> Option<usize> {
    PROVIDERS.iter().position(|provider| provider.name.eq_ignore_ascii_case(name))
}

pub const PROVIDERS: &[Provider] = &[
    // First on purpose. Measured 2026-08-30 against 8.8.8.8: it substitutes
    // `cloudcode-pa.googleapis.com` for one of its own egress addresses (TTL 60),
    // and that address accepts the SNI and answers as Google's own frontend
    // (`Server: ESF`, valid certificate, TLS handshake 0.30 s).
    //
    // The address that measurement named was `186.246.45.126`, and it is written
    // out here no longer ON PURPOSE: the service deleted that egress and returned
    // the address to its hoster, and something else answers on it today (checked
    // 2026-09-12, G43). The substitution still works — the service just answers
    // with whichever egress it currently runs — so the FINDING holds and only the
    // number expired. Do not re-derive it from a stranger's host.
    // `cloudcode-pa` is the name a 22-resolver
    // sweep found **nobody** substituting (S9) - the whole reason the client used
    // to be pushed onto `daily-` instead (N15). It substitutes `daily-` and
    // `generativelanguage` from the same address, and correctly passes
    // `jetski-webchannel` through, so it is not a blanket rewriter.
    //
    // `v4`/`v6` are empty because it speaks **only** DoH over HTTP/2 - HTTP/1.1
    // gets a 505 and its two addresses answer nothing on UDP:53. See `Transport`
    // for why that emptiness is load-bearing rather than an omission.
    Provider {
        name: "dns-ai.ru",
        v4: &[],
        v6: &[],
        transport: Transport::Doh(&DNS_AI),
    },
    Provider {
        name: "comss.one",
        v4: &["83.220.169.155", "212.109.195.93", "195.133.25.16"],
        v6: &[],
        transport: Transport::Udp,
    },
    Provider {
        name: "geohide.ru",
        v4: &["45.155.204.190", "37.230.192.51"],
        v6: &["2a0c:9300:0:54::1"],
        transport: Transport::Udp,
    },
    // Last on purpose: the user's own server, empty until they type one in.
    Provider {
        name: "свой DNS",
        v4: &[],
        v6: &[],
        transport: Transport::Custom,
    },
    // xbox-dns.ru is not here any more (owner, 2.14.0_1). Measured over the ISP
    // link on 2026-09-18, both its resolvers answer both gate hosts with genuine
    // Google (`172.217.x`, the set 8.8.8.8 gives) and substitute only
    // `generativelanguage`, which is not ours to route (D18). It never won a race
    // for either name, so all it contributed was a third party seeing the query,
    // and a row in the window promising something it does not do. Its patcher
    // reaches the gate hosts through its credentialed CONNECT relay instead, and
    // that path is already a route of its own (`routes::Kind::Relay`).
];

/// Addresses are the three `dns.dns-ai.ru` resolves to, hardcoded so the relay can
/// reach it before anything else resolves. Safe because the certificate still has
/// to prove the name (`*.dns-ai.ru`, verified live), so a stale or poisoned
/// address fails the handshake instead of becoming a silent man-in-the-middle.
///
/// THESE GO STALE SILENTLY, AND ONE DID (G43). Until 2026-09-12 the first entry
/// was `217.60.10.20` — an address the service had deleted and handed back to its
/// hoster. It does not refuse the connection, it **blackholes** it, so every
/// query spent the whole `PER_ADDR_BUDGET` (2.5 s) on it before falling through
/// to the second address. Two consequences, both measured from a Russian line on
/// 2026-09-12: every uncached lookup of a gate host cost an extra 2.5 s, and
/// 100 % of our traffic landed on one of the service's two nodes — it ran at 48 %
/// of a core while its sibling sat at 15 %, because the certificate check meant a
/// dead address failed safely and therefore failed *quietly*.
///
/// Every entry below is live and was verified answering on `/dns-query` before
/// being written here. The third, `185.251.90.181`, replaced `94.232.43.149`
/// (msk1, nginx) on 2026-09-27 at the service's request - the old node is being
/// withdrawn; the new one answered `/dns-query` over h2 the same day. The walk spreads queries
/// evenly across all three - which is the point of listing a node at all (G43).
/// 2026-10-20: `192.144.59.14` (timeout) and `186.246.49.127` (refused) were
/// both dead, so two of every three walks paid the full `PER_ADDR_BUDGET` before
/// an answer - the slow "400 bypass" start. Replaced by the service's current
/// `194.87.196.13` and `45.151.102.219` (owner's list), both h2 with a valid
/// `*.dns-ai.ru` certificate in 0.22-0.26 s over the ISP link. Its IPv6 pair
/// (`2a00:b700:5::3:62`, `2a12:5940:d4ef::219`) is listed too, but unmeasured:
/// the dev machine has no working IPv6. `doh.rs` decides at runtime - an address
/// that fails sits out (30 s, doubling to 15 min) and is retried later, an IPv6
/// one with a 1.2 s slice - so a line without IPv6 pays that once per bench, not
/// per query (the G43 mistake), and a line with it uses it.
/// When re-checking (P14), check the ADDRESSES too, not only whether the
/// provider still substitutes: a hardcoded address is a measurement with an
/// expiry date.
pub static DNS_AI: crate::doh::Endpoint = crate::doh::Endpoint {
    host: "dns.dns-ai.ru",
    path: "/dns-query",
    addrs: &[
        "194.87.196.13",
        "45.151.102.219",
        "185.251.90.181",
        "2a00:b700:5::3:62",
        "2a12:5940:d4ef::219",
    ],
};

/// Resolvers used only to recognise an unsubstituted answer. They must be
/// services with no geo-unblocking of their own - that is the whole point of
/// the comparison - and are never used to answer the client.
pub const REFERENCE_V4: &[&str] = &["8.8.8.8", "1.1.1.1"];

/// Addresses the DPI on the ISP link injects instead of the real answer for
/// some names (measured: both 1.1.1.1 and 8.8.8.8 return this pair for
/// `example.com` and `chatgpt.com` over that link). A reference poisoned this
/// way would make every provider look like it substituted, so these are dropped
/// before the comparison and an all-stub reference counts as no reference.
const REFERENCE_STUBS: &[Ipv4Addr] = &[Ipv4Addr::new(8, 6, 112, 0), Ipv4Addr::new(8, 47, 69, 0)];

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

/// How long a decision is reused before the providers are raced again. Short
/// enough to pick up a list change within minutes, long enough that the routed
/// names - which Windows re-asks every 60 s, the substituted TTL - cost one
/// upstream query each rather than a fan-out to every provider.
const CHOICE_TTL: Duration = Duration::from_secs(5 * 60);

/// Budget for a full race. The Windows DNS client gives a nameserver about a
/// second before moving to the next one in the NRPT rule, and that fallback is
/// a direct provider query whose unsubstituted answer would then be cached for
/// its full TTL. Providers answer in 30-80 ms, so this is generous and still
/// well inside that window.
const RACE_BUDGET: Duration = Duration::from_millis(700);

/// Timeout for a single upstream query once a provider has been chosen.
const QUERY_TIMEOUT: Duration = Duration::from_secs(4);

/// Timeout for that same query when a client is waiting on it.
///
/// The full `QUERY_TIMEOUT` is right for a racer that nothing blocks on, and
/// wrong for the fast path: a provider that goes quiet - measured on geohide,
/// which drops whole query rounds - would hold the client for 4 s per address
/// while Windows, which waits about one, has long since asked the fallback
/// nameserver instead. A provider that has not answered in 250 ms has lost, and
/// the race that follows is budgeted, so the two together stay inside the
/// second.
const FAST_PATH_TIMEOUT: Duration = Duration::from_millis(250);

/// The floor a DoH provider gets on the fast path, in place of
/// `FAST_PATH_TIMEOUT`.
///
/// 250 ms is right for a UDP one-shot and impossible for DoH: the TLS handshake
/// alone measured 0.29 s, so the chosen provider would fail every time, be
/// forgotten, and re-race - the fast path turned into its own slow path. A full
/// DoH exchange measured ~0.35 s, and this still leaves most of the second
/// Windows waits before it asks the fallback nameserver (I23).
const DOH_FAST_TIMEOUT: Duration = Duration::from_millis(600);

/// How long a race will hold a decided answer waiting for the preferred
/// provider. Inside `RACE_BUDGET`, and sized by the same ~0.35 s measurement.
const PREFERRED_GRACE: Duration = Duration::from_millis(500);

/// Names worth waiting a moment longer for the preferred provider on: the two
/// hosts the gate actually lives on.
const PREFERRED_NAMES: &[&str] = &[
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
];

/// How long a vetted answer is handed straight back out of memory.
///
/// This is not about saving upstream queries. Windows gives the relay about a
/// second before it moves to the next nameserver in the NRPT rule, and that one
/// is a provider's own resolver, whose answer nothing has vetted: measured,
/// 2 cold resolutions of `daily-cloudcode-pa` in 6 fell through that way and
/// came back carrying geohide's black-holed `95.182.120.241`, which then cost
/// the client ~21 s on its first connection. An answer already in memory is
/// returned in microseconds, so the fall-through never happens.
///
/// Public because the relay's warm loop has to run inside it: the two together
/// are the guarantee, and a cadence longer than this window would leave gaps in
/// which a client query still pays for a cold resolution.
pub const ANSWER_TTL: Duration = Duration::from_secs(30);

/// How long a vetted answer is still better than nothing. While a provider is
/// quiet the alternative is not a fresher answer, it is the unvetted fallback -
/// so a substituted answer from minutes ago wins. Only substitutions are served
/// stale: prolonging a passthrough would keep the region gate shut for no gain,
/// and there the fallback (a measured substituter, I22) is the better degradation.
const ANSWER_STALE_TTL: Duration = Duration::from_secs(5 * 60);

/// An entry no client has asked for in this long is dropped, so the warm loop
/// stops refreshing a question shape nobody sends any more.
const ANSWER_IDLE: Duration = Duration::from_secs(10 * 60);

/// The longest a *non-substituted* answer may live in the client's cache.
///
/// A TTL is the resolver's opinion about its own answer, and these resolvers
/// disagree wildly: geohide substitutes `daily-cloudcode-pa` with TTL 60, while
/// comss returns the genuine Google address for the same name with TTL 3199.
/// Hand that second one to Windows unchanged and one lost race pins the client
/// to an unsubstituted address for 53 minutes - the relay is never asked again,
/// and every CloudCode call for that hour leaves from the blocked region and
/// answers `User location is not supported`. Measured exactly that way.
///
/// So an answer that did not defeat the gate is only ever believed until the
/// next race, and the warm loop is what runs that race.
const PASSTHROUGH_TTL: u32 = 60;

/// A vetted reply, exactly as it went out to the client.
struct Answer {
    reply: Vec<u8>,
    provider: &'static str,
    verdict: Verdict,
    /// When the reply arrived from upstream - what the TTLs are counted from.
    at: Instant,
    /// `ANSWER_TTL`, or the resolver's own TTL when that is shorter.
    good_for: Duration,
    /// Last time a *client* asked this exact question, as opposed to the warm
    /// loop refreshing it.
    wanted: Instant,
}

/// Vetted answers, keyed by the client's query with its transaction id zeroed.
///
/// Keyed by the whole query rather than by (name, qtype) on purpose: a reply is
/// only valid for the exact question that produced it - same flags, same EDNS
/// options, same spelling of the name - and reusing it for a differently shaped
/// question would mean rebuilding a message this module deliberately never
/// rebuilds. The cost is that an unusual client shape simply misses the cache.
static ANSWERS: Mutex<Option<HashMap<Vec<u8>, Answer>>> = Mutex::new(None);

/// Names every one of these services exists to unblock. Asking a provider for
/// one is how the relay learns what that provider's proxy address actually
/// looks like, instead of trying to recognise Google's netblocks - which span a
/// dozen unrelated /8s and change.
///
/// The answer is only believed when it differs from what the reference resolver
/// says for the same name, so a provider that stops proxying a control name
/// yields an empty set rather than teaching the relay that Cloudflare is a
/// proxy.
///
/// Several names, used in rotation, for two reasons. This source is public, so
/// a provider can read exactly what the relay asks and when: one fixed control
/// name is a crisp signature and a single point to special-case. And they are
/// deliberately spread across unrelated operators (Cloudflare, Anthropic,
/// Google), so no single upstream change takes the whole set out. All five were
/// measured proxied by all three providers.
///
/// Avoid `grok.com` here: the DPI on the ISP link answers it with the stub pair,
/// so the reference is unusable and nothing can be learned from it.
const CONTROL_NAMES: &[&str] = &[
    "chatgpt.com",
    "api.openai.com",
    "claude.ai",
    "gemini.google.com",
    "ai.google.dev",
];

/// How long learned proxy addresses are kept. Long, because they are stable and
/// the set is a union: geohide rotates between three addresses in three
/// unrelated /16s, so a single probe only ever sees part of it.
const PROXY_SET_TTL: Duration = Duration::from_secs(30 * 60);

/// Proxy addresses learned per provider, with the moment the entry was last
/// refreshed.
static PROXY_SET: Mutex<Option<HashMap<usize, ProxySet>>> = Mutex::new(None);

#[derive(Default)]
struct ProxySet {
    legacy: Option<(Vec<IpAddr>, Instant)>,
    witnessed: Vec<(IpAddr, DnsCandidateOrigin)>,
}

/// Effective inputs captured before a provider query. Never logged or serialized.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DnsSourceWitness {
    selected: Vec<usize>,
    custom: Vec<Ipv4Addr>,
    missing_defaults: bool,
    rotate: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsSourceError { Missing, Broken, Unavailable, StateUnavailable, Cancelled, Deadline, SourceTimeout, NoReference, NoAnswer, InvalidInput, InputChanged }

#[derive(Clone, Copy)]
pub(crate) enum DnsMissingPolicy { RequireSettings, LegacyDefaults }

#[derive(Clone)]
struct DnsCandidateOrigin {
    provider: usize,
    inputs: DnsSourceWitness,
    observed: Instant,
    expires: Instant,
    target: Option<String>,
}

#[derive(Clone)]
pub(crate) struct DnsCandidate {
    pub(crate) ip: Ipv4Addr,
    origins: Vec<DnsCandidateOrigin>,
}

#[cfg(test)]
pub(crate) fn test_source_witness() -> DnsSourceWitness {
    witness_from_read(crate::settings::Read::Parsed(crate::settings::Settings::default()), DnsMissingPolicy::RequireSettings)
        .expect("default synthetic settings")
}

#[cfg(test)]
pub(crate) fn test_source_witness_with_providers(names: &[&str], rotate: bool) -> DnsSourceWitness {
    assert!(!names.is_empty());
    assert!(names.iter().all(|name| PROVIDERS.iter().any(|provider| provider.name.eq_ignore_ascii_case(name))));
    let mut settings = crate::settings::Settings::default();
    settings.provider_order = names.iter().map(|name| (*name).to_owned()).collect();
    settings.disabled_providers = PROVIDERS.iter().filter(|provider|
        !names.iter().any(|name| provider.name.eq_ignore_ascii_case(name))).map(|provider| provider.name.to_owned()).collect();
    settings.rotate_providers = rotate;
    settings.custom_dns = "192.0.2.53".into();
    witness_from_read(crate::settings::Read::Parsed(settings), DnsMissingPolicy::RequireSettings).expect("synthetic settings")
}

#[cfg(test)]
pub(crate) fn test_source_candidate(ip: Ipv4Addr, witness: &DnsSourceWitness) -> DnsCandidate {
    let provider = *witness.selected.first().expect("synthetic witness needs an enabled provider");
    test_candidate_for_index(ip, witness, provider)
}

#[cfg(test)]
pub(crate) fn test_source_candidate_for_provider(ip: Ipv4Addr, witness: &DnsSourceWitness, provider: &str) -> DnsCandidate {
    let idx = provider_index(provider).expect("unknown synthetic provider");
    assert!(witness.selected.contains(&idx), "synthetic provider must be selected");
    test_candidate_for_index(ip, witness, idx)
}

#[cfg(test)]
fn test_candidate_for_index(ip: Ipv4Addr, witness: &DnsSourceWitness, provider: usize) -> DnsCandidate {
    let observed = Instant::now();
    DnsCandidate { ip, origins: vec![DnsCandidateOrigin { provider, inputs: witness.clone(), observed,
        expires: observed + PROXY_SET_TTL, target: None }] }
}

/// Missing defaults apply only to an already selected legacy/default provider.
pub(crate) fn current_witness(policy: DnsMissingPolicy) -> Result<DnsSourceWitness, DnsSourceError> {
    witness_from_read(crate::settings::read(), policy)
}

fn witness_from_read(read: crate::settings::Read, policy: DnsMissingPolicy) -> Result<DnsSourceWitness, DnsSourceError> {
    let (settings, missing_defaults) = match read {
        crate::settings::Read::Parsed(s) => (s, false),
        crate::settings::Read::Missing if matches!(policy, DnsMissingPolicy::LegacyDefaults) => (crate::settings::Settings::default(), true),
        crate::settings::Read::Missing => return Err(DnsSourceError::Missing),
        crate::settings::Read::Broken => return Err(DnsSourceError::Broken),
        crate::settings::Read::Unavailable => return Err(DnsSourceError::Unavailable),
    };
    Ok(witness_from_settings(&settings, missing_defaults))
}

fn witness_from_settings(settings: &crate::settings::Settings, missing_defaults: bool) -> DnsSourceWitness {
    let custom = parse_custom_dns(&settings.custom_dns);
    let mut selected: Vec<usize> = usable_providers(settings, !custom.is_empty())
        .filter_map(|p| provider_index(p.name))
        .collect();
    if !settings.rotate_providers { selected.truncate(1); }
    let custom = if selected.iter().any(|idx| matches!(&PROVIDERS[*idx].transport, Transport::Custom)) {
        custom
    } else { Vec::new() };
    DnsSourceWitness { selected, custom, missing_defaults, rotate: settings.rotate_providers }
}

fn legacy_inputs_for_work(work: Option<&ResolverWork>) -> DnsSourceWitness {
    #[cfg(test)]
    if let Some(settings) = work.and_then(|work| work.legacy_settings.as_ref()) {
        return witness_from_settings(settings, false);
    }
    let _ = work;
    witness_from_settings(&crate::settings::routing_snapshot(), false)
}

impl DnsCandidate {
    /// Preserve each origin and its own observation time when combining sources.
    pub(crate) fn merge(&mut self, other: Self) -> bool {
        if self.ip != other.ip { return false; }
        if self.origins.iter().filter_map(|origin| origin.target.as_ref()).any(|host|
            other.origins.iter().filter_map(|origin| origin.target.as_ref()).any(|other_host| other_host != host)) { return false; }
        let now = Instant::now();
        self.origins.retain(|origin| origin.expires > now);
        for origin in other.origins.into_iter().filter(|origin| origin.expires > now) {
            if let Some(existing) = self.origins.iter_mut().find(|existing|
                existing.provider == origin.provider && existing.inputs == origin.inputs && existing.target == origin.target) {
                if origin.expires > existing.expires { *existing = origin; }
            } else {
                self.origins.push(origin);
            }
        }
        true
    }
}

fn origin_is_current(origin: &DnsCandidateOrigin, witness: &DnsSourceWitness) -> bool {
    witness.selected.contains(&origin.provider)
        && origin.inputs == *witness
        && Instant::now() < origin.expires
}

pub(crate) fn source_is_current(candidate: &DnsCandidate, witness: &DnsSourceWitness) -> Result<bool, DnsSourceError> {
    Ok(candidate.origins.iter().any(|origin| origin_is_current(origin, witness)))
}

pub(crate) fn current_candidates(witness: &DnsSourceWitness) -> Result<Vec<DnsCandidate>, DnsSourceError> {
    let guard = PROXY_SET.lock().map_err(|_| DnsSourceError::StateUnavailable)?;
    Ok(candidates_from_sets(guard.as_ref(), witness))
}

/// The Mac relay's maintenance owner is the only producer of these witnessed
/// discovery inputs. A changed egress needs fresh discovery and qualification.
#[cfg(target_os = "macos")]
pub(crate) fn invalidate_witnessed_candidates() {
    if let Ok(mut guard) = PROXY_SET.lock() {
        if let Some(sets) = guard.as_mut() {
            for set in sets.values_mut() { set.witnessed.clear(); }
        }
    }
}

fn candidates_from_sets(map: Option<&HashMap<usize, ProxySet>>, witness: &DnsSourceWitness) -> Vec<DnsCandidate> {
    let mut out: Vec<DnsCandidate> = Vec::new();
    if let Some(map) = map {
        for idx in &witness.selected {
            if let Some(set) = map.get(idx) {
                for (address, origin) in &set.witnessed {
                    let IpAddr::V4(ip) = address else { continue; };
                    if !is_public_v4(*ip) || !origin_is_current(origin, witness) { continue; }
                    if let Some(candidate) = out.iter_mut().find(|candidate| candidate.ip == *ip) {
                        candidate.merge(DnsCandidate { ip: *ip, origins: vec![origin.clone()] });
                    } else {
                        out.push(DnsCandidate { ip: *ip, origins: vec![origin.clone()] });
                    }
                }
            }
        }
    }
    out
}

#[derive(Default)]
pub(crate) struct DnsDiscoveryCursor {
    inputs: Option<DnsSourceWitness>,
    host: String,
    pin: Option<u32>,
    control: Option<&'static str>,
    phase: DiscoveryPhase,
    position: usize,
    reference: Vec<IpAddr>,
    reference_until: Option<Instant>,
    resume_provider: usize,
    zero_ttl: bool,
}

#[derive(Clone, Copy, Default)]
enum DiscoveryPhase { #[default] Initial, ControlReference, ControlProviders, TargetReference, TargetProviders, Done }

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiscoveryState { Pending, Exhausted }

pub(crate) struct DiscoveryStep {
    pub(crate) candidates: Vec<DnsCandidate>,
    pub(crate) state: DiscoveryState,
}

fn discovery_check(deadline: Instant, work: Option<&ResolverWork>) -> Result<Duration, DnsSourceError> {
    if work.is_some_and(ResolverWork::is_cancelled) { return Err(DnsSourceError::Cancelled); }
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() { return Err(DnsSourceError::Deadline); }
    Ok(left)
}

fn discovery_after_attempt(deadline: Instant, work: Option<&ResolverWork>) -> Result<(), DnsSourceError> {
    if work.is_some_and(ResolverWork::is_cancelled) { return Err(DnsSourceError::Cancelled); }
    #[cfg(test)]
    if work.is_some_and(|work| work.force_expired_after_attempt) { return Err(DnsSourceError::SourceTimeout); }
    if Instant::now() >= deadline { return Err(DnsSourceError::SourceTimeout); }
    Ok(())
}

fn valid_discovery_host(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && host.is_ascii()
        && host.split('.').all(|label| !label.is_empty() && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-') && !label.ends_with('-'))
}

fn target_candidates(idx: usize, addrs: Vec<IpAddr>, reference: &[IpAddr], controls: &[DnsCandidate],
    host: &str, witness: &DnsSourceWitness, observed: Instant, ttl: Duration) -> Vec<DnsCandidate> {
    let proxy: Vec<IpAddr> = controls.iter().filter(|candidate|
        candidate.origins.iter().any(|origin| origin.provider == idx && origin.target.is_none() && origin_is_current(origin, witness)))
        .map(|candidate| IpAddr::V4(candidate.ip)).collect();
    addrs.into_iter().filter_map(|address| {
        let IpAddr::V4(ip) = address else { return None; };
        if !is_public_v4(ip) || proxy.is_empty() || classify(&[address], reference, &proxy) != Verdict::Substituted { return None; }
        let proof_expiry = controls.iter().filter(|candidate| block(&IpAddr::V4(candidate.ip)) == block(&address))
            .flat_map(|candidate| candidate.origins.iter())
            .filter(|origin| origin.provider == idx && origin.target.is_none() && origin_is_current(origin, witness))
            .map(|origin| origin.expires).max()?;
        let expires = observed.checked_add(ttl.min(PROXY_SET_TTL))?.min(proof_expiry);
        Some(DnsCandidate { ip, origins: vec![DnsCandidateOrigin { provider: idx, inputs: witness.clone(), observed, expires, target: Some(host.to_owned()) }] })
    }).collect()
}

/// One serial I/O step. The cursor owns no worker, socket, or persistent DNS cache.
pub(crate) fn discover_next(witness: &DnsSourceWitness, host: &str, cursor: &mut DnsDiscoveryCursor,
    pin: u32, budget: Duration, work: Option<&ResolverWork>) -> Result<DiscoveryStep, DnsSourceError> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !valid_discovery_host(&host) { return Err(DnsSourceError::InvalidInput); }
    let deadline = Instant::now().checked_add(budget).ok_or(DnsSourceError::InvalidInput)?;
    if let Some(existing) = cursor.inputs.as_ref() {
        if existing != witness || cursor.host != host || cursor.pin != Some(pin) { return Err(DnsSourceError::InputChanged); }
    } else {
        cursor.inputs = Some(witness.clone());
        cursor.host = host;
        cursor.pin = Some(pin);
        cursor.control = Some(CONTROL_NAMES[ROTATION.fetch_add(1, Ordering::Relaxed) % CONTROL_NAMES.len()]);
    }
    discovery_check(deadline, work)?;
    discover_step(witness, cursor, pin, deadline, work, false)
}

fn discover_step(witness: &DnsSourceWitness, cursor: &mut DnsDiscoveryCursor, pin: u32,
    deadline: Instant, work: Option<&ResolverWork>, paired: bool) -> Result<DiscoveryStep, DnsSourceError> {
    let pending = |candidates| DiscoveryStep { candidates, state: DiscoveryState::Pending };
    match cursor.phase {
        DiscoveryPhase::Initial => {
            cursor.phase = DiscoveryPhase::ControlReference;
            Ok(pending(current_candidates(witness)?))
        }
        DiscoveryPhase::ControlReference | DiscoveryPhase::TargetReference => {
            let control = matches!(cursor.phase, DiscoveryPhase::ControlReference);
            if cursor.position >= REFERENCE_V4.len() { return Err(DnsSourceError::NoReference); }
            let server = REFERENCE_V4[cursor.position].parse::<Ipv4Addr>().map_err(|_| DnsSourceError::InvalidInput)?;
            let name = if control { cursor.control.ok_or(DnsSourceError::InvalidInput)? } else { &cursor.host };
            let query = dns_client::build_query(name, ROTATION.fetch_add(1, Ordering::Relaxed) as u16);
            let timeout = discovery_check(deadline, work)?.min(QUERY_TIMEOUT);
            #[cfg(test)]
            let reply = work.and_then(|work| work.fixture.as_ref()).map(|fixture| (fixture.reference)(server, &query))
                .unwrap_or_else(|| dns_client::query_raw_via(&query, server, pin, timeout));
            #[cfg(not(test))]
            let reply = dns_client::query_raw_via(&query, server, pin, timeout);
            cursor.position += 1;
            discovery_after_attempt(deadline, work)?;
            let usable = reply.ok().and_then(|reply| {
                let ttl = dns_client::answer_ttl(&reply)?;
                Some((dns_client::answer_addrs(&reply), Duration::from_secs(ttl.into()).min(ANSWER_TTL)))
            });
            if let Some((usable, ttl)) = usable.filter(|(addresses, _)| addresses.iter().any(|address| matches!(address, IpAddr::V4(ip) if !REFERENCE_STUBS.contains(ip)))) {
                cursor.reference = usable;
                cursor.reference_until = if ttl.is_zero() { Some(deadline) } else { Instant::now().checked_add(ttl) };
                cursor.zero_ttl = ttl.is_zero();
                cursor.position = cursor.resume_provider;
                cursor.resume_provider = 0;
                cursor.phase = if control { DiscoveryPhase::ControlProviders } else { DiscoveryPhase::TargetProviders };
                discover_step(witness, cursor, pin, deadline, work, true)
            } else if cursor.position == REFERENCE_V4.len() {
                Err(DnsSourceError::NoReference)
            } else { Ok(pending(Vec::new())) }
        }
        DiscoveryPhase::ControlProviders | DiscoveryPhase::TargetProviders => {
            let control = matches!(cursor.phase, DiscoveryPhase::ControlProviders);
            let reference_until = cursor.reference_until.ok_or(DnsSourceError::NoReference)?;
            if !paired && Instant::now() >= reference_until {
                cursor.resume_provider = cursor.position;
                cursor.position = 0;
                cursor.reference.clear();
                cursor.reference_until = None;
                cursor.phase = if control { DiscoveryPhase::ControlReference } else { DiscoveryPhase::TargetReference };
                return Ok(pending(Vec::new()));
            }
            if cursor.position >= witness.selected.len() {
                cursor.position = 0;
                cursor.reference.clear();
                cursor.reference_until = None;
                cursor.phase = if control { DiscoveryPhase::TargetReference } else { DiscoveryPhase::Done };
                return Ok(DiscoveryStep { candidates: Vec::new(), state: if control { DiscoveryState::Pending } else { DiscoveryState::Exhausted } });
            }
            let idx = witness.selected[cursor.position];
            let name = if control { cursor.control.ok_or(DnsSourceError::InvalidInput)? } else { &cursor.host };
            let query = dns_client::build_query(name, ROTATION.fetch_add(1, Ordering::Relaxed) as u16);
            let io_deadline = deadline;
            let timeout = discovery_check(io_deadline, work)?.min(QUERY_TIMEOUT);
            let mut started = false;
            #[cfg(test)]
            let reply = work.and_then(|work| work.fixture.as_ref()).map(|fixture| { started = true; (fixture.provider)(idx, &query) })
                .unwrap_or_else(|| ask_provider_with_inputs(&PROVIDERS[idx], &query, pin, timeout, work.map(|work| &work.cancelled), Some(witness), Some(io_deadline), Some(&mut started)));
            #[cfg(not(test))]
            let reply = ask_provider_with_inputs(&PROVIDERS[idx], &query, pin, timeout, work.map(|work| &work.cancelled), Some(witness), Some(io_deadline), Some(&mut started));
            if !started { discovery_check(deadline, work)?; }
            cursor.position += 1;
            if cursor.zero_ttl {
                cursor.resume_provider = cursor.position;
                cursor.position = 0;
                cursor.reference_until = None;
                cursor.phase = if control { DiscoveryPhase::ControlReference } else { DiscoveryPhase::TargetReference };
                cursor.zero_ttl = false;
            }
            discovery_after_attempt(deadline, work)?;
            let reply = reply.ok_or(DnsSourceError::NoAnswer)?;
            let observed = Instant::now();
            let addrs = dns_client::answer_addrs(&reply);
            if control {
                if classify(&addrs, &cursor.reference, &[]) == Verdict::Substituted {
                    learn_witnessed_proxy_addrs(idx, &addrs, witness)?;
                    let candidates = current_candidates(witness)?.into_iter().filter(|candidate|
                        addrs.contains(&IpAddr::V4(candidate.ip)) && candidate.origins.iter().any(|origin| origin.provider == idx)).collect();
                    return Ok(pending(candidates));
                }
                return Ok(pending(Vec::new()));
            }
            let controls = current_candidates(witness)?;
            let ttl = dns_client::answer_ttl(&reply).ok_or(DnsSourceError::NoAnswer)?;
            let candidates = target_candidates(idx, addrs, &cursor.reference, &controls, &cursor.host, witness, observed, Duration::from_secs(ttl.into()));
            Ok(pending(candidates))
        }
        DiscoveryPhase::Done => Ok(DiscoveryStep { candidates: Vec::new(), state: DiscoveryState::Exhausted }),
    }
}

/// A substituted address is only useful if the client can actually open a TLS
/// connection to it, and that does not follow from answering DNS: geohide hands
/// out three proxy addresses for `daily-cloudcode-pa` and any of them may be
/// silently dropping SYNs on 443. Handing a dead one to the client costs ~20 s
/// on the first connection - Windows' SYN retransmission budget - before it
/// falls through to a live address. So substituted addresses are probed on the
/// port the client will use, and the dead ones are cut out of the answer.
const LIVENESS_PORT: u16 = 443;
/// Probed on the default route rather than the ISP interface: DNS has to dodge
/// the tunnel, but the client's own connection will not, so this must ask the
/// question the client is going to ask.
const LIVENESS_BUDGET: Duration = Duration::from_millis(500);
/// The same probe on the warm loop, where nothing is waiting on it.
///
/// 500 ms was chosen when a live proxy connected in ~35 ms. On a slower hour the
/// same addresses answered in 124-928 ms, so the tight budget started reporting
/// live-but-slow addresses as dead and cutting them out - the answer shrank from
/// three proxies to one, which is the opposite of the redundancy this is for.
/// Off the client's path there is no reason to be mean about it.
const LIVENESS_BUDGET_WARM: Duration = Duration::from_millis(2500);
/// How long "this address answered" is believed.
///
/// Was ten minutes, on the assumption that a working proxy keeps working. It
/// does not: measured three times inside one hour, geohide's three addresses
/// swapped which of them was dead each time - all three alive, then
/// `37.230.192.51` gone, then `45.155.204.190` gone. A ten-minute verdict meant
/// the relay kept advertising an address that had died nine minutes ago, which
/// is exactly the 20 s stall this whole probe exists to prevent (`State refresh
/// took 17697ms` in the language server's log). Short enough now that the warm
/// loop re-probes on almost every pass.
const LIVENESS_TTL_ALIVE: Duration = Duration::from_secs(20);
/// Short, so an address that comes back is used again within a minute or two
/// rather than being written off for the rest of the session.
const LIVENESS_TTL_DEAD: Duration = Duration::from_secs(60);

static LIVENESS: Mutex<Option<HashMap<IpAddr, (bool, Instant)>>> = Mutex::new(None);

/// Rotates which provider wins a tie, so equally good providers share the load
/// instead of the first entry serving everything.
static ROTATION: AtomicUsize = AtomicUsize::new(0);

/// Winning provider per (name, qtype), with the verdict that won it and the
/// moment it was decided. The verdict is remembered too, so a cache hit can
/// still tell a caller whether the answer it is about to use was substituted.
static CHOICE: Mutex<Option<HashMap<(String, u16), (usize, Verdict, Instant)>>> = Mutex::new(None);

/// Every provider's IPv6 addresses, in provider order. The NRPT rule takes
/// these only when the relay is off - with the relay up a v6 nameserver would
/// let Windows send the query straight out, skipping the relay entirely.
pub fn all_v6() -> Vec<&'static str> {
    let mut list: Vec<&'static str> = in_user_order()
        .into_iter()
        .filter(|p| !denied(p.name))
        .flat_map(|p| p.v6.iter().copied())
        .collect();
    if !crate::settings::rotation_enabled() {
        // Rotation off narrows the nameserver list too, or Windows would still
        // be pointed at providers the user took out of the pool.
        list.truncate(1);
    }
    list
}

/// One address per provider - what goes into an NRPT rule. Windows tries the
/// nameservers in order, so listing every address of one provider ahead of the
/// next provider would make a provider outage look like a total failure.
pub fn fallback_v4() -> Vec<&'static str> {
    // Filtered by the deny-list only, *then* truncated: the head of `PROVIDERS`
    // speaks DoH and carries no UDP address at all (I49), so narrowing by name
    // first would leave Windows a rule with no nameserver in it. Truncating the
    // assembled addresses picks the first enabled provider that actually has
    // one, which is what a nameserver list needs.
    // Windows tries nameservers in the order given, so the user's order is what
    // decides which service sees a lookup first.
    let mut list: Vec<&'static str> = in_user_order()
        .into_iter()
        .filter(|p| !denied(p.name))
        .filter_map(|p| p.v4.first().copied())
        .collect();
    if !crate::settings::rotation_enabled() {
        list.truncate(1);
    }
    list
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Outside every netblock the reference answered from - a proxy address.
    Substituted,
    /// A different address in the same netblock family. Google rotates its edge
    /// per query and per resolver, so this is almost always just another
    /// genuine Google address, not a substitution.
    Sibling,
    /// The same netblock the reference gave: a passthrough.
    Passthrough,
    /// No usable reference, or no addresses to compare.
    Unknown,
}

/// The netblock an address belongs to, coarse enough that Google's per-query
/// edge rotation does not look like a change: a /16 for IPv4, a /32 for IPv6.
fn block(addr: &IpAddr) -> (u8, u32) {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (4, u32::from_be_bytes([o[0], o[1], 0, 0]))
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            (6, u32::from_be_bytes([o[0], o[1], o[2], o[3]]))
        }
    }
}

/// Decides what a provider's answer is worth, given what an honest resolver
/// says for the same name (`reference`) and which addresses that provider is
/// known to hand out as its proxy (`proxy`, from `learn_proxy_addrs`).
///
/// Both inputs are needed, and this is the whole subtlety of the module.
/// Comparing against the reference alone marks `oauth2.googleapis.com` as
/// substituted whenever a provider's recursion lands on 173.194.0.0/16 while
/// the reference landed on 64.233.0.0/16 - both are plain Google, reached
/// through different edges. Nothing about the address itself separates those
/// two cases: Google's netblocks span a dozen unrelated /8s, and reverse DNS
/// does not help either (measured: 172.217.113.4, a perfectly genuine Google
/// answer, has no PTR at all, and neither does the geohide proxy). So the
/// proxy address is measured instead of guessed - see `learn_proxy_addrs`.
///
/// With no proxy knowledge yet, "differs from the honest answer" is the best
/// evidence available and is taken at face value. That is the behaviour the
/// tool had before, and it can only ever prefer a different answer to an
/// identical one - never a passthrough.
pub fn classify(candidate: &[IpAddr], reference: &[IpAddr], proxy: &[IpAddr]) -> Verdict {
    if candidate.is_empty() {
        return Verdict::Unknown;
    }
    let reference: Vec<&IpAddr> = reference
        .iter()
        .filter(|a| match a {
            IpAddr::V4(v4) => !REFERENCE_STUBS.contains(v4),
            IpAddr::V6(_) => true,
        })
        .collect();
    if reference.is_empty() {
        return Verdict::Unknown;
    }
    // Only compare within a family: an AAAA answer says nothing about the A
    // records the reference happened to return.
    let families: Vec<u8> = candidate.iter().map(|a| block(a).0).collect();
    let comparable: Vec<&&IpAddr> = reference
        .iter()
        .filter(|a| families.contains(&block(a).0))
        .collect();
    if comparable.is_empty() {
        return Verdict::Unknown;
    }

    let ref_blocks: Vec<(u8, u32)> = comparable.iter().map(|a| block(a)).collect();
    if candidate.iter().any(|a| ref_blocks.contains(&block(a))) {
        return Verdict::Passthrough;
    }
    if proxy.is_empty() {
        return Verdict::Substituted;
    }
    let proxy_blocks: Vec<(u8, u32)> = proxy.iter().map(block).collect();
    if candidate.iter().any(|a| proxy_blocks.contains(&block(a))) {
        return Verdict::Substituted;
    }
    Verdict::Sibling
}

/// How much a verdict is worth when picking a winner.
fn rank(v: Verdict) -> u8 {
    match v {
        Verdict::Substituted => 3,
        Verdict::Unknown => 2,
        Verdict::Sibling => 1,
        Verdict::Passthrough => 0,
    }
}

fn cached_liveness(addr: &IpAddr) -> Option<bool> {
    let guard = LIVENESS.lock().ok()?;
    let (alive, at) = guard.as_ref()?.get(addr)?;
    let ttl = if *alive {
        LIVENESS_TTL_ALIVE
    } else {
        LIVENESS_TTL_DEAD
    };
    (at.elapsed() < ttl).then_some(*alive)
}

/// How long a certificate check that passed is believed (once a day).
///
/// The chain and the name are verified against the public roots, always. Doing it
/// on every 20-second liveness probe costs a full handshake each time for an
/// answer that changes about as often as a provider rebuilds its proxy, so an
/// address that passed is only re-checked after this long; in between, the probe
/// is the connection alone. A failure is never remembered: it is retried at the
/// liveness cadence like any dead address.
const TLS_VERIFIED_FOR: Duration = Duration::from_secs(24 * 60 * 60);

static TLS_VERIFIED: Mutex<Option<HashMap<(IpAddr, String), Instant>>> = Mutex::new(None);

fn tls_verified_recently(addr: IpAddr, name: &str) -> bool {
    let Ok(guard) = TLS_VERIFIED.lock() else {
        return false;
    };
    guard
        .as_ref()
        .and_then(|m| m.get(&(addr, name.to_string())))
        .is_some_and(|at| at.elapsed() < TLS_VERIFIED_FOR)
}

fn remember_tls_verified(addr: IpAddr, name: &str) {
    if let Ok(mut guard) = TLS_VERIFIED.lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert((addr, name.to_string()), Instant::now());
    }
}

fn remember_liveness(addr: IpAddr, alive: bool) {
    // An address that stopped answering has to prove itself again when it comes
    // back: the day's trust was for the endpoint that was there, not for
    // whatever is listening after an outage.
    if !alive {
        if let Ok(mut guard) = TLS_VERIFIED.lock() {
            if let Some(m) = guard.as_mut() {
                m.retain(|(a, _), _| *a != addr);
            }
        }
    }
    if let Ok(mut guard) = LIVENESS.lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert(addr, (alive, Instant::now()));
    }
}

/// Whether `addr` will actually serve `sni` inside `budget`.
///
/// TCP alone is not the question the client asks. Measured within one minute on
/// one machine: one provider's proxy accepted TCP in 34 ms and then spent 10.5 s
/// on the TLS handshake, while another did the whole handshake in 249 ms. A
/// TCP-only probe calls both healthy and the client pays the difference.
///
/// With `sni` set the handshake is also the **security** check: rustls validates
/// the chain against the public roots and the name against the certificate, so
/// an address that fronts anything other than a genuine Google endpoint fails
/// here rather than in the client. That is why the three "could not even try"
/// paths below answer `false`: giving an unverifiable address the benefit of the
/// doubt is exactly the doubt the check exists to remove.
///
/// With no `sni` it falls back to the connection alone. A handshake that
/// verified is remembered for `TLS_VERIFIED_FOR`.
fn reachable(addr: IpAddr, budget: Duration, sni: Option<&str>) -> bool {
    let Ok(sock) =
        std::net::TcpStream::connect_timeout(&SocketAddr::new(addr, LIVENESS_PORT), budget)
    else {
        return false;
    };
    let Some(name) = sni else {
        return true;
    };
    if tls_verified_recently(addr, name) {
        return true;
    }
    let Ok(server) = ServerName::try_from(name.to_string()) else {
        return false;
    };
    let Ok(mut conn) = ClientConnection::new(crate::proxy::probe_config(), server) else {
        return false;
    };
    sock.set_read_timeout(Some(budget)).ok();
    sock.set_write_timeout(Some(budget)).ok();
    let mut sock = sock;
    let deadline = Instant::now() + budget;
    // Driven by hand rather than through `Stream`, so the budget covers the whole
    // handshake and not each syscall inside it.
    while conn.is_handshaking() {
        if Instant::now() >= deadline {
            return false;
        }
        if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
            return false;
        }
        if conn.wants_read() {
            match conn.read_tls(&mut sock) {
                Ok(0) => return false,
                Ok(_) => {
                    if conn.process_new_packets().is_err() {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
    }
    remember_tls_verified(addr, name);
    true
}

/// The addresses among `addrs` that will not accept a connection.
///
/// A live proxy completes the handshake in tens of milliseconds; a black hole
/// never answers at all, so the budget separates them without waiting out the
/// operating system's own retransmission schedule. Unknown-because-slow counts
/// as dead only for `LIVENESS_TTL_DEAD`, which is short on purpose.
///
/// `fresh` ignores what is already known and re-probes. The warm loop passes it
/// and a client query never does: the probe costs up to `LIVENESS_BUDGET`, which
/// is affordable on a timer and not while Windows is counting to one. It is what
/// keeps the cached verdict from outliving the thing it describes.
fn dead_addrs(addrs: &[IpAddr], fresh: bool, sni: Option<&str>) -> Vec<IpAddr> {
    dead_addrs_with_work(addrs, fresh, sni, None).expect("legacy liveness launch behavior")
}

fn dead_addrs_with_work(addrs: &[IpAddr], fresh: bool, sni: Option<&str>, work: Option<&ResolverWork>) -> Result<Vec<IpAddr>, String> {
    check_resolver_work(work)?;
    let mut dead = Vec::new();
    let mut unknown = Vec::new();
    for a in addrs {
        match if fresh { None } else { cached_liveness(a) } {
            Some(true) => {}
            Some(false) => dead.push(*a),
            None => unknown.push(*a),
        }
    }
    if unknown.is_empty() {
        return Ok(dead);
    }

    // Generous when the warm loop is asking, tight when a client is waiting.
    let budget = if fresh {
        LIVENESS_BUDGET_WARM
    } else {
        LIVENESS_BUDGET
    };

    let (tx, rx) = mpsc::channel::<(IpAddr, bool)>();
    for a in &unknown {
        let tx = tx.clone();
        let addr = *a;
        let sni = sni.map(|s| s.to_string());
        #[cfg(test)]
        let fixture = work.and_then(|work| work.fixture.clone());
        launch_resolver(work, ResolverChildKind::Liveness(addr), move |cancelled| {
            #[cfg(test)]
            let ok = fixture.as_ref().map(|fixture| (fixture.liveness)(addr)).unwrap_or_else(|| reachable(addr, budget, sni.as_deref()));
            #[cfg(not(test))]
            let ok = reachable(addr, budget, sni.as_deref());
            let delivery = deliver_resolver(&tx, (addr, ok), cancelled);
            ResolverChildResult { observation: ResolverObservation::Reachable(ok), delivery, cancelled: false }
        })?;
    }
    drop(tx);

    let deadline = Instant::now() + budget;
    let mut answered: Vec<IpAddr> = Vec::new();
    while answered.len() < unknown.len() {
        check_resolver_work(work)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok((addr, alive)) => {
                check_resolver_work(work)?;
                answered.push(addr);
                remember_liveness(addr, alive);
                if !alive {
                    dead.push(addr);
                }
            }
            Err(_) => break,
        }
    }
    // Whatever did not answer inside the budget is treated as dead for now. It
    // is not written off: the next query re-probes it after LIVENESS_TTL_DEAD.
    //
    // Tracked in a list rather than read back out of the cache: on the `fresh`
    // path the cache is exactly what is being distrusted, and a stale "alive"
    // sitting there would mask a probe that never came back - which is the bug
    // this whole parameter exists to fix.
    for a in unknown {
        check_resolver_work(work)?;
        if !answered.contains(&a) {
            remember_liveness(a, false);
            dead.push(a);
        }
    }
    check_resolver_work(work)?;
    Ok(dead)
}

/// Cuts unreachable addresses out of a substituted answer.
///
/// Only substituted answers are filtered. A passthrough is Google's own edge
/// and needs no vetting, and probing it would put a TCP connection on every
/// name the relay ever sees for nothing.
fn drop_dead_addrs(reply: Vec<u8>, fresh: bool, sni: Option<&str>) -> Vec<u8> {
    drop_dead_addrs_with_work(reply, fresh, sni, None).expect("legacy liveness launch behavior")
}

fn drop_dead_addrs_with_work(reply: Vec<u8>, fresh: bool, sni: Option<&str>, work: Option<&ResolverWork>) -> Result<Vec<u8>, String> {
    check_resolver_work(work)?;
    let addrs = dns_client::answer_addrs(&reply);
    if addrs.len() < 2 {
        // With a single address there is nothing to fall through to, so
        // removing it would turn a slow answer into no answer.
        return Ok(reply);
    }
    let dead = dead_addrs_with_work(&addrs, fresh, sni, work)?;
    if dead.is_empty() {
        return Ok(reply);
    }
    Ok(dns_client::without_addrs(&reply, &dead).unwrap_or(reply))
}

/// What is currently known about a provider's proxy addresses.
fn known_proxy_addrs(idx: usize) -> Vec<IpAddr> {
    let Ok(guard) = PROXY_SET.lock() else {
        return Vec::new();
    };
    guard
        .as_ref()
        .and_then(|m| m.get(&idx)).and_then(|set| set.legacy.as_ref())
        .filter(|(_, at)| at.elapsed() < PROXY_SET_TTL)
        .map(|(addrs, _)| addrs.clone())
        .unwrap_or_default()
}

/// True when a provider's proxy addresses need probing again.
fn proxy_addrs_are_stale(idx: usize) -> bool {
    let Ok(guard) = PROXY_SET.lock() else {
        return false;
    };
    guard
        .as_ref()
        .and_then(|m| m.get(&idx)).and_then(|set| set.legacy.as_ref())
        .map_or(true, |(_, at)| at.elapsed() >= PROXY_SET_TTL)
}

/// Unions freshly seen proxy addresses into what is already known.
///
/// A union rather than a replacement: a provider that rotates between several
/// proxy addresses would otherwise look like it changed its proxy on every
/// probe, and an answer served from the address the last probe missed would be
/// classified as somebody else's.
fn learn_proxy_addrs(idx: usize, addrs: Vec<IpAddr>) {
    if addrs.is_empty() {
        return;
    }
    if let Ok(mut guard) = PROXY_SET.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        let entry = map.entry(idx).or_default().legacy
            .get_or_insert_with(|| (Vec::new(), Instant::now()));
        for a in addrs {
            if !entry.0.contains(&a) {
                entry.0.push(a);
            }
        }
        entry.1 = Instant::now();
    }
}

fn learn_witnessed_proxy_addrs(idx: usize, addrs: &[IpAddr], witness: &DnsSourceWitness) -> Result<(), DnsSourceError> {
    if !witness.selected.contains(&idx) || addrs.is_empty() { return Ok(()); }
    {
        let mut guard = PROXY_SET.lock().map_err(|_| DnsSourceError::StateUnavailable)?;
        let set = guard.get_or_insert_with(HashMap::new).entry(idx).or_default();
        let now = Instant::now();
        set.witnessed.retain(|(_, origin)| origin.expires > now);
        for &address in addrs {
            if let Some((_, origin)) = set.witnessed.iter_mut().find(|(old, origin)| *old == address && origin.inputs == *witness) {
                origin.observed = now;
                origin.expires = now + PROXY_SET_TTL;
            } else {
                set.witnessed.push((address, DnsCandidateOrigin { provider: idx, inputs: witness.clone(), observed: now, expires: now + PROXY_SET_TTL, target: None }));
            }
        }
    }
    Ok(())
}

fn cached_choice(key: &(String, u16)) -> Option<(usize, Verdict)> {
    let guard = CHOICE.lock().ok()?;
    let map = guard.as_ref()?;
    let (idx, verdict, at) = map.get(key)?;
    (at.elapsed() < CHOICE_TTL).then_some((*idx, *verdict))
}

fn remember_choice(key: (String, u16), idx: usize, verdict: Verdict) {
    if let Ok(mut guard) = CHOICE.lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert(key, (idx, verdict, Instant::now()));
    }
}

fn forget_choice(key: &(String, u16)) {
    if let Ok(mut guard) = CHOICE.lock() {
        if let Some(map) = guard.as_mut() {
            map.remove(key);
        }
    }
}

/// A query with its transaction id blanked, which is the only part of it that
/// changes between two askings of the same question.
fn answer_key(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut key = query.to_vec();
    key[0] = 0;
    key[1] = 0;
    Some(key)
}

/// A cached answer for `query`, re-stamped so it is a valid reply to *this*
/// asking: the client's transaction id, and TTLs counted down by however long
/// the reply has been sitting here.
fn cached_answer(
    query: &[u8],
    stale: bool,
    from_client: bool,
) -> Option<(Vec<u8>, &'static str, Verdict)> {
    let key = answer_key(query)?;
    let mut guard = ANSWERS.lock().ok()?;
    let hit = guard.as_mut()?.get_mut(&key)?;
    let age = hit.at.elapsed();
    let usable = if stale {
        hit.verdict == Verdict::Substituted && age < ANSWER_STALE_TTL
    } else {
        age < hit.good_for
    };
    if !usable {
        return None;
    }
    if from_client {
        hit.wanted = Instant::now();
    }
    let mut reply = dns_client::age_reply(&hit.reply, age.as_secs() as u32)?;
    reply[0..2].copy_from_slice(&query[0..2]);
    Some((reply, hit.provider, hit.verdict))
}

/// Stores what went out to the client, so the next asking costs nothing.
///
/// Only replies whose records can be walked are kept: a message this cannot age
/// is one it must not hand out later with a stale TTL, and refusing it here
/// keeps the serving path free of that decision.
fn remember_answer(
    query: &[u8],
    reply: &[u8],
    provider: &'static str,
    verdict: Verdict,
    from_client: bool,
) {
    let (Some(key), Some(ttl)) = (answer_key(query), dns_client::answer_ttl(reply)) else {
        return;
    };
    let Ok(mut guard) = ANSWERS.lock() else {
        return;
    };
    let map = guard.get_or_insert_with(HashMap::new);
    // A substitution still inside its stale window outranks a fresh answer that
    // is not one. Overwriting it would throw away the entry `prefer_substituted`
    // exists to serve, and one lost race would again become an hour of them.
    if verdict != Verdict::Substituted {
        if let Some(prev) = map.get(&key) {
            if prev.verdict == Verdict::Substituted && prev.at.elapsed() < ANSWER_STALE_TTL {
                return;
            }
        }
    }
    let now = Instant::now();
    // Read before the sweep below, or an entry evicted mid-refresh would come
    // back looking freshly wanted and never age out again.
    let wanted = match map.get(&key) {
        Some(prev) if !from_client => prev.wanted,
        _ => now,
    };
    map.insert(
        key,
        Answer {
            reply: reply.to_vec(),
            provider,
            verdict,
            at: now,
            good_for: ANSWER_TTL.min(Duration::from_secs(ttl.into())),
            wanted,
        },
    );
    map.retain(|_, a| a.wanted.elapsed() < ANSWER_IDLE);
}

/// The questions the warm loop should re-ask: every shape a client has actually
/// sent for one of `names`, and a plain A query for any name not yet seen.
///
/// Replaying the client's own bytes is what makes warming work at all - a
/// synthesised query is a different key, so its answer would sit in the cache
/// while every real query still went upstream.
fn warm_queries(names: &[&str]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut covered: Vec<String> = Vec::new();
    if let Ok(guard) = ANSWERS.lock() {
        if let Some(map) = guard.as_ref() {
            for key in map.keys() {
                let Some(name) = dns_client::question_name(key) else {
                    continue;
                };
                if names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                    covered.push(name);
                    out.push(key.clone());
                }
            }
        }
    }
    for n in names {
        if !covered.iter().any(|c| c.eq_ignore_ascii_case(n)) {
            out.push(dns_client::build_query(n, 0));
        }
    }
    out
}

/// Re-resolves the routed names off the client's critical path, so a query that
/// does arrive is answered out of memory instead of racing three providers and
/// probing addresses while Windows counts to one.
pub fn warm(names: &[&str], if_index: u32) {
    warm_with_work(names, if_index, None).expect("legacy resolver launch behavior")
}

pub(crate) fn warm_owned(names: &[&str], if_index: u32, work: &ResolverWork) -> Result<(), String> {
    warm_with_work(names, if_index, Some(work))
}

fn warm_with_work(names: &[&str], if_index: u32, work: Option<&ResolverWork>) -> Result<(), String> {
    check_resolver_work(work)?;
    let inputs = legacy_inputs_for_work(work);
    ensure_proxy_sets_learned_with_inputs(if_index, work, &inputs)?;
    for mut query in warm_queries(names) {
        check_resolver_work(work)?;
        let id = ROTATION.fetch_add(1, Ordering::Relaxed) as u16;
        query[0..2].copy_from_slice(&id.to_be_bytes());
        let hit = resolve_upstream_with_inputs(&query, if_index, false, work, &inputs)?;
        check_resolver_work(work)?;
        note_served_a(&query, &hit);
    }
    check_resolver_work(work)
}

fn usable_providers(settings: &crate::settings::Settings, custom_usable: bool) -> impl Iterator<Item = &'static Provider> + '_ {
    in_order(&settings.provider_order).into_iter().filter(move |p| {
        settings.provider_enabled(p.name) && (custom_usable || !matches!(&p.transport, Transport::Custom))
    })
}

/// The provider that would answer with rotation disabled. An empty Custom slot
/// keeps its saved position and switch but has no address to ask.
pub(crate) fn first_usable_provider(settings: &crate::settings::Settings) -> Option<&'static str> {
    usable_providers(settings, !parse_custom_dns(&settings.custom_dns).is_empty())
        .next()
        .map(|p| p.name)
}

/// The pool laid out the way the user arranged it.
///
/// The compiled order is by measured substitution and is the default; a user who
/// dragged the list into a different order gets theirs. Anything they never
/// touched keeps its compiled position at the end, so a provider added in a later
/// release still appears instead of being silently dropped by a saved order that
/// predates it.
/// The owner's own service leads the pool by default (owner, 2.15.0): it is the
/// one resolver that substitutes *both* gate names, over DoH, and it is his to
/// run. It is shown in the provider list with its own switch, so this is a
/// disclosed default, not a lock: a user can turn it off, and if they place it
/// somewhere themselves in `provider_order`, that explicit choice is kept. Only
/// when they have NOT placed it — the common case, and every fresh install — is
/// it pulled to the front, so `dns-ai` leads without silently overriding a
/// deliberate reorder.
const LEAD_PROVIDER: &str = "dns-ai.ru";

fn in_user_order() -> Vec<&'static Provider> {
    let wanted = crate::settings::provider_order_cached();
    in_order(&wanted)
}

fn in_order(wanted: &[String]) -> Vec<&'static Provider> {
    let mut out: Vec<&'static Provider> = Vec::new();
    // Lead with the owner's service unless the user placed it themselves.
    let user_placed_lead = wanted.iter().any(|n| n.eq_ignore_ascii_case(LEAD_PROVIDER));
    if !user_placed_lead {
        if let Some(p) = PROVIDERS.iter().find(|p| p.name == LEAD_PROVIDER) {
            out.push(p);
        }
    }
    for name in wanted {
        if let Some(p) = PROVIDERS.iter().find(|p| p.name.eq_ignore_ascii_case(name)) {
            if !out.iter().any(|q| q.name == p.name) {
                out.push(p);
            }
        }
    }
    // Anything not named in the saved order keeps its compiled position after the
    // listed ones, so a provider added in a later release is never dropped.
    for p in PROVIDERS {
        if !out.iter().any(|q| q.name == p.name) {
            out.push(p);
        }
    }
    out
}

/// The providers that can be handed to Windows as a nameserver.
///
/// A DoH provider carries no UDP address by construction (I49), so it can answer
/// through the relay and still be useless in an NRPT rule. Leaving *only* those
/// enabled empties the rule's fallback list, and a rule with no nameserver is
/// worse than no rule at all — hence the guard in `ops`.
pub fn udp_provider_names() -> Vec<&'static str> {
    in_user_order()
        .into_iter()
        .filter(|p| !p.v4.is_empty())
        .map(|p| p.name)
        .collect()
}

/// The provider names in the user's order — what the window's list draws.
pub fn ordered_provider_names(order: &[String]) -> Vec<&'static str> {
    in_order(order).into_iter().map(|p| p.name).collect()
}

/// Switched off by name in the window.
fn denied(name: &str) -> bool {
    crate::settings::disabled_providers_cached()
        .iter()
        .any(|d| d.eq_ignore_ascii_case(name))
}

fn ask_provider(
    provider: &Provider,
    query: &[u8],
    if_index: u32,
    timeout: Duration,
) -> Option<Vec<u8>> {
    ask_provider_cancellable(provider, query, if_index, timeout, None)
}

fn ask_provider_cancellable(provider: &Provider, query: &[u8], if_index: u32, timeout: Duration, cancelled: Option<&ResolverCancellation>) -> Option<Vec<u8>> {
    ask_provider_with_inputs(provider, query, if_index, timeout, cancelled, None, None, None)
}

fn query_custom_with_inputs<F>(servers: &[Ipv4Addr], timeout: Duration, cancelled: Option<&ResolverCancellation>, deadline: Option<Instant>, mut query: F) -> Option<Vec<u8>>
where F: FnMut(Ipv4Addr, Duration) -> Option<Vec<u8>> {
    for &ip in servers {
        if cancelled.is_some_and(ResolverCancellation::is_cancelled) { return None; }
        let left = deadline.map_or(timeout, |until| timeout.min(until.saturating_duration_since(Instant::now())));
        if left.is_zero() { return None; }
        if let Some(reply) = query(ip, left) { return Some(reply); }
    }
    None
}

fn ask_provider_with_inputs(provider: &Provider, query: &[u8], if_index: u32, timeout: Duration, cancelled: Option<&ResolverCancellation>, witness: Option<&DnsSourceWitness>, deadline: Option<Instant>, mut started: Option<&mut bool>) -> Option<Vec<u8>> {
    let stopped = || cancelled.is_some_and(ResolverCancellation::is_cancelled);
    let remaining = || deadline.map_or(timeout, |until| timeout.min(until.saturating_duration_since(Instant::now())));
    if stopped() { return None; }
    let legacy_inputs;
    let inputs = match witness {
        Some(inputs) => inputs,
        None => {
            legacy_inputs = legacy_inputs_for_work(None);
            &legacy_inputs
        }
    };
    if !provider_index(provider.name).is_some_and(|idx| inputs.selected.contains(&idx)) {
        return None;
    }
    match provider.transport {
        Transport::Udp => {
            for server in provider.v4 {
                if stopped() { return None; }
                let timeout = remaining();
                if timeout.is_zero() { return None; }
                let Ok(ip) = server.parse::<Ipv4Addr>() else {
                    continue;
                };
                if let Some(started) = started.as_deref_mut() { *started = true; }
                if let Ok(reply) = dns_client::query_raw_via(query, ip, if_index, timeout) {
                    return Some(reply);
                }
            }
            None
        }
        Transport::Custom => {
            query_custom_with_inputs(&inputs.custom, timeout, cancelled, deadline, |ip, left| {
                if let Some(started) = started.as_deref_mut() { *started = true; }
                dns_client::query_raw_via(query, ip, if_index, left).ok()
            })
        }
        Transport::Doh(endpoint) => {
            let timeout = remaining();
            if timeout.is_zero() { return None; }
            if let Some(started) = started.as_deref_mut() { *started = true; }
            #[cfg(target_os = "macos")]
            let answer = if deadline.is_some() {
                crate::doh::query_on_interface(endpoint, query, timeout, if_index)
            } else {
                crate::doh::query(endpoint, query, timeout)
            };
            #[cfg(not(target_os = "macos"))]
            let answer = crate::doh::query(endpoint, query, timeout);
            let mut reply = answer.ok()?;
            // Re-stamp the transaction id. RFC 8484 tells a DoH client to send 0
            // and a server is free to answer with 0 whatever we asked with, but
            // the reply is handed to Windows over UDP:53, where an id that does
            // not match the question is simply dropped - a failure that would
            // look exactly like the resolver being slow. Nothing else in the
            // message is touched: the relay's contract is that it forwards the
            // provider's own bytes (I23).
            if reply.len() >= 2 && query.len() >= 2 {
                reply[0] = query[0];
                reply[1] = query[1];
            }
            Some(reply)
        }
    }
}

/// What one racer produced.
enum Heat {
    /// A provider's raw reply to the question the client asked.
    Provider(usize, Vec<u8>),
    /// An honest resolver's answer to the same question.
    Reference(Vec<IpAddr>),
    /// A provider's answer for `CONTROL_NAME`, i.e. its proxy address.
    Control(usize, Vec<IpAddr>),
    /// An honest resolver's answer for `CONTROL_NAME`, without which the line
    /// above cannot be believed.
    ControlReference(Vec<IpAddr>),
}

/// Whether a tunnel is carrying **the client's** traffic, as last seen by the
/// relay's warm loop (`VPN_CHECK_EVERY`).
///
/// The client's, not the machine's: a tunnel that holds a default route but
/// excludes `language_server.exe` must leave substitution on, or the rules
/// resolve to genuine Google and the gate answers 400 with the layer nominally
/// installed (G29). `egress::vpn_verdict` is what decides; this only stores it.
///
/// A plain flag rather than a parameter threaded through six call sites, and a
/// flag the *relay* sets rather than something this module probes: detection
/// shells out to PowerShell, and nothing that a client query waits on may do
/// that. Defaults to `false`, which is the pre-existing behaviour - a machine
/// that never learns the answer keeps substituting exactly as before.
static VPN_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Until when substitution is forced on regardless of the tunnel verdict.
///
/// Set by the region-400 watch (`ls_log`): the client was measured inside a
/// tunnel, the relay stood down for it, and the gate answered 400 anyway - so
/// the tunnel exits somewhere blocked and "the VPN decides" (D13) is the wrong
/// call for this tunnel. Substituting then sends the client to a provider's
/// proxy *through* the tunnel, which still lifts the gate. It is a window, not
/// a flag: the tunnel may be replaced by a permitted one, and when the window
/// closes the stand-down logic is back in charge until the log says otherwise.
static FORCE_SUBSTITUTE_UNTIL: Mutex<Option<Instant>> = Mutex::new(None);

pub fn set_vpn_active(active: bool) {
    VPN_ACTIVE.store(active, Ordering::Relaxed);
}

/// Whether the relay is standing down for a tunnel right now. False while
/// substitution is forced, whatever the tunnel verdict says.
pub fn vpn_is_active() -> bool {
    VPN_ACTIVE.load(Ordering::Relaxed) && !substitution_forced()
}

/// The raw tunnel verdict, ignoring any force. For the log line that explains
/// why the relay is doing what it does.
pub fn tunnel_carries_client() -> bool {
    VPN_ACTIVE.load(Ordering::Relaxed)
}

pub fn force_substitution(for_how_long: Duration) {
    if let Ok(mut until) = FORCE_SUBSTITUTE_UNTIL.lock() {
        *until = Some(Instant::now() + for_how_long);
    }
}

pub fn substitution_forced() -> bool {
    substitution_forced_for().is_some()
}

/// How much of that window is left, for the record the window reads (`gate`).
/// `None` when nothing is forced.
pub fn substitution_forced_for() -> Option<Duration> {
    FORCE_SUBSTITUTE_UNTIL
        .lock()
        .ok()
        .and_then(|u| *u)
        .and_then(|until| until.checked_duration_since(Instant::now()))
}

/// The verdict of the answer most recently handed out for each name, by the
/// client path or the warm loop alike. What the proxy asks when deciding
/// whether a direct tunnel to that name has anything substituted to reach.
static SERVED: Mutex<Option<HashMap<String, (Verdict, Instant)>>> = Mutex::new(None);

/// A served verdict older than this is forgotten: the warm loop refreshes every
/// routed name every 15 s, so a name unseen for minutes is one nobody asks for.
const SERVED_TTL: Duration = Duration::from_secs(10 * 60);

fn note_served(name: &str, verdict: Verdict) {
    if let Ok(mut guard) = SERVED.lock() {
        guard.get_or_insert_with(HashMap::new).insert(
            name.trim_end_matches('.').to_ascii_lowercase(),
            (verdict, Instant::now()),
        );
    }
}

/// What the relay last answered `name` with, if it answered recently.
pub fn served_verdict(name: &str) -> Option<Verdict> {
    let guard = SERVED.lock().ok()?;
    let (verdict, at) = guard
        .as_ref()?
        .get(&name.trim_end_matches('.').to_ascii_lowercase())?;
    (at.elapsed() < SERVED_TTL).then_some(*verdict)
}

/// Drops every remembered choice and cached answer for `names`, so the next
/// query - the warm loop's, within 15 s - races the providers from scratch.
///
/// The region-400 watch calls this: an answer that led to the gate is not one
/// to keep serving for the rest of its TTL, whoever gave it.
pub fn forget_names(names: &[&str]) {
    let wanted: Vec<String> = names
        .iter()
        .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    // The choice key carries the name as the client spelt it, so it is compared
    // case-folded rather than looked up.
    if let Ok(mut guard) = CHOICE.lock() {
        if let Some(map) = guard.as_mut() {
            map.retain(|(name, _), _| {
                !wanted.contains(&name.trim_end_matches('.').to_ascii_lowercase())
            });
        }
    }
    // Expired, not removed. The entry's *shape* - the client's own query bytes -
    // is what the warm loop replays (`warm_queries`), and a removed shape means
    // the next client query of that shape misses the cache and pays for a cold
    // race. Zero life and a non-substituted verdict take it out of both the
    // fresh path and the stale-substituted preference, and let the next answer
    // overwrite it whatever its verdict.
    if let Ok(mut guard) = ANSWERS.lock() {
        if let Some(map) = guard.as_mut() {
            for (key, answer) in map.iter_mut() {
                let hit = dns_client::question_name(key)
                    .map(|q| q.trim_end_matches('.').to_ascii_lowercase())
                    .is_some_and(|q| wanted.contains(&q));
                if hit {
                    answer.good_for = Duration::ZERO;
                    answer.verdict = Verdict::Unknown;
                }
            }
        }
    }
}

/// Answers a routed name the way the tunnel's own resolver would, and says so.
///
/// Used while a VPN is up. Substituting there is worse than useless: an NRPT
/// rule overrides the resolver the user deliberately turned on, and the address
/// it hands back points at a provider's proxy that the traffic then reaches
/// *through* the tunnel - a detour to reach what the tunnel already reaches
/// directly, and pure loss when the exit is somewhere the gate does not apply
/// (S25, G26).
///
/// It asks the reference resolvers over the **default route** - `if_index` 0, so
/// the query leaves through the tunnel like everything else - rather than
/// reading the VPN's own configured servers. Same result for these names, and it
/// avoids depending on that configuration being usable: this was written on a
/// machine whose VPN set DNS to two addresses that answer nothing at all on
/// UDP:53, being DoH-only.
///
/// The verdict is honestly `Passthrough`, so the answer is capped at
/// `PASSTHROUGH_TTL` and never outranks a real substitution left in the cache
/// from before the tunnel came up (I26).
fn resolve_through_tunnel(
    query: &[u8],
    from_client: bool,
    work: Option<&ResolverWork>,
) -> Result<Option<(Vec<u8>, &'static str, Verdict)>, String> {
    for server in REFERENCE_V4 {
        check_resolver_work(work)?;
        let Ok(ip) = server.parse::<Ipv4Addr>() else {
            continue;
        };
        let budget = if from_client {
            FAST_PATH_TIMEOUT
        } else {
            QUERY_TIMEOUT
        };
        let reply = dns_client::query_raw_via(query, ip, 0, budget);
        check_resolver_work(work)?;
        if let Ok(reply) = reply {
            let reply = dns_client::cap_ttl(&reply, PASSTHROUGH_TTL).unwrap_or(reply);
            remember_answer(query, &reply, "VPN", Verdict::Passthrough, from_client);
            return Ok(Some((reply, "VPN", Verdict::Passthrough)));
        }
    }
    Ok(None)
}

/// The provider to prefer for `name`, and how long a racer may be held for it.
///
/// A DoH provider loses a fair race by construction: it pays a TLS handshake
/// where a UDP provider answers in one round trip, so listing it first in
/// `PROVIDERS` buys nothing on its own. What is worth preferring is not the DNS
/// latency but **the proxy the answer points at**, which is the number the IDE
/// actually feels - measured, dns-ai.ru's proxy completes TLS in 0.29 s against
/// comss's 0.37-0.99 s and geohide's 1.3-7.8 s. It is also the owner's own
/// service, so an outage is his to fix rather than a third party's to notice.
///
/// Deliberately narrow: two names, one bounded wait, and no effect at all once
/// the answer cache is warm - which is the state a client query is normally in.
fn preferred_provider(name: &str) -> Option<usize> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if !PREFERRED_NAMES.contains(&name.as_str()) {
        return None;
    }
    PROVIDERS
        .iter()
        .position(|p| matches!(p.transport, Transport::Doh(_)))
}

/// What a one-shot to `provider` needs at minimum, whatever the caller budgeted.
fn one_shot_floor(provider: &Provider, budget: Duration) -> Duration {
    match provider.transport {
        Transport::Doh(_) => budget.max(DOH_FAST_TIMEOUT),
        Transport::Udp | Transport::Custom => budget,
    }
}

/// Answers `query`, from memory when a recent vetted answer is there and from
/// the providers otherwise.
///
/// The reply is handed back as the raw bytes the provider sent, never rebuilt:
/// the relay's contract is that any record type and any EDNS option survives
/// the round trip untouched. A cached reply is the same bytes with the client's
/// transaction id and its TTLs counted down.
pub fn resolve_best(query: &[u8], if_index: u32) -> Option<(Vec<u8>, &'static str, Verdict)> {
    resolve_best_with_work(query, if_index, None).expect("legacy resolver launch behavior")
}

pub(crate) fn resolve_best_owned(query: &[u8], if_index: u32, work: &ResolverWork) -> Result<Option<(Vec<u8>, &'static str, Verdict)>, String> {
    resolve_best_with_work(query, if_index, Some(work))
}

fn resolve_best_with_work(query: &[u8], if_index: u32, work: Option<&ResolverWork>) -> Result<Option<(Vec<u8>, &'static str, Verdict)>, String> {
    check_resolver_work(work)?;
    let hit = match cached_answer(query, false, true) {
        Some(hit) => Some(hit), None => resolve_upstream_with_work(query, if_index, true, work)?,
    };
    check_resolver_work(work)?;
    note_served_a(query, &hit);
    Ok(hit)
}

/// Records the verdict of an **A** answer for its name. Only A: Windows asks
/// AAAA for every name too, and the providers answer that with Google's own
/// IPv6 (a passthrough by construction, which is why `dns.rs` re-orders the
/// prefix policy). Keyed by name alone, the AAAA verdict overwrote the A one
/// and took the direct route out of the table on alternate warm passes.
fn note_served_a(query: &[u8], hit: &Option<(Vec<u8>, &'static str, Verdict)>) {
    if dns_client::question_type(query) != Some(QTYPE_A) {
        return;
    }
    if let (Some(name), Some((_, _, verdict))) = (dns_client::question_name(query), hit) {
        note_served(&name, *verdict);
    }
}

/// Asks upstream whatever is cached, and stores the result.
///
/// This is what the warm loop calls: going through `resolve_best` would just
/// hand back the entry it exists to replace.
pub fn refresh(query: &[u8], if_index: u32) -> Option<(Vec<u8>, &'static str, Verdict)> {
    refresh_with_work(query, if_index, None).expect("legacy resolver launch behavior")
}

pub(crate) fn refresh_owned(query: &[u8], if_index: u32, work: &ResolverWork) -> Result<Option<(Vec<u8>, &'static str, Verdict)>, String> {
    refresh_with_work(query, if_index, Some(work))
}

fn refresh_with_work(query: &[u8], if_index: u32, work: Option<&ResolverWork>) -> Result<Option<(Vec<u8>, &'static str, Verdict)>, String> {
    check_resolver_work(work)?;
    let hit = resolve_upstream_with_work(query, if_index, false, work)?;
    check_resolver_work(work)?;
    note_served_a(query, &hit);
    Ok(hit)
}

/// Asks every provider and every reference resolver at once and returns the
/// answer of the provider that actually substituted the name.
fn resolve_upstream_with_work(
    query: &[u8],
    if_index: u32,
    from_client: bool,
    work: Option<&ResolverWork>,
) -> Result<Option<(Vec<u8>, &'static str, Verdict)>, String> {
    let inputs = legacy_inputs_for_work(work);
    resolve_upstream_with_inputs(query, if_index, from_client, work, &inputs)
}

fn resolve_upstream_with_inputs(
    query: &[u8], if_index: u32, from_client: bool, work: Option<&ResolverWork>,
    legacy_inputs: &DnsSourceWitness,
) -> Result<Option<(Vec<u8>, &'static str, Verdict)>, String> {
    check_resolver_work(work)?;
    let qtype = dns_client::question_type(query).unwrap_or(0);
    let name = dns_client::question_name(query).unwrap_or_default();
    let key = (name, qtype);

    // With a tunnel up the VPN decides, not us. Checked before the choice cache
    // as well as before the race, or a provider chosen minutes earlier would go
    // on answering for the whole `CHOICE_TTL` after the user connected.
    if vpn_is_active() {
        if let Some(hit) = resolve_through_tunnel(query, from_client, work)? {
            check_resolver_work(work)?;
            return Ok(Some(hit));
        }
        check_resolver_work(work)?;
        // The tunnel's resolver is not answering either; fall through rather
        // than hand the client nothing.
    }

    // Anything that is not an address lookup cannot be classified, so it goes
    // to whichever provider is already known good for this name - or the first
    // one that answers.
    let classifiable = qtype == QTYPE_A || qtype == QTYPE_AAAA;
    // All provider and control queries in this ordinary race use the same
    // cached settings snapshot. This is legacy DNS input, not source authority.

    // Nothing here may outlast what Windows will wait for while a client is
    // blocked on it: past that it asks the fallback nameserver, whose answer no
    // liveness probe and no reference comparison has been anywhere near.
    let one_shot = if from_client {
        FAST_PATH_TIMEOUT
    } else {
        QUERY_TIMEOUT
    };

    if let Some((idx, verdict)) = cached_choice(&key) {
        let budget = one_shot_floor(&PROVIDERS[idx], one_shot);
        if let Some(reply) = ask_provider_with_inputs(&PROVIDERS[idx], query, if_index, budget, work.map(|work| &work.cancelled), Some(legacy_inputs), None, None) {
            check_resolver_work(work)?;
            let reply = vet_with_work(reply, verdict, !from_client, Some(key.0.as_str()), work)?;
            remember_answer(query, &reply, PROVIDERS[idx].name, verdict, from_client);
            return Ok(prefer_substituted(query, from_client, (reply, PROVIDERS[idx].name, verdict)));
        }
        check_resolver_work(work)?;
        // The chosen provider went away; re-race rather than keep asking it.
        forget_choice(&key);
    }

    if !classifiable {
        let start = ROTATION.fetch_add(1, Ordering::Relaxed);
        for step in 0..PROVIDERS.len() {
            check_resolver_work(work)?;
            let idx = (start + step) % PROVIDERS.len();
            if let Some(reply) = ask_provider_with_inputs(&PROVIDERS[idx], query, if_index, one_shot, work.map(|work| &work.cancelled), Some(legacy_inputs), None, None) {
                check_resolver_work(work)?;
                return Ok(Some((reply, PROVIDERS[idx].name, Verdict::Unknown)));
            }
        }
        check_resolver_work(work)?;
        return Ok(None);
    }

    let (tx, rx) = mpsc::channel::<Heat>();
    for idx in 0..PROVIDERS.len() {
        let tx = tx.clone();
        let q = query.to_vec();
        let inputs = (*legacy_inputs).clone();
        #[cfg(test)]
        let fixture = work.and_then(|work| work.fixture.clone());
        #[cfg(test)]
        let observer = work.and_then(|work| work.legacy_input_observer.clone());
        launch_resolver(work, ResolverChildKind::Provider(idx), move |cancelled| {
            // The generous timeout is right here: nothing blocks on one racer,
            // the race as a whole is bounded by RACE_BUDGET, and a straggler
            // simply sends into a channel nobody is reading any more.
            #[cfg(test)]
            if let Some(observer) = observer { observer(idx, &q, &inputs); }
            #[cfg(test)]
            let reply = fixture.as_ref().map(|fixture| (fixture.provider)(idx, &q)).unwrap_or_else(|| ask_provider_with_inputs(&PROVIDERS[idx], &q, if_index, QUERY_TIMEOUT, Some(cancelled), Some(&inputs), None, None));
            #[cfg(not(test))]
            let reply = ask_provider_with_inputs(&PROVIDERS[idx], &q, if_index, QUERY_TIMEOUT, Some(cancelled), Some(&inputs), None, None);
            let delivery = reply.as_ref().map_or(ResolverDelivery::NoMessage, |reply|
                deliver_resolver(&tx, Heat::Provider(idx, reply.clone()), cancelled));
            ResolverChildResult { observation: reply.map_or(ResolverObservation::NoAnswer, ResolverObservation::Reply), delivery, cancelled: false }
        })?;
    }
    for server in REFERENCE_V4 {
        let Ok(ip) = server.parse::<Ipv4Addr>() else {
            continue;
        };
        let tx = tx.clone();
        let q = query.to_vec();
        #[cfg(test)]
        let fixture = work.and_then(|work| work.fixture.clone());
        launch_resolver(work, ResolverChildKind::Reference(ip), move |cancelled| {
            #[cfg(test)]
            let reply = fixture.as_ref().map(|fixture| (fixture.reference)(ip, &q)).unwrap_or_else(|| dns_client::query_raw_via(&q, ip, if_index, QUERY_TIMEOUT));
            #[cfg(not(test))]
            let reply = dns_client::query_raw_via(&q, ip, if_index, QUERY_TIMEOUT);
            let delivery = reply.as_ref().map_or(ResolverDelivery::NoMessage, |reply|
                deliver_resolver(&tx, Heat::Reference(dns_client::answer_addrs(reply)), cancelled));
            ResolverChildResult { observation: match reply { Ok(reply) => ResolverObservation::Reply(reply), Err(error) => ResolverObservation::Error(error) }, delivery, cancelled: false }
        })?;
    }

    // The control probes ride along in the same batch rather than on a timer:
    // in wall-clock they cost nothing, because everything here runs in
    // parallel, and they only run at all when something has gone stale -
    // normally once every PROXY_SET_TTL, not once per query.
    let learning = (0..PROVIDERS.len()).any(proxy_addrs_are_stale);
    if learning {
        // A different control name each round: the same one every time would be
        // a signature in a source anyone can read.
        let picked = CONTROL_NAMES[ROTATION.fetch_add(1, Ordering::Relaxed) % CONTROL_NAMES.len()];
        let control = dns_client::build_query(picked, 0x0C71);
        for idx in 0..PROVIDERS.len() {
            let tx = tx.clone();
            let q = control.clone();
            let inputs = (*legacy_inputs).clone();
            #[cfg(test)]
            let fixture = work.and_then(|work| work.fixture.clone());
            #[cfg(test)]
            let observer = work.and_then(|work| work.legacy_input_observer.clone());
            launch_resolver(work, ResolverChildKind::ControlProvider(idx), move |cancelled| {
                #[cfg(test)]
                if let Some(observer) = observer { observer(idx, &q, &inputs); }
                #[cfg(test)]
                let reply = fixture.as_ref().map(|fixture| (fixture.provider)(idx, &q)).unwrap_or_else(|| ask_provider_with_inputs(&PROVIDERS[idx], &q, if_index, QUERY_TIMEOUT, Some(cancelled), Some(&inputs), None, None));
                #[cfg(not(test))]
                let reply = ask_provider_with_inputs(&PROVIDERS[idx], &q, if_index, QUERY_TIMEOUT, Some(cancelled), Some(&inputs), None, None);
                let delivery = reply.as_ref().map_or(ResolverDelivery::NoMessage, |reply|
                    deliver_resolver(&tx, Heat::Control(idx, dns_client::answer_addrs(reply)), cancelled));
                ResolverChildResult { observation: reply.map_or(ResolverObservation::NoAnswer, ResolverObservation::Reply), delivery, cancelled: false }
            })?;
        }
        if let Ok(ip) = REFERENCE_V4[0].parse::<Ipv4Addr>() {
            let tx = tx.clone();
            #[cfg(test)]
            let fixture = work.and_then(|work| work.fixture.clone());
            launch_resolver(work, ResolverChildKind::ControlReference(ip), move |cancelled| {
                #[cfg(test)]
                let reply = fixture.as_ref().map(|fixture| (fixture.reference)(ip, &control)).unwrap_or_else(|| dns_client::query_raw_via(&control, ip, if_index, QUERY_TIMEOUT));
                #[cfg(not(test))]
                let reply = dns_client::query_raw_via(&control, ip, if_index, QUERY_TIMEOUT);
                let delivery = reply.as_ref().map_or(ResolverDelivery::NoMessage, |reply|
                    deliver_resolver(&tx, Heat::ControlReference(dns_client::answer_addrs(reply)), cancelled));
                ResolverChildResult { observation: match reply { Ok(reply) => ResolverObservation::Reply(reply), Err(error) => ResolverObservation::Error(error) }, delivery, cancelled: false }
            })?;
        }
    }
    // Every sender lives in a thread; the local one would otherwise keep the
    // channel open past the last answer.
    drop(tx);

    let deadline = Instant::now() + RACE_BUDGET;
    let preferred = preferred_provider(&key.0);
    let grace_until = Instant::now() + PREFERRED_GRACE;
    let mut reference: Vec<IpAddr> = Vec::new();
    let mut replies: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut control: Vec<(usize, Vec<IpAddr>)> = Vec::new();
    let mut control_reference: Vec<IpAddr> = Vec::new();
    let mut got_reference = false;
    let mut got_control_reference = false;

    loop {
        check_resolver_work(work)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(Heat::Reference(addrs)) => {
                reference.extend(addrs);
                got_reference = true;
            }
            Ok(Heat::Provider(idx, reply)) => replies.push((idx, reply)),
            Ok(Heat::Control(idx, addrs)) => control.push((idx, addrs)),
            Ok(Heat::ControlReference(addrs)) => {
                control_reference = addrs;
                got_control_reference = true;
            }
            // Everyone finished, or nobody is left to answer.
            Err(_) => break,
        }

        // A control answer counts as a proxy address only when it differs from
        // what the honest resolver says for the same name. Without that check a
        // provider that quietly stopped proxying the control name would teach
        // the relay that Cloudflare's addresses are its proxy.
        if got_control_reference {
            while let Some((idx, addrs)) = control.pop() {
                if classify(&addrs, &control_reference, &[]) == Verdict::Substituted {
                    learn_proxy_addrs(idx, addrs);
                }
            }
        }

        // Waiting for the control probes is only worth it while they can still
        // change a verdict. Once they are in - or were never started - the
        // first clear winner ends the race.
        let still_learning = learning && !got_control_reference;
        // Hold a decided race briefly for the preferred provider, but only while
        // it could still turn up and only for the names it is preferred on. Past
        // the grace the pool answers as it always did - preference must never
        // become a way to answer slower than the tool used to.
        let holding_for_preferred = preferred
            .is_some_and(|p| !replies.iter().any(|(i, _)| *i == p) && Instant::now() < grace_until);
        if got_reference && !replies.is_empty() && !still_learning && !holding_for_preferred {
            // The preferred provider wins among equals; `pick` decides otherwise.
            let hit = preferred
                .and_then(|p| replies.iter().position(|(i, _)| *i == p))
                .filter(|&h| {
                    classify(
                        &dns_client::answer_addrs(&replies[h].1),
                        &reference,
                        &known_proxy_addrs(replies[h].0),
                    ) == Verdict::Substituted
                })
                .or_else(|| pick(&replies, &reference, Verdict::Substituted));
            if let Some(hit) = hit {
                let name = key.0.clone();
                remember_choice(key, replies[hit].0, Verdict::Substituted);
                let (idx, reply) = replies.swap_remove(hit);
                let reply = vet_with_work(reply, Verdict::Substituted, !from_client, Some(&name), work)?;
                remember_answer(
                    query,
                    &reply,
                    PROVIDERS[idx].name,
                    Verdict::Substituted,
                    from_client,
                );
                check_resolver_work(work)?;
                return Ok(Some((reply, PROVIDERS[idx].name, Verdict::Substituted)));
            }
        }
        if replies.len() == PROVIDERS.len() && got_reference && !still_learning {
            break;
        }
    }

    check_resolver_work(work)?;
    if replies.is_empty() {
        // Every provider went quiet. A substituted answer from minutes ago is
        // still the best thing in the building: the alternative is not a fresh
        // answer but Windows falling through to an unvetted fallback.
        check_resolver_work(work)?;
        return Ok(cached_answer(query, true, from_client));
    }
    // Nothing substituted. Hand back the best of what arrived anyway - an
    // unsubstituted answer still resolves the name, and refusing to answer
    // would only push Windows onto the direct fallback for the same result.
    let best = best_of(&replies, &reference);
    // Only for a query a client is actually waiting on. The warm loop races the
    // same names every 15 s, and two of the four never substitute by design, so
    // logging its races would fill the 64 KB budget in about an hour and take
    // the diagnostics with it.
    if from_client && !replies.is_empty() && !dns_client::answer_addrs(&replies[best].1).is_empty()
    {
        let heard: Vec<&str> = replies.iter().map(|(i, _)| PROVIDERS[*i].name).collect();
        crate::dns_forwarder::log_race(&key.0, &heard, got_reference);
    }
    let verdict = classify(
        &dns_client::answer_addrs(&replies[best].1),
        &reference,
        &known_proxy_addrs(replies[best].0),
    );
    // Only a substitution is worth remembering. A choice cached on any weaker
    // verdict is a five-minute promise to stop looking: the fast path re-asks
    // that provider, it keeps answering (with the genuine address), so nothing
    // ever fails and no re-race is triggered. Measured exactly that way - one
    // lost race and the relay served comss's genuine `daily-cloudcode-pa` for as
    // long as the choice lived, while geohide was substituting it in 40 ms the
    // whole time. Forgetting instead costs a race per warm pass, which is off
    // the client's path and is precisely the work this module exists to do.
    forget_choice(&key);
    let (idx, reply) = replies.swap_remove(best);
    let reply = vet_with_work(reply, verdict, !from_client, Some(key.0.as_str()), work)?;
    remember_answer(query, &reply, PROVIDERS[idx].name, verdict, from_client);
    check_resolver_work(work)?;
    Ok(prefer_substituted(query, from_client, (reply, PROVIDERS[idx].name, verdict)))
}

/// Filters a reply before it goes back to the client.
///
/// A substitution gets its dead addresses cut out - those belong to a third
/// party rather than to Google, so they are the only ones worth probing. Every
/// other verdict gets its TTL clamped instead: see `PASSTHROUGH_TTL`.
fn vet(reply: Vec<u8>, verdict: Verdict, fresh: bool, sni: Option<&str>) -> Vec<u8> {
    vet_with_work(reply, verdict, fresh, sni, None).expect("legacy liveness launch behavior")
}

fn vet_with_work(reply: Vec<u8>, verdict: Verdict, fresh: bool, sni: Option<&str>, work: Option<&ResolverWork>) -> Result<Vec<u8>, String> {
    check_resolver_work(work)?;
    if verdict == Verdict::Substituted {
        drop_dead_addrs_with_work(reply, fresh, sni, work)
    } else {
        Ok(dns_client::cap_ttl(&reply, PASSTHROUGH_TTL).unwrap_or(reply))
    }
}

/// Hands back the best answer available for `query`, preferring a substitution
/// already in memory over a freshly-arrived unsubstituted one.
///
/// Without this a single lost race is not a blip but an outage: the genuine
/// answer goes into the Windows cache and every request for its whole TTL leaves
/// from the blocked region, with the relay never consulted again.
fn prefer_substituted(
    query: &[u8],
    from_client: bool,
    fresh: (Vec<u8>, &'static str, Verdict),
) -> Option<(Vec<u8>, &'static str, Verdict)> {
    if fresh.2 == Verdict::Substituted {
        return Some(fresh);
    }
    cached_answer(query, true, from_client).or(Some(fresh))
}

/// Seeds each provider's proxy-address set from a control name, sequentially.
///
/// `substituting_addrs` runs in the menu process at rule-setup time, which has
/// its own (cold) `PROXY_SET` - the relay's warm loop that normally learns it
/// lives in a different process. Without this the set is empty, and `classify`
/// falls back to its bootstrap rule (`proxy.is_empty()` -> `Substituted`), which
/// flags a genuine answer that merely landed on a different Google /16 (D7).
/// That is exactly how xbox-dns, which returns genuine for `daily-cloudcode-pa`,
/// ended up written into that name's NRPT fallback - the I22 leak. Learning the
/// sets first makes `classify` take the proxy-match path, so a genuine
/// different-/16 answer is `Sibling`, not `Substituted`.
fn ensure_proxy_sets_learned(if_index: u32) {
    ensure_proxy_sets_learned_with_work(if_index, None).expect("legacy resolver behavior")
}

fn ensure_proxy_sets_learned_with_work(if_index: u32, work: Option<&ResolverWork>) -> Result<(), String> {
    let inputs = legacy_inputs_for_work(work);
    ensure_proxy_sets_learned_with_inputs(if_index, work, &inputs)
}

fn ensure_proxy_sets_learned_with_inputs(if_index: u32, work: Option<&ResolverWork>, legacy_inputs: &DnsSourceWitness) -> Result<(), String> {
    check_resolver_work(work)?;
    #[cfg(test)]
    if let Some(learning) = work.and_then(|work| work.fixture.as_ref()).and_then(|fixture| fixture.learning.as_ref()) {
        learning();
        return check_resolver_work(work);
    }
    if !(0..PROVIDERS.len()).any(proxy_addrs_are_stale) {
        return Ok(());
    }
    // Union across two usable control names, not one: geohide rotates its proxy
    // across three addresses in three /16s (see PROXY_SET_TTL), so a single probe
    // can miss the /16 it later answers `daily-cloudcode-pa` from - which would
    // drop its sole substituter and fall the rule back to every provider (the I22
    // leak). `learn_proxy_addrs` unions, so a second name closes most of that gap
    // without paying for all five.
    const ROUNDS: usize = 2;
    let mut done = 0;
    for &picked in CONTROL_NAMES {
        check_resolver_work(work)?;
        if done >= ROUNDS {
            break;
        }
        let control = dns_client::build_query(picked, 0x0C71);
        let mut cref: Vec<IpAddr> = Vec::new();
        for server in REFERENCE_V4 {
            check_resolver_work(work)?;
            if let Ok(ip) = server.parse::<Ipv4Addr>() {
                if let Ok(reply) = dns_client::query_raw_via(&control, ip, if_index, QUERY_TIMEOUT)
                {
                    check_resolver_work(work)?;
                    cref.extend(dns_client::answer_addrs(&reply));
                }
            }
        }
        // A control name the ISP link's DPI stubs (e.g. chatgpt.com) yields no
        // usable reference - classify filters those stubs - so try the next.
        let usable = cref.iter().any(|a| match a {
            IpAddr::V4(v) => !REFERENCE_STUBS.contains(v),
            IpAddr::V6(_) => true,
        });
        if !usable {
            continue;
        }
        for idx in 0..PROVIDERS.len() {
            check_resolver_work(work)?;
            if let Some(reply) = ask_provider_with_inputs(&PROVIDERS[idx], &control, if_index, QUERY_TIMEOUT, work.map(|work| &work.cancelled), Some(legacy_inputs), None, None) {
                check_resolver_work(work)?;
                let addrs = dns_client::answer_addrs(&reply);
                if classify(&addrs, &cref, &[]) == Verdict::Substituted {
                    learn_proxy_addrs(idx, addrs);
                }
            }
        }
        done += 1;
    }
    check_resolver_work(work)
}

pub fn substituting_addrs(name: &str, if_index: u32) -> Vec<&'static str> {
    let inputs = legacy_inputs_for_work(None);
    ensure_proxy_sets_learned_with_inputs(if_index, None, &inputs).expect("legacy resolver behavior");
    let query = dns_client::build_query(name, 0x6767);

    let mut reference: Vec<IpAddr> = Vec::new();
    for server in REFERENCE_V4 {
        if let Ok(ip) = server.parse::<Ipv4Addr>() {
            if let Ok(reply) = dns_client::query_raw_via(&query, ip, if_index, QUERY_TIMEOUT) {
                reference.extend(dns_client::answer_addrs(&reply));
            }
        }
    }

    let mut out = Vec::new();
    for (idx, provider) in PROVIDERS.iter().enumerate() {
        let Some(reply) = ask_provider_with_inputs(provider, &query, if_index, QUERY_TIMEOUT, None, Some(&inputs), None, None) else {
            continue;
        };
        let addrs = dns_client::answer_addrs(&reply);
        let known = known_proxy_addrs(idx);
        // Only a substitution backed by a *known* proxy address is written into
        // an NRPT fallback. classify's empty-set bootstrap exists to learn
        // control names, not to build rules: trusting it here would flag genuine
        // Google on a different /16 and re-open the I22 leak (see
        // `ensure_proxy_sets_learned`).
        if !known.is_empty() && classify(&addrs, &reference, &known) == Verdict::Substituted {
            if let Some(first) = provider.v4.first() {
                out.push(*first);
            }
        }
    }
    out
}

/// Resolves `name` the same way, for callers that want addresses rather than a
/// packet - `hosts_pin` writes literals, not DNS messages.
///
/// The verdict comes back with them so the caller can refuse to pin an answer
/// that was never substituted: freezing a genuine Google address into `hosts`
/// buys nothing and goes stale the moment Google rotates its edge.
pub fn resolve_a_best(name: &str, if_index: u32) -> Option<(Vec<Ipv4Addr>, &'static str, Verdict)> {
    resolve_a_best_with_work(name, if_index, None).expect("legacy resolver launch behavior")
}

fn resolve_a_best_with_work(name: &str, if_index: u32, work: Option<&ResolverWork>) -> Result<Option<(Vec<Ipv4Addr>, &'static str, Verdict)>, String> {
    check_resolver_work(work)?;
    // The id only has to be echoed back; `query_raw_via` matches on it.
    let query = dns_client::build_query(name, 0x5A5A);
    let Some((reply, provider, verdict)) = resolve_best_with_work(&query, if_index, work)? else { return Ok(None); };
    let addrs: Vec<Ipv4Addr> = dns_client::answer_addrs(&reply)
        .into_iter()
        .filter_map(|a| match a {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    if addrs.is_empty() {
        return Ok(None);
    }
    check_resolver_work(work)?;
    Ok(Some((addrs, provider, verdict)))
}

/// What the `Direct` route walks: the race winner's answer, then every proxy
/// address any provider is known to hand out, the ones that accept a connection
/// first.
///
/// `resolve_a_best` alone is one provider's word. A single-address answer is
/// never vetted (`drop_dead_addrs` keeps the last address so a slow answer does
/// not become no answer), so a winner whose lone proxy had died put the direct
/// route on a black hole every time while another provider's proxy served the
/// same name (measured: dns-ai.ru's address timed out, geohide's completed TLS).
pub fn direct_addrs(name: &str, if_index: u32) -> Option<(Vec<Ipv4Addr>, &'static str, Verdict)> {
    direct_addrs_with_work(name, if_index, None).expect("legacy resolver launch behavior")
}

pub(crate) fn direct_addrs_owned(name: &str, if_index: u32, work: &ResolverWork) -> Result<Option<(Vec<Ipv4Addr>, &'static str, Verdict)>, String> {
    direct_addrs_with_work(name, if_index, Some(work))
}

fn direct_addrs_with_work(name: &str, if_index: u32, work: Option<&ResolverWork>) -> Result<Option<(Vec<Ipv4Addr>, &'static str, Verdict)>, String> {
    check_resolver_work(work)?;
    let Some((mut addrs, provider, verdict)) = resolve_a_best_with_work(name, if_index, work)? else { return Ok(None); };
    if verdict != Verdict::Substituted {
        return Ok(Some((addrs, provider, verdict)));
    }
    for idx in 0..PROVIDERS.len() {
        for a in known_proxy_addrs(idx) {
            if let IpAddr::V4(v4) = a {
                if !addrs.contains(&v4) {
                    addrs.push(v4);
                }
            }
        }
    }
    // Only previously measured dead addresses move behind other candidates.
    // A request must not wait for fresh liveness of unrelated pool members.
    addrs.sort_by_key(|a| cached_liveness(&IpAddr::V4(*a)) == Some(false));
    check_resolver_work(work)?;
    Ok(Some((addrs, provider, verdict)))
}

/// Genuine Google for `name`, as the routing table's own path resolves it: the
/// reference resolvers asked over the **default route**, i.e. through the
/// user's VPN when one holds it, so the edge is the one that tunnel's exit is
/// served from. What the `Vpn` route connects to.
///
/// Cached for a minute: it is asked once per gate connection on that route, and
/// Google's edge for a name does not move on that scale.
pub fn genuine_a(name: &str) -> Vec<Ipv4Addr> {
    const TTL: Duration = Duration::from_secs(60);
    const BUDGET: Duration = Duration::from_secs(2);
    static CACHE: Mutex<Option<HashMap<String, (Vec<Ipv4Addr>, Instant)>>> = Mutex::new(None);

    let key = name.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(guard) = CACHE.lock() {
        if let Some((addrs, at)) = guard.as_ref().and_then(|m| m.get(&key)) {
            if at.elapsed() < TTL && !addrs.is_empty() {
                return addrs.clone();
            }
        }
    }
    let query = dns_client::build_query(&key, 0x7A7A);
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for server in REFERENCE_V4 {
        let Ok(ip) = server.parse::<Ipv4Addr>() else {
            continue;
        };
        if let Ok(reply) = dns_client::query_raw_via(&query, ip, 0, BUDGET) {
            out = dns_client::answer_addrs(&reply)
                .into_iter()
                .filter_map(|a| match a {
                    IpAddr::V4(v4) if is_public_v4(v4) => Some(v4),
                    _ => None,
                })
                .collect();
            if !out.is_empty() {
                break;
            }
        }
    }
    if !out.is_empty() {
        if let Ok(mut guard) = CACHE.lock() {
            guard
                .get_or_insert_with(HashMap::new)
                .insert(key, (out.clone(), Instant::now()));
        }
    }
    out
}

/// An address Google could actually be at. Not the DPI's stubs, and not the
/// ranges a tunnel's "fake IP" DNS hands out (198.18.0.0/15) or anything
/// private: connecting there hands the name back to whatever answered it, and
/// that can resolve it through us again.
pub(crate) fn is_public_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    !(REFERENCE_STUBS.contains(&v4)
        || v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 198 && (18..20).contains(&o[1]))
        || o[0] >= 224)
}

/// Index of the first reply with exactly `want`, in rotated provider order.
fn pick(replies: &[(usize, Vec<u8>)], reference: &[IpAddr], want: Verdict) -> Option<usize> {
    let start = ROTATION.load(Ordering::Relaxed);
    let mut best: Option<usize> = None;
    // Every provider index, not `replies.len()` of them: walking only as many
    // slots as there were replies skipped any reply whose provider sat outside
    // that rotated window, so a lone substitution from the last provider could
    // go unseen.
    for i in 0..PROVIDERS.len() {
        // Rotate over provider indices so a tie does not always go to the same
        // provider, then map back to the position in `replies`.
        let wanted_provider = (start + i) % PROVIDERS.len();
        let Some(pos) = replies.iter().position(|(idx, _)| *idx == wanted_provider) else {
            continue;
        };
        let verdict = classify(
            &dns_client::answer_addrs(&replies[pos].1),
            reference,
            &known_proxy_addrs(wanted_provider),
        );
        if verdict == want {
            best = Some(pos);
            break;
        }
    }
    if best.is_some() {
        ROTATION.fetch_add(1, Ordering::Relaxed);
    }
    best
}

/// Highest-ranked reply, ties broken by rotation.
fn best_of(replies: &[(usize, Vec<u8>)], reference: &[IpAddr]) -> usize {
    let start = ROTATION.fetch_add(1, Ordering::Relaxed);
    let mut best = 0usize;
    let mut best_rank = 0u8;
    let mut seen = false;
    // Every provider index (see `pick`). This one mattered more: with two replies
    // in a pool of four, a rotated window of two slots could miss the empty AAAA
    // answer entirely and hand back the other one - Google's own IPv6.
    for i in 0..PROVIDERS.len() {
        let wanted_provider = (start + i) % PROVIDERS.len();
        let Some(pos) = replies.iter().position(|(idx, _)| *idx == wanted_provider) else {
            continue;
        };
        let r = rank(classify(
            &dns_client::answer_addrs(&replies[pos].1),
            reference,
            &known_proxy_addrs(wanted_provider),
        ));
        if !seen || r > best_rank {
            seen = true;
            best_rank = r;
            best = pos;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_held_probe_cannot_enter_publication() {
        let work = Arc::new(ResolverWork::new(thread::current()));
        let admitted = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_work = work.clone();
        let worker_admitted = admitted.clone();
        let worker = thread::spawn(move || {
            let _ = entered_tx.send(());
            if release_rx.recv_timeout(Duration::from_secs(5)).is_err() { return false; }
            worker_work.with_open(|| worker_admitted.store(true, Ordering::SeqCst)).is_err()
        });
        let entered = entered_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        work.cancel();
        let _ = release_tx.send(());
        let rejected = worker.join().unwrap();
        assert!(entered && rejected && !admitted.load(Ordering::SeqCst));
    }

    #[test]
    fn completed_cancel_prevents_later_publication_admission() {
        let work = Arc::new(ResolverWork::new(thread::current()));
        let (inside_tx, inside_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let publisher_work = work.clone();
        let publisher = thread::spawn(move || publisher_work.with_open(|| {
            let _ = inside_tx.send(());
            release_rx.recv_timeout(Duration::from_secs(5)).is_ok()
        }));
        let entered = inside_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        let canceller_work = work.clone();
        let canceller = thread::spawn(move || canceller_work.cancel());
        let _ = release_tx.send(());
        let publication = publisher.join().unwrap();
        canceller.join().unwrap();
        let later = AtomicBool::new(false);
        let rejected = work.with_open(|| later.store(true, Ordering::SeqCst)).is_err();
        assert!(entered && publication.unwrap() && rejected && !later.load(Ordering::SeqCst));
    }

    #[test]
    fn external_parent_cancel_is_checked_at_guard_entry() {
        let parent = Arc::new(AtomicBool::new(true));
        let work = ResolverWork::with_cancellation(thread::current(), parent);
        let entered = AtomicBool::new(false);
        assert!(work.with_open(|| entered.store(true, Ordering::SeqCst)).is_err());
        assert!(!entered.load(Ordering::SeqCst));
    }

    #[test]
    fn witness_missing_and_invalid_settings_are_distinct() {
        assert!(matches!(witness_from_read(crate::settings::Read::Missing, DnsMissingPolicy::RequireSettings), Err(DnsSourceError::Missing)));
        assert!(witness_from_read(crate::settings::Read::Missing, DnsMissingPolicy::LegacyDefaults).unwrap().missing_defaults);
        assert!(matches!(witness_from_read(crate::settings::Read::Broken, DnsMissingPolicy::LegacyDefaults), Err(DnsSourceError::Broken)));
        assert!(matches!(witness_from_read(crate::settings::Read::Unavailable, DnsMissingPolicy::LegacyDefaults), Err(DnsSourceError::Unavailable)));
    }

    #[test]
    fn witness_respects_order_rotation_and_custom_input() {
        let mut settings = crate::settings::Settings::default();
        let custom = PROVIDERS.iter().position(|provider| matches!(&provider.transport, Transport::Custom)).unwrap();
        settings.provider_order = vec![PROVIDERS[custom].name.to_string(), LEAD_PROVIDER.to_string()];
        settings.rotate_providers = false;
        settings.custom_dns = "192.0.2.53 junk 192.0.2.53 127.0.0.53; 198.51.100.53".to_string();
        let inputs = witness_from_read(crate::settings::Read::Parsed(settings.clone()), DnsMissingPolicy::RequireSettings).unwrap();
        assert_eq!(inputs.selected, vec![custom]);
        assert_eq!(inputs.custom, vec![Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(198, 51, 100, 53)]);

        settings.set_provider_enabled(PROVIDERS[custom].name, false);
        let inputs = witness_from_read(crate::settings::Read::Parsed(settings), DnsMissingPolicy::RequireSettings).unwrap();
        assert_eq!(inputs.selected, vec![provider_index(LEAD_PROVIDER).unwrap()]);
        assert!(inputs.custom.is_empty());
    }

    #[test]
    fn unusable_custom_does_not_displace_the_next_provider() {
        let custom = PROVIDERS.iter().position(|provider| matches!(&provider.transport, Transport::Custom)).unwrap();
        let lead = provider_index(LEAD_PROVIDER).unwrap();
        let mut settings = crate::settings::Settings::default();
        settings.provider_order = vec![PROVIDERS[custom].name.to_string(), LEAD_PROVIDER.to_string()];
        settings.rotate_providers = false;
        for text in [" \t ", "junk 127.0.0.53 0.0.0.0 224.0.0.1"] {
            settings.custom_dns = text.into();
            let strict = witness_from_read(crate::settings::Read::Parsed(settings.clone()), DnsMissingPolicy::RequireSettings).unwrap();
            let mut work = ResolverWork::new(thread::current());
            work.legacy_settings = Some(settings.clone());
            let legacy = legacy_inputs_for_work(Some(&work));
            assert_eq!(strict.selected, [lead]);
            assert!(strict.custom.is_empty());
            assert!(legacy == strict);
            assert!(settings.provider_enabled(PROVIDERS[custom].name));
        }

        settings.rotate_providers = true;
        let rotated = witness_from_settings(&settings, false);
        assert_eq!(rotated.selected.first(), Some(&lead));
        assert!(!rotated.selected.contains(&custom));
    }

    #[test]
    fn provider_identity_is_stable_across_constant_slice_reads() {
        for (idx, provider) in PROVIDERS.iter().enumerate() {
            let inputs = test_source_witness_with_providers(&[provider.name], false);
            assert_eq!(inputs.selected, vec![idx]);
            assert_eq!(provider_index(PROVIDERS[idx].name), Some(idx));
        }
    }

    #[test]
    fn legacy_winner_does_not_wait_for_unwitnessed_control_reference() {
        const NAME: &str = "legacy-witness-independent.invalid";
        struct Restore(Option<HashMap<usize, ProxySet>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                *PROXY_SET.lock().unwrap_or_else(|e| e.into_inner()) = self.0.take();
                forget_names(&[NAME]);
            }
        }
        let old = PROXY_SET.lock().unwrap().take();
        let _restore = Restore(old);
        let address = Ipv4Addr::new(8, 8, 1, 1);
        for idx in 0..PROVIDERS.len() { learn_proxy_addrs(idx, vec![IpAddr::V4(address)]); }
        forget_names(&[NAME]);
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let fixture = ResolverFixture {
            provider: Arc::new(move |_, query| dns_client::synth_reply(query, Some(address), 60)),
            reference: Arc::new(move |_, query| {
                let name = dns_client::question_name(query).unwrap_or_default();
                if CONTROL_NAMES.contains(&name.as_str()) {
                    let _ = held_tx.send(());
                    let _ = release_rx.lock().unwrap().recv_timeout(Duration::from_secs(3));
                }
                dns_client::synth_reply(query, Some(Ipv4Addr::new(1, 1, 1, 1)), 60).ok_or("fixture reply".into())
            }),
            liveness: Arc::new(|_| true), learning: None,
        };
        let mut work = ResolverWork::new(thread::current());
        work.fixture = Some(Arc::new(fixture));
        let query = dns_client::build_query(NAME, 0x1234);
        let result = resolve_upstream_with_work(&query, 0, true, Some(&work));
        let control_started = held_rx.try_recv().is_ok();
        let _ = release_tx.send(());
        let mut terminals = Vec::new();
        while work.has_unreceived() {
            work.receive_into(&mut terminals).unwrap();
            if work.has_unreceived() { thread::park_timeout(Duration::from_millis(1)); }
        }
        assert!(!control_started, "strict witness readiness must not schedule legacy control learning");
        assert!(result.unwrap().is_some_and(|(_, _, verdict)| verdict == Verdict::Substituted));
    }

    #[test]
    fn legacy_target_and_control_share_captured_cached_inputs() {
        const NAME: &str = "legacy-cached-inputs.invalid";
        struct Restore(Option<HashMap<usize, ProxySet>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                *PROXY_SET.lock().unwrap_or_else(|e| e.into_inner()) = self.0.take();
                forget_names(&[NAME]);
            }
        }
        let old = PROXY_SET.lock().unwrap().take();
        let _restore = Restore(old);
        forget_names(&[NAME]);
        let custom = PROVIDERS.iter().position(|p| matches!(&p.transport, Transport::Custom)).unwrap();
        let mut cached_a = crate::settings::Settings::default();
        cached_a.custom_dns = "10.2.3.4".into();
        let mut disk_b = cached_a.clone();
        disk_b.custom_dns = "10.2.3.5".into();
        let strict_b = witness_from_read(crate::settings::Read::Parsed(disk_b), DnsMissingPolicy::RequireSettings).unwrap();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let record = observations.clone();
        let fixture = ResolverFixture {
            provider: Arc::new(|_, query| dns_client::synth_reply(query, Some(Ipv4Addr::new(8, 8, 1, 1)), 60)),
            reference: Arc::new(|_, query| dns_client::synth_reply(query, Some(Ipv4Addr::new(1, 1, 1, 1)), 60).ok_or("fixture reply".into())),
            liveness: Arc::new(|_| true), learning: None,
        };
        let mut work = ResolverWork::new(thread::current());
        work.fixture = Some(Arc::new(fixture));
        work.legacy_settings = Some(cached_a);
        work.legacy_input_observer = Some(Arc::new(move |idx, query, inputs| {
            if idx == custom { record.lock().unwrap().push((dns_client::question_name(query).unwrap_or_default(), inputs.custom.clone())); }
        }));
        let query = dns_client::build_query(NAME, 0x2345);
        let result = resolve_upstream_with_work(&query, 0, true, Some(&work));
        let mut terminals = Vec::new();
        while work.has_unreceived() {
            work.receive_into(&mut terminals).unwrap();
            if work.has_unreceived() { thread::park_timeout(Duration::from_millis(1)); }
        }
        let observed = observations.lock().unwrap();
        assert!(observed.iter().any(|(name, _)| name == NAME));
        assert!(observed.iter().any(|(name, _)| CONTROL_NAMES.contains(&name.as_str())));
        assert!(observed.iter().all(|(_, custom)| *custom == vec![Ipv4Addr::new(10, 2, 3, 4)]));
        assert_eq!(strict_b.custom, vec![Ipv4Addr::new(10, 2, 3, 5)]);
        assert!(result.unwrap().is_some());
        assert!(current_candidates(&strict_b).unwrap().is_empty());
    }

    #[test]
    fn source_requires_selected_fresh_matching_custom_input() {
        let mut inputs = DnsSourceWitness { selected: vec![0], custom: vec![Ipv4Addr::new(10, 0, 0, 1)], missing_defaults: false, rotate: true };
        let now = Instant::now();
        let origin = DnsCandidateOrigin { provider: 0, inputs: inputs.clone(), observed: now, expires: now + PROXY_SET_TTL, target: None };
        let candidate = DnsCandidate { ip: Ipv4Addr::new(1, 1, 1, 1), origins: vec![origin] };
        assert!(source_is_current(&candidate, &inputs).unwrap());
        inputs.custom = vec![Ipv4Addr::new(10, 0, 0, 2)];
        assert!(!source_is_current(&candidate, &inputs).unwrap());
        inputs.custom = vec![Ipv4Addr::new(10, 0, 0, 1)];
        inputs.selected.clear();
        assert!(!source_is_current(&candidate, &inputs).unwrap());
    }

    #[test]
    fn legacy_entries_do_not_authorize_and_shared_candidate_keeps_sources() {
        let address = Ipv4Addr::new(1, 1, 1, 1);
        let now = Instant::now();
        let inputs = DnsSourceWitness { selected: vec![0, 1], custom: Vec::new(), missing_defaults: false, rotate: true };
        let mut sets = HashMap::new();
        sets.insert(0, ProxySet { legacy: Some((vec![address.into()], now)), witnessed: Vec::new() });
        assert!(candidates_from_sets(Some(&sets), &inputs).is_empty());
        for idx in 0..2 {
            sets.entry(idx).or_default().witnessed.push((address.into(), DnsCandidateOrigin { provider: idx, inputs: inputs.clone(), observed: now, expires: now + PROXY_SET_TTL, target: None }));
        }
        let candidates = candidates_from_sets(Some(&sets), &inputs);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].origins.len(), 2);
        let mut merged = DnsCandidate { ip: address, origins: vec![candidates[0].origins[0].clone()] };
        assert!(merged.merge(DnsCandidate { ip: address, origins: vec![candidates[0].origins[1].clone()] }));
        let one_enabled = DnsSourceWitness { selected: vec![1], ..inputs.clone() };
        assert!(!source_is_current(&merged, &one_enabled).unwrap());
        assert!(merged.merge(DnsCandidate { ip: address, origins: vec![DnsCandidateOrigin { provider: 1, inputs: one_enabled.clone(), observed: now, expires: now + PROXY_SET_TTL, target: None }] }));
        assert!(source_is_current(&merged, &one_enabled).unwrap());
        let none_enabled = DnsSourceWitness { selected: Vec::new(), ..inputs };
        assert!(!source_is_current(&candidates[0], &none_enabled).unwrap());
    }

    #[test]
    fn held_custom_query_uses_captured_inputs_after_settings_change() {
        let mut settings = crate::settings::Settings::default();
        settings.custom_dns = "10.2.3.4".into();
        let captured = witness_from_read(crate::settings::Read::Parsed(settings.clone()), DnsMissingPolicy::RequireSettings).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let worker = thread::spawn(move || query_custom_with_inputs(&captured.custom, Duration::from_secs(5), None, None, |ip, _| {
            entered_tx.send(ip).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            Some(vec![1])
        }));
        let observed = entered_rx.recv_timeout(Duration::from_secs(5));
        settings.custom_dns = "10.2.3.5".into();
        let changed = witness_from_read(crate::settings::Read::Parsed(settings), DnsMissingPolicy::RequireSettings).unwrap();
        let _ = resume_tx.send(());
        let result = worker.join();
        assert_eq!(observed.unwrap(), Ipv4Addr::new(10, 2, 3, 4));
        assert_eq!(changed.custom, vec![Ipv4Addr::new(10, 2, 3, 5)]);
        assert_eq!(result.unwrap(), Some(vec![1]));
    }

    #[test]
    fn target_evidence_requires_live_control_and_honest_reference() {
        let inputs = DnsSourceWitness { selected: vec![0], custom: Vec::new(), missing_defaults: false, rotate: true };
        let control_ip = Ipv4Addr::new(8, 8, 1, 1);
        let target_ip = Ipv4Addr::new(8, 8, 2, 2);
        let reference = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let now = Instant::now();
        let control = DnsCandidate { ip: control_ip, origins: vec![DnsCandidateOrigin { provider: 0, inputs: inputs.clone(), observed: now, expires: now + PROXY_SET_TTL, target: None }] };
        let answer = vec![IpAddr::V4(target_ip)];
        let ttl = Duration::from_secs(60);
        assert!(target_candidates(0, answer.clone(), &reference, &[], "example.test", &inputs, now, ttl).is_empty());
        assert!(target_candidates(0, answer.clone(), &[], &[control.clone()], "example.test", &inputs, now, ttl).is_empty());
        assert!(target_candidates(0, vec![reference[0]], &reference, &[control.clone()], "example.test", &inputs, now, ttl).is_empty());
        assert!(target_candidates(0, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 1, 1))], &reference, &[control.clone()], "example.test", &inputs, now, ttl).is_empty());
        assert_eq!(target_candidates(0, answer.clone(), &reference, &[control], "example.test", &inputs, now, ttl).len(), 1);
        assert_eq!(classify(&answer, &reference, &[IpAddr::V4(control_ip)]), Verdict::Substituted);
    }

    #[test]
    fn target_origin_expires_with_its_control_proof() {
        let now = Instant::now();
        let old = now.checked_sub(Duration::from_secs(1)).unwrap();
        let inputs = DnsSourceWitness { selected: vec![0], custom: Vec::new(), missing_defaults: false, rotate: true };
        let candidate = DnsCandidate { ip: Ipv4Addr::new(8, 8, 8, 8), origins: vec![DnsCandidateOrigin {
            provider: 0, inputs: inputs.clone(), observed: now, expires: old, target: Some("example.test".into()),
        }] };
        assert!(!source_is_current(&candidate, &inputs).unwrap());
    }

    #[test]
    fn target_answer_ttl_and_zero_ttl_bound_reuse() {
        let inputs = test_source_witness();
        let control = test_source_candidate(Ipv4Addr::new(8, 8, 1, 1), &inputs);
        let idx = inputs.selected[0];
        let now = Instant::now();
        let answers = vec![IpAddr::V4(Ipv4Addr::new(8, 8, 2, 2))];
        let reference = [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let candidates = target_candidates(idx, answers.clone(), &reference, &[control.clone()], "example.test", &inputs, now, Duration::from_secs(1));
        assert_eq!(candidates[0].origins[0].expires, now + Duration::from_secs(1));
        let zero = target_candidates(idx, answers, &reference, &[control], "example.test", &inputs, now, Duration::ZERO);
        assert!(!source_is_current(&zero[0], &inputs).unwrap());
    }

    #[test]
    fn candidate_merge_deduplicates_without_refresh_and_requires_full_witness() {
        let a = test_source_witness();
        let mut candidate = test_source_candidate(Ipv4Addr::new(8, 8, 8, 8), &a);
        let before = candidate.origins[0].observed;
        let original = candidate.clone();
        for _ in 0..1000 { assert!(candidate.merge(original.clone())); }
        assert_eq!(candidate.origins.len(), 1);
        assert_eq!(candidate.origins[0].observed, before);
        let mut b = a.clone();
        b.rotate = !b.rotate;
        assert!(!source_is_current(&candidate, &b).unwrap());
        assert!(source_is_current(&candidate, &a).unwrap());
        let mut sets = HashMap::new();
        sets.insert(a.selected[0], ProxySet { legacy: None, witnessed: vec![(IpAddr::V4(candidate.ip), candidate.origins[0].clone())] });
        assert!(candidates_from_sets(Some(&sets), &b).is_empty());
        assert_eq!(candidates_from_sets(Some(&sets), &a).len(), 1);
    }

    #[test]
    fn zero_and_short_reference_ttl_pair_with_provider_in_same_step() {
        for ttl in [0, 1] {
            let inputs = test_source_witness();
            let calls = Arc::new(AtomicUsize::new(0));
            let provider_calls = calls.clone();
            let fixture = ResolverFixture {
                provider: Arc::new(move |_, query| {
                    provider_calls.fetch_add(1, Ordering::Relaxed);
                    dns_client::synth_reply(query, Some(Ipv4Addr::new(1, 1, 1, 1)), 60)
                }),
                reference: Arc::new(move |_, query| dns_client::synth_reply(query, Some(Ipv4Addr::new(1, 1, 1, 1)), ttl).ok_or("invalid fixture".into())),
                liveness: Arc::new(|_| true), learning: None,
            };
            let mut work = ResolverWork::new(thread::current());
            work.fixture = Some(Arc::new(fixture));
            let mut cursor = DnsDiscoveryCursor { inputs: Some(inputs.clone()), host: "example.test".into(), pin: Some(0),
                control: Some(CONTROL_NAMES[0]), phase: DiscoveryPhase::ControlReference, ..Default::default() };
            let step = discover_next(&inputs, "example.test", &mut cursor, 0, Duration::from_secs(2), Some(&work)).unwrap();
            assert!(step.candidates.is_empty());
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            if ttl == 0 { assert!(matches!(cursor.phase, DiscoveryPhase::ControlReference)); }
        }
    }

    #[test]
    fn discovery_reports_cancellation_deadline_and_input_changes() {
        let inputs = DnsSourceWitness { selected: Vec::new(), custom: Vec::new(), missing_defaults: false, rotate: true };
        let mut cancelled = DnsDiscoveryCursor::default();
        let work = ResolverWork::new(thread::current());
        work.cancel();
        assert!(matches!(discover_next(&inputs, "example.test", &mut cancelled, 0, Duration::from_secs(1), Some(&work)), Err(DnsSourceError::Cancelled)));
        let mut expired = DnsDiscoveryCursor::default();
        assert!(matches!(discover_next(&inputs, "example.test", &mut expired, 0, Duration::ZERO, None), Err(DnsSourceError::Deadline)));
        assert_eq!(expired.position, 0);
        let mut bound = DnsDiscoveryCursor::default();
        assert!(discover_next(&inputs, "example.test", &mut bound, 0, Duration::from_secs(1), None).is_ok());
        assert!(matches!(discover_next(&inputs, "other.test", &mut bound, 0, Duration::from_secs(1), None), Err(DnsSourceError::InputChanged)));
        assert!(matches!(discover_next(&inputs, "example.test", &mut bound, 1, Duration::from_secs(1), None), Err(DnsSourceError::InputChanged)));
    }

    #[test]
    fn discovery_reloads_expired_reference_before_more_providers() {
        let inputs = DnsSourceWitness { selected: vec![0], custom: Vec::new(), missing_defaults: false, rotate: true };
        let mut cursor = DnsDiscoveryCursor { inputs: Some(inputs.clone()), host: "example.test".into(), pin: Some(0),
            control: Some(CONTROL_NAMES[0]), phase: DiscoveryPhase::TargetProviders, position: 0,
            reference: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))], reference_until: Some(Instant::now()), ..Default::default() };
        let step = discover_next(&inputs, "example.test", &mut cursor, 0, Duration::from_secs(1), None).unwrap();
        assert!(step.candidates.is_empty());
        assert!(matches!(cursor.phase, DiscoveryPhase::TargetReference));
    }

    #[test]
    fn discovery_advances_after_settled_timeout_to_later_live_provider() {
        let names = [PROVIDERS[0].name, PROVIDERS[1].name];
        let inputs = test_source_witness_with_providers(&names, true);
        let first = inputs.selected[0];
        let second = inputs.selected[1];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let fixture = ResolverFixture {
            provider: Arc::new(move |idx, query| {
                recorded.lock().unwrap().push(idx);
                dns_client::synth_reply(query, Some(Ipv4Addr::new(1, 1, 1, 1)), 60)
            }),
            reference: Arc::new(|_, query| dns_client::synth_reply(query, Some(Ipv4Addr::new(1, 1, 1, 1)), 60).ok_or("invalid fixture".into())),
            liveness: Arc::new(|_| true), learning: None,
        };
        let mut work = ResolverWork::new(thread::current());
        work.fixture = Some(Arc::new(fixture));
        work.force_expired_after_attempt = true;
        let mut cursor = DnsDiscoveryCursor { inputs: Some(inputs.clone()), host: "example.test".into(), pin: Some(0),
            control: Some(CONTROL_NAMES[0]), phase: DiscoveryPhase::TargetProviders, position: 0,
            reference: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            reference_until: Some(Instant::now() + Duration::from_secs(30)), ..Default::default() };
        assert!(matches!(discover_next(&inputs, "example.test", &mut cursor, 0, Duration::from_secs(1), Some(&work)), Err(DnsSourceError::SourceTimeout)));
        assert_eq!(cursor.position, 1);
        work.force_expired_after_attempt = false;
        let step = discover_next(&inputs, "example.test", &mut cursor, 0, Duration::from_secs(1), Some(&work)).unwrap();
        assert!(step.candidates.is_empty());
        assert_eq!(*calls.lock().unwrap(), vec![first, second]);
    }

    #[test]
    fn discovery_advances_reference_after_settled_timeout() {
        let inputs = test_source_witness();
        let fixture = ResolverFixture {
            provider: Arc::new(|_, query| dns_client::synth_reply(query, Some(Ipv4Addr::new(1, 1, 1, 1)), 60)),
            reference: Arc::new(|_, query| dns_client::synth_reply(query, Some(Ipv4Addr::new(1, 1, 1, 1)), 60).ok_or("invalid fixture".into())),
            liveness: Arc::new(|_| true), learning: None,
        };
        let mut work = ResolverWork::new(thread::current());
        work.fixture = Some(Arc::new(fixture));
        work.force_expired_after_attempt = true;
        let mut cursor = DnsDiscoveryCursor { inputs: Some(inputs.clone()), host: "example.test".into(), pin: Some(0),
            control: Some(CONTROL_NAMES[0]), phase: DiscoveryPhase::ControlReference, ..Default::default() };
        assert!(matches!(discover_next(&inputs, "example.test", &mut cursor, 0, Duration::from_secs(1), Some(&work)), Err(DnsSourceError::SourceTimeout)));
        assert_eq!(cursor.position, 1);
        assert!(cursor.reference.is_empty());
        work.force_expired_after_attempt = false;
        let step = discover_next(&inputs, "example.test", &mut cursor, 0, Duration::from_secs(1), Some(&work)).unwrap();
        assert!(step.candidates.is_empty());
    }

    #[test]
    fn substituted_connection_completes_before_post_winner_learning() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        const NAME: &str = "post-winner-learning.invalid";
        const LATER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
        struct RestoreSets(Option<HashMap<usize, ProxySet>>);
        impl Drop for RestoreSets {
            fn drop(&mut self) {
                *PROXY_SET.lock().unwrap_or_else(|error| error.into_inner()) = self.0.take();
                forget_names(&[NAME]);
            }
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = listener.local_addr().unwrap();
        let _restore_sets = RestoreSets(PROXY_SET.lock().unwrap().take());
        learn_proxy_addrs(0, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        forget_names(&[NAME]);
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let fixture = ResolverFixture {
            provider: Arc::new(|index, query| {
                (index == 0 && dns_client::question_name(query).as_deref() == Some(NAME))
                    .then(|| dns_client::synth_reply(query, Some(Ipv4Addr::LOCALHOST), 60).unwrap())
            }),
            reference: Arc::new(|_, query| dns_client::synth_reply(query, Some(Ipv4Addr::new(142, 250, 74, 10)), 60).ok_or("synthetic reply malformed".into())),
            liveness: Arc::new(|_| true),
            learning: Some(Arc::new(move || {
                let _ = held_tx.send(());
                if release_rx.lock().unwrap().recv_timeout(Duration::from_secs(15)).is_ok() {
                    learn_proxy_addrs(1, vec![IpAddr::V4(LATER)]);
                }
            })),
        };
        let fixture = Arc::new(fixture);
        let mut query_owner = ResolverWork::new(thread::current());
        query_owner.fixture = Some(fixture.clone());
        let query_work = Arc::new(query_owner);
        let mut warm_owner = ResolverWork::new(thread::current());
        warm_owner.fixture = Some(fixture.clone());
        let warm_work = Arc::new(warm_owner);
        let maintenance_work = warm_work.clone();
        let maintenance = thread::spawn(move || warm_owned(&[], 0, &maintenance_work));
        let learning_entered = held_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        let worker_work = query_work.clone();
        let outer = learning_entered.then(|| thread::spawn(move || -> Result<Verdict, String> {
            let (addresses, _, verdict) = direct_addrs_owned(NAME, 0, &worker_work)?
                .ok_or_else(|| "fixture did not resolve".to_string())?;
            if verdict != Verdict::Substituted || !addresses.contains(&Ipv4Addr::LOCALHOST) {
                return Err("fixture winner was not the classified loopback answer".into());
            }
            let candidates = addresses.into_iter().map(|ip| SocketAddr::from((ip, target.port()))).collect();
            let mut stream = crate::proxy::connect_fixture_addrs(candidates, Duration::from_secs(2))?;
            stream.write_all(b"ok").map_err(|e| e.to_string())?;
            Ok(verdict)
        }));
        let deadline = Instant::now() + QUERY_TIMEOUT + RACE_BUDGET;
        let mut received = false;
        while learning_entered && Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let mut bytes = [0; 2];
                received = stream.read_exact(&mut bytes).is_ok() && &bytes == b"ok";
                break;
            }
            thread::park_timeout(Duration::from_millis(10));
        }
        let finish_until = Instant::now() + Duration::from_secs(1);
        while received && outer.as_ref().is_some_and(|worker| !worker.is_finished()) && Instant::now() < finish_until {
            thread::park_timeout(Duration::from_millis(10));
        }
        let request_finished_before_cancel = outer.as_ref().is_some_and(|worker| worker.is_finished());
        query_work.cancel();
        let learning_was_held = !maintenance.is_finished() && !warm_work.is_cancelled();
        let absent_while_held = !known_proxy_addrs(1).contains(&IpAddr::V4(LATER));
        let release = release_tx.send(());
        let result = outer.map(|outer| outer.join());
        let maintenance_result = maintenance.join();
        let mut terminals = Vec::new();
        for work in [&query_work, &warm_work] {
            while work.has_unreceived() {
                work.receive_into(&mut terminals).unwrap();
                if work.has_unreceived() { thread::park_timeout(Duration::from_millis(10)); }
            }
        }
        let learned_after_warm = known_proxy_addrs(1).contains(&IpAddr::V4(LATER));
        let mut later_owner = ResolverWork::new(thread::current());
        later_owner.fixture = Some(fixture);
        let later = direct_addrs_owned(NAME, 0, &later_owner);
        while later_owner.has_unreceived() {
            later_owner.receive_into(&mut terminals).unwrap();
            if later_owner.has_unreceived() { thread::park_timeout(Duration::from_millis(10)); }
        }
        let mut facts = Vec::new();
        let mut panics = Vec::new();
        let receiving = receive_terminals(&mut terminals, &mut facts, &mut panics);
        assert!(learning_entered && request_finished_before_cancel && query_work.is_cancelled() && learning_was_held && release.is_ok());
        assert!(maintenance_result.unwrap().is_ok());
        assert!(result.unwrap().unwrap().is_ok());
        assert!(receiving.is_ok() && panics.is_empty());
        assert!(absent_while_held && learned_after_warm);
        assert!(later.unwrap().is_some_and(|(addresses, _, verdict)| verdict == Verdict::Substituted && addresses.contains(&LATER)));
        assert!(received, "connection did not complete while post-winner learning was held (entered={learning_was_held})");
    }

    #[test]
    fn owned_race_delivers_winner_before_held_loser_and_receives_original_panic() {
        const NAME: &str = "owned-resolver-custody.invalid";
        assert!(PROVIDERS.len() >= 2);
        forget_names(&[NAME]);
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let (panic_tx, panic_rx) = mpsc::channel();
        let liveness_calls = Arc::new(AtomicUsize::new(0));
        let calls = liveness_calls.clone();
        let fixture = ResolverFixture {
            provider: Arc::new(move |index, query| {
                if dns_client::question_name(query).as_deref() != Some(NAME) { return None; }
                if index == 1 {
                    held_tx.send(()).expect("retained held-start receiver");
                    release_rx.lock().unwrap().recv().expect("creator releases held racer");
                    let payload = std::panic::catch_unwind(|| std::panic::panic_any(947u64)).unwrap_err();
                    panic_tx.send(payload.as_ref() as *const _ as *const () as usize).expect("retained panic identity receiver");
                    std::panic::resume_unwind(payload);
                }
                (index == 0).then(|| dns_client::synth_reply(query, Some(Ipv4Addr::new(192, 0, 2, 47)), 60).unwrap())
            }),
            reference: Arc::new(|_, query| dns_client::synth_reply(query, Some(Ipv4Addr::new(142, 250, 74, 10)), 60).ok_or("synthetic reply malformed".into())),
            liveness: Arc::new(move |_| { calls.fetch_add(1, Ordering::SeqCst); true }),
            learning: None,
        };
        let mut owner = ResolverWork::new(thread::current());
        owner.fixture = Some(Arc::new(fixture));
        let work = Arc::new(owner);
        // This is the same registration helper as the race's four child kinds.
        let live = dead_addrs_with_work(&[IpAddr::V4(Ipv4Addr::new(203, 0, 113, 247))], true, None, Some(&work));
        let (reply_tx, reply_rx) = mpsc::channel();
        let query_work = work.clone();
        let started = thread::Builder::new().spawn(move || {
            let query = dns_client::build_query(NAME, 0x4747);
            let result = resolve_best_owned(&query, 0, &query_work);
            let delivery = reply_tx.send(result.as_ref().ok().and_then(|reply| reply.as_ref().map(|reply| reply.0.clone())));
            (result, delivery)
        });
        let outer = match started {
            Ok(outer) => outer,
            Err(error) => {
                work.cancel();
                let mut retained = Vec::new();
                while work.has_unreceived() {
                    let _ = work.receive_into(&mut retained);
                    if work.has_unreceived() { thread::park_timeout(Duration::from_millis(50)); }
                }
                panic!("outer fixture worker did not start after nested settlement: {error}");
            }
        };
        let held_started = held_rx.recv_timeout(QUERY_TIMEOUT);
        let early_reply = reply_rx.recv_timeout(QUERY_TIMEOUT + RACE_BUDGET);
        let until = Instant::now() + QUERY_TIMEOUT;
        while !outer.is_finished() && Instant::now() < until { thread::park_timeout(Duration::from_millis(50)); }
        let outer_done_early = outer.is_finished();
        let mut terminals = Vec::new();
        let mut receiving_error = work.poll_finished().err();
        let joined_still_owed = work.has_unreceived() && work.state.lock().unwrap().entries.iter()
            .any(|entry| matches!(entry.state, ResolverEntryState::Finished(Some(_))));
        if let Err(error) = work.receive_into(&mut terminals) { receiving_error.get_or_insert(error); }
        let pending_after_outer = work.has_unreceived();
        work.cancel();
        let pending_after_cancel = work.has_unreceived();
        let admission_closed = work.spawn(ResolverChildKind::Provider(0), |_| ResolverChildResult {
            observation: ResolverObservation::NoAnswer, delivery: ResolverDelivery::NoMessage, cancelled: false,
        }).is_err();
        // Always release/receive resources before any observation assertion.
        let release = release_tx.send(());
        while !outer.is_finished() { thread::park_timeout(Duration::from_millis(50)); }
        let outer = outer.join();
        while work.has_unreceived() {
            if let Err(error) = work.receive_into(&mut terminals) { receiving_error.get_or_insert(error); }
            if work.has_unreceived() { thread::park_timeout(Duration::from_millis(50)); }
        }
        let original_address = panic_rx.recv_timeout(QUERY_TIMEOUT);
        forget_names(&[NAME]);
        assert!(live.unwrap().is_empty());
        assert_eq!(liveness_calls.load(Ordering::SeqCst), 1);
        held_started.unwrap();
        release.unwrap();
        assert!(receiving_error.is_none());
        let packet = early_reply.unwrap().expect("actual resolver winner delivered");
        assert!(dns_client::answer_addrs(&packet).contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 47))));
        assert!(outer_done_early && joined_still_owed && pending_after_outer && pending_after_cancel && admission_closed);
        let (semantic, delivery) = outer.unwrap();
        assert!(semantic.unwrap().is_some());
        assert!(delivery.is_ok());
        assert!(terminals.iter().any(|terminal| matches!(terminal.kind, ResolverChildKind::Liveness(_))));
        assert!(terminals.iter().any(|terminal| matches!(&terminal.result, ResolverTermination::Finished(Ok(result)) if matches!(result.observation, ResolverObservation::Reply(_)))));
        let expected = original_address.unwrap();
        let mut facts = Vec::new();
        let mut panics = Vec::new();
        receive_terminals(&mut terminals, &mut facts, &mut panics).unwrap();
        assert!(terminals.is_empty() && !work.has_unreceived());
        assert_eq!(panics.len(), 1);
        assert_eq!(panics[0].as_ref() as *const _ as *const () as usize, expected);
        assert_eq!(panics[0].downcast_ref::<u64>(), Some(&947));
        assert!(facts.iter().any(|fact| fact.contains("reply_bytes=")));
    }

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    #[test]
    fn served_verdicts_are_kept_per_name_case_folded() {
        note_served("Daily-Cloudcode-PA.googleapis.com.", Verdict::Substituted);
        assert_eq!(
            served_verdict("daily-cloudcode-pa.googleapis.com"),
            Some(Verdict::Substituted)
        );
        assert_eq!(served_verdict("nobody.asked.example"), None);
    }

    #[test]
    fn forgetting_a_name_drops_its_choice_and_its_answers() {
        let name = "forget-me.example";
        remember_choice((name.to_string(), QTYPE_A), 0, Verdict::Substituted);
        assert!(cached_choice(&(name.to_string(), QTYPE_A)).is_some());
        let query = dns_client::build_query(name, 0x1111);
        let mut reply = query.clone();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 1;
        reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1]);
        remember_answer(&query, &reply, "test", Verdict::Substituted, true);
        assert!(cached_answer(&query, false, false).is_some());

        forget_names(&["FORGET-ME.example"]);
        assert!(cached_choice(&(name.to_string(), QTYPE_A)).is_none());
        assert!(cached_answer(&query, false, false).is_none());
        assert!(
            cached_answer(&query, true, false).is_none(),
            "not served as a stale substitution either"
        );
        // The shape survives for the warm loop to replay.
        let shapes = warm_queries(&[name]);
        assert!(
            shapes.iter().any(|q| answer_key(q) == answer_key(&query)),
            "the client's query shape must still be warmed"
        );
    }

    #[test]
    fn only_an_a_answer_records_a_served_verdict() {
        let name = "served-a.example";
        let a = dns_client::build_query(name, 1);
        let mut aaaa = a.clone();
        let n = aaaa.len();
        aaaa[n - 3] = 28; // qtype AAAA
        let hit = Some((Vec::new(), "test", Verdict::Substituted));
        note_served_a(&a, &hit);
        assert_eq!(served_verdict(name), Some(Verdict::Substituted));
        let hit = Some((Vec::new(), "test", Verdict::Passthrough));
        note_served_a(&aaaa, &hit);
        assert_eq!(
            served_verdict(name),
            Some(Verdict::Substituted),
            "an AAAA passthrough must not overwrite the A verdict"
        );
    }

    fn udp_providers() -> Vec<&'static Provider> {
        PROVIDERS
            .iter()
            .filter(|p| matches!(p.transport, Transport::Udp))
            .collect()
    }

    #[test]
    fn custom_dns_takes_plain_ipv4_and_refuses_loops_and_junk() {
        let got = parse_custom_dns("77.88.8.8, 77.88.8.8;1.1.1.1  127.0.0.53 0.0.0.0 junk 224.0.0.1");
        assert_eq!(
            got,
            vec!["77.88.8.8".parse::<Ipv4Addr>().unwrap(), "1.1.1.1".parse().unwrap()]
        );
        assert!(parse_custom_dns("").is_empty());
    }

    /// The slot carries no address of its own (like a DoH provider): it must never
    /// leak into an NRPT nameserver list, and it must be in the pool.
    #[test]
    fn the_custom_slot_is_in_the_pool_and_offers_no_nameserver() {
        let p = PROVIDERS
            .iter()
            .find(|p| matches!(p.transport, Transport::Custom))
            .expect("a custom slot");
        assert!(p.v4.is_empty() && p.v6.is_empty());
        assert!(!fallback_v4().iter().any(|a| a.is_empty()));
    }

    #[test]
    fn every_udp_provider_has_at_least_one_address() {
        assert!(!PROVIDERS.is_empty());
        for p in udp_providers() {
            assert!(!p.v4.is_empty(), "{} has no IPv4 address", p.name);
            for a in p.v4 {
                assert!(a.parse::<Ipv4Addr>().is_ok(), "{} is not an address", a);
            }
        }
    }

    /// The NRPT rule takes one address per provider, so a provider outage falls
    /// through to a different service rather than to its own dead sibling.
    #[test]
    fn the_fallback_list_is_one_address_per_udp_provider() {
        let fallback = fallback_v4();
        let udp = udp_providers();
        assert_eq!(fallback.len(), udp.len());
        for (i, p) in udp.iter().enumerate() {
            assert_eq!(fallback[i], p.v4[0]);
        }
    }

    /// The invariant a DoH provider lives or dies by.
    ///
    /// `fallback_v4`/`all_v6` feed NRPT nameserver lists, and Windows can only be
    /// pointed at something that answers UDP:53. A DoH endpoint answers nothing
    /// there - measured: both of dns-ai.ru's addresses time out on 53 - so if one
    /// ever reached a rule, that name would get a nameserver that never replies
    /// and the whole rule would hang on it. Enforced structurally by empty
    /// `v4`/`v6`, which is easy to undo by accident while "filling in" a provider
    /// entry, so it is asserted rather than commented.
    #[test]
    fn a_doh_provider_is_never_offered_as_a_nameserver() {
        let listed: Vec<&str> = fallback_v4().into_iter().chain(all_v6()).collect();
        for p in PROVIDERS {
            let Transport::Doh(endpoint) = p.transport else {
                continue;
            };
            assert!(
                p.v4.is_empty() && p.v6.is_empty(),
                "{} speaks DoH, so its address list must stay empty",
                p.name
            );
            for a in endpoint.addrs {
                assert!(
                    !listed.contains(a),
                    "{} would be handed to Windows as a nameserver",
                    a
                );
            }
        }
    }

    /// The flag defaults to "no tunnel", which is the behaviour every existing
    /// machine already has: a relay that never learns the answer keeps
    /// substituting exactly as before rather than quietly standing down.
    ///
    /// The region-400 override lives in the same test because it shares this
    /// flag: while forced, the relay substitutes even though the tunnel verdict
    /// says stand down, and the force expires on its own.
    #[test]
    fn the_vpn_flag_defaults_to_off_and_round_trips() {
        assert!(!vpn_is_active(), "должно быть выключено по умолчанию");
        set_vpn_active(true);
        assert!(vpn_is_active());

        force_substitution(Duration::from_millis(80));
        assert!(substitution_forced());
        assert!(!vpn_is_active(), "forced: the tunnel no longer decides");
        assert!(tunnel_carries_client(), "the raw verdict is still readable");
        std::thread::sleep(Duration::from_millis(120));
        assert!(!substitution_forced());
        assert!(
            vpn_is_active(),
            "the window closed; the tunnel decides again"
        );

        set_vpn_active(false);
        assert!(!vpn_is_active());
    }

    /// Preference is for the two gate names and nothing else. Widening it would
    /// put a bounded wait on names that never needed one.
    #[test]
    fn only_the_gate_names_have_a_preferred_provider() {
        let doh = PROVIDERS
            .iter()
            .position(|p| matches!(p.transport, Transport::Doh(_)))
            .expect("a DoH provider");
        assert_eq!(preferred_provider("cloudcode-pa.googleapis.com"), Some(doh));
        assert_eq!(
            preferred_provider("daily-cloudcode-pa.googleapis.com"),
            Some(doh)
        );
        // A question name may arrive rooted or in any case; neither changes it.
        assert_eq!(
            preferred_provider("CloudCode-PA.GoogleAPIs.com."),
            Some(doh)
        );
        for other in [
            "generativelanguage.googleapis.com",
            "jetski-webchannel.googleapis.com",
            "accounts.google.com",
            "",
        ] {
            assert_eq!(preferred_provider(other), None, "{}", other);
        }
    }

    /// 250 ms cannot cover a TLS handshake, so a cached choice pointing at the
    /// DoH provider would fail on the fast path every time, be forgotten, and
    /// re-race - the fast path becoming the slow one.
    #[test]
    fn the_fast_path_gives_a_doh_provider_room_to_answer() {
        let doh = PROVIDERS
            .iter()
            .find(|p| matches!(p.transport, Transport::Doh(_)))
            .expect("a DoH provider");
        let udp = PROVIDERS
            .iter()
            .find(|p| matches!(p.transport, Transport::Udp))
            .expect("a UDP provider");
        assert_eq!(one_shot_floor(doh, FAST_PATH_TIMEOUT), DOH_FAST_TIMEOUT);
        assert_eq!(one_shot_floor(udp, FAST_PATH_TIMEOUT), FAST_PATH_TIMEOUT);
        // A caller that already budgeted more keeps it.
        assert_eq!(one_shot_floor(doh, QUERY_TIMEOUT), QUERY_TIMEOUT);
        // And the whole thing still fits inside the second Windows waits (I23).
        assert!(DOH_FAST_TIMEOUT < Duration::from_secs(1));
        assert!(PREFERRED_GRACE <= RACE_BUDGET);
    }

    /// A DoH endpoint's addresses still have to be addresses: they are dialled
    /// directly, precisely so the resolver is reachable before DNS works.
    #[test]
    fn doh_endpoints_carry_parsable_addresses() {
        for p in PROVIDERS {
            if let Transport::Doh(endpoint) = p.transport {
                assert!(!endpoint.addrs.is_empty(), "{} has no address", p.name);
                for a in endpoint.addrs {
                    assert!(a.parse::<IpAddr>().is_ok(), "{} is not an address", a);
                }
                assert!(endpoint.path.starts_with('/'), "path must be absolute");
            }
        }
    }

    /// A reference resolver must never be a provider: it exists to show what an
    /// unsubstituted answer looks like.
    #[test]
    fn reference_resolvers_are_not_providers() {
        let providers: Vec<&str> = PROVIDERS
            .iter()
            .flat_map(|p| p.v4.iter().copied())
            .collect();
        for r in REFERENCE_V4 {
            assert!(!providers.contains(r), "{} is on both lists", r);
        }
    }

    /// The proxy addresses the three providers were measured handing out. In
    /// production these are learned at runtime from `CONTROL_NAME`; here they
    /// stand in for what that probe would have found.
    fn learned_proxies() -> Vec<IpAddr> {
        vec![
            v4("87.228.47.204"),
            v4("45.88.174.254"),
            v4("37.230.192.51"),
        ]
    }

    #[test]
    fn the_same_netblock_is_a_passthrough() {
        // What xbox-dns now answers for cloudcode-pa: Google's own edge, a
        // different host inside the same /16 the reference gave.
        let candidate = [v4("172.217.113.4")];
        let reference = [v4("172.217.114.4"), v4("172.217.112.4")];
        assert_eq!(
            classify(&candidate, &reference, &learned_proxies()),
            Verdict::Passthrough
        );
    }

    #[test]
    fn a_proxy_address_is_a_substitution() {
        let google = [v4("172.217.118.4")];
        for proxy in learned_proxies() {
            assert_eq!(
                classify(&[proxy], &google, &learned_proxies()),
                Verdict::Substituted,
                "{:?} is a measured proxy address",
                proxy
            );
        }
    }

    /// The false positive the proxy set exists to kill: two different Google
    /// netblocks are not a substitution. Nothing about the addresses themselves
    /// says so - only knowing what the provider's proxy looks like does.
    #[test]
    fn another_google_netblock_is_only_a_sibling() {
        assert_eq!(
            classify(
                &[v4("173.194.220.95")],
                &[v4("64.233.163.95")],
                &learned_proxies()
            ),
            Verdict::Sibling
        );
        assert!(rank(Verdict::Sibling) < rank(Verdict::Substituted));
    }

    /// Before the control probe has ever run there is nothing to recognise a
    /// proxy by, so "differs from the honest answer" is taken at face value -
    /// the behaviour the tool had before, which never prefers a passthrough.
    #[test]
    fn without_a_learned_proxy_any_difference_counts() {
        assert_eq!(
            classify(&[v4("173.194.220.95")], &[v4("64.233.163.95")], &[]),
            Verdict::Substituted
        );
        // Still not enough to call an identical answer substituted.
        assert_eq!(
            classify(&[v4("172.217.113.4")], &[v4("172.217.114.4")], &[]),
            Verdict::Passthrough
        );
    }

    /// A DPI-stubbed reference must not turn every answer into a substitution.
    #[test]
    fn a_stubbed_reference_is_no_reference() {
        let stub = [v4("8.6.112.0"), v4("8.47.69.0")];
        assert_eq!(
            classify(&[v4("172.217.118.4")], &stub, &learned_proxies()),
            Verdict::Unknown
        );
        assert_eq!(
            classify(&[v4("87.228.47.204")], &stub, &learned_proxies()),
            Verdict::Unknown
        );
    }

    #[test]
    fn nothing_to_compare_is_unknown() {
        assert_eq!(classify(&[], &[v4("8.8.8.8")], &[]), Verdict::Unknown);
        assert_eq!(classify(&[v4("87.228.47.204")], &[], &[]), Verdict::Unknown);
        // An AAAA answer against an A-only reference says nothing.
        let v6: IpAddr = "2a00:ab00:1233:26::50".parse::<IpAddr>().unwrap();
        assert_eq!(
            classify(&[v6], &[v4("172.217.118.4")], &[]),
            Verdict::Unknown
        );
    }

    #[test]
    fn a_substitution_outranks_everything_else() {
        assert!(rank(Verdict::Substituted) > rank(Verdict::Unknown));
        assert!(rank(Verdict::Unknown) > rank(Verdict::Sibling));
        assert!(rank(Verdict::Sibling) > rank(Verdict::Passthrough));
    }

    /// The reason the whole module exists: the answer that broke the tool must
    /// be recognised as not-a-substitution, so the next provider gets a turn.
    #[test]
    fn the_regression_that_broke_the_tool_is_detected() {
        let xbox_cloudcode = [v4("172.217.113.4")];
        let google = [v4("172.217.114.4")];
        assert_ne!(
            classify(&xbox_cloudcode, &google, &learned_proxies()),
            Verdict::Substituted
        );
    }

    /// The union is what makes a rotating provider recognisable: geohide serves
    /// its proxy from three addresses in three unrelated /16s, so one probe only
    /// ever sees part of the set.
    #[test]
    fn learned_proxy_addresses_accumulate() {
        let idx = PROVIDERS.len() + 41; // a slot no real provider uses
        learn_proxy_addrs(idx, vec![v4("95.182.120.241")]);
        learn_proxy_addrs(idx, vec![v4("37.230.192.51"), v4("95.182.120.241")]);
        let known = known_proxy_addrs(idx);
        assert_eq!(known.len(), 2, "duplicates must not pile up: {:?}", known);
        assert!(known.contains(&v4("37.230.192.51")));

        // An answer served from the address the first probe missed is still
        // recognised as that provider's proxy.
        assert_eq!(
            classify(&[v4("37.230.192.51")], &[v4("172.217.118.4")], &known),
            Verdict::Substituted
        );
    }

    /// The control names are the one place this tool announces itself to a
    /// provider, and the source is public. Several, from unrelated operators,
    /// so no single upstream change - or a rule aimed at this tool - takes the
    /// whole learning mechanism out.
    #[test]
    fn control_names_are_several_and_not_one_operator() {
        assert!(
            CONTROL_NAMES.len() >= 3,
            "one control name is a signature, not a probe"
        );
        let non_google = CONTROL_NAMES
            .iter()
            .filter(|n| !n.contains("google."))
            .count();
        assert!(
            non_google >= 2,
            "the set must survive a Google-side change: {:?}",
            CONTROL_NAMES
        );
        // The DPI on the ISP link stubs this one, so its reference is unusable.
        assert!(!CONTROL_NAMES.contains(&"grok.com"));
    }

    /// An empty learning round must not overwrite what is already known, or a
    /// provider that failed to answer the control probe once would lose its set.
    #[test]
    fn an_empty_probe_does_not_erase_the_set() {
        let idx = PROVIDERS.len() + 42;
        learn_proxy_addrs(idx, vec![v4("87.228.47.204")]);
        learn_proxy_addrs(idx, vec![]);
        assert_eq!(known_proxy_addrs(idx), vec![v4("87.228.47.204")]);
    }

    /// Live: what the NRPT fallback list will be built from for each routed
    /// name. `daily-cloudcode-pa` must come back with geohide only - the bug
    /// was xbox-dns/comss (which return genuine Google for it) sitting in that
    /// list and leaking. Run VPN-off.
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn substituting_addrs_excludes_passthrough_providers() {
        for name in [
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "antigravity-unleash.goog",
        ] {
            let subs = substituting_addrs(name, 0);
            println!("{:<38} substituted by {:?}", name, subs);
            // Whatever is returned must be a real provider address, never a
            // reference resolver - a reference in the fallback would be a leak.
            for s in &subs {
                assert!(
                    !REFERENCE_V4.contains(s),
                    "{} is a reference resolver, not a substituter",
                    s
                );
            }
        }
    }

    /// Live: the whole pool, provider by provider and name by name — what each
    /// answered, what proxy set was learned for it, and the verdict that follows.
    ///
    /// This is the quarterly re-measurement P14 asks for, in one command. It
    /// asserts nothing about *who* substitutes what, because that is exactly the
    /// thing that changes without warning and must not be pinned in a test (N15:
    /// a measurement recorded as a property of a host outlived the measurement by
    /// months). It only pins the two rules that are ours: an NRPT fallback never
    /// names a reference resolver, and never names a DoH provider (I49).
    ///
    ///     cargo test the_pool_measured_provider_by_provider -- --ignored --nocapture
    #[test]
    #[ignore = "needs a live network, VPN off; run with --ignored"]
    fn the_pool_measured_provider_by_provider() {
        const NAMES: &[&str] = &[
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
        ];

        ensure_proxy_sets_learned(0);
        println!("learned proxy sets:");
        for (idx, p) in PROVIDERS.iter().enumerate() {
            println!("  {:<12} {:?}", p.name, known_proxy_addrs(idx));
        }

        for name in NAMES {
            let query = dns_client::build_query(name, 0x6767);
            let mut reference: Vec<IpAddr> = Vec::new();
            for server in REFERENCE_V4 {
                if let Ok(ip) = server.parse::<Ipv4Addr>() {
                    if let Ok(reply) = dns_client::query_raw_via(&query, ip, 0, QUERY_TIMEOUT) {
                        reference.extend(dns_client::answer_addrs(&reply));
                    }
                }
            }
            println!("\n{}\n  reference {:?}", name, reference);
            for (idx, p) in PROVIDERS.iter().enumerate() {
                let known = known_proxy_addrs(idx);
                match ask_provider(p, &query, 0, QUERY_TIMEOUT) {
                    None => println!("  {:<12} нет ответа", p.name),
                    Some(reply) => {
                        let addrs = dns_client::answer_addrs(&reply);
                        // Wire counts alongside the parsed addresses: an empty
                        // list with ANCOUNT>0 is a parse problem, an empty list
                        // with ANCOUNT=0 is the provider (G24 was the first).
                        let rcode = reply.get(3).map_or(0xFF, |b| b & 0x0F);
                        let ancount = if reply.len() >= 8 {
                            u16::from_be_bytes([reply[6], reply[7]])
                        } else {
                            0
                        };
                        // Both verdicts: the bootstrap one the relay may act on,
                        // and the stricter one an NRPT fallback needs.
                        println!(
                            "  {:<12} rcode={} an={} len={} {:?} -> race {:?}, rule {}",
                            p.name,
                            rcode,
                            ancount,
                            reply.len(),
                            addrs,
                            classify(&addrs, &reference, &known),
                            if known.is_empty() {
                                "исключён (прокси-набор не выучен)".to_string()
                            } else {
                                format!("{:?}", classify(&addrs, &reference, &known))
                            }
                        );
                    }
                }
            }
            for s in substituting_addrs(name, 0) {
                assert!(!REFERENCE_V4.contains(&s), "{} is a reference resolver", s);
                assert!(
                    PROVIDERS
                        .iter()
                        .any(|p| p.v4.contains(&s) && !matches!(p.transport, Transport::Doh(_))),
                    "{} is not a UDP provider address (I49)",
                    s
                );
            }
        }
    }

    /// Live end-to-end: races the real providers and prints what each answered.
    /// Must run with the VPN off, or every provider sees a foreign client and
    /// substitutes nothing.
    #[test]
    #[ignore = "needs a live network; run with --ignored"]
    fn races_the_real_providers() {
        for name in [
            "generativelanguage.googleapis.com",
            "cloudcode-pa.googleapis.com",
        ] {
            let mut query = vec![0x77, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            for label in name.split('.') {
                query.push(label.len() as u8);
                query.extend_from_slice(label.as_bytes());
            }
            query.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);

            match resolve_best(&query, 0) {
                Some((reply, provider, verdict)) => {
                    println!(
                        "{:<38} {:?} via {} -> {:?}",
                        name,
                        verdict,
                        provider,
                        dns_client::answer_addrs(&reply)
                    );
                }
                None => println!("{:<38} no provider answered", name),
            }
        }
    }

    /// Header + question for `name`, shaped the way a real client asks.
    fn query_for(name: &str, id: u16, edns: bool) -> Vec<u8> {
        let mut q = vec![0, 0, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q[0..2].copy_from_slice(&id.to_be_bytes());
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);
        if edns {
            q[11] = 1; // ARCOUNT
            q.extend_from_slice(&[0, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0x00, 0x00]);
        }
        q
    }

    /// One A record for `name`, TTL 60, exactly the shape geohide answers with.
    fn reply_for(name: &str, id: u16, addr: [u8; 4]) -> Vec<u8> {
        let mut b = query_for(name, id, false);
        b[2] = 0x81;
        b[3] = 0x80;
        b[7] = 1; // ANCOUNT
        b.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04]);
        b.extend_from_slice(&addr);
        b
    }

    /// Serialises every test that shares the process-wide answer cache.
    ///
    /// This used to be a bare call, and cargo runs tests in parallel threads of
    /// one process: two of them would each wipe the map the other had just
    /// written, and whichever asserted second failed. Roughly one run in ten, and
    /// it read exactly like a product bug. Holding the guard for the length of a
    /// test is what makes "nothing else may be in the cache" true rather than
    /// merely intended.
    static CACHE_TESTS: Mutex<()> = Mutex::new(());

    #[must_use = "hold the guard for the whole test, or the cache is shared again"]
    fn clear_answers() -> std::sync::MutexGuard<'static, ()> {
        // A panicking test poisons this, and the next one still has to run: what
        // it guards is wiped by every caller anyway, so the poison carries no
        // information worth propagating.
        let guard = CACHE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut g) = ANSWERS.lock() {
            *g = None;
        }
        guard
    }

    #[test]
    fn a_cached_answer_is_restamped_for_the_client_that_asks() {
        let _cache = clear_answers();
        let name = "cache-restamp.example";
        let stored = reply_for(name, 0x1111, [45, 155, 204, 190]);
        remember_answer(
            &query_for(name, 0x1111, false),
            &stored,
            "geohide.ru",
            Verdict::Substituted,
            true,
        );

        // A different client, a different transaction id, the same question.
        let asking = query_for(name, 0xBEEF, false);
        let (reply, provider, verdict) = cached_answer(&asking, false, true).unwrap();
        assert_eq!(&reply[0..2], &[0xBE, 0xEF]);
        assert_eq!(provider, "geohide.ru");
        assert_eq!(verdict, Verdict::Substituted);
        assert_eq!(
            dns_client::answer_addrs(&reply),
            dns_client::answer_addrs(&stored)
        );
    }

    /// A reply is only an answer to the exact question that fetched it. Windows
    /// sends EDNS0; a cache keyed loosely enough to serve that reply to a query
    /// without an OPT record would be handing back a malformed message.
    #[test]
    fn a_differently_shaped_question_is_a_miss() {
        let _cache = clear_answers();
        let name = "cache-shape.example";
        remember_answer(
            &query_for(name, 1, false),
            &reply_for(name, 1, [1, 2, 3, 4]),
            "geohide.ru",
            Verdict::Substituted,
            true,
        );
        assert!(cached_answer(&query_for(name, 2, false), false, true).is_some());
        assert!(cached_answer(&query_for(name, 2, true), false, true).is_none());
    }

    /// Serving a stored reply with its original TTL would keep Windows on it for
    /// the cache window *plus* the resolver's TTL, i.e. past the minute in which
    /// these providers may move the address.
    #[test]
    fn a_served_answer_carries_the_time_it_already_spent_in_the_cache() {
        let _cache = clear_answers();
        let name = "cache-ttl.example";
        let query = query_for(name, 3, false);
        remember_answer(
            &query,
            &reply_for(name, 3, [1, 2, 3, 4]),
            "geohide.ru",
            Verdict::Substituted,
            true,
        );
        if let Ok(mut g) = ANSWERS.lock() {
            let entry = g.as_mut().unwrap().get_mut(&answer_key(&query).unwrap());
            let entry = entry.unwrap();
            entry.at = Instant::now() - Duration::from_secs(20);
        }
        let (reply, _, _) = cached_answer(&query, false, true).unwrap();
        assert_eq!(dns_client::answer_ttl(&reply), Some(40));
    }

    /// Only a substitution is worth serving stale. Keeping a passthrough alive
    /// would hold the region gate shut, and there the NRPT fallback - built from
    /// measured substituters (I22) - is the better thing to fall through to.
    #[test]
    fn only_a_substitution_survives_past_its_freshness() {
        let _cache = clear_answers();
        for (name, verdict, expected) in [
            ("stale-sub.example", Verdict::Substituted, true),
            ("stale-pass.example", Verdict::Passthrough, false),
        ] {
            let query = query_for(name, 4, false);
            remember_answer(
                &query,
                &reply_for(name, 4, [1, 2, 3, 4]),
                "geohide.ru",
                verdict,
                true,
            );
            if let Ok(mut g) = ANSWERS.lock() {
                let key = answer_key(&query).unwrap();
                g.as_mut().unwrap().get_mut(&key).unwrap().at =
                    Instant::now() - ANSWER_TTL - Duration::from_secs(5);
            }
            assert!(cached_answer(&query, false, true).is_none(), "{}", name);
            assert_eq!(
                cached_answer(&query, true, true).is_some(),
                expected,
                "{}",
                name
            );
        }
    }

    /// The whole point of warming: it has to re-ask the shape the client sends,
    /// or every real query still goes upstream while the cache serves nobody.
    #[test]
    fn warming_replays_the_shapes_a_client_actually_sent() {
        let _cache = clear_answers();
        let name = "warm-shape.example";
        let asked = query_for(name, 0x4242, true);
        remember_answer(
            &asked,
            &reply_for(name, 0x4242, [1, 2, 3, 4]),
            "geohide.ru",
            Verdict::Substituted,
            true,
        );

        let queries = warm_queries(&[name]);
        assert_eq!(queries.len(), 1, "the seen shape, and no invented one");
        assert_eq!(answer_key(&queries[0]), answer_key(&asked));
    }

    /// A cached "alive" must not survive the address dying. Measured: geohide
    /// rotated which of its three was dead three times inside an hour, and a
    /// ten-minute verdict meant the relay advertised a corpse for nine of them.
    #[test]
    fn the_warm_path_re_probes_instead_of_trusting_what_it_knows() {
        let addr = v4("203.0.113.9");
        // A blackhole address in TEST-NET-3: nothing there, so a probe says dead.
        remember_liveness(addr, true);
        assert_eq!(cached_liveness(&addr), Some(true));

        // The client path takes the cached word for it and stays cheap...
        assert!(dead_addrs(&[addr], false, None).is_empty());
        // ...while the warm path asks the network and finds out otherwise.
        assert_eq!(dead_addrs(&[addr], true, None), vec![addr]);
    }

    /// A certificate check that passed is remembered for a day, per address and
    /// name; nothing else is remembered, and another name is checked afresh.
    #[test]
    fn a_verified_certificate_is_remembered_for_a_day_and_per_name() {
        let addr: IpAddr = "203.0.113.77".parse().unwrap();
        assert!(!tls_verified_recently(addr, "a.example"));
        remember_tls_verified(addr, "a.example");
        assert!(tls_verified_recently(addr, "a.example"));
        assert!(!tls_verified_recently(addr, "b.example"));
        assert_eq!(TLS_VERIFIED_FOR, Duration::from_secs(86_400));
        // ...but an outage ends it: the address is checked afresh on its return.
        remember_liveness(addr, false);
        assert!(!tls_verified_recently(addr, "a.example"));
    }

    /// Believing "alive" for longer than the providers keep an address alive is
    /// the whole bug; the warm loop has to get at least one pass inside it.
    #[test]
    fn a_live_verdict_expires_faster_than_the_addresses_rotate() {
        assert!(LIVENESS_TTL_ALIVE <= Duration::from_secs(30));
    }

    /// The outage this exists to stop: comss answers `daily-cloudcode-pa` with
    /// the genuine Google address and a TTL of 3199 s. Passed through unchanged,
    /// one lost race pins Windows to a blocked address for 53 minutes.
    #[test]
    fn an_answer_that_did_not_beat_the_gate_expires_quickly() {
        let mut long = reply_for("ttl-cap.example", 5, [172, 217, 115, 4]);
        let at = long.len() - 10;
        long[at..at + 4].copy_from_slice(&3199u32.to_be_bytes());
        assert_eq!(dns_client::answer_ttl(&long), Some(3199));

        for v in [Verdict::Passthrough, Verdict::Sibling, Verdict::Unknown] {
            let out = vet(long.clone(), v, false, None);
            assert_eq!(
                dns_client::answer_ttl(&out),
                Some(PASSTHROUGH_TTL),
                "{:?}",
                v
            );
        }
        // A substitution keeps the resolver's own TTL - it is the answer we want
        // the client to hold, and these providers already publish a short one.
        let subbed = vet(long.clone(), Verdict::Substituted, false, None);
        assert_eq!(dns_client::answer_ttl(&subbed), Some(3199));
    }

    /// A genuine answer must not evict, nor outrank, a substitution we already
    /// hold: that is the difference between one lost race and an hour of them.
    #[test]
    fn a_substitution_in_hand_beats_a_fresh_genuine_answer() {
        let _cache = clear_answers();
        let name = "prefer-sub.example";
        let query = query_for(name, 1, false);
        let good = reply_for(name, 1, [45, 155, 204, 190]);
        remember_answer(&query, &good, "geohide.ru", Verdict::Substituted, true);

        let genuine = reply_for(name, 1, [172, 217, 115, 4]);
        remember_answer(&query, &genuine, "comss.one", Verdict::Passthrough, true);

        // The cache still holds the substitution...
        let (cached, provider, verdict) = cached_answer(&query, false, true).unwrap();
        assert_eq!(provider, "geohide.ru");
        assert_eq!(verdict, Verdict::Substituted);
        assert_eq!(
            dns_client::answer_addrs(&cached),
            dns_client::answer_addrs(&good)
        );

        // ...and it is what goes out, not the genuine answer that just arrived.
        let fresh = (genuine, "comss.one", Verdict::Passthrough);
        let (out, who, v) = prefer_substituted(&query, true, fresh).unwrap();
        assert_eq!((who, v), ("geohide.ru", Verdict::Substituted));
        assert_eq!(
            dns_client::answer_addrs(&out),
            dns_client::answer_addrs(&good)
        );
    }

    /// With nothing better in hand the genuine answer is still served: refusing
    /// to answer would only push Windows onto the unvetted NRPT fallback.
    #[test]
    fn a_genuine_answer_is_served_when_there_is_nothing_better() {
        let _cache = clear_answers();
        let name = "no-sub.example";
        let query = query_for(name, 2, false);
        let genuine = reply_for(name, 2, [172, 217, 115, 4]);
        let fresh = (genuine, "comss.one", Verdict::Passthrough);
        let (_, who, v) = prefer_substituted(&query, true, fresh).unwrap();
        assert_eq!((who, v), ("comss.one", Verdict::Passthrough));
    }

    /// Before any client has asked, there is no shape to replay - warming still
    /// has to prime the name, or the first query pays the full cold price.
    #[test]
    fn an_unseen_name_is_warmed_with_a_plain_query() {
        let _cache = clear_answers();
        let queries = warm_queries(&["warm-unseen.example"]);
        assert_eq!(queries.len(), 1);
        assert_eq!(
            dns_client::question_name(&queries[0]).as_deref(),
            Some("warm-unseen.example")
        );
    }
}
