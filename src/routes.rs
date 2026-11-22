//! The route table: every way a gate host can be reached, what each was last
//! measured at, what each has *proved*, and the order the proxy should try them
//! in.
//!
//! Why a table and not a ladder. The proxy used to try its routes in a fixed
//! order - own proxy, built-in exit, relay, direct - and the order was a guess
//! about speed that the measurements then contradicted: the direct tunnel to a
//! substituted address answered in 0.28 s while the relay it sat *below* took
//! 0.40-0.80 s (kb/rivals.md Fact 3). A DNS race is not a speed measurement and
//! neither is a list, so every route is timed on the warm loop with the same
//! request.
//!
//! Speed is not the question that matters, though, and since 2.14.0_1 it is
//! only the tie-break. A probe cannot see the region gate - the refusal arrives
//! inside the client's own TLS and an unauthenticated call is answered 401 from
//! every exit alike (kb/dns.md) - so the fastest route can be the one Google
//! refuses, every time. What *can* see the gate is the client's own log: a
//! model answer writes `streamGenerateContent … ResponseID:` and a refusal
//! writes `User location is not supported` (`ls_log`). Each is attributed to the
//! route that carried it, and the order is:
//!
//! 1. the user's own proxy, whenever it is usable - they typed it in;
//! 2. routes that carried a model answer since their last refusal, fastest
//!    first - proof beats speed;
//! 3. the rest by measured speed, then unmeasured in the default order;
//! 4. routes that carried a refusal, last, for a penalty that grows each time
//!    the same route is refused again without a success in between.
//!
//! What the table has learned is about *this network*: a route refused from
//! behind one VPN may be exactly right without it. The relay hands the table a
//! fingerprint of the network (`set_context`), and a new one wipes the evidence
//! while keeping the timings.
//!
//! A route that carried a refusal also has its open gate tunnels closed at once
//! (D26). Every request on them is refused anyway, and a client that keeps its
//! pooled connection would otherwise go on being refused for another minute and
//! a half after the table has already switched - which is exactly what "send
//! the message again" ran into.

use std::cell::RefCell;
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The routes a gate host can take, as the proxy knows them. `Exits` is the
/// whole built-in pool: which exit inside it answers is that module's business,
/// and the table measures the pool as one route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Own,
    /// The owner's dedicated group proxy server. Whitelisted to the two gate
    /// hosts only; credential private in `.group`.
    Group,
    Exits,
    Relay,
    /// A tunnel to the address the DNS layer substituted, pinned to the ISP link
    /// while a VPN holds the default route (N25).
    Direct,
    /// Genuine Google through the user's own VPN. Only offered while a tunnel
    /// holds the default route and its exit is not in a blocked region.
    Vpn,
}

pub const ALL: [Kind; 6] = [Kind::Own, Kind::Group, Kind::Exits, Kind::Relay, Kind::Direct, Kind::Vpn];
const N: usize = ALL.len();

impl Kind {
    fn index(self) -> usize {
        match self {
            Kind::Own => 0,
            Kind::Group => 1,
            Kind::Exits => 2,
            Kind::Relay => 3,
            Kind::Direct => 4,
            Kind::Vpn => 5,
        }
    }

    /// How the route is named in the log and in the window. Never an address
    /// (I46).
    pub fn label(self) -> &'static str {
        match self {
            Kind::Own => "свой прокси",
            Kind::Group => "прокси из группы",
            Kind::Exits => "встроенный выход",
            Kind::Relay => "резервный релей",
            Kind::Direct => "напрямую",
            Kind::Vpn => "через ваш VPN",
        }
    }
}

/// The order before anything has been measured. Own first; the owner's
/// dedicated group server (Group) next; then the authenticated CONNECT relay
/// (relay.xbox-dns.ru) which has dedicated permitted-region egress and zero
/// region-400s; then built-in foreign exits; the user's VPN next; and direct
/// DNS substitution last as fallback when proxy routes are not usable.
///
/// A build without a DNS layer (Linux) has no substituted address for the direct
/// tunnel to reach, so there it goes to the back regardless; see `order_with`.
const DEFAULT_ORDER: [Kind; N] = [Kind::Group, Kind::Own, Kind::Relay, Kind::Exits, Kind::Direct, Kind::Vpn];

/// Routes taken first whenever usable and not benched, ahead of anything
/// measured (owner, 2026-10-05: «если активен прокси от моей группы - то все
/// запросы к моделям должны идти сначала на него … всё так же как с кастомным
/// прокси»). The group's server first: it is the one the owner runs and
/// vouches for; the user's own proxy right after it.
const PINNED: [Kind; 2] = [Kind::Group, Kind::Own];

/// The pinned pair in force: whichever of the group code and the user's own
/// proxy was added later leads (owner, 2026-10-05: «в зависимости от того какой
/// был добавлен позднее»).
fn pinned_now() -> [Kind; 2] {
    if crate::settings::own_proxy_first() {
        [Kind::Own, Kind::Group]
    } else {
        PINNED
    }
}

/// A measurement older than this says nothing about the route now. Probes run
/// every two minutes; three misses in a row and the route is unmeasured again.
const SAMPLE_TTL: Duration = Duration::from_secs(15 * 60);

/// How much faster a challenger must measure to take the lead, in percent.
/// Twenty: the measured spread between two probes of one healthy route is
/// under that, and swapping routes for a difference nobody would notice costs a
/// cold connection to a proxy that was idle.
const SWITCH_MARGIN_PCT: u64 = 20;

/// How long a route that carried a region 400 stays at the back of the line,
/// the first time. Long enough that the client's pooled connections to it have
/// expired and a retry actually takes another route; short enough that a proxy
/// whose exit rotated back into a usable region is not written off.
pub const REGION_PENALTY: Duration = Duration::from_secs(10 * 60);

/// The bench a route gets the *first* time, before anything says the gate is
/// refusing the road rather than the request.
///
/// Short on purpose. A refusal is pinned on whichever tunnel was open around
/// its timestamp (`attribute`), and a client that fans several gate connections
/// out at once makes that an educated guess. Benching on the first one is still
/// right - it is what switches the route inside the two-second watch, which is
/// what the user feels - but a wrong guess should cost two minutes, not ten.
/// Anything that is really being refused is refused again immediately and moves
/// on to the steps below.
const FIRST_PENALTY: Duration = Duration::from_secs(2 * 60);

/// …and each time it is refused again with no model answer in between. A route
/// that keeps being refused on this network is not going to start working in
/// ten minutes, and handing it the next request every ten minutes was one
/// failed message per cycle for the user (the reason proof exists at all).
const PENALTY_STEPS: [Duration; 4] = [
    FIRST_PENALTY,
    REGION_PENALTY,
    Duration::from_secs(60 * 60),
    Duration::from_secs(6 * 60 * 60),
];

/// How long a model answer keeps the route that carried it safe from a bench.
///
/// A field report (2026-09-20, `2.15.0_2`) showed the cost of not having this:
/// the built-in exit carried a model answer at 14:35:16 and was benched for ten
/// minutes by a refusal at 14:35:18 - three times over six minutes, and every
/// route the bench pushed that user onto carried nothing, so the table came
/// back to the same exit half a minute later. A route that delivered an answer
/// two seconds ago is demonstrably not the thing being refused: the refusal
/// belongs to a request the backend turned down whatever the road, or to one of
/// the connections the client made without us. Its tunnels are still cut, which
/// is the half that makes the retry take a fresh connection; the bench is not.
///
/// Ninety seconds: shorter than the shortest bench, and comfortably wider than
/// the answer-to-refusal gaps the field reports show (2-12 s).
const PROOF_PROTECTS_FOR: Duration = Duration::from_secs(90);

/// How long a model answer keeps a route in the proven tier. A working route is
/// re-proved by every answer it carries, so this only matters for a machine
/// that sat idle - and after half a day the network it proved itself on is
/// likely not the one it is on now.
const PROOF_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// A refusal or an answer is attributed to a tunnel that was open within this
/// much of the log line's stamp: whole-second stamps, and a log flushed a
/// moment after the response.
const ATTRIBUTION_SLACK: Duration = Duration::from_secs(3);

/// Closed tunnels are kept this long for attribution. An event older than this
/// is not attributed at all (`dns_forwarder::answer_log`).
pub const TUNNEL_MEMORY: Duration = Duration::from_secs(10 * 60);
/// A cap on remembered closed tunnels, generous enough that a burst of short
/// connections cannot push out one that is still inside `TUNNEL_MEMORY` and
/// matters for attribution. Open tunnels are never dropped.
const MAX_TUNNEL_RECORDS: usize = 512;

/// How long a route that failed to even *open* a tunnel for a live connection
/// sits behind the others. Short: this is a connect failure, not the gate - a
/// pinned direct route behind a kill-switch VPN, an exit that stopped answering
/// - and it only has to keep the next connections from waiting out the same
/// budget until the next probe says something.
const STUMBLE_FOR: Duration = Duration::from_secs(60);

/// …and how long one that failed its *probe* does.
///
/// Longer than `PROBE_HEALTHY_EVERY`, deliberately: a probe failure that wore
/// off before the next probe would leave the route a candidate again with
/// nothing new known about it, which is what a field report showed - «напрямую»
/// failed its handshake every two and a half minutes for an hour and a half and
/// was still picked as the gate route, because a failed probe only cleared the
/// measurement and an unmeasured route is a candidate. This keeps a route that
/// cannot answer a probe out of the way until one succeeds, and no longer: the
/// first successful probe `record`s a sample, and the stumble expires on its
/// own.
const PROBE_STUMBLE_FOR: Duration = Duration::from_secs(3 * 60);

/// How long a route whose live tunnel went **silent** sits behind the others:
/// it opened, the client spoke, and nothing came back before the tunnel closed.
///
/// The failure nothing else sees. The route said `200`, so it never stumbled;
/// the gate never answered, so there is no 400 to blame it with; and its probe
/// can still pass between two dead tunnels, so it kept being put first - a
/// built-in exit that stopped carrying held the table on itself, and the user
/// had to switch the exits off by hand for the DNS route to be tried at all.
/// Not cleared by a probe (`record`), only by a model answer (`credit`) or by
/// the bench running out: a live connection that got nothing outweighs a probe.
/// Two steps, not the four a refusal climbs - a network that dropped out makes
/// every route go silent at once, and that must not cost the best one an hour.
const SILENT_STEPS: [Duration; 2] = [Duration::from_secs(2 * 60), Duration::from_secs(10 * 60)];

/// Fewer bytes than this back to the client is no TLS server flight at all: a
/// ServerHello alone is larger. What does arrive is an alert or a proxy's error
/// text, which is the same answer - the route does not reach Google.
const SILENT_MAX_BYTES: u64 = 64;

#[derive(Clone, Copy)]
struct Sample {
    latency: Duration,
    at: Instant,
}

struct DnsEndpoint {
    host: String,
    candidate: crate::resolvers::DnsCandidate,
    generation: u64,
    checked: Option<Instant>,
    latency: Duration,
    reachable: bool,
    refusal_at: Option<Instant>,
    refusal_blocking: bool,
    model_proven: bool,
    model_seen: Option<Instant>,
    silent_until: Option<Instant>,
    silent_streak: u8,
    drop_streak: usize,
    drop_continuity: Option<(crate::ls_log::LogSourceId, u64)>,
    last_event_at: Option<Instant>,
    last_event_source: Option<crate::ls_log::LogSourceId>,
}

struct DnsState {
    generation: u64,
    witness: Option<crate::resolvers::DnsSourceWitness>,
    allow_missing_defaults: bool,
    network: Option<u64>,
    pending: Vec<String>,
    entries: Vec<DnsEndpoint>,
    hosts: Vec<DnsHostWork>,
    next_host: usize,
    maintenance_thread: Option<std::thread::Thread>,
    consumed: Vec<DnsSourceCursor>,
}

struct DnsSourceCursor { source: crate::ls_log::LogSourceId, end: u64, boundary: Option<u64>, observed: Instant }

impl DnsState {
    const fn new() -> Self {
        Self { generation: 0, witness: None, allow_missing_defaults: false, network: None,
            pending: Vec::new(), entries: Vec::new(), hosts: Vec::new(), next_host: 0, maintenance_thread: None, consumed: Vec::new() }
    }
}

#[cfg(test)]
pub(crate) struct DnsStateTestLease { saved: Option<DnsState>, context: u64 }

#[cfg(test)]
impl Drop for DnsStateTestLease {
    fn drop(&mut self) {
        if let Ok(mut table) = TABLE.lock() {
            if let Some(saved) = self.saved.take() { table.dns = saved; }
            table.context = self.context;
            DNS_CHANGED.notify_all();
        }
    }
}

#[cfg(test)]
pub(crate) fn lease_test_dns_state() -> Result<DnsStateTestLease, String> {
    let mut table = TABLE.lock().map_err(|_| "route state unavailable")?;
    let context = table.context;
    table.context = 0;
    let saved = std::mem::replace(&mut table.dns, DnsState::new());
    Ok(DnsStateTestLease { saved: Some(saved), context })
}

struct DnsHostWork {
    host: String,
    cursor: Option<crate::resolvers::DnsDiscoveryCursor>,
    queued: Vec<crate::resolvers::DnsCandidate>,
    exhausted: bool,
    finished_at: Option<Instant>,
}

/// Everything the table knows, behind one lock: consulted on the path of every
/// gate connection, so the lock is taken once and released immediately.
struct Table {
    samples: [Option<Sample>; N],
    penalised: [Option<Instant>; N],
    /// When each route last carried a model answer.
    ok_at: [Option<Instant>; N],
    /// When each route last carried a refusal that counted *as evidence*
    /// against it - one that was neither protected by a live answer (D32) nor
    /// by a fresh one (D31). This is what `proven` reads.
    ///
    /// Split from `refused_at` because the two answer different questions and
    /// sharing one field made a protected route lose its place anyway: `blame`
    /// declined to bench or cut it and then stamped this, `proven` went false,
    /// and the route dropped out of tier 0 into whatever its measurement said.
    /// A field report (2026-09-21) shows the result - the leader flapping
    /// between the route that was streaming an answer and the next one every
    /// fifteen seconds, so half the client's new connections went to a road
    /// nothing had proved (G76).
    bad_at: [Option<Instant>; N],
    /// When each route last carried a refusal at all, protected or not, for the
    /// window's table. Never evidence.
    refused_at: [Option<Instant>; N],
    /// Refusal episodes and model answers pinned on each route since the relay
    /// started or the network changed. Only the report reads them: "this route
    /// answered twenty times and was refused thirty" is the one line that says
    /// whether a route half-works, which no single timestamp can.
    ok_count: [u32; N],
    bad_count: [u32; N],
    /// Refusals in a row with no answer in between, which sets the next penalty.
    streak: [u8; N],
    /// Until when a route that failed to open for a live connection sits last.
    stumbled: [Option<Instant>; N],
    /// Until when a route whose live tunnel went silent sits last
    /// (`SILENT_STEPS`), and how many times in a row it did.
    silent: [Option<Instant>; N],
    silent_streak: [u8; N],
    /// The route the last `refresh_leader` put first, for the hysteresis.
    leader: Option<Kind>,
    /// The route that most recently opened a gate tunnel, and when.
    last_used: Option<(Kind, Instant)>,
    /// The network the evidence was gathered on (`set_context`).
    context: u64,
    dns: DnsState,
}

static TABLE: Mutex<Table> = Mutex::new(Table {
    samples: [None; N],
    penalised: [None; N],
    ok_at: [None; N],
    bad_at: [None; N],
    refused_at: [None; N],
    ok_count: [0; N],
    bad_count: [0; N],
    streak: [0; N],
    stumbled: [None; N],
    silent: [None; N],
    silent_streak: [0; N],
    leader: None,
    last_used: None,
    context: 0,
    dns: DnsState::new(),
});
static DNS_CHANGED: Condvar = Condvar::new();

/// A newly received Own endpoint must not inherit another endpoint's ranking.
pub(crate) fn reset_own_projection() -> Result<(), String> {
    {
        let mut t = TABLE.lock().map_err(|_| "route table unavailable".to_string())?;
        let i = Kind::Own.index();
        t.samples[i] = None;
        t.penalised[i] = None;
        t.ok_at[i] = None;
        t.bad_at[i] = None;
        t.refused_at[i] = None;
        t.streak[i] = 0;
        t.stumbled[i] = None;
        t.silent[i] = None;
        t.silent_streak[i] = 0;
        if t.leader == Some(Kind::Own) { t.leader = None; }
    }
    Ok(())
}

/// Records one measurement of a route. Blended with the previous fresh one, so
/// a single slow probe does not by itself hand the lead to somebody else.
pub fn record(kind: Kind, latency: Duration) {
    crate::net::note_reached();
    let Ok(mut t) = TABLE.lock() else {
        return;
    };
    let now = Instant::now();
    let blended = match t.samples[kind.index()] {
        Some(prev) if now.duration_since(prev.at) < SAMPLE_TTL => (prev.latency + latency) / 2,
        _ => latency,
    };
    t.samples[kind.index()] = Some(Sample {
        latency: blended,
        at: now,
    });
    // Every caller of this is a probe or a health check that just completed a
    // real request over the route, which settles the one question a stumble
    // asks - whether it opens. Without this a route that failed one probe would
    // stay at the back for the rest of `PROBE_STUMBLE_FOR` after the next probe
    // had already succeeded.
    t.stumbled[kind.index()] = None;
}

/// Forgets what was measured: the route failed its probe, so whatever it was
/// timed at last time is not what a request would meet now.
///
/// On its own this does not say the route is *bad* - it says nothing is known
/// about it. For a probe that actually ran and failed, use `probe_failed`.
pub fn record_failure(kind: Kind) {
    if let Ok(mut t) = TABLE.lock() {
        t.samples[kind.index()] = None;
    }
}

/// A probe ran against `kind` and it did not answer: forget the measurement and
/// keep it out of the running until a probe succeeds (`PROBE_STUMBLE_FOR`).
///
/// Not for a probe that was never applicable - a VPN row with no tunnel up is
/// unmeasured, not failing - only for one that tried and got nothing.
pub fn probe_failed(kind: Kind) {
    record_failure(kind);
    stumble_for(kind, PROBE_STUMBLE_FOR);
}

/// The route's last fresh measurement, if it has one.
#[cfg_attr(not(test), allow(dead_code))]
pub fn latency(kind: Kind) -> Option<Duration> {
    let t = TABLE.lock().ok()?;
    fresh(&t.samples, kind)
}

fn fresh(samples: &[Option<Sample>; N], kind: Kind) -> Option<Duration> {
    samples[kind.index()]
        .filter(|s| s.at.elapsed() < SAMPLE_TTL)
        .map(|s| s.latency)
}

/// Whether `kind` is serving a region bench. Only the ordering inside this
/// module consults it now - a bench moves a route to the back, it does not take
/// it out of the table (`proxy::route_usable`).
#[cfg_attr(not(test), allow(dead_code))]
pub fn is_penalised(kind: Kind) -> bool {
    TABLE
        .lock()
        .ok()
        .is_some_and(|t| penalised(&t.penalised, kind))
}

fn penalised(list: &[Option<Instant>; N], kind: Kind) -> bool {
    list[kind.index()].is_some_and(|until| Instant::now() < until)
}

fn proven(ok: &[Option<Instant>; N], bad: &[Option<Instant>; N], kind: Kind) -> bool {
    let i = kind.index();
    match (ok[i], bad[i]) {
        (Some(ok), bad) => ok.elapsed() < PROOF_TTL && bad.is_none_or(|b| ok > b),
        (None, _) => false,
    }
}

/// Whether `kind` carried a model answer since its last refusal.
#[cfg_attr(not(test), allow(dead_code))]
pub fn is_proven(kind: Kind) -> bool {
    TABLE
        .lock()
        .ok()
        .is_some_and(|t| proven(&t.ok_at, &t.bad_at, kind))
}

/// A model answer came through `kind`: it works on this network, now.
pub fn credit(kind: Kind) {
    if let Ok(mut t) = TABLE.lock() {
        let i = kind.index();
        t.ok_at[i] = Some(Instant::now());
        t.ok_count[i] = t.ok_count[i].saturating_add(1);
        t.streak[i] = 0;
        // A route that carried an answer is not one to keep behind the others.
        t.penalised[i] = None;
        t.stumbled[i] = None;
        t.silent[i] = None;
        t.silent_streak[i] = 0;
    }
}

/// `kind` failed to open a tunnel for a live connection (before any `200`).
/// Not the gate, so no penalty and no evidence - just out of the way of the
/// next few connections, which would otherwise each wait out its budget again.
pub fn stumble(kind: Kind) {
    stumble_for(kind, STUMBLE_FOR);
}

/// The same, for however long the caller knows it needs. Never shortens a
/// stumble already running: a route kept back by a failed probe should not be
/// let out early by one connect failure with a shorter clock.
pub fn stumble_for(kind: Kind, how_long: Duration) {
    if let Ok(mut t) = TABLE.lock() {
        let until = Instant::now() + how_long;
        let slot = &mut t.stumbled[kind.index()];
        if slot.is_none_or(|prev| prev < until) {
            *slot = Some(until);
        }
    }
}

/// What a refusal did to the route it was pinned on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blamed {
    /// Benched for this long, and its open gate tunnels closed.
    Benched(Duration),
    /// Left alone: it carried a model answer this recently
    /// (`PROOF_PROTECTS_FOR`), so the refusal is not evidence against the
    /// route - and its open tunnels are the ones carrying the conversation.
    Proven(Duration),
    /// Tunnels closed, no new bench: it was already serving one. The retries a
    /// client makes on a connection it still held are the same refusal, not a
    /// new one.
    AlreadyBenched,
    /// Left alone, and not on a clock: a tunnel that carried a model answer is
    /// still open on this route, so an answer is still arriving through it
    /// (D32). Carries how long since its last byte and how much it has handed
    /// the client, which is what a field report needs to see that the thing
    /// being protected is a real answer and not an idle socket.
    Streaming { idle: Duration, to_client: u64 },
}

/// A refusal came through `kind`: bench it and close its gate tunnels, unless
/// something says the refusal is not about the route.
///
/// Closing the tunnels is the half that makes the client's retry take a fresh
/// connection instead of going on being refused for another minute and a half
/// on a pooled one (D26). It is exactly the wrong thing to do to a route that
/// is working: a model answer arrives as a stream, so cutting a proven route's
/// sockets is how a user loses an answer halfway through, reported from the
/// field as «to rabotaet, to net».
///
/// Two things can say the route is working, and they answer different
/// questions. An **open tunnel that carried an answer** says one is arriving
/// right now, so nothing is done to the route for as long as that connection
/// lives (D32) - no clock, because a model that is thinking sends nothing while
/// it thinks, and a ninety-second rule measured from the *start* of the stream
/// is what cut long answers in half. A **recent answer with no tunnel left** is
/// the weaker case, the short exchange that is already over: it keeps its place
/// for `PROOF_PROTECTS_FOR`, and then the next refusal benches it as usual.
pub fn blame(kind: Kind) -> Blamed {
    // The tunnel list first, and released before `TABLE` is taken: the two locks
    // are never held together (G30, I50).
    let streaming = live_answer(kind);
    let outcome = blame_table(kind, streaming);
    if !matches!(outcome, Blamed::Proven(_) | Blamed::Streaming { .. }) {
        cut_tunnels(kind);
    }
    outcome
}

/// The table half of `blame`, so the lock is released before `cut_tunnels`
/// takes the tunnel list (the two are never held together - G30, I50).
fn blame_table(kind: Kind, streaming: Option<(Duration, u64)>) -> Blamed {
    let Ok(mut t) = TABLE.lock() else {
        return Blamed::AlreadyBenched;
    };
    let i = kind.index();
    let now = Instant::now();
    // Recorded either way: the window's table shows when each route was last
    // refused, and a protected route is one the user should still see taking
    // refusals.
    let answered_ago = t.ok_at[i].map(|ok| ok.elapsed());
    t.refused_at[i] = Some(now);
    t.bad_count[i] = t.bad_count[i].saturating_add(1);
    // Ahead of everything else, the already-benched arm included: that arm
    // cuts, and this is the one case where cutting is the damage (D32).
    if let Some((idle, to_client)) = streaming {
        // `bad_at` deliberately untouched. "Does nothing at all" (D31) has to
        // include the ordering: a route that is handing the client an answer
        // right now must stay in the proven tier, or the next connection is
        // offered a road nothing has proved while this one works (G76).
        return Blamed::Streaming { idle, to_client };
    }
    if penalised(&t.penalised, kind) {
        t.bad_at[i] = Some(now);
        return Blamed::AlreadyBenched;
    }
    if let Some(ago) = answered_ago.filter(|a| *a < PROOF_PROTECTS_FOR) {
        // Not a strike either: a streak is "refused again with no model answer
        // in between", and there was one - and not evidence either, for the
        // same reason as the arm above.
        return Blamed::Proven(ago);
    }
    t.bad_at[i] = Some(now);
    let step = (t.streak[i] as usize).min(PENALTY_STEPS.len() - 1);
    let penalty = PENALTY_STEPS[step];
    t.streak[i] = t.streak[i].saturating_add(1);
    t.penalised[i] = Some(now + penalty);
    Blamed::Benched(penalty)
}

/// Tells the table which network it is on. A different fingerprint wipes what
/// was learned - proofs, refusals, penalties - and keeps the timings, which the
/// probes refresh on their own. Returns whether it changed.
pub fn set_context(fingerprint: u64) -> bool {
    let Ok(mut t) = TABLE.lock() else {
        return false;
    };
    if t.context == fingerprint {
        return false;
    }
    let first = t.context == 0;
    t.context = fingerprint;
    if !first {
        // The group server's exit sits in the same country on every network, so
        // a region-400 it drew is not news that a VPN going up or down can
        // overturn. Wiping it put the pinned group back in front of the VPN
        // each time the network changed, and the VPN was never asked.
        let g = Kind::Group.index();
        let kept = (
            t.penalised[g],
            t.streak[g],
            t.bad_at[g],
            t.refused_at[g],
            t.bad_count[g],
        );
        t.ok_at = [None; N];
        t.bad_at = [None; N];
        t.refused_at = [None; N];
        t.ok_count = [0; N];
        t.bad_count = [0; N];
        t.streak = [0; N];
        t.penalised = [None; N];
        t.stumbled = [None; N];
        t.silent = [None; N];
        t.silent_streak = [0; N];
        (t.penalised[g], t.streak[g], t.bad_at[g], t.refused_at[g], t.bad_count[g]) = kept;
    }
    !first
}

/// The order to try routes in for the next connection, best first, among those
/// `usable` says are worth trying at all.
///
/// The table is copied out from under its lock before `usable` is consulted:
/// `usable` asks this module questions of its own (`is_penalised`), and a
/// non-reentrant lock held across that call deadlocked the very first live
/// connection (G30, I50).
pub fn order(usable: impl Fn(Kind) -> bool) -> Vec<Kind> {
    if let Some(k) = forced(&crate::settings::debug_route()) {
        return if usable(k) { vec![k] } else { Vec::new() };
    }
    let s = snapshot();
    order_with(&s, cfg!(target_os = "windows"), usable)
}

/// Orders current health evidence using the caller's already captured settings.
/// The settings values are fixed for one connection; route health remains live.
pub(crate) fn order_for_profile(
    debug_route: &str,
    own_first: bool,
    usable: impl Fn(Kind) -> bool,
) -> Vec<Kind> {
    if !debug_route.trim().is_empty() {
        return match forced(debug_route) {
            Some(k) if usable(k) => vec![k],
            _ => Vec::new(),
        };
    }
    let pinned = if own_first {
        [Kind::Own, Kind::Group]
    } else {
        [Kind::Group, Kind::Own]
    };
    let s = snapshot_with_pinned(pinned);
    order_with(&s, cfg!(target_os = "windows"), usable)
}

/// The route a diagnostic run pinned in `settings.json` (`debug_route`).
fn forced(name: &str) -> Option<Kind> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "own" => Kind::Own,
        "group" => Kind::Group,
        "exits" => Kind::Exits,
        "relay" => Kind::Relay,
        "direct" => Kind::Direct,
        "vpn" => Kind::Vpn,
        _ => return None,
    })
}

#[derive(Clone, Copy)]
struct Snapshot {
    samples: [Option<Sample>; N],
    penalised: [Option<Instant>; N],
    ok_at: [Option<Instant>; N],
    bad_at: [Option<Instant>; N],
    refused_at: [Option<Instant>; N],
    ok_count: [u32; N],
    bad_count: [u32; N],
    stumbled: [Option<Instant>; N],
    silent: [Option<Instant>; N],
    leader: Option<Kind>,
    /// Group and Own, in the order they lead the table.
    pinned: [Kind; 2],
}

/// What the table holds right now, without holding it.
fn snapshot() -> Snapshot {
    snapshot_with_pinned(pinned_now())
}

fn snapshot_with_pinned(pinned: [Kind; 2]) -> Snapshot {
    match TABLE.lock() {
        Ok(t) => Snapshot {
            samples: t.samples,
            penalised: t.penalised,
            ok_at: t.ok_at,
            bad_at: t.bad_at,
            refused_at: t.refused_at,
            ok_count: t.ok_count,
            bad_count: t.bad_count,
            stumbled: t.stumbled,
            silent: t.silent,
            leader: t.leader,
            pinned,
        },
        Err(_) => Snapshot {
            samples: [None; N],
            penalised: [None; N],
            ok_at: [None; N],
            bad_at: [None; N],
            refused_at: [None; N],
            ok_count: [0; N],
            bad_count: [0; N],
            stumbled: [None; N],
            silent: [None; N],
            leader: None,
            pinned,
        },
    }
}

/// The route sitting first right now, or `None` before the first pass has
/// picked one. Read by the record the window shows (`gate`).
pub fn leader() -> Option<Kind> {
    snapshot().leader
}

/// Re-derives the leader from the latest evidence and measurements, and says so
/// in the log when it changed. Run once per warm pass, after the probes.
pub fn refresh_leader(usable: impl Fn(Kind) -> bool) {
    let s = snapshot();
    let order = order_with(&s, cfg!(target_os = "windows"), usable);
    let Some(&best) = order.first() else {
        return;
    };
    if s.leader == Some(best) {
        return;
    }
    if let Ok(mut t) = TABLE.lock() {
        t.leader = Some(best);
    }
    let describe = |k: Kind| match fresh(&s.samples, k) {
        Some(d) => format!("{} ({} мс)", k.label(), d.as_millis()),
        None => format!("{} (не измерен)", k.label()),
    };
    let line = match s.leader {
        Some(prev) => format!(
            "маршрут гейт-хостов: {}, было {}",
            describe(best),
            describe(prev)
        ),
        None => format!("маршрут гейт-хостов: {}", describe(best)),
    };
    note(&line);
}

/// The pure ordering, so it can be tested without the static.
///
/// Group, then Own, first when usable and not benched (`PINNED`). Then four tiers, each in the default
/// order inside itself unless measured: proven (fastest first, the sitting
/// leader kept unless clearly beaten), measured, unmeasured, penalised. Without
/// a DNS layer the direct tunnel has nothing substituted to reach, so it counts
/// as penalised.
///
/// A benched Own joins the benched tier like any other route. Putting it first
/// regardless meant a region 400 through the user's proxy was answered by
/// cutting its tunnels and sending the retry straight back into it - the log
/// said «следующее соединение пойдёт другим» and the next one went the same
/// way, refusal after refusal. The bench ends, or an answer lifts it, and Own
/// is first again.
fn order_with(s: &Snapshot, has_dns_layer: bool, usable: impl Fn(Kind) -> bool) -> Vec<Kind> {
    let benched = |k: Kind| {
        penalised(&s.penalised, k) || penalised(&s.stumbled, k) || penalised(&s.silent, k)
    };
    let mut out: Vec<Kind> = Vec::with_capacity(N);
    // Pinned routes: taken first whenever usable and not benched, in this
    // order, regardless of speed. A benched one joins the rest like any route.
    // Except one that was refused and has not answered since while another
    // usable route has: the pin is an owner's preference for a road that works,
    // not for one that keeps drawing region-400 while the VPN carries the model.
    let other_proven = |k: Kind| {
        ALL.iter().any(|&o| {
            o != k && usable(o) && !benched(o) && proven(&s.ok_at, &s.bad_at, o)
        })
    };
    for k in s.pinned {
        let refused_unproven = s.refused_at[k.index()].is_some() && !proven(&s.ok_at, &s.bad_at, k);
        if usable(k) && !benched(k) && !(refused_unproven && other_proven(k)) {
            out.push(k);
        }
    }

    let rest: Vec<Kind> = DEFAULT_ORDER
        .iter()
        .copied()
        .filter(|k| usable(*k) && !out.contains(k))
        .collect();

    let tier = |k: Kind| -> u8 {
        if benched(k) || (k == Kind::Direct && !has_dns_layer) {
            3
        } else if proven(&s.ok_at, &s.bad_at, k) {
            0
        } else if fresh(&s.samples, k).is_some() {
            1
        } else {
            2
        }
    };

    for t in 0..=1u8 {
        let mut measured: Vec<(Kind, Duration)> = rest
            .iter()
            .copied()
            .filter(|k| tier(*k) == t)
            // A proven route that has not been timed yet still goes ahead of
            // everything unproven; it simply sorts last among the proven.
            .map(|k| (k, fresh(&s.samples, k).unwrap_or(Duration::MAX)))
            .collect();
        measured.sort_by_key(|(_, d)| *d);
        keep_leader(&mut measured, s.leader);
        out.extend(measured.iter().map(|(k, _)| *k));
    }
    out.extend(rest.iter().copied().filter(|k| tier(*k) == 2));
    // Benched routes last, the one whose bench ends first ahead: when every
    // route has been refused, the likeliest to work again is the one refused
    // longest ago.
    let mut benched: Vec<Kind> = rest.iter().copied().filter(|k| tier(*k) == 3).collect();
    let ends = |k: &Kind| {
        let i = k.index();
        let live = |u: Option<Instant>| u.filter(|u| *u > Instant::now());
        live(s.penalised[i])
            .max(live(s.stumbled[i]))
            .max(live(s.silent[i]))
    };
    benched.sort_by_key(ends);
    out.extend(benched);
    out
}

/// Hysteresis: the sitting leader stays ahead of a challenger in its own tier
/// that is not clearly faster.
fn keep_leader(tier: &mut Vec<(Kind, Duration)>, leader: Option<Kind>) {
    let Some(lead) = leader else { return };
    let Some(lead_pos) = tier.iter().position(|(k, _)| *k == lead) else {
        return;
    };
    if lead_pos == 0 {
        return;
    }
    let lead_ms = tier[lead_pos].1.as_millis() as u64;
    let best_ms = tier[0].1.as_millis() as u64;
    let clearly_faster =
        best_ms.saturating_mul(100) < lead_ms.saturating_mul(100 - SWITCH_MARGIN_PCT);
    if !clearly_faster {
        let item = tier.remove(lead_pos);
        tier.insert(0, item);
    }
}

// ---------------------------------------------------------------------------
// Open tunnels: who carried what, and closing a refused route's connections.
// ---------------------------------------------------------------------------

/// The clock the lock-free activity stamps count from. An `Instant` does not
/// fit in an atomic, and taking `TUNNELS` on every 8 KB chunk would put a
/// global lock on the byte path of every tunnel at once.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// What a tunnel has moved, written by the threads pumping it and read by the
/// table without touching them.
///
/// Both directions are counted because both are a conversation in flight: the
/// answer streaming back, and the request going out - a long chat is a 100 KB
/// upload before it is anything else (field, `116225 B out`).
#[derive(Default)]
pub struct Activity {
    /// Milliseconds since `epoch()` when the last byte moved, either way.
    /// Zero means nothing has moved yet.
    at_ms: AtomicU64,
    to_client: AtomicU64,
    to_upstream: AtomicU64,
}

impl Activity {
    /// `n` bytes reached the client. Called per chunk, so it does no more than
    /// two relaxed adds and a clock read.
    pub fn to_client(&self, n: u64) {
        self.to_client.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// `n` bytes went out toward Google.
    pub fn to_upstream(&self, n: u64) {
        self.to_upstream.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    fn touch(&self) {
        // `max(1)`: zero is "nothing yet", and the first millisecond of the
        // process would otherwise read as silence for the tunnel's whole life.
        let ms = (epoch().elapsed().as_millis() as u64).max(1);
        self.at_ms.store(ms, Ordering::Relaxed);
    }

    /// How long since the last byte, or `None` if none has moved.
    pub fn idle(&self) -> Option<Duration> {
        match self.at_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(epoch().elapsed().saturating_sub(Duration::from_millis(ms))),
        }
    }

    /// Bytes to the client, bytes out.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.to_client.load(Ordering::Relaxed),
            self.to_upstream.load(Ordering::Relaxed),
        )
    }
}

/// One gate tunnel, from the `200` to the end of its splice.
struct Tunnel {
    id: u64,
    kind: Kind,
    own: Option<std::sync::Weak<crate::upstream::OwnContext>>,
    /// Which gate host it carries. The client keeps a pool per host, and the two
    /// pools can sit on different routes - an event about one host must not be
    /// pinned on the other's tunnel.
    host: String,
    opened: Instant,
    closed: Option<Instant>,
    /// When a model answer was attributed to *this* tunnel. The one fact that
    /// separates a conversation in flight from a pooled connection the client
    /// keeps feeding refused requests: a refusal-only tunnel is never credited
    /// here, however busy it looks (D32).
    answered_at: Option<Instant>,
    /// What has moved through it and when, shared with its pump threads.
    activity: Arc<Activity>,
    /// The client's socket, kept while the tunnel is open so a refused route's
    /// connections can be closed from outside the thread pumping them.
    client: Option<TcpStream>,
    /// The upstream socket, when the route hands it to `splice`: closing only
    /// the client side left the other direction blocked on an idle Google
    /// connection for minutes (G52).
    upstream: Option<TcpStream>,
    dns_binding: Option<DnsBinding>,
    dns_peer: Option<DnsPeerIdentity>,
    // Conservative protection for an original plausible answer-bearing stream;
    // this is not a per-tunnel claim that the model actually answered here.
    dns_answered: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DnsAdmission { pub(crate) ip: std::net::Ipv4Addr, pub(crate) generation: u64 }

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DnsPeerIdentity { pub(crate) host: String, pub(crate) ip: std::net::Ipv4Addr, pub(crate) generation: u64 }

pub(crate) enum DnsSelection {
    Ready(Vec<(DnsAdmission, crate::resolvers::DnsCandidate)>),
    Pending,
    NoEligible,
}

/// Called with the producer's freshly received settings witness. This counter
/// represents observed changes only; it is not a cross-process mutation log.
pub(crate) fn begin_dns_maintenance(host: &str, witness: &crate::resolvers::DnsSourceWitness, allow_missing_defaults: bool) -> Result<u64, String> {
    if !crate::gate_hosts::is_public_dns_target(host, 443) { return Err("DNS candidate host denied".into()); }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let live: Vec<DnsPeerIdentity> = TUNNELS.lock().map_err(|_| "tunnel state unavailable")?.iter()
        .filter(|tunnel| tunnel.closed.is_none()).filter_map(|tunnel| tunnel.dns_peer.clone()).collect();
    let mut table = TABLE.lock().map_err(|_| "route state unavailable")?;
    // Retain active peers, fresh qualifications, and refusal/model history for
    // the existing proof-retention interval; expired input supplies no authority.
    table.dns.entries.retain(|entry| entry.checked.is_some_and(|at| at.elapsed() < SAMPLE_TTL)
        || entry.refusal_at.is_some_and(|at| at.elapsed() < PROOF_TTL)
        || entry.model_seen.is_some_and(|at| at.elapsed() < PROOF_TTL)
        || live.iter().any(|peer| peer.host == entry.host && peer.ip == entry.candidate.ip && peer.generation == entry.generation));
    let network = (table.context != 0).then_some(table.context);
    if table.dns.witness.as_ref() != Some(witness) || table.dns.network != network || table.dns.allow_missing_defaults != allow_missing_defaults {
        table.dns.generation = table.dns.generation.checked_add(1).ok_or("DNS generation exhausted")?;
        table.dns.witness = Some(witness.clone());
        table.dns.allow_missing_defaults = allow_missing_defaults;
        table.dns.network = network;
        table.dns.pending.clear();
        table.dns.hosts.clear();
    }
    if !table.dns.hosts.iter().any(|work| work.host == host) {
        table.dns.hosts.push(DnsHostWork { host: host.clone(), cursor: Some(Default::default()),
            queued: Vec::new(), exhausted: false, finished_at: None });
    }
    let has_ready = table.dns.entries.iter().any(|entry| entry.host == host && entry.generation == table.dns.generation
        && entry.reachable && entry.checked.is_some_and(|at| at.elapsed() < SAMPLE_TTL)
        && entry.silent_until.is_none_or(|until| Instant::now() >= until)
        && (!entry.refusal_blocking || entry.refusal_at.is_none_or(|at| at.elapsed() >= FIRST_PENALTY)));
    let retry_after = if has_ready { SAMPLE_TTL } else { crate::dns_forwarder::WARM_EVERY };
    let work = table.dns.hosts.iter_mut().find(|work| work.host == host).expect("DNS host work inserted");
    if work.exhausted && work.finished_at.is_some_and(|at| at.elapsed() >= retry_after) {
        work.cursor = Some(Default::default());
        work.exhausted = false;
        work.finished_at = None;
    }
    let pending = !work.exhausted || !work.queued.is_empty();
    if pending && !table.dns.pending.contains(&host) { table.dns.pending.push(host); }
    Ok(table.dns.generation)
}

pub(crate) enum DnsMaintenanceWork {
    Discover(crate::resolvers::DnsDiscoveryCursor),
    Probe(crate::resolvers::DnsCandidate),
    Complete,
}

pub(crate) fn dns_maintenance_host() -> Result<&'static str, String> {
    let hosts: Vec<_> = crate::gate_hosts::public_dns_hosts().collect();
    let mut table = TABLE.lock().map_err(|_| "route state unavailable")?;
    let host = hosts[table.dns.next_host % hosts.len()];
    table.dns.next_host = (table.dns.next_host + 1) % hosts.len();
    Ok(host)
}

pub(crate) fn seed_dns_candidates(host: &str, generation: u64, candidates: Vec<crate::resolvers::DnsCandidate>) -> Result<bool, String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut table = TABLE.lock().map_err(|_| "route state unavailable")?;
    if table.dns.generation != generation { return Ok(false); }
    for candidate in candidates {
        let existing = table.dns.entries.iter_mut().find(|entry| entry.host == host && entry.generation == generation && entry.candidate.ip == candidate.ip);
        if let Some(entry) = existing {
            if entry.candidate.merge(candidate.clone()) && entry.checked.is_some_and(|at| at.elapsed() < PROBE_STUMBLE_FOR) { continue; }
        }
        let work = table.dns.hosts.iter_mut().find(|work| work.host == host).ok_or("DNS maintenance host missing")?;
        if let Some(queued) = work.queued.iter_mut().find(|queued| queued.ip == candidate.ip) {
            if !queued.merge(candidate.clone()) { work.queued.push(candidate); }
        } else { work.queued.push(candidate); }
    }
    let queued = table.dns.hosts.iter().find(|work| work.host == host).is_some_and(|work| !work.queued.is_empty());
    if queued && !table.dns.pending.contains(&host) { table.dns.pending.push(host); }
    Ok(true)
}

pub(crate) fn take_dns_maintenance(host: &str, generation: u64) -> Result<Option<DnsMaintenanceWork>, String> {
    let mut table = TABLE.lock().map_err(|_| "route state unavailable")?;
    if table.dns.generation != generation { return Ok(None); }
    let work = table.dns.hosts.iter_mut().find(|work| work.host == host).ok_or("DNS maintenance host missing")?;
    if !work.queued.is_empty() { return Ok(Some(DnsMaintenanceWork::Probe(work.queued.remove(0)))); }
    if work.exhausted { return Ok(Some(DnsMaintenanceWork::Complete)); }
    Ok(work.cursor.take().map(DnsMaintenanceWork::Discover))
}

pub(crate) fn receive_dns_discovery(host: &str, generation: u64, cursor: crate::resolvers::DnsDiscoveryCursor,
    exhausted: bool) -> Result<bool, String> {
    let mut table = TABLE.lock().map_err(|_| "route state unavailable")?;
    if table.dns.generation != generation { return Ok(false); }
    let work = table.dns.hosts.iter_mut().find(|work| work.host == host).ok_or("DNS maintenance host missing")?;
    if work.cursor.is_some() { return Err("DNS discovery cursor already owned".into()); }
    work.cursor = Some(cursor);
    work.exhausted = exhausted;
    Ok(true)
}

/// The caller verifies the captured source witness against a fresh settings
/// read before publication; this owner rejects a superseded local generation.
pub(crate) fn publish_dns_candidate(host: &str, generation: u64, candidate: crate::resolvers::DnsCandidate,
    result: Result<crate::proxy::CandidateProbe, String>) -> Result<bool, String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !crate::gate_hosts::is_public_dns_target(&host, 443) || !crate::resolvers::is_public_v4(candidate.ip) {
        return Err("DNS candidate host or address denied".into());
    }
    let peer = DnsPeerIdentity { host: host.clone(), ip: candidate.ip, generation };
    let protected = live_dns_answer(&peer);
    let mut table = TABLE.lock().map_err(|_| "route state unavailable")?;
    if table.dns.generation != generation || table.dns.network != (table.context != 0).then_some(table.context) { return Ok(false); }
    if protected && !matches!(&result, Ok(crate::proxy::CandidateProbe::Reachable(_))) { return Ok(true); }
    let pos = table.dns.entries.iter().position(|entry| entry.host == host && entry.candidate.ip == candidate.ip);
    let entry = match pos {
        Some(pos) => &mut table.dns.entries[pos],
        None => {
            table.dns.entries.push(DnsEndpoint { host, candidate: candidate.clone(), generation,
                checked: None, latency: Duration::MAX, reachable: false, refusal_at: None, refusal_blocking: false, model_proven: false, model_seen: None,
                silent_until: None, silent_streak: 0, drop_streak: 0, drop_continuity: None, last_event_at: None, last_event_source: None });
            table.dns.entries.last_mut().expect("inserted DNS endpoint")
        }
    };
    if entry.generation != generation {
        entry.model_proven = false;
        entry.reachable = false;
        entry.silent_until = None;
        entry.silent_streak = 0;
        entry.drop_streak = 0;
        entry.drop_continuity = None;
        entry.last_event_at = None;
        entry.last_event_source = None;
        entry.candidate = candidate;
    } else if !entry.candidate.merge(candidate.clone()) {
        entry.candidate = candidate;
    }
    entry.generation = generation;
    entry.checked = Some(Instant::now());
    match result {
        Ok(crate::proxy::CandidateProbe::Reachable(latency)) => { entry.reachable = true; entry.latency = latency; }
        Ok(crate::proxy::CandidateProbe::Refused) => { entry.reachable = false; entry.refusal_at = Some(Instant::now()); entry.refusal_blocking = true; entry.model_proven = false; }
        Err(_) => { entry.reachable = false; }
    }
    DNS_CHANGED.notify_all();
    Ok(true)
}

pub(crate) fn finish_dns_maintenance(host: &str, generation: u64) {
    if let Ok(mut table) = TABLE.lock() {
        if table.dns.generation == generation {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            table.dns.pending.retain(|pending| pending != &host);
            if let Some(work) = table.dns.hosts.iter_mut().find(|work| work.host == host) { work.finished_at = Some(Instant::now()); }
            DNS_CHANGED.notify_all();
        }
    }
}

pub(crate) fn abandon_dns_maintenance(host: &str, generation: u64) {
    if let Ok(mut table) = TABLE.lock() {
        if table.dns.generation == generation {
            table.dns.pending.retain(|pending| pending != host);
            table.dns.hosts.retain(|work| work.host != host);
            DNS_CHANGED.notify_all();
        }
    }
}

pub(crate) fn suspend_dns_maintenance() {
    if let Ok(mut table) = TABLE.lock() {
        table.dns.witness = None;
        table.dns.pending.clear();
        table.dns.hosts.clear();
        DNS_CHANGED.notify_all();
    }
}

pub(crate) fn dns_has_pending_maintenance() -> bool {
    TABLE.lock().ok().is_some_and(|table| !table.dns.pending.is_empty())
}

pub(crate) fn register_dns_maintenance_thread() {
    if let Ok(mut table) = TABLE.lock() { table.dns.maintenance_thread = Some(std::thread::current()); }
}

pub(crate) fn unregister_dns_maintenance_thread() {
    if let Ok(mut table) = TABLE.lock() {
        if table.dns.maintenance_thread.as_ref().is_some_and(|thread| thread.id() == std::thread::current().id()) {
            table.dns.maintenance_thread = None;
        }
    }
}

pub(crate) fn request_dns_refresh(host: &str) {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !crate::gate_hosts::is_public_dns_target(&host, 443) { return; }
    let wake = TABLE.lock().ok().and_then(|mut table| {
        for entry in &mut table.dns.entries { if entry.host == host { entry.reachable = false; } }
        if let Some(work) = table.dns.hosts.iter_mut().find(|work| work.host == host) {
            if work.exhausted { work.cursor = Some(Default::default()); work.exhausted = false; work.finished_at = None; }
        }
        if !table.dns.pending.contains(&host) { table.dns.pending.push(host); }
        table.dns.maintenance_thread.clone()
    });
    if let Some(wake) = wake { wake.unpark(); }
}

pub(crate) fn wait_dns_change(budget: Duration) -> Result<(), String> {
    let table = TABLE.lock().map_err(|_| "route state unavailable")?;
    let _guard = DNS_CHANGED.wait_timeout(table, budget).map_err(|_| "route state unavailable")?;
    Ok(())
}

pub(crate) fn dns_selection(host: &str, witness: &crate::resolvers::DnsSourceWitness) -> Result<DnsSelection, String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let table = TABLE.lock().map_err(|_| "route state unavailable")?;
    let network = (table.context != 0).then_some(table.context);
    if table.dns.witness.as_ref() != Some(witness) || table.dns.network != network { return Ok(DnsSelection::Pending); }
    let generation = table.dns.generation;
    let mut ready: Vec<_> = table.dns.entries.iter().filter(|entry| entry.host == host && entry.generation == generation
        && entry.reachable && entry.checked.is_some_and(|at| at.elapsed() < SAMPLE_TTL)
        && entry.silent_until.is_none_or(|until| Instant::now() >= until)
        && (!entry.refusal_blocking || entry.refusal_at.is_none_or(|at| at.elapsed() >= FIRST_PENALTY)))
        .map(|entry| (entry.model_proven && network.is_some(), entry.latency, entry.candidate.clone())).collect();
    ready.sort_by_key(|(proven, latency, _)| (!*proven, *latency));
    if !ready.is_empty() {
        return Ok(DnsSelection::Ready(ready.into_iter().map(|(_, _, candidate)|
            (DnsAdmission { ip: candidate.ip, generation }, candidate)).collect()));
    }
    if table.dns.pending.contains(&host) { Ok(DnsSelection::Pending) } else { Ok(DnsSelection::NoEligible) }
}

pub(crate) fn dns_admission_current(host: &str, admission: DnsAdmission, witness: &crate::resolvers::DnsSourceWitness) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let Ok(table) = TABLE.lock() else { return false; };
    let network = (table.context != 0).then_some(table.context);
    table.dns.generation == admission.generation && table.dns.network == network && table.dns.witness.as_ref() == Some(witness)
        && table.dns.entries.iter().any(|entry| entry.host == host && entry.generation == admission.generation
            && entry.candidate.ip == admission.ip && entry.reachable && entry.checked.is_some_and(|at| at.elapsed() < SAMPLE_TTL)
            && entry.silent_until.is_none_or(|until| Instant::now() >= until)
            && (!entry.refusal_blocking || entry.refusal_at.is_none_or(|at| at.elapsed() >= FIRST_PENALTY)))
}

pub(crate) fn dns_maintenance_pending(host: &str, witness: &crate::resolvers::DnsSourceWitness) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    TABLE.lock().ok().is_some_and(|table| table.dns.witness.as_ref() == Some(witness)
        && table.dns.network == (table.context != 0).then_some(table.context) && table.dns.pending.contains(&host))
}

#[cfg(test)]
fn apply_dns_feedback(dns: &mut DnsState, peer: &DnsPeerIdentity, answered: bool) -> bool {
    let network_measured = dns.network.is_some();
    if let Some(entry) = dns.entries.iter_mut().find(|entry|
        entry.generation == peer.generation && entry.host == peer.host && entry.candidate.ip == peer.ip) {
        if answered {
            entry.model_seen = Some(Instant::now());
            if network_measured { entry.model_proven = true; entry.refusal_blocking = false; entry.silent_until = None; entry.silent_streak = 0; }
        } else { entry.model_proven = false; entry.refusal_at = Some(Instant::now()); entry.refusal_blocking = true; }
        true
    } else { false }
}

pub(crate) enum LogFeedback {
    Direct { applied: bool, tunnel: u64 },
    Other(Option<(Kind, u64)>),
    Ambiguous,
}

/// Aggregate observations retain their legacy path only for non-Direct routes.
/// Direct authority comes exclusively from the separately received batch.
pub(crate) fn receive_log_feedback(at: Instant, route_host: Option<&str>, _endpoint_host: Option<&str>, _answered: Option<bool>) -> LogFeedback {
    let host = route_host.map(|h| h.trim_end_matches('.').to_ascii_lowercase());
    let Ok(list) = TUNNELS.lock() else { return LogFeedback::Ambiguous; };
    let mut direct = false;
    let mut other = false;
    let mut newest: Option<&Tunnel> = None;
    for tunnel in list.iter().filter(|t| host.as_ref().is_none_or(|h| *h == t.host))
        .filter(|t| t.opened <= at + ATTRIBUTION_SLACK)
        .filter(|t| t.closed.is_none_or(|closed| closed + ATTRIBUTION_SLACK >= at)) {
        if tunnel.kind == Kind::Direct { direct = true; } else { other = true; }
        if newest.is_none_or(|old| old.opened <= tunnel.opened) { newest = Some(tunnel); }
    }
    if direct && other { return LogFeedback::Ambiguous; }
    let carried = newest.map(|t| (t.kind, t.id));
    if let Some((Kind::Direct, tunnel)) = carried {
        LogFeedback::Direct { applied: false, tunnel }
    } else { LogFeedback::Other(carried) }
}

fn live_dns_answer(peer: &DnsPeerIdentity) -> bool {
    TUNNELS.lock().ok().is_some_and(|list| list.iter().any(|t|
        t.closed.is_none() && t.dns_answered && t.dns_peer.as_ref() == Some(peer)))
}

fn apply_dns_silence(dns: &mut DnsState, peer: &DnsPeerIdentity, protected: bool) -> Option<Duration> {
    if dns.generation != peer.generation || protected { return None; }
    let measured = dns.network.is_some();
    let entry = dns.entries.iter_mut().find(|entry|
        entry.generation == peer.generation && entry.host == peer.host && entry.candidate.ip == peer.ip)?;
    if entry.silent_until.is_some_and(|until| Instant::now() < until)
        || (entry.refusal_blocking && entry.refusal_at.is_some_and(|at| at.elapsed() < FIRST_PENALTY))
        || (measured && entry.model_proven && entry.model_seen.is_some_and(|at| at.elapsed() < PROOF_PROTECTS_FOR)) {
        return None;
    }
    let index = (entry.silent_streak as usize).min(SILENT_STEPS.len() - 1);
    let duration = SILENT_STEPS[index];
    entry.silent_until = Instant::now().checked_add(duration);
    if entry.silent_until.is_none() { return None; }
    entry.silent_streak = entry.silent_streak.saturating_add(1);
    Some(duration)
}

/// A silent tunnel may affect only its own currently witnessed endpoint.
fn dns_silence(peer: &DnsPeerIdentity, binding: &DnsBinding) -> Option<Duration> {
    let protected = live_dns_answer(peer);
    let policy = if binding.allow_missing_defaults { crate::resolvers::DnsMissingPolicy::LegacyDefaults } else { crate::resolvers::DnsMissingPolicy::RequireSettings };
    let fresh = crate::resolvers::current_witness(policy).ok()?;
    if fresh != binding.witness || !crate::resolvers::source_is_current(&binding.candidate, &fresh).ok()? { return None; }
    let mut table = TABLE.lock().ok()?;
    let network = (table.context != 0).then_some(table.context);
    if table.dns.generation != peer.generation || table.dns.network != network || table.dns.witness.as_ref() != Some(&fresh) { return None; }
    if !crate::resolvers::source_is_current(&binding.candidate, &fresh).ok()? { return None; }
    let current = table.dns.entries.iter().find(|entry| entry.generation == peer.generation && entry.host == peer.host && entry.candidate.ip == peer.ip)?;
    if !crate::resolvers::source_is_current(&current.candidate, &fresh).ok()? { return None; }
    apply_dns_silence(&mut table.dns, peer, protected)
}

static TUNNELS: Mutex<Vec<Tunnel>> = Mutex::new(Vec::new());
static NEXT_TUNNEL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The connection the current thread is serving, between `begin` and `end`.
///
/// Thread-local because the routes that commit a tunnel (`note_used`) are
/// called on the thread that serves it, and two of them live in private
/// modules whose signatures carry no socket (I68).
struct Serving {
    client: Option<TcpStream>,
    host: String,
    tunnel: Option<u64>,
    /// Handed to the pump by `serving_activity` once `note_used` has made one.
    activity: Option<Arc<Activity>>,
    own: Option<Arc<crate::upstream::OwnContext>>,
    dns_binding: Option<DnsBinding>,
}

#[derive(Clone)]
struct DnsBinding {
    admission: DnsAdmission,
    candidate: crate::resolvers::DnsCandidate,
    witness: crate::resolvers::DnsSourceWitness,
    allow_missing_defaults: bool,
}

thread_local! {
    static SERVING: RefCell<Option<Serving>> = const { RefCell::new(None) };
}

/// Called by the proxy before it offers a gate connection to the routes. The
/// returned guard ends the record when it goes out of scope, whichever way the
/// serving code leaves - a record left open would pin every later event on a
/// tunnel that no longer exists.
#[must_use]
pub fn begin_gate_connection(client: &TcpStream, host: &str) -> GateConnection {
    let clone = client.try_clone().ok();
    SERVING.with(|s| {
        *s.borrow_mut() = Some(Serving {
            client: clone,
            host: host.trim_end_matches('.').to_ascii_lowercase(),
            tunnel: None,
            activity: None,
            own: None,
            dns_binding: None,
        })
    });
    GateConnection { _private: () }
}

pub(crate) fn bind_serving_own(own: Arc<crate::upstream::OwnContext>) {
    SERVING.with(|s| { if let Some(serving) = s.borrow_mut().as_mut() { serving.own = Some(own); } });
}

pub(crate) fn bind_serving_dns(admission: DnsAdmission, candidate: crate::resolvers::DnsCandidate,
    witness: crate::resolvers::DnsSourceWitness, allow_missing_defaults: bool) -> bool {
    SERVING.with(|s| {
        let mut state = s.borrow_mut();
        let Some(serving) = state.as_mut() else { return false; };
        serving.dns_binding = Some(DnsBinding { admission, candidate, witness, allow_missing_defaults });
        true
    })
}

/// Revalidate a selected candidate against fresh inputs and the real socket
/// immediately before any CONNECT response bytes. Non-candidate paths are
/// unchanged and return Ok without manufacturing a binding.
pub(crate) fn validate_serving_dns(socket: &TcpStream) -> Result<(), String> {
    let binding = SERVING.with(|s| s.borrow().as_ref().and_then(|serving| serving.dns_binding.clone()));
    let Some(binding) = binding else { return Ok(()); };
    let policy = if binding.allow_missing_defaults { crate::resolvers::DnsMissingPolicy::LegacyDefaults } else { crate::resolvers::DnsMissingPolicy::RequireSettings };
    let fresh = crate::resolvers::current_witness(policy).map_err(|_| "DNS source settings unavailable")?;
    let source_current = crate::resolvers::source_is_current(&binding.candidate, &fresh).map_err(|error| format!("DNS source check failed before commit: {error:?}"))?;
    if fresh != binding.witness || !source_current {
        return Err("DNS candidate source changed".into());
    }
    let host = SERVING.with(|s| s.borrow().as_ref().map(|serving| serving.host.clone())).ok_or("DNS serving context missing")?;
    if !dns_admission_current(&host, binding.admission, &fresh) { return Err("DNS candidate eligibility changed".into()); }
    let expected = std::net::SocketAddr::from((binding.admission.ip, 443));
    if socket.peer_addr().ok() != Some(expected) { return Err("DNS candidate peer changed".into()); }
    Ok(())
}

/// Ends the current thread's gate-connection record when dropped.
pub struct GateConnection {
    _private: (),
}

impl Drop for GateConnection {
    fn drop(&mut self) {
        end_gate_connection();
    }
}

/// Hands the tunnel being served on this thread its upstream socket, so a cut
/// closes both sides (G52). A no-op outside a gate connection - `splice` also
/// carries every non-gate tunnel.
pub fn attach_upstream(upstream: &TcpStream) {
    let Some(id) = SERVING.with(|s| s.borrow().as_ref().and_then(|s| s.tunnel)) else {
        return;
    };
    let peer = upstream.peer_addr().ok();
    let Ok(clone) = upstream.try_clone() else {
        return;
    };
    if let Ok(mut list) = TUNNELS.lock() {
        if let Some(t) = list.iter_mut().find(|t| t.id == id && t.closed.is_none()) {
            if t.kind == Kind::Direct {
                if let (Some(binding), Some(std::net::SocketAddr::V4(actual))) = (t.dns_binding.as_ref(), peer) {
                    let admission = binding.admission;
                    if *actual.ip() == admission.ip && actual.port() == 443 {
                        t.dns_peer = Some(DnsPeerIdentity { host: t.host.clone(), ip: admission.ip, generation: admission.generation });
                    }
                }
            }
            t.upstream = Some(clone);
        }
    }
}

/// Ends the current thread's gate-connection record.
fn end_gate_connection() {
    let serving = SERVING.with(|s| s.borrow_mut().take());
    let Some(serving) = serving else { return };
    let Some(id) = serving.tunnel else { return };
    let mut went_silent = None;
    let mut direct_silent = None;
    if let Ok(mut list) = TUNNELS.lock() {
        if let Some(t) = list.iter_mut().find(|t| t.id == id) {
            t.closed = Some(Instant::now());
            t.client = None;
            t.upstream = None;
            let (to_client, to_upstream) = t.activity.bytes();
            if t.kind != Kind::Direct && is_silent(to_client, to_upstream) && t.answered_at.is_none() {
                went_silent = Some(t.kind);
            } else if t.kind == Kind::Direct && is_silent(to_client, to_upstream) && !t.dns_answered {
                direct_silent = t.dns_peer.clone().zip(t.dns_binding.clone());
            }
        }
        prune(&mut list);
    }
    if let Some((peer, binding)) = direct_silent {
        if let Some(bench) = dns_silence(&peer, &binding) {
            note(&format!("DNS Direct: проверенный адрес не ответил — отложен на {} мин", bench.as_secs() / 60));
        }
    }
    // After `TUNNELS` is released: the two locks are never held together (G30).
    if let Some(kind) = went_silent {
        let bench = if kind == Kind::Own {
            serving.own.as_ref().and_then(|own| {
                let streaming = live_answer_own(own).is_some();
                own.if_current(|| silence(kind, streaming)).flatten()
            })
        } else { silence(kind, live_answer(kind).is_some()) };
        if let Some(bench) = bench {
            note(&format!(
                "{}: соединение открылось, но Google не ответил ни байта — маршрут отложен на {} мин, следующие соединения идут другим путём",
                kind.label(),
                bench.as_secs() / 60
            ));
        }
    }
}

/// A tunnel the client spoke into and got nothing - or next to nothing - back
/// from. One the client never used (nothing out) says nothing about the route.
fn is_silent(to_client: u64, to_upstream: u64) -> bool {
    to_upstream > 0 && to_client < SILENT_MAX_BYTES
}

/// Puts `kind` behind the others for going silent on a live tunnel. `None` when
/// it is already there - a burst of the client's parallel connections dying on
/// one dead route is one event, not a climb up the steps - when a refusal
/// already benched it and cut the tunnel that is closing now, or when the route
/// is demonstrably carrying: an answer streaming through another of its tunnels
/// (`streaming`, D32) or one that arrived within `PROOF_PROTECTS_FOR` (D31).
fn silence(kind: Kind, streaming: bool) -> Option<Duration> {
    let mut t = TABLE.lock().ok()?;
    let i = kind.index();
    if penalised(&t.penalised, kind) || penalised(&t.silent, kind) {
        return None;
    }
    if streaming || t.ok_at[i].is_some_and(|ok| ok.elapsed() < PROOF_PROTECTS_FOR) {
        return None;
    }
    let step = (t.silent_streak[i] as usize).min(SILENT_STEPS.len() - 1);
    let bench = SILENT_STEPS[step];
    t.silent_streak[i] = t.silent_streak[i].saturating_add(1);
    t.silent[i] = Some(Instant::now() + bench);
    Some(bench)
}

/// The client's log says a generation request died under its connection (EOF)
/// again and again with no answer between: the route said `200`, completed the
/// handshake and then closed on the request, which neither the probe nor the
/// silent-tunnel check can see. Same bench and same protections as `silence` -
/// not while an answer streams through it, not within `PROOF_PROTECTS_FOR` of
/// one - because one EOF is a connection reaped and the retry belongs on the
/// same route. Returns the bench, `None` when nothing was done.
pub fn bench_dropping(kind: Kind) -> Option<Duration> {
    silence(kind, live_answer(kind).is_some())
}

/// Notes that a gate tunnel was just opened on `kind`. Called where the `200`
/// goes out, i.e. once the route is the one the client is actually on.
pub fn note_used(kind: Kind) {
    let now = Instant::now();
    let id = NEXT_TUNNEL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (client, host, own, dns_binding) = SERVING
        .with(|s| {
            let mut s = s.borrow_mut();
            let serving = s.as_mut()?;
            serving.tunnel = Some(id);
            Some((
                serving.client.as_ref().and_then(|c| c.try_clone().ok()),
                serving.host.clone(),
                if kind == Kind::Own { serving.own.clone() } else { None },
                if kind == Kind::Direct { serving.dns_binding.clone() } else { None },
            ))
        })
        .unwrap_or_default();
    let publish = || { if let Ok(mut t) = TABLE.lock() { t.last_used = Some((kind, now)); } };
    if kind == Kind::Own {
        if let Some(bound) = own.as_ref() { bound.if_current(publish); }
    } else { publish(); }
    let activity = Arc::new(Activity::default());
    SERVING.with(|s| {
        if let Some(serving) = s.borrow_mut().as_mut() {
            serving.activity = Some(Arc::clone(&activity));
        }
    });
    if let Ok(mut list) = TUNNELS.lock() {
        list.push(Tunnel {
            id,
            kind,
            own: own.as_ref().map(Arc::downgrade),
            host,
            opened: now,
            closed: None,
            answered_at: None,
            activity,
            client,
            upstream: None,
            dns_binding,
            dns_peer: None,
            dns_answered: false,
        });
        prune(&mut list);
    }
}

/// The activity stamp of the gate tunnel this thread is serving, for its pump
/// to mark as bytes move. `None` outside a gate connection, or before the
/// route committed one: `splice` carries every non-gate tunnel too.
pub fn serving_activity() -> Option<Arc<Activity>> {
    SERVING.with(|s| s.borrow().as_ref().and_then(|s| s.activity.clone()))
}

fn prune(list: &mut Vec<Tunnel>) {
    list.retain(|t| t.closed.is_none_or(|c| c.elapsed() < TUNNEL_MEMORY));
    // Oldest closed first; the list is in opening order.
    while list.len() > MAX_TUNNEL_RECORDS {
        match list.iter().position(|t| t.closed.is_some()) {
            Some(i) => {
                list.remove(i);
            }
            None => break,
        }
    }
}

/// How many gate tunnels each route has open right now.
pub fn open_counts() -> [u32; N] {
    let mut out = [0u32; N];
    if let Ok(list) = TUNNELS.lock() {
        for t in list.iter().filter(|t| t.closed.is_none()) {
            out[t.kind.index()] += 1;
        }
    }
    out
}

/// Closes every open gate tunnel on `kind`. The splice under each ends on the
/// shutdown, the client sees its connection go and dials again - and its next
/// connection is offered to the table afresh.
fn cut_tunnels(kind: Kind) {
    let Ok(mut list) = TUNNELS.lock() else { return };
    // A tunnel that carried a model answer is never cut, whatever brought the
    // route here. `blame` already turns back before this for the same reason,
    // and saying it twice is deliberate: this is the call that destroys a live
    // answer, so it is the call that must not depend on a caller's check (D32).
    for t in list
        .iter_mut()
        .filter(|t| t.kind == kind && t.closed.is_none() && t.answered_at.is_none())
    {
        for sock in [t.client.take(), t.upstream.take()].into_iter().flatten() {
            sock.shutdown(std::net::Shutdown::Both).ok();
        }
    }
}

/// Closes every open gate tunnel on `kind`, answered or not. Only for the user's
/// own switch-off of a route: D32 guards a live answer against *our* mistaken
/// cuts, and a route the user turned off must not keep carrying traffic.
pub(crate) fn cut_absent_own() -> Result<(), String> {
    let sockets = crate::upstream::while_own_absent(|| {
        let mut list = TUNNELS.lock().map_err(|_| "tunnel owner unavailable".to_string())?;
        Ok::<_, String>(list.iter_mut().filter(|t| t.kind == Kind::Own && t.closed.is_none())
            .flat_map(|t| [t.client.take(), t.upstream.take()].into_iter().flatten()).collect::<Vec<_>>())
    })?;
    if let Some(sockets) = sockets {
        for sock in sockets? {
            if let Err(error) = sock.shutdown(std::net::Shutdown::Both) {
                crate::dns_forwarder::log_proxy(&format!("own tunnel shutdown failed: {error}"));
            }
        }
    }
    Ok(())
}

/// The route that carried a request answered at `at`: the one with a tunnel
/// open around that moment, for `host` when the log line named it. When tunnels
/// on several routes were open, the one opened most recently before it - a
/// client keeps one connection per host and puts new requests on the newest.
///
/// `None` when no tunnel of ours was open around it: the client reached Google
/// some other way, and pinning the event on whichever route last opened a
/// tunnel would bench a route that never saw it.
#[cfg_attr(not(test), allow(dead_code))]
pub fn attribute(at: Instant, host: Option<&str>) -> Option<Kind> {
    attribute_tunnel(at, host).map(|(kind, _)| kind)
}

/// The same, naming the tunnel as well: an answer is credited to the one that
/// carried it, not only to its route, because that tunnel is what tells a
/// conversation in flight from a pooled connection being refused (D32).
pub fn attribute_tunnel(at: Instant, host: Option<&str>) -> Option<(Kind, u64)> {
    let host = host.map(|h| h.trim_end_matches('.').to_ascii_lowercase());
    let list = TUNNELS.lock().ok()?;
    list.iter()
        .filter(|t| host.as_ref().is_none_or(|h| *h == t.host))
        .filter(|t| t.opened <= at + ATTRIBUTION_SLACK)
        .filter(|t| t.closed.is_none_or(|c| c + ATTRIBUTION_SLACK >= at))
        .max_by_key(|t| t.opened)
        .map(|t| (t.kind, t.id))
}

/// Endpoint evidence is valid only if every plausible tunnel names the same
/// actual checked peer and admission generation. Aggregate attribution remains
/// unchanged for the existing route-level controls.
fn matching_dns_tunnels<'a>(list: &'a [Tunnel], at: Instant, host: &str) -> Option<(DnsPeerIdentity, Vec<&'a Tunnel>)> {
    let mut matches = list.iter().filter(|t| t.host == host)
        .filter(|t| t.opened <= at + ATTRIBUTION_SLACK)
        .filter(|t| t.closed.is_none_or(|closed| closed + ATTRIBUTION_SLACK >= at));
    let first = matches.next()?;
    let peer = first.dns_peer.clone()?;
    let mut found = vec![first];
    for tunnel in matches {
        if tunnel.dns_peer.as_ref() != Some(&peer) { return None; }
        found.push(tunnel);
    }
    Some((peer, found))
}

#[cfg(test)]
fn unique_dns_peer(at: Instant, host: Option<&str>) -> Option<DnsPeerIdentity> {
    let host = host?.trim_end_matches('.').to_ascii_lowercase();
    let list = TUNNELS.lock().ok()?;
    matching_dns_tunnels(&list, at, &host).map(|(peer, _)| peer)
}

fn dns_feedback_bindings(at: Instant, host: Option<&str>) -> Option<(DnsPeerIdentity, Vec<(u64, DnsBinding)>)> {
    let host = host?.trim_end_matches('.').to_ascii_lowercase();
    let list = TUNNELS.lock().ok()?;
    let (peer, plausible) = matching_dns_tunnels(&list, at, &host)?;
    let bindings = plausible.into_iter().map(|tunnel| tunnel.dns_binding.clone().map(|binding| (tunnel.id, binding))).collect::<Option<Vec<_>>>()?;
    Some((peer, bindings))
}

pub(crate) enum ShutdownSide {
    Succeeded,
    Missing,
    Failed(std::io::Error),
}

pub(crate) enum DirectBatchEffect {
    NoAction(&'static str),
    StateChanged,
    Protected,
    AlreadyClosed,
    Shutdown { client: ShutdownSide, upstream: ShutdownSide },
}

struct PreparedDirect {
    peer: DnsPeerIdentity,
    ids: Vec<u64>,
    witness: crate::resolvers::DnsSourceWitness,
    needs_explicit: bool,
    needs_legacy: bool,
}

fn prepare_direct_signal(signal: &crate::ls_log::DirectSignal,
    initial_explicit: Option<&crate::resolvers::DnsSourceWitness>, initial_legacy: Option<&crate::resolvers::DnsSourceWitness>) -> Option<PreparedDirect> {
    if signal.conflicting_record || signal.source.is_none() || signal.record_start >= signal.record_end { return None; }
    let at = signal.at?;
    if at > Instant::now() || at.elapsed() > TUNNEL_MEMORY { return None; }
    let host = signal.host.as_deref()?;
    if !crate::gate_hosts::is_public_dns_target(host, 443) { return None; }
    let (peer, bindings) = dns_feedback_bindings(at, Some(host))?;
    let mut witness = None;
    let mut needs_explicit = false;
    let mut needs_legacy = false;
    for (_, binding) in &bindings {
        needs_explicit |= !binding.allow_missing_defaults;
        needs_legacy |= binding.allow_missing_defaults;
        let fresh = if binding.allow_missing_defaults { initial_legacy? } else { initial_explicit? };
        if *fresh != binding.witness || !crate::resolvers::source_is_current(&binding.candidate, fresh).ok()? { return None; }
        if witness.as_ref().is_some_and(|previous| previous != fresh) { return None; }
        witness = Some(fresh.clone());
    }
    Some(PreparedDirect { peer, ids: bindings.into_iter().map(|(id, _)| id).collect(), witness: witness?, needs_explicit, needs_legacy })
}

struct DirectCutPlan { peer: DnsPeerIdentity, id: u64, witness: crate::resolvers::DnsSourceWitness }

#[cfg(test)]
static DIRECT_PREPARED_TEST_PAUSE: Mutex<Option<(std::sync::mpsc::Sender<bool>, std::sync::mpsc::Receiver<()>)>> = Mutex::new(None);

/// Receive a complete drain once. Only this owner applies Direct state and
/// recovers the exact original sockets; no aggregate Direct fallback follows.
pub(crate) fn receive_direct_batch(signals: &[crate::ls_log::DirectSignal]) -> Vec<DirectBatchEffect> {
    use crate::ls_log::{DirectSignalKind, SignalContinuity};
    if signals.is_empty() { return Vec::new(); }
    let initial_explicit = crate::resolvers::current_witness(crate::resolvers::DnsMissingPolicy::RequireSettings).ok();
    let initial_legacy = crate::resolvers::current_witness(crate::resolvers::DnsMissingPolicy::LegacyDefaults).ok();
    let mut order: Vec<_> = signals.iter().collect();
    order.sort_by_key(|signal| signal.at);
    let mut tied = vec![false; order.len()];
    let mut start = 0;
    while start < order.len() {
        let mut end = start + 1;
        while end < order.len() && order[end].at == order[start].at { end += 1; }
        if order[start].at.is_some() && order[start..end].iter().any(|signal| signal.source != order[start].source) {
            tied[start..end].fill(true);
        } else {
            order[start..end].sort_by_key(|signal| signal.record_start);
        }
        start = end;
    }
    let mut binding_cache: std::collections::HashMap<(String, Instant), Option<Arc<PreparedDirect>>> = std::collections::HashMap::new();
    let prepared: Vec<_> = order.iter().enumerate().map(|(index, signal)| {
        if (tied[index] && !matches!(&signal.kind, DirectSignalKind::Answer))
            || signal.conflicting_record || signal.source.is_none() || signal.record_start >= signal.record_end {
            return None;
        }
        let key = (signal.host.as_ref()?.clone(), signal.at?);
        binding_cache.entry(key).or_insert_with(|| prepare_direct_signal(signal, initial_explicit.as_ref(), initial_legacy.as_ref()).map(Arc::new)).clone()
    }).collect();
    #[cfg(test)]
    {
        let pause = DIRECT_PREPARED_TEST_PAUSE.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some((entered, release)) = pause {
            if entered.send(prepared.iter().any(Option::is_some)).is_ok() { let _ = release.recv_timeout(Duration::from_secs(10)); }
        }
    }
    // A final uncached observation occurs after preparation and immediately
    // before entering the in-memory batch transaction.
    let requires_settings = prepared.iter().flatten().any(|item| item.needs_explicit);
    let allows_legacy = prepared.iter().flatten().any(|item| item.needs_legacy);
    let current_explicit = requires_settings.then(|| crate::resolvers::current_witness(crate::resolvers::DnsMissingPolicy::RequireSettings));
    let current_legacy = allows_legacy.then(|| crate::resolvers::current_witness(crate::resolvers::DnsMissingPolicy::LegacyDefaults));
    let mut results = Vec::new();
    let mut plans: Vec<DirectCutPlan> = Vec::new();
    let mut sockets: Vec<(Option<TcpStream>, Option<TcpStream>)> = Vec::new();
    {
        // Existing lock order: tunnel owner before routes table. No I/O while
        // locked; original handles are taken only after the whole drain.
        let Ok(mut tunnels) = TUNNELS.lock() else { return vec![DirectBatchEffect::NoAction("tunnel state unavailable")]; };
        let Ok(mut table) = TABLE.lock() else { return vec![DirectBatchEffect::NoAction("route state unavailable")]; };
        let expired: Vec<_> = table.dns.consumed.iter().filter(|cursor| cursor.observed.elapsed() >= TUNNEL_MEMORY)
            .map(|cursor| cursor.source.clone()).collect();
        table.dns.consumed.retain(|cursor| cursor.observed.elapsed() < TUNNEL_MEMORY);
        for entry in &mut table.dns.entries {
            if entry.drop_continuity.as_ref().is_some_and(|(source, _)| expired.contains(source)) { entry.drop_continuity = None; }
        }
        // Admit exact source spans against the committed pre-batch cursor in
        // physical order. Chronological evaluation below cannot advance that
        // cursor past another still-unprocessed fresh record.
        let mut sources: std::collections::HashMap<crate::ls_log::LogSourceId, Vec<usize>> = std::collections::HashMap::new();
        for (index, signal) in order.iter().enumerate() {
            if let Some(source) = signal.source.as_ref() { sources.entry(source.clone()).or_default().push(index); }
        }
        let mut admitted = vec![false; order.len()];
        let mut boundary = vec![None; order.len()];
        for (source, mut indices) in sources {
            indices.sort_by_key(|index| (order[*index].record_start, order[*index].record_end));
            let mut overlaps = std::collections::HashSet::new();
            let mut widest: Option<usize> = None;
            for &index in &indices {
                if let Some(prior) = widest {
                    let a = order[prior]; let b = order[index];
                    if b.record_start < a.record_end && (a.record_start, a.record_end) != (b.record_start, b.record_end) {
                        overlaps.insert(prior); overlaps.insert(index);
                    }
                    if b.record_end > a.record_end { widest = Some(index); }
                } else { widest = Some(index); }
            }
            let cursor = table.dns.consumed.iter().position(|cursor| cursor.source == source);
            let mut end = cursor.map_or(0, |index| table.dns.consumed[index].end);
            let mut latest_boundary = cursor.and_then(|index| table.dns.consumed[index].boundary);
            let mut advanced = false;
            for index in indices {
                let signal = order[index];
                if signal.record_start >= signal.record_end { continue; }
                if signal.record_start < end {
                    if overlaps.contains(&index) && signal.record_end > end {
                        end = signal.record_end;
                        advanced = true;
                    }
                    continue;
                }
                if overlaps.contains(&index) {
                    end = signal.record_end;
                    advanced = true;
                    latest_boundary = Some(signal.record_start);
                    continue;
                }
                admitted[index] = true;
                end = signal.record_end;
                advanced = true;
                if signal.continuity == SignalContinuity::Fence || prepared[index].is_none() {
                    latest_boundary = Some(signal.record_start);
                }
                boundary[index] = latest_boundary;
            }
            if advanced {
                if let Some(index) = cursor {
                    table.dns.consumed[index].end = end;
                    table.dns.consumed[index].boundary = latest_boundary;
                    table.dns.consumed[index].observed = Instant::now();
                } else {
                    table.dns.consumed.push(DnsSourceCursor { source, end, boundary: latest_boundary, observed: Instant::now() });
                }
            }
        }
        for (index, (signal, prepared)) in order.into_iter().zip(prepared).enumerate() {
            let Some(source) = signal.source.as_ref() else {
                for entry in &mut table.dns.entries { entry.drop_continuity = None; }
                results.push(DirectBatchEffect::NoAction("source identity unavailable"));
                continue;
            };
            if !admitted[index] { results.push(DirectBatchEffect::NoAction("invalid, overlapping or consumed record")); continue; }
            let Some(prepared) = prepared else { results.push(DirectBatchEffect::NoAction("event binding unavailable or ambiguous")); continue; };
            let at = signal.at.expect("prepared timestamp");
            if (prepared.needs_explicit && !matches!(current_explicit.as_ref(), Some(Ok(witness)) if witness == &prepared.witness))
                || (prepared.needs_legacy && !matches!(current_legacy.as_ref(), Some(Ok(witness)) if witness == &prepared.witness)) {
                results.push(DirectBatchEffect::NoAction("settings changed before batch")); continue;
            }
            let network = (table.context != 0).then_some(table.context);
            if table.dns.generation != prepared.peer.generation || table.dns.network != network || table.dns.witness.as_ref() != Some(&prepared.witness)
                {
                results.push(DirectBatchEffect::NoAction("source or context changed")); continue;
            }
            let still_plausible = matching_dns_tunnels(&tunnels, at, &prepared.peer.host)
                .is_some_and(|(peer, plausible)| peer == prepared.peer && plausible.len() == prepared.ids.len()
                    && plausible.iter().all(|tunnel| prepared.ids.contains(&tunnel.id)));
            if !still_plausible { results.push(DirectBatchEffect::NoAction("plausible tunnel set changed")); continue; }
            let mut ids = Vec::new();
            let mut invalid = false;
            for id in &prepared.ids {
                let Some(tunnel) = tunnels.iter().find(|tunnel| tunnel.id == *id) else { invalid = true; break; };
                if tunnel.opened > at + ATTRIBUTION_SLACK || tunnel.dns_peer.as_ref() != Some(&prepared.peer)
                    || tunnel.dns_binding.as_ref().is_none_or(|binding| binding.witness != prepared.witness
                        || !matches!(crate::resolvers::source_is_current(&binding.candidate, &prepared.witness), Ok(true))) {
                    invalid = true; break;
                }
                ids.push(*id);
            }
            if invalid { results.push(DirectBatchEffect::NoAction("original tunnel changed")); continue; }
            let peer_protected = tunnels.iter().any(|tunnel| tunnel.closed.is_none() && tunnel.dns_answered && tunnel.dns_peer.as_ref() == Some(&prepared.peer));
            let measured = table.dns.network.is_some();
            let Some(entry) = table.dns.entries.iter_mut().find(|entry| entry.generation == prepared.peer.generation
                && entry.host == prepared.peer.host && entry.candidate.ip == prepared.peer.ip) else {
                results.push(DirectBatchEffect::NoAction("endpoint no longer current")); continue;
            };
            let unordered = entry.last_event_at.is_some_and(|previous| {
                let gap = if previous > at { previous.duration_since(at) } else { at.duration_since(previous) };
                let same_ordered_source = signal.continuity == SignalContinuity::Proven
                    && entry.last_event_source.as_ref() == Some(source);
                (gap < Duration::from_secs(1) && !same_ordered_source)
                    || (previous > at && (gap >= Duration::from_secs(1) || !same_ordered_source))
            });
            if !matches!(crate::resolvers::source_is_current(&entry.candidate, &prepared.witness), Ok(true)) {
                results.push(DirectBatchEffect::NoAction("stale endpoint source")); continue;
            }
            if unordered {
                if matches!(&signal.kind, DirectSignalKind::Answer) {
                    // Unresolved ordering cannot justify a cut, but the valid
                    // original answer still conservatively protects its IDs.
                    plans.retain(|plan| plan.peer != prepared.peer || !ids.contains(&plan.id));
                    entry.model_seen = Some(entry.model_seen.map_or(at, |previous| previous.max(at)));
                    for id in &ids {
                        if let Some(tunnel) = tunnels.iter_mut().find(|tunnel| tunnel.id == *id && tunnel.closed.is_none()) { tunnel.dns_answered = true; }
                    }
                    results.push(DirectBatchEffect::StateChanged);
                } else {
                    results.push(DirectBatchEffect::NoAction("stale or unordered endpoint event"));
                }
                continue;
            }
            entry.last_event_source = Some(source.clone());
            match &signal.kind {
                DirectSignalKind::Answer => {
                    entry.last_event_at = Some(at);
                    entry.drop_streak = 0;
                    entry.drop_continuity = Some((source.clone(), signal.record_end));
                    entry.model_seen = Some(at);
                    if measured { entry.model_proven = true; entry.refusal_blocking = false; entry.silent_until = None; entry.silent_streak = 0; }
                    plans.retain(|plan| plan.peer != prepared.peer || !ids.contains(&plan.id));
                    for id in &ids {
                        if let Some(tunnel) = tunnels.iter_mut().find(|tunnel| tunnel.id == *id && tunnel.closed.is_none()) { tunnel.dns_answered = true; }
                    }
                    results.push(DirectBatchEffect::StateChanged);
                }
                DirectSignalKind::Refusal => {
                    entry.last_event_at = Some(at);
                    let already_penalized = entry.refusal_blocking && entry.refusal_at.is_some_and(|previous|
                        at.checked_duration_since(previous).is_some_and(|elapsed| elapsed < FIRST_PENALTY));
                    if !already_penalized { entry.refusal_at = Some(at); }
                    if !peer_protected { entry.model_proven = false; entry.refusal_blocking = true; }
                    for id in ids { if !plans.iter().any(|plan| plan.id == id) {
                        plans.push(DirectCutPlan { peer: prepared.peer.clone(), id, witness: prepared.witness.clone() });
                    } }
                    results.push(DirectBatchEffect::StateChanged);
                }
                DirectSignalKind::Drop => {
                    let continuous = signal.continuity == SignalContinuity::Proven && entry.drop_continuity.as_ref()
                        .is_some_and(|(previous, end)| previous == source && *end <= signal.record_start
                            && boundary[index].is_none_or(|start| *end > start));
                    entry.drop_streak = if continuous { entry.drop_streak.saturating_add(1) } else { 1 };
                    entry.drop_continuity = Some((source.clone(), signal.record_end));
                    entry.last_event_at = Some(at);
                    if entry.drop_streak >= crate::dns_forwarder::DROP_BENCH_AT {
                        if !peer_protected && entry.silent_until.is_none_or(|until| Instant::now() >= until) {
                            let index = (entry.silent_streak as usize).min(SILENT_STEPS.len() - 1);
                            entry.silent_until = at.checked_add(SILENT_STEPS[index]);
                            entry.silent_streak = entry.silent_streak.saturating_add(1);
                        }
                        for id in ids { if !plans.iter().any(|plan| plan.id == id) {
                            plans.push(DirectCutPlan { peer: prepared.peer.clone(), id, witness: prepared.witness.clone() });
                        } }
                    }
                    results.push(DirectBatchEffect::StateChanged);
                }
            }
        }
        for plan in plans {
                let id = plan.id;
                let Some(tunnel) = tunnels.iter_mut().find(|tunnel| tunnel.id == id && tunnel.dns_peer.as_ref() == Some(&plan.peer)) else {
                    results.push(DirectBatchEffect::NoAction("original tunnel missing")); continue;
                };
                let network = (table.context != 0).then_some(table.context);
                if table.dns.generation != plan.peer.generation || table.dns.network != network || table.dns.witness.as_ref() != Some(&plan.witness)
                    || tunnel.dns_binding.as_ref().is_none_or(|binding| binding.witness != plan.witness
                        || !matches!(crate::resolvers::source_is_current(&binding.candidate, &plan.witness), Ok(true)))
                    || !table.dns.entries.iter().any(|entry| entry.generation == plan.peer.generation && entry.host == plan.peer.host
                        && entry.candidate.ip == plan.peer.ip && matches!(crate::resolvers::source_is_current(&entry.candidate, &plan.witness), Ok(true))) {
                    results.push(DirectBatchEffect::NoAction("original binding no longer current")); continue;
                }
                if tunnel.dns_answered { results.push(DirectBatchEffect::Protected); continue; }
                if tunnel.closed.is_some() { results.push(DirectBatchEffect::AlreadyClosed); continue; }
                sockets.push((tunnel.client.take(), tunnel.upstream.take()));
        }
    }
    let shutdown = |socket: Option<TcpStream>| match socket {
        None => ShutdownSide::Missing,
        Some(socket) => match socket.shutdown(std::net::Shutdown::Both) {
            Ok(()) => ShutdownSide::Succeeded,
            Err(error) => ShutdownSide::Failed(error),
        },
    };
    for (client, upstream) in sockets {
        results.push(DirectBatchEffect::Shutdown { client: shutdown(client), upstream: shutdown(upstream) });
    }
    results
}

fn tunnel_own(id: u64) -> Option<Arc<crate::upstream::OwnContext>> {
    TUNNELS.lock().ok()?.iter().find(|t| t.id == id)?.own.as_ref()?.upgrade()
}

pub(crate) fn own_attributed_drops(id: u64, count: usize, clear: bool) -> Option<usize> {
    let own = tunnel_own(id)?;
    own.if_current(|| if clear { own.clear_drops(); 0 } else { own.add_drops(count) })
}

pub(crate) fn credit_attributed(kind: Kind, id: u64) -> bool {
    if kind != Kind::Own { credit(kind); return true; }
    tunnel_own(id).and_then(|own| own.if_current(|| credit(kind))).is_some()
}

pub(crate) fn bench_dropping_attributed(kind: Kind, id: u64) -> Option<Option<Duration>> {
    if kind != Kind::Own { return Some(bench_dropping(kind)); }
    let own = tunnel_own(id)?;
    let streaming = live_answer_own(&own).is_some();
    own.if_current(|| silence(kind, streaming))
}

pub(crate) fn blame_attributed(kind: Kind, id: u64) -> Option<Blamed> {
    if kind != Kind::Own { return Some(blame(kind)); }
    let own = tunnel_own(id)?;
    let streaming = live_answer_own(&own);
    let outcome = own.if_current(|| blame_table(kind, streaming))?;
    if !matches!(outcome, Blamed::Proven(_) | Blamed::Streaming { .. }) {
        cut_own_tunnels(&own);
    }
    Some(outcome)
}

fn cut_own_tunnels(own: &Arc<crate::upstream::OwnContext>) {
    let sockets = {
        let Ok(mut list) = TUNNELS.lock() else { return };
        list.iter_mut().filter(|t| t.kind == Kind::Own && t.closed.is_none()
            && t.answered_at.is_none() && t.own.as_ref().and_then(|bound| bound.upgrade()).is_some_and(|bound| Arc::ptr_eq(&bound, own)))
            .flat_map(|t| [t.client.take(), t.upstream.take()].into_iter().flatten())
            .collect::<Vec<_>>()
    };
    for sock in sockets {
        if let Err(error) = sock.shutdown(std::net::Shutdown::Both) {
            crate::dns_forwarder::log_proxy(&format!("own tunnel shutdown failed: {error}"));
        }
    }
}

/// Marks the tunnel a model answer came through. Closed tunnels are marked too:
/// the log line is read seconds after the answer started, and a short answer is
/// over by then - what matters is that the credit lands on the right record.
pub fn credit_tunnel(id: u64) {
    if let Ok(mut list) = TUNNELS.lock() {
        if let Some(t) = list.iter_mut().find(|t| t.id == id) {
            t.answered_at = Some(Instant::now());
        }
    }
}

/// What one gate connection looks like, for the line the log writes when a
/// refusal is pinned on it.
///
/// A refusal and a model answer on the **same** connection is a different
/// diagnosis from one on a sibling, and the relay log could not tell them apart
/// until now: three field reports (2026-09-21) showed a route refusing once a
/// minute while answering on the same minute, and nothing in the log said
/// whether the refused request rode the connection that was answering. If it
/// did, no route change can help - the backend is turning single requests down
/// - and the report should say so instead of sending the user round the routes
/// again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// This very connection carried a model answer, and how long ago.
    pub answered_ago: Option<Duration>,
    /// Still open.
    pub open: bool,
    /// Since it was opened.
    pub age: Duration,
    /// Bytes handed to the client on it, and how long since the last one.
    pub to_client: u64,
    pub idle: Duration,
}

/// `Shape` of one tunnel, by the id `attribute_tunnel` gave.
pub fn tunnel_shape(id: u64) -> Option<Shape> {
    let list = TUNNELS.lock().ok()?;
    let t = list.iter().find(|t| t.id == id)?;
    Some(Shape {
        answered_ago: t.answered_at.map(|a| a.elapsed()),
        open: t.closed.is_none(),
        age: t.opened.elapsed(),
        to_client: t.activity.bytes().0,
        idle: t.activity.idle().unwrap_or_else(|| t.opened.elapsed()),
    })
}

/// Closes one gate tunnel by id, and only if it never carried a model answer.
///
/// The narrow half of `cut_tunnels`. When a route is protected because *another*
/// of its connections is streaming an answer (D32), the connection the refusal
/// actually came in on is still a connection the client will go on being
/// refused over, and D26's reason for cutting applies to it and to nothing else
/// on the route. Returns whether anything was closed, so the log can say which
/// of the two cases this was.
#[allow(dead_code)]
pub fn cut_tunnel(id: u64) -> bool {
    let Ok(mut list) = TUNNELS.lock() else {
        return false;
    };
    let Some(t) = list
        .iter_mut()
        .find(|t| t.id == id && t.closed.is_none() && t.answered_at.is_none())
    else {
        return false;
    };
    let mut cut = false;
    for sock in [t.client.take(), t.upstream.take()].into_iter().flatten() {
        sock.shutdown(std::net::Shutdown::Both).ok();
        cut = true;
    }
    cut
}

/// Closes one gate tunnel that encountered a region-400 refusal, even if it
/// carried an answer in the past.
///
/// Keeping a poisoned connection open in the client's HTTP/2 keep-alive pool
/// guarantees that subsequent requests sent into it will also fail. Closing it
/// forces the client to open a fresh connection on the best available route.
pub fn cut_refused_tunnel(id: u64) -> bool {
    let sockets = {
        let Ok(mut list) = TUNNELS.lock() else { return false; };
        let Some(t) = list.iter_mut().find(|t| t.id == id && t.closed.is_none()) else { return false; };
        [t.client.take(), t.upstream.take()]
    };
    let mut cut = false;
    for sock in sockets.into_iter().flatten() {
        if let Err(error) = sock.shutdown(std::net::Shutdown::Both) {
            crate::dns_forwarder::log_proxy(&format!("refused tunnel shutdown failed: {error}"));
        }
        cut = true;
    }
    cut
}

/// An **open** tunnel of `kind` that carried a model answer, i.e. a conversation
/// still in flight, with how long since its last byte.
///
/// No clock and no idle limit on purpose (D32, owner): a model that is thinking
/// sends nothing for as long as it thinks, and the whole point of this check is
/// that the answer survives it. What ends the protection is the connection
/// closing - the client's own signal that the exchange is over.
fn live_answer(kind: Kind) -> Option<(Duration, u64)> {
    let list = TUNNELS.lock().ok()?;
    list.iter()
        .filter(|t| t.kind == kind && t.closed.is_none() && t.answered_at.is_some())
        .map(|t| {
            let idle = t.activity.idle().unwrap_or_else(|| t.opened.elapsed());
            (idle, t.activity.bytes().0)
        })
        // The liveliest of them: with several open, one gone quiet says nothing
        // while another is still handing the client bytes.
        .min_by_key(|(idle, _)| *idle)
}

fn live_answer_own(own: &Arc<crate::upstream::OwnContext>) -> Option<(Duration, u64)> {
    let list = TUNNELS.lock().ok()?;
    list.iter().filter(|t| t.kind == Kind::Own && t.closed.is_none() && t.answered_at.is_some()
        && t.own.as_ref().and_then(|bound| bound.upgrade()).is_some_and(|bound| Arc::ptr_eq(&bound, own)))
        .map(|t| (t.activity.idle().unwrap_or_else(|| t.opened.elapsed()), t.activity.bytes().0))
        .min_by_key(|(idle, _)| *idle)
}

// ---------------------------------------------------------------------------
// What the window is told.
// ---------------------------------------------------------------------------

/// One row of the table as the window's report shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Row {
    pub label: String,
    pub usable: bool,
    pub latency_ms: Option<u32>,
    pub proven: bool,
    /// Seconds since the last model answer it carried.
    pub ok_ago: Option<u64>,
    /// Seconds since the last refusal it carried, whether or not that refusal
    /// was held against it.
    pub refused_ago: Option<u64>,
    /// Model answers and refusal episodes pinned on it since the relay started
    /// or the network last changed.
    pub answers: u32,
    pub refusals: u32,
    /// Seconds of bench left.
    pub bench_left: Option<u64>,
    pub open: u32,
}

/// Every route, in the order the table would offer them, for the record the
/// window reads (`gate`).
pub fn rows(usable: impl Fn(Kind) -> bool) -> Vec<Row> {
    let s = snapshot();
    let open = open_counts();
    let order = order_with(&s, cfg!(target_os = "windows"), &usable);
    let mut kinds: Vec<Kind> = order.clone();
    kinds.extend(ALL.iter().copied().filter(|k| !order.contains(k)));
    // A build without the relay has no such route at all - not an unusable one.
    kinds.retain(|&k| k != Kind::Relay || cfg!(relay));
    kinds
        .into_iter()
        .map(|k| {
            let i = k.index();
            Row {
                label: k.label().to_string(),
                usable: order.contains(&k),
                latency_ms: fresh(&s.samples, k)
                    .map(|d| d.as_millis().min(u32::MAX as u128) as u32),
                proven: proven(&s.ok_at, &s.bad_at, k),
                ok_ago: s.ok_at[i].map(|a| a.elapsed().as_secs()),
                refused_ago: s.refused_at[i].map(|a| a.elapsed().as_secs()),
                answers: s.ok_count[i],
                refusals: s.bad_count[i],
                bench_left: s.penalised[i]
                    .max(s.stumbled[i])
                    .max(s.silent[i])
                    .and_then(|u| u.checked_duration_since(Instant::now()))
                    .map(|d| d.as_secs()),
                open: open[i],
            }
        })
        .collect()
}

/// Log sink, silent under test: these lines go to the live relay log (G18).
fn note(message: &str) {
    #[cfg(not(test))]
    crate::dns_forwarder::log_proxy(message);
    #[cfg(test)]
    let _ = message;
}

#[cfg(test)]
mod tests {

    #[test]
    #[ignore = "isolated process: owns the current Own slot, route table and loopback sockets"]
    fn guard_drop_silence_is_bound_to_the_actual_own_endpoint() {
        use super::*;
        struct Cleanup;
        impl Drop for Cleanup { fn drop(&mut self) { crate::upstream::fixture_select_own(None); } }
        let _cleanup = Cleanup;
        let a = crate::upstream::parse("192.0.2.1:8080").unwrap();
        let b = crate::upstream::parse("192.0.2.2:8080").unwrap();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (client, _) = listener.accept().unwrap();
        let open = |own: Arc<crate::upstream::OwnContext>| {
            let guard = begin_gate_connection(&client, "example.invalid");
            bind_serving_own(own);
            note_used(Kind::Own);
            serving_activity().unwrap().to_upstream(5);
            guard
        };
        let old_a = crate::upstream::fixture_select_own(Some(a.clone())).unwrap();
        let guard = open(old_a.clone());
        let _current_b = crate::upstream::fixture_select_own(Some(b.clone())).unwrap();
        drop(guard);
        assert!(TABLE.lock().unwrap().silent[Kind::Own.index()].is_none());
        let guard = open(old_a);
        let _ = crate::upstream::fixture_select_own(Some(a));
        drop(guard);
        assert!(TABLE.lock().unwrap().silent[Kind::Own.index()].is_none());
        let current_b = crate::upstream::fixture_select_own(Some(b)).unwrap();
        let guard = open(current_b);
        drop(guard);
        assert!(TABLE.lock().unwrap().silent[Kind::Own.index()].is_some());
    }

    #[test]
    #[ignore = "isolated process: owns the current Own slot and tunnel table"]
    fn old_own_tunnel_cannot_publish_or_bench_new_endpoint() {
        use super::*;
        struct Cleanup(u64);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Ok(mut list) = TUNNELS.lock() { list.retain(|t| t.id != self.0); }
                crate::upstream::fixture_select_own(None);
            }
        }
        let a = crate::upstream::fixture_select_own(Some(crate::upstream::parse("192.0.2.1:8080").unwrap())).unwrap();
        let id = NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed);
        let _cleanup = Cleanup(id);
        TUNNELS.lock().unwrap().push(Tunnel { id, kind: Kind::Own, own: Some(Arc::downgrade(&a)),
            host: "example.invalid".into(), opened: Instant::now(), closed: None, answered_at: None,
            activity: Arc::new(Activity::default()), client: None, upstream: None, dns_binding: None, dns_peer: None, dns_answered: false });
        let b = crate::upstream::fixture_select_own(Some(crate::upstream::parse("192.0.2.2:8080").unwrap())).unwrap();
        assert!(b.usable());
        assert!(!credit_attributed(Kind::Own, id));
        assert!(own_attributed_drops(id, 1, false).is_none());
        assert!(blame_attributed(Kind::Own, id).is_none());
        assert!(bench_dropping_attributed(Kind::Own, id).is_none());
        assert!(!is_proven(Kind::Own));
        assert_eq!(b.add_drops(1), 1);
        assert!(b.usable());
    }

    #[test]
    fn a_pinned_route_name_maps_to_its_kind_and_junk_to_none() {
        assert_eq!(forced(" Relay "), Some(Kind::Relay));
        assert_eq!(forced("vpn"), Some(Kind::Vpn));
        assert_eq!(forced(""), None);
        assert_eq!(forced("proxy"), None);
    }
    use super::*;

    #[test]
    fn endpoint_feedback_requires_unambiguous_host_peer_and_generation() {
        const HOST: &str = "fixture-peer.invalid";
        struct Cleanup(Vec<u64>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                TUNNELS.lock().unwrap_or_else(|error| error.into_inner()).retain(|t| !self.0.contains(&t.id));
            }
        }
        let ids = vec![NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed), NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed)];
        let _cleanup = Cleanup(ids.clone());
        let now = Instant::now();
        let identity = |ip| DnsPeerIdentity { host: HOST.into(), ip, generation: 7 };
        let first = identity(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let second = identity(std::net::Ipv4Addr::new(192, 0, 2, 2));
        {
            let mut list = TUNNELS.lock().unwrap();
            for (id, peer) in [(ids[0], first.clone()), (ids[1], second)] {
                list.push(Tunnel { id, kind: Kind::Direct, own: None, host: HOST.into(), opened: now,
                    closed: None, answered_at: None, activity: Arc::new(Activity::default()),
                    client: None, upstream: None, dns_binding: None, dns_peer: Some(peer), dns_answered: false });
            }
        }
        assert!(unique_dns_peer(now, None).is_none());
        assert!(unique_dns_peer(now, Some(HOST)).is_none());
        TUNNELS.lock().unwrap().iter_mut().find(|t| t.id == ids[1]).unwrap().dns_peer = Some(first.clone());
        assert_eq!(unique_dns_peer(now, Some(HOST)), Some(first));
        TUNNELS.lock().unwrap().iter_mut().find(|t| t.id == ids[1]).unwrap().dns_peer.as_mut().unwrap().generation = 8;
        assert!(unique_dns_peer(now, Some(HOST)).is_none());
    }

    #[test]
    #[ignore = "isolated process: owns tunnel records and loopback sockets"]
    fn ambiguous_direct_log_feedback_never_credits_or_cuts_siblings() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        const HOST: &str = "cloudcode-pa.googleapis.com";
        struct Cleanup(Vec<u64>);
        impl Drop for Cleanup {
            fn drop(&mut self) { TUNNELS.lock().unwrap_or_else(|error| error.into_inner()).retain(|t| !self.0.contains(&t.id)); }
        }
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut peer_a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server_a, _) = listener.accept().unwrap();
        let mut peer_b = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server_b, _) = listener.accept().unwrap();
        server_a.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        server_b.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let ids = vec![NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed), NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed)];
        let _cleanup = Cleanup(ids.clone());
        let at = Instant::now();
        {
            let mut list = TUNNELS.lock().unwrap();
            for (index, server) in [(0, &server_a), (1, &server_b)] {
                let ip = std::net::Ipv4Addr::new(192, 0, 2, (index + 1) as u8);
                list.push(Tunnel { id: ids[index], kind: Kind::Direct, own: None, host: HOST.into(), opened: at,
                    closed: None, answered_at: None, activity: Arc::new(Activity::default()), client: Some(server.try_clone().unwrap()),
                    upstream: None, dns_binding: None, dns_peer: Some(DnsPeerIdentity { host: HOST.into(), ip, generation: 1 }), dns_answered: false });
            }
        }
        let proven_before = is_proven(Kind::Direct);
        let answer = receive_log_feedback(at, Some(HOST), Some(HOST), Some(true));
        let refusal = receive_log_feedback(at, Some(HOST), Some(HOST), Some(false));
        peer_a.write_all(b"a").unwrap();
        peer_b.write_all(b"b").unwrap();
        let mut a = [0]; let mut b = [0];
        server_a.read_exact(&mut a).unwrap();
        server_b.read_exact(&mut b).unwrap();
        assert_eq!((a, b), ([b'a'], [b'b']));
        assert!(matches!(answer, LogFeedback::Direct { applied: false, .. }));
        assert!(matches!(refusal, LogFeedback::Direct { applied: false, .. }));
        assert_eq!(is_proven(Kind::Direct), proven_before);
        assert!(TUNNELS.lock().unwrap().iter().filter(|t| ids.contains(&t.id)).all(|t| t.answered_at.is_none()));
        TUNNELS.lock().unwrap().iter_mut().find(|t| t.id == ids[1]).unwrap().kind = Kind::Own;
        assert!(matches!(receive_log_feedback(at, Some(HOST), Some(HOST), Some(false)), LogFeedback::Ambiguous));
        peer_a.write_all(b"c").unwrap();
        peer_b.write_all(b"d").unwrap();
        server_a.read_exact(&mut a).unwrap();
        server_b.read_exact(&mut b).unwrap();
        assert_eq!((a, b), ([b'c'], [b'd']));
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn current_direct_refusal_closes_the_original_pooled_socket_pair() {
        direct_log_socket_fixture(false, 0);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn scanned_refusal_through_forwarder_closes_the_original_socket_pair() {
        direct_log_socket_fixture(true, 0);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn scanned_drop_answer_drop_keeps_socket_and_resets_streak() {
        direct_log_socket_fixture(true, 1);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn scanned_two_drops_recover_the_original_socket_pair() {
        direct_log_socket_fixture(true, 2);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn scanned_later_answer_protects_socket_before_batch_shutdown() {
        direct_log_socket_fixture(true, 3);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn separate_log_polls_recover_after_two_drops() {
        direct_log_socket_fixture(true, 4);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn scanned_drops_for_distinct_endpoints_are_not_combined() {
        direct_log_socket_fixture(true, 5);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn ambiguous_answer_protects_original_streams_but_not_later_stream() {
        direct_log_socket_fixture(true, 6);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn mixed_direct_and_own_log_refusal_preserves_both_streams() {
        direct_log_socket_fixture(true, 7);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn new_plausible_tunnel_during_preparation_prevents_feedback() {
        direct_log_socket_fixture(true, 8);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn later_timestamp_answer_before_refusal_span_protects_original_pair() {
        direct_log_socket_fixture(true, 9);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn valid_answer_before_unplaced_record_protects_next_batch() {
        direct_log_socket_fixture(true, 10);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn fenced_record_precedes_later_proven_record_even_when_time_is_reversed() {
        direct_log_socket_fixture(true, 11);
    }

    #[test]
    #[ignore = "isolated process: controlled settings and owned loopback sockets"]
    fn complete_refusal_at_retained_log_boundary_closes_original_pair() {
        direct_log_socket_fixture(true, 12);
    }

    fn direct_log_socket_fixture(through_forwarder: bool, scenario: u8) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        const HOST: &str = "cloudcode-pa.googleapis.com";
        struct Cleanup(Vec<u64>);
        impl Drop for Cleanup {
            fn drop(&mut self) { TUNNELS.lock().unwrap_or_else(|error| error.into_inner()).retain(|t| !self.0.contains(&t.id)); }
        }
        let _lease = lease_test_dns_state().unwrap();
        let witness = crate::resolvers::current_witness(crate::resolvers::DnsMissingPolicy::LegacyDefaults).unwrap();
        let candidate = crate::resolvers::test_source_candidate(std::net::Ipv4Addr::new(8, 8, 8, 8), &witness);
        let generation = begin_dns_maintenance(HOST, &witness, true).unwrap();
        assert!(publish_dns_candidate(HOST, generation, candidate.clone(), Ok(crate::proxy::CandidateProbe::Reachable(Duration::from_millis(1)))).unwrap());
        let route_state_before = (is_proven(Kind::Direct), is_penalised(Kind::Direct), is_proven(Kind::Own), is_penalised(Kind::Own));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client_peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut client_control, _) = listener.accept().unwrap();
        let mut upstream_peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut upstream_control, _) = listener.accept().unwrap();
        client_control.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        upstream_control.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        let id = NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed);
        let mut cleanup = Cleanup(vec![id]);
        let peer = DnsPeerIdentity { host: HOST.into(), ip: candidate.ip, generation };
        let binding = DnsBinding { admission: DnsAdmission { ip: candidate.ip, generation }, candidate: candidate.clone(),
            witness: witness.clone(), allow_missing_defaults: true };
        let opened = Instant::now();
        TUNNELS.lock().unwrap().push(Tunnel { id, kind: Kind::Direct, own: None, host: HOST.into(), opened,
            closed: None, answered_at: None, activity: Arc::new(Activity::default()),
            client: Some(client_control.try_clone().unwrap()), upstream: Some(upstream_control.try_clone().unwrap()),
            dns_binding: Some(binding.clone()), dns_peer: Some(peer.clone()), dns_answered: false });
        let mut additional = Vec::new();
        if scenario == 6 || scenario == 7 || scenario == 12 {
            let remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (control, _) = listener.accept().unwrap();
            control.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
            let other_id = NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed);
            cleanup.0.push(other_id);
            TUNNELS.lock().unwrap().push(Tunnel { id: other_id, kind: if scenario == 7 { Kind::Own } else { Kind::Direct }, own: None, host: HOST.into(), opened,
                closed: None, answered_at: None, activity: Arc::new(Activity::default()), client: Some(control.try_clone().unwrap()), upstream: None,
                dns_binding: (scenario != 7).then(|| binding.clone()), dns_peer: (scenario != 7).then(|| peer.clone()), dns_answered: scenario == 12 });
            additional.push((remote, control));
        }
        if scenario == 5 || scenario == 11 {
            const OTHER: &str = "aicode.googleapis.com";
            assert!(publish_dns_candidate(OTHER, generation, candidate.clone(), Ok(crate::proxy::CandidateProbe::Reachable(Duration::from_millis(1)))).unwrap());
            let other_id = NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed);
            cleanup.0.push(other_id);
            let other_peer = DnsPeerIdentity { host: OTHER.into(), ip: candidate.ip, generation };
            let other_binding = DnsBinding { admission: DnsAdmission { ip: candidate.ip, generation }, candidate: candidate.clone(),
                witness: witness.clone(), allow_missing_defaults: true };
            TUNNELS.lock().unwrap().push(Tunnel { id: other_id, kind: Kind::Direct, own: None, host: OTHER.into(), opened,
                closed: None, answered_at: None, activity: Arc::new(Activity::default()), client: None, upstream: None,
                dns_binding: Some(other_binding), dns_peer: Some(other_peer), dns_answered: false });
        }
        // The synthetic admission key is test-only; both retained handles and
        // their independently observed peer traffic are real local sockets.
        struct RemoveLog(std::path::PathBuf);
        impl Drop for RemoveLog { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
        let path = std::env::temp_dir().join(format!("antigravity-direct-{}-{id}.log", std::process::id()));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let _log = RemoveLog(path.clone());
        if scenario == 12 {
            let refusal = b"I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 user location is not supported\n";
            let budget = usize::try_from(crate::ls_log::test_max_read()).expect("log budget fits a test buffer");
            let padding = budget.checked_sub(refusal.len() + 1).expect("log budget must hold the complete record");
            file.write_all(b"old history\n").unwrap();
            file.write_all(refusal).unwrap();
            file.write_all(&vec![b'x'; padding]).unwrap();
            file.write_all(b"\n").unwrap();
        } else if scenario == 9 {
            file.write_all(concat!(
                "I0901 15:09:25.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent ResponseID: a\n",
                "I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 user location is not supported\n"
            ).as_bytes()).unwrap();
        } else if scenario == 10 {
            file.write_all(concat!(
                "I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent ResponseID: a\n",
                "URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n"
            ).as_bytes()).unwrap();
        } else if scenario == 1 {
            file.write_all(concat!(
                "I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n",
                "I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent ResponseID: a\n",
                "I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n"
            ).as_bytes()).unwrap();
        } else if scenario == 6 {
            file.write_all(b"I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent ResponseID: a\n").unwrap();
        } else if scenario == 4 || scenario == 11 {
            file.write_all(b"I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n").unwrap();
        } else if scenario == 5 {
            file.write_all(concat!(
                "I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n",
                "I0901 15:09:24.000000 URL: https://aicode.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n"
            ).as_bytes()).unwrap();
        } else if scenario == 2 || scenario == 3 {
            file.write_all(concat!(
                "I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n",
                "I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n"
            ).as_bytes()).unwrap();
            if scenario == 3 {
                file.write_all(b"I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent ResponseID: a\n").unwrap();
            }
        } else {
            file.write_all(b"I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 user location is not supported\n").unwrap();
        }
        drop(file);
        if scenario == 12 {
            use std::io::Seek;
            let mut check = std::fs::File::open(&path).unwrap();
            let budget = crate::ls_log::test_max_read();
            let length = check.metadata().unwrap().len();
            assert!(length > budget, "fixture must force the owned read budget to skip history");
            check.seek(std::io::SeekFrom::Start(length - budget - 1)).unwrap();
            let mut prefix = [0u8; 2];
            check.read_exact(&mut prefix).unwrap();
            assert_eq!(prefix, [b'\n', b'I'], "retained tail begins at the checked complete-record boundary");
        }
        let clock = crate::utils::LocalClock { month: 9, day: 1, second_of_day: 15 * 3600 + 9 * 60 + if scenario == 9 || scenario == 11 { 25 } else { 24 } };
        let tally = if scenario == 12 {
            let mut cursor = crate::ls_log::TestLogCursor::default();
            crate::ls_log::test_poll_log(&mut cursor, &path, Some(clock), Instant::now())
        } else if scenario == 11 {
            let mut cursor = crate::ls_log::TestLogCursor::default();
            let first = crate::ls_log::test_poll_log(&mut cursor, &path, Some(clock), Instant::now());
            assert_eq!(first.direct_signals.len(), 1);
            crate::dns_forwarder::test_answer_log(&[(path.clone(), first)]);
            struct RestoreFile { held: std::path::PathBuf, original: std::path::PathBuf, moved: bool }
            impl Drop for RestoreFile { fn drop(&mut self) { if self.moved { let _ = std::fs::rename(&self.held, &self.original); } } }
            let held = path.with_extension("held");
            assert!(!held.exists(), "owned temporary hold destination must be vacant");
            let mut restore = RestoreFile { held: held.clone(), original: path.clone(), moved: false };
            std::fs::rename(&path, &held).unwrap();
            restore.moved = true;
            let gap = crate::ls_log::test_poll_log(&mut cursor, &path, Some(clock), Instant::now());
            assert!(gap.direct_signals.is_empty());
            std::fs::rename(&held, &path).unwrap();
            restore.moved = false;
            let mut append = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            append.write_all(concat!(
                "I0901 15:09:25.000000 URL: https://aicode.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n",
                "I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n"
            ).as_bytes()).unwrap();
            drop(append);
            let next_clock = crate::utils::LocalClock { month: 9, day: 1, second_of_day: 15 * 3600 + 9 * 60 + 25 };
            let next = crate::ls_log::test_poll_log(&mut cursor, &path, Some(next_clock), Instant::now());
            assert_eq!(next.direct_signals.len(), 2);
            assert_eq!(next.direct_signals[0].continuity, crate::ls_log::SignalContinuity::Fence);
            assert_eq!(next.direct_signals[1].continuity, crate::ls_log::SignalContinuity::Proven);
            next
        } else if scenario == 10 {
            let mut cursor = crate::ls_log::TestLogCursor::default();
            let first = crate::ls_log::test_poll_log(&mut cursor, &path, Some(clock), Instant::now());
            assert_eq!(first.direct_signals.len(), 2);
            assert!(first.direct_signals[0].at.is_some() && first.direct_signals[1].at.is_none());
            crate::dns_forwarder::test_answer_log(&[(path.clone(), first)]);
            let mut append = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            append.write_all(b"I0901 15:09:25.000000 URL: https://cloudcode-pa.googleapis.com/v1 user location is not supported\n").unwrap();
            drop(append);
            let next_clock = crate::utils::LocalClock { month: 9, day: 1, second_of_day: 15 * 3600 + 9 * 60 + 25 };
            let refusal = crate::ls_log::test_poll_log(&mut cursor, &path, Some(next_clock), Instant::now());
            assert_eq!(refusal.direct_signals.len(), 1);
            refusal
        } else if scenario == 6 {
            let mut cursor = crate::ls_log::TestLogCursor::default();
            let answer = crate::ls_log::test_poll_log(&mut cursor, &path, Some(clock), Instant::now());
            assert_eq!(answer.direct_signals.len(), 1);
            crate::dns_forwarder::test_answer_log(&[(path.clone(), answer)]);
            let remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (control, _) = listener.accept().unwrap();
            control.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
            let new_id = NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed);
            cleanup.0.push(new_id);
            TUNNELS.lock().unwrap().push(Tunnel { id: new_id, kind: Kind::Direct, own: None, host: HOST.into(), opened: Instant::now(),
                closed: None, answered_at: None, activity: Arc::new(Activity::default()), client: Some(control.try_clone().unwrap()), upstream: None,
                dns_binding: Some(binding.clone()), dns_peer: Some(peer.clone()), dns_answered: false });
            additional.push((remote, control));
            let mut append = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            append.write_all(b"I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 user location is not supported\n").unwrap();
            drop(append);
            let refusal = crate::ls_log::test_poll_log(&mut cursor, &path, Some(clock), Instant::now());
            assert_eq!(refusal.direct_signals.len(), 1);
            refusal
        } else if scenario == 4 {
            let mut cursor = crate::ls_log::TestLogCursor::default();
            let first = crate::ls_log::test_poll_log(&mut cursor, &path, Some(clock), Instant::now());
            assert_eq!(first.direct_signals.len(), 1);
            crate::dns_forwarder::test_answer_log(&[(path.clone(), first)]);
            client_peer.write_all(b"p").unwrap();
            let mut prior = [0]; client_control.read_exact(&mut prior).unwrap();
            assert_eq!(prior, [b'p']);
            let mut append = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            append.write_all(b"I0901 15:09:24.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n").unwrap();
            drop(append);
            let second = crate::ls_log::test_poll_log(&mut cursor, &path, Some(clock), Instant::now());
            assert_eq!(second.direct_signals.len(), 1);
            assert_eq!(second.direct_signals[0].continuity, crate::ls_log::SignalContinuity::Proven);
            second
        } else {
            let (end, tally) = crate::ls_log::test_scan_log(&path, Some(0), Some(clock), Instant::now());
            assert!(end > 0 && tally.direct_signals.len() == match scenario { 1 | 3 => 3, 2 | 5 | 9 => 2, _ => 1 });
            tally
        };
        let signal_count = tally.direct_signals.len();
        let result = if scenario == 8 {
            struct ClearPause;
            impl Drop for ClearPause { fn drop(&mut self) { DIRECT_PREPARED_TEST_PAUSE.lock().unwrap_or_else(|e| e.into_inner()).take(); } }
            let _pause_cleanup = ClearPause;
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            *DIRECT_PREPARED_TEST_PAUSE.lock().unwrap() = Some((entered_tx, release_rx));
            let worker_path = path.clone();
            std::thread::scope(|scope| {
                let worker = scope.spawn(move || crate::dns_forwarder::test_answer_log(&[(worker_path, tally)]));
                assert!(entered_rx.recv_timeout(Duration::from_secs(5)).expect("actual prepared boundary not reached"),
                    "race requires an accepted original binding before insertion");
                let remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let (control, _) = listener.accept().unwrap();
                control.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
                let other_id = NEXT_TUNNEL.fetch_add(1, Ordering::Relaxed);
                cleanup.0.push(other_id);
                let other_candidate = crate::resolvers::test_source_candidate(std::net::Ipv4Addr::new(1, 1, 1, 1), &witness);
                let other_binding = DnsBinding { admission: DnsAdmission { ip: other_candidate.ip, generation }, candidate: other_candidate.clone(),
                    witness: witness.clone(), allow_missing_defaults: true };
                let other_peer = DnsPeerIdentity { host: HOST.into(), ip: other_candidate.ip, generation };
                TUNNELS.lock().unwrap().push(Tunnel { id: other_id, kind: Kind::Direct, own: None, host: HOST.into(), opened: Instant::now(),
                    closed: None, answered_at: None, activity: Arc::new(Activity::default()), client: Some(control.try_clone().unwrap()), upstream: None,
                    dns_binding: Some(other_binding), dns_peer: Some(other_peer), dns_answered: false });
                additional.push((remote, control));
                release_tx.send(()).expect("prepared worker released early");
                worker.join().expect("prepared worker failed");
            });
            None
        } else if through_forwarder {
            crate::dns_forwarder::test_answer_log(&[(path.clone(), tally)]);
            None
        } else {
            let first = receive_direct_batch(&tally.direct_signals);
            let replay = receive_direct_batch(&tally.direct_signals);
            assert!(replay.iter().all(|effect| matches!(effect, DirectBatchEffect::NoAction(_))), "replay must not reapply or shut down again");
            Some(first)
        };
        let mut byte = [0];
        let client_live = client_peer.write_all(b"c").is_ok() && client_control.read_exact(&mut byte).is_ok();
        let upstream_live = upstream_peer.write_all(b"u").is_ok() && upstream_control.read_exact(&mut byte).is_ok();
        if let Some(result) = result {
            assert!(result.iter().any(|effect| matches!(effect, DirectBatchEffect::StateChanged)), "fixture must exercise a currently admitted refusal");
            assert!(result.iter().any(|effect| matches!(effect, DirectBatchEffect::Shutdown { client: ShutdownSide::Succeeded, upstream: ShutdownSide::Succeeded })), "both owned shutdown results must be received");
        }
        if matches!(scenario, 1 | 3 | 5 | 6 | 7 | 8 | 9 | 10 | 11) {
            assert!(client_live && upstream_live, "the answered connection must remain usable on both sides");
            let table = TABLE.lock().unwrap();
            let entry = table.dns.entries.iter().find(|entry| entry.host == HOST && entry.generation == generation).unwrap();
            assert_eq!(entry.drop_streak, if matches!(scenario, 3 | 6 | 7 | 8 | 9 | 10) { 0 } else { 1 });
            if scenario == 9 || scenario == 10 { assert!(entry.model_seen.is_some(), "valid answer must remain observable"); }
            if scenario == 7 || scenario == 8 {
                assert!(entry.refusal_at.is_none() && !entry.refusal_blocking && entry.model_seen.is_none() && !entry.model_proven,
                    "ambiguous feedback must not change endpoint evidence");
            }
            if scenario == 5 || scenario == 11 {
                let other = table.dns.entries.iter().find(|entry| entry.host == "aicode.googleapis.com" && entry.generation == generation).unwrap();
                assert_eq!(other.drop_streak, 1);
            }
            drop(table);
            if scenario == 6 {
                let (original_remote, original_control) = &mut additional[0];
                original_remote.write_all(b"o").unwrap();
                original_control.read_exact(&mut byte).unwrap();
                let (new_remote, new_control) = &mut additional[1];
                let new_live = new_remote.write_all(b"n").is_ok() && new_control.read_exact(&mut byte).is_ok();
                assert!(!new_live, "later unmatched stream must remain recoverable");
            }
            if scenario == 7 || scenario == 8 {
                assert_eq!((is_proven(Kind::Direct), is_penalised(Kind::Direct), is_proven(Kind::Own), is_penalised(Kind::Own)), route_state_before,
                    "ambiguous feedback must not credit or penalise either route");
                let (other_remote, other_control) = &mut additional[0];
                other_remote.write_all(b"s").unwrap();
                other_control.read_exact(&mut byte).unwrap();
                assert_eq!(byte, [b's']);
                assert!(TUNNELS.lock().unwrap().iter().filter(|t| cleanup.0.contains(&t.id))
                    .all(|t| t.answered_at.is_none() && !t.dns_answered), "ambiguous feedback must not credit either route");
            }
        } else {
            assert!(!client_live, "the original client-side pooled socket remained usable");
            assert!(!upstream_live, "the original upstream-side pooled socket remained usable");
            if scenario == 12 {
                assert_eq!(signal_count, 1, "the complete refusal is the only retained event");
                let (protected_remote, protected_control) = &mut additional[0];
                protected_remote.write_all(b"s").unwrap();
                protected_control.read_exact(&mut byte).unwrap();
                assert_eq!(byte, [b's'], "the independently protected sibling remains usable");
            }
        }
    }

    #[test]
    #[ignore = "isolated process: owns candidate route state"]
    fn candidate_refusal_is_not_cleared_by_anonymous_reachability() {
        struct Restore { dns: Option<DnsState>, context: u64 }
        impl Drop for Restore {
            fn drop(&mut self) {
                let mut table = TABLE.lock().unwrap_or_else(|error| error.into_inner());
                table.dns = self.dns.take().unwrap();
                table.context = self.context;
            }
        }
        let saved = {
            let mut table = TABLE.lock().unwrap();
            let context = table.context;
            table.context = 0;
            Restore { dns: Some(std::mem::replace(&mut table.dns, DnsState::new())), context }
        };
        let _restore = saved;
        let host = "cloudcode-pa.googleapis.com";
        let witness = crate::resolvers::test_source_witness();
        let candidate = crate::resolvers::test_source_candidate(std::net::Ipv4Addr::new(8, 8, 8, 8), &witness);
        let other = crate::resolvers::test_source_candidate(std::net::Ipv4Addr::new(1, 1, 1, 1), &witness);
        let generation = begin_dns_maintenance(host, &witness, true).unwrap();
        assert!(publish_dns_candidate(host, generation, candidate.clone(), Ok(crate::proxy::CandidateProbe::Reachable(Duration::from_millis(10)))).unwrap());
        assert!(publish_dns_candidate(host, generation, other.clone(), Ok(crate::proxy::CandidateProbe::Reachable(Duration::from_millis(12)))).unwrap());
        assert!(matches!(dns_selection(host, &witness).unwrap(), DnsSelection::Ready(_)));
        {
            let peer = DnsPeerIdentity { host: host.into(), ip: candidate.ip, generation };
            let mut table = TABLE.lock().unwrap();
            assert_eq!(apply_dns_silence(&mut table.dns, &peer, true), None);
            assert_eq!(apply_dns_silence(&mut table.dns, &peer, false), Some(SILENT_STEPS[0]));
            assert_eq!(apply_dns_silence(&mut table.dns, &peer, false), None);
            assert!(table.dns.entries.iter().find(|entry| entry.candidate.ip == other.ip).unwrap().silent_until.is_none());
            table.dns.entries.iter_mut().find(|entry| entry.candidate.ip == candidate.ip).unwrap().silent_until = Some(Instant::now());
            assert_eq!(apply_dns_silence(&mut table.dns, &peer, false), Some(SILENT_STEPS[1]));
            let entry = table.dns.entries.iter_mut().find(|entry| entry.candidate.ip == candidate.ip).unwrap();
            entry.silent_until = None;
            entry.silent_streak = 0;
            apply_dns_feedback(&mut table.dns, &peer, true);
            let entry = table.dns.entries.iter().find(|entry| entry.host == host).unwrap();
            assert!(entry.model_seen.is_some() && !entry.model_proven);
        }
        assert!(publish_dns_candidate(host, generation, candidate.clone(), Ok(crate::proxy::CandidateProbe::Refused)).unwrap());
        assert!(publish_dns_candidate(host, generation, candidate.clone(), Ok(crate::proxy::CandidateProbe::Reachable(Duration::from_millis(5)))).unwrap());
        finish_dns_maintenance(host, generation);
        assert!(matches!(dns_selection(host, &witness).unwrap(), DnsSelection::Ready(items)
            if !items.iter().any(|(admission, _)| admission.ip == candidate.ip)
                && items.iter().any(|(admission, _)| admission.ip == other.ip)));
        {
            let mut table = TABLE.lock().unwrap();
            let entry = table.dns.entries.iter_mut().find(|entry| entry.host == host).unwrap();
            entry.refusal_at = Instant::now().checked_sub(FIRST_PENALTY + Duration::from_secs(1));
        }
        assert!(matches!(dns_selection(host, &witness).unwrap(), DnsSelection::Ready(_)));
        TABLE.lock().unwrap().context = 1;
        assert!(matches!(dns_selection(host, &witness).unwrap(), DnsSelection::Pending));
        assert!(!publish_dns_candidate(host, generation, candidate, Ok(crate::proxy::CandidateProbe::Reachable(Duration::ZERO))).unwrap());
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn sample(n: u64) -> Option<Sample> {
        Some(Sample {
            latency: ms(n),
            at: Instant::now(),
        })
    }

    /// The tests that change the table's evidence share one process-wide table,
    /// and `set_context` wipes it for everyone - so they take turns.
    static STATEFUL: Mutex<()> = Mutex::new(());

    fn turn() -> std::sync::MutexGuard<'static, ()> {
        STATEFUL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn a_refused_unproven_pin_yields_to_a_proven_route() {
        let mut s = blank();
        let (g, v) = (Kind::Group.index(), Kind::Vpn.index());
        s.refused_at[g] = Some(Instant::now());
        s.ok_at[v] = Some(Instant::now());
        assert_eq!(order_with(&s, true, |k| k != Kind::Own)[0], Kind::Vpn);
        // Nothing else has answered: the pin keeps its place.
        s.ok_at[v] = None;
        assert_eq!(order_with(&s, true, |k| k != Kind::Own)[0], Kind::Group);
    }

    fn blank() -> Snapshot {
        Snapshot {
            samples: [None; N],
            penalised: [None; N],
            ok_at: [None; N],
            bad_at: [None; N],
            refused_at: [None; N],
            ok_count: [0; N],
            bad_count: [0; N],
            stumbled: [None; N],
            silent: [None; N],
            leader: None,
            pinned: PINNED,
        }
    }

    #[test]
    fn the_later_added_of_group_and_own_leads() {
        let mut s = blank();
        let all = |_: Kind| true;
        assert_eq!(order_with(&s, true, all)[..2], [Kind::Group, Kind::Own]);
        s.pinned = [Kind::Own, Kind::Group];
        let order = order_with(&s, true, all);
        assert_eq!(order[..2], [Kind::Own, Kind::Group]);
        // Everything else keeps its own order behind the pair.
        assert_eq!(order[2..], [Kind::Relay, Kind::Exits, Kind::Direct, Kind::Vpn]);
    }

    #[test]
    fn unmeasured_routes_take_the_default_order() {
        let order = order_with(&blank(), true, |_| true);
        assert_eq!(
            order,
            vec![Kind::Group, Kind::Own, Kind::Relay, Kind::Exits, Kind::Direct, Kind::Vpn]
        );
    }

    #[test]
    fn without_a_dns_layer_direct_goes_last_whatever_it_measured() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(50);
        s.samples[Kind::Exits.index()] = sample(400);
        let order = order_with(&s, false, |k| k != Kind::Own && k != Kind::Vpn && k != Kind::Group);
        assert_eq!(order, vec![Kind::Exits, Kind::Relay, Kind::Direct]);
    }

    #[test]
    fn measured_routes_go_fastest_first_and_unmeasured_after_them() {
        let mut s = blank();
        s.samples[Kind::Relay.index()] = sample(1300);
        s.samples[Kind::Exits.index()] = sample(450);
        let order = order_with(&s, true, |k| k != Kind::Own && k != Kind::Vpn && k != Kind::Group);
        assert_eq!(order, vec![Kind::Exits, Kind::Relay, Kind::Direct]);
    }

    #[test]
    fn the_leader_keeps_its_place_unless_beaten_by_the_margin() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(300);
        s.samples[Kind::Exits.index()] = sample(270);
        s.leader = Some(Kind::Direct);
        let usable = |k: Kind| k != Kind::Own && k != Kind::Vpn && k != Kind::Group;
        assert_eq!(order_with(&s, true, usable)[0], Kind::Direct);
        s.samples[Kind::Exits.index()] = sample(180);
        assert_eq!(order_with(&s, true, usable)[0], Kind::Exits);
    }

    #[test]
    fn a_penalised_route_is_last_even_when_fastest() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(100);
        s.samples[Kind::Relay.index()] = sample(1300);
        s.penalised[Kind::Direct.index()] = Some(Instant::now() + ms(60_000));
        s.leader = Some(Kind::Direct);
        let usable = |k: Kind| k != Kind::Own && k != Kind::Vpn && k != Kind::Group;
        assert_eq!(
            order_with(&s, true, usable),
            vec![Kind::Relay, Kind::Exits, Kind::Direct]
        );
        s.penalised[Kind::Direct.index()] = Some(Instant::now() - ms(1));
        s.leader = None;
        assert_eq!(order_with(&s, true, usable)[0], Kind::Direct);
    }

    /// The whole point of proof: the fastest route is not the one that works.
    /// A slower route that carried a model answer goes ahead of a faster one
    /// that never has.
    #[test]
    fn a_route_that_carried_an_answer_beats_a_faster_one_that_did_not() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(120);
        s.samples[Kind::Exits.index()] = sample(900);
        s.ok_at[Kind::Exits.index()] = Some(Instant::now());
        s.leader = Some(Kind::Direct);
        let usable = |k: Kind| k != Kind::Own && k != Kind::Vpn && k != Kind::Group;
        assert_eq!(order_with(&s, true, usable)[0], Kind::Exits);
        // A refusal after the answer takes the proof away again.
        s.bad_at[Kind::Exits.index()] = Some(Instant::now() + ms(1));
        assert_eq!(order_with(&s, true, usable)[0], Kind::Direct);
    }

    /// A route that could not even open for a live connection steps aside for a
    /// minute, so the next connections do not each wait out its budget.
    #[test]
    fn a_route_that_failed_to_open_steps_aside() {
        let mut s = blank();
        s.samples[Kind::Direct.index()] = sample(100);
        s.samples[Kind::Exits.index()] = sample(500);
        s.stumbled[Kind::Direct.index()] = Some(Instant::now() + ms(60_000));
        let order = order_with(&s, true, |k| k != Kind::Own && k != Kind::Vpn && k != Kind::Group);
        assert_eq!(order, vec![Kind::Exits, Kind::Relay, Kind::Direct]);
        s.stumbled[Kind::Direct.index()] = Some(Instant::now() - ms(1));
        assert_eq!(
            order_with(&s, true, |k| k != Kind::Own && k != Kind::Vpn && k != Kind::Group)[0],
            Kind::Direct
        );
    }

    /// The field case behind `SILENT_STEPS`: a built-in exit that answered once
    /// and then went dead kept the table on itself, and the DNS route was never
    /// tried until the user switched the exits off.
    #[test]
    fn a_proven_route_that_went_silent_gives_way_to_the_dns_route() {
        let mut s = blank();
        s.samples[Kind::Exits.index()] = sample(400);
        s.samples[Kind::Direct.index()] = sample(600);
        s.ok_at[Kind::Exits.index()] = Some(Instant::now() - ms(600_000));
        s.leader = Some(Kind::Exits);
        let usable = |k: Kind| k == Kind::Exits || k == Kind::Direct;
        assert_eq!(order_with(&s, true, usable)[0], Kind::Exits);
        s.silent[Kind::Exits.index()] = Some(Instant::now() + ms(120_000));
        assert_eq!(
            order_with(&s, true, usable),
            vec![Kind::Direct, Kind::Exits]
        );
    }

    #[test]
    fn only_a_tunnel_the_client_spoke_into_and_heard_nothing_from_is_silent() {
        assert!(is_silent(0, 517), "ClientHello out, nothing back");
        assert!(is_silent(7, 517), "a TLS alert is not a server flight");
        assert!(!is_silent(0, 0), "never used by the client");
        assert!(!is_silent(4_800, 517), "a handshake came back");
    }

    #[test]
    fn silence_benches_once_per_episode_and_only_an_answer_lifts_it() {
        let _turn = turn();
        set_context(0x6666);
        assert_eq!(silence(Kind::Relay, false), Some(SILENT_STEPS[0]));
        // The client's other connections dying on the same route: one event.
        assert_eq!(silence(Kind::Relay, false), None);
        // A probe that passes does not let it out early.
        record(Kind::Relay, ms(300));
        assert!(snapshot().silent[Kind::Relay.index()].is_some());
        assert_eq!(
            order(|k| k == Kind::Relay || k == Kind::Exits)[0],
            Kind::Exits
        );
        // A model answer does, and protects it from the next silent tunnel.
        credit(Kind::Relay);
        assert!(snapshot().silent[Kind::Relay.index()].is_none());
        assert_eq!(silence(Kind::Relay, false), None);
        // An answer streaming through another of its tunnels protects it too.
        set_context(0x6667);
        assert_eq!(silence(Kind::Relay, true), None);
        // Escalates to the second step and stays there.
        if let Ok(mut t) = TABLE.lock() {
            t.silent_streak[Kind::Relay.index()] = 5;
        }
        assert_eq!(silence(Kind::Relay, false), Some(SILENT_STEPS[1]));
    }

    #[test]
    fn with_every_route_benched_the_one_benched_longest_ago_goes_first() {
        let mut s = blank();
        let now = Instant::now();
        s.penalised[Kind::Direct.index()] = Some(now + ms(600_000));
        s.penalised[Kind::Exits.index()] = Some(now + ms(60_000));
        s.penalised[Kind::Relay.index()] = Some(now + ms(3_600_000));
        let order = order_with(&s, true, |k| k != Kind::Own && k != Kind::Vpn && k != Kind::Group);
        assert_eq!(order, vec![Kind::Exits, Kind::Direct, Kind::Relay]);
    }

    #[test]
    fn the_users_own_proxy_is_first_whenever_it_is_usable() {
        let mut s = blank();
        s.samples[Kind::Own.index()] = sample(900);
        s.samples[Kind::Direct.index()] = sample(100);
        s.ok_at[Kind::Direct.index()] = Some(Instant::now());
        s.leader = Some(Kind::Direct);
        assert_eq!(order_with(&s, true, |k| k != Kind::Group)[0], Kind::Own);
        assert_eq!(
            order_with(&s, true, |k| k != Kind::Own && k != Kind::Group)[0],
            Kind::Direct
        );
    }

    #[test]
    fn the_group_proxy_goes_first_then_the_users_own_whatever_is_measured() {
        let mut s = blank();
        s.samples[Kind::Group.index()] = sample(900);
        s.samples[Kind::Own.index()] = sample(800);
        s.samples[Kind::Direct.index()] = sample(100);
        s.ok_at[Kind::Direct.index()] = Some(Instant::now());
        s.leader = Some(Kind::Direct);
        let order = order_with(&s, true, |_| true);
        assert_eq!(order[..3], [Kind::Group, Kind::Own, Kind::Direct]);
        // Group not usable (switch off, no key, probe failed): Own leads.
        assert_eq!(order_with(&s, true, |k| k != Kind::Group)[0], Kind::Own);
    }

    #[test]
    fn a_benched_group_proxy_gives_way_and_comes_back() {
        let now = Instant::now();
        let usable = |k: Kind| k != Kind::Vpn && k != Kind::Own;
        for bench in [
            |s: &mut Snapshot, until| s.penalised[Kind::Group.index()] = Some(until),
            |s: &mut Snapshot, until| s.stumbled[Kind::Group.index()] = Some(until),
            |s: &mut Snapshot, until| s.silent[Kind::Group.index()] = Some(until),
        ] {
            let mut s = blank();
            bench(&mut s, now + ms(600_000));
            assert_eq!(
                order_with(&s, true, usable),
                vec![Kind::Relay, Kind::Exits, Kind::Direct, Kind::Group]
            );
            // With the user's own proxy present it takes the lead meanwhile.
            assert_eq!(order_with(&s, true, |k| k != Kind::Vpn)[0], Kind::Own);

            let mut s = blank();
            bench(&mut s, now - ms(1));
            assert_eq!(order_with(&s, true, usable)[0], Kind::Group);
        }
    }

    #[test]
    fn a_benched_own_proxy_gives_way_and_comes_back() {
        let now = Instant::now();
        let usable = |k: Kind| k != Kind::Vpn && k != Kind::Group;
        for bench in [
            |s: &mut Snapshot, until| s.penalised[Kind::Own.index()] = Some(until),
            |s: &mut Snapshot, until| s.stumbled[Kind::Own.index()] = Some(until),
            |s: &mut Snapshot, until| s.silent[Kind::Own.index()] = Some(until),
        ] {
            let mut s = blank();
            bench(&mut s, now + ms(600_000));
            let order = order_with(&s, true, usable);
            assert_eq!(
                order,
                vec![Kind::Relay, Kind::Exits, Kind::Direct, Kind::Own]
            );

            // The bench over, first again.
            let mut s = blank();
            bench(&mut s, now - ms(1));
            assert_eq!(order_with(&s, true, usable)[0], Kind::Own);
        }
    }

    #[test]
    fn a_benched_own_proxy_sorts_among_the_benched_by_when_it_ends() {
        let now = Instant::now();
        let mut s = blank();
        s.penalised[Kind::Own.index()] = Some(now + ms(600_000));
        s.penalised[Kind::Relay.index()] = Some(now + ms(60_000));
        let order = order_with(&s, true, |k| k != Kind::Vpn && k != Kind::Group);
        assert_eq!(
            order,
            vec![Kind::Exits, Kind::Direct, Kind::Relay, Kind::Own]
        );
        // An unusable Own is not offered at all, benched or not.
        let order = order_with(&s, true, |k| k != Kind::Vpn && k != Kind::Own && k != Kind::Group);
        assert!(!order.contains(&Kind::Own));
    }

    #[test]
    fn unusable_routes_are_not_offered_at_all() {
        let order = order_with(&blank(), true, |k| k == Kind::Relay);
        assert_eq!(order, vec![Kind::Relay]);
        assert!(order_with(&blank(), true, |_| false).is_empty());
    }

    /// `usable` may ask the table questions of its own. This deadlocked once:
    /// `order` held the lock while `is_penalised` tried to take it, and the
    /// first live connection through the proxy never got its 200 (G30).
    #[test]
    fn ordering_may_consult_the_table_from_inside_usable() {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = done.clone();
        std::thread::spawn(move || {
            let _ = order(|k| !is_penalised(k) && latency(k).is_none() || is_proven(k) || true);
            refresh_leader(|k| !is_penalised(k));
            let _ = rows(|k| !is_penalised(k));
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "order() deadlocked on its own table"
            );
            std::thread::sleep(ms(10));
        }
    }

    /// The static half, in one test because it shares process-wide state:
    /// timings blend and expire, a refusal benches for a growing time, an
    /// answer lifts the bench and proves the route, and a new network forgets
    /// both.
    #[test]
    fn the_table_learns_and_forgets() {
        let _turn = turn();
        record_failure(Kind::Relay);
        assert_eq!(latency(Kind::Relay), None);
        record(Kind::Relay, ms(1000));
        record(Kind::Relay, ms(500));
        assert_eq!(latency(Kind::Relay), Some(ms(750)), "blended");
        record_failure(Kind::Relay);
        assert_eq!(latency(Kind::Relay), None);

        set_context(0x1111);
        assert_eq!(blame(Kind::Relay), Blamed::Benched(PENALTY_STEPS[0]));
        assert!(is_penalised(Kind::Relay));
        // Already benched: the client's retries on the old connection are the
        // same refusal, not a new one.
        assert_eq!(blame(Kind::Relay), Blamed::AlreadyBenched);
        credit(Kind::Relay);
        assert!(!is_penalised(Kind::Relay), "an answer lifts the bench");
        assert!(is_proven(Kind::Relay));
        // Refused straight after an answer: the route is left alone entirely -
        // its tier included, which is what Â«Ð½Ðµ Ñ‚Ñ€Ð¾Ð½ÑƒÑ‚Â» has to mean if the next
        // connection is not to be handed to somebody else (G76).
        assert!(matches!(blame(Kind::Relay), Blamed::Proven(_)));
        assert!(!is_penalised(Kind::Relay), "a proven route is not benched");
        assert!(is_proven(Kind::Relay), "and it keeps its place");
        let relay_row = rows(|k| k == Kind::Relay)
            .into_iter()
            .find(|r| r.label == Kind::Relay.label());
        if cfg!(relay) {
            assert!(
                relay_row.is_some_and(|r| r.refused_ago.is_some()),
                "but the refusal is still on the record the window shows"
            );
        } else {
            assert!(relay_row.is_none(), "a build without the relay shows no relay row");
        }
        // Once the proof has aged out, the same refusal benches - at the first
        // step, because the answer reset the streak.
        age_out_answer(Kind::Relay);
        assert_eq!(blame(Kind::Relay), Blamed::Benched(PENALTY_STEPS[0]));
        // A new network forgets it all.
        assert!(set_context(0x2222));
        assert!(!is_penalised(Kind::Relay));
        assert!(!set_context(0x2222), "the same network is not a change");
    }

    #[test]
    fn repeated_refusals_bench_for_longer_each_time() {
        let _turn = turn();
        // Uses Vpn so it cannot collide with the test above on the statics.
        set_context(0x3333);
        for step in [0usize, 1, 2, 3, 3] {
            assert_eq!(
                blame(Kind::Vpn),
                Blamed::Benched(PENALTY_STEPS[step]),
                "step {step}"
            );
            if let Ok(mut t) = TABLE.lock() {
                t.penalised[Kind::Vpn.index()] = Some(Instant::now() - ms(1));
            }
        }
        credit(Kind::Vpn);
    }

    /// Pushes `kind`'s last answer out of `PROOF_PROTECTS_FOR` without waiting
    /// ninety seconds for it.
    fn age_out_answer(kind: Kind) {
        if let Ok(mut t) = TABLE.lock() {
            t.ok_at[kind.index()] = Instant::now().checked_sub(PROOF_PROTECTS_FOR + ms(1));
        }
    }

    /// The field case this exists for: a route answers, is refused two seconds
    /// later, and must keep both its place in the table and its open tunnels.
    #[test]
    fn an_answer_just_now_keeps_a_refusal_from_benching_the_route() {
        let _turn = turn();
        set_context(0x4444);
        credit(Kind::Own);
        // Ten refusals in a row while the answers keep coming change nothing:
        // no bench, and no streak to escalate once the protection does lapse.
        for _ in 0..10 {
            assert!(matches!(blame(Kind::Own), Blamed::Proven(_)));
            credit(Kind::Own);
        }
        assert!(!is_penalised(Kind::Own));
        age_out_answer(Kind::Own);
        assert_eq!(
            blame(Kind::Own),
            Blamed::Benched(PENALTY_STEPS[0]),
            "the first step, because every answer reset the streak"
        );
    }

    /// A failed probe is not the same as an unmeasured route: it has to keep the
    /// route out of the running, or the next connection goes straight back to
    /// something that just refused to answer one.
    #[test]
    fn a_failed_probe_keeps_the_route_back_where_a_lost_measurement_did_not() {
        let _turn = turn();
        set_context(0x5555);
        record(Kind::Direct, ms(300));
        record_failure(Kind::Direct);
        assert_eq!(latency(Kind::Direct), None);
        // With the DNS layer, as on Windows: without it (Linux) Direct is last
        // whatever happened to it, and the test could not tell the two apart.
        let after_loss = order_with(&snapshot(), true, |_| true);
        probe_failed(Kind::Direct);
        let after_probe = order_with(&snapshot(), true, |_| true);
        assert!(
            after_probe.last() == Some(&Kind::Direct) && after_loss.last() != Some(&Kind::Direct),
            "{after_loss:?} then {after_probe:?}"
        );
        assert!(PROBE_STUMBLE_FOR > STUMBLE_FOR, "a probe runs every 2 min");
    }

    /// Attribution by open tunnel, and the tunnel of a refused route closed from
    /// outside the thread that pumps it.
    #[test]
    fn a_refusal_is_pinned_on_the_tunnel_that_was_open_and_that_tunnel_is_closed() {
        let _turn = turn();
        use std::io::Read;
        use std::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bound");
        let addr = listener.local_addr().expect("addr");
        let mut far = TcpStream::connect(addr).expect("connected");
        let (near, _) = listener.accept().expect("accepted");

        // Exits carries a tunnel, on a thread of its own, the way `serve` does.
        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let _gate = begin_gate_connection(&near, "daily-cloudcode-pa.googleapis.com");
            note_used(Kind::Exits);
            tx.send(()).ok();
            // Stands in for the splice: returns when the socket is shut down.
            let mut buf = [0u8; 1];
            let mut near = near;
            let _ = near.read(&mut buf);
        });
        rx.recv().expect("opened");
        assert_eq!(attribute(Instant::now(), None), Some(Kind::Exits));
        assert_eq!(
            attribute(Instant::now(), Some("daily-cloudcode-pa.googleapis.com")),
            Some(Kind::Exits)
        );
        // An event about the other host is not this tunnel's.
        assert_eq!(
            attribute(Instant::now(), Some("cloudcode-pa.googleapis.com")),
            None
        );
        assert!(open_counts()[Kind::Exits.index()] >= 1);

        set_context(0x4444);
        blame(Kind::Exits);
        // The far end sees its connection go.
        far.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut buf = [0u8; 1];
        let got = far.read(&mut buf);
        assert!(matches!(got, Ok(0) | Err(_)), "the tunnel was not closed");
        far.shutdown(std::net::Shutdown::Both).ok();
        drop(far);
        server.join().expect("server thread");
        credit(Kind::Exits);
    }

    /// D32: while a tunnel that carried an answer is open, a refusal pinned on
    /// that route does nothing at all - no bench, and above all no cut. This is
    /// the field symptom as a test: a long answer streaming while something
    /// else on the machine keeps walking into the gate.
    #[test]
    fn an_answer_still_streaming_keeps_its_route_and_its_socket() {
        let _turn = turn();
        use std::io::{ErrorKind, Read};
        use std::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bound");
        let addr = listener.local_addr().expect("addr");
        let mut far = TcpStream::connect(addr).expect("connected");
        let (near, _) = listener.accept().expect("accepted");

        let (tx, rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let _gate = begin_gate_connection(&near, "daily-cloudcode-pa.googleapis.com");
            note_used(Kind::Exits);
            tx.send(serving_activity()).ok();
            // Stands in for the splice: returns when the socket ends.
            let mut buf = [0u8; 1];
            let mut near = near;
            let _ = near.read(&mut buf);
            done_tx.send(()).ok();
        });
        let activity = rx
            .recv()
            .expect("opened")
            .expect("a gate tunnel has a stamp");

        set_context(0x5555);
        let (kind, id) = attribute_tunnel(Instant::now(), None).expect("attributed");
        assert_eq!(kind, Kind::Exits);
        credit_tunnel(id);
        // The answer hands the client bytes, the way a stream does.
        activity.to_client(8 * 1024);

        match blame(Kind::Exits) {
            Blamed::Streaming { to_client, .. } => assert_eq!(to_client, 8 * 1024),
            other => panic!("a streaming answer was not recognised: {other:?}"),
        }
        assert!(
            !is_penalised(Kind::Exits),
            "a route carrying an answer must not be benched"
        );
        // And the socket is still there: this is the half that cut answers in two.
        far.set_read_timeout(Some(Duration::from_millis(250))).ok();
        let mut buf = [0u8; 1];
        let got = far.read(&mut buf);
        assert!(
            matches!(&got, Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)),
            "the live answer's socket was cut: {got:?}"
        );

        // The client ends the exchange. Nothing is in flight any more, so the
        // next refusal benches the route exactly as it did before (D26).
        far.shutdown(std::net::Shutdown::Both).ok();
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the tunnel ended");
        server.join().expect("server thread");
        assert!(
            live_answer(Kind::Exits).is_none(),
            "a closed tunnel protects nothing"
        );
        assert!(matches!(blame(Kind::Exits), Blamed::Benched(_)));
        assert!(is_penalised(Kind::Exits));
    }

    /// G76, the flap three field reports (2026-09-21) show: a refusal the table
    /// declines to hold against a route must not cost it its place either.
    ///
    /// It did. `blame` stamped the refusal whatever it decided, `proven` reads
    /// that stamp, and the route dropped out of the proven tier the moment it
    /// was refused - so the leader swapped to whatever measured fastest, swapped
    /// back on the next answer, and did it again fifteen seconds later. Half the
    /// client's new connections went to a road nothing had proved, while the
    /// road that was answering sat second.
    #[test]
    fn a_protected_refusal_does_not_cost_the_route_its_place() {
        let _turn = turn();
        set_context(0x7601);
        let usable = |k: Kind| matches!(k, Kind::Exits | Kind::Relay);
        credit(Kind::Exits);
        record(Kind::Relay, ms(50));
        assert_eq!(order(usable).first(), Some(&Kind::Exits));

        // A refusal inside `PROOF_PROTECTS_FOR`: not evidence (D31).
        assert!(matches!(blame(Kind::Exits), Blamed::Proven(_)));
        assert!(
            is_proven(Kind::Exits),
            "a refusal that was not held against the route must not unprove it"
        );
        assert_eq!(
            order(usable).first(),
            Some(&Kind::Exits),
            "the route that answered must still be the one offered first"
        );

        // The user is still told it happened - that half was never the bug.
        let row = rows(usable)
            .into_iter()
            .find(|r| r.label == Kind::Exits.label())
            .expect("a row for the route");
        assert!(row.refused_ago.is_some(), "the report must still show it");
        assert_eq!((row.answers, row.refusals), (1, 1));
    }

    /// And the other way round, so the fix cannot quietly turn every refusal
    /// into a free one: once nothing protects the route, the refusal is
    /// evidence, the bench lands and the proof goes.
    #[test]
    fn an_unprotected_refusal_still_takes_the_proof_away() {
        let _turn = turn();
        set_context(0x7602);
        let usable = |k: Kind| matches!(k, Kind::Exits | Kind::Relay);
        credit(Kind::Exits);
        age_out_answer(Kind::Exits);
        assert!(matches!(blame(Kind::Exits), Blamed::Benched(_)));
        assert!(!is_proven(Kind::Exits));
        record(Kind::Relay, ms(50));
        assert_eq!(order(usable).first(), Some(&Kind::Relay));
    }

    /// The narrow cut: when one connection on a route is streaming an answer
    /// and the refusal arrived on a *different* one, that other one is closed
    /// and the streaming one is not. Anything else leaves the client retrying
    /// over a pooled connection that is being refused (D26) or cuts the answer
    /// in half (D32) - the two halves of the same field report.
    #[test]
    fn only_the_refused_connection_is_cut_beside_a_live_answer() {
        let _turn = turn();
        use std::io::{ErrorKind, Read};
        use std::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bound");
        let addr = listener.local_addr().expect("addr");

        // Two gate tunnels on one route, the way a client's pool makes them.
        let mut open_one = |host: &'static str| {
            let far = TcpStream::connect(addr).expect("connected");
            let (near, _) = listener.accept().expect("accepted");
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let _gate = begin_gate_connection(&near, host);
                note_used(Kind::Exits);
                tx.send(attribute_tunnel(Instant::now(), Some(host))).ok();
                let mut buf = [0u8; 1];
                let mut near = near;
                let _ = near.read(&mut buf);
            });
            let (_, id) = rx.recv().expect("opened").expect("attributed");
            (far, id, thread)
        };
        let (mut answering, answering_id, t1) = open_one("daily-cloudcode-pa.googleapis.com");
        let (mut refused, refused_id, t2) = open_one("cloudcode-pa.googleapis.com");
        assert_ne!(answering_id, refused_id);

        set_context(0x7603);
        credit(Kind::Exits);
        credit_tunnel(answering_id);

        // The refusal came in on the sibling.
        assert!(matches!(blame(Kind::Exits), Blamed::Streaming { .. }));
        assert!(cut_tunnel(refused_id), "the refused connection must be cut");
        assert!(
            !cut_tunnel(answering_id),
            "the connection carrying the answer must never be cut"
        );

        refused.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut buf = [0u8; 1];
        assert!(
            matches!(refused.read(&mut buf), Ok(0) | Err(_)),
            "the refused connection is still open"
        );
        answering
            .set_read_timeout(Some(Duration::from_millis(250)))
            .ok();
        let got = answering.read(&mut buf);
        assert!(
            matches!(&got, Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)),
            "the answer's own connection was cut: {got:?}"
        );

        // `tunnel_shape` is what the log line reads to tell the two apart.
        assert!(tunnel_shape(answering_id)
            .expect("a shape")
            .answered_ago
            .is_some());
        assert!(tunnel_shape(refused_id)
            .expect("a shape")
            .answered_ago
            .is_none());

        refused.shutdown(std::net::Shutdown::Both).ok();
        answering.shutdown(std::net::Shutdown::Both).ok();
        drop(refused);
        drop(answering);
        t1.join().expect("first tunnel");
        t2.join().expect("second tunnel");
    }

    /// Both directions count as activity: a long chat is a 100 KB upload before
    /// it is an answer (field: `116225 B out` against `4253 B to client`).
    #[test]
    fn a_tunnels_activity_counts_both_directions() {
        let a = Activity::default();
        assert!(a.idle().is_none(), "nothing has moved yet");
        assert_eq!(a.bytes(), (0, 0));
        a.to_upstream(116_225);
        assert_eq!(a.bytes(), (0, 116_225));
        assert!(a.idle().is_some_and(|d| d < Duration::from_secs(1)));
        a.to_client(4_253);
        assert_eq!(a.bytes(), (4_253, 116_225));
    }
}
