use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::background;
use crate::dns_forwarder;
use crate::egress::{self, Egress};
use crate::hosts_pin;
use crate::resolvers;
use crate::utils::{CommandOutcome, CommandObservation};

#[cfg(windows)]
pub(crate) mod machine_state;
#[cfg(windows)]
mod nrpt;
#[cfg(windows)]
mod prefix;

fn receive_command(outcome: &CommandOutcome, observation: CommandObservation) -> Result<(), String> {
    match observation {
        CommandObservation::Complete if outcome.complete() && outcome.releasable() && outcome.exit().is_some_and(|status| status.success()) => Ok(()),
        CommandObservation::NotStarted => Err("DNS helper did not start; actual failure retained".into()),
        CommandObservation::Complete => Err("DNS helper failed or exit status is unknown; effect may be partial".into()),
        CommandObservation::Deadline => Err("DNS helper deadline expired; effect may be partial".into()),
        CommandObservation::Failed => Err("DNS helper failed; effect may be partial".into()),
        CommandObservation::Pending => Err("DNS helper remains pending; effect may be partial".into()),
    }
}

// NRPT-based selective DNS routing. Only the exact hostnames that Antigravity
// actually talks to AND that the upstream resolver actually proxies are routed
// to xbox-dns.ru; everything else stays on the system default resolver.
//
// The namespaces below were verified against the resolver: each one answers
// with a proxy address instead of the real Google address. Hosts that the
// resolver merely forwards (accounts.google.com, oauth2.googleapis.com,
// aiplatform.googleapis.com, *.googleusercontent.com, antigravity.google, ...)
// are deliberately NOT listed - a rule for them would send DNS traffic to a
// third party for zero benefit.
//
// The only names that actually need unblock DNS, measured end-to-end.
//
// `cloudcode-pa` is back (2026-08-30), and it is the one entry here whose
// history matters. It was dropped under N2 because a 22-resolver sweep found
// **nobody** substituting it (S9) - a rule for a name every provider answers
// genuinely is pure DNS leakage. That premise died the moment a provider that
// does substitute it was measured: dns-ai.ru answers with one of its own egress
// addresses, and that address accepts the SNI and replies as Google's own
// frontend. (The 2026-08-30 measurement named `186.246.45.126`; that egress has
// since been deleted and the address reassigned, so the number is not repeated
// here — see the note in `resolvers.rs` and G43.) N2 still holds
// as written - do not add a name *nobody* substitutes - but it was never a rule
// about this hostname, it was a rule about the measurement, and the measurement
// changed. `antigravity-unleash` stays out: still genuine everywhere.
//
// `daily-cloudcode-pa` stays because it is the same service by another name and
// two providers reach it. `generativelanguage` and `aistudio.google.com` are
// **deliberately absent** (owner, `_4`): both were only ever routed for the
// Gemini CLI flow, the IDE was measured running a full agentic task with the
// `generativelanguage` rule removed, and another of the owner's tools owns those
// two names now. Their rules remain outside the owned NRPT scope.
// Everything else Antigravity talks to - oauth2/www/play/accounts and
// jetski-webchannel - works on real Google and is deliberately not listed.
const AG_NRPT_CORE: &[&str] = &[
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
];

/// The names an NRPT rule always points at the relay - and therefore the ones
/// the relay keeps a fresh answer for. Warming anything else would put queries
/// on a third party for names Windows never sends here.
pub fn core_namespaces() -> &'static [&'static str] {
    AG_NRPT_CORE
}

/// Drops what the Windows DNS Client has cached for the gate names, so a client
/// that was already running asks again instead of living on answers that
/// predate our rules.
///
/// Nothing else on the machine tells it to. A field report of 2026-09-21 shows
/// `Antigravity обратился к Google мимо обхода` six times over three minutes after
/// a relay start, with the first `loopback` line arriving only once the client's
/// cached answer expired on its own: three minutes of refusals for a user whose
/// switches were all green (G75).
///
/// Called **after** the relay is bound and about to answer, never before. A
/// re-ask that arrives while nothing of ours is listening goes to the plain
/// resolvers and is cached unsubstituted for its full TTL - the very state this
/// is meant to end.
#[cfg(target_os = "windows")]
pub fn flush_client_cache() -> bool {
    // Loaded by hand and never linked. `DnsFlushResolverCacheEntry_W` is
    // exported by dnsapi.dll on every Windows that matters, but it is in no
    // documented import library, and a missing import stops the exe from
    // starting at all - on every machine, for a cache flush (D28).
    extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut std::ffi::c_void, flags: u32) -> usize;
        fn FreeLibrary(module: usize) -> i32;
        fn GetProcAddress(module: usize, name: *const u8) -> usize;
    }
    type FlushEntry = unsafe extern "system" fn(*const u16) -> i32;

    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
    let module = unsafe { LoadLibraryExW(c"dnsapi.dll".to_bytes().iter().map(|&b| u16::from(b)).chain(Some(0))
        .collect::<Vec<_>>().as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module == 0 { return false; }
    let entry = unsafe { GetProcAddress(module, b"DnsFlushResolverCacheEntry_W\0".as_ptr()) };
    if entry != 0 {
        // Per name, not the whole cache: everything else on this machine keeps
        // what it has, and these two are the only names whose stale answer is
        // ours to fix. The return value is not read - it is false for a name
        // that was not cached, which is success as far as this is concerned.
        let flush: FlushEntry = unsafe { std::mem::transmute(entry) };
        for name in core_namespaces() {
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { flush(wide.as_ptr()) };
        }
    }
    unsafe { FreeLibrary(module); }
    entry != 0
}

/// No NRPT and no DNS Client here: there are no rules of ours in front of a
/// resolver cache to invalidate.
#[cfg(not(target_os = "windows"))]
pub fn flush_client_cache() -> bool {
    false
}

// The unblock resolvers live in `resolvers` - the rules and the relay have to
// name the same services, and which of them actually substitutes a given name
// is decided per query rather than assumed here.

// Windows default precedence for the IPv4-mapped prefix.
// Precedence that puts IPv4 above native IPv6.

// is_nrpt_applied() shells out to PowerShell, which costs a few hundred ms.
// The menu redraws on every keystroke, so the answer is cached and invalidated
// explicitly whenever we change the rules ourselves.
static NRPT_CACHE: Mutex<Option<bool>> = Mutex::new(None);

#[allow(dead_code)]
pub fn invalidate_cache() {
    if let Ok(mut c) = NRPT_CACHE.lock() {
        *c = None;
    }
}

/// Queries whether NRPT rules are currently active after explicitly dropping the cache.
///
/// Expensive: shells out to PowerShell on Windows, so this is intended for on-demand
/// checks (e.g. user toggles, periodic health checks), not for every UI render frame.
#[allow(dead_code)]
pub fn is_nrpt_applied_fresh(owner: &mut CommandOutcome) -> Result<bool, String> {
    invalidate_cache();
    is_nrpt_applied(owner)
}

#[cfg(not(target_os = "windows"))]
pub fn remove_dns_nrpt(_owner: &mut CommandOutcome) -> Result<(), String> { Ok(()) }

#[cfg(target_os = "windows")]
pub fn remove_dns_nrpt(owner: &mut CommandOutcome) -> Result<(), String> {
    remove_dns_nrpt_checked(owner)
}

#[cfg(target_os = "windows")]
pub(crate) fn remove_dns_nrpt_checked(owner: &mut CommandOutcome) -> Result<(), String> {
    let writer = machine_state::Writer::acquire()?;
    hosts_pin::check_update(&writer)?;
    let result = nrpt::apply(owner, &writer, None);
    invalidate_cache();
    result?;
    hosts_pin::remove_entries(&writer).map_err(|e| format!("Owned NRPT rules retired; hosts cleanup failed: {e}"))?;
    prefix::restore(owner, &writer).map_err(|e| format!("Owned NRPT rules retired; IPv4 prefix cleanup failed: {e}"))?;
    flush_nrpt_cache()
}

#[cfg(windows)]
fn flush_nrpt_cache() -> Result<(), String> {
    if flush_client_cache() { Ok(()) }
    else { Err("Owned DNS effects received; exact-domain cache refresh is unavailable".into()) }
}

/// Fresh, failure-transparent evidence for privilege preflight.
#[cfg(target_os = "windows")]
pub(crate) struct NrptState {
    pub(crate) core_applied: bool,
    pub(crate) owned_rules_present: bool,
    pub(crate) recovery_pending: bool,
    pub(crate) auxiliary_cleanup: bool,
}

#[cfg(windows)]
impl NrptState {
    pub(crate) fn needs_retirement(&self) -> bool {
        self.owned_rules_present || self.recovery_pending || self.auxiliary_cleanup
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn checked_nrpt_state(owner: &mut CommandOutcome) -> Result<NrptState, String> {
    let mut state = nrpt::inspect(owner)?;
    state.auxiliary_cleanup = machine_state::has_auxiliary_cleanup()?;
    Ok(state)
}

#[cfg(windows)]
pub(crate) fn saved_dns_wish() -> Result<Option<bool>, String> {
    use crate::settings::{Read, TransportWish};
    match crate::settings::read() {
        Read::Parsed(settings) => match settings.checked_transport_effects()?.dns {
            TransportWish::Set(value) => Ok(Some(value)),
            TransportWish::Unspecified | TransportWish::Inactive => Ok(None),
        },
        Read::Missing => Ok(None),
        Read::Broken | Read::Unavailable => Err("Сохранённое намерение DNS недоступно.".into()),
    }
}

/// No NRPT layer on Linux yet, so no rules are ever applied. Returning false
/// keeps the "running without admin" advisory honest and stops `main()` probing
/// PowerShell that is not there.
#[cfg(not(target_os = "windows"))]
pub fn is_nrpt_applied(_owner: &mut CommandOutcome) -> Result<bool, String> {
    Ok(false)
}

/// True when every core namespace already has a rule. Extra rules (e.g. the
/// Gemini-only namespace) do not make this false - they are still ours and are
/// cleaned up together.
#[cfg(target_os = "windows")]
pub fn is_nrpt_applied(owner: &mut CommandOutcome) -> Result<bool, String> {
    if let Ok(cache) = NRPT_CACHE.lock() {
        if let Some(v) = *cache {
            return Ok(v);
        }
    }

    let applied = checked_nrpt_state(owner)?.core_applied;

    if let Ok(mut cache) = NRPT_CACHE.lock() {
        *cache = Some(applied);
    }
    Ok(applied)
}

/// Resolvers to write into the rule.
///
/// With the local relay running it goes first and the real resolvers stay on as
/// fallbacks, so a relay that is down degrades to the direct path instead of
/// leaving the names unresolvable. IPv6 is dropped in that case: Windows is free
/// to pick a v6 resolver, and that query would leave through the tunnel and skip
/// the relay entirely.
/// The NRPT nameserver list for one specific name.
///
/// The relay goes first; it does the smart per-query provider selection and is
/// almost always what answers. The fallbacks matter only when the relay is slow
/// or down - and they must contain **only providers that actually substitute
/// this name**. A provider that returns the genuine Google address here is not
/// a harmless fallback: Windows will occasionally prefer its fast genuine answer
/// over the relay's and cache it for minutes, and the region error comes back
/// (measured: xbox-dns leaked genuine for `daily-cloudcode-pa` ~1 query in 8).
///
/// When nobody substitutes the name (`antigravity-unleash` is genuine
/// everywhere; `cloudcode-pa` is no longer proxied by anyone), genuine is the
/// only answer there is, so every provider is listed as a plain resolver -
/// there is nothing to leak.
fn nameservers_for(name: &str, via_relay: bool, if_index: u32) -> Vec<String> {
    assemble_nameservers(via_relay, &resolvers::substituting_addrs(name, if_index))
}

/// The pure half of `nameservers_for`, split out so the ordering rules can be
/// tested without a live network probe. `substituters` is what actually proxies
/// the name; empty means nobody does.
fn assemble_nameservers(via_relay: bool, substituters: &[&str]) -> Vec<String> {
    let mut servers: Vec<String> = Vec::new();
    if via_relay {
        servers.push(dns_forwarder::LISTEN_IP.to_string());
    }

    if substituters.is_empty() {
        for s in resolvers::fallback_v4() {
            servers.push(s.to_string());
        }
    } else {
        for s in substituters {
            servers.push(s.to_string());
        }
    }

    // IPv6 only without the relay: with the relay up a v6 nameserver would let
    // Windows send the query out of the tunnel, skipping the relay entirely.
    if !via_relay {
        for s in resolvers::all_v6() {
            servers.push(s.to_string());
        }
    }
    servers
}

/// What the DNS step ended up doing. `pinned` is non-empty only when a tunnel
/// forced the fallback path.
pub struct DnsOutcome {
    pub vpn_active: bool,
    /// True when a tunnel was up **and the client was measured inside it**, so
    /// this run installed no rules and left the machine resolving exactly as the
    /// VPN configured it.
    pub stood_down_for_vpn: bool,
    /// Which way the client's own traffic was going. Only measured when a tunnel
    /// is up - with none there is nothing for it to decide - so `Unknown` here
    /// means either "no tunnel" or "tunnel, client not running"; `vpn_active`
    /// separates the two.
    pub client: egress::ClientEgress,
    pub via_relay: bool,
    pub pinned: Vec<String>,
    pub pin_error: Option<String>,
    /// True when the probe budget ran out and the remaining names were given the
    /// full provider list instead of a measured one.
    pub probe_gave_up: bool,
}



/// Resolves each routed namespace through the ISP link and pins whatever a
/// provider substitutes into `hosts`. Only genuinely substituted addresses are
/// written: a real Google address in `hosts` buys nothing and goes stale the
/// moment Google rotates its edge.
///
/// The "substituted?" question used to be answered by resolving twice - once
/// bound to the ISP link, once left to the routing table - and writing the
/// address only when the two differed, which says nothing without a tunnel up.
/// `resolvers` answers it directly by comparing every provider against a
/// reference resolver, so the same test now holds with or without a VPN.
#[cfg(windows)]
fn pin_substituted_hosts(writer: &machine_state::Writer, namespaces: &[&str], if_index: u32) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    for ns in namespaces {
        let Some((addrs, _, verdict)) = resolvers::resolve_a_best(ns, if_index) else {
            continue;
        };
        if verdict != resolvers::Verdict::Substituted {
            continue;
        }
        entries.push((ns.to_string(), addrs[0]));
    }

    let pinned = entries.iter().map(|(h, _)| h.clone()).collect();
    hosts_pin::write_entries(writer, &entries)?;
    Ok(pinned)
}

/// One character of progress on the caller's line.
fn tick() {
    use std::io::Write;
    // Was a progress dot on the console line. The window has no console, and the
    // step is reported as a whole when it finishes.
    std::io::stdout().flush().ok();
}

/// Longest the whole rule-building probe may take.
///
/// There has to be a bound. `substituting_addrs` asks every provider about every
/// name over UDP/53, and `ask_provider` walks a provider's addresses one at a
/// time at `QUERY_TIMEOUT` each; where those queries are simply dropped - a
/// corporate firewall, some VPN configurations - the arithmetic reaches minutes,
/// all of it behind one printed line with nothing moving. That is what users
/// reported as an eternal hang at "Патч для Google серверов...".
///
/// Past this, the remaining names get the full provider list - the same list a
/// name nobody substitutes gets anyway. The cost is that the fallback may then
/// hold a provider that returns genuine Google for that name (I22), which is a
/// rule that leaks when the relay is slow. A leak that degrades beats a hang
/// that does not end, and the relay is still listed first.
const PROBE_BUDGET: Duration = Duration::from_secs(25);

/// Limit for the small helpers here (`netsh`). Short, because they answer in
/// milliseconds when they answer at all.
const HELPER_LIMIT: Duration = Duration::from_secs(15);

/// The DNS/NRPT layer is the last part of the Linux port (kb/patch.md). Until it
/// lands, the binary/JS patch is what lifts the gate on a permitted exit, and
/// this reports "not done" so the caller can say so rather than half-running the
/// Windows path.
#[cfg(not(target_os = "windows"))]
pub fn setup_dns_nrpt(_owner: &mut CommandOutcome) -> Result<DnsOutcome, String> {
    Err("DNS-слой на Linux пока не портирован".to_string())
}

#[cfg(target_os = "windows")]
pub fn setup_dns_nrpt(owner: &mut CommandOutcome) -> Result<DnsOutcome, String> {
    let egress = egress::detect(owner)?;
    let via_relay = background::is_enabled(owner)?;

    // The rules go in whatever the tunnel does (D25). Until 2.14.0_1 a tunnel
    // carrying the client installed nothing and left the VPN to decide (D13) -
    // which also meant the client could never be brought back to us, and G29's
    // and G50's users got nothing at all. Now the relay decides at runtime what
    // the rules answer: with its loopback door up every gate connection comes to
    // its route table, where the user's VPN is one of the routes; with the door
    // down it answers as the tunnel's own resolver would for a client measured
    // inside it (`resolvers::resolve_through_tunnel`). It is the one process
    // that knows which of the two is true at the moment it matters.
    //
    // Measured all the same, so `DnsOutcome` still reports what the tunnel was
    // doing when the rules went in.
    let (_, client) = egress::vpn_verdict(owner, egress.as_ref())?;

    let namespaces: Vec<&str> = AG_NRPT_CORE.to_vec();

    // Each name gets its own rule with its own nameserver list, because which
    // providers substitute a name differs per name (only geohide proxies
    // `daily-cloudcode-pa`; xbox-dns and comss return genuine Google for it).
    // The probe leaves through the ISP interface so a tunnel does not hide the
    // substitution.
    let probe_if = egress.as_ref().map(|e| e.if_index).unwrap_or(0);
    let probe_until = Instant::now() + PROBE_BUDGET;
    let mut probe_gave_up = false;
    let mut desired = Vec::new();
    for &name in &namespaces {
        let servers = if Instant::now() < probe_until {
            // A dot per name, because the probing below is network-bound and the
            // caller has already printed its label: without this the step is a
            // motionless line for as long as the queries take, which is what an
            // eternal hang looks like from the outside.
            tick();
            nameservers_for(name, via_relay, probe_if)
        } else {
            probe_gave_up = true;
            assemble_nameservers(via_relay, &[])
        };
        desired.push((name, servers));
    }
    let writer = machine_state::Writer::acquire()?;
    if saved_dns_wish()? != Some(true) {
        return Err("Сохранённый режим больше не включает DNS; правила не изменены.".into());
    }
    hosts_pin::check_update(&writer)?;
    let result = nrpt::apply(owner, &writer, Some(desired));
    invalidate_cache();
    result?;
    flush_nrpt_cache()?;
    prefix::apply(owner, &writer).map_err(|e| format!("Owned NRPT rules received; IPv4 preference failed: {e}"))?;

    // Fallback for a machine without the relay. With a tunnel up the rules alone
    // cannot work: Windows sends the query through the VPN whatever the routing
    // table says, so the resolver sees a foreign client and forwards the genuine
    // Google address. Pinning the substituted address takes DNS out of the loop,
    // at the cost of freezing a TTL-60 answer in a static file - which is
    // exactly what the relay exists to avoid, so it wins whenever it is on.
    let (pinned, pin_error) = match &egress {
        _ if via_relay => {
            hosts_pin::remove_entries(&writer).map_err(|e| format!("Owned NRPT rules received; stale hosts cleanup failed: {e}"))?;
            (Vec::new(), None)
        }
        Some(eg) if eg.vpn_active => match pin_substituted_hosts(&writer, &namespaces, eg.if_index) {
            Ok(pinned) => (pinned, None),
            Err(e) => (Vec::new(), Some(e)),
        },
        _ => {
            hosts_pin::remove_entries(&writer).map_err(|e| format!("Owned NRPT rules received; hosts cleanup failed: {e}"))?;
            (Vec::new(), None)
        }
    };
    if !pinned.is_empty() {
        // hosts is consulted through the same cache the rules just flushed.
        flush_nrpt_cache()?;
    }

    Ok(DnsOutcome {
        vpn_active: egress.as_ref().map_or(false, |e: &Egress| e.vpn_active),
        stood_down_for_vpn: false,
        client,
        via_relay,
        pinned,
        pin_error,
        probe_gave_up,
    })
}

/// What to print after the DNS step, or `None` when there is nothing worth
/// saying. A conflicting rule is reported on top of everything else: it makes
/// the rest a no-op for that name, silently.
pub fn outcome_note(owner: &mut CommandOutcome, o: &DnsOutcome) -> Result<Option<String>, String> {
    let mut lines: Vec<String> = Vec::new();

    // Said first and on its own: nothing else in this function describes rules
    // that were not written, and a user who sees no other note would reasonably
    // assume the step silently failed.
    if o.stood_down_for_vpn {
        return Ok(Some(
            "  Обнаружен активный VPN, трафик Antigravity идёт через него —\n  \
             правила DNS не создавались. Запросы идут так, как их настраивает\n  \
             VPN. Если выход VPN в разрешённом регионе, обход уже работает и\n  \
             без наших правил; если нет — отключите VPN и запустите пункт 1 снова."
                .to_string(),
        ));
    }

    // The two cases a tunnel used to swallow. Said early and in full, because a
    // user who sees "VPN обнаружен" and rules created at the same time will
    // otherwise read it as the tool contradicting itself.
    if o.vpn_active {
        lines.push(
            match o.client {
                egress::ClientEgress::Physical => {
                    "  VPN активен, но трафик Antigravity идёт мимо него\n  \
                     (исключён из VPN) — правила DNS созданы: без них\n  \
                     запросы уходят из заблокированного региона и возвращают\n  \
                     ошибку 400."
                }
                _ => {
                    "  VPN активен, Antigravity не запущен — проверить, идёт ли\n  \
                     его трафик через VPN, не удалось. Правила DNS созданы:\n  \
                     лишние они лишь замедляют на один переход, а недостающие\n  \
                     дают ошибку 400."
                }
            }
            .to_string(),
        );
    }

    if o.probe_gave_up {
        lines.push(
            "  \x1b[33mПроверка DNS-провайдеров не уложилась в отведённое время —\n  \
             правила записаны по общему списку. Обычно это значит, что запросы\n  \
             к DNS блокирует сеть или VPN.\x1b[0m\x1b[92m"
                .to_string(),
        );
    }



    if o.via_relay {
        #[cfg(target_os = "windows")]
        let relay_running = background::is_running(owner)?;
        #[cfg(not(target_os = "windows"))]
        let relay_running = { let _ = owner; background::is_running() };
        lines.push(
            if relay_running {
                "  Резолвинг идёт через фоновый релей — адреса берутся с канала\n  \
                 провайдера и обновляются по TTL."
            } else {
                "  \x1b[33mФоновый релей включён, но не запущен — временно работает\n  \
                 прямой путь.\x1b[0m\x1b[92m"
            }
            .to_string(),
        );
        return Ok(Some(lines.join("\n")));
    }

    if let Some(note) = fallback_note(o) {
        lines.push(note);
    }
    if lines.is_empty() {
        Ok(None)
    } else {
        Ok(Some(lines.join("\n")))
    }
}

/// The `hosts`-pinning half of the message, used when the relay is off.
fn fallback_note(o: &DnsOutcome) -> Option<String> {
    if let Some(e) = &o.pin_error {
        return Some(format!(
            "  \x1b[33mНе удалось закрепить адреса: {}\x1b[0m\x1b[92m",
            e
        ));
    }
    if !o.pinned.is_empty() {
        return Some(format!(
            "  VPN активен — {} адресов получено напрямую через провайдера и закреплено.",
            o.pinned.len()
        ));
    }
    // Says nothing about the VPN itself: `outcome_note` has already printed a
    // line about it by the time this is reached, and saying "VPN активен" twice
    // in one step reads as two different findings.
    if o.vpn_active {
        return Some(
            "  \x1b[33mРезолвер не подменяет адреса даже с канала провайдера —\n  \
             проверьте, что DNS-провайдеры доступны.\x1b[0m\x1b[92m"
                .to_string(),
        );
    }
    None
}

/// Keeps the DNS layer honest about the network it woke up on. Runs on every
/// elevated start of the unlocker.
///
/// Two jobs, and the first one is new: **a VPN that came up after the machine
/// was patched takes the rules back off.** `setup_dns_nrpt` refuses to
/// install them while a tunnel is up, but that only covers the machine's state
/// at patch time; a user who connects a VPN afterwards would otherwise keep
/// overriding their own resolver for three names indefinitely. Returns the
/// machine to "whatever the VPN configured", which is the whole rule (G26).
///
/// The second is the older one: the pinned `hosts` block is a static copy of a
/// TTL-60 answer, so it is rewritten while it is still the fallback in use, and
/// dropped the moment it is not.
/// Nothing is pinned on Linux yet (no NRPT, no relay), so there is nothing to
/// refresh. A no-op keeps `main()`'s startup path clean.
#[cfg(not(target_os = "windows"))]
pub fn refresh_pinned_hosts(_owner: &mut CommandOutcome) -> Result<(), String> { Ok(()) }

#[cfg(target_os = "windows")]
pub fn refresh_pinned_hosts(owner: &mut CommandOutcome) -> Result<(), String> {
    if !checked_nrpt_state(owner)?.core_applied {
        return Ok(());
    }
    // Same evidence rule as `setup_dns_nrpt`, and it matters more here: this
    // runs unattended on every elevated start, so reading "a tunnel is up" as
    // "the client is in it" would quietly strip a working configuration off a
    // machine whose client is excluded from that tunnel (G29). Rules are removed
    // only when the client is measured inside it - and here the measurement is
    // usually available, because a user opens this tool while Antigravity is
    // running.
    // No VPN branch any more (D25): the rules stay whatever the tunnel does, and
    // the relay decides at runtime what they answer.
    // The relay resolves live, so a pinned block would only be a stale copy.
    let writer = machine_state::Writer::acquire()?;
    if !checked_nrpt_state(owner)?.core_applied { return Ok(()); }
    hosts_pin::remove_entries(&writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    #[cfg(windows)]
    #[test]
    fn pending_owned_cleanup_survives_the_last_rule_removal() {
        let mut empty = NrptState { core_applied: false, owned_rules_present: false,
            recovery_pending: false, auxiliary_cleanup: false };
        assert!(!empty.needs_retirement());
        empty.auxiliary_cleanup = true;
        assert!(empty.needs_retirement());
        assert!(!empty.core_applied && !empty.owned_rules_present);
    }

    /// The stand-down is announced on its own and nothing else is printed with
    /// it: a user who saw no note at all would reasonably read a step that wrote
    /// no rules as a step that failed.
    #[test]
    fn a_vpn_stand_down_says_so_and_says_nothing_else() {
        let o = DnsOutcome {
            vpn_active: true,
            stood_down_for_vpn: true,
            client: egress::ClientEgress::Tunnel,
            via_relay: true,
            pinned: Vec::new(),
            pin_error: None,
            probe_gave_up: true,
        };
        let mut owner = CommandOutcome::default();
        let note = outcome_note(&mut owner, &o).unwrap().expect("должно быть сообщение");
        assert!(note.contains("VPN"), "{}", note);
        assert!(note.contains("правила DNS не создавались"), "{}", note);
        // The relay/probe/takeover lines belong to a run that wrote rules.
        assert!(!note.contains("релей"), "{}", note);
        assert!(!note.contains("Забраны правила"), "{}", note);
    }

    /// The G29 case, from the other side: a tunnel is up, the client was
    /// measured going around it, so the rules **were** written. Seeing "VPN"
    /// and created rules in the same run reads as a contradiction unless the
    /// note explains it, so it must be there and it must not be the stand-down
    /// text.
    #[test]
    fn a_client_outside_the_tunnel_is_told_why_rules_were_written() {
        let with = |client| DnsOutcome {
            vpn_active: true,
            stood_down_for_vpn: false,
            client,
            via_relay: false,
            pinned: Vec::new(),
            pin_error: None,
                probe_gave_up: false,
        };

        let mut owner = CommandOutcome::default();
        let excluded = outcome_note(&mut owner, &with(egress::ClientEgress::Physical)).unwrap().expect("сообщение");
        assert!(excluded.contains("мимо него"), "{}", excluded);
        assert!(excluded.contains("400"), "{}", excluded);
        assert!(!excluded.contains("не создавались"), "{}", excluded);

        // Antigravity was not running: the rules still go in, and the note says
        // the measurement is what is missing rather than claiming either way.
        let unknown = outcome_note(&mut owner, &with(egress::ClientEgress::Unknown)).unwrap().expect("сообщение");
        assert!(unknown.contains("не запущен"), "{}", unknown);
        assert!(!unknown.contains("не создавались"), "{}", unknown);

        // No tunnel at all: nothing to explain, so nothing is said about one.
        let plain = DnsOutcome {
            vpn_active: false,
            ..with(egress::ClientEgress::Unknown)
        };
        assert!(
            outcome_note(&mut owner, &plain).unwrap().map_or(true, |n| !n.contains("VPN")),
            "{:?}",
            outcome_note(&mut owner, &plain)
        );
    }

    #[test]
    fn the_relay_goes_first_in_the_rule() {
        // A name only geohide substitutes: the fallback is geohide alone -
        // never a provider that returns genuine Google for it.
        let geohide = "45.155.204.190";
        let servers = assemble_nameservers(true, &[geohide]);
        assert_eq!(
            servers.first().map(|s| s.as_str()),
            Some(dns_forwarder::LISTEN_IP)
        );
        assert!(servers.iter().any(|s| s == geohide));
        // The genuine-returning providers must NOT be in this name's fallback.
        for other in ["111.88.96.50", "83.220.169.155"] {
            assert!(
                !servers.iter().any(|s| s == other),
                "a non-substituting provider leaked into the fallback: {:?}",
                servers
            );
        }
        // No IPv6 while the relay is up.
        assert!(!servers.iter().any(|s| s.contains(':')));
    }

    #[test]
    fn a_name_nobody_substitutes_lists_every_reachable_provider() {
        // antigravity-unleash is genuine everywhere - there is nothing to leak,
        // so all providers serve as plain resolvers behind the relay.
        //
        // "Every provider" means every provider Windows can be pointed at. A DoH
        // provider has no UDP address by construction (see `resolvers::Transport`)
        // and must stay out of the list even here, where the rule is at its most
        // permissive: a nameserver that answers nothing is worse than one fewer
        // fallback.
        let servers = assemble_nameservers(true, &[]);
        for p in resolvers::PROVIDERS {
            match p.v4.first() {
                Some(first) => assert!(
                    servers.iter().any(|s| s == first),
                    "{} missing from {:?}",
                    p.name,
                    servers
                ),
                None => {
                    if let resolvers::Transport::Doh(endpoint) = p.transport {
                        for a in endpoint.addrs {
                            assert!(
                                !servers.iter().any(|s| s == a),
                                "DoH address {} leaked into a nameserver list",
                                a
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn without_the_relay_ipv6_is_listed_and_loopback_is_not() {
        let servers = assemble_nameservers(false, &["45.155.204.190"]);
        assert!(!servers.iter().any(|s| s == dns_forwarder::LISTEN_IP));
        assert!(
            servers.iter().any(|s| s.contains(':')),
            "v6 resolvers belong in the no-relay list: {:?}",
            servers
        );
    }

    /// The end-to-end path this machine can actually exercise: resolve through
    /// the ISP link past a live tunnel and rewrite the real hosts block, exactly
    /// as startup does. Needs admin, a live network and the rules already in
    /// place. Deliberately leaves the block behind - that is the working state.
    #[test]
    #[ignore = "writes the real hosts file; run with --ignored"]
    fn pins_the_real_hosts_file() {
        let path = hosts_pin::hosts_path();
        let before = std::fs::read_to_string(&path).unwrap_or_default();
        println!("--- before ---\n{}\n--------------", before);

        // Each precondition, so a silent no-op says which one failed.
        let mut owner = CommandOutcome::default();
        println!("nrpt applied: {}", is_nrpt_applied(&mut owner).unwrap());
        let eg = egress::detect(&mut owner).unwrap();
        println!(
            "egress: if{:?} vpn={:?}",
            eg.as_ref().map(|e| e.if_index),
            eg.as_ref().map(|e| e.vpn_active)
        );
        if let Some(eg) = &eg {
            let server: Ipv4Addr = resolvers::PROVIDERS[0].v4[0].parse().unwrap();
            for ns in AG_NRPT_CORE {
                println!(
                    "  {}\n    isp={:?}\n    tun={:?}\n    best={:?}",
                    ns,
                    crate::dns_client::resolve_a_via(ns, server, eg.if_index),
                    crate::dns_client::resolve_a_via(ns, server, 0),
                    resolvers::resolve_a_best(ns, eg.if_index)
                        .map(|(a, p, v)| format!("{:?} via {} {:?}", a, p, v))
                );
            }
        }

        refresh_pinned_hosts(&mut owner).unwrap();

        let after = std::fs::read_to_string(&path).unwrap_or_default();
        println!("--- after ---\n{}\n-------------", after);

        // Whatever else lived in the file has to survive untouched.
        for line in before.lines().filter(|l| !l.trim().is_empty()) {
            assert!(
                after.contains(line),
                "hosts lost a pre-existing line: {}",
                line
            );
        }

        // The outcome differs by design, so assert the right one instead of
        // passing silently either way.
        let pinned = after.contains("AG_UNLOCKER_HOSTS_BEGIN");
        if eg.map_or(false, |e| e.vpn_active) {
            assert!(pinned, "a tunnel is up but nothing was pinned");
        } else {
            assert!(!pinned, "no tunnel, so the block should not be there");
            println!("(без VPN пиннинг не нужен — правила NRPT справляются сами)");
        }
    }
}
