//! What the bypass is doing about the region 400, written where the window can
//! read it — and the window's own live watch of the client's log.
//!
//! The watch that *acts* lives in the relay (`ls_log::poll` →
//! `dns_forwarder::answer_region_400`) and has to: that is the process holding
//! the route table, the resolver cache and the tunnel verdict. The window is a
//! different process, and until now its only view of any of it was
//! `forwarder.log` — a file written for a person to read, not for a parser
//! (P29). So the relay leaves one small record beside that log: what it is doing
//! now, and what it did about the last refusal.
//!
//! Two halves of one answer, and the split is deliberate:
//!
//! * **the symptom** — `ls_log::newest_refusal`, read by the window itself, so
//!   "Antigravity is hitting the gate right now" is visible whether or not
//!   anything of ours is running. That is exactly the case where the user most
//!   needs to be told something (the bypass is off, or the relay died).
//! * **the answer** — this record, written by the side that knows. The window
//!   never infers "it was intercepted" from a switch being on; it says so only
//!   when the relay wrote down that it did something.
//!
//! Best-effort in both directions. A missing, stale or unparsable record means
//! the window says nothing about the answer, never that there was none.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FILE_NAME: &str = "gate.json";

/// A record older than this is not being refreshed by anybody.
///
/// Sized against the **pass**, not against `WARM_EVERY`: a pass is 15 s of sleep
/// plus its work, and that work opens with a PowerShell VPN check every four
/// minutes and runs probes with budgets of seconds each. Ten sleeps' worth of
/// slack, because the cost of being too tight is the window calling a live relay
/// dead, and the cost of being too loose is a dead one described as alive for a
/// couple of minutes - and the second claim is not the one the window rests
/// anything on: whether the service is running is `Status::relay_running`,
/// measured, and this record is only the *answer* half (I58).
pub const STALE_AFTER: Duration = Duration::from_secs(150);

/// The relay's side of the story.
///
/// Unix seconds rather than a formatted stamp: the only question ever asked of
/// these is "how long ago", the two processes share a clock, and neither has to
/// agree with the other about how to print one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    /// When the relay last wrote this.
    pub at: u64,
    /// The route the table currently puts first, by `routes::Kind::label()`.
    /// Empty until the first probe lands.
    pub route: String,
    /// Until when substitution is forced on because of a refusal. 0 = not
    /// forced, which is the ordinary state.
    pub forced_until: u64,
    /// Whether the DNS layer is standing down for a tunnel carrying the client.
    /// Always false since D25 - the bypass carries the gate hosts on every
    /// network - and kept so an older window reading a newer record still parses.
    pub stood_down: bool,
    /// The last refusal episode and what was done about it.
    pub last_400: Option<Episode>,
    /// The last model answer the relay saw in a client log, and the route it
    /// credited with it.
    pub last_ok: Option<Proof>,
    /// Whether gate hosts are answered with the loopback listener's addresses
    /// (`loopback`), i.e. whether every gate connection on the machine is ours
    /// to route, env variable or not.
    pub loopback: bool,
    /// Whether a VPN holds the default route, and where its exit is (a country
    /// code, empty until measured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<bool>,
    pub vpn_exit: String,
    /// The route table, best first, for the report the window copies out.
    pub routes: Vec<crate::routes::Row>,
    /// The relay generation that wrote this.
    pub version: u32,
    /// What keeps a listener of the relay from coming up (P53, `portcheck`).
    /// Empty when both bound. Written the moment a bind fails or succeeds,
    /// not at the next warm pass: the user is looking at the window then.
    pub blockers: Vec<Blocker>,
    /// Unix time something on the internet last answered the relay (a resolver,
    /// a DoH node, a route probe). 0 = nothing yet.
    pub reached_at: u64,
    /// When this relay process started. With `reached_at` it tells a relay that
    /// is cut off from one that has only just started (`cut_off`).
    pub started_at: u64,
    /// The relay's own exe - the file an antivirus exception has to name.
    pub exe: String,
    /// Untrusted serialized transport facts; lifecycle owners must bind these
    /// to the actual current process and listeners before granting readiness.
    #[cfg(windows)]
    #[serde(default, deserialize_with = "decode_transport", serialize_with = "encode_transport", skip_serializing_if = "TransportObservation::is_absent")]
    pub(crate) transport: TransportObservation,
    /// Optional image-bound generation. Absence never establishes an older image.
    #[cfg(windows)]
    #[serde(default, deserialize_with = "decode_installed_generation", serialize_with = "encode_installed_generation")]
    pub(crate) installed_generation: InstalledGenerationObservation,
    #[cfg(windows)]
    #[serde(skip)]
    pub(crate) persistence_hold: Option<String>,
}

#[cfg(windows)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportInstance {
    pub(crate) pid: u32,
    pub(crate) creation_time: u64,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CapabilityObservation {
    Disabled,
    Starting,
    Ready,
    Failed(String),
}

#[cfg(windows)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportCapabilities {
    pub(crate) dns: CapabilityObservation,
    pub(crate) tcp_proxy: CapabilityObservation,
    pub(crate) dns_alias: CapabilityObservation,
}

#[cfg(windows)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportReport {
    pub(crate) schema: u32,
    pub(crate) instance: TransportInstance,
    pub(crate) active_config: crate::settings::ActiveTransportConfig,
    pub(crate) observed: TransportCapabilities,
}

#[cfg(windows)]
impl TransportReport {
    fn validate(&self) -> Result<(), String> {
        let config = self.active_config;
        if self.schema != 1 || self.instance.pid == 0 || self.instance.creation_time == 0 {
            return Err("invalid transport schema or process identity".into());
        }
        config.validate()?;
        for value in [&self.observed.dns, &self.observed.tcp_proxy, &self.observed.dns_alias] {
            if matches!(value, CapabilityObservation::Failed(cause) if cause.is_empty()) {
                return Err("transport failure cause is empty".into());
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Default)]
pub(crate) enum TransportObservation {
    #[default]
    Absent,
    Valid(TransportReport),
    Invalid(String),
}

#[cfg(windows)]
impl TransportObservation {
    fn is_absent(&self) -> bool { matches!(self, Self::Absent) }
}

#[cfg(windows)]
fn decode_transport<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<TransportObservation, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    let parsed = serde_json::from_value::<TransportReport>(value).map_err(|_| "malformed transport observation".to_owned())
        .and_then(|report| { report.validate()?; Ok(report) });
    Ok(match parsed { Ok(report) => TransportObservation::Valid(report), Err(error) => TransportObservation::Invalid(error) })
}

#[cfg(windows)]
fn encode_transport<S: serde::Serializer>(value: &TransportObservation, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        TransportObservation::Absent => serializer.serialize_none(),
        TransportObservation::Valid(report) => {
            report.validate().map_err(serde::ser::Error::custom)?;
            report.serialize(serializer)
        }
        // Preserve the component-local unknown state without copying untrusted
        // payload into a later advisory report or blocking unrelated fields.
        TransportObservation::Invalid(_) => serializer.serialize_none(),
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledGeneration {
    pub(crate) schema: u32,
    pub(crate) generation: u32,
    pub(crate) program_native_id: crate::windows_coordinator::windows_installation::NativeObjectId,
    pub(crate) program_sha256: String,
}

#[cfg(windows)]
#[derive(Debug, Clone, Default)]
pub(crate) enum InstalledGenerationObservation {
    #[default]
    Absent,
    Valid(InstalledGeneration),
    Invalid(String),
}

#[cfg(windows)]
fn decode_installed_generation<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<InstalledGenerationObservation, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() { return Ok(InstalledGenerationObservation::Absent); }
    let parsed = serde_json::from_value::<InstalledGeneration>(value).map_err(|error| error.to_string())
        .and_then(|binding| {
            if binding.schema != 1 || binding.generation == 0 || binding.program_sha256.len() != 64
                || !binding.program_sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
                return Err("invalid installed generation schema, value or digest".into());
            }
            Ok(binding)
        });
    Ok(match parsed { Ok(binding) => InstalledGenerationObservation::Valid(binding),
        Err(cause) => InstalledGenerationObservation::Invalid(cause) })
}

#[cfg(windows)]
fn encode_installed_generation<S: serde::Serializer>(binding: &InstalledGenerationObservation, serializer: S) -> Result<S::Ok, S::Error> {
    match binding {
        InstalledGenerationObservation::Absent => serializer.serialize_none(),
        InstalledGenerationObservation::Valid(value) => value.serialize(serializer),
        InstalledGenerationObservation::Invalid(cause) => Err(serde::ser::Error::custom(format!("invalid installed generation: {cause}"))),
    }
}

#[cfg(windows)]
pub(crate) enum BoundGeneration {
    Bound(u32),
    Unknown(String),
}

#[cfg(windows)]
pub(crate) fn receive_bound_generation(program: &crate::windows_coordinator::windows_installation::CheckedPath) -> BoundGeneration {
    let Some(path) = path() else { return BoundGeneration::Unknown("relay report path unavailable".into()); };
    receive_bound_generation_from(&path, program)
}

#[cfg(windows)]
fn receive_bound_generation_from(path: &std::path::Path, program: &crate::windows_coordinator::windows_installation::CheckedPath) -> BoundGeneration {
    match receive_bound_report_from(path, program) {
        Ok(report) => match report.installed_generation {
            InstalledGenerationObservation::Valid(binding) => BoundGeneration::Bound(binding.generation),
            _ => BoundGeneration::Unknown("installed generation binding disappeared".into()),
        },
        Err(cause) => BoundGeneration::Unknown(cause),
    }
}

#[cfg(windows)]
pub(crate) fn receive_bound_report(program: &crate::windows_coordinator::windows_installation::CheckedPath) -> Result<Report, String> {
    let path = path().ok_or("relay report path unavailable")?;
    receive_bound_report_from(&path, program)
}

#[cfg(windows)]
fn receive_bound_report_from(path: &std::path::Path, program: &crate::windows_coordinator::windows_installation::CheckedPath) -> Result<Report, String> {
    let source = checked_runtime_metadata_source(program)?;
    let data = crate::windows_coordinator::windows_installation::read_protected_user_metadata(path)?
        .ok_or("protected generation report absent")?;
    let report: Report = serde_json::from_slice(&data).map_err(|error| format!("invalid protected report: {error}"))?;
    checked_installed_generation(&report, &source)?.ok_or("installed generation binding absent")?;
    program.recheck()?;
    Ok(report)
}

#[cfg(windows)]
fn checked_installed_generation(report: &Report, source: &RuntimeMetadataSource) -> Result<Option<u32>, String> {
    match &report.installed_generation {
        InstalledGenerationObservation::Absent => Ok(None),
        InstalledGenerationObservation::Invalid(cause) => Err(format!("invalid installed generation binding: {cause}")),
        InstalledGenerationObservation::Valid(binding) if binding.program_native_id == source.program && binding.program_sha256 == source.sha256 => Ok(Some(binding.generation)),
        InstalledGenerationObservation::Valid(_) => Err("installed generation does not match the protected program".into()),
    }
}

/// The writer's observed payload may establish absent binding or a conflict.
/// Only the protected reader can receive a present binding as current.
#[cfg(windows)]
pub(crate) fn generation_repair_required(preflight: &crate::windows_coordinator::windows_installation::UserMetadataPreflight,
    program: &crate::windows_coordinator::windows_installation::CheckedPath) -> Result<bool, String> {
    let Some(data) = preflight.bytes() else { return Ok(true); };
    let report: Report = serde_json::from_slice(data).map_err(|error| format!("invalid existing generation report: {error}"))?;
    match checked_installed_generation(&report, &checked_runtime_metadata_source(program)?)? {
        None => Ok(true),
        Some(generation) if generation != crate::dns_forwarder::RELAY_VERSION => Err("installed generation conflicts with the selected image".into()),
        Some(_) => { require_current_generation(program)?; Ok(false) }
    }
}

#[cfg(windows)]
pub(crate) fn require_current_generation(program: &crate::windows_coordinator::windows_installation::CheckedPath) -> Result<(), String> {
    match receive_bound_generation(program) {
        BoundGeneration::Bound(generation) if generation == crate::dns_forwarder::RELAY_VERSION => Ok(()),
        BoundGeneration::Bound(_) => Err("installed generation conflicts with the selected image".into()),
        BoundGeneration::Unknown(cause) => Err(cause),
    }
}

#[cfg(all(windows, test))]
pub(crate) fn receive_fixture_generation(path: &std::path::Path,
    program: &crate::windows_coordinator::windows_installation::CheckedPath) -> BoundGeneration {
    receive_bound_generation_from(path, program)
}

/// The caller supplies the independently received actual published program;
/// the returned publication retains its preimage until the operation settles.
#[cfg(windows)]
pub(crate) fn publish_program_generation(program: &crate::windows_coordinator::windows_installation::CheckedPath,
    preflight: Option<&crate::windows_coordinator::windows_installation::UserMetadataPreflight>)
    -> Result<crate::windows_coordinator::windows_installation::UserMetadataPublication,
        crate::windows_coordinator::windows_installation::MetadataFailure> {
    use crate::windows_coordinator::windows_installation as owner;
    let prepare = || -> Result<(PathBuf, Vec<u8>), String> {
        let payload = program_generation_payload(program)?;
        program.recheck()?;
        Ok((path().ok_or("gate report path unavailable")?, payload))
    };
    let (target, payload) = prepare().map_err(|cause| owner::MetadataFailure {
        phase: "generation-report-preparation", cause, replace_result: None,
        evidence: serde_json::json!({"kind":"generation-report-preparation","publicationAttempted":false}), live: Vec::new(), pending: None, unwind: None, secondary_unwinds: Vec::new(),
    })?;
    owner::publish_user_metadata_checked(owner::UserMetadataField::GateReport, &target, &payload, preflight)
}

#[cfg(windows)]
fn program_generation_payload(program: &crate::windows_coordinator::windows_installation::CheckedPath) -> Result<Vec<u8>, String> {
    let source = checked_runtime_metadata_source(program)?;
    let report = Report { installed_generation: InstalledGenerationObservation::Valid(InstalledGeneration {
        schema: 1, generation: crate::dns_forwarder::RELAY_VERSION,
        program_native_id: source.program, program_sha256: source.sha256,
    }), ..Report::default() };
    serde_json::to_vec(&report).map_err(|error| format!("generation report serialization: {error}"))
}

#[cfg(all(windows, test))]
pub(crate) fn fixture_program_generation_payload(program: &crate::windows_coordinator::windows_installation::CheckedPath) -> Result<Vec<u8>, String> {
    program_generation_payload(program)
}

/// Something on this machine that keeps part of the bypass from running, as the
/// relay diagnosed it (`portcheck::diagnose`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Blocker {
    /// `door` (the gate hosts' listeners on `:443`) or `proxy` (the local proxy).
    pub what: String,
    /// The address that could not be bound.
    pub addr: String,
    /// `held`, `reserved`, `denied` or `other` (`portcheck::Cause::code`).
    pub cause: String,
    /// The program listening there, when `held` and its name could be read.
    pub by: String,
    /// The OS's own words, for the report.
    pub error: String,
}

/// How long a relay may run without anything on the internet answering it
/// before the window calls it cut off and asks whether *it* can reach anything.
/// Past two of the route probes' two-minute rounds, and past any DNS the
/// machine asked in between - a relay that works hears back every few seconds.
pub const CUT_OFF_AFTER: Duration = Duration::from_secs(4 * 60);

/// A model answer, as the relay saw it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Proof {
    /// When the relay noticed it.
    pub at: u64,
    /// The route credited with it, by label. Empty when no gate tunnel of ours
    /// was open around it - the client reached Google some other way.
    pub route: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Episode {
    /// When the relay *noticed*, which is up to one warm pass after the client
    /// logged it.
    pub at: u64,
    pub count: u32,
    /// What was done about it, in the words the window shows. Written by the
    /// side that knows, so the window never has to guess from a switch.
    pub acted: String,
    /// The route the refusal was pinned on, by label; empty when none of ours
    /// was open around it.
    pub route: String,
    /// No gate tunnel of ours carried it: the client dialled Google itself, so
    /// nothing the route table does can help until its connections come to us.
    pub bypassed: bool,
}

impl Report {
    /// How long ago this was written. A record stamped in the future — a clock
    /// moved between the two processes — reads as brand new rather than as an
    /// error; the alternative is calling a live relay dead.
    pub fn age(&self) -> Duration {
        Duration::from_secs(now_unix().saturating_sub(self.at))
    }

    pub fn is_stale(&self) -> bool {
        self.age() > STALE_AFTER
    }

    /// The relay has run for `CUT_OFF_AFTER` and nothing outside this machine
    /// has answered it for as long. Only a warm-looping relay of gen 32 or
    /// later publishes `reached_at`: an older one, or the Linux proxy (which
    /// writes this file only to record a blocker), is never called cut off.
    pub fn cut_off(&self) -> bool {
        if self.started_at == 0 || self.version < 32 {
            return false;
        }
        let now = now_unix();
        let limit = CUT_OFF_AFTER.as_secs();
        now.saturating_sub(self.started_at) >= limit
            && now.saturating_sub(self.reached_at.max(self.started_at)) >= limit
    }

    /// How much of the forced-substitution window is left. Only ever set with
    /// the loopback door down (D25's fallback, `resolvers::force_substitution`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn forced_left(&self) -> Option<Duration> {
        self.forced_until
            .checked_sub(now_unix())
            .filter(|left| *left > 0)
            .map(Duration::from_secs)
    }

    /// Everything the window draws, `at` excepted.
    ///
    /// `at` moves every warm pass and changes nothing on screen, so comparing it
    /// would wake the UI every fifteen seconds to redraw the same words.
    /// The route table rows are left out on purpose: their ages move every
    /// pass, and nothing on screen shows them - only the copied report does, and
    /// that reads the file fresh when the button is pressed.
    fn same_state_as(&self, other: &Report) -> bool {
        self.route == other.route
            && self.forced_until == other.forced_until
            && self.stood_down == other.stood_down
            && self.last_400 == other.last_400
            && self.last_ok == other.last_ok
            && self.loopback == other.loopback
            && self.tunnel == other.tunnel
            && self.vpn_exit == other.vpn_exit
            && self.blockers == other.blockers
            && self.reached_at == other.reached_at
            && self.started_at == other.started_at
            && self.exe == other.exe
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn path() -> Option<PathBuf> {
    let dir = crate::dns_forwarder::checked_log_dir().ok()?;
    if dir.as_os_str().is_empty() {
        return None;
    }
    Some(dir.join(FILE_NAME))
}

pub fn read() -> Option<Report> {
    read_checked().ok().flatten()
}

/// Fresh report evidence: only a missing file means that no report exists.
pub(crate) fn read_checked() -> Result<Option<Report>, String> {
    let path = path().ok_or("relay report path unavailable")?;
    checked_report(std::fs::read_to_string(path))
}

fn checked_report(raw: std::io::Result<String>) -> Result<Option<Report>, String> {
    match raw {
        Ok(raw) => serde_json::from_str::<Report>(&raw)
            .map(|mut report| {
                if crate::egress::observation_support() == crate::egress::ObservationSupport::Unsupported {
                    report.tunnel = None;
                    report.vpn_exit.clear();
                }
                Some(report)
            })
            .map_err(|e| format!("invalid relay report: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read relay report: {e}")),
    }
}

// ---------------------------------------------------------------------------
// The relay's side
// ---------------------------------------------------------------------------

/// This process's copy, so a partial update never has to read the file back to
/// keep the fields it is not changing.
#[cfg(not(windows))]
static CURRENT: Mutex<Option<Report>> = Mutex::new(None);

#[cfg(windows)]
#[derive(Default)]
struct WindowsWriterState {
    report: Report,
    live_resources: Vec<crate::windows_coordinator::windows_installation::AcquiredCreation>,
    pending: Vec<RuntimePendingMetadata>,
    secondary_unwinds: Vec<crate::windows_coordinator::windows_installation::OwnedUnwind>,
}
#[cfg(windows)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RuntimeMetadataSource {
    program: crate::windows_coordinator::windows_installation::NativeObjectId,
    sha256: String,
}
#[cfg(windows)]
struct RuntimePendingMetadata {
    source: RuntimeMetadataSource,
    receipt: crate::windows_coordinator::windows_installation::PendingUserMetadataPublication,
}
#[cfg(windows)]
impl WindowsWriterState {
    fn prepare_metadata(&mut self, field: crate::windows_coordinator::windows_installation::UserMetadataField,
        source: &RuntimeMetadataSource, recheck_source: &dyn Fn() -> Result<RuntimeMetadataSource, String>) -> Result<(), String> {
        use crate::windows_coordinator::windows_installation as owner;
        let mut index = 0;
        while index < self.pending.len() {
            if self.pending[index].receipt.field() != field { index += 1; continue; }
            if self.pending[index].source != *source { return Err("pending metadata source differs from current protected program".into()); }
            let received = owner::receive_pending_user_metadata(&mut self.pending[index].receipt, field);
            if recheck_source()? != *source { return Err("metadata source changed during pending receiving".into()); }
            if self.pending[index].receipt.restoration_owed() { return Err("pending metadata restoration remains owed".into()); }
            let published = match received {
                owner::PendingMetadataReceiving::CanonicalUnchangedReceived => false,
                owner::PendingMetadataReceiving::PublishedReceived => true,
                owner::PendingMetadataReceiving::Held { cause, actual } => return Err(format!("{cause}; actual={actual:?}")),
            };
            self.pending[index].receipt.release_received(published, &mut self.live_resources);
            self.pending.remove(index);
        }
        if field == owner::UserMetadataField::GateReport { self.report.persistence_hold = None; }
        for result in self.finish_live_resources() {
            if let Err(cause) = result { eprintln!("metadata cleanup remains held: {cause}"); }
        }
        Ok(())
    }

    fn write_gate_metadata(&mut self, target: &std::path::Path, source: &RuntimeMetadataSource,
        recheck_source: &dyn Fn() -> Result<RuntimeMetadataSource, String>, change: impl FnOnce(&mut Report)) -> Result<(), String> {
        use crate::windows_coordinator::windows_installation as owner;
        self.prepare_metadata(owner::UserMetadataField::GateReport, source, recheck_source)?;
        if recheck_source()? != *source { return Err("runtime metadata source changed before publication".into()); }
        change(&mut self.report);
        self.report.at = now_unix();
        if self.report.started_at == 0 { self.report.started_at = self.report.at; }
        self.report.installed_generation = InstalledGenerationObservation::Valid(InstalledGeneration {
            schema: 1, generation: crate::dns_forwarder::RELAY_VERSION,
            program_native_id: source.program.clone(), program_sha256: source.sha256.clone(),
        });
        let payload = serde_json::to_vec(&self.report).map_err(|error| format!("gate report serialization: {error}"))?;
        if recheck_source()? != *source { return Err("runtime metadata source changed before publication".into()); }
        let mut publication = match owner::publish_user_metadata(owner::UserMetadataField::GateReport, target, &payload) {
            Ok(value) => value,
            Err(mut error) => {
                let unwind = error.unwind.take();
                let pending = error.pending.is_some();
                if let Some(receipt) = error.pending.take() { self.pending.push(RuntimePendingMetadata { source: source.clone(), receipt }); }
                self.live_resources.append(&mut error.live);
                self.secondary_unwinds.append(&mut error.secondary_unwinds);
                if let Some(payload) = unwind { std::panic::resume_unwind(payload.0); }
                let message = format!("{error}; actual={}", error.evidence);
                if pending { self.report.persistence_hold = Some(message.clone()); }
                let finishes = self.finish_live_resources();
                if !finishes.is_empty() { return Err(format!("{message}; owned-resource receiving={finishes:?}")); }
                return Err(message);
            }
        };
        let current = recheck_source().and_then(|actual| {
            if actual == *source { Ok(()) } else { Err("runtime metadata source changed after publication".into()) }
        });
        if let Err(error) = current {
            let message = format!("gate publication retained after image recheck: {error}; actual={}", publication.evidence());
            self.report.persistence_hold = Some(message.clone());
            let mut failure = publication.into_failure("gate-image-recheck", message.clone(), true, false);
            if let Some(receipt) = failure.pending.take() { self.pending.push(RuntimePendingMetadata { source: source.clone(), receipt }); }
            self.live_resources.append(&mut failure.live);
            let finishes = self.finish_live_resources();
            return Err(format!("{message}; owned-resource receiving={finishes:?}"));
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| publication.settle())) {
            Ok(Ok(_)) => {},
            Ok(Err(cause)) => {
                let mut error = publication.into_failure("gate-settlement", cause, false, false);
                let message = format!("{error}; actual={}", error.evidence);
                if let Some(receipt) = error.pending.take() { self.pending.push(RuntimePendingMetadata { source: source.clone(), receipt }); }
                self.live_resources.append(&mut error.live);
                let finishes = self.finish_live_resources();
                return Err(format!("{message}; owned-resource receiving={finishes:?}"));
            },
            Err(payload) => {
                let mut error = publication.into_failure("gate-settlement-unwind", "gate settlement unwound".into(), true, false);
                if let Some(receipt) = error.pending.take() { self.pending.push(RuntimePendingMetadata { source: source.clone(), receipt }); }
                self.live_resources.append(&mut error.live);
                std::panic::resume_unwind(payload)
            }
        }
        Ok(())
    }

    fn finish_live_resources(&mut self) -> Vec<Result<serde_json::Value, String>> {
        let mut results = Vec::new();
        let mut index = 0;
        while index < self.live_resources.len() {
            match self.live_resources[index].finish() {
                Ok(evidence) => { results.push(Ok(evidence)); self.live_resources.remove(index); }
                Err(cause) => { results.push(Err(cause)); index += 1; }
            }
        }
        results
    }
}
#[cfg(windows)]
static CURRENT: Mutex<Option<WindowsWriterState>> = Mutex::new(None);

#[cfg(windows)]
fn runtime_metadata_source() -> Result<RuntimeMetadataSource, String> {
    with_runtime_metadata_source(|source, _| Ok(source.clone()))
}

#[cfg(windows)]
fn checked_runtime_metadata_source(program: &crate::windows_coordinator::windows_installation::CheckedPath) -> Result<RuntimeMetadataSource, String> {
    use sha2::{Digest, Sha256};
    program.recheck()?;
    let bytes = program.read_snapshot()?;
    program.recheck()?;
    Ok(RuntimeMetadataSource { program: program.native_id(), sha256: hex::encode(Sha256::digest(&bytes)) })
}

#[cfg(windows)]
fn with_runtime_metadata_source<T>(action: impl FnOnce(&RuntimeMetadataSource,
    &dyn Fn() -> Result<RuntimeMetadataSource, String>) -> Result<T, String>) -> Result<T, String> {
    use crate::windows_coordinator::windows_installation as owner;
    let image = RUNTIME_IMAGE.get().ok_or("runtime image was not received")?;
    image.recheck()?;
    let locations = owner::background_locations()?;
    let inputs = owner::background_inputs(locations.managed_root(), locations.managed_directory(), None, &crate::dns_forwarder::log_dir())?;
    let lease = owner::background_lease(inputs, None)?;
    let program = owner::checked_background_path(&lease, locations.managed_program(), owner::PathKind::File)?;
    if program.native_id() != image.native_id() { return Err("runtime image differs from protected managed program".into()); }
    let check = || {
        image.recheck()?;
        program.recheck()?;
        let current = owner::checked_background_path(&lease, locations.managed_program(), owner::PathKind::File)?;
        if current.native_id() != program.native_id() || current.native_id() != image.native_id() {
            return Err("runtime image differs from protected managed program".into());
        }
        let source = checked_runtime_metadata_source(&current)?;
        program.recheck()?;
        image.recheck()?;
        Ok(source)
    };
    let source = check()?;
    // The real image, background lease and checked program remain held across
    // the callback; its checker borrows those pins, not a scripted verdict.
    action(&source, &check)
}

#[cfg(windows)]
fn with_windows_writer<T>(action: impl FnOnce(&mut WindowsWriterState) -> Result<T, String>) -> Result<T, String> {
    let mut guard = CURRENT.lock().map_err(|_| "metadata writer lock poisoned")?;
    let state = guard.get_or_insert_with(WindowsWriterState::default);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(state)));
    drop(guard);
    match result { Ok(value) => value, Err(payload) => std::panic::resume_unwind(payload) }
}

#[cfg(windows)]
pub(crate) fn recheck_runtime_metadata_source(expected: &RuntimeMetadataSource) -> Result<(), String> {
    if runtime_metadata_source()? != *expected { return Err("runtime metadata source changed".into()); }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn prepare_runtime_metadata(field: crate::windows_coordinator::windows_installation::UserMetadataField)
    -> Result<RuntimeMetadataSource, String> {
    with_runtime_metadata_source(|source, check| with_windows_writer(|state| {
        state.prepare_metadata(field, source, check)?;
        Ok(source.clone())
    }))
}

#[cfg(windows)]
pub(crate) fn retain_runtime_metadata_failure(mut failure: crate::windows_coordinator::windows_installation::MetadataFailure,
    source: RuntimeMetadataSource) -> String {
    let unwind = failure.unwind.take();
    let finishes = match CURRENT.lock() {
        Ok(mut guard) => {
            let state = guard.get_or_insert_with(WindowsWriterState::default);
            if let Some(receipt) = failure.pending.take() { state.pending.push(RuntimePendingMetadata { source: source.clone(), receipt }); }
            state.live_resources.append(&mut failure.live);
            state.secondary_unwinds.append(&mut failure.secondary_unwinds);
            if unwind.is_none() { state.finish_live_resources() } else { Vec::new() }
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            let state = guard.get_or_insert_with(WindowsWriterState::default);
            if let Some(receipt) = failure.pending.take() { state.pending.push(RuntimePendingMetadata { source, receipt }); }
            state.live_resources.append(&mut failure.live);
            state.secondary_unwinds.append(&mut failure.secondary_unwinds);
            if unwind.is_none() { state.finish_live_resources() } else { Vec::new() }
        }
    };
    if let Some(payload) = unwind { std::panic::resume_unwind(payload.0); }
    let mut message = format!("{failure}; actual={}", failure.evidence);
    if !finishes.is_empty() { message.push_str(&format!("; owned-resource receiving={finishes:?}")); }
    message
}

#[cfg(windows)]
pub(crate) fn finish_runtime_metadata() -> Result<(), String> {
    let mut guard = CURRENT.lock().map_err(|_| "gate report writer lock poisoned")?;
    let Some(state) = guard.as_mut() else { return Ok(()); };
    let results = state.finish_live_resources();
    let mut held = results.into_iter().filter_map(Result::err).collect::<Vec<_>>();
    if !state.pending.is_empty() { held.push("pending canonical metadata receiving".into()); }
    if held.is_empty() { Ok(()) } else { Err(format!("runtime metadata resources remain held: {}", held.join("; "))) }
}

#[cfg(windows)]
static RUNTIME_IMAGE: std::sync::OnceLock<std::sync::Arc<crate::windows_coordinator::process_identity::CurrentImage>> = std::sync::OnceLock::new();

#[cfg(windows)]
pub(crate) fn receive_runtime_image(image: std::sync::Arc<crate::windows_coordinator::process_identity::CurrentImage>) -> Result<(), String> {
    image.recheck()?;
    RUNTIME_IMAGE.set(image).map_err(|_| "runtime image was already received".into())
}

/// Capture this producer's real process identity once, independently of desired
/// settings timestamps or an older report belonging to the same executable.
#[cfg(windows)]
pub(crate) fn transport_started(active_config: crate::settings::ActiveTransportConfig) -> Result<TransportReport, String> {
    let image = RUNTIME_IMAGE.get().ok_or("runtime image was not received")?;
    image.recheck()?;
    let process = image.process();
    let report = TransportReport {
        schema: 1,
        instance: TransportInstance { pid: process.pid(), creation_time: process.creation() },
        active_config,
        observed: TransportCapabilities {
            dns: if active_config.dns { CapabilityObservation::Starting } else { CapabilityObservation::Disabled },
            tcp_proxy: if active_config.tcp_proxy { CapabilityObservation::Starting } else { CapabilityObservation::Disabled },
            dns_alias: if active_config.dns_alias { CapabilityObservation::Starting } else { CapabilityObservation::Disabled },
        },
    };
    report.validate()?;
    image.recheck()?;
    Ok(report)
}

#[cfg(windows)]
fn transport_config_matches(before: &TransportReport, after: &TransportReport) -> bool {
    before.instance.pid == after.instance.pid
        && before.instance.creation_time == after.instance.creation_time
        && before.active_config == after.active_config
}

#[cfg(windows)]
pub(crate) fn recheck_transport_instance(expected: &TransportInstance) -> Result<(), String> {
    let image = RUNTIME_IMAGE.get().ok_or("runtime image was not received")?;
    image.recheck()?;
    if expected.pid != image.process().pid() || expected.creation_time != image.process().creation() {
        return Err("transport instance differs from held current image".into());
    }
    Ok(())
}

/// Publish through the existing protected Gate owner. A failed publication
/// retains that owner's real pending/preimage obligations and returns the error.
#[cfg(windows)]
pub(crate) fn publish_transport(report: &TransportReport, proxy_blocker: Option<&Blocker>, dns_blocker: Option<&Blocker>, alias_blocker: Option<&Blocker>) -> Result<(), String> {
    report.validate()?;
    let image = RUNTIME_IMAGE.get().ok_or("runtime image was not received")?;
    image.recheck()?;
    if report.instance.pid != image.process().pid() || report.instance.creation_time != image.process().creation() {
        return Err("transport producer instance differs from its held runtime image".into());
    }
    with_runtime_metadata_source(|source, check| {
        let target = path().ok_or("gate report path unavailable")?;
        with_windows_writer(|state| {
            if let TransportObservation::Valid(before) = &state.report.transport {
                if !transport_config_matches(before, report) {
                    return Err("active transport configuration is immutable for this carrier instance".into());
                }
            }
            state.write_gate_metadata(&target, source, check, |current| {
                current.transport = TransportObservation::Valid(report.clone());
                current.version = crate::dns_forwarder::RELAY_VERSION;
                current.exe = image.path().to_string_lossy().into_owned();
                current.loopback = matches!(report.observed.dns_alias, CapabilityObservation::Ready);
                current.blockers.retain(|blocker| !matches!(blocker.what.as_str(), "proxy" | "dns" | "door"));
                if let Some(blocker) = proxy_blocker { current.blockers.push(blocker.clone()); }
                if let Some(blocker) = dns_blocker { current.blockers.push(blocker.clone()); }
                if let Some(blocker) = alias_blocker { current.blockers.push(blocker.clone()); }
            })
        })
    })
}

#[cfg(not(windows))]
fn update(change: impl FnOnce(&mut Report)) {
    let snapshot = {
        let Ok(mut guard) = CURRENT.lock() else {
            return;
        };
        let report = guard.get_or_insert_with(Report::default);
        change(report);
        report.at = now_unix();
        if report.started_at == 0 {
            // `CURRENT` starts empty in every process, so the first write is
            // this relay's start.
            report.started_at = report.at;
        }
        report.clone()
    };
    // Outside the lock. Nothing here calls back into this module, but a file
    // write held under a lock the warm pass wants is the shape I50 is about,
    // and keeping it out costs nothing.
    let Some(path) = path() else { return };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let Ok(json) = serde_json::to_string(&snapshot) else {
        return;
    };
    // Temp then rename, the pattern `patch_binary::write_atomic` already sets.
    // `fs::write` truncates first, and the window reads this file every three
    // seconds: a read landing inside that window gets an empty file, fails to
    // parse, and is indistinguishable from "the relay is not reporting" - so a
    // one-in-a-hundred-thousand read would put a wrong sentence on screen. A
    // rename is atomic on both platforms and costs nothing at this size.
    // One temp name per write: the warm pass and a listener thread
    // (`set_blocker`) can both be here at once, and two writers sharing one temp
    // file could rename the other's half-written copy into place.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{seq}.tmp"));
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, json).is_ok() && std::fs::rename(&tmp, &path).is_err() {
        std::fs::remove_file(&tmp).ok();
    }
}

#[cfg(windows)]
fn update(change: impl FnOnce(&mut Report)) {
    let result = with_runtime_metadata_source(|source, check| {
        let target = path().ok_or("gate report path unavailable")?;
        with_windows_writer(|state| state.write_gate_metadata(&target, source, check, change))
    });
    if let Err(error) = result {
        eprintln!("gate report persistence failed: {error}");
        crate::dns_forwarder::log_gate_failure(&error);
    }
}

/// What the relay is doing now, as one warm pass sees it.
pub struct Now<'a> {
    pub route: Option<&'a str>,
    pub forced_for: Option<Duration>,
    pub stood_down: bool,
    pub loopback: bool,
    pub tunnel: Option<bool>,
    pub vpn_exit: &'a str,
    pub routes: Vec<crate::routes::Row>,
}

/// Called once per warm pass with what the relay is doing now.
pub fn publish(now: Now<'_>) {
    update(|r| {
        if let Some(route) = now.route {
            r.route = route.to_string();
        }
        r.forced_until = now.forced_for.map_or(0, |left| now_unix() + left.as_secs());
        r.stood_down = now.stood_down;
        r.loopback = now.loopback;
        r.tunnel = now.tunnel;
        r.vpn_exit = now.vpn_exit.to_string();
        r.routes = now.routes;
        r.version = crate::dns_forwarder::RELAY_VERSION;
        r.reached_at = crate::net::last_reached();
        if r.exe.is_empty() {
            r.exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
        }
    });
}

/// Writes the record the moment the relay starts, before anything it does has
/// had time to succeed or fail.
///
/// The window decides whether the relay is alive from this file's age: the
/// watchdog is a separate process of the same image name, so the task list
/// cannot tell the two apart (P54). Without a write at start there would be a
/// window after every install where a perfectly live relay has published
/// nothing yet and would read as dead.
pub fn note_started() {
    update(|_| {});
}

/// Records what keeps `what` (`dns`, `door` or `proxy`) from binding, or clears
/// it.
/// Written through at once rather than at the next warm pass.
pub fn set_blocker(what: &str, blocker: Option<Blocker>) {
    update(|r| {
        r.blockers.retain(|b| b.what != what);
        r.blockers.extend(blocker);
        // The exception the window may have to ask for names this file, and a
        // bind fails before the first warm pass would have written it.
        if r.exe.is_empty() {
            r.exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
        }
    });
}

/// Called when a refusal has been answered, with what was done about it.
pub fn record_episode(count: u32, acted: String, route: Option<&str>) {
    update(|r| {
        r.last_400 = Some(Episode {
            at: now_unix(),
            count,
            acted,
            route: route.unwrap_or_default().to_string(),
            bypassed: route.is_none(),
        })
    });
}

/// Called when a model answer shows up in a client log.
pub fn record_answer(route: Option<&str>) {
    update(|r| {
        r.last_ok = Some(Proof {
            at: now_unix(),
            route: route.unwrap_or_default().to_string(),
        })
    });
}

// ---------------------------------------------------------------------------
// The window's side
// ---------------------------------------------------------------------------

/// How far back a refusal still counts as "right now" on screen. Long enough to
/// still be there when a user hits the gate, swears, and goes looking for this
/// window; short enough that it is about this session rather than this morning.
pub const RECENT: Duration = Duration::from_secs(10 * 60);

/// How far back a model answer still counts as proof that the bypass works.
/// Longer than `RECENT`: a working setup is quiet between messages, and a user
/// who opens the window after lunch should still see that it worked this
/// morning - on the same network, which is what the relay's context reset
/// (`routes::set_context`) is for when it is not.
pub const ANSWER_RECENT: Duration = Duration::from_secs(12 * 60 * 60);

/// The whole of what the watcher knows.
#[derive(Debug, Clone, Default)]
pub struct View {
    /// The client's own log. `ago` is measured at the moment this was taken —
    /// the window adds its own elapsed time on top rather than being sent a
    /// fresh one every tick.
    pub seen: Option<crate::ls_log::Sighting>,
    /// The newest model answer in the client's log, the same way.
    pub answered: Option<crate::ls_log::Sighting>,
    /// The newest refusal over the same horizon as `answered`. `seen` stops at
    /// `RECENT`, and without this a refusal eleven minutes old that came *after*
    /// the last answer disappeared, and the answer before it turned the card
    /// green again - a claim about a route that was last seen failing.
    pub refused_long: Option<crate::ls_log::Sighting>,
    /// Google asking the account to verify itself, with the page to do it on.
    pub verify: Option<crate::ls_log::Verification>,
    /// Google out of capacity for the chosen model (503), inside `RECENT`.
    pub overloaded: Option<crate::ls_log::Overload>,
    /// The account's credentials refused (401), inside `RECENT`.
    pub unauthorized: Option<crate::ls_log::Sighting>,
    /// Google-side failures (503/429/500) over the answers' horizon, for the report.
    pub server_errors: Option<crate::ls_log::Sighting>,
    /// The relay's record, or `None` when there is none or it has gone stale.
    pub relay: Option<Report>,
    /// Whether this window reaches the internet, asked only while the relay is
    /// cut off: the difference between "no internet" and "something on this
    /// machine blocks the relay alone" (P53). `None` = not asked.
    pub net_ok: Option<bool>,
}

/// Watcher → window.
pub enum Signal {
    Gate(View),
    /// "Ask the system again where the client's traffic leaves." Sent rather
    /// than measured here on purpose: `ops` owns that measurement, and the row
    /// it colours must not be able to disagree with the decision the DNS layer
    /// made from the same call.
    MeasureVpn,
}

/// How often the two files are looked at. Both reads are a `metadata` and a
/// bounded tail; the expensive measurement is rate-limited separately below.
const TICK: Duration = Duration::from_secs(3);

/// A refusal this new is one the user is living through right now, and worth
/// re-measuring the tunnel for at once — "is Antigravity inside your VPN" is
/// the first question a fresh 400 raises.
const FRESH: Duration = Duration::from_secs(90);

/// Floors and ceiling for the VPN measurement, which spawns PowerShell and is
/// therefore never put on a plain timer.
///
/// What gates it is the client's own log growing: the question is where
/// *Antigravity's* traffic leaves, which means nothing while Antigravity is not
/// running — and a language server that is running writes as it serves. So an
/// idle machine costs one measurement every `GAP_IDLE`, a working one at most
/// one every `GAP_BUSY`, and a fresh refusal jumps the queue.
const GAP_AFTER_400: Duration = Duration::from_secs(15);
const GAP_BUSY: Duration = Duration::from_secs(45);
const GAP_IDLE: Duration = Duration::from_secs(5 * 60);

/// How often the list of log files is rebuilt. Antigravity can be installed,
/// started or updated while this window is open, and each of those changes the
/// list — but none of them happens on a three-second scale.
const RELIST_EVERY: Duration = Duration::from_secs(60);

/// How often the window re-asks whether it reaches the internet, while the
/// relay stays cut off.
const NET_PROBE_EVERY: Duration = Duration::from_secs(2 * 60);

/// How long the relay must look cut off, to this window, before it asks.
const CUT_OFF_CONFIRM: Duration = Duration::from_secs(60);

/// Whether this process can open a connection to the internet at all: the
/// HTTPS port of three public resolvers, Yandex's first because it answers from
/// inside Russia whatever else is filtered. Plain TCP, no data - the question is
/// only whether a socket of *this* program gets out.
fn reaches_internet() -> bool {
    const TARGETS: [[u8; 4]; 3] = [[77, 88, 8, 8], [8, 8, 8, 8], [1, 1, 1, 1]];
    TARGETS.iter().any(|ip| {
        std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from((*ip, 443)),
            Duration::from_secs(3),
        )
        .is_ok()
    })
}

pub fn spawn_watch(tx: Sender<Signal>, wake: Box<dyn Fn() + Send>) {
    std::thread::Builder::new()
        .name("gate".to_string())
        .spawn(move || watch(tx, wake))
        .ok();
}

fn watch(tx: Sender<Signal>, wake: Box<dyn Fn() + Send>) {
    let mut shown = View::default();
    // The file list is walked, not watched: `%APPDATA%` and then the IDE's
    // per-launch `logs` folders. Once a minute, never on the tick.
    let mut logs = crate::ls_log::candidate_logs();
    let mut listed = Instant::now();
    let mut bytes = crate::ls_log::bytes_of(&logs);
    // The last real scan and when it was taken, so an age can be carried
    // forward without reading the file again.
    let mut found: Option<(crate::ls_log::Sighting, Instant)> = None;
    let mut answered: Option<(crate::ls_log::Sighting, Instant)> = None;
    let mut refused_long: Option<(crate::ls_log::Sighting, Instant)> = None;
    let mut verify: Option<(crate::ls_log::Verification, Instant)> = None;
    let mut overloaded: Option<(crate::ls_log::Overload, Instant)> = None;
    let mut server_errors: Option<(crate::ls_log::Sighting, Instant)> = None;
    let mut unauthorized: Option<(crate::ls_log::Sighting, Instant)> = None;
    // The first tick scans whatever is already there: a user who hits the gate
    // and *then* opens this window is the case this whole path exists for.
    let mut scan = true;
    // `ops` takes a VPN measurement on its first snapshot, so the clock starts
    // now rather than at zero.
    let mut measured = Instant::now();
    // This window's own reach, taken while the relay looks cut off, and since
    // when it has looked so.
    let mut net_ok: Option<(bool, Instant)> = None;
    let mut cut_since: Option<Instant> = None;

    loop {
        std::thread::sleep(TICK);

        if listed.elapsed() >= RELIST_EVERY {
            logs = crate::ls_log::candidate_logs();
            listed = Instant::now();
        }
        // A log that has not grown cannot have gained a refusal, so the tail is
        // only read when it has. Idle, this whole tick is one `metadata` per
        // file; the alternative was scanning a quarter-megabyte of glog every
        // three seconds for the lifetime of the window.
        let grew = {
            let now = crate::ls_log::bytes_of(&logs);
            let grew = now != bytes;
            bytes = now;
            grew
        };
        if grew || scan {
            scan = false;
            // A scan that finds nothing does not disprove what the last one
            // found. The tail read is bounded (`HISTORY_TAIL`), so a client
            // writing hard can push a refusal that is still inside `RECENT` out
            // of the bytes we look at - and flipping from "поймана" to "не
            // встречалась" on that is a positive claim about the part of the
            // file nobody read. Only time retires a sighting, below.
            let h = crate::ls_log::history(&logs, RECENT, ANSWER_RECENT);
            let at = Instant::now();
            found = h.refused_recent.map(|s| (s, at)).or(found);
            answered = h.answered.map(|s| (s, at)).or(answered);
            refused_long = h.refused.map(|s| (s, at)).or(refused_long);
            verify = h.verify.map(|v| (v, at)).or(verify);
            overloaded = h.overloaded.map(|o| (o, at)).or(overloaded);
            unauthorized = h.unauthorized.map(|s| (s, at)).or(unauthorized);
            server_errors = h.server_errors.map(|s| (s, at)).or(server_errors);
        }

        let view = View {
            // Carried forward rather than re-read. `count` is as of the last
            // scan, which is exact whenever anything is happening — a client
            // that is hitting the gate is a client writing to its log — and at
            // worst counts one that has just aged out while it sits silent.
            seen: found.and_then(|(s, at)| {
                let ago = s.ago + at.elapsed();
                (ago <= RECENT).then_some(crate::ls_log::Sighting { ago, ..s })
            }),
            answered: answered.and_then(|(s, at)| {
                let ago = s.ago + at.elapsed();
                (ago <= ANSWER_RECENT).then_some(crate::ls_log::Sighting { ago, ..s })
            }),
            refused_long: refused_long.and_then(|(s, at)| {
                let ago = s.ago + at.elapsed();
                (ago <= ANSWER_RECENT).then_some(crate::ls_log::Sighting { ago, ..s })
            }),
            verify: verify.as_ref().and_then(|(v, at)| {
                let ago = v.ago + at.elapsed();
                (ago <= ANSWER_RECENT).then(|| crate::ls_log::Verification {
                    ago,
                    url: v.url.clone(),
                })
            }),
            overloaded: overloaded.as_ref().and_then(|(o, at)| {
                let ago = o.ago + at.elapsed();
                (ago <= RECENT).then(|| crate::ls_log::Overload { ago, ..o.clone() })
            }),
            unauthorized: unauthorized.and_then(|(s, at)| {
                let ago = s.ago + at.elapsed();
                (ago <= RECENT).then_some(crate::ls_log::Sighting { ago, ..s })
            }),
            server_errors: server_errors.and_then(|(s, at)| {
                let ago = s.ago + at.elapsed();
                (ago <= ANSWER_RECENT).then_some(crate::ls_log::Sighting { ago, ..s })
            }),
            relay: read().filter(|r| !r.is_stale()),
            net_ok: None,
        };
        let mut view = view;
        if view.relay.as_ref().is_some_and(Report::cut_off) {
            // A minute of it first: a machine back from sleep reads as cut off
            // until the relay's first answer lands a few seconds later, and a
            // card about the antivirus for that would be a false alarm.
            let since = *cut_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= CUT_OFF_CONFIRM
                && net_ok.is_none_or(|(_, at)| at.elapsed() >= NET_PROBE_EVERY)
            {
                net_ok = Some((reaches_internet(), Instant::now()));
            }
            view.net_ok = net_ok.map(|(ok, _)| ok);
        } else {
            cut_since = None;
            net_ok = None;
        }
        let worth = worth_sending(&view, &shown);
        let fresh = view.seen.is_some_and(|s| s.ago <= FRESH);

        let gap = if worth && fresh {
            GAP_AFTER_400
        } else if grew {
            GAP_BUSY
        } else {
            GAP_IDLE
        };
        if measured.elapsed() >= gap {
            measured = Instant::now();
            if tx.send(Signal::MeasureVpn).is_err() {
                return;
            }
            wake();
        }

        if worth {
            shown = view.clone();
            if tx.send(Signal::Gate(view)).is_err() {
                return;
            }
            wake();
        }
    }
}

/// Whether the window is looking at something other than what it is showing.
///
/// `ago` grows by a tick every tick, so comparing it outright would wake the UI
/// three times a minute for ever. What matters is a refusal *newer* than the one
/// on screen, or a different number of them — the window ages its own copy in
/// between.
fn worth_sending(fresh: &View, shown: &View) -> bool {
    let relay_changed = match (&fresh.relay, &shown.relay) {
        (Some(a), Some(b)) => !a.same_state_as(b),
        (None, None) => false,
        _ => true,
    };
    if relay_changed || fresh.net_ok != shown.net_ok {
        return true;
    }
    let newer = |a: Option<crate::ls_log::Sighting>, b: Option<crate::ls_log::Sighting>| match (a, b) {
        (Some(a), Some(b)) => a.count != b.count || a.ago < b.ago,
        (a, b) => a.is_some() != b.is_some(),
    };
    let verify_changed = match (&fresh.verify, &shown.verify) {
        (Some(a), Some(b)) => a.url != b.url || a.ago < b.ago,
        (a, b) => a.is_some() != b.is_some(),
    };
    let overload_changed = match (&fresh.overloaded, &shown.overloaded) {
        (Some(a), Some(b)) => a.count != b.count || a.ago < b.ago || a.model != b.model,
        (a, b) => a.is_some() != b.is_some(),
    };
    newer(fresh.seen, shown.seen)
        || newer(fresh.answered, shown.answered)
        || newer(fresh.refused_long, shown.refused_long)
        || newer(fresh.unauthorized, shown.unauthorized)
        || verify_changed
        || overload_changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_observation_codec_preserves_unknown() {
        for (json, expected) in [(r#"{"tunnel":true}"#, Some(true)), (r#"{"tunnel":false}"#, Some(false)),
            (r#"{}"#, None), (r#"{"tunnel":null}"#, None)] {
            let report: Report = serde_json::from_str(json).unwrap();
            assert_eq!(report.tunnel, expected);
            let value = serde_json::to_value(report).unwrap();
            if expected.is_none() { assert!(value.get("tunnel").is_none()); }
        }
        assert!(serde_json::from_str::<Report>(r#"{"tunnel":"false"}"#).is_err());
        assert!(serde_json::from_str::<Report>(r#"{"tunnel":{}}"#).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn old_mac_boolean_is_not_a_current_measurement() {
        let report = checked_report(Ok(r#"{"tunnel":false,"vpn_exit":"old"}"#.into())).unwrap().unwrap();
        assert_eq!(report.tunnel, None);
        assert!(report.vpn_exit.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn transport_producer_binding_rejects_instance_or_configuration_change() {
        let report = TransportReport { schema: 1, instance: TransportInstance { pid: 7, creation_time: 11 },
            active_config: crate::settings::ActiveTransportConfig { profile: crate::settings::TransportProfile::SystemTcp,
                dns: false, tcp_proxy: true, client_proxy: true, dns_alias: false },
            observed: TransportCapabilities { dns: CapabilityObservation::Disabled, tcp_proxy: CapabilityObservation::Starting,
                dns_alias: CapabilityObservation::Disabled } };
        assert!(transport_config_matches(&report, &report));
        let mut changed = report.clone();
        changed.instance.creation_time += 1;
        assert!(!transport_config_matches(&report, &changed));
        let mut changed = report.clone();
        changed.instance.pid += 1;
        assert!(!transport_config_matches(&report, &changed));
        let mut changed = report.clone();
        changed.active_config.tcp_proxy = false;
        assert!(!transport_config_matches(&report, &changed));
        let mut configured = report.clone();
        configured.active_config.profile = crate::settings::TransportProfile::ExistingConfigured;
        configured.active_config.client_proxy = false;
        assert!(configured.validate().is_ok());
        let mut client_on = configured.clone();
        client_on.active_config.client_proxy = true;
        assert!(client_on.validate().is_ok());
        assert!(!transport_config_matches(&configured, &client_on));
    }

    #[cfg(windows)]
    #[test]
    fn transport_report_wire_requires_complete_nonzero_identity() {
        let old: Report = serde_json::from_str(r#"{"version":7}"#).unwrap();
        assert!(matches!(old.transport, TransportObservation::Absent));
        let json = r#"{"version":7,"route":"synthetic","transport":{"schema":1,"instance":{"pid":4242,"creation_time":18446744073709551615},"active_config":{"profile":"system_tcp","dns":false,"tcp_proxy":true,"client_proxy":true,"dns_alias":false},"observed":{"dns":"disabled","tcp_proxy":"ready","dns_alias":"disabled"}}}"#;
        let report: Report = serde_json::from_str(json).unwrap();
        let TransportObservation::Valid(ref observed) = report.transport else { panic!("valid wire rejected") };
        assert_eq!(observed.instance.creation_time, u64::MAX);
        let roundtrip: Report = serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(matches!(roundtrip.transport, TransportObservation::Valid(ref item) if item.instance.creation_time == u64::MAX));
        for mutate in ["pid", "creation_time", "schema", "active_config", "observed"] {
            let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
            match mutate {
                "pid" | "creation_time" => value["transport"]["instance"][mutate] = 0.into(),
                _ => { value["transport"].as_object_mut().unwrap().remove(mutate); }
            }
            let decoded: Report = serde_json::from_value(value).unwrap();
            assert!(matches!(decoded.transport, TransportObservation::Invalid(_)), "{mutate}");
            assert_eq!(decoded.version, 7);
            assert_eq!(decoded.route, "synthetic");
            let again: Report = serde_json::from_slice(&serde_json::to_vec(&decoded).unwrap()).unwrap();
            assert!(matches!(again.transport, TransportObservation::Invalid(_)));
            assert_eq!(again.version, 7);
            assert_eq!(again.route, "synthetic");
        }
        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["transport"]["active_config"]["dns"] = true.into();
        let decoded: Report = serde_json::from_value(value).unwrap();
        assert!(matches!(decoded.transport, TransportObservation::Invalid(_)));
        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["transport"]["active_config"].as_object_mut().unwrap().remove("client_proxy");
        let decoded: Report = serde_json::from_value(value).unwrap();
        assert!(matches!(decoded.transport, TransportObservation::Invalid(_)));
        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["transport"]["active_config"]["profile"] = "existing_configured".into();
        value["transport"]["active_config"]["dns"] = true.into();
        value["transport"]["active_config"]["client_proxy"] = false.into();
        let decoded: Report = serde_json::from_value(value).unwrap();
        assert!(matches!(decoded.transport, TransportObservation::Valid(_)), "DNS/route on with client off is valid");
    }

    #[cfg(windows)]
    fn runtime_gate_fixture() -> (PathBuf, crate::windows_coordinator::windows_installation::CheckedPath,
        crate::windows_coordinator::windows_installation::NativeObjectId) {
        use crate::windows_coordinator::windows_installation as owner;
        let parent = PathBuf::from(std::env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT").expect("explicit qualified private fixture parent"));
        let root = owner::context_fixture_directory(&parent).unwrap();
        let program_path = root.join("runtime-program.bin");
        owner::write_deployment_data(&program_path, b"owned private Gate runtime program").unwrap();
        let program = owner::CheckedPath::open(&program_path, owner::PathKind::File, owner::PathPurpose::Executable).unwrap();
        let target = root.join(FILE_NAME);
        owner::write_deployment_data(&target, &serde_json::to_vec(&Report::default()).unwrap()).unwrap();
        let original = owner::CheckedPath::open(&target, owner::PathKind::File, owner::PathPurpose::Review).unwrap().native_id();
        (root, program, original)
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit qualified private fixture parent; real Gate publication/receiving, no runtime globals or installed state"]
    fn runtime_gate_natural_write_receives_pending_without_replaying_old_rename() {
        use crate::windows_coordinator::windows_installation as owner;
        let (root, program, original) = runtime_gate_fixture();
        let target = root.join(FILE_NAME);
        let source = checked_runtime_metadata_source(&program).unwrap();
        let check = || checked_runtime_metadata_source(&program);
        let mut state = WindowsWriterState::default();
        owner::test_reset_metadata_rename_trace();
        owner::fail_next_metadata_post_publish();
        let failure = state.write_gate_metadata(&target, &source, &check, |report| {
            report.route = "first owned Gate update".into();
            report.loopback = true;
        }).unwrap_err();
        assert_eq!(state.pending.len(), 1);
        assert!(state.pending[0].source == source);
        let retained_failure = state.report.persistence_hold.clone().expect("real post-publication failure is retained");
        assert!(failure.contains(&retained_failure));
        let actual: serde_json::Value = serde_json::from_str(retained_failure.split_once("; actual=").unwrap().1).unwrap();
        assert_eq!(actual["oldMoved"], true);
        assert_eq!(actual["newPublished"], true);
        assert_eq!(actual["oldRenameResult"], true);
        assert_eq!(actual["stageRenameResult"], true);
        assert!(actual["rollbackRenameResult"].is_null());
        assert_eq!(owner::test_metadata_rename_count(&original), 1);
        let first_published = state.pending[0].receipt.test_held_stage_id().unwrap();
        assert_eq!(owner::test_metadata_rename_count(&first_published), 1);

        // This is the same Gate entry used by production update: common prepare,
        // source comparison, pending receiving/release, serialization and write.
        state.write_gate_metadata(&target, &source, &check, |report| report.route = "second owned Gate update".into()).unwrap();
        assert!(state.pending.is_empty() && state.live_resources.is_empty());
        assert!(state.report.persistence_hold.is_none());
        assert_eq!(owner::test_metadata_rename_count(&original), 1, "old A must not be renamed again during receipt");
        assert_eq!(owner::test_metadata_rename_count(&first_published), 2, "new operation may retire B after its first publication");
        let final_pin = owner::CheckedPath::open(&target, owner::PathKind::File, owner::PathPurpose::Review).unwrap();
        assert!(final_pin.native_id() != first_published);
        assert_eq!(owner::test_metadata_rename_count(&final_pin.native_id()), 1);
        let report: Report = serde_json::from_slice(&owner::read_protected_user_metadata(&target).unwrap().unwrap()).unwrap();
        assert_eq!(report.route, "second owned Gate update");
        assert!(report.loopback);
        assert!(matches!(report.installed_generation, InstalledGenerationObservation::Valid(binding)
            if binding.program_native_id == source.program && binding.program_sha256 == source.sha256));
        eprintln!("owned Gate natural re-entry root={}; original failure retained: {retained_failure}", root.display());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit qualified private fixture parent; real changed checked source, no runtime globals or installed state"]
    fn runtime_gate_changed_checked_program_holds_pending_without_native_moves() {
        use crate::windows_coordinator::windows_installation as owner;
        let (root, program, original) = runtime_gate_fixture();
        let target = root.join(FILE_NAME);
        let source = checked_runtime_metadata_source(&program).unwrap();
        let check = || checked_runtime_metadata_source(&program);
        let mut state = WindowsWriterState::default();
        owner::test_reset_metadata_rename_trace();
        owner::fail_next_metadata_post_publish();
        state.write_gate_metadata(&target, &source, &check, |report| report.route = "owned pending Gate update".into()).unwrap_err();
        let retained_failure = state.report.persistence_hold.clone().unwrap();
        let before = std::fs::read(&target).unwrap();
        let published = state.pending[0].receipt.test_held_stage_id().unwrap();
        let old_moves = owner::test_metadata_rename_count(&original);
        let published_moves = owner::test_metadata_rename_count(&published);

        let changed_path = root.join("different-runtime-program.bin");
        owner::write_deployment_data(&changed_path, b"a different actual checked runtime program").unwrap();
        let changed = owner::CheckedPath::open(&changed_path, owner::PathKind::File, owner::PathPurpose::Executable).unwrap();
        let changed_source = checked_runtime_metadata_source(&changed).unwrap();
        assert!(source != changed_source);
        let changed_check = || checked_runtime_metadata_source(&changed);
        let held = state.write_gate_metadata(&target, &changed_source, &changed_check,
            |_| panic!("a source conflict must not invoke the report change")).unwrap_err();
        assert!(held.contains("pending metadata source differs from current protected program"));
        assert_eq!(state.pending.len(), 1);
        assert!(state.pending[0].source == source);
        assert_eq!(state.report.persistence_hold.as_deref(), Some(retained_failure.as_str()));
        assert_eq!(std::fs::read(&target).unwrap(), before);
        assert_eq!(owner::test_metadata_rename_count(&original), old_moves);
        assert_eq!(owner::test_metadata_rename_count(&published), published_moves);
        assert_eq!(owner::test_metadata_rename_count(&changed_source.program), 0);

        // Restore the fixture's actually retained original checked source, then
        // settle through the same natural Gate call, never by extracting a receipt.
        state.write_gate_metadata(&target, &source, &check, |report| report.route = "original checked source restored".into()).unwrap();
        assert!(state.pending.is_empty() && state.live_resources.is_empty());
        assert_eq!(owner::test_metadata_rename_count(&original), old_moves);
        eprintln!("owned Gate source-hold root={}; held={held}; original failure={retained_failure}", root.display());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "owned private fixture; Gate old cleanup failure after published receiving"]
    fn runtime_gate_cleanup_failure_does_not_hold_received_publication() {
        use crate::windows_coordinator::windows_installation as owner;
        let (root, program, _) = runtime_gate_fixture();
        let target = root.join(FILE_NAME);
        let source = checked_runtime_metadata_source(&program).unwrap();
        let check = || checked_runtime_metadata_source(&program);
        let mut state = WindowsWriterState::default();
        owner::test_change_old_during_metadata_settlement();
        let error = state.write_gate_metadata(&target, &source, &check, |_| {}).unwrap_err();
        assert!(error.contains("displaced preimage changed"));
        assert!(state.pending.is_empty());
        assert!(!state.live_resources.is_empty());
        assert!(owner::read_protected_user_metadata(&target).unwrap().is_some());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "owned private fixture; normal Gate settlement mismatch handoff"]
    fn runtime_gate_settlement_mismatch_retains_accepted_publication() {
        use crate::windows_coordinator::windows_installation as owner;
        let (root, program, original) = runtime_gate_fixture();
        let target = root.join(FILE_NAME);
        let source = checked_runtime_metadata_source(&program).unwrap();
        let check = || checked_runtime_metadata_source(&program);
        let mut state = WindowsWriterState::default();
        owner::test_reset_metadata_rename_trace();
        owner::test_change_creation_during_metadata_settlement();
        let error = state.write_gate_metadata(&target, &source, &check, |_| {}).unwrap_err();
        assert!(error.contains("published metadata changed before settlement"));
        assert_eq!(state.pending.len(), 1);
        assert!(state.pending[0].source == source);
        let pending = &mut state.pending[0].receipt;
        assert!(pending.test_accepted_transition_retained());
        assert!(pending.test_stage_creation_differs_from_expected().unwrap());
        let stage = pending.test_held_stage_id().unwrap();
        let old_moves = owner::test_metadata_rename_count(&original);
        let stage_moves = owner::test_metadata_rename_count(&stage);
        assert!(state.write_gate_metadata(&target, &source, &check, |_| panic!("changed snapshot must hold")).is_err());
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.pending[0].receipt.test_held_stage_id().unwrap(), stage);
        assert_eq!(owner::test_metadata_rename_count(&original), old_moves);
        assert_eq!(owner::test_metadata_rename_count(&stage), stage_moves);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit qualified private fixture parent; changed incomplete stage must remain held"]
    fn runtime_gate_does_not_replay_changed_incompletely_received_stage() {
        use crate::windows_coordinator::windows_installation as owner;
        let (root, program, original) = runtime_gate_fixture();
        let target = root.join(FILE_NAME);
        let source = checked_runtime_metadata_source(&program).unwrap();
        let check = || checked_runtime_metadata_source(&program);
        let mut state = WindowsWriterState::default();
        owner::test_reset_metadata_rename_trace();
        owner::fail_metadata_rename_readback_after(2);
        owner::change_creation_before_failed_metadata_rename_receiving();
        state.write_gate_metadata(&target, &source, &check, |_| {}).unwrap_err();
        assert_eq!(state.pending.len(), 1);
        assert!(state.pending[0].receipt.test_stage_creation_differs_from_expected().unwrap());
        let stage = state.pending[0].receipt.test_held_stage_id().unwrap();
        let old_moves = owner::test_metadata_rename_count(&original);
        let stage_moves = owner::test_metadata_rename_count(&stage);
        let held = state.write_gate_metadata(&target, &source, &check, |_| panic!("unreceived transition must hold")).unwrap_err();
        assert!(held.contains("canonical metadata differs"));
        assert_eq!(state.pending.len(), 1);
        assert_eq!(owner::test_metadata_rename_count(&original), old_moves);
        assert_eq!(owner::test_metadata_rename_count(&stage), stage_moves);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit qualified private fixture parent; authentic observer and differing pending expectation"]
    fn authentic_observation_does_not_resolve_different_pending_snapshot() {
        use crate::windows_coordinator::windows_installation as owner;
        let (root, program, original) = runtime_gate_fixture();
        let target = root.join(FILE_NAME);
        let source = checked_runtime_metadata_source(&program).unwrap();
        let check = || checked_runtime_metadata_source(&program);
        let mut state = WindowsWriterState::default();
        owner::test_reset_metadata_rename_trace();
        owner::fail_next_metadata_post_publish();
        let first = state.write_gate_metadata(&target, &source, &check, |report| report.route = "fixture".into()).unwrap_err();
        let stage = state.pending[0].receipt.test_held_stage_id().unwrap();
        state.pending[0].receipt.test_invalidate_produced_snapshot();
        assert!(matches!(receive_fixture_generation(&target, &program), BoundGeneration::Bound(value) if value == crate::dns_forwarder::RELAY_VERSION));
        let old_moves = owner::test_metadata_rename_count(&original);
        let stage_moves = owner::test_metadata_rename_count(&stage);
        let held = state.write_gate_metadata(&target, &source, &check, |_| panic!("pending mismatch must hold")).unwrap_err();
        assert!(held.contains("canonical metadata differs"), "actual held cause: {held}");
        assert_eq!(state.pending.len(), 1);
        assert!(state.report.persistence_hold.as_ref().is_some_and(|cause| first.contains(cause)));
        assert_eq!(owner::test_metadata_rename_count(&original), old_moves);
        assert_eq!(owner::test_metadata_rename_count(&stage), stage_moves);
        eprintln!("owned authentic-observation/pending-mismatch fixture root={}; actual held={held}", root.display());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit qualified private fixture parent; real Gate foreign occupant, no runtime globals or installed state"]
    fn runtime_gate_foreign_canonical_holds_pending_without_native_moves() {
        use crate::windows_coordinator::windows_installation as owner;
        let (root, program, original) = runtime_gate_fixture();
        let target = root.join(FILE_NAME);
        let source = checked_runtime_metadata_source(&program).unwrap();
        let check = || checked_runtime_metadata_source(&program);
        let mut state = WindowsWriterState::default();
        owner::test_reset_metadata_rename_trace();
        owner::occupy_next_metadata_vacancy();
        let first = state.write_gate_metadata(&target, &source, &check, |report| report.route = "owned foreign fixture".into()).unwrap_err();
        assert!(first.contains("os error 183"));
        assert_eq!(state.pending.len(), 1);
        let stage = state.pending[0].receipt.test_held_stage_id().unwrap();
        let foreign = owner::CheckedPath::open(&target, owner::PathKind::File, owner::PathPurpose::Review).unwrap().native_id();
        let before = std::fs::read(&target).unwrap();
        assert_eq!(before, b"independent synthetic occupant");
        let old_moves = owner::test_metadata_rename_count(&original);
        let stage_moves = owner::test_metadata_rename_count(&stage);
        let foreign_moves = owner::test_metadata_rename_count(&foreign);
        let held = state.write_gate_metadata(&target, &source, &check,
            |_| panic!("foreign canonical occupancy must not invoke report change")).unwrap_err();
        assert!(held.contains("pending metadata restoration remains owed"));
        assert_eq!(state.pending.len(), 1);
        assert_eq!(std::fs::read(&target).unwrap(), before);
        assert_eq!(owner::CheckedPath::open(&target, owner::PathKind::File, owner::PathPurpose::Review).unwrap().native_id(), foreign);
        assert_eq!(owner::test_metadata_rename_count(&original), old_moves);
        assert_eq!(owner::test_metadata_rename_count(&stage), stage_moves);
        assert_eq!(owner::test_metadata_rename_count(&foreign), foreign_moves);
        eprintln!("owned Gate foreign occupancy root={}; initial={first}; next={held}", root.display());
    }

    #[cfg(windows)]
    #[test]
    fn optional_installed_generation_keeps_old_report_codec_compatible() {
        let old: Report = serde_json::from_str(r#"{"version":7}"#).unwrap();
        assert!(matches!(old.installed_generation, InstalledGenerationObservation::Absent));
        let binding = InstalledGeneration { schema: 1, generation: 7,
            program_native_id: crate::windows_coordinator::windows_installation::NativeObjectId { volume: 0, file: [0; 16] },
            program_sha256: "0".repeat(64) };
        let report = Report { version: 7, installed_generation: InstalledGenerationObservation::Valid(binding), ..Report::default() };
        let encoded = serde_json::to_string(&report).unwrap();
        eprintln!("synthetic report sample: {encoded}");
        let decoded: Report = serde_json::from_str(&encoded).unwrap();
        assert!(matches!(decoded.installed_generation, InstalledGenerationObservation::Valid(value) if value.generation == 7));
        #[derive(Deserialize)]
        struct OldReport { version: u32 }
        assert_eq!(serde_json::from_str::<OldReport>(&encoded).unwrap().version, 7);
        let mut malformed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        malformed["installed_generation"]["extra"] = true.into();
        let decoded: Report = serde_json::from_value(malformed).unwrap();
        assert_eq!(decoded.version, 7);
        assert!(matches!(&decoded.installed_generation, InstalledGenerationObservation::Invalid(cause) if !cause.is_empty()));
        assert!(serde_json::to_string(&decoded).is_err());
    }
    use crate::ls_log::Sighting;

    #[test]
    fn checked_report_distinguishes_missing_invalid_and_io_failure() {
        let encoded = serde_json::to_string(&Report::default()).unwrap();
        assert!(checked_report(Ok(encoded)).unwrap().is_some());
        assert!(checked_report(Err(std::io::ErrorKind::NotFound.into())).unwrap().is_none());
        assert!(checked_report(Err(std::io::ErrorKind::PermissionDenied.into())).is_err());
        assert!(checked_report(Ok(String::new())).is_err());
        assert!(checked_report(Ok("{".into())).is_err());
    }

    fn seen(ago: u64, count: usize) -> Option<Sighting> {
        Some(Sighting {
            ago: Duration::from_secs(ago),
            count,
        })
    }

    /// The tick must not wake the window just because time passed: the only
    /// news is a newer refusal, a different count, or one appearing/expiring.
    #[test]
    fn only_a_change_is_worth_waking_the_window_for() {
        let shown = View {
            seen: seen(120, 2),
            answered: None,
            refused_long: None,
            verify: None,
            overloaded: None,
            server_errors: None,
            unauthorized: None,
            relay: None,
            net_ok: None,
        };
        let older = View {
            seen: seen(123, 2),
            ..shown.clone()
        };
        assert!(
            !worth_sending(&older, &shown),
            "the same refusal, three seconds on"
        );
        let newer = View {
            seen: seen(4, 3),
            ..shown.clone()
        };
        assert!(worth_sending(&newer, &shown));
        let link = |ago: u64, url: &str| {
            Some(crate::ls_log::Verification {
                ago: Duration::from_secs(ago),
                url: url.to_string(),
            })
        };
        let asked = View {
            verify: link(10, "https://accounts.google.com/a"),
            ..shown.clone()
        };
        assert!(worth_sending(&asked, &shown), "a verification demand appeared");
        let aged = View {
            verify: link(13, "https://accounts.google.com/a"),
            ..shown.clone()
        };
        assert!(!worth_sending(&aged, &asked), "the same demand, three seconds on");
        let again = View {
            verify: link(2, "https://accounts.google.com/b"),
            ..shown.clone()
        };
        assert!(worth_sending(&again, &asked), "a fresh link");
        let expired = View {
            seen: None,
            ..shown.clone()
        };
        assert!(worth_sending(&expired, &shown));
        assert!(worth_sending(&shown, &expired));
        // A model answer appearing is news too - it is what turns the card green.
        let proved = View {
            answered: seen(5, 1),
            ..shown.clone()
        };
        assert!(worth_sending(&proved, &shown));
        assert!(!worth_sending(
            &View {
                answered: seen(8, 1),
                ..proved.clone()
            },
            &proved
        ));
    }

    /// `at` moves every warm pass and draws nothing, so it must not count as a
    /// change; everything the window prints must.
    #[test]
    fn the_relays_record_counts_as_changed_only_where_it_shows() {
        let base = Report {
            at: 1_000,
            route: "напрямую".into(),
            ..Report::default()
        };
        let later = Report {
            at: 1_015,
            ..base.clone()
        };
        assert!(base.same_state_as(&later));
        let rerouted = Report {
            route: "релей".into(),
            ..base.clone()
        };
        assert!(!base.same_state_as(&rerouted));
        let answered = Report {
            last_400: Some(Episode {
                at: 1_010,
                count: 1,
                acted: "маршрут отложен".into(),
                ..Episode::default()
            }),
            ..base.clone()
        };
        assert!(!base.same_state_as(&answered));

        let shown = View {
            seen: None,
            answered: None,
            refused_long: None,
            verify: None,
            overloaded: None,
            server_errors: None,
            unauthorized: None,
            relay: Some(base),
            net_ok: None,
        };
        assert!(!worth_sending(
            &View {
                relay: Some(later),
                ..shown.clone()
            },
            &shown
        ));
        assert!(worth_sending(
            &View {
                relay: Some(answered),
                ..shown.clone()
            },
            &shown
        ));
        // A relay that stopped writing is news: the answer half is gone.
        assert!(worth_sending(
            &View {
                relay: None,
                ..shown.clone()
            },
            &shown
        ));
    }

    /// A record nobody has refreshed for over a minute is not a running relay.
    #[test]
    fn a_record_goes_stale_and_a_future_one_does_not() {
        let fresh = Report {
            at: now_unix(),
            ..Report::default()
        };
        assert!(!fresh.is_stale());
        let old = Report {
            at: now_unix() - STALE_AFTER.as_secs() - 1,
            ..Report::default()
        };
        assert!(old.is_stale());
        // A clock that moved must not be read as a dead relay.
        let ahead = Report {
            at: now_unix() + 30,
            ..Report::default()
        };
        assert!(!ahead.is_stale());
        assert_eq!(ahead.age(), Duration::ZERO);
    }

    #[test]
    fn the_forced_window_counts_down_and_then_stops() {
        let forced = Report {
            forced_until: now_unix() + 600,
            ..Report::default()
        };
        assert!(forced.forced_left().is_some_and(|d| d.as_secs() > 590));
        let over = Report {
            forced_until: now_unix() - 1,
            ..Report::default()
        };
        assert_eq!(over.forced_left(), None);
        assert_eq!(Report::default().forced_left(), None);
    }

    /// A relay nothing answers is cut off only once it has run long enough to
    /// have heard back, and only if it is new enough to say when it did.
    #[test]
    fn a_relay_is_cut_off_only_after_minutes_of_silence() {
        let now = now_unix();
        let long = CUT_OFF_AFTER.as_secs() + 10;
        let r = Report {
            version: 32,
            started_at: now - long,
            reached_at: 0,
            ..Report::default()
        };
        assert!(r.cut_off());
        assert!(!Report { reached_at: now - 5, ..r.clone() }.cut_off());
        assert!(!Report { started_at: now - 30, ..r.clone() }.cut_off());
        assert!(!Report { version: 31, ..r.clone() }.cut_off());
        assert!(!Report { started_at: 0, ..r }.cut_off());
    }
}
