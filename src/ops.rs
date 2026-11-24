//! The switch layer: every capability the window can turn on or off, and the
//! one worker thread that does it.
//!
//! The console build expressed this as numbered menu items, each a script that
//! printed as it went. A switch needs three things a menu item never did: an
//! honest *enable*, an *undo* that is its exact mirror, and a read-only *state*
//! query so the switch can be drawn where the system actually is rather than
//! where the user last left it.
//!
//! ## What is load-bearing here
//!
//! The order of the steps, not the steps. Every sequence below is a documented
//! bug fix and is marked with the invariant it encodes:
//!
//! * **I5** — the relay comes up *before* the NRPT rules, because the rules name
//!   it as the first nameserver.
//! * **I20** — nothing may be re-patching while an unpatch runs, so both
//!   watchdogs stop first and are put back afterwards.
//! * **I39** — the legacy CA comes out *last*, and only once the relay is
//!   current; pulling it from under an old relay kills every gate request.
//! * **I45** — a failed file undo stops later independent file effects, while
//!   the background owner still receives its required service restoration.
//!   Primary and restoration outcomes remain distinct.
//! * **I52/I53/I54** — the proxy variable is written only after the legacy pair
//!   is gone, no foreign proxy exists, the rename landed, and something actually
//!   answers on the port.
//!
//! ## Threading
//!
//! One worker, one queue, for everything that touches the system. Not for
//! tidiness: `setup_dns_nrpt` is remove-then-add with no lock, `enable`/`disable`
//! both drive the same image name, and two patch runs race the same files. A
//! second worker would interleave them into a half-installed state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

use crate::settings::Settings;
use crate::settings::TransportChoice;
use crate::utils::is_admin;
use crate::wsl_api::DesktopDiscovery;
use crate::wsl_controller::DiscoveryOrigin;
use crate::{background, dns, endpoint, patch_binary, proxy, upstream};

/// Everything the UI can flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cap {
    /// Switch 1: the client patch that lifts the account-region block.
    ClientPatch,
    /// Re-applies the patch after Antigravity updates itself.
    Watchdog,
    /// The DNS half of the 400 bypass: local relay + NRPT rules.
    Dns,
    /// Our own CONNECT proxy, named by the private env var the patch installs.
    LocalProxy,
    /// The user's own HTTP proxy.
    OwnProxy,
    /// The built-in permitted-region exits.
    BuiltinExits,
    GroupProxy,
    /// Whether the DNS pool rotates, or only its first enabled member answers.
    DnsRotation,
    // `VpnDetect` is gone (D25): the layer no longer stands down for a tunnel,
    // so there is nothing left for that switch to decide. `settings.vpn_detect`
    // stays in the file so an older build reading it still finds the field.
}

impl Cap {
    pub fn supported(self) -> bool {
        !(cfg!(target_os = "macos") && self == Cap::Dns)
    }

    /// Windows gates the DNS layer behind UAC. Without admin these do not fail —
    /// the cmdlets carry `-ErrorAction SilentlyContinue` — they quietly do
    /// nothing, which is exactly the way a switch ends up lying.
    pub fn needs_admin(self) -> bool {
        cfg!(target_os = "windows") && matches!(self, Cap::Dns | Cap::Watchdog)
    }

    pub fn title(self) -> &'static str {
        match self {
            Cap::ClientPatch => "Разблокировать вход в аккаунт",
            Cap::Watchdog => "Автопатч Antigravity",
            Cap::Dns => "Обход через DNS",
            Cap::LocalProxy => "Локальный прокси",
            Cap::OwnProxy => "Свой HTTP-прокси",
            Cap::BuiltinExits => "Встроенные выходы",
            Cap::GroupProxy => "Прокси из группы",
            Cap::DnsRotation => "Ротация DNS-серверов",
        }
    }
}

/// Where a capability actually is, as opposed to where the user put the switch.
#[derive(Debug, Clone, PartialEq)]
pub enum State {
    On,
    Off,
    /// On, but not the whole way — some installs patched and some not, or rules
    /// present with the relay down.
    Partial(String),
    /// **Off**, with a line saying what being off costs. Draws as an off switch.
    ///
    /// Not a flavour of `Partial`, and the difference is a bug that shipped:
    /// `is_on()` is true for `Partial`, so a switch whose off state was described
    /// with one drew itself back **on** the moment the worker's snapshot landed —
    /// «Сверять TLS» and «Ротация» could not be turned off at all, while the log
    /// said they had been. A note is a note; whether the thing is on is a
    /// separate question and now has a separate variant.
    OffNote(String),
    /// Cannot be turned on right now, and the reason is not the user's mistake:
    /// no admin, a foreign proxy that outranks ours, a VPN the layer stood down
    /// for. Drawn as an off switch with the reason next to it.
    Blocked(String),
}

impl State {
    pub fn is_on(&self) -> bool {
        matches!(self, State::On | State::Partial(_))
    }
    pub fn note(&self) -> Option<&str> {
        match self {
            State::Partial(s) | State::Blocked(s) | State::OffNote(s) => Some(s),
            _ => None,
        }
    }
}

/// One Antigravity *kind*, as the paths list draws it.
///
/// There is a row per kind rather than per found install, and it survives the
/// kind not being installed: an empty row with a pencil is how a user says
/// "it is here, you missed it". A list that only shows what was found gives
/// them nowhere to say it.
#[cfg(any(windows, target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(windows, derive(Copy))]
pub(crate) enum InstallCoverage {
    Complete,
    Incomplete,
    #[cfg(windows)]
    ObservedStandard,
    #[cfg(target_os = "macos")]
    ObservedStandard(PathBuf),
}

#[derive(Debug, Clone)]
pub struct InstallRow {
    /// `None` when this kind was neither found nor pointed at by hand.
    pub path: Option<PathBuf>,
    pub label: &'static str,
    /// Whether inspection found a complete patch. `None` means the patch
    /// status is unconfirmed. Inspection runs off the drawing thread.
    pub patched: Option<bool>,
    /// Added by hand through the pencil, rather than found by the scan.
    pub manual: bool,
    #[cfg(windows)]
    pub(crate) observed_kind: Option<crate::InstallationKind>,
    #[cfg(any(windows, target_os = "macos"))]
    pub(crate) coverage: InstallCoverage,
}

impl InstallRow {
    pub(crate) fn saved_path(&self) -> Option<&Path> {
        if self.manual { self.path.as_deref() } else { None }
    }

    pub(crate) fn display_path(&self) -> Option<&Path> {
        #[cfg(target_os = "macos")]
        if self.coverage != InstallCoverage::Complete { return None; }
        self.path.as_deref()
    }

    pub(crate) fn discovery_note(&self) -> Option<std::borrow::Cow<'static, str>> {
        #[cfg(any(windows, target_os = "macos"))]
        {
            match &self.coverage {
                InstallCoverage::Complete => None,
                InstallCoverage::Incomplete => Some("не удалось проверить".into()),
                #[cfg(windows)]
                InstallCoverage::ObservedStandard => Some("обнаружена в стандартном месте (только просмотр)".into()),
                #[cfg(target_os = "macos")]
                InstallCoverage::ObservedStandard(path) => {
                    let path = crate::utils::mask_path(&path.to_string_lossy());
                    Some(format!("только просмотр · {path}").into())
                }
            }
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        { None }
    }

    pub(crate) fn patch_observation_label(&self) -> Option<&'static str> {
        self.display_path()?;
        Some(match self.patched {
            Some(true) => "пропатчена",
            Some(false) => "не полностью пропатчена",
            None => "патч не проверен",
        })
    }

    pub(crate) fn unconfirmed_patch_note(&self) -> Option<&'static str> {
        #[cfg(any(windows, target_os = "macos"))]
        if self.patched.is_none() {
            return self.patch_observation_label();
        }
        None
    }
}

#[cfg(windows)]
impl InstallRow {
    pub(crate) fn recovery_path(&self) -> Option<&Path> {
        if self.observed_kind == Some(crate::InstallationKind::Desktop) { self.path.as_deref() } else { None }
    }
}

/// What the VPN measurement found, as the indicator draws it.
///
/// The distinction is the whole point and it is a measured one, not a guess: a
/// tunnel being up says nothing about whether *Antigravity* is inside it. Per-app
/// split tunnelling made "a VPN is connected" mean the opposite of what it looks
/// like, and reading it as "skip the rules" left the client in the blocked region
/// with no bypass at all (G29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnSeen {
    /// No tunnel on the machine.
    None,
    /// A tunnel is up, but Antigravity's own sockets do not leave through it.
    NotCarryingClient,
    /// Measured: Antigravity's sockets leave through the tunnel.
    CarryingClient,
    /// Measured: some of them do and some do not — two language servers on
    /// different sides of a split tunnel, or sockets that outlived a rule
    /// change. The half inside faces the gate from wherever the tunnel exits.
    PartlyCarryingClient,
    /// A tunnel is up, and Antigravity's own traffic goes to **our** proxy — so
    /// the socket that faces the gate is the relay's, not the client's.
    ///
    /// The ordinary state for a patched client with the local-proxy route on,
    /// and the one the tool's own success created: excluding `language_server`
    /// from a VPN stopped meaning anything the moment it stopped making gate
    /// connections. Whether the *relay* is in the tunnel is a question this
    /// measurement does not answer (P34).
    ViaLocalProxy,
    /// A tunnel is up and there was nothing to read: Antigravity is not running,
    /// or has not dialled out yet.
    ///
    /// Its own variant because it used to be folded into `NotCarryingClient`,
    /// and that is the same mistake the tool forbids itself elsewhere — treating
    /// an absence of evidence as evidence (the resolver rule in CLAUDE.md). The
    /// window opens before Antigravity is started far more often than not, so
    /// the message every VPN user got was the confident and usually wrong «VPN
    /// активен, но Antigravity идёт мимо него». What the layer *does* is
    /// unchanged: no measurement still means the rules go in (S37).
    Unmeasured,
}

#[derive(Debug, Clone)]
pub struct ProviderRow {
    pub name: String,
    pub enabled: bool,
}

/// A whole-system snapshot. Produced on the worker, rendered on the UI thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportView { LegacyOrMissing, SystemTcp, ExistingConfigured, Invalid }

/// Package presence in the standard VS Code extension roots of this profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VsCodeAntigravityObservation {
    Found,
    NotFound,
    Incomplete,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub wsl: crate::wsl_api::WslStatus,
    pub admin: bool,
    pub installs: Vec<InstallRow>,
    pub(crate) vscode_antigravity: VsCodeAntigravityObservation,
    pub client_patch: State,
    pub watchdog: State,
    pub dns: State,
    pub local_proxy: State,
    pub own_proxy: State,
    pub builtin_exits: State,
    pub group_proxy: State,
    pub dns_rotation: State,
    pub(crate) transport_view: TransportView,
    pub(crate) transport_choices: Result<crate::settings::TransportChoices, String>,
    pub(crate) transport_ready: Option<bool>,
    /// What the last measurement saw. `None` means it has not been taken yet;
    /// taking it spawns PowerShell, so it is not done on every refresh.
    pub vpn: Option<VpnSeen>,
    pub own_proxy_text: String,
    pub custom_dns_text: String,
    pub relay_outdated: bool,
    #[cfg(windows)]
    pub(crate) selected_delivery: Result<bool, String>,
    /// Whether the relay task is registered *and* running. The raw fact, kept
    /// beside the `dns` row that already folds it into a verdict: the gate strip
    /// has to say "there is nobody to catch the next 400" without re-deriving it
    /// from a string meant for a switch.
    pub relay_running: bool,
    pub(crate) background_observation_error: Option<String>,
    /// Whether our NRPT rules are in. The raw fact, beside `relay_running`, for
    /// the same reason: a running service with no rules is a bypass nobody's
    /// queries ever reach, and the status card has to be able to say so.
    pub rules: bool,
    pub(crate) rules_observed: Option<bool>,
    pub providers: Vec<ProviderRow>,
    /// Where **our own** service's connections leave. `None` when there was
    /// nothing to read, or no tunnel to read it against.
    ///
    /// The half the client stopped being able to answer (G46), and the one that
    /// decides whether a provider serving only Russian addresses will serve us
    /// at all. Reported, never acted on: the stand-down decision is still the
    /// client's (D13, P34).
    pub relay_egress: Option<crate::egress::ClientEgress>,
}

impl Status {
    pub fn get(&self, cap: Cap) -> &State {
        match cap {
            Cap::ClientPatch => &self.client_patch,
            Cap::Watchdog => &self.watchdog,
            Cap::Dns => &self.dns,
            Cap::LocalProxy => &self.local_proxy,
            Cap::OwnProxy => &self.own_proxy,
            Cap::BuiltinExits => &self.builtin_exits,
            Cap::GroupProxy => &self.group_proxy,
            Cap::DnsRotation => &self.dns_rotation,
        }
    }

    /// The bypass master switch. Derived, never stored: it is on when any part
    /// of the bypass is, which keeps one truth instead of two.
    pub fn bypass_on(&self) -> bool {
        if cfg!(windows) && self.transport_view == TransportView::SystemTcp { return matches!(self.local_proxy, State::On) && self.rules_observed == Some(false) && self.transport_ready == Some(true); }
        if cfg!(windows) { return self.dns.is_on() || self.local_proxy.is_on(); }
        self.dns.is_on()
            || self.local_proxy.is_on()
            || self.builtin_exits.is_on()
            || self.group_proxy.is_on()
            || self.own_proxy.is_on()
    }
}

/// The parts of the bypass, in the order the master switch sends them.
///
/// Not the same in both directions. ON: the relay has to be answering before the
/// proxy variable may name it (I53) â€” the worker runs these in order, so DNS
/// finishes first. OFF: the variable comes off *before* the listener it names
/// goes away, or a sign-in that lands in between dials a dead port (G31).
pub fn bypass_order(on: bool) -> Vec<Cap> {
    let mut order = if on {
        // The user's own proxy is theirs to switch on: it needs an address.
        vec![
            Cap::Dns,
            Cap::LocalProxy,
            Cap::BuiltinExits,
            Cap::GroupProxy,
        ]
    } else {
        vec![
            Cap::LocalProxy,
            Cap::OwnProxy,
            Cap::BuiltinExits,
            Cap::GroupProxy,
            Cap::Dns,
        ]
    };
    order.retain(|cap| cap.supported());
    order
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Step,
    Info,
    Ok,
    Warn,
    Err,
}

/// Worker → UI.
pub enum Event {
    Log(Level, String),
    Status(Box<Status>),
    /// `Some(what)` while an action runs, `None` when the queue drains. The UI
    /// dims the switches in between so a second click cannot queue a race.
    Busy(Option<String>),
    #[cfg(windows)]
    InstallationRecoveryPrepared(InstallationRecoveryPreview),
    #[cfg(windows)]
    InstallationRecoveryClosed,
    /// Every owned GUI operation actually settled and Settings were saved.
    ShutdownReady,
}

#[cfg(windows)]
pub struct InstallationRecoveryPreview {
    pub(crate) proposal_id: String,
    pub(crate) path: PathBuf,
    pub(crate) operation_id: String,
}

/// UI → worker.
pub enum Cmd {
    RequestElevation,
    #[cfg(windows)]
    Elevate(crate::instances::GuiReplacementAction),
    SetWslEnabled(bool),
    SetWslDistro { name: String, selected: bool },
    RefreshWsl,
    ApplySettings,
    CancelWsl,
    Shutdown,
    /// The key was accepted and the main screen is up. Auto-patch may act from
    /// here on, never before: the first scan runs under the licence screen, and
    /// patching from there would hand the patch to anyone without a key.
    Unlocked,
    /// Store the licence key just accepted, so the next start skips the screen.
    RememberLicense(String),
    /// Ask the system again where the client's traffic leaves.
    ///
    /// Its own command because it is the one measurement that goes stale on its
    /// own — a user connects a VPN, or starts Antigravity, and nothing in this
    /// window was touched. Sent by the gate watcher, which knows when it is
    /// worth paying for (`gate`), and answered here because `ops` owns the
    /// measurement the DNS layer's decision is made from (I59).
    RemeasureVpn,
    /// The answer to the above, coming back from the thread it was taken on.
    ///
    /// It carries the relay's liveness too, because that is the other fact the
    /// gate strip shows and the other one that goes stale on its own — a relay
    /// can die while the window sits open, and until this arrived nothing
    /// re-read it short of the user flipping a switch. Both probes are cheap
    /// process spawns and neither belongs on the worker's queue.
    Probed {
        vpn: VpnSeen,
        relay: bool,
        relay_egress: Option<crate::egress::ClientEgress>,
    },
    /// Re-read the system *including* whether each install is patched, which
    /// means reading every Language Server binary end to end.
    #[allow(dead_code)]
    DeepRefresh,
    Set(Cap, bool),
    AddPath(PathBuf),
    ForgetPath(PathBuf),
    /// The «Пропатчить» button of one install row.
    PatchInstall(PathBuf),
    #[cfg(windows)]
    PrepareInstallationRecovery { path: PathBuf },
    #[cfg(windows)]
    ConfirmInstallationRecovery { proposal_id: String },
    #[cfg(windows)]
    DismissInstallationRecovery { proposal_id: String },
    SetOwnProxy(String),
    SetCustomDns(String),
    SetGroupKey(String),
    CopyGroupCommand,
    SetProvider(String, bool),
    /// The whole pool in the order the user dragged it into.
    ReorderProviders(Vec<String>),
    /// Everything on, in the order that works: the patch, auto-patch, then the
    /// bypass. The one button a user who is not a programmer needs.
    EnableAll,
    /// Select the system-network TCP profile through the canonical settings owner.
    UseSystemTcp,
    UseExistingConfigured(crate::settings::TransportChoices),
    /// Puts the service back the way the switches say it should be: reinstalls
    /// the relay when it is missing, stopped or older than this build, rewrites
    /// the rules, restores the proxy variable.
    Repair,
    #[allow(dead_code)]
    Stop,
}

pub struct Worker {
    tx: Sender<Cmd>,
    lifetime: Arc<GuiLifetime>,
}

#[cfg(test)]
pub(crate) fn layout_test_worker(lifetime: Arc<GuiLifetime>) -> (Worker, Receiver<Cmd>) {
    let (tx, rx) = mpsc::channel();
    (Worker { tx, lifetime }, rx)
}

/// Main-owned custody across GUI/TUI shutdown and renderer return. This holds
/// actual handles, not a second status/settings store.
#[derive(Default)]
pub struct GuiLifetime {
    commands: Arc<crate::command_lifetime::CommandLifetime>,
    command_result: Mutex<Vec<String>>,
    command_panics: Mutex<Vec<Box<dyn std::any::Any + Send>>>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    command: Mutex<Option<Sender<Cmd>>>,
    shutdown_ready: AtomicBool,
    save_failed: AtomicBool,
    started: AtomicBool,
    abort_requested: Arc<AtomicBool>,
    channel_lost: AtomicBool,
    handoff_requested: AtomicBool,
    arming_started: AtomicBool,
    handoff_committed: AtomicBool,
    failure: Mutex<Option<String>>,
    bootstrap_hold: Mutex<Option<String>>,
    #[cfg(windows)]
    replacement: Mutex<Option<crate::instances::GuiReplacementReady>>,
    #[cfg(windows)]
    action: Mutex<Option<crate::instances::GuiReplacementAction>>,
    #[cfg(windows)]
    retirement_input: Mutex<Option<RetirementInput>>,
    #[cfg(windows)]
    image: Option<Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>>,
    #[cfg(windows)]
    stopped_delivery: Mutex<StoppedDeliveryStatus>,
    #[cfg(windows)]
    stopped_delivery_retry: std::sync::Condvar,
}

#[cfg(windows)]
#[derive(Clone, Default)]
pub(crate) enum StoppedDeliveryStatus {
    #[default]
    Ready,
    Running,
    ResourceHeld(Arc<String>),
    Finished(Result<(), String>),
}

#[cfg(windows)]
use crate::windows_coordinator::windows_installation as vendor_records;

#[cfg(windows)]
pub(crate) struct VendorSupersessionPreview {
    pub(crate) path: PathBuf,
    pub(crate) observation: vendor_records::VendorSupersessionConfirmation,
}

#[cfg(windows)]
pub(crate) struct VendorPublicationFailure {
    failure: vendor_records::MetadataFailure,
    dispositions: Vec<serde_json::Value>,
}

#[cfg(windows)]
impl VendorPublicationFailure {
    fn message(&self) -> String {
        let mut message = self.failure.to_string();
        let receiving = &self.failure.evidence["postEffectReceiving"];
        let receipt = receiving["receiptSha256"].as_str().filter(|digest| hex::decode_to_slice(digest, &mut [0; 32]).is_ok());
        if let Some(digest) = receipt.filter(|_| receiving["result"].as_str() == Some("received") && receiving["disposition"].is_object()) {
            message.push_str(&format!("\nСвидетельство подтверждено независимым чтением. SHA-256 {digest}"));
        } else if self.failure.evidence["stageRenameResult"].as_bool() == Some(true) {
            message.push_str("\nФайл свидетельства перемещён на защищённое место. Итоговая проверка не завершена.");
        }
        if !self.dispositions.is_empty() {
            message.push_str(&format!("\nПодтверждено завершение ресурсов: {}.", self.dispositions.len()));
        }
        message
    }
}

#[cfg(windows)]
#[derive(Clone)]
pub(crate) enum VendorSupersessionProblem {
    Admission(String),
    Publication(Arc<Mutex<VendorPublicationFailure>>),
}

#[cfg(windows)]
impl From<String> for VendorSupersessionProblem {
    fn from(error: String) -> Self { Self::Admission(error) }
}

#[cfg(windows)]
impl From<&str> for VendorSupersessionProblem {
    fn from(error: &str) -> Self { Self::Admission(error.into()) }
}

#[cfg(windows)]
impl std::fmt::Display for VendorSupersessionProblem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admission(error) => formatter.write_str(error),
            Self::Publication(actual) => formatter.write_str(&actual.lock().unwrap_or_else(|error| error.into_inner()).message()),
        }
    }
}

#[cfg(windows)]
#[derive(Clone)]
pub(crate) enum VendorSupersessionStatus {
    Checking,
    Select(Vec<PathBuf>),
    Confirm(Arc<VendorSupersessionPreview>),
    Held(Arc<String>),
    Finished(Result<Option<[u8; 32]>, VendorSupersessionProblem>),
}

#[cfg(windows)]
pub(crate) enum VendorSupersessionCommand {
    Select(usize),
    Confirm(Arc<VendorSupersessionPreview>, background::VendorForegroundOwner),
    Retry(Arc<String>),
    Cancel,
}

#[cfg(windows)]
#[derive(Clone)]
pub(crate) struct VendorSupersessionSession {
    lifetime: Arc<GuiLifetime>,
    status: Arc<Mutex<VendorSupersessionStatus>>,
    commands: Sender<VendorSupersessionCommand>,
}

#[cfg(windows)]
impl VendorSupersessionSession {
    pub(crate) fn status(&self) -> VendorSupersessionStatus {
        self.status.lock().unwrap_or_else(|error| error.into_inner()).clone()
    }

    pub(crate) fn send(&self, command: VendorSupersessionCommand) {
        if matches!(&command, VendorSupersessionCommand::Cancel) { self.lifetime.request_shutdown(); }
        let _ = self.commands.send(command);
    }
}

impl GuiLifetime {
    pub(crate) fn new_command_scope(&self) -> Result<crate::command_lifetime::PendingCommand, String> {
        self.commands.begin("GUI operation")
    }
    fn command_scopes_settled(&self) -> bool {
        matches!(self.receive_command_results(), crate::command_lifetime::Receiving::Ready)
    }
    fn receive_command_results(&self) -> crate::command_lifetime::Receiving {
        let receiving = self.commands.receive();
        self.command_result.lock().unwrap_or_else(|error| error.into_inner()).extend(self.commands.take_failures());
        self.command_panics.lock().unwrap_or_else(|error| error.into_inner()).extend(self.commands.take_panics());
        receiving
    }
    pub(crate) fn take_final_command_results(&self) -> Result<Vec<String>, String> {
        if !matches!(self.receive_command_results(), crate::command_lifetime::Receiving::Ready) {
            return Err("command operation receiving remains pending".into());
        }
        let mut results = self.command_result.lock().map_err(|_| "GUI command-result destination unavailable")?;
        Ok(std::mem::take(&mut *results))
    }
    fn take_command_result_batch(&self) -> Vec<String> {
        std::mem::take(&mut *self.command_result.lock().unwrap_or_else(|error| error.into_inner()))
    }
    pub(crate) fn take_command_panics(&self) -> Vec<Box<dyn std::any::Any + Send>> {
        std::mem::take(&mut *self.command_panics.lock().unwrap_or_else(|error| error.into_inner()))
    }
    #[cfg(windows)]
    pub(crate) fn with_image(image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>) -> Self {
        Self { image: Some(image), ..Self::default() }
    }
    #[cfg(windows)]
    pub(crate) fn retained_image(&self) -> Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String> {
        self.image.clone().unwrap_or_else(|| Err("source-selection hold: current image was not received".into()))
    }
    #[cfg(windows)]
    pub(crate) fn stopped_delivery_status(&self) -> StoppedDeliveryStatus {
        self.stopped_delivery.lock().unwrap_or_else(|error| error.into_inner()).clone()
    }
    #[cfg(windows)]
    pub(crate) fn start_stopped_delivery(self: &Arc<Self>, wake: impl Fn() + Send + 'static) -> Result<(), String> {
        let mut worker = self.worker.lock().map_err(|_| "Не удалось получить владение рабочим потоком обновления.")?;
        let mut status = self.stopped_delivery.lock().map_err(|_| "Состояние обновления недоступно.")?;
        if worker.is_some() || self.started.load(Ordering::SeqCst)
            || self.abort_requested.load(Ordering::SeqCst) || !matches!(&*status, StoppedDeliveryStatus::Ready) {
            return Err("Этот запуск уже получил действие обновления или отмены.".into());
        }
        let image = self.retained_image()?;
        let lifetime = self.clone();
        let job = match std::thread::Builder::new().name("stopped-background-delivery".into())
            .spawn(move || run_stopped_delivery_worker(lifetime, image, wake)) {
            Ok(job) => job,
            Err(cause) => {
                let error = format!("Рабочий поток обновления не запущен: {cause}");
                *status = StoppedDeliveryStatus::Finished(Err(error.clone()));
                return Err(error);
            }
        };
        *status = StoppedDeliveryStatus::Running;
        *worker = Some(job);
        self.started.store(true, Ordering::SeqCst);
        Ok(())
    }
    #[cfg(windows)]
    pub(crate) fn retry_stopped_delivery_hold(&self, observed: &Arc<String>) {
        let mut status = self.stopped_delivery.lock().unwrap_or_else(|error| error.into_inner());
        if matches!(&*status, StoppedDeliveryStatus::ResourceHeld(active) if Arc::ptr_eq(active, observed)) {
            *status = StoppedDeliveryStatus::Running;
            self.stopped_delivery_retry.notify_one();
        }
    }
    #[cfg(windows)]
    fn record_maintenance_panic(&self, context: &str, payload: Box<dyn std::any::Any + Send>) -> String {
        // Only the known failure phase belongs in the window. The root
        // receives the original payload after the owning worker retires.
        self.command_panics.lock().unwrap_or_else(|error| error.into_inner()).push(payload);
        context.to_owned()
    }
    #[cfg(windows)]
    fn fail_stopped_delivery(&self, error: String) {
        let mut status = self.stopped_delivery.lock().unwrap_or_else(|error| error.into_inner());
        let failure = match &*status {
            StoppedDeliveryStatus::Finished(Err(primary)) => format!("{primary}\n\n{error}"),
            StoppedDeliveryStatus::ResourceHeld(primary) => format!("{primary}\n\n{error}"),
            StoppedDeliveryStatus::Finished(Ok(())) => format!("Результат обновления подтверждён.\n\n{error}"),
            _ => error,
        };
        *status = StoppedDeliveryStatus::Finished(Err(failure));
    }
    #[cfg(windows)]
    fn receive_stopped_delivery_join(&self, joined: std::thread::Result<()>) {
        let failure = match joined {
            Err(payload) => Some(self.record_maintenance_panic("Рабочий поток обновления аварийно завершился", payload)),
            Ok(()) if !self.shutdown_ready.load(Ordering::SeqCst) => Some("Рабочий поток завершился без результата обновления.".into()),
            Ok(()) => None,
        };
        if let Some(error) = failure { self.fail_stopped_delivery(error); }
        self.shutdown_ready.store(true, Ordering::SeqCst);
    }
    #[cfg(windows)]
    pub(crate) fn receive_retirement_input(&self, descriptor: crate::instances::GuiRetirementInputRef) -> Result<(), String> {
        let input = RetirementInput::receive(descriptor)?;
        let mut slot = self.retirement_input.lock().map_err(|_| "retirement input lock poisoned")?;
        if slot.is_some() { return Err("retirement input already received".into()); }
        *slot = Some(input);
        Ok(())
    }
    pub(crate) fn hold_automatic_effects(&self, reason: String) -> Result<(), String> {
        *self.bootstrap_hold.lock().map_err(|_| "GUI startup hold receiving lock poisoned")? = Some(reason);
        Ok(())
    }
    pub(crate) fn fallback_hold(&self) -> Option<String> {
        match self.bootstrap_hold.lock() {
            Ok(hold) => hold.clone(),
            Err(_) => Some("Не удалось получить ограничение автоматического запуска.".into()),
        }
    }
    fn clear_automatic_hold(&self) -> Result<(), String> {
        *self.bootstrap_hold.lock().map_err(|_| "GUI startup hold lock poisoned")? = None;
        Ok(())
    }
    #[cfg(windows)]
    pub(crate) fn receive_action(&self, action: crate::instances::GuiReplacementAction) -> Result<(), String> {
        let mut slot = self.action.lock().map_err(|_| "GUI action receiving lock poisoned")?;
        if slot.is_some() { return Err("GUI action already received".into()); }
        *slot = Some(action);
        Ok(())
    }
    pub fn request_shutdown(&self) {
        self.save_failed.store(false, Ordering::SeqCst);
        self.abort_requested.store(true, Ordering::SeqCst);
        if let Ok(command) = self.command.lock() {
            if let Some(command) = command.as_ref() { let _ = command.send(Cmd::Shutdown); }
        }
    }
    /// Event loops may retire on true. This never sends COMMIT: Main owns the
    /// final exit corridor after the renderer/terminal loop has returned.
    pub fn poll_close(&self) -> Result<bool, String> {
        let commands_received = matches!(self.receive_command_results(),
            crate::command_lifetime::Receiving::Ready);
        if self.save_failed.load(Ordering::SeqCst) { return Err("настройки не сохранены; повторите закрытие после устранения ошибки".into()); }
        if let Some(error) = self.failure.lock().map_err(|_| "worker failure observation poisoned")?.as_ref() {
            return Err(error.clone());
        }
        let mut worker = self.worker.lock().map_err(|_| "worker custody lock poisoned")?;
        if let Some(job) = worker.as_ref() {
            if !job.is_finished() { return Ok(false); }
            let joined = worker.take().unwrap().join();
            #[cfg(windows)]
            let joined = if !matches!(self.stopped_delivery_status(), StoppedDeliveryStatus::Ready) {
                self.receive_stopped_delivery_join(joined);
                Ok(())
            } else { joined };
            if joined.is_err() {
                let error = "worker did not return a received shutdown outcome".to_owned();
                *self.failure.lock().map_err(|_| "worker failure observation poisoned")? = Some(error.clone());
                return Err(error);
            }
        }
        if self.started.load(Ordering::SeqCst) && !self.shutdown_ready.load(Ordering::SeqCst) {
            return Err("worker returned before saved/settled shutdown receiving".into());
        }
        if !commands_received { return Ok(false); }
        Ok(true)
    }
    pub(crate) fn can_retry_renderer(&self) -> bool {
        if self.started.load(Ordering::SeqCst) || self.abort_requested.load(Ordering::SeqCst)
            || self.handoff_requested.load(Ordering::SeqCst) || self.fallback_hold().is_some() { return false; }
        true
    }
    pub(crate) fn can_start_fallback(&self) -> bool {
        if !self.can_retry_renderer() { return false; }
        #[cfg(windows)]
        if self.action.lock().map_or(true, |action| action.is_some()) { return false; }
        true
    }
    pub(crate) fn request_final_retirement(&self) {
        if !self.shutdown_ready.load(Ordering::SeqCst) { self.request_shutdown(); }
    }
    pub(crate) fn save_retry_pending(&self) -> bool { self.save_failed.load(Ordering::SeqCst) }
    pub(crate) fn finalize_exit(&self) -> Result<bool, String> {
        if !self.poll_close()? { return Ok(false); }
        #[cfg(windows)]
        {
            let mut slot = self.replacement.lock().map_err(|_| "replacement custody lock poisoned")?;
            if let Some(replacement) = slot.as_mut() {
                if self.handoff_committed.load(Ordering::SeqCst) { return Ok(true); }
                if self.abort_requested.load(Ordering::SeqCst) && !self.arming_started.load(Ordering::SeqCst) {
                    replacement.request_abort()?;
                    if !replacement.poll_retired()? { return Ok(false); }
                    slot.take();
                    return Ok(true);
                }
                // The helper marks its own possible COMMIT before writing. A
                // failed/uncertain write must never turn back into an abort.
                self.arming_started.store(true, Ordering::SeqCst);
                match replacement.arm_for_exit() {
                    Ok(true) => {
                        self.handoff_committed.store(true, Ordering::SeqCst);
                        return Ok(true);
                    }
                    Ok(false) => {},
                    Err(error) => {
                        if self.abort_requested.load(Ordering::SeqCst) && replacement.poll_retired()? {
                            slot.take();
                            return Ok(true);
                        }
                        return Err(error);
                    }
                }
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub fn replacement_committed(&self) -> bool { self.handoff_committed.load(Ordering::SeqCst) }
    #[cfg(windows)]
    fn accept_replacement(&self, ready: crate::instances::GuiReplacementReady) -> Result<(), crate::instances::GuiReplacementReady> {
        match self.replacement.lock() {
            Ok(mut slot) if slot.is_none() => {
                *slot = Some(ready);
                self.handoff_requested.store(true, Ordering::SeqCst);
                Ok(())
            }
            _ => Err(ready),
        }
    }
}

#[cfg(windows)]
fn run_stopped_delivery_worker(lifetime: Arc<GuiLifetime>, image: Arc<crate::windows_coordinator::process_identity::CurrentImage>,
    wake: impl Fn()) {
    // This worker receives just the selected operation and shutdown. It never
    // constructs the normal settings worker or sends a command through it.
    let mut wake = Some(wake);
    let mut publish = |status| {
        *lifetime.stopped_delivery.lock().unwrap_or_else(|error| error.into_inner()) = status;
        let notify = wake.take()?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(&notify)) {
            Ok(()) => { wake = Some(notify); None }
            Err(payload) => Some(lifetime.record_maintenance_panic("Не удалось обновить окно во время завершения", payload)),
        }
    };
    let mut receiver_errors = Vec::new();
    let result = background::require_stopped_delivery_elevation(&image).and_then(|()| {
        let mut receiving = background::deliver_stopped_managed_image_with_receiving(&lifetime.abort_requested, Ok(image));
        let result = receiving.result.clone();
        if let Some(payload) = receiving.take_pending_unwind() {
            receiver_errors.push(lifetime.record_maintenance_panic("Выполнение фонового обновления аварийно прервалось", payload));
        }
        loop {
            let finishes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receiving.finish_live_resources()));
            let held = match finishes {
                Ok(results) => results.into_iter().filter_map(Result::err).collect::<Vec<_>>(),
                Err(payload) => {
                    let error = lifetime.record_maintenance_panic("Получение ресурса прервано. Владение ресурсом сохраняется", payload);
                    receiver_errors.push(error.clone());
                    vec![error]
                }
            };
            if held.is_empty() { break; }
            let primary = result.as_ref().err().map(|error| format!("{error}\n\n")).unwrap_or_default();
            let hold = Arc::new(format!("{primary}Завершение ожидает сохранения ресурса операции.\n{}", held.join("\n")));
            if let Some(error) = publish(StoppedDeliveryStatus::ResourceHeld(hold.clone())) {
                receiver_errors.push(error);
            }
            // The explicit retry must acknowledge this exact hold.
            let status = lifetime.stopped_delivery.lock().unwrap_or_else(|error| error.into_inner());
            drop(lifetime.stopped_delivery_retry.wait_while(status, |state| {
                matches!(state, StoppedDeliveryStatus::ResourceHeld(active) if Arc::ptr_eq(active, &hold))
            })
                .unwrap_or_else(|error| error.into_inner()));
        }
        result
    });
    let notify_error = publish(StoppedDeliveryStatus::Finished(result));
    receiver_errors.extend(notify_error);
    if !receiver_errors.is_empty() { lifetime.fail_stopped_delivery(receiver_errors.join("\n")); }
    lifetime.shutdown_ready.store(true, Ordering::SeqCst);
}

#[cfg(windows)]
pub(crate) fn start_vendor_supersession(lifetime: &Arc<GuiLifetime>, manual: Vec<PathBuf>) -> Result<VendorSupersessionSession, String> {
    let image = lifetime.retained_image()?;
    let mut worker = lifetime.worker.lock().map_err(|_| "Не удалось получить владение потоком обслуживания.")?;
    if worker.is_some() || lifetime.started.load(Ordering::SeqCst) || lifetime.abort_requested.load(Ordering::SeqCst) {
        return Err("Этот запуск уже получил действие обслуживания или отмены.".into());
    }
    let (commands, receiver) = mpsc::channel();
    let status = Arc::new(Mutex::new(VendorSupersessionStatus::Checking));
    let worker_status = status.clone();
    let owner = lifetime.clone();
    let job = std::thread::Builder::new().name("vendor-supersession".into()).spawn(move || {
        let publish = |status| { *worker_status.lock().unwrap_or_else(|error| error.into_inner()) = status; };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_vendor_supersession(&owner, &image, manual, &receiver, &publish)
        }));
        let outcome = match outcome {
            Ok(result) => result,
            Err(payload) => Err(owner.record_maintenance_panic("Запись истории Desktop аварийно прервалась", payload).into()),
        };
        publish(VendorSupersessionStatus::Finished(outcome));
        owner.shutdown_ready.store(true, Ordering::SeqCst);
    }).map_err(|error| format!("Рабочий поток обслуживания не запущен: {error}"))?;
    *worker = Some(job);
    lifetime.started.store(true, Ordering::SeqCst);
    Ok(VendorSupersessionSession { lifetime: lifetime.clone(), status, commands })
}

#[cfg(windows)]
fn discover_vendor_desktops(owner: &mut crate::utils::CommandOutcome, manual: Vec<PathBuf>, cancel: &AtomicBool)
    -> Result<Vec<(vendor_records::CheckedPath, vendor_records::CheckedPath)>, String> {
    let mut paths = crate::find_all_installs_checked(owner, cancel)?;
    for path in manual { if !paths.contains(&path) { paths.push(path); } }
    let mut desktops: Vec<(vendor_records::CheckedPath, vendor_records::CheckedPath)> = Vec::new();
    for path in paths {
        if cancel.load(Ordering::SeqCst) { return Ok(Vec::new()); }
        let root = vendor_records::CheckedPath::open(&path, vendor_records::PathKind::Directory, vendor_records::PathPurpose::Source)?;
        let layout = crate::receive_installation_layout(root.as_path())?;
        if layout.kind != crate::InstallationKind::Desktop { continue; }
        let anchor = vendor_records::CheckedPath::open(&layout.anchor, vendor_records::PathKind::File, vendor_records::PathPurpose::ReplaceSource)?;
        root.recheck()?;
        anchor.recheck()?;
        if let Some((_, previous)) = desktops.iter().find(|(previous, _)| previous.native_id() == root.native_id()) {
            if previous.native_id() != anchor.native_id() { return Err("Найдены несовместимые идентификаторы одной установки Desktop.".into()); }
        } else { desktops.push((root, anchor)); }
    }
    Ok(desktops)
}

#[cfg(windows)]
fn bind_checked_desktop(root: &vendor_records::CheckedPath, anchor: &vendor_records::CheckedPath) -> Result<vendor_records::BoundInstallation, String> {
    let mut bound = vendor_records::BoundInstallation::open(anchor.as_path())?;
    if bound.native_root_id() != root.native_id() || bound.native_executable_id() != anchor.native_id() {
        return Err("Desktop target native identity changed".into());
    }
    if let Some(context) = crate::windows_coordinator::receive_saved_context(&bound)? { bound.attach_ancestor_context(context)?; }
    Ok(bound)
}

#[cfg(windows)]
fn run_vendor_supersession(lifetime: &GuiLifetime, image: &crate::windows_coordinator::process_identity::CurrentImage,
    manual: Vec<PathBuf>, commands: &Receiver<VendorSupersessionCommand>, publish: &impl Fn(VendorSupersessionStatus)) -> Result<Option<[u8; 32]>, VendorSupersessionProblem> {
    use VendorSupersessionCommand as Command;
    let cancel = lifetime.abort_requested.as_ref();
    background::require_vendor_supersession_actor(image)?;
    let desktops = lifetime.new_command_scope()?.with_result(|owner| discover_vendor_desktops(owner, manual, cancel))?;
    if cancel.load(Ordering::SeqCst) { return Ok(None); }
    if desktops.is_empty() { return Err("Подтверждённые установки Antigravity Desktop не найдены.".into()); }
    publish(VendorSupersessionStatus::Select(desktops.iter().map(|(root, _)| root.as_path().to_owned()).collect()));
    let selected = match commands.recv() {
        Ok(Command::Select(index)) if !cancel.load(Ordering::SeqCst) => index,
        _ => return Ok(None),
    };
    publish(VendorSupersessionStatus::Checking);
    let (root, anchor) = desktops.get(selected).ok_or("Выбранная установка Desktop не была получена.")?;
    root.recheck()?;
    anchor.recheck()?;
    let layout = crate::receive_installation_layout(root.as_path())?;
    if layout.kind != crate::InstallationKind::Desktop || !vendor_records::same_windows_path(&layout.anchor, anchor.as_path())? {
        return Err("Расположение выбранной установки Desktop изменилось.".into());
    }
    let bound = bind_checked_desktop(root, anchor)?;
    let observation = vendor_records::observe_vendor_supersession(&bound, cancel)?;
    if cancel.load(Ordering::SeqCst) { return Ok(None); }
    let preview = Arc::new(VendorSupersessionPreview { path: root.as_path().to_owned(), observation });
    publish(VendorSupersessionStatus::Confirm(preview.clone()));
    let foreground = loop {
        match commands.recv() {
            Ok(Command::Confirm(confirmed, foreground)) if Arc::ptr_eq(&confirmed, &preview) && !cancel.load(Ordering::SeqCst) => break foreground,
            Ok(Command::Confirm(_, _)) | Ok(Command::Cancel) | Err(_) => return Ok(None),
            Ok(_) => {}
        }
    };
    publish(VendorSupersessionStatus::Checking);
    background::require_vendor_supersession_actor(image)?;
    root.recheck()?;
    anchor.recheck()?;
    match vendor_records::record_vendor_supersession(&bound, &preview.observation, cancel, move || foreground.recheck()) {
        Ok(receipt) => Ok(Some(receipt)),
        Err(vendor_records::VendorSupersessionFailure::Admission(error)) => Err(error.into()),
        Err(vendor_records::VendorSupersessionFailure::Publication(mut failure)) => {
            if let Some(payload) = failure.unwind.take() {
                lifetime.record_maintenance_panic("Запись защищённого свидетельства прервалась", payload.0);
            }
            for payload in failure.secondary_unwinds.drain(..) {
                lifetime.record_maintenance_panic("Получение защищённого свидетельства прервалось", payload.0);
            }
            let mut actual = VendorPublicationFailure { failure, dispositions: Vec::new() };
            loop {
                let mut held = Vec::new();
                actual.failure.live.retain_mut(|resource| match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resource.finish())) {
                    Ok(Ok(disposition)) => { actual.dispositions.push(disposition); false }
                    Ok(Err(error)) => { held.push(error); true }
                    Err(payload) => {
                        held.push(lifetime.record_maintenance_panic("Получение защищённого ресурса прервалось", payload));
                        true
                    }
                });
                if actual.failure.pending.is_some() { held.push("Требуется независимое получение защищённой записи её владельцем.".into()); }
                if held.is_empty() { return Err(VendorSupersessionProblem::Publication(Arc::new(Mutex::new(actual)))); }
                let hold = Arc::new(format!("{}\n\n{}", actual.message(), held.join("\n")));
                publish(VendorSupersessionStatus::Held(hold.clone()));
                loop {
                    match commands.recv() {
                        Ok(Command::Retry(observed)) if Arc::ptr_eq(&observed, &hold) => break,
                        Ok(_) => {}
                        Err(_) => std::thread::park(),
                    }
                }
                publish(VendorSupersessionStatus::Checking);
            }
        }
    }
}

impl Worker {
    pub fn send(&self, cmd: Cmd) {
        if matches!(&cmd, Cmd::Shutdown | Cmd::Stop) {
            self.lifetime.request_shutdown();
            return;
        }
        // A closed worker means the app is going down; there is nothing useful
        // to do about it and nothing to tell the user.
        let _ = self.tx.send(cmd);
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if !self.lifetime.shutdown_ready.load(Ordering::SeqCst) { self.lifetime.request_shutdown(); }
    }
}

/// Starts the worker. `wake` is called after every event so the UI thread
/// repaints — egui sleeps until something asks it not to.
pub fn spawn(events: Sender<Event>, wake: Box<dyn Fn() + Send>, lifetime: Arc<GuiLifetime>) -> Worker {
    let (tx, rx) = mpsc::channel::<Cmd>();
    // The worker keeps a sender of its own, for the one job it hands to a
    // thread and gets an answer back from (`RemeasureVpn`). It means the
    // channel never disconnects, so the loop does not end when the window drops
    // its `Worker` — which costs nothing here, because the window closing is the
    // process exiting.
    let own = tx.clone();
    let mut worker_slot = match lifetime.worker.lock() {
        Ok(slot) => slot,
        Err(_) => {
            let _ = events.send(Event::Log(Level::Err, "Не удалось получить владение рабочим потоком.".into()));
            return Worker { tx, lifetime: lifetime.clone() };
        }
    };
    if worker_slot.is_some() {
        let _ = events.send(Event::Log(Level::Err, "Предыдущий рабочий поток ещё удерживается владельцем окна.".into()));
        return Worker { tx, lifetime: lifetime.clone() };
    }
    let worker_lifetime = lifetime.clone();
    let failure_events = events.clone();
    let started = std::thread::Builder::new()
        .name("ops".to_string())
        .spawn(move || run_worker(rx, own, events, wake, worker_lifetime));
    match started {
        Ok(job) => {
            *worker_slot = Some(job);
            lifetime.started.store(true, Ordering::SeqCst);
            if let Ok(mut command) = lifetime.command.lock() { *command = Some(tx.clone()); }
        }
        Err(error) => { let _ = failure_events.send(Event::Log(Level::Err, format!("Рабочий поток не запущен: {error}"))); }
    }
    drop(worker_slot);
    Worker { tx, lifetime }
}

// ---------------------------------------------------------------------------
// The worker loop
// ---------------------------------------------------------------------------

struct Ctx {
    received_command_results: Mutex<Vec<String>>,
    events: Sender<Event>,
    wake: Arc<Mutex<Box<dyn Fn() + Send>>>,
    settings: Settings,
    wsl: crate::wsl_controller::WslController,
    native_apply_pending: Arc<AtomicBool>,
    native_cancel: Arc<AtomicBool>,
    #[cfg(windows)]
    background_receivings: Vec<background::BackgroundReceiving>,
    #[cfg(windows)]
    background_finish_reported: bool,
    lifetime: Arc<GuiLifetime>,
    vpn_job: Option<ProbeJob>,
    vpn_unsettled: bool,
    startup: Startup,
    /// Whether the *proxy variable* rename landed in this session's patch run.
    ///
    /// Not a process-wide flag: the console build died after one run, so a
    /// sticky "it landed" atomic was harmless there. A window that patches
    /// twice would inherit the first run's verdict and keep writing a variable
    /// that nothing reads any more. Reset on every patch.
    proxy_var_carried: Option<bool>,
    proxy_var_retryable: bool,
    /// Cached per-install inspection. On macOS it is bound to a checked file
    /// snapshot; other platforms retain their last deep-pass result.
    ///
    /// A shallow refresh must not throw this away: reading a 150 MB binary is
    /// what makes the answer expensive, and without a memory every cheap refresh
    /// would blank the switch back to "not checked yet" — which reads as the
    /// patch having come undone.
    #[cfg(not(target_os = "macos"))]
    patched_seen: HashMap<PathBuf, bool>,
    #[cfg(target_os = "macos")]
    patched_seen: HashMap<PathBuf, MacObservation>,
    /// Last VPN measurement. `egress::detect` drives PowerShell and is capped at
    /// a minute, so it is taken on the deep pass and after anything that could
    /// change it — never on a plain refresh.
    vpn: Option<VpnSeen>,
    /// Taken with it: where our own service's sockets sit.
    relay_egress: Option<crate::egress::ClientEgress>,
    /// The last snapshot that was actually asked of the system.
    ///
    /// What makes `Scan::Settings` possible: a switch that only writes a field of
    /// `settings.json` cannot have changed a scheduled task, an NRPT rule or an
    /// environment variable, so re-asking Windows about all three is pure latency
    /// — and it was about two seconds of it per flip, which is what «слишком
    /// много времени» was.
    last: Option<Status>,
    /// The raw pair `read_dns` needs, kept from the last system scan so the DNS
    /// row can be recomputed for a new `vpn_detect` without going near PowerShell.
    #[cfg(not(windows))]
    dns_probe: (bool, bool),
    #[cfg(windows)]
    dns_probe: Result<WindowsSystemObservation, String>,
    /// `ensure_route_carrier` switched the local-proxy wish on, rather than the
    /// user: only then does letting go of the last route switch it off again.
    carrier_set_proxy: bool,
}

fn run_ctx_job<T>(mut ctx: std::sync::MutexGuard<'_, Ctx>, action: impl FnOnce(&mut Ctx) -> T) -> T {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&mut ctx)));
    drop(ctx);
    match result { Ok(value) => value, Err(payload) => std::panic::resume_unwind(payload) }
}

#[cfg(not(windows))]
type ProbeCompletion = (VpnSeen, bool, Option<crate::egress::ClientEgress>);
#[cfg(not(windows))]
struct ProbeJob {
    handle: std::thread::JoinHandle<ProbeCompletion>,
    command_receipt: crate::command_lifetime::PendingCommand,
}
#[cfg(windows)]
struct ProbeCompletion {
    vpn: VpnSeen,
    relay_egress: Option<crate::egress::ClientEgress>,
    observation: Result<WindowsSystemObservation, String>,
}
#[cfg(windows)]
struct ProbeJob {
    handle: std::thread::JoinHandle<ProbeCompletion>,
    valid: bool,
    cancel: Arc<AtomicBool>,
    command_receipt: Option<crate::command_lifetime::PendingCommand>,
}

#[cfg(windows)]
struct WindowsSystemObservation {
    background: Result<background::BackgroundObservation, String>,
    selected_delivery: Result<bool, String>,
    rules: Result<(bool, bool), String>, // core rules, any owned rules
    transport: Option<(crate::settings::ActiveTransportConfig, background::TransportChannelObservation, background::TransportChannelObservation, background::TransportChannelObservation, Option<u16>)>,
    transport_error: Option<String>,
}

#[cfg(windows)]
fn receive_probe_completion(ctx: &mut Ctx) -> bool {
    if !ctx.vpn_job.as_ref().is_some_and(|job| job.handle.is_finished()) { return false; }
    let job = ctx.vpn_job.take().unwrap();
    let completion = job.handle.join();

    ctx.receive_command_results();
    // The owned worker can panic before sending its notification or clearing
    // this flag. Only receipt of its finished handle settles the measurement.
    MEASURING_VPN.store(false, Ordering::SeqCst);
    if !job.valid {
        // A newer synchronous observation may already have replaced the
        // invalidated cache while this older job was still running.
        push_status(ctx, Scan::Settings);
        return ctx.dns_probe.is_err();
    }
    match completion {
        Ok(completion) => {
            let before = ctx.vpn;
            ctx.vpn = Some(completion.vpn);
            ctx.relay_egress = completion.relay_egress;
            ctx.dns_probe = completion.observation;
            if before.is_some() && before != ctx.vpn {
                if let Some(line) = vpn_change_line(completion.vpn) { ctx.log(Level::Info, line); }
            }
        }
        Err(_) => ctx.dns_probe = Err("Наблюдение службы прервано".into()),
    }
    push_status(ctx, Scan::Settings);
    false
}

#[cfg(windows)]
fn start_readonly_probe(ctx: &mut Ctx, back: Sender<Cmd>) {
    let image = ctx.lifetime.retained_image();
    let owner = match ctx.lifetime.new_command_scope() {
        Ok(owner) => owner,
        Err(error) => { ctx.dns_probe = Err(error); push_status(ctx, Scan::Settings); return; }
    };
    let observation_owner = match ctx.lifetime.new_command_scope() {
        Ok(owner) => owner,
        Err(error) => { ctx.dns_probe = Err(error); push_status(ctx, Scan::Settings); return; }
    };
    let receipt = owner.clone();
    start_readonly_probe_with(ctx, back, Some(receipt), move |cancel| {
        let measured = owner.with_result(measure_vpn);
        let observation = observation_owner.with_classified(|owner| observe_system(owner, cancel, image), observation_failure);
        let (vpn, relay_egress) = measured.unwrap_or((VpnSeen::Unmeasured, None));
        ProbeCompletion { vpn, relay_egress, observation }
    });
}

#[cfg(windows)]
fn start_readonly_probe_with(ctx: &mut Ctx, back: Sender<Cmd>,
    command_receipt: Option<crate::command_lifetime::PendingCommand>,
    query: impl FnOnce(&AtomicBool) -> ProbeCompletion + Send + 'static) {
    if ctx.vpn_job.is_some() || MEASURING_VPN.swap(true, Ordering::SeqCst) {

        return;
    }
    // GUI shutdown can cancel the query even while a native callback holds
    // Ctx. Mutation cancellation is a separate, possibly already-latched token.
    let cancel = ctx.lifetime.abort_requested.clone();
    let job_cancel = cancel.clone();
    match std::thread::Builder::new().name("vpn-probe".to_string()).spawn(move || {
        let completion = query(&cancel);
        MEASURING_VPN.store(false, Ordering::SeqCst);
        let _ = back.send(Cmd::Probed { vpn: VpnSeen::None, relay: false, relay_egress: None });
        completion
    }) {
        Ok(handle) => ctx.vpn_job = Some(ProbeJob { handle, valid: true, cancel: job_cancel, command_receipt }),
        Err(error) => {

            MEASURING_VPN.store(false, Ordering::SeqCst);
            ctx.dns_probe = Err(format!("Не удалось начать наблюдение службы: {error}"));
            push_status(ctx, Scan::Settings);
        }
    }
}

#[cfg(windows)]
fn invalidate_background_observation(ctx: &mut Ctx) {
    if let Some(job) = ctx.vpn_job.as_mut() { job.valid = false; }
    ctx.dns_probe = Err("Наблюдение устарело во время применения; требуется повторная проверка".into());
}

#[cfg(windows)]
fn receive_system_observation(ctx: &mut Ctx, observation: Result<WindowsSystemObservation, String>) {
    // A synchronous System/Deep read supersedes every query already in flight,
    // even when there was no mutation during either query.
    if let Some(job) = ctx.vpn_job.as_mut() { job.valid = false; }
    ctx.dns_probe = observation;
}

#[cfg(windows)]
fn dispatch_readonly_probe(
    shared: &Mutex<Ctx>, command: &mut Option<Cmd>, refresh_requested: &mut bool,
    native_active: bool, shutdown: bool, start: impl FnOnce(&mut Ctx),
) {
    match command {
        Some(Cmd::RemeasureVpn) => { *refresh_requested = true; *command = None; },
        // Every field is notification-only. An older notification may arrive
        // while a newer query is unfinished; it never supplies facts or a join.
        Some(Cmd::Probed { .. }) => { *command = None; },
        _ => {},
    }
    let stopping = shutdown || matches!(command, Some(Cmd::Shutdown | Cmd::Stop));
    // The actual native job may own Ctx. Keep the request latched until it
    // releases the guard; a logical native hold is deliberately not a gate.
    let Ok(mut ctx) = shared.try_lock() else { return; };
    if stopping {
        if let Some(job) = &ctx.vpn_job { job.cancel.store(true, Ordering::SeqCst); }
    }
    // Reap on the existing Core cadence even if the worker never notified us.
    if receive_probe_completion(&mut ctx) { *refresh_requested = true; }
    if *refresh_requested && !native_active && !stopping && ctx.vpn_job.is_none() {
        start(&mut ctx);
        *refresh_requested = false;
    }
}

fn begin_native_change(ctx: &mut Ctx, description: &str) {
    #[cfg(windows)]
    invalidate_background_observation(ctx);
    // Invalidation must precede the first published mutation-start event.
    ctx.busy(Some(description));
    push_status(ctx, Scan::Settings);
}

fn begin_owned_command(ctx: &mut Ctx, command: &Cmd) {
    let description = "Применение выбранного действия";
    if cfg!(windows) && matches!(command, Cmd::PatchInstall(_)) {
        // Patching this installation does not change background service state.
        ctx.busy(Some(description));
    } else {
        begin_native_change(ctx, description);
    }
}

#[cfg(windows)]
fn receive_shutdown_request(ctx: &mut Ctx, command: &Option<Cmd>) {
    if matches!(command, Some(Cmd::Shutdown | Cmd::Stop)) { ctx.begin_shutdown_attempt(); }
}

#[cfg(windows)]
fn observe_system(owner: &mut crate::utils::CommandOutcome, cancel: &AtomicBool, image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>) -> Result<WindowsSystemObservation, String> {
    if cancel.load(Ordering::SeqCst) { return Err("Наблюдение отменено до начала".into()); }
    let rules = dns::checked_nrpt_state(owner).map(|state| (state.core_applied, state.owned_rules_present));
    let (background, transport, transport_error) = match crate::settings::checked_transport_intent() {
        crate::settings::TransportIntent::Explicit { requirements, .. } => {
            match background::observe_background_for_transport(cancel, None, requirements.active_config) {
                Ok(received) => (Ok(received.background), Some((received.expected, received.dns, received.tcp_proxy, received.dns_alias, received.tcp_proxy_port)), None),
                Err(error) => (Err(error), None, None),
            }
        }
        crate::settings::TransportIntent::Legacy(_) => (background::observe_background(cancel, None, true, true), None, None),
        intent @ (crate::settings::TransportIntent::Missing | crate::settings::TransportIntent::Broken(_)) => {
            let error = match intent {
                crate::settings::TransportIntent::Missing => "Режим подключения ещё не выбран".into(),
                crate::settings::TransportIntent::Broken(error) => format!("Режим подключения не получен: {error}"),
                _ => unreachable!(),
            };
            (background::observe_background(cancel, None, false, false), None, Some(error))
        }
    };
    let selected_delivery = match image {
        Err(error) => Err(error),
        Ok(image) if background.is_ok() => background::selected_delivery_required(cancel, image),
        Ok(_) => Err("Сравнение пакета недоступно: состояние установленной службы не получено".into()),
    };
    Ok(WindowsSystemObservation { background, selected_delivery, rules, transport, transport_error })
}

#[cfg(windows)]
fn selected_delivery_unreceived(lifetime: &GuiLifetime) -> Result<bool, String> {
    Err(lifetime.retained_image().err().unwrap_or_else(|| "Сравнение выбранного пакета ещё не получено".into()))
}

#[cfg(windows)]
pub(crate) fn selected_delivery_warning(error: &str) -> String {
    let code = error.rsplit_once("os error ").and_then(|(_, tail)| {
        let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty()).then_some(digits)
    });
    match code {
        Some(code) => format!("Выбранный пакет не удалось сравнить (os error {code}); подробности сохранены в результате."),
        None => "Выбранный пакет не удалось сравнить; подробности сохранены в результате.".into(),
    }
}

#[cfg(windows)]
fn observation_failure(result: &Result<WindowsSystemObservation, String>) -> Option<String> {
    match result {
        Err(error) => Some(error.clone()),
        Ok(value) => {
            let mut errors = Vec::new();
            if let Err(error) = &value.rules { errors.push(format!("DNS: {error}")); }
            match &value.background {
                Err(error) => errors.push(format!("служба: {error}")),
                Ok(background) => {
                    if let Some(Err(error)) = &background.dns_ready { errors.push(format!("DNS: {error}")); }
                    if let Some(Err(error)) = &background.proxy_ready { errors.push(format!("TCP: {error}")); }
                }
            }
            if let Err(error) = &value.selected_delivery { errors.push(selected_delivery_warning(error)); }
            if let Some(error) = &value.transport_error { errors.push(format!("режим: {error}")); }
            if let Some((_, dns, tcp, alias, _)) = &value.transport {
                for (name, state) in [("DNS", dns), ("TCP", tcp), ("адреса", alias)] {
                    match state {
                        background::TransportChannelObservation::Unknown(error)
                        | background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Failed(error)) => errors.push(format!("{name}: {error}")),
                        _ => {}
                    }
                }
            }
            (!errors.is_empty()).then(|| errors.join("; "))
        }
    }
}

#[cfg(windows)]
fn initial_dns_probe() -> Result<WindowsSystemObservation, String> { Err("Состояние службы ещё не проверено".into()) }
#[cfg(not(windows))]
fn initial_dns_probe() -> (bool, bool) { (false, false) }
enum Startup {
    Ordinary,
    Explicit,
    Held(String),
    #[cfg(windows)]
    Resume(crate::instances::GuiApplyContinuation),
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacObservation {
    settled: Option<(patch_binary::MacTargetSnapshot, Option<bool>)>,
    pending: Option<patch_binary::MacTargetSnapshot>,
    pending_ready: bool,
}

#[cfg(target_os = "macos")]
fn mac_observe_install(path: &Path, deep: bool, observation: &mut MacObservation) -> Option<bool> {
    mac_observe_with(path, deep, observation, patch_binary::inspect_file)
}

#[cfg(target_os = "macos")]
fn mac_observe_with(path: &Path, deep: bool, observation: &mut MacObservation,
    mut inspect: impl FnMut(&Path) -> patch_binary::FileState) -> Option<bool> {
    let before = match patch_binary::mac_target_snapshot(path) {
        Ok(snapshot) => snapshot,
        Err(_) => { *observation = MacObservation::default(); return None; }
    };
    if !deep {
        if let Some((snapshot, result)) = &observation.settled {
            if snapshot == &before { return *result; }
        }
        if observation.pending.as_ref() != Some(&before) {
            observation.settled = None;
            observation.pending = Some(before);
            observation.pending_ready = false;
            return None;
        }
        if !observation.pending_ready { return None; }
    }
    let mut patched = !before.targets.is_empty();
    let mut unreadable = false;
    for (target, _) in &before.targets {
        match inspect(target) {
            patch_binary::FileState::Patched => {},
            patch_binary::FileState::Unreadable(_) => unreadable = true,
            _ => patched = false,
        }
    }
    let result = if unreadable || before.targets.is_empty() { None } else { Some(patched) };
    match patch_binary::mac_target_snapshot(path) {
        Ok(after) if after == before => {
            observation.settled = Some((before, result));
            observation.pending = None;
            observation.pending_ready = false;
            result
        },
        _ => { *observation = MacObservation::default(); None }
    }
}

enum NativeCompletion {
    Retired,
    #[cfg(windows)]
    InstallationRecoveryChecked(Option<InstallationRecoveryProposal>),
    #[cfg(windows)]
    NeedsElevation(crate::instances::GuiApplyContinuation),
    #[cfg(windows)]
    Held(String),
}

/// How much of the system a refresh is allowed to ask about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scan {
    /// Everything, including reading every Language Server binary end to end and
    /// re-measuring where the client's traffic leaves.
    Deep,
    /// Everything the system can be asked cheaply: tasks, rules, the proxy
    /// variable. Not the binaries.
    System,
    /// Installation discovery only, using cached patch observations.
    #[cfg(windows)]
    Installations,
    /// Nothing from the system. The last snapshot with the settings-derived
    /// fields recomputed — instant, and correct exactly for the switches that
    /// change nothing but a line in `settings.json`.
    Settings,
}

impl Ctx {
    fn with_command<T>(&self, action: impl FnOnce(&mut crate::utils::CommandOutcome) -> Result<T, String>) -> Result<T, String> {
        let scope = self.lifetime.new_command_scope()?;
        let result = scope.with_result(action);
        self.receive_command_results();
        result
    }
    fn receive_command_results(&self) {
        self.lifetime.receive_command_results();
        let batch = self.lifetime.take_command_result_batch();
        if !batch.is_empty() {
            // This current operation-result batch is committed before optional
            // GUI presentation. A later batch replaces already received facts,
            // rather than overwriting another unreceived operation in the root.
            let mut current = self.received_command_results.lock().unwrap_or_else(|error| error.into_inner());
            *current = batch;
            for error in current.iter() { self.log(Level::Warn, error.clone()); }
        }
    }
    fn proxy_env_is_ours(&self) -> Result<bool, String> {
        #[cfg(windows)]
        { self.with_command(endpoint::proxy_env_is_ours) }
        #[cfg(not(windows))]
        { Ok(endpoint::proxy_env_is_ours()) }
    }
    fn log(&self, level: Level, msg: impl Into<String>) {
        if self.events.send(Event::Log(level, msg.into())).is_err() { self.lifetime.channel_lost.store(true, Ordering::SeqCst); }
        if let Ok(wake) = self.wake.lock() { (wake)(); }
    }
    #[cfg(windows)]
    fn retain_background_receiving(&mut self, receiving: background::BackgroundReceiving) -> Result<(), String> {
        self.background_receivings.push(receiving);
        if let Some(payload) = self.background_receivings.last_mut().unwrap().take_pending_unwind() {
            std::panic::resume_unwind(payload);
        }
        // Store the packet before settlement: a panic must not discard the
        // only owner of any native resources that settlement has not released.
        let finishes = self.background_receivings.last_mut().unwrap().finish_live_resources();
        let result = self.background_receivings.last().unwrap().result.clone();
        for finish in finishes {
            match finish {
                Ok(evidence) => self.log(Level::Info, format!("Ресурс операции сохранён: {evidence}")),
                Err(cause) => self.log(Level::Warn, format!("Ресурс операции ожидает завершения: {cause}")),
            }
        }
        result
    }
    #[cfg(windows)]
    fn finish_background_resources(&mut self) -> bool {
        // A held native disposition is retried only on a new shutdown request,
        // not on every worker polling iteration.
        if self.background_finish_reported { return false; }
        let mut results = Vec::new();
        for receiving in &mut self.background_receivings { results.extend(receiving.finish_live_resources()); }
        let mut held = Vec::new();
        for result in results {
            match result {
                Ok(evidence) => self.log(Level::Info, format!("Ресурс операции сохранён: {evidence}")),
                Err(cause) => held.push(cause),
            }
        }
        if held.is_empty() { self.background_finish_reported = false; return true; }
        if !self.background_finish_reported {
            self.log(Level::Err, format!("Завершение ожидает сохранения ресурса операции: {}", held.join("; ")));
            self.background_finish_reported = true;
        }
        false
    }
    #[cfg(windows)]
    fn begin_shutdown_attempt(&mut self) { self.background_finish_reported = false; }
    fn poll_wsl_report(&mut self) -> bool {
        let Some(diagnostics) = self.wsl.poll() else { return false; };
        for diagnostic in diagnostics { self.log(Level::Err, diagnostic); }
        true
    }
    fn busy(&self, what: Option<&str>) {
        self.emit(Event::Busy(what.map(|s| s.to_string())));
    }
    fn emit(&self, event: Event) {
        emit_worker_event(&self.events, &self.wake, &self.lifetime, event);
    }
}

fn emit_worker_event(events: &Sender<Event>, wake: &Mutex<Box<dyn Fn() + Send>>, lifetime: &GuiLifetime, event: Event) {
    if events.send(event).is_err() { lifetime.channel_lost.store(true, Ordering::SeqCst); }
    if let Ok(wake) = wake.lock() { (wake)(); }
}

#[cfg(all(test, windows))]
pub(crate) fn test_forward_wsl_diagnostic(events: Sender<Event>, error: String) -> bool {
    let lifetime = Arc::new(GuiLifetime::default());
    let mut ctx = Ctx { received_command_results: Mutex::new(Vec::new()), events, wake: Arc::new(Mutex::new(Box::new(|| {}))), settings: Settings::default(),
        wsl: crate::wsl_controller::test_pending_diagnostic(error), native_apply_pending: Arc::new(AtomicBool::new(false)),
        native_cancel: Arc::new(AtomicBool::new(false)), background_receivings: Vec::new(), #[cfg(windows)] background_finish_reported: false, lifetime: lifetime.clone(),
        vpn_job: None, vpn_unsettled: false, startup: Startup::Ordinary, proxy_var_carried: None,
        proxy_var_retryable: false, patched_seen: HashMap::new(), vpn: None, relay_egress: None,
        last: None, dns_probe: initial_dns_probe(), carrier_set_proxy: false };
    while !ctx.poll_wsl_report() { std::thread::yield_now(); }
    assert!(!ctx.poll_wsl_report());
    lifetime.channel_lost.load(Ordering::SeqCst)
}

/// True while a VPN measurement is out at a thread. One at a time: the watcher
/// can ask again before the last answer is back, and two PowerShell probes
/// racing produce the same answer twice at twice the cost.
static MEASURING_VPN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn receive_wsl_refresh_command(requested: &mut Option<DiscoveryOrigin>, command: &Option<Cmd>) -> bool {
    match command {
        Some(Cmd::RefreshWsl) => { *requested = Some(DiscoveryOrigin::Manual); true }
        Some(Cmd::CancelWsl | Cmd::Shutdown | Cmd::Stop) => { *requested = None; false }
        _ => false,
    }
}

// Consume one coalesced presentation request only when the existing owner can start it.
fn take_wsl_refresh(
    requested: &mut Option<DiscoveryOrigin>, available: bool, command: &Option<Cmd>, first_command: &Option<Cmd>,
) -> Option<DiscoveryOrigin> {
    if available && command.is_none() && first_command.is_none() { requested.take() } else { None }
}

#[cfg(all(windows, ag_private_startup_scan_timing))]
pub(crate) mod startup_scan_timing {
    use super::{patch_binary, DesktopDiscovery};
    use serde::Serialize;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, HashMap};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{FILETIME, GetLastError};
    use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};

    thread_local! {
        static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) };
    }

    enum Active {
        Startup { origin: Instant, install: Option<InstallTiming> },
        InstallWorker(InstallTiming),
    }

    pub(super) struct InstallTiming {
        origin: Instant,
        discovery_and_classification: Option<Classification>,
        row_count: usize,
        inspections: Vec<RowInspection>,
        discovery_phases: [Option<PhaseSample>; PHASES.len()],
        registry_script: Option<&'static str>,
        active_row: Option<usize>,
        file_coverage: FileCoverage,
    }

    #[derive(Clone, Copy)]
    pub(crate) enum DiscoveryPhase {
        RegistryHelper,
        RegistryAcceptance,
        RegistryDecode,
        RegistryDirectories,
        CandidateResolution,
        LocalClassification,
    }

    const PHASES: [(DiscoveryPhase, &str); 6] = [
        (DiscoveryPhase::RegistryHelper, "registry_helper"),
        (DiscoveryPhase::RegistryAcceptance, "registry_acceptance"),
        (DiscoveryPhase::RegistryDecode, "registry_decode"),
        (DiscoveryPhase::RegistryDirectories, "registry_directories"),
        (DiscoveryPhase::CandidateResolution, "candidate_resolution"),
        (DiscoveryPhase::LocalClassification, "local_classification"),
    ];

    #[derive(Serialize)]
    struct PhaseSample {
        status: &'static str,
        span: Span,
    }

    pub(crate) struct PhaseGuard {
        phase: DiscoveryPhase,
        start: Option<Mark>,
    }

    pub(crate) fn record_registry_script(script: crate::RegistryScript, same_image: bool) {
        let selected = match (same_image, script) {
            (true, _) => "winreg_helper",
            (false, crate::RegistryScript::Provider) => "provider",
            (false, crate::RegistryScript::Managed) => "managed",
        };
        with_install(|timing| timing.registry_script = Some(selected));
    }

    pub(crate) fn discovery_phase(phase: DiscoveryPhase) -> PhaseGuard {
        PhaseGuard { phase, start: install_mark() }
    }

    impl PhaseGuard {
        pub(crate) fn finish(mut self, received: bool) {
            self.record(if received { "received" } else { "unreceived" });
        }

        fn record(&mut self, status: &'static str) {
            if let Some(start) = self.start.take() {
                with_install(|timing| {
                    let span = start.finish(timing.origin);
                    timing.discovery_phases[self.phase as usize] = Some(PhaseSample { status, span });
                });
            }
        }
    }

    impl Drop for PhaseGuard {
        fn drop(&mut self) {
            self.record("unreceived");
        }
    }

    #[derive(Default)]
    struct FileCoverage {
        attempts: usize,
        opened: usize,
        unknown: usize,
        query_wall_ns: u128,
        by_identity: HashMap<(u64, [u8; 16]), Vec<usize>>,
    }

    impl FileCoverage {
        fn observe(&mut self, row_index: usize, file: &File) {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandleEx, FileIdInfo, FILE_ID_INFO};
            self.opened += 1;
            let mut info = FILE_ID_INFO::default();
            let start = Instant::now();
            // This is the File already opened by inspect_file_stream.
            let ok = unsafe {
                GetFileInformationByHandleEx(file.as_raw_handle(), FileIdInfo,
                    (&mut info as *mut FILE_ID_INFO).cast(), std::mem::size_of::<FILE_ID_INFO>() as u32)
            };
            self.query_wall_ns += start.elapsed().as_nanos();
            if ok == 0 || info.FileId.Identifier == [0; 16] {
                self.unknown += 1;
                return;
            }
            let rows = self.by_identity.entry((info.VolumeSerialNumber, info.FileId.Identifier)).or_default();
            if rows.last() != Some(&row_index) {
                rows.push(row_index);
            }
        }

        fn receipt(&self) -> serde_json::Value {
            let open_failed = self.attempts.checked_sub(self.opened);
            let status = match (self.attempts, open_failed, self.by_identity.is_empty(), self.unknown) {
                (_, None, _, _) => "inconsistent",
                (0, Some(0), _, _) => "not_attempted",
                (_, _, true, _) => "unavailable",
                (_, Some(0), false, 0) => "complete",
                _ => "partial",
            };
            let mut overlap_groups = BTreeMap::<&[usize], usize>::new();
            for rows in self.by_identity.values().filter(|rows| rows.len() > 1) {
                *overlap_groups.entry(rows.as_slice()).or_default() += 1;
            }
            let overlap_groups: Vec<_> = overlap_groups.into_iter().map(|(row_indices, distinct_known_identities)| {
                serde_json::json!({ "row_indices": row_indices, "distinct_known_identities": distinct_known_identities })
            }).collect();
            serde_json::json!({
                "status": status,
                "open_attempts": self.attempts,
                "opened": self.opened,
                "open_failed": open_failed,
                "identity_unavailable": self.unknown,
                "distinct_known_identities": self.by_identity.len(),
                "overlap_groups": overlap_groups,
                "identity_query_wall_ns": self.query_wall_ns,
            })
        }
    }

    pub(crate) fn observe_inspect_handle(file: &File) {
        with_install(|timing| {
            if let Some(row_index) = timing.active_row {
                timing.file_coverage.observe(row_index, file);
            }
        });
    }

    #[derive(Serialize)]
    struct Classification {
        span: Span,
        outcome: ClassificationOutcome,
    }

    #[derive(Serialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    enum ClassificationOutcome {
        Absent,
        Present,
        Incomplete { desktop_found: bool },
    }

    #[derive(Serialize)]
    struct RowInspection {
        row_index: usize,
        span: Span,
        outcome: InspectionOutcome,
    }

    #[derive(Serialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    enum InspectionOutcome {
        Empty,
        Observed { unreadable_results: usize, signature_missing_results: usize },
    }

    pub(super) struct Mark {
        wall: Instant,
        cpu: Result<ThreadCpu, u32>,
    }

    struct ThreadCpu {
        user: u64,
        kernel: u64,
    }

    #[derive(Serialize)]
    struct Span {
        start_offset_ns: u128,
        end_offset_ns: u128,
        wall_ns: u128,
        cpu: CpuDelta,
    }

    #[derive(Serialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    enum CpuDelta {
        Received { user_100ns: u64, kernel_100ns: u64 },
        ReadFailure { start_os_error: Option<u32>, end_os_error: Option<u32> },
        CounterRegressed,
    }

    fn current_thread_cpu() -> Result<ThreadCpu, u32> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // GetCurrentThread returns the pseudo-handle for this calling thread.
        let ok = unsafe {
            GetThreadTimes(GetCurrentThread(), &mut creation, &mut exit, &mut kernel, &mut user)
        };
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        let ticks = |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        Ok(ThreadCpu { user: ticks(user), kernel: ticks(kernel) })
    }

    impl Mark {
        pub(super) fn start() -> Self {
            let cpu = current_thread_cpu();
            Self { wall: Instant::now(), cpu }
        }

        fn finish(self, origin: Instant) -> Span {
            let end = Instant::now();
            let cpu = match (self.cpu, current_thread_cpu()) {
                (Ok(start), Ok(end)) => match (end.user.checked_sub(start.user), end.kernel.checked_sub(start.kernel)) {
                    (Some(user_100ns), Some(kernel_100ns)) => CpuDelta::Received { user_100ns, kernel_100ns },
                    _ => CpuDelta::CounterRegressed,
                },
                (start, end) => CpuDelta::ReadFailure {
                    start_os_error: start.err(),
                    end_os_error: end.err(),
                },
            };
            Span {
                start_offset_ns: self.wall.duration_since(origin).as_nanos(),
                end_offset_ns: end.duration_since(origin).as_nanos(),
                wall_ns: end.duration_since(self.wall).as_nanos(),
                cpu,
            }
        }
    }

    impl InstallTiming {
        pub(super) fn new(origin: Instant) -> Self {
            Self {
                origin, discovery_and_classification: None, row_count: 0, inspections: Vec::new(),
                discovery_phases: Default::default(), registry_script: None,
                active_row: None, file_coverage: FileCoverage::default(),
            }
        }

        pub(super) fn classify(&mut self, start: Mark, row_count: usize, target: &DesktopDiscovery) {
            let span = start.finish(self.origin);
            let outcome = match target {
                DesktopDiscovery::Absent => ClassificationOutcome::Absent,
                DesktopDiscovery::Present => ClassificationOutcome::Present,
                DesktopDiscovery::Incomplete { desktop_found, .. } =>
                    ClassificationOutcome::Incomplete { desktop_found: *desktop_found },
            };
            self.discovery_and_classification = Some(Classification { span, outcome });
            self.row_count = row_count;
        }

        fn inspect(&mut self, start: Mark, row_index: usize, state: &patch_binary::InstallState) {
            let span = start.finish(self.origin);
            self.active_row = None;
            self.file_coverage.attempts += state.files.len();
            let outcome = if state.is_empty() {
                InspectionOutcome::Empty
            } else {
                let mut unreadable_results = 0;
                let mut signature_missing_results = 0;
                for (_, file_state) in &state.files {
                    match file_state {
                        patch_binary::FileState::Unreadable(_) => unreadable_results += 1,
                        patch_binary::FileState::SignatureMissing => signature_missing_results += 1,
                        patch_binary::FileState::Patched | patch_binary::FileState::Unpatched => {}
                    }
                }
                InspectionOutcome::Observed { unreadable_results, signature_missing_results }
            };
            self.inspections.push(RowInspection { row_index, span, outcome });
        }

        fn discovery_receipt(&self) -> serde_json::Value {
            let phases: serde_json::Map<_, _> = PHASES.into_iter().map(|(phase, name)| {
                let status = match &self.discovery_phases[phase as usize] {
                    Some(sample) => serde_json::json!(sample),
                    None => serde_json::json!({ "status": "not_reached" }),
                };
                (name.to_owned(), status)
            }).collect();
            serde_json::Value::Object(phases)
        }
    }

    fn with_install<T>(visit: impl FnOnce(&mut InstallTiming) -> T) -> Option<T> {
        ACTIVE.with(|active| {
            match active.try_borrow_mut().ok()?.as_mut()? {
                Active::InstallWorker(timing) => Some(visit(timing)),
                Active::Startup { .. } => None,
            }
        })
    }

    // The parent passes the origin explicitly; TLS is separate on the child thread.
    pub(super) struct InstallScope;

    pub(super) fn begin_install(origin: Option<Instant>) -> Option<InstallScope> {
        let origin = origin?;
        ACTIVE.with(|active| {
            *active.borrow_mut() = Some(Active::InstallWorker(InstallTiming::new(origin)));
        });
        Some(InstallScope)
    }

    impl InstallScope {
        pub(super) fn take(self) -> Option<InstallTiming> {
            ACTIVE.with(|active| match active.borrow_mut().take() {
                Some(Active::InstallWorker(timing)) => Some(timing),
                _ => None,
            })
        }
    }

    impl Drop for InstallScope {
        fn drop(&mut self) {
            ACTIVE.with(|active| *active.borrow_mut() = None);
        }
    }

    pub(super) fn install_mark() -> Option<Mark> {
        with_install(|_| Mark::start())
    }

    pub(super) fn record_classification(start: Option<Mark>, row_count: usize, target: &DesktopDiscovery) {
        if let Some(start) = start {
            with_install(|timing| timing.classify(start, row_count, target));
        }
    }

    pub(super) fn inspect_start(row_index: usize) -> Option<Mark> {
        with_install(|timing| {
            timing.active_row = Some(row_index);
            Mark::start()
        })
    }

    pub(super) fn inspect_end(start: Option<Mark>, row_index: usize, state: &patch_binary::InstallState) {
        if let Some(start) = start {
            with_install(|timing| timing.inspect(start, row_index, state));
        }
    }

    pub(super) fn begin() -> Mark {
        let start = Mark::start();
        ACTIVE.with(|active| {
            *active.borrow_mut() = Some(Active::Startup { origin: start.wall, install: None });
        });
        start
    }

    pub(super) fn install_origin() -> Option<Instant> {
        ACTIVE.with(|active| match active.borrow().as_ref() {
            Some(Active::Startup { origin, .. }) => Some(*origin),
            _ => None,
        })
    }

    pub(super) fn receive_install(install: Option<InstallTiming>) {
        if let Some(install) = install {
            ACTIVE.with(|active| {
                if let Some(Active::Startup { install: receipt, .. }) = active.borrow_mut().as_mut() {
                    *receipt = Some(install);
                }
            });
        }
    }

    pub(super) fn finish(start: Mark) {
        let origin = start.wall;
        let startup = start.finish(origin);
        let install = ACTIVE.with(|active| match active.borrow_mut().take() {
            Some(Active::Startup { install, .. }) => install,
            _ => None,
        });
        if write_receipt(startup, install).is_err() {
            let _ = io::stderr().lock().write_all(b"Startup scan timing receipt unavailable.\n");
        }
    }

    fn write_receipt(startup: Span, install: Option<InstallTiming>) -> io::Result<()> {
        let install = match install {
            Some(install) => serde_json::json!({
                "status": "received",
                "discovery_phases": install.discovery_receipt(),
                "registry_script": install.registry_script,
                "file_coverage": install.file_coverage.receipt(),
                "discovery_and_classification": install.discovery_and_classification,
                "row_count": install.row_count,
                "inspect_invocations": install.inspections.len(),
                "inspections": install.inspections,
            }),
            None => serde_json::json!({ "status": "unreceived" }),
        };
        let receipt = serde_json::json!({
            "schema": 2,
            "identity_query_basis": "same-handle identity work is inside row spans; identity_query_wall_ns sums only native identity calls",
            "wall_basis": "monotonic offsets from startup push_status entry",
            "cpu_basis": "same-thread counters sampled just before wall start and just after wall end",
            "startup_push_status": startup,
            "install_worker": install,
        });
        let bytes = serde_json::to_vec(&receipt)?;
        let mut file = OpenOptions::new().write(true).create_new(true).open("startup-scan-timing.json")?;
        file.write_all(&bytes)?;
        file.sync_all()
    }
}

fn run_worker(
    rx: Receiver<Cmd>,
    own: Sender<Cmd>,
    events: Sender<Event>,
    wake: Box<dyn Fn() + Send>,
    lifetime: Arc<GuiLifetime>,
) {
    let owner_events = events.clone();
    let owner_wake = Arc::new(Mutex::new(wake));
    let native_apply_pending = Arc::new(AtomicBool::new(false));
    let native_cancel = Arc::new(AtomicBool::new(false));
    let Some((settings, startup, mut first_command)) = worker_boot(&rx, &owner_events, &owner_wake, &lifetime) else { return; };
    let mut ctx = Ctx { received_command_results: Mutex::new(Vec::new()),
        events,
        wake: owner_wake.clone(),
        settings,
        wsl: crate::wsl_controller::WslController::default(),
        native_apply_pending: native_apply_pending.clone(),
        native_cancel: native_cancel.clone(),
        #[cfg(windows)]
        background_receivings: Vec::new(), #[cfg(windows)] background_finish_reported: false,
        lifetime: lifetime.clone(),
        vpn_job: None,
        vpn_unsettled: false,
        startup,
        proxy_var_carried: None,
        proxy_var_retryable: false,
        patched_seen: HashMap::new(),
        vpn: None,
        relay_egress: None,
        last: None,
        dns_probe: initial_dns_probe(),
        carrier_set_proxy: false,
    };

    if matches!(ctx.startup, Startup::Ordinary) {
        settle_decline(&mut ctx);
        startup_housekeeping(&mut ctx);
    }

    // The first snapshot is deep: the window opens on the licence screen, so
    // reading the binaries costs the user nothing here and the main screen is
    // already truthful when it appears.
    #[cfg(all(windows, ag_private_startup_scan_timing))]
    let startup_scan_mark = startup_scan_timing::begin();
    push_status(&mut ctx, Scan::Deep);
    #[cfg(all(windows, ag_private_startup_scan_timing))]
    startup_scan_timing::finish(startup_scan_mark);

    let shared = Arc::new(Mutex::new(ctx));
    let mut native_job: Option<std::thread::JoinHandle<Result<NativeCompletion, String>>> = None;
    #[cfg(windows)]
    let mut installation_recovery: Option<InstallationRecoveryProposal> = None;
    #[cfg(windows)]
    let mut unlocked = false;
    let mut shutdown = false;
    let mut refresh_requested = cfg!(windows).then_some(DiscoveryOrigin::Startup);
    let mut native_unsettled = false;
    #[cfg(windows)]
    let mut probe_refresh_requested = true;
    #[cfg(target_os = "macos")]
    let mut last_mac_observation = std::time::Instant::now();
    let mut last_vscode_observation = std::time::Instant::now();
    #[cfg(windows)]
    let mut elevation_progress: Option<Receiver<crate::instances::ElevationProgress>> = None;
    loop {
        lifetime.receive_command_results();
        let mut native_finished = false;
        #[cfg(windows)]
        let mut native_hold = None;
        #[cfg(windows)]
        let mut recovery_checked = None;
        #[cfg(windows)]
        if let Some(progress) = elevation_progress.as_ref() {
            while let Ok(progress) = progress.try_recv() {
                let event = match progress {
                    crate::instances::ElevationProgress::WaitingForConsent => Event::Busy(Some("Ожидание подтверждения администратора".into())),
                    crate::instances::ElevationProgress::WaitingForReplacement => Event::Busy(Some("Подготовка нового окна".into())),
                    crate::instances::ElevationProgress::ObservationPending(error) => Event::Log(Level::Warn, format!("Ожидается завершение передачи окна: {error}")),
                };
                if owner_events.send(event).is_err() { lifetime.channel_lost.store(true, Ordering::SeqCst); }
                if let Ok(wake) = owner_wake.lock() { (wake)(); }
            }
        }
        let mut command = if let Some(command) = first_command.take() { Some(command) } else { match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(command) => Some(command),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => { shutdown = true; None },
        } };
        #[cfg(windows)]
        if receive_installation_recovery_dismissal(&mut installation_recovery, &mut command) {
            emit_worker_event(&owner_events, &owner_wake, &lifetime, Event::InstallationRecoveryClosed);
        }
        if receive_wsl_refresh_command(&mut refresh_requested, &command) { command = None; }
        if native_job.as_ref().is_some_and(|job| job.is_finished()) {
            match native_job.take().unwrap().join() {
                Ok(Ok(completion)) => {
                    native_apply_pending.store(false, Ordering::SeqCst);
                    native_finished = true;
                    match completion {
                        NativeCompletion::Retired => {},
                        #[cfg(windows)]
                        NativeCompletion::InstallationRecoveryChecked(prepared) => recovery_checked = Some(prepared),
                        #[cfg(windows)]
                        NativeCompletion::NeedsElevation(intent) => {
                            if !native_cancel.load(Ordering::SeqCst)
                                && !lifetime.abort_requested.load(Ordering::SeqCst)
                                && !lifetime.channel_lost.load(Ordering::SeqCst) {
                                first_command = Some(Cmd::Elevate(crate::instances::GuiReplacementAction::ResumeApply(intent)));
                            }
                        },
                        #[cfg(windows)]
                        NativeCompletion::Held(reason) => native_hold = Some(reason),
                    }
                },
                Ok(Err(error)) => {
                    native_apply_pending.store(false, Ordering::SeqCst);
                    native_finished = true;
                    let _ = owner_events.send(Event::Log(Level::Err, error));
                }
                Err(payload) => {
                    lifetime.command_panics.lock().unwrap_or_else(|error| error.into_inner()).push(payload);
                    native_unsettled = true;
                    let _ = owner_events.send(Event::Log(Level::Err, "Наблюдение применения прервано; требуется восстановление.".into()));
                }
            }
            #[cfg(windows)]
            { elevation_progress = None; }
        }
        if lifetime.abort_requested.load(Ordering::SeqCst) || lifetime.channel_lost.load(Ordering::SeqCst) {
            native_cancel.store(true, Ordering::SeqCst);
            shutdown = true;
        }
        if lifetime.handoff_requested.load(Ordering::SeqCst) { shutdown = true; }
        #[cfg(windows)]
        dispatch_readonly_probe(&shared, &mut command, &mut probe_refresh_requested,
            native_job.is_some(), shutdown, |ctx| start_readonly_probe(ctx, own.clone()));
        if native_job.is_some() || native_unsettled {
            match command {
                Some(Cmd::CancelWsl) => native_cancel.store(true, Ordering::SeqCst),
                Some(Cmd::Shutdown | Cmd::Stop) => { native_cancel.store(true, Ordering::SeqCst); shutdown = true; },
                #[cfg(not(windows))]
                Some(probed @ Cmd::Probed { .. }) => {
                    MEASURING_VPN.store(false, Ordering::SeqCst);
                    let _ = probed;
                },
                Some(_) => { let _ = owner_events.send(Event::Log(Level::Warn, "Подождите завершения применения настроек.".into())); },
                None => {},
            }
            if let Ok(wake) = owner_wake.lock() { (wake)(); }
            continue;
        }
        let mut ctx = match shared.lock() {
            Ok(ctx) => ctx,
            Err(_) => { native_unsettled = true; continue; },
        };
        #[cfg(windows)]
        if let Some(reason) = native_hold { hold_apply(&mut ctx, reason); }
    #[cfg(not(windows))]
    if ctx.vpn_job.as_ref().is_some_and(|job| job.handle.is_finished()) {
            let job = ctx.vpn_job.take().unwrap();
            let outcome = job.handle.join();

            ctx.receive_command_results();
            MEASURING_VPN.store(false, Ordering::SeqCst);
            match outcome {
                Ok((vpn, relay, relay_egress)) => {
                    let before = ctx.vpn;
                    ctx.vpn = Some(vpn);
                    ctx.relay_egress = relay_egress;
                    if before.is_some() && before != ctx.vpn {
                        if let Some(line) = vpn_change_line(vpn) { ctx.log(Level::Info, line); }
                    }
                    ctx.dns_probe.1 = relay;
                    push_status(&mut ctx, Scan::Settings);
                }
                Err(_) => { ctx.vpn_unsettled = false; ctx.log(Level::Err, "Наблюдение проверки сети прервано."); }
            }
        }
        if native_finished {
            push_status(&mut ctx, Scan::Settings);
            if !ctx.wsl.is_pending() && !lifetime.handoff_requested.load(Ordering::SeqCst) { ctx.busy(None); }
        }
        if ctx.poll_wsl_report() {
            push_status(&mut ctx, Scan::Settings);
            if !ctx.wsl.is_pending() { ctx.busy(None); }
            #[cfg(windows)]
            if ctx.wsl.take_elevation_request() && !shutdown
                && !native_cancel.load(Ordering::SeqCst) {
                ctx.log(Level::Err, "Права изменились после начала применения. Оставшиеся действия WSL остановлены; проверьте результат и повторите «Применить».");
            }
        }
        #[cfg(windows)]
        receive_shutdown_request(&mut ctx, &command);
        if shutdown {
            #[cfg(windows)]
            drop(installation_recovery.take());
            ctx.wsl.request_cancel();
            if finish_shutdown(&mut ctx, &lifetime) { return; }
            continue;
        }
        #[cfg(windows)]
        if let Some(prepared) = recovery_checked {
            receive_prepared_installation_recovery(&ctx, &mut installation_recovery, &command, prepared, |proposal| {
                recheck_installation_recovery_input(&ctx.settings, proposal.saved_sha256, &ctx.native_cancel, &ctx.lifetime)
            });
        }
        if let Some(origin) = take_wsl_refresh(&mut refresh_requested, !ctx.wsl.is_pending(), &command, &first_command) {
            if let Err(error) = ctx.wsl.request_discovery(origin) { ctx.log(Level::Warn, error); }
            #[cfg(windows)]
            push_status(&mut ctx, match origin {
                DiscoveryOrigin::Startup => Scan::System,
                DiscoveryOrigin::Manual => Scan::Installations,
            });
            #[cfg(not(windows))]
            push_status(&mut ctx, Scan::Settings);
        }
        #[cfg(target_os = "macos")]
        if command.is_none() && first_command.is_none() && !ctx.wsl.is_pending()
            && !matches!(ctx.startup, Startup::Held(_)) && !ctx.vpn_unsettled && ctx.vpn_job.is_none()
            && !MEASURING_VPN.load(Ordering::SeqCst) && last_mac_observation.elapsed() >= crate::watchdog::POLL {
            last_mac_observation = std::time::Instant::now();
            if let Some(rows) = mac_idle_observation(&mut ctx) { push_mac_idle_status(&mut ctx, rows); }
        }
        if !matches!(command, Some(Cmd::Shutdown | Cmd::Stop)) {
            if let Some(status) = ctx.last.as_mut() {
                if let Some(observation) = poll_vscode_antigravity(
                    &mut last_vscode_observation, std::time::Instant::now(),
                    status.vscode_antigravity, observe_current_vscode_antigravity,
                ) {
                    status.vscode_antigravity = observation;
                    let snapshot = Box::new(status.clone());
                    ctx.emit(Event::Status(snapshot));
                }
            }
        }
        let Some(cmd) = command else { continue; };
        #[cfg(windows)]
        let cmd = match cmd {
            Cmd::Unlocked => { unlocked = true; Cmd::Unlocked },
            Cmd::PrepareInstallationRecovery { path } => {
                drop(installation_recovery.take());
                ctx.emit(Event::InstallationRecoveryClosed);
                if !unlocked || ctx.wsl.is_pending() || ctx.vpn_unsettled {
                    ctx.log(Level::Warn, "Проверка восстановления сейчас недоступна.");
                    continue;
                }
                native_cancel.store(false, Ordering::SeqCst);
                native_apply_pending.store(true, Ordering::SeqCst);
                ctx.busy(Some("Проверка восстановления Desktop"));
                push_status(&mut ctx, Scan::Settings);
                let settings = ctx.settings.clone();
                let cancellation = native_cancel.clone();
                let job_lifetime = lifetime.clone();
                let (events, wake) = (owner_events.clone(), owner_wake.clone());
                native_job = match std::thread::Builder::new().name("installation-recovery-check".into()).spawn(move || {
                    prepare_installation_recovery(&path, &settings, &cancellation, &job_lifetime, |lease| {
                        emit_worker_event(&events, &wake, &job_lifetime,
                            Event::Busy(Some(installation_recovery_wait_text(lease).into())));
                    }).map(NativeCompletion::InstallationRecoveryChecked)
                        .map_err(|error| format!("Не удалось проверить восстановление Desktop: {error}"))
                }) {
                    Ok(job) => Some(job),
                    Err(error) => {
                        native_apply_pending.store(false, Ordering::SeqCst);
                        ctx.log(Level::Err, format!("Не удалось начать проверку восстановления Desktop: {error}"));
                        ctx.busy(None);
                        push_status(&mut ctx, Scan::Settings);
                        None
                    }
                };
                continue;
            }
            Cmd::ConfirmInstallationRecovery { proposal_id } => {
                let proposal = match take_installation_recovery(&mut installation_recovery, &proposal_id) {
                    Ok(proposal) => proposal,
                    Err(error) => { ctx.log(Level::Warn, error); continue; }
                };
                ctx.emit(Event::InstallationRecoveryClosed);
                if !unlocked || ctx.wsl.is_pending() || ctx.vpn_unsettled {
                    ctx.log(Level::Warn, "Восстановление сейчас недоступно. Проверьте выбранную установку снова.");
                    continue;
                }
                native_cancel.store(false, Ordering::SeqCst);
                native_apply_pending.store(true, Ordering::SeqCst);
                ctx.busy(Some("Восстановление метаданных Desktop"));
                push_status(&mut ctx, Scan::Settings);
                let shared = shared.clone();
                native_job = match std::thread::Builder::new().name("installation-recovery".into()).spawn(move || {
                    let ctx = shared.lock().map_err(|_| "installation recovery owner lock was poisoned".to_owned())?;
                    run_ctx_job(ctx, |ctx| complete_installation_recovery(ctx, proposal))
                }) {
                    Ok(job) => Some(job),
                    Err(error) => {
                        native_apply_pending.store(false, Ordering::SeqCst);
                        ctx.log(Level::Err, format!("Не удалось начать восстановление Desktop: {error}"));
                        ctx.busy(None);
                        push_status(&mut ctx, Scan::Settings);
                        None
                    }
                };
                continue;
            }
            command => command,
        };
        if matches!(ctx.startup, Startup::Held(_)) && !matches!(&cmd, Cmd::Shutdown | Cmd::Stop | Cmd::CancelWsl) {
            if !genuine_command(&cmd) { continue; }
            if crate::settings::saved_intent_sha256(&ctx.settings).is_err() {
                if let Some(display) = saved_display() { ctx.settings = display; push_status(&mut ctx, Scan::Settings); }
                ctx.log(Level::Err, "Настройки снова изменились; автоматическое применение не выполняется.");
                continue;
            }
            if let Err(error) = lifetime.clear_automatic_hold() { ctx.log(Level::Err, error); continue; }
            ctx.startup = Startup::Explicit;
            ctx.log(Level::Info, "Принят новый выбор пользователя; прежнее продолжение не повторяется.");
        }
        if ctx.wsl.is_applying() && !matches!(&cmd, Cmd::CancelWsl | Cmd::Shutdown | Cmd::Stop | Cmd::Probed { .. }) {
            ctx.log(Level::Warn, "Подождите завершения подготовки WSL.");
            continue;
        }
        match cmd {
            #[cfg(windows)]
            Cmd::PrepareInstallationRecovery { .. } | Cmd::ConfirmInstallationRecovery { .. }
            | Cmd::DismissInstallationRecovery { .. } => unreachable!("selected recovery is received before startup hold clearing"),
            Cmd::RequestElevation => {
                #[cfg(windows)]
                { first_command = Some(Cmd::Elevate(crate::instances::GuiReplacementAction::ShowMain {})); }
                #[cfg(not(windows))]
                ctx.log(Level::Warn, "Передача Windows-окна недоступна на этой платформе.");
            },
            #[cfg(windows)]
            Cmd::Elevate(action) => {
                #[cfg(windows)]
                {
                    if ctx.wsl.is_pending() || ctx.vpn_job.is_some() || ctx.vpn_unsettled {
                        ctx.log(Level::Warn, "Дождитесь завершения текущей операции перед передачей окна.");
                        continue;
                    }
                    match &action {
                        crate::instances::GuiReplacementAction::ShowMain {} => {
                            if !ctx.settings.save() { ctx.log(Level::Err, "Настройки не сохранены; новое окно не запущено."); continue; }
                        },
                        crate::instances::GuiReplacementAction::ResumeApply(intent) => {
                            let _ = intent; // Receiving stays inside the owned cancellable job.
                        }
                    };
                    let (progress, received) = mpsc::channel();
                    elevation_progress = Some(received);
                    native_cancel.store(false, Ordering::SeqCst);
                    native_apply_pending.store(true, Ordering::SeqCst);
                    begin_native_change(&mut ctx, "Подготовка передачи окна");
                    let cancellation = native_cancel.clone();
                    let lifetime = lifetime.clone();
                    native_job = match std::thread::Builder::new().name("gui-elevation".into()).spawn(move || {
                        if let crate::instances::GuiReplacementAction::ResumeApply(intent) = &action {
                            if let Err(error) = receive_apply_continuation(&lifetime, intent, &cancellation, lifetime.retained_image()) {
                                return Ok(NativeCompletion::Held(format!("Данные применения изменились; передача остановлена: {error}")));
                            }
                        }
                        if cancellation.load(Ordering::SeqCst) { return Ok(NativeCompletion::Retired); }
                        let image = lifetime.retained_image()?;
                        let mut ready = crate::instances::request_elevation(&image, action, cancellation.clone(), progress.clone())?;
                        if cancellation.load(Ordering::SeqCst) {
                            retire_replacement(&mut ready, &progress);
                            return Ok(NativeCompletion::Retired);
                        }
                        if let Err(mut ready) = lifetime.accept_replacement(ready) {
                            retire_replacement(&mut ready, &progress);
                            return Err("Передача окна не принята; новое окно завершено.".into());
                        }
                        Ok(NativeCompletion::Retired)
                    }) {
                        Ok(job) => Some(job),
                        Err(error) => {
                            native_apply_pending.store(false, Ordering::SeqCst);
                            elevation_progress = None;
                            ctx.log(Level::Err, format!("Не удалось начать передачу окна: {error}"));
                            ctx.busy(None);
                            push_status(&mut ctx, Scan::Settings);
                            None
                        }
                    };
                }
            },
            Cmd::Stop | Cmd::Shutdown => { ctx.wsl.request_cancel(); shutdown = true; },
            Cmd::CancelWsl => ctx.wsl.request_cancel(),
            Cmd::RefreshWsl => unreachable!("refresh is latched before busy handling"),
            Cmd::SetWslEnabled(enabled) => {
                if wsl_status(&ctx).pending { ctx.log(Level::Warn, "Дождитесь завершения операции WSL."); continue; }
                let mut wanted = ctx.settings.clone();
                wanted.wsl = Some(crate::wsl_api::WslPreferences { enabled,
                    distros: wanted.wsl.as_ref().map(|p| p.distros.clone()).unwrap_or_default() });
                if wanted.save() { ctx.settings = wanted; }
                else { ctx.log(Level::Err, "Настройки WSL не сохранились; выбор не изменён."); }
                push_status(&mut ctx, Scan::Settings);
            },
            Cmd::SetWslDistro { name, selected } => {
                let current = wsl_status(&ctx);
                if name.is_empty() || name.chars().any(char::is_control)
                    || !current.can_set_distro(&name, selected) {
                    ctx.log(Level::Err, "Дистрибутив не подтверждён; обновите список WSL.");
                    continue;
                }
                let mut wanted = ctx.settings.clone();
                let preferences = wanted.wsl.get_or_insert(crate::wsl_api::WslPreferences { enabled: false, distros: Vec::new() });
                preferences.distros.retain(|old| old != &name);
                if selected { preferences.distros.push(name); }
                if wanted.save() { ctx.settings = wanted; }
                else { ctx.log(Level::Err, "Настройки WSL не сохранились; выбор не изменён."); }
                push_status(&mut ctx, Scan::Settings);
            },
            Cmd::ApplySettings => {
                if ctx.wsl.is_pending() { ctx.log(Level::Warn, "Подождите завершения поиска WSL."); continue; }
                #[allow(unused_mut)]
                let mut resumed = false;
                #[cfg(windows)]
                let mut resume_intent = None;
                #[cfg(windows)]
                if let Startup::Resume(intent) = &ctx.startup {
                    resume_intent = Some(intent.clone());
                    ctx.startup = Startup::Explicit;
                    resumed = true;
                }
                if !resumed && !ctx.settings.save() { ctx.log(Level::Err, "Настройки не сохранены; применение не начато."); continue; }
                let wanted = ctx.settings.clone();
                native_cancel.store(false, Ordering::SeqCst);
                native_apply_pending.store(true, Ordering::SeqCst);
                begin_native_change(&mut ctx, "Применение настроек");
                let shared = shared.clone();
                let cancellation = native_cancel.clone();
                native_job = match std::thread::Builder::new().name("apply-settings".into()).spawn(move || {
                    let ctx = shared.lock().map_err(|_| "settings owner lock was poisoned".to_owned())?;
                    run_ctx_job(ctx, |ctx| {
                        let result = apply_acknowledged(ctx, wanted, &cancellation, #[cfg(windows)] resume_intent);
                        push_status(ctx, Scan::Deep);
                        result
                    })
                }) {
                    Ok(job) => Some(job),
                    Err(error) => {
                        native_apply_pending.store(false, Ordering::SeqCst);
                        ctx.log(Level::Err, format!("Не удалось начать применение: {error}"));
                        ctx.busy(None);
                        push_status(&mut ctx, Scan::Settings);
                        None
                    }
                };
            },
            Cmd::RememberLicense(key) => {
                if ctx.settings.license_key != key {
                    ctx.settings.license_key = key;
                    ctx.settings.save();
                }
            }
            // Off the queue, not on it. The measurement drives PowerShell and
            // takes seconds; on the queue, a user flipping a switch in the
            // middle of one would watch it snap back until it finished — G42's
            // lesson, applied to a job nobody asked for. No `busy` marker
            // either, for the same reason: nothing the user is waiting on is
            // running.
            #[cfg(windows)]
            Cmd::RemeasureVpn | Cmd::Probed { .. } => unreachable!("Windows read-only commands are received before the native gate"),
            #[cfg(not(windows))]
            Cmd::RemeasureVpn => {
                use std::sync::atomic::Ordering;
                if ctx.vpn_job.is_none() && !MEASURING_VPN.swap(true, Ordering::SeqCst) {
                    let back = own.clone();
                    let owner = match ctx.lifetime.new_command_scope() {
                        Ok(owner) => owner,
                        Err(error) => { MEASURING_VPN.store(false, Ordering::SeqCst); ctx.log(Level::Err, error); continue; }
                    };
                    let receipt = owner.clone();
                    let spawned = std::thread::Builder::new()
                        .name("vpn-probe".to_string())
                        .spawn(move || {
                            let (vpn, relay_egress) = match owner.with_result(measure_vpn) {
                                Ok(value) => value,
                                Err(error) => { eprintln!("VPN observation unavailable: {error}"); (VpnSeen::Unmeasured, None) }
                            };
                            let relay = background::is_enabled() && background::is_running();
                            let _ = back.send(Cmd::Probed { vpn: VpnSeen::None, relay: false, relay_egress: None });
                            (vpn, relay, relay_egress)
                        });
                    match spawned {
                        Ok(handle) => ctx.vpn_job = Some(ProbeJob { handle, command_receipt: receipt }),
                        Err(_) => {

                        // Or the flag would stay raised and this window would
                        // never measure again.
                        MEASURING_VPN.store(false, Ordering::SeqCst);
                        }
                    }
                }
            }
            #[cfg(not(windows))]
            Cmd::Probed { .. } => {},
            Cmd::DeepRefresh => {
                ctx.busy(Some("Проверка установок"));
                push_status(&mut ctx, Scan::Deep);
                ctx.busy(None);
            }
            command @ (Cmd::Set(_, _) | Cmd::EnableAll | Cmd::UseSystemTcp | Cmd::UseExistingConfigured(_) | Cmd::Repair
                | Cmd::SetOwnProxy(_) | Cmd::SetGroupKey(_) | Cmd::CopyGroupCommand | Cmd::Unlocked
                | Cmd::AddPath(_) | Cmd::PatchInstall(_)) => {
                native_cancel.store(false, Ordering::SeqCst);
                native_apply_pending.store(true, Ordering::SeqCst);
                begin_owned_command(&mut ctx, &command);
                let shared = shared.clone();
                native_job = match std::thread::Builder::new().name("settings-command".into()).spawn(move || {
                    let ctx = shared.lock().map_err(|_| "settings owner lock was poisoned".to_owned())?;
                    run_ctx_job(ctx, |ctx| dispatch_owned_command(ctx, command))
                }) {
                    Ok(job) => Some(job),
                    Err(error) => {
                        native_apply_pending.store(false, Ordering::SeqCst);
                        ctx.log(Level::Err, format!("Не удалось начать выбранное действие: {error}"));
                        ctx.busy(None);
                        push_status(&mut ctx, Scan::Settings);
                        None
                    }
                };
            },
            Cmd::ForgetPath(p) => {
                ctx.settings.manual_paths.retain(|x| x != &p);
                ctx.settings.save();
                push_status(&mut ctx, Scan::System);
            }
            Cmd::SetCustomDns(text) => {
                set_custom_dns(&mut ctx, &text);
                ctx.settings.save();
                push_status(&mut ctx, Scan::Settings);
            }
            Cmd::ReorderProviders(order) => {
                ctx.settings.provider_order = order;
                ctx.settings.save();
                ctx.log(
                    Level::Info,
                    match first_enabled_provider(&ctx.settings) {
                        Some(n) => format!("Порядок DNS изменён, первый — {}", n),
                        None => "Порядок DNS изменён.".to_string(),
                    },
                );
                // The order is ours alone — nothing on the machine changed, so
                // there is nothing on the machine to re-read.
                push_status(&mut ctx, Scan::Settings);
            }
            Cmd::SetProvider(name, on) => {
                ctx.settings.set_provider_enabled(&name, on);
                // Never let the last one go: an empty pool is a dead DNS layer
                // that still draws as installed.
                if all_providers_disabled(&ctx.settings) {
                    ctx.settings.set_provider_enabled(&name, true);
                    ctx.log(
                        Level::Warn,
                        "Нельзя отключить все DNS-серверы — хотя бы один должен остаться.",
                    );
                } else if !on && no_usable_nameserver(&ctx.settings) {
                    ctx.settings.set_provider_enabled(&name, true);
                    ctx.log(
                        Level::Warn,
                        "Этот сервер нельзя отключить: он остался единственным, который Windows может использовать как DNS-сервер напрямую.",
                    );
                } else {
                    ctx.log(
                        Level::Info,
                        format!(
                            "DNS-сервер {} {}",
                            name,
                            if on {
                                "включён"
                            } else {
                                "отключён"
                            }
                        ),
                    );
                }
                ctx.settings.save();
                let rewrote = reapply_dns_rules(&mut ctx);
                // Only when the rules were actually rewritten is there anything
                // new on the machine to read back.
                push_status(
                    &mut ctx,
                    if rewrote {
                        Scan::System
                    } else {
                        Scan::Settings
                    },
                );
            }
        }
    }
}

fn finish_shutdown(ctx: &mut Ctx, lifetime: &GuiLifetime) -> bool {
    if ctx.wsl.is_pending() || ctx.vpn_job.is_some() || ctx.vpn_unsettled
        || lifetime.save_failed.load(Ordering::SeqCst) { return false; }
    if !lifetime.command_scopes_settled() { return false; }
    #[cfg(windows)]
    if !ctx.finish_background_resources() { return false; }
    #[cfg(windows)]
    if lifetime.handoff_requested.load(Ordering::SeqCst)
        && crate::settings::saved_intent_sha256(&ctx.settings).is_err() {
        hold_apply(ctx, "Сохранённые настройки изменились перед передачей окна; они не перезаписаны. Закройте окно для отмены передачи.".into());
        if !lifetime.abort_requested.load(Ordering::SeqCst) {
            lifetime.save_failed.store(true, Ordering::SeqCst);
            return false;
        }
    }
    if matches!(ctx.startup, Startup::Held(_)) || lifetime.handoff_requested.load(Ordering::SeqCst) || ctx.settings.save() {
        lifetime.commands.close_admission();
        lifetime.shutdown_ready.store(true, Ordering::SeqCst);
        let _ = ctx.events.send(Event::ShutdownReady);
        if let Ok(wake) = ctx.wake.lock() { (wake)(); }
        return true;
    }
    ctx.log(Level::Err, "Не удалось сохранить настройки; окно остаётся открытым.");
    lifetime.save_failed.store(true, Ordering::SeqCst);
    false
}

/// The one thing that runs on its own, before the user has touched anything.
///
/// `refresh_pinned_hosts` exists because the host routes that keep our queries
/// off a VPN survive a reboot only while the network stays the same. It is also
/// the one call that can turn a switch off by itself: with the client measured
/// inside a tunnel it strips the rules outright (G29). In a console that was
/// invisible and harmless; in a window it reads as the tool spontaneously
/// disabling itself, so the flip is watched for and explained.
fn startup_housekeeping(ctx: &mut Ctx) {
    if !cfg!(target_os = "windows") || !is_admin() {
        return;
    }
    let before = match ctx.with_command(dns::is_nrpt_applied) {
        Ok(value) => value, Err(error) => { ctx.log(Level::Warn, error); return; }
    };
    if let Err(error) = ctx.with_command(dns::refresh_pinned_hosts) { ctx.log(Level::Warn, error); return; }
    dns::invalidate_cache();
    let after = match ctx.with_command(dns::is_nrpt_applied) {
        Ok(value) => value, Err(error) => { ctx.log(Level::Warn, error); return; }
    };
    if before && !after {
        ctx.log(
            Level::Warn,
            "Antigravity идёт через активный VPN — правила DNS сняты, чтобы не перебивать \
             ваш туннель. Выключите VPN и включите «Обход через DNS» заново.",
        );
    }
}

fn all_providers_disabled(s: &Settings) -> bool {
    crate::resolvers::provider_names()
        .iter()
        .all(|n| !s.provider_enabled(n))
}

/// Whether the selection would leave the NRPT rule with no nameserver.
///
/// The pool would still resolve — the head of the list speaks DoH through the
/// relay — but Windows itself would be pointed at nothing, so any lookup that
/// bypasses the relay (it stopped, it is being upgraded) fails outright instead
/// of falling back. I49.
fn no_usable_nameserver(s: &Settings) -> bool {
    crate::resolvers::udp_provider_names()
        .iter()
        .all(|n| !s.provider_enabled(n))
}

/// The one that answers when rotation is off: first in pool order that the user
/// has not switched off. Pool order is by measured substitution, so its head is
/// the one most likely to still be substituting.
fn first_enabled_provider(s: &Settings) -> Option<&'static str> {
    crate::resolvers::ordered_provider_names()
        .into_iter()
        .find(|n| s.provider_enabled(n))
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// How much of the system has to be re-read after `cap` was flipped.
///
/// The rule is "what could this switch have changed", not "how important is it":
/// `VerifyTls`, `VpnDetect` and `BuiltinExits` write one field of `settings.json`
/// and nothing else, so asking Windows about scheduled tasks, NRPT rules and the
/// user environment afterwards is two seconds of latency buying a byte-identical
/// answer.
fn scan_after(cap: Cap) -> Scan {
    match cap {
        // The one action that changes what is *inside* the binaries, so the one
        // that has to pay for re-reading them.
        Cap::ClientPatch => Scan::Deep,
        Cap::Watchdog | Cap::Dns | Cap::LocalProxy | Cap::OwnProxy | Cap::DnsRotation => {
            Scan::System
        }
        Cap::BuiltinExits | Cap::GroupProxy => Scan::Settings,
    }
}

fn push_status(ctx: &mut Ctx, scan: Scan) {
    push_status_mode(ctx, scan, None, #[cfg(target_os = "macos")] None)
}

#[cfg(target_os = "macos")]
fn push_mac_idle_status(ctx: &mut Ctx, rows: Vec<InstallRow>) {
    let vscode_antigravity = ctx.last.as_ref().map_or(VsCodeAntigravityObservation::Incomplete, |previous|
        previous.vscode_antigravity);
    push_status_mode(ctx, Scan::System, Some(vscode_antigravity), Some(rows))
}

fn push_status_mode(ctx: &mut Ctx, scan: Scan, mac_idle_extension: Option<VsCodeAntigravityObservation>,
    #[cfg(target_os = "macos")] mac_idle_rows: Option<Vec<InstallRow>>,
) {
    // The measurement answers "do the client's own sockets leave through a
    // tunnel", which no switch in this window changes — only what we then do
    // about it. So it is taken on the deep pass and when it has never been
    // taken, and a settings flip inherits it rather than paying a PowerShell
    // round trip to be told the same thing.
    #[cfg(not(windows))]
    if scan == Scan::Deep || ctx.vpn.is_none() {
        let (vpn, relay_egress) = match ctx.lifetime.new_command_scope() {
            Ok(owner) => match owner.with_result(measure_vpn) {
                Ok(value) => value, Err(error) => { ctx.log(Level::Warn, error); (VpnSeen::Unmeasured, None) }
            },
            Err(error) => { ctx.log(Level::Err, error); (VpnSeen::Unmeasured, None) }
        };
        ctx.vpn = Some(vpn);
        ctx.relay_egress = relay_egress;
    }

    let status = match scan {
        Scan::Settings => match ctx.last.clone() {
            Some(prev) => settings_only_status(ctx, prev),
            // Nothing to reuse yet (a flip before the first snapshot landed):
            // ask properly rather than invent a snapshot.
            None => read_status(ctx, false, None, #[cfg(target_os = "macos")] None),
        },
        #[cfg(windows)]
        Scan::Installations => match ctx.last.clone() {
            Some(previous) => installations_only_status(ctx, previous),
            // The worker normally publishes initial status before receiving Refresh.
            // Without that cache, build the first whole snapshot as before.
            None => read_status(ctx, false, None),
        },
        Scan::System => read_status(ctx, false, mac_idle_extension, #[cfg(target_os = "macos")] mac_idle_rows),
        Scan::Deep => read_status(ctx, true, None, #[cfg(target_os = "macos")] None),
    };

    #[cfg(target_os = "macos")]
    if mac_idle_extension.is_some() && ctx.lifetime.abort_requested.load(Ordering::SeqCst) { return; }
    if mac_idle_extension.is_some() && ctx.last.as_ref().is_some_and(|previous| {
        previous.installs.len() == status.installs.len() && previous.installs.iter().zip(&status.installs)
            .all(|(a, b)| {
                let same = a.path == b.path && a.label == b.label && a.manual == b.manual && a.patched == b.patched;
                #[cfg(target_os = "macos")]
                let same = same && a.coverage == b.coverage;
                same
            })
    }) { return; }

    #[cfg(not(target_os = "macos"))]
    if scan == Scan::Deep {
        ctx.patched_seen = status
            .installs
            .iter()
            .filter_map(|r| match (&r.path, r.patched) {
                (Some(p), Some(v)) => Some((p.clone(), v)),
                _ => None,
            })
            .collect();
    }
    ctx.last = Some(status.clone());
    if ctx.events.send(Event::Status(Box::new(status))).is_err() { ctx.lifetime.channel_lost.store(true, Ordering::SeqCst); }
    if let Ok(wake) = ctx.wake.lock() { (wake)(); }
}

fn wsl_status(ctx: &Ctx) -> crate::wsl_api::WslStatus {
    let target = ctx.last.as_ref().map(|status| status.wsl.desktop_target.clone())
        .unwrap_or_default();
    wsl_status_with_target(ctx, target)
}

fn wsl_status_with_target(ctx: &Ctx, target: DesktopDiscovery) -> crate::wsl_api::WslStatus {
    let mut status = ctx.wsl.snapshot(ctx.settings.wsl.clone());
    status.pending |= ctx.native_apply_pending.load(Ordering::SeqCst) || ctx.vpn_unsettled;
    if let Startup::Held(reason) = &ctx.startup { status.error = Some(reason.clone()); }
    status.desktop_target = target;
    status.apply_eligibility = wsl_apply_eligibility(&status, &ctx.settings);
    status
}

fn wsl_apply_eligibility(status: &crate::wsl_api::WslStatus, settings: &Settings) -> Result<(), String> {
    use crate::wsl_api::{RegistrationFreshness, RegistrationState};
    if status.pending || status.loading { return Err("Дождитесь завершения текущей операции WSL.".into()); }
    if let Some(error) = &status.error { return Err(format!("Состояние WSL не подтверждено: {error}")); }
    let preferences = status.preferences.as_ref().ok_or("Выбор WSL ещё не подтверждён.")?;
    if !preferences.enabled { return Err("WSL выключен; применять изменения не требуется.".into()); }
    if preferences.distros.is_empty() { return Err("Выберите дистрибутив WSL.".into()); }
    if !crate::wsl_runtime::preparation_can_start_guest(settings) { return Err("Для WSL не выбраны изменения.".into()); }
    if status.registration_freshness != RegistrationFreshness::Current { return Err("Обновите список дистрибутивов WSL.".into()); }
    if preferences.distros.iter().any(|name| !status.distributions.iter().any(|row| &row.name == name && row.selected && row.registration == RegistrationState::Present)) {
        return Err("Выбранный дистрибутив WSL не подтверждён.".into());
    }
    match &status.desktop_target {
        DesktopDiscovery::Present => Ok(()),
        DesktopDiscovery::Absent => Err("Установка Antigravity Desktop не найдена; для WSL нужна Desktop.".into()),
        DesktopDiscovery::Incomplete { desktop_found: true, error } => Err(format!("Не удалось проверить все установки Antigravity: {error}")),
        DesktopDiscovery::Incomplete { desktop_found: false, error } => Err(format!("Установка Desktop не проверена: {error}")),
    }
}

/// The existing native job owns Ctx while the outer loop receives cancel/close.
/// These selected command effects run off the command-receiving thread.
fn dispatch_owned_command(ctx: &mut Ctx, command: Cmd) -> Result<NativeCompletion, String> {
    if ctx.native_cancel.load(Ordering::SeqCst) {
        return Err("Выбранное действие отменено до начала.".into());
    }
    #[cfg(windows)]
    if matches!(&command, Cmd::Repair) && matches!(ctx.startup, Startup::Ordinary) && is_admin() {
        if let crate::settings::Read::Parsed(settings) = crate::settings::read() {
            let effects = settings.checked_transport_effects()?;
            if specified_wish(&effects.carrier) == Some(true) || specified_wish(&effects.watchdog) == Some(true) {
                ctx.busy(Some("Чиню службу обхода"));
                let (handled, receiving) = background::repair_current_generation_with_receiving(
                    &ctx.native_cancel, ctx.lifetime.retained_image());
                ctx.retain_background_receiving(receiving)?;
                if handled {
                    push_status(ctx, Scan::System);
                    return Ok(NativeCompletion::Retired);
                }
                let (handled, receiving) = background::repair_prior_transition_with_receiving(
                    background::BackgroundChanges { relay: specified_wish(&effects.carrier), watchdog: specified_wish(&effects.watchdog) },
                    &ctx.native_cancel, ctx.lifetime.retained_image());
                ctx.retain_background_receiving(receiving)?;
                if handled {
                    push_status(ctx, Scan::System);
                    return Ok(NativeCompletion::Retired);
                }
            }
        }
    }
    let owns_proxy_persistence = matches!(&command, Cmd::SetOwnProxy(_) | Cmd::Set(Cap::OwnProxy, _));
    let saves_intent = !owns_proxy_persistence && matches!(&command, Cmd::Set(_, _) | Cmd::SetGroupKey(_) | Cmd::EnableAll | Cmd::Repair);
    let effect = (|| -> Result<(), String> { match command {
            Cmd::Set(cap, on) => {
                ctx.busy(Some(cap.title()));
                apply(ctx, cap, on)?;
                push_status(ctx, scan_after(cap));
                // Turning auto-patch on is asking for Antigravity to be patched;
                // waiting for the watchdog's next poll would show the switch on
                // and the install still grey.
                if cap == Cap::Watchdog && on && auto_patch_found(ctx) {
                    push_status(ctx, Scan::Deep);
                }
            }
            Cmd::SetOwnProxy(text) => {
                ctx.busy(Some("Проверка прокси"));
                set_own_proxy(ctx, &text)?;
                push_status(ctx, Scan::System);
            }
            Cmd::SetGroupKey(text) => {
                ctx.busy(Some("Проверка ключа"));
                match crate::group_key::parse_key(&text) {
                    Ok(_) => {
                        let mut staged = ctx.settings.clone();
                        staged.group_key = text.trim().to_string();
                        staged.group_key_at = crate::gate::now_unix();
                        staged.set_transport_choice(TransportChoice::GroupProxy(true))?;
                        ctx.settings = save_received_settings(&staged).map_err(|error| format!("Ключ не получен из сохранённых настроек; применение не начиналось: {error}"))?;
                        apply(ctx, Cap::GroupProxy, true)?;
                        ctx.log(crate::ops::Level::Ok, "Ключ принят.");
                        push_status(ctx, scan_after(Cap::GroupProxy));
                    }
                    Err(e) => {
                        ctx.log(crate::ops::Level::Err, format!("{}", e));
                    }
                }
            }
            Cmd::CopyGroupCommand => {
                #[cfg(target_os = "macos")]
                {
                    let code = crate::hwid::pc_code().map_err(|error| format!("Код устройства недоступен: {error}"))?;
                    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Копирование отменено.".into()); }
                    if !crate::utils::set_clipboard_text(&format!("/ag+{code}")) { return Err("Команду не удалось скопировать.".into()); }
                    ctx.log(Level::Ok, "Команда скопирована — отправьте её в группе.");
                }
                #[cfg(not(target_os = "macos"))]
                return Err("Команда недоступна на этой платформе.".into());
            }
            Cmd::EnableAll => {
                ctx.busy(Some("Включаю"));
                enable_all(ctx)?;
                push_status(ctx, Scan::Deep);
            }
            Cmd::UseSystemTcp => {
                ctx.busy(Some("Системное подключение"));
                use_system_tcp(ctx)?;
                push_status(ctx, Scan::System);
            }
            Cmd::UseExistingConfigured(choices) => {
                ctx.busy(Some("Настроенное подключение"));
                use_existing_configured(ctx, choices)?;
                push_status(ctx, Scan::System);
            }
            Cmd::Repair => {
                ctx.busy(Some("Чиню службу обхода"));
                repair(ctx)?;
                push_status(ctx, Scan::System);
            }
        Cmd::Unlocked => {
            if matches!(ctx.startup, Startup::Ordinary) {
                if auto_patch_found(ctx) { push_status(ctx, Scan::Deep); }
                else { push_status(ctx, Scan::System); }
            } else { push_status(ctx, Scan::Settings); }
        },
        Cmd::AddPath(path) => {
            if !ctx.settings.manual_paths.contains(&path) {
                ctx.settings.manual_paths.push(path);
                if !ctx.settings.save() { return Err("Путь не сохранён; патч не начинался.".into()); }
            }
            push_status(ctx, Scan::Deep);
            if auto_patch_found(ctx) { push_status(ctx, Scan::Deep); }
        },
        Cmd::PatchInstall(path) => {
            let label = crate::install_label(&path);
            if !patch_found(ctx, vec![(label, path)]) {
                return Err(format!("{label}: патч не записан, см. предыдущий результат"));
            }
            push_status(ctx, Scan::Deep);
        },
        _ => return Err("Команда не относится к выбранному действию.".into()),
    }; Ok(()) })();
    let saved = !saves_intent || ctx.settings.save();
    match (effect, saved) {
        (Ok(()), true) => {},
        (Err(error), true) => return Err(error),
        (Ok(()), false) => return Err("Действие получено, но выбранные настройки не сохранены.".into()),
        (Err(error), false) => return Err(format!("{error}; выбранные настройки также не сохранены")),
    }
    Ok(NativeCompletion::Retired)
}

fn genuine_command(command: &Cmd) -> bool {
    matches!(command, Cmd::RequestElevation | Cmd::ApplySettings | Cmd::SetWslEnabled(_) | Cmd::SetWslDistro { .. }
        | Cmd::Set(_, _) | Cmd::AddPath(_) | Cmd::ForgetPath(_) | Cmd::PatchInstall(_) | Cmd::SetOwnProxy(_)
        | Cmd::SetCustomDns(_) | Cmd::SetGroupKey(_) | Cmd::CopyGroupCommand | Cmd::SetProvider(_, _) | Cmd::ReorderProviders(_)
        | Cmd::EnableAll | Cmd::UseSystemTcp | Cmd::UseExistingConfigured(_) | Cmd::Repair)
}

fn worker_boot(rx: &Receiver<Cmd>, events: &Sender<Event>, wake: &Arc<Mutex<Box<dyn Fn() + Send>>>,
    lifetime: &Arc<GuiLifetime>) -> Option<(Settings, Startup, Option<Cmd>)> {
    let hold = match lifetime.bootstrap_hold.lock() {
        Ok(mut hold) => hold.take(),
        Err(_) => return rejected_boot(rx, events, wake, lifetime, "Не удалось получить ограничение автоматического запуска.".into()),
    };
    if let Some(reason) = hold { return held_boot(rx, events, wake, lifetime, reason); }
    #[cfg(windows)]
    {
        let action = match lifetime.action.lock() {
            Ok(mut action) => action.take(),
            Err(_) => return rejected_boot(rx, events, wake, lifetime, "Не удалось получить продолжение GUI.".into()),
        };
        if let Some(crate::instances::GuiReplacementAction::ResumeApply(intent)) = action {
            if lifetime.retirement_input.lock().map_or(true, |value| value.is_some()) {
                return rejected_boot(rx, events, wake, lifetime, "Конфликт входных данных продолжения.".into());
            }
            if let Some(descriptor) = intent.retirement_input.clone() {
                if let Err(error) = lifetime.receive_retirement_input(descriptor) {
                    return held_boot(rx, events, wake, lifetime, format!("Не удалось получить входные данные продолжения: {error}"));
                }
            }
            match receive_apply_continuation(lifetime, &intent, &lifetime.abort_requested, lifetime.retained_image()) {
                Ok(plan) => return Some((plan.wanted.clone(), Startup::Resume(intent), Some(Cmd::ApplySettings))),
                Err(error) => {
                    let reason = format!("Данные изменились во время передачи окна; применение не выполнялось: {error}");
                    return held_boot(rx, events, wake, lifetime, reason);
                }
            }
        }
        if lifetime.retirement_input.lock().map_or(true, |value| value.is_some()) {
            return Some((Settings::load(), Startup::Explicit, None));
        }
    }
    Some((Settings::load(), Startup::Ordinary, None))
}

fn held_boot(rx: &Receiver<Cmd>, events: &Sender<Event>, wake: &Arc<Mutex<Box<dyn Fn() + Send>>>,
    lifetime: &Arc<GuiLifetime>, reason: String) -> Option<(Settings, Startup, Option<Cmd>)> {
    if let Err(error) = lifetime.hold_automatic_effects(reason.clone()) { let _ = events.send(Event::Log(Level::Err, error)); }
    let _ = events.send(Event::Log(Level::Err, reason.clone()));
    // Display-only receiving never qualifies a rejected or already-consumed
    // continuation. Only an actual canonical saved snapshot may enter Ctx.
    if let Some(display) = saved_display() {
        Some((display, Startup::Held(reason), None))
    } else { rejected_boot(rx, events, wake, lifetime, reason) }
}

fn saved_display() -> Option<Settings> {
    let display = Settings::load();
    crate::settings::saved_intent_sha256(&display).ok().map(|_| display)
}

#[cfg(windows)]
fn hold_apply(ctx: &mut Ctx, reason: String) {
    if let Some(display) = saved_display() { ctx.settings = display; }
    ctx.startup = Startup::Held(reason.clone());
    if let Err(error) = ctx.lifetime.hold_automatic_effects(reason.clone()) { ctx.log(Level::Err, error); }
    ctx.log(Level::Err, reason);
}

fn rejected_boot(rx: &Receiver<Cmd>, events: &Sender<Event>, wake: &Arc<Mutex<Box<dyn Fn() + Send>>>,
    lifetime: &Arc<GuiLifetime>, reason: String) -> Option<(Settings, Startup, Option<Cmd>)> {
    let _ = events.send(Event::Log(Level::Err, reason.clone()));
    let _ = events.send(Event::Busy(Some("Сохранённые данные не подтверждены; применение остановлено.".into())));
    if let Ok(wake) = wake.lock() { (wake)(); }
    loop {
        match rx.recv() {
            Ok(Cmd::Shutdown | Cmd::Stop) | Err(_) => {
                // No Settings or effects were accepted, so preserve the actual
                // saved bytes instead of writing a fabricated default snapshot.
                lifetime.shutdown_ready.store(true, Ordering::SeqCst);
                let _ = events.send(Event::ShutdownReady);
                if let Ok(wake) = wake.lock() { (wake)(); }
                return None;
            }
            Ok(Cmd::ApplySettings) => {
                let settings = Settings::load();
                if crate::settings::saved_intent_sha256(&settings).is_ok() {
                    return Some((settings, Startup::Explicit, Some(Cmd::ApplySettings)));
                }
                let _ = events.send(Event::Log(Level::Err, "Сохранённые настройки не подтверждены; данные не изменены.".into()));
                if let Ok(wake) = wake.lock() { (wake)(); }
            }
            _ => {},
        }
    }
}

#[cfg(windows)]
fn retire_replacement(ready: &mut crate::instances::GuiReplacementReady,
    progress: &Sender<crate::instances::ElevationProgress>) {
    let mut last_error = None;
    loop {
        let outcome = ready.request_abort().and_then(|_| ready.poll_retired());
        match outcome {
            Ok(true) => return,
            Ok(false) => {},
            Err(error) => {
                if last_error.as_ref() != Some(&error) {
                    let _ = progress.send(crate::instances::ElevationProgress::ObservationPending(error.clone()));
                    last_error = Some(error);
                }
            }
        }
        std::thread::sleep(crate::wsl_runtime::OWNER_OBSERVATION_CADENCE);
    }
}

/// The last snapshot with every settings-derived field recomputed, and nothing
/// asked of the machine.
///
/// The DNS row is included because it is settings-derived *in part*: whether a
/// measured tunnel blocks it depends on `vpn_detect`. It is rebuilt from the raw
/// pair the last system scan kept, so a settings-only flip updates the row
/// it governs without going near a scheduled task.
fn settings_only_status(ctx: &Ctx, prev: Status) -> Status {
    #[cfg(not(windows))]
    let (rules, relay) = ctx.dns_probe;
    #[cfg(windows)]
    let (rules, relay) = (prev.rules, prev.relay_running);
    let status = Status {
        wsl: wsl_status(ctx),
        #[cfg(windows)]
        selected_delivery: selected_delivery_unreceived(&ctx.lifetime),
        dns: dns_state(
            prev.admin,
            rules,
            relay,
            ctx.vpn,
            ctx.settings.vpn_detect,
            ctx.settings.dns,
        ),
        // Not `..prev`: `Cmd::Probed` refreshes this behind the window's back,
        // and a row carried forward from the last system scan would say a relay
        // that died an hour ago is still running.
        relay_running: relay,
        rules,
        own_proxy_text: upstream::configured()
            .map(|u| u.display())
            .unwrap_or_else(|| ctx.settings.own_proxy.clone()),
        vpn: ctx.vpn,
        relay_egress: ctx.relay_egress,
        ..prev
    }
    .with_settings_switches(&ctx.settings);
    #[cfg(windows)]
    { return apply_windows_observation(status, &ctx.dns_probe, &ctx.settings, ctx.vpn); }
    #[cfg(not(windows))]
    { status }
}

#[cfg(windows)]
fn observed_watchdog_state(role: background::RoleObservation) -> State {
    match role {
        background::RoleObservation::Absent => State::Off,
        background::RoleObservation::Registered => State::Partial("Задача создана, но не запущена".into()),
        background::RoleObservation::Running => State::On,
    }
}

#[cfg(windows)]
fn apply_windows_observation(mut status: Status, observation: &Result<WindowsSystemObservation, String>, settings: &Settings, vpn: Option<VpnSeen>) -> Status {
    status.transport_ready = None;
    status.relay_outdated = false;
    if let Ok(observed) = observation {
        status.selected_delivery = observed.selected_delivery.clone();
        status.relay_outdated = matches!(&observed.selected_delivery, Ok(true));
        let background = match &observed.background {
            Ok(background) => background,
            Err(error) => {
                status.background_observation_error = Some(error.clone());
                status.dns = State::Blocked(format!("Состояние службы не проверено: {error}"));
                status.watchdog = State::Blocked(format!("Состояние службы не проверено: {error}"));
                status.local_proxy = State::Blocked(format!("Состояние службы не проверено: {error}"));
                status.rules_observed = observed.rules.as_ref().ok().map(|(_, owned)| *owned);
                if let Ok((core, _)) = &observed.rules { status.rules = *core; }
                return status;
            }
        };
        if let Some(error) = &observed.transport_error {
            status.watchdog = observed_watchdog_state(background.watchdog);
            status.relay_running = matches!(background.relay, background::RoleObservation::Running);
            status.background_observation_error = None;
            status.dns = State::Blocked(error.clone());
            status.local_proxy = State::Blocked(error.clone());
            status.rules_observed = observed.rules.as_ref().ok().map(|(_, owned)| *owned);
            return status;
        }
        if let Some((expected, dns_channel, tcp_channel, alias_channel, port)) = &observed.transport {
            let current = settings.transport_requirements().map(|value| value.active_config);
            if current.as_ref() != Ok(expected) {
                status.background_observation_error = Some("Сохранённый режим изменился после наблюдения службы".into());
                status.dns = State::Blocked("Состояние DNS для текущего режима ещё не получено".into());
                status.local_proxy = State::Blocked("Состояние прокси для текущего режима ещё не получено".into());
                return status;
            }
            status.watchdog = observed_watchdog_state(background.watchdog);
            status.background_observation_error = None;
            status.transport_ready = if expected.profile == crate::settings::TransportProfile::SystemTcp {
                match (dns_channel, tcp_channel, alias_channel) {
                    (background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled),
                     background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready),
                     background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled)) if port.is_some_and(|value| value != 0) => Some(true),
                    (background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Failed(_)), _, _)
                    | (_, background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Failed(_)), _)
                    | (_, _, background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Failed(_))) => Some(false),
                    _ => None,
                }
            } else { None };
            status.relay_running = matches!(background.relay, background::RoleObservation::Running);
            status.dns = match &observed.rules {
                Err(error) => { status.rules_observed = None; State::Blocked(format!("Правила DNS не проверены: {error}")) },
                Ok((core_rules, owned_rules)) => {
                    status.rules = *core_rules;
                    status.rules_observed = Some(*owned_rules);
                    if !expected.dns { State::Off }
                    else { match dns_channel {
                        background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready) => dns_state(status.admin, *core_rules, true, vpn, settings.vpn_detect, true),
                        background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Failed(error)) => State::Blocked(format!("DNS: {error}")),
                        _ => State::Blocked("Состояние DNS ещё не подтверждено".into()),
                    } }
                }
            };
            if expected.client_proxy {
                match tcp_channel {
                    background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready) => {}
                    background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Failed(error)) => status.local_proxy = State::Blocked(format!("Локальный прокси: {error}")),
                    _ => status.local_proxy = State::Blocked("Локальный прокси ещё не подтверждён".into()),
                }
            }
            return status;
        }
        status.background_observation_error = None;
        status.relay_running = matches!(background.relay, background::RoleObservation::Running);
        status.watchdog = observed_watchdog_state(background.watchdog);
        status.dns = match &observed.rules {
            Err(error) => {
                status.rules_observed = None;
                State::Blocked(format!("Правила DNS не проверены: {error}"))
            }
            Ok((rules, owned_rules)) => {
                status.rules = *rules;
                status.rules_observed = Some(*owned_rules);
                match &background.dns_ready {
                    Some(Ok(ready)) => dns_state(status.admin, *rules, *ready, vpn, settings.vpn_detect, settings.dns),
                    Some(Err(error)) => State::Blocked(format!("DNS: {error}")),
                    None => State::Blocked("Состояние DNS ещё не подтверждено".into()),
                }
            }
        };
        match &background.proxy_ready {
            Some(Ok(false)) if settings.local_proxy && !matches!(status.local_proxy, State::Blocked(_)) => {
                status.local_proxy = State::Partial("локальный прокси ещё не подтверждён".into());
            }
            Some(Err(error)) => status.local_proxy = State::Blocked(format!("Локальный прокси: {error}")),
            None => status.local_proxy = State::Blocked("Локальный прокси ещё не подтверждён".into()),
            Some(Ok(_)) => {}
        }
    } else if let Err(error) = observation {
        status.background_observation_error = Some(error.clone());
        status.rules_observed = None;
        let note = format!("Состояние службы не проверено: {error}");
        status.dns = State::Blocked(note.clone());
        status.watchdog = State::Blocked(note.clone());
        status.local_proxy = State::Blocked(note);
    }
    status
}

impl Status {
    /// The four switches that are nothing but a field of `settings.json`, plus
    /// the provider list they order. Written once so `read_status` and
    /// `settings_only_status` cannot drift apart — the bug that would produce is
    /// a switch that answers differently depending on which path drew it.
    fn with_settings_switches(mut self, s: &Settings) -> Self {
        self.transport_choices = s.transport_choices();
        self.transport_view = match &s.transport_profile {
            crate::settings::TransportProfileSetting::Absent => TransportView::LegacyOrMissing,
            crate::settings::TransportProfileSetting::Invalid(_) => TransportView::Invalid,
            crate::settings::TransportProfileSetting::Explicit(_) if s.transport_requirements().is_err() => TransportView::Invalid,
            crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::SystemTcp) => TransportView::SystemTcp,
            crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::ExistingConfigured) => TransportView::ExistingConfigured,
        };
        self.builtin_exits = if proxy::exits_available() { on_off(s.builtin_exits) }
            else { State::Blocked("В этой сборке встроенные выходы недоступны; сохранённый выбор не изменён.".into()) };
        self.group_proxy = on_off(s.group_proxy);
        self.custom_dns_text = s.custom_dns.clone();
        self.dns_rotation = if s.rotate_providers {
            State::On
        } else {
            // Naming the one that will answer is the whole point of switching
            // rotation off, so the switch says which it is rather than leaving
            // the user to count down the list.
            State::OffNote(match first_enabled_provider(s) {
                Some(name) => format!("используется только {}", name),
                None => "ни один сервер не включён".to_string(),
            })
        };
        self.providers = crate::resolvers::ordered_provider_names()
            .iter()
            .map(|n| ProviderRow {
                name: (*n).to_string(),
                enabled: s.provider_enabled(n),
            })
            .collect();
        self
    }
}

fn on_off(v: bool) -> State {
    if v {
        State::On
    } else {
        State::Off
    }
}

#[cfg(not(windows))]
fn receive_relay_currentness(value: Result<bool, String>) -> (bool, Option<String>) {
    match value {
        Ok(outdated) => (outdated, None),
        Err(error) => (false, Some(format!("Версия службы не подтверждена: {error}"))),
    }
}

fn interrupted_install_observation() -> (Vec<InstallRow>, DesktopDiscovery) {
    (Vec::new(), DesktopDiscovery::Incomplete {
        desktop_found: false,
        error: "Поиск установок прерван.".into(),
    })
}

fn summarize_client_patch(installs: &[InstallRow], wanted: bool) -> State {
    let patched: Vec<bool> = installs.iter().filter_map(|i| i.patched).collect();
    #[cfg(target_os = "macos")]
    let has_unknown = installs.iter().any(|row| row.path.is_some() && row.patched.is_none());
    #[cfg(not(target_os = "macos"))]
    let has_unknown = false;
    if has_unknown {
        if patched.iter().any(|value| *value) || wanted {
            State::Partial("состояние некоторых установок не проверено".into())
        } else { State::OffNote("состояние некоторых установок не проверено".into()) }
    } else if patched.is_empty() {
        // Not inspected yet, or nothing found. Fall back to what the user asked
        // for rather than claiming knowledge we do not have.
        if wanted {
            State::Partial("состояние ещё не проверено".into())
        } else {
            State::Off
        }
    } else if patched.iter().all(|p| *p) {
        State::On
    } else if patched.iter().any(|p| *p) {
        State::Partial("пропатчены не все установки".into())
    } else {
        State::Off
    }
}

#[cfg(windows)]
fn status_with_installation_observation(
    ctx: &Ctx,
    previous: Status,
    (installs, desktop_target): (Vec<InstallRow>, DesktopDiscovery),
    vscode_antigravity: VsCodeAntigravityObservation,
) -> Status {
    Status {
        wsl: wsl_status_with_target(ctx, desktop_target),
        client_patch: summarize_client_patch(&installs, ctx.settings.client_patch),
        installs,
        vscode_antigravity,
        ..previous
    }
}

#[cfg(windows)]
fn installations_only_status(ctx: &Ctx, previous: Status) -> Status {
    let settings = &ctx.settings;
    let patched_seen = &ctx.patched_seen;
    let owner = ctx.lifetime.new_command_scope();
    let receipt = owner.as_ref().ok().cloned();
    let cancel = &ctx.lifetime.abort_requested;
    let image = ctx.lifetime.retained_image().ok();
    let (observation, vscode_antigravity) = std::thread::scope(|scope| {
        scope.spawn(move || {
            let installs = collect_installs(settings, false, patched_seen, owner, cancel, image);
            (installs, observe_current_vscode_antigravity())
        }).join()
    }).unwrap_or_else(|_| (interrupted_install_observation(), VsCodeAntigravityObservation::Incomplete));
    drop(receipt);
    ctx.receive_command_results();
    status_with_installation_observation(ctx, previous, observation, vscode_antigravity)
}

fn read_status(ctx: &mut Ctx, deep: bool, mac_idle_extension: Option<VsCodeAntigravityObservation>,
    #[cfg(target_os = "macos")] mac_idle_rows: Option<Vec<InstallRow>>,
) -> Status {
    let admin = is_admin();

    // Every probe below spawns a helper process — two scheduled-task queries, a
    // tasklist, up to three reads of the user environment — and they are
    // independent of one another. Run in series they added up to seconds per
    // switch; run at once the refresh costs the slowest one. They only read, so
    // there is nothing here for them to race over.
    let settings = &ctx.settings;
    #[cfg(not(target_os = "macos"))]
    let patched_seen = &ctx.patched_seen;
    #[cfg(target_os = "macos")]
    let patched_seen = &mut ctx.patched_seen;
    #[cfg(target_os = "macos")]
    let previous = ctx.last.as_ref();
    #[cfg(windows)]
    let image = ctx.lifetime.retained_image();
    #[cfg(windows)]
    let install_image = image.as_ref().ok().cloned();
    #[cfg(windows)]
    let lifetime = ctx.lifetime.clone();
    #[cfg(windows)]
    let proxy_owner = ctx.lifetime.new_command_scope();
    #[cfg(windows)]
    let proxy_receipt = proxy_owner.as_ref().ok().map(|call| call.clone());
    #[cfg(windows)]
    let observation_owner = lifetime.new_command_scope();
    #[cfg(windows)]
    let observation_receipt = observation_owner.as_ref().ok().map(|call| call.clone());
    #[cfg(windows)]
    let install_owner = lifetime.new_command_scope();
    #[cfg(windows)]
    let install_receipt = install_owner.as_ref().ok().map(|call| call.clone());
    #[cfg(windows)]
    let install_cancel = lifetime.abort_requested.clone();
    #[cfg(not(windows))]
    let dns_owner = ctx.lifetime.new_command_scope();
    #[cfg(not(windows))]
    let dns_receipt = dns_owner.as_ref().ok().map(|call| call.clone());
    #[cfg(not(windows))]
    let previous_dns_probe = ctx.dns_probe;
    #[cfg(all(windows, ag_private_startup_scan_timing))]
    let startup_origin = startup_scan_timing::install_origin();
    let (install_observation, watchdog, dns_probe, local_proxy, own_proxy, own_proxy_text, relay_outdated) =
        std::thread::scope(|scope| {
            let installs = scope.spawn(move || {
                #[cfg(all(windows, ag_private_startup_scan_timing))]
                let install_timing = startup_scan_timing::begin_install(startup_origin);
                let observed = collect_installs(settings, deep, patched_seen, #[cfg(target_os = "macos")] previous,
                    #[cfg(target_os = "macos")] mac_idle_rows,
                    #[cfg(windows)] install_owner, #[cfg(windows)] &install_cancel, #[cfg(windows)] install_image);
                let observed = (observed, mac_idle_extension.unwrap_or_else(observe_current_vscode_antigravity));
                #[cfg(all(windows, ag_private_startup_scan_timing))]
                let observed = (observed, install_timing.and_then(startup_scan_timing::InstallScope::take));
                observed
            });
            #[cfg(not(windows))]
            let watchdog = scope.spawn(move || read_watchdog(admin));
            #[cfg(not(windows))]
            let dns_probe = scope.spawn(move || {
                let owner = dns_owner?;
                owner.with_result(probe_dns)
            });
            #[cfg(windows)]
            let observation = scope.spawn(move || {
                let owner = observation_owner?;
                owner.with_classified(|owner| observe_system(owner, &lifetime.abort_requested, image), observation_failure)
            });
            let local_proxy = scope.spawn(move || read_local_proxy(settings, #[cfg(windows)] proxy_owner));
            let own_proxy = scope.spawn(read_own_proxy);
            let own_proxy_text = scope.spawn(move || {
                upstream::configured()
                    .map(|u| u.display())
                    .unwrap_or_else(|| settings.own_proxy.clone())
            });
            #[cfg(target_os = "macos")]
            let relay_outdated = scope.spawn(background::checked_relay_outdated);
            #[cfg(all(not(windows), not(target_os = "macos")))]
            let relay_outdated = scope.spawn(|| Ok::<bool, String>(background::relay_is_outdated()));
            #[cfg(windows)]
            let observation = observation.join().unwrap_or_else(|_| Err("Наблюдение службы прервано".into()));
            let installs = installs.join();
            #[cfg(all(windows, ag_private_startup_scan_timing))]
            let installs = installs.map(|(observed, timing)| {
                startup_scan_timing::receive_install(timing);
                observed
            });
            (
                installs.unwrap_or_else(|_| (interrupted_install_observation(), VsCodeAntigravityObservation::Incomplete)),
                #[cfg(not(windows))]
                watchdog.join().unwrap_or(State::Off),
                #[cfg(windows)]
                State::Off,
                #[cfg(not(windows))]
                dns_probe.join().unwrap_or_else(|_| Err("DNS observation worker unwound".into()))
                    .unwrap_or_else(|error| { eprintln!("DNS observation unavailable; previous value retained: {error}"); previous_dns_probe }),
                #[cfg(windows)]
                observation,
                local_proxy.join().unwrap_or(State::Off),
                own_proxy.join().unwrap_or(State::Off),
                own_proxy_text.join().unwrap_or_default(),
                #[cfg(not(windows))]
                relay_outdated.join().unwrap_or_else(|_| Err("Проверка версии службы прервана".into())),
                #[cfg(windows)]
                false,
            )
        });
    #[cfg(windows)]
    { drop(proxy_receipt); drop(observation_receipt); drop(install_receipt); }
    #[cfg(not(windows))]
    drop(dns_receipt);
    ctx.receive_command_results();
    #[cfg(not(windows))]
    let (relay_outdated, background_observation_error) = receive_relay_currentness(relay_outdated);
    #[cfg(not(windows))]
    if let Some(detail) = &background_observation_error { ctx.log(Level::Warn, detail.clone()); }
    #[cfg(windows)]
    let background_observation_error = None;
    let ((installs, desktop_target), vscode_antigravity) = install_observation;
    #[cfg(windows)]
    receive_system_observation(ctx, dns_probe);
    #[cfg(not(windows))]
    { ctx.dns_probe = dns_probe; }
    #[cfg(windows)]
    let dns_probe = ctx.last.as_ref().map_or((false, false), |s| (s.rules, s.relay_running));
    #[cfg(not(windows))]
    let dns_probe = ctx.dns_probe;
    #[cfg(windows)]
    let relay_outdated = ctx.last.as_ref().is_some_and(|s| matches!(&s.selected_delivery, Ok(true)));

    let client_patch = summarize_client_patch(&installs, ctx.settings.client_patch);

    let status = Status {
        wsl: wsl_status_with_target(ctx, desktop_target),
        admin,
        client_patch,
        watchdog,
        dns: dns_state(
            admin,
            dns_probe.0,
            dns_probe.1,
            ctx.vpn,
            ctx.settings.vpn_detect,
            ctx.settings.dns,
        ),
        local_proxy,
        own_proxy,
        own_proxy_text,
        custom_dns_text: ctx.settings.custom_dns.clone(),
        builtin_exits: State::Off,
        group_proxy: State::Off,
        vpn: ctx.vpn,
        dns_rotation: State::Off,
        transport_view: TransportView::LegacyOrMissing,
        transport_choices: Err("Настройки подключения ещё не получены".into()),
        transport_ready: None,
        relay_outdated,
        #[cfg(windows)]
        selected_delivery: selected_delivery_unreceived(&ctx.lifetime),
        relay_running: dns_probe.1,
        background_observation_error,
        rules: dns_probe.0,
        rules_observed: None,
        relay_egress: ctx.relay_egress,
        providers: Vec::new(),
        installs,
        vscode_antigravity,
    }
    .with_settings_switches(&ctx.settings);
    #[cfg(windows)]
    { return apply_windows_observation(status, &ctx.dns_probe, &ctx.settings, ctx.vpn); }
    #[cfg(not(windows))]
    { status }
}

/// Asks the system where the traffic actually leaves.
///
/// Deliberately the same call `setup_dns_nrpt` makes, so the indicator and the
/// decision can never disagree: anything else would be a second opinion, and a
/// second opinion is how a user ends up told one thing while the layer does
/// another.
fn measure_vpn(owner: &mut crate::utils::CommandOutcome) -> Result<(VpnSeen, Option<crate::egress::ClientEgress>), String> {
    use crate::egress::ClientEgress;
    if crate::egress::observation_support() == crate::egress::ObservationSupport::Unsupported {
        return Ok((VpnSeen::Unmeasured, None));
    }
    let egress = crate::egress::detect(owner)?;
    if !egress.as_ref().is_some_and(|e| e.vpn_active) {
        return Ok((VpnSeen::None, None));
    }
    // One reading, both halves — the same call `egress::vpn_verdict` makes for
    // the DNS layer, so the row this colours and the decision that layer takes
    // cannot be looking at different data. What is *reported* is the
    // measurement itself, not the verdict derived from it: "stand the layer
    // down" and "the client is outside the tunnel" are different questions, and
    // reading the first as the second is what made the indicator claim a
    // measurement nobody had taken.
    let reading = crate::egress::read(owner)?;
    let client = match reading.client {
        ClientEgress::Tunnel => VpnSeen::CarryingClient,
        ClientEgress::Mixed => VpnSeen::PartlyCarryingClient,
        ClientEgress::Physical => VpnSeen::NotCarryingClient,
        ClientEgress::ViaLocalProxy => VpnSeen::ViaLocalProxy,
        ClientEgress::Unknown => VpnSeen::Unmeasured,
    };
    Ok((client, Some(reading.relay)))
}

/// The one line the journal gets when the answer changes. An `Unmeasured` is
/// not a change worth a line: it says only that Antigravity stopped running.
fn vpn_change_line(now: VpnSeen) -> Option<&'static str> {
    match now {
        VpnSeen::None => Some("VPN отключён — обход снова работает сам."),
        VpnSeen::CarryingClient => Some(
            "Antigravity пошёл через VPN — снятие ошибки 400 теперь зависит от вашего сервера.",
        ),
        VpnSeen::NotCarryingClient => Some("Трафик Antigravity идёт мимо VPN — обход применяется."),
        VpnSeen::ViaLocalProxy => Some(
            "Antigravity ходит через локальный прокси — до серверов Google \
             соединение открывает служба обхода, а не он сам.",
        ),
        VpnSeen::PartlyCarryingClient => {
            Some("Часть трафика Antigravity пошла через VPN, часть идёт мимо.")
        }
        VpnSeen::Unmeasured => None,
    }
}

/// Windows registers the watcher as a machine task, which takes UAC; on Linux
/// it is a user unit and anyone may have it. Without this the «Включить всё»
/// path and the patch switch skipped auto-patch for every non-root user, and the
/// row stayed off for good.
fn watchdog_allowed(admin: bool) -> bool {
    admin || !cfg!(target_os = "windows")
}

fn read_watchdog(admin: bool) -> State {
    #[cfg(windows)]
    { let _ = admin; return match background::checked_task_state() {
        Ok(value) if value.watchdog_enabled => State::On,
        Ok(_) => State::Off,
        Err(error) => State::Blocked(error),
    }; }
    #[cfg(target_os = "macos")]
    { return match background::watchdog_running_checked() {
        Ok(true) => State::On, Ok(false) => State::Off, Err(error) => State::Blocked(error),
    }; }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
    if background::is_watchdog_enabled() {
        State::On
    } else if !admin && cfg!(target_os = "windows") {
        State::Blocked("нужны права администратора".into())
    } else {
        State::Off
    }
    }
}

fn watchdog_checked() -> Result<bool, String> {
    #[cfg(windows)]
    { background::checked_task_state().map(|state| state.watchdog_enabled) }
    #[cfg(target_os = "macos")]
    { background::watchdog_running_checked() }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    { Ok(background::is_watchdog_enabled()) }
}

fn stop_watchdog_checked() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    { background::disable_watchdog_checked() }
    #[cfg(not(target_os = "macos"))]
    { background::disable_watchdog(); Ok(()) }
}

/// The two facts about the DNS layer that only the machine can answer: are our
/// NRPT rules in, and is the relay task both registered and running.
///
/// Split from the verdict below so a settings-only refresh can rebuild the row
/// from the last measurement instead of asking Windows again (`Scan::Settings`).
#[cfg(not(windows))]
fn probe_dns(owner: &mut crate::utils::CommandOutcome) -> Result<(bool, bool), String> {
    let rules = dns::is_nrpt_applied(owner)?;
    let relay = background::is_enabled() && background::is_running() && relay_reporting();
    Ok((rules, relay))
}

/// Whether the relay itself is alive, and not only a process of its name.
///
/// `is_running` matches `ag_dns.exe` in the task list, and the watchdog is a
/// second process with that same image name - so a relay that died on startup
/// still read as running for as long as its watchdog lived (P54). A field
/// report printed both halves of that contradiction in one paste: «Служба:
/// запущена» over «Записи нет — служба не запущена или старая». The relay
/// writes `gate.json` from its first moment (`gate::note_started`) and on every
/// warm pass; the watchdog never writes it.
///
/// Windows only. The Linux proxy writes that file solely to record a blocker,
/// so there the systemd unit being active is all there is to go on.
fn relay_reporting() -> bool {
    !cfg!(target_os = "windows") || crate::gate::read().is_some_and(|r| !r.is_stale())
}

fn dns_state(
    admin: bool,
    rules: bool,
    relay: bool,
    vpn: Option<VpnSeen>,
    detect_on: bool,
    wanted: bool,
) -> State {
    if !Cap::Dns.supported() {
        return State::Blocked("Обход через DNS недоступен на macOS".into());
    }
    // No VPN branch any more (D25): the layer does not stand down for a tunnel,
    // so a client measured inside one says nothing about whether the rules are
    // doing their job. The parameters stay so the callers keep one signature.
    let _ = (vpn, detect_on);
    match (rules, relay) {
        (true, true) => State::On,
        // The rules name the relay first (I5). Rules without it resolve through
        // the fallback providers only, which works but is not what was asked
        // for — and it is exactly what a crashed relay looks like.
        (true, false) => State::Partial("правила стоят, служба не запущена".into()),
        // A service that runs for the sake of a route (own proxy, group, exits)
        // is not a half-installed DNS layer: the DNS switch is off, and drawing
        // it as `Partial` - which reads as on - made it impossible to switch off
        // while any route kept the service up.
        (false, true) if !wanted => State::Off,
        (false, true) => State::Partial("служба работает, правил нет".into()),
        (false, false) => {
            if !admin && cfg!(target_os = "windows") {
                State::Blocked("нужны права администратора".into())
            } else {
                State::Off
            }
        }
    }
}

/// The local-proxy switch: what the user asked for, and whether the variable
/// has caught up with it.
///
/// Both halves, because the two readers of this route are not the same process.
/// The relay obeys `settings.local_proxy` and nothing else; the window used to
/// draw the switch from the environment alone, so a variable that outlived a
/// failed removal made the window say «вкл» in the same minute the service
/// logged «выключена в настройках», with nothing on screen to explain it or
/// any way for the user to act on it (G74, two field reports on `2.15.1`).
fn read_local_proxy(settings: &Settings, #[cfg(windows)] owner: Result<crate::command_lifetime::PendingCommand, String>) -> State {
    let url = proxy::proxy_url();
    #[cfg(windows)]
    let scope = match owner { Ok(scope) => scope, Err(error) => return State::Blocked(error) };
    #[cfg(windows)]
    return scope.with_result(|owner| {
        if endpoint::foreign_proxy(owner, &url)?.is_some() { return Ok(State::Blocked("в системе задан свой прокси".into())); }
        Ok(local_proxy_state(settings.local_proxy, endpoint::proxy_env_is_ours(owner)?))
    }).unwrap_or_else(State::Blocked);
    #[cfg(not(windows))]
    let foreign = endpoint::foreign_proxy(&url);
    #[cfg(not(windows))]
    if let Some(foreign) = foreign {
        // Measured (G33): ours wins over theirs inside the patched server, so
        // leaving both set silently hijacks a proxy the user configured on
        // purpose. Theirs means ours stays off - whatever the setting says.
        let _ = foreign;
        return State::Blocked("в системе задан свой прокси".into());
    }
    #[cfg(not(windows))]
    let ours = endpoint::proxy_env_is_ours();
    #[cfg(not(windows))]
    local_proxy_state(settings.local_proxy, ours)
}

/// The switch itself, away from the machine it reads.
///
/// The invariant, and the whole point of the split: the switch **never reads as
/// on while the setting is off**, because the setting is the only thing the
/// relay obeys. Anything else is a window that disagrees with the service and
/// leaves the user nothing to act on (G74).
fn local_proxy_state(wanted: bool, ours: bool) -> State {
    match (wanted, ours) {
        (true, true) => State::On,
        // Asked for, not written yet: the relay writes it once its listener
        // answers, and `repair` does the same while the window is open. An
        // on-ish state, so `Partial` and never `OffNote` - the switch has to
        // stay switchable (G41).
        (true, false) => State::Partial("переменная ещё не выставлена".into()),
        // Off, and the variable is still there: a removal that did not land.
        // The relay takes it off within a minute now; saying so beats a switch
        // that contradicts the service's own log.
        (false, true) => State::OffNote("переменная ещё не снята".into()),
        (false, false) => State::Off,
    }
}

fn read_own_proxy() -> State {
    if upstream::configured().is_some() {
        State::On
    } else {
        State::Off
    }
}

/// The three kinds, in the order the window lists them.
const INSTALL_KINDS: [&str; 3] = ["Antigravity 2.0", "Antigravity IDE", "Antigravity CLI"];

fn fast_install_roots() -> Vec<PathBuf> {
    #[cfg(all(test, target_os = "macos"))]
    let discovered = if std::env::var_os("AG_MAC_CACHE_TEST_ROOT").is_some() {
        Vec::new()
    } else { crate::discover_installs_fast() };
    #[cfg(not(all(test, target_os = "macos")))]
    let discovered = crate::discover_installs_fast();
    discovered
}

fn install_rows(settings: &Settings) -> Vec<InstallRow> {
    install_rows_from_discovery(settings, fast_install_roots())
}

fn install_rows_from_discovery(settings: &Settings, discovered: Vec<PathBuf>) -> Vec<InstallRow> {
    // Manual paths retain their existing display precedence.
    let mut chosen: Vec<(PathBuf, bool)> = settings.manual_paths.iter().map(|p| (p.clone(), true)).collect();
    for path in discovered {
        if !chosen.iter().any(|(p, _)| p == &path) {
            chosen.push((path, false));
        }
    }

    let mut rows: Vec<InstallRow> = Vec::new();
    for label in INSTALL_KINDS {
        let hit = chosen
            .iter()
            .find(|(p, _)| crate::install_label(p) == label)
            .cloned();
        rows.push(match hit {
            Some((path, manual)) => InstallRow {
                label,
                patched: None,
                manual,
                path: Some(path),
                #[cfg(windows)]
                observed_kind: None,
                #[cfg(any(windows, target_os = "macos"))]
                coverage: InstallCoverage::Complete,
            },
            None => InstallRow {
                label,
                patched: None,
                manual: false,
                path: None,
                #[cfg(windows)]
                observed_kind: None,
                #[cfg(any(windows, target_os = "macos"))]
                coverage: InstallCoverage::Complete,
            },
        });
    }
    // Anything the user pointed at that does not answer to one of the three
    // names still gets a row - it is theirs, and dropping it silently would look
    // like the pencil did nothing.
    for (path, manual) in chosen {
        if !manual || rows.iter().any(|r| r.path.as_ref() == Some(&path)) {
            continue;
        }
        rows.push(InstallRow {
            label: crate::install_label(&path),
            patched: None,
            manual: true,
            path: Some(path),
            #[cfg(windows)]
            observed_kind: None,
            #[cfg(any(windows, target_os = "macos"))]
            coverage: InstallCoverage::Complete,
        });
    }

    rows
}

#[cfg(target_os = "macos")]
fn mac_user_applications_directory(home: &Path) -> Option<PathBuf> {
    if !home.is_absolute() || home.components().any(|part| part == std::path::Component::ParentDir) {
        return None;
    }
    Some(home.join("Applications"))
}

#[cfg(target_os = "macos")]
fn mac_user_application_candidates(home: &Path) -> Vec<PathBuf> {
    use std::fs;

    let Some(directory) = mac_user_applications_directory(home) else { return Vec::new(); };
    let ancestors: Vec<_> = directory.ancestors().collect();
    if !ancestors.into_iter().rev().all(|parent| fs::symlink_metadata(parent).is_ok_and(|metadata| metadata.is_dir())) {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(directory) else { return Vec::new(); };
    let mut candidates: Vec<_> = entries.filter_map(Result::ok).filter_map(|entry| {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        (name.ends_with(".app") && name.contains("antigravity") && entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .then(|| entry.path())
    }).collect();
    candidates.sort_unstable();
    candidates
}

#[cfg(target_os = "macos")]
fn receive_mac_inventory(
    rows: &mut [InstallRow],
    discovered: &[PathBuf],
    user_apps: &[PathBuf],
    mut observe_kind: impl FnMut(&Path) -> Option<crate::InstallationKind>,
) {
    use crate::InstallationKind::{Cli, Desktop, Ide};
    let mut kinds = HashMap::new();
    for path in discovered.iter().chain(user_apps) {
        kinds.entry(path.as_path()).or_insert_with(|| observe_kind(path));
    }
    let labels = [(Desktop, INSTALL_KINDS[0]), (Ide, INSTALL_KINDS[1]), (Cli, INSTALL_KINDS[2])];
    for row in rows {
        let Some(intended) = labels.iter().find_map(|(kind, label)| (*label == row.label).then_some(*kind)) else {
            row.coverage = InstallCoverage::Incomplete;
            continue;
        };
        let bound = row.path.as_deref().and_then(|path| {
            *kinds.entry(path).or_insert_with(|| observe_kind(path))
        });
        let mut passive = discovered.iter().chain(user_apps.iter().filter(|_| intended != Cli));
        row.coverage = if bound == Some(intended) {
            InstallCoverage::Complete
        } else if let Some(path) = passive.find(|path| kinds.get(path.as_path()) == Some(&Some(intended))) {
            InstallCoverage::ObservedStandard(path.clone())
        } else {
            InstallCoverage::Incomplete
        };
    }
}

#[cfg(target_os = "macos")]
fn mac_install_rows(settings: &Settings, previous: Option<&Status>, user_apps: &[PathBuf]) -> Vec<InstallRow> {
    let discovered = fast_install_roots();
    let mut rows = install_rows_from_discovery(settings, discovered.clone());
    if let Some(previous) = previous {
        for old in &previous.installs {
            let Some(path) = &old.path else { continue; };
            if rows.iter().any(|row| row.path.as_ref() == Some(path)) { continue; }
            if patch_binary::mac_target_snapshot(path).is_err() {
                if let Err(error) = std::fs::metadata(path) {
                    if patch_binary::mac_confirm_absent(path, error).is_ok() { continue; }
                }
                let mut unknown = old.clone(); unknown.patched = None;
                if let Some(slot) = rows.iter_mut().find(|row| row.label == old.label && row.path.is_none()) { *slot = unknown; }
                else { rows.push(unknown); }
            }
        }
    }
    receive_mac_inventory(&mut rows, &discovered, user_apps, crate::observe_mac_installation_kind);
    rows
}

#[cfg(target_os = "macos")]
fn carry_mac_user_inventory(rows: &mut [InstallRow], previous: &[InstallRow], home: &Path) {
    let Some(directory) = mac_user_applications_directory(home) else { return; };
    for row in rows {
        if row.coverage != InstallCoverage::Incomplete || row.label == INSTALL_KINDS[2] { continue; }
        if let Some(prior) = previous.iter().find(|prior| {
            prior.label == row.label && prior.path == row.path && prior.manual == row.manual
                && matches!(&prior.coverage, InstallCoverage::ObservedStandard(path)
                    if path.parent() == Some(directory.as_path()))
        }) { row.coverage = prior.coverage.clone(); }
    }
}

#[cfg(target_os = "macos")]
fn mac_idle_observation(ctx: &mut Ctx) -> Option<Vec<InstallRow>> {
    let previous = ctx.last.as_ref()?;
    if ctx.lifetime.abort_requested.load(Ordering::SeqCst) { return None; }
    // The supplemental search belongs to this deferred pass. Its projected
    // rows are reused for publication, including any incomplete evidence.
    let user_apps = if cfg!(test) && std::env::var_os("AG_MAC_CACHE_TEST_ROOT").is_some() {
        Vec::new()
    } else {
        crate::dns_forwarder::unix_user_home().map_or_else(|_| Vec::new(), |home| mac_user_application_candidates(&home))
    };
    if ctx.lifetime.abort_requested.load(Ordering::SeqCst) { return None; }
    let rows = mac_install_rows(&ctx.settings, Some(previous), &user_apps);
    if ctx.lifetime.abort_requested.load(Ordering::SeqCst) { return None; }
    let old = &previous.installs;
    let mut changed = rows.len() != old.len() || rows.iter().zip(old).any(|(left, right)|
        left.path != right.path || left.label != right.label || left.manual != right.manual
            || left.coverage != right.coverage);
    for row in &rows {
        let Some(path) = &row.path else { continue; };
        let visible = old.iter().find(|prior| prior.path.as_ref() == Some(path)).and_then(|prior| prior.patched);
        let observation = ctx.patched_seen.entry(path.clone()).or_default();
        match patch_binary::mac_target_snapshot(path) {
            Ok(snapshot) if observation.settled.as_ref().is_some_and(|(old, _)| old == &snapshot) => {},
            Ok(snapshot) if observation.pending.as_ref() == Some(&snapshot) => {
                if !observation.pending_ready { observation.pending_ready = true; changed = true; }
            },
            Ok(snapshot) => {
                observation.settled = None;
                observation.pending = Some(snapshot);
                observation.pending_ready = false;
                if visible.is_some() { changed = true; }
            },
            Err(_) => {
                *observation = MacObservation::default();
                if visible.is_some() { changed = true; }
            },
        }
    }
    ctx.patched_seen.retain(|path, _| rows.iter().any(|row| row.path.as_ref() == Some(path)));
    changed.then_some(rows)
}

// Presence is informational. Two manifest walks per minute bound idle staleness
// to half a minute without putting JSON reads on the 2-second metadata poll.
const VSCODE_OBSERVATION_INTERVAL: Duration = Duration::from_secs(30);

fn poll_vscode_antigravity(
    last_observation: &mut std::time::Instant,
    now: std::time::Instant,
    previous: VsCodeAntigravityObservation,
    observe: impl FnOnce() -> VsCodeAntigravityObservation,
) -> Option<VsCodeAntigravityObservation> {
    if now.duration_since(*last_observation) < VSCODE_OBSERVATION_INTERVAL { return None; }
    *last_observation = now;
    let current = observe();
    (current != previous).then_some(current)
}

fn observe_current_vscode_antigravity() -> VsCodeAntigravityObservation {
    #[cfg(windows)]
    let profile = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let profile = std::env::var_os("HOME");
    observe_vscode_antigravity(profile.as_deref().map(Path::new))
}

fn observe_vscode_antigravity(profile: Option<&Path>) -> VsCodeAntigravityObservation {
    use VsCodeAntigravityObservation::{Found, Incomplete, NotFound};

    let Some(profile) = profile.filter(|path| path.is_absolute()) else { return Incomplete; };
    match std::fs::symlink_metadata(profile) {
        Ok(metadata) if metadata.is_dir() && !is_vscode_observation_link(&metadata) => {},
        _ => return Incomplete,
    }

    let mut result = NotFound;
    for editor in [".vscode", ".vscode-insiders"] {
        match observe_vscode_extension_root(profile, editor) {
            Found => return Found,
            Incomplete => result = Incomplete,
            NotFound => {},
        }
    }
    result
}

fn observe_vscode_extension_root(profile: &Path, editor: &str) -> VsCodeAntigravityObservation {
    use std::fs;
    use std::io::ErrorKind;
    use VsCodeAntigravityObservation::{Found, Incomplete, NotFound};

    let mut root = profile.to_path_buf();
    for component in [editor, "extensions"] {
        root.push(component);
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.is_dir() && !is_vscode_observation_link(&metadata) => {},
            Err(error) if error.kind() == ErrorKind::NotFound => return NotFound,
            _ => return Incomplete,
        }
    }

    let Ok(entries) = fs::read_dir(root) else { return Incomplete; };
    let mut result = NotFound;
    for entry in entries {
        let candidate = entry.and_then(|entry| entry.metadata().map(|metadata| (entry.path(), metadata)));
        match candidate {
            Ok((path, metadata)) if !is_vscode_observation_link(&metadata) => {
                if metadata.is_dir() {
                    match read_vscode_extension_manifest(&path.join("package.json")) {
                        Ok(true) => return Found,
                        Ok(false) => {},
                        Err(()) => result = Incomplete,
                    }
                } else if !metadata.is_file() {
                    result = Incomplete;
                }
            },
            _ => result = Incomplete,
        }
    }
    result
}

fn is_vscode_observation_link(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    { crate::discovery_reparse_point(metadata) }
    #[cfg(not(windows))]
    { metadata.file_type().is_symlink() }
}

fn read_vscode_extension_manifest(path: &Path) -> Result<bool, ()> {
    use std::io::{BufRead, BufReader};

    #[derive(serde::Deserialize)]
    struct ExtensionManifest {
        publisher: String,
        name: String,
    }

    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_file() || is_vscode_observation_link(&metadata) { return Err(()); }
    let file = std::fs::File::open(path).map_err(|_| ())?;
    let mut reader = BufReader::new(file);
    // Serde structs can deserialize from sequences. A package manifest has named fields.
    loop {
        let buffer = reader.fill_buf().map_err(|_| ())?;
        match buffer.iter().copied().find(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n')) {
            Some(b'{') => break,
            Some(_) => return Err(()),
            None if buffer.is_empty() => return Err(()),
            None => { let consumed = buffer.len(); reader.consume(consumed); },
        }
    }
    let manifest: ExtensionManifest = serde_json::from_reader(reader).map_err(|_| ())?;
    if manifest.publisher.trim().is_empty() || manifest.name.trim().is_empty() { return Err(()); }
    Ok(manifest.publisher == "google" && manifest.name == "google-antigravity")
}

fn collect_installs(
    settings: &Settings,
    deep: bool,
    #[cfg(not(target_os = "macos"))] seen: &HashMap<PathBuf, bool>,
    #[cfg(target_os = "macos")] seen: &mut HashMap<PathBuf, MacObservation>,
    #[cfg(target_os = "macos")] previous: Option<&Status>,
    #[cfg(target_os = "macos")] mac_idle_rows: Option<Vec<InstallRow>>,
    #[cfg(windows)] discovery: Result<crate::command_lifetime::PendingCommand, String>,
    #[cfg(windows)] cancellation: &AtomicBool,
    #[cfg(windows)] image: Option<Arc<crate::windows_coordinator::process_identity::CurrentImage>>,
) -> (Vec<InstallRow>, DesktopDiscovery) {
    #[cfg(all(windows, ag_private_startup_scan_timing))]
    let classify_start = startup_scan_timing::install_mark();
    #[cfg(windows)]
    let (mut rows, desktop_target) = match discovery {
        Ok(owner) => owner.with_classified(|command| project_install_discovery(
            settings, crate::find_passive_status_installs_checked(command, cancellation, image),
            || crate::observe_standard_install_kinds(crate::standard_install_candidates(), cancellation),
        ), |(_, target)| target.error().map(str::to_owned)),
        Err(error) => project_install_discovery(settings, Err(error), Vec::new),
    };
    #[cfg(all(windows, ag_private_startup_scan_timing))]
    startup_scan_timing::record_classification(classify_start, rows.len(), &desktop_target);
    #[cfg(all(not(windows), not(target_os = "macos")))]
    let mut rows = install_rows(settings);
    #[cfg(target_os = "macos")]
    let mut rows = mac_idle_rows.unwrap_or_else(|| {
        let mut rows = mac_install_rows(settings, previous, &[]);
        if let Some(previous) = previous {
            if let Ok(home) = crate::dns_forwarder::unix_user_home() {
                carry_mac_user_inventory(&mut rows, &previous.installs, &home);
            }
        }
        rows
    });
    #[cfg(all(windows, ag_private_startup_scan_timing))]
    let mut next_row_index = 0;
    for row in &mut rows {
        #[cfg(all(windows, ag_private_startup_scan_timing))]
        let row_index = {
            let index = next_row_index;
            next_row_index += 1;
            index
        };
        let Some(path) = row.path.clone() else {
            continue;
        };
        #[cfg(target_os = "macos")]
        { row.patched = mac_observe_install(&path, deep, seen.entry(path.clone()).or_default()); }
        #[cfg(not(target_os = "macos"))]
        if deep {
            #[cfg(all(windows, ag_private_startup_scan_timing))]
            let inspect_start = startup_scan_timing::inspect_start(row_index);
            let state = patch_binary::inspect_install(&path);
            #[cfg(all(windows, ag_private_startup_scan_timing))]
            startup_scan_timing::inspect_end(inspect_start, row_index, &state);
            row.patched = if state.is_empty() {
                None
            } else {
                Some(state.fully_patched())
            };
        } else {
            row.patched = seen.get(&path).copied();
        }
    }
    #[cfg(windows)]
    { (rows, desktop_target) }
    #[cfg(not(windows))]
    { (rows, DesktopDiscovery::Incomplete { desktop_found: false, error: "Применение WSL доступно только в Windows.".into() }) }
}

#[cfg(windows)]
fn project_install_discovery(
    settings: &Settings,
    discovered: Result<Vec<PathBuf>, String>,
    observe_standard: impl FnOnce() -> Vec<crate::InstallationKind>,
) -> (Vec<InstallRow>, DesktopDiscovery) {
    let discovered = match discovered {
        Ok(paths) => paths,
        Err(error) => {
            use crate::InstallationKind::{Cli, Desktop, Ide};
            let observed = observe_standard();
            let mut rows = install_rows_from_discovery(settings, Vec::new());
            for row in &mut rows {
                let standards = [(Desktop, INSTALL_KINDS[0]), (Ide, INSTALL_KINDS[1]), (Cli, INSTALL_KINDS[2])];
                row.coverage = if row.path.is_none()
                    && standards.into_iter().any(|(kind, label)| row.label == label && observed.contains(&kind))
                {
                    InstallCoverage::ObservedStandard
                } else {
                    InstallCoverage::Incomplete
                };
            }
            return (rows, DesktopDiscovery::Incomplete { desktop_found: false, error });
        }
    };
    let mut all = discovered.clone();
    for path in &settings.manual_paths { if !all.contains(path) { all.push(path.clone()); } }
    #[cfg(all(windows, ag_private_startup_scan_timing))]
    let classification = startup_scan_timing::discovery_phase(startup_scan_timing::DiscoveryPhase::LocalClassification);
    let kinds: Vec<_> = all.iter().map(|path| (path, crate::receive_installation_layout(path).map(|layout| layout.kind))).collect();
    let target = desktop_kind_result(kinds.iter().map(|(_, kind)| kind.clone()));
    #[cfg(all(windows, ag_private_startup_scan_timing))]
    classification.finish(!matches!(&target, DesktopDiscovery::Incomplete { .. }));
    let mut rows = install_rows_from_discovery(settings, discovered);
    for row in &mut rows {
        if matches!(&target, DesktopDiscovery::Incomplete { .. }) {
            row.coverage = InstallCoverage::Incomplete;
        }
        row.observed_kind = kinds.iter().find(|(path, _)| row.path.as_ref() == Some(*path))
            .and_then(|(_, kind)| kind.as_ref().ok().copied());
    }
    (rows, target)
}

#[cfg(windows)]
fn desktop_kind_result(kinds: impl IntoIterator<Item = Result<crate::InstallationKind, String>>) -> DesktopDiscovery {
    let mut desktop_found = false;
    let mut first_error = None;
    for kind in kinds {
        match kind {
            Ok(crate::InstallationKind::Desktop) => desktop_found = true,
            Err(error) if first_error.is_none() => first_error = Some(error),
            _ => {}
        }
    }
    match first_error {
        Some(error) => DesktopDiscovery::Incomplete { desktop_found, error },
        None if desktop_found => DesktopDiscovery::Present,
        None => DesktopDiscovery::Absent,
    }
}

// ---------------------------------------------------------------------------
// Applying a switch
// ---------------------------------------------------------------------------

fn save_received_settings(staged: &Settings) -> Result<Settings, String> {
    staged.encode_for_save()?;
    staged.save_checked()?;
    let saved = crate::settings::saved_intent_sha256(staged)?;
    crate::settings::receive_saved_intent(&saved)
}

fn commit_transport(ctx: &mut Ctx, choices: impl IntoIterator<Item = TransportChoice>) -> Result<(), String> {
    let mut staged = ctx.settings.clone();
    let mut changed = false;
    #[cfg(target_os = "macos")]
    let mut proxy_intent_changed = false;
    for choice in choices {
        if matches!(choice, TransportChoice::BuiltinExits(true)) && !proxy::exits_available() {
            return Err("Встроенные выходы недоступны; включение не выполнено.".into());
        }
        #[cfg(target_os = "macos")]
        let proxy_choice = matches!(choice, TransportChoice::LocalProxy(_));
        let edit = staged.set_transport_choice(choice)?;
        #[cfg(target_os = "macos")]
        { proxy_intent_changed |= proxy_choice && (edit.value_changed || edit.presence_changed); }
        changed |= edit.value_changed || edit.presence_changed;
    }
    if changed {
        #[cfg(target_os = "macos")]
        let _proxy_guard = proxy_intent_changed.then(crate::instances::acquire_proxy_environment_writer).transpose()?;
        ctx.settings = save_received_settings(&staged)?;
    }
    Ok(())
}

#[cfg(windows)]
enum ProfileSelection { System, Configured(crate::settings::TransportChoices) }

#[cfg(windows)]
fn configured_values(c: crate::settings::TransportChoices) -> Result<(bool, bool, bool, bool, bool), String> {
    match (c.dns, c.local_proxy, c.builtin_exits, c.group_proxy, c.own_proxy_enabled) {
        (Some(dns), Some(local), Some(builtin), Some(group), Some(own)) => Ok((dns, local, builtin, group, own)),
        _ => Err("Выберите включено или выключено для каждого варианта подключения.".into()),
    }
}

/// Receive the exact saved profile before any migration effect.
#[cfg(windows)]
fn select_profile(ctx: &mut Ctx, selection: ProfileSelection) -> Result<crate::settings::ActiveTransportConfig, String> {
    let configured = match selection {
        ProfileSelection::System => None,
        ProfileSelection::Configured(c) => Some(configured_values(c)?),
    };
    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Действие отменено до начала.".into()); }
    if !is_admin() { return Err("Нужны права администратора для изменения собственных правил DNS.".into()); }
    let mut staged = match crate::settings::read() {
        crate::settings::Read::Missing => Settings::default(),
        crate::settings::Read::Parsed(settings) => settings,
        crate::settings::Read::Broken | crate::settings::Read::Unavailable => return Err("Настройки не получены; изменение не начиналось.".into()),
    };
    if let Some((dns, local, builtin, group, own)) = configured {
        if builtin && !proxy::exits_available() {
            return Err("Встроенные выходы недоступны; режим не изменён.".into());
        }
        staged.select_existing_configured(dns, local, builtin, group, own)?;
    } else { staged.select_system_tcp()?; }
    staged.encode_for_save()?;
    staged.save_checked()?;
    let digest = crate::settings::saved_intent_sha256(&staged)?;
    let (received, requirements) = match crate::settings::receive_saved_transport_intent(&digest)? {
        crate::settings::TransportIntent::Explicit { settings, requirements } => (settings, requirements),
        _ => return Err("Сохранённый режим подключения не подтверждён; правила DNS не изменялись.".into()),
    };
    let requested = if configured.is_some() { crate::settings::TransportProfile::ExistingConfigured } else { crate::settings::TransportProfile::SystemTcp };
    if requirements.active_config.profile != requested {
        return Err("Получен другой режим подключения; правила DNS не изменялись.".into());
    }
    ctx.settings = received;
    Ok(requirements.active_config)
}

#[cfg(windows)]
fn reconcile_explicit_carrier(ctx: &mut Ctx, expected: crate::settings::ActiveTransportConfig, watchdog: Option<bool>) -> Result<(), String> {
    let requirements = ctx.settings.transport_requirements()?;
    if requirements.active_config != expected { return Err("Сохранённый режим подключения изменился до получения службы.".into()); }
    if expected.profile == crate::settings::TransportProfile::SystemTcp && expected.client_proxy && ctx.with_command(dns::checked_nrpt_state)?.owned_rules_present {
        return Err("Собственные правила DNS всё ещё присутствуют; системное подключение не подтверждено.".into());
    }
    let cancellation = ctx.native_cancel.clone();
    let receiving = background::reconcile_changes_with_receiving(
        background::BackgroundChanges { relay: Some(requirements.carrier), watchdog },
        background::ImageDemand::DeliverSelectedImage, &cancellation, ctx.lifetime.retained_image(), Some(expected));
    ctx.retain_background_receiving(receiving)?;
    if expected.client_proxy { enable_local_proxy_effect(ctx)?; }
    Ok(())
}

#[cfg(windows)]
fn apply_selected_profile(ctx: &mut Ctx, expected: crate::settings::ActiveTransportConfig) -> Result<(), String> {
    if !expected.dns { remove_dns_rules_effect(ctx)?; }
    if !expected.client_proxy && ctx.proxy_env_is_ours()? { disable_local_proxy_effect(ctx)?; }
    reconcile_explicit_carrier(ctx, expected, None)?;
    if expected.dns { apply_dns_rules_after_explicit_ready(ctx, expected)?; }
    if ctx.settings.transport_requirements()?.carrier {
        let received = background::observe_background_for_transport(&ctx.native_cancel,
            Some(ctx.lifetime.retained_image()?), expected)?;
        for (name, wanted, observed) in [
            ("DNS", expected.dns, &received.dns),
            ("TCP", expected.tcp_proxy, &received.tcp_proxy),
            ("локальные адреса DNS", expected.dns_alias, &received.dns_alias),
        ] {
            let matches = match (wanted, observed) {
                (true, background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready)) => true,
                (false, background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled)) => true,
                _ => false,
            };
            if !matches {
                let detail = match observed {
                    background::TransportChannelObservation::Unknown(error)
                    | background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Failed(error)) => format!(": {error}"),
                    _ => String::new(),
                };
                return Err(format!("Состояние {name} для выбранного режима не подтверждено{detail}."));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn use_system_tcp(ctx: &mut Ctx) -> Result<(), String> {
    let expected = select_profile(ctx, ProfileSelection::System)?;
    apply_selected_profile(ctx, expected)?;
    ctx.log(Level::Ok, "Режим службы и локальный прокси подтверждены; ответ модели проверяется отдельно.");
    Ok(())
}

#[cfg(windows)]
fn use_existing_configured(ctx: &mut Ctx, choices: crate::settings::TransportChoices) -> Result<(), String> {
    let expected = select_profile(ctx, ProfileSelection::Configured(choices))?;
    apply_selected_profile(ctx, expected)?;
    ctx.log(Level::Ok, "Выбранный режим службы получен; ответ модели проверяется отдельно.");
    Ok(())
}

#[cfg(not(windows))]
fn use_existing_configured(_ctx: &mut Ctx, _choices: crate::settings::TransportChoices) -> Result<(), String> {
    Err("Выбор режима на этой платформе пока не поддерживается.".into())
}

#[cfg(not(windows))]
fn use_system_tcp(_ctx: &mut Ctx) -> Result<(), String> {
    Err("Системное подключение на этой платформе пока не поддерживается.".into())
}

fn apply(ctx: &mut Ctx, cap: Cap, on: bool) -> Result<(), String> {
    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Действие отменено до следующего эффекта.".into()); }
    if !cap.supported() { return Err("Обход через DNS недоступен на macOS".into()); }
    #[cfg(windows)]
    if on && matches!(cap, Cap::Dns | Cap::LocalProxy | Cap::OwnProxy | Cap::BuiltinExits | Cap::GroupProxy) {
        match crate::settings::read() {
            crate::settings::Read::Parsed(settings) if !matches!(settings.transport_profile, crate::settings::TransportProfileSetting::Invalid(_)) => {}
            crate::settings::Read::Parsed(_) => return Err("Сохранённый режим подключения не распознан; включение не начиналось.".into()),
            crate::settings::Read::Missing => return Err("Сначала выберите способ подключения.".into()),
            crate::settings::Read::Broken | crate::settings::Read::Unavailable => return Err("Настройки подключения не получены; включение не начиналось.".into()),
        }
    }
    #[cfg(windows)]
    if cap == Cap::Dns && on && matches!(ctx.settings.transport_profile,
        crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::SystemTcp)) {
        return Err("Для включения DNS откройте «Настроенное подключение», выберите все пункты и примените режим.".into());
    }
    if cap.needs_admin() && !is_admin() {
        return Err("Нужны права администратора. Нажмите «Перезапустить от имени администратора».".into());
    }

    match (cap, on) {
        (Cap::ClientPatch, true) => {
            // From the click, unlike the line below: the user wants the patch
            // whether or not an install was found to take it, and auto-patch
            // puts it on whatever turns up later (D27).
            commit_transport(ctx, [TransportChoice::PatchDeclined(false)])?;
            // Set from the result, not from the click: a run that found no
            // install patched nothing, and persisting `true` there would leave
            // the switch reading On for ever on a machine with no Antigravity.
            #[cfg(windows)]
            let patched = enable_client_patch_received(ctx, None)?;
            #[cfg(not(windows))]
            let patched = enable_client_patch_received(ctx)?;
            ctx.settings.client_patch = patched;
            // Switching the patch off took the watchdog task down with it. The
            // relay's own watchdog thread acts again the moment the decline is
            // gone, so without the task back the switch would read off while
            // patching went on. `set_watchdog` no longer starts the relay, so
            // this does not depend on the bypass being wanted.
            if watchdog_allowed(is_admin())
                && ctx.settings.auto_patch_wanted()
                && !watchdog_checked()?
            {
                set_watchdog_effect(ctx, true)?;
            }
        }
        (Cap::ClientPatch, false) => {
            let mut staged = ctx.settings.clone();
            staged.client_patch = false;
            // The one wish auto-patch has to respect (G38). Saved before
            // anything is unpatched, so a watchdog reading the file mid-run
            // already sees it.
            staged.set_transport_choice(TransportChoice::PatchDeclined(true))?;
            ctx.settings = save_received_settings(&staged).map_err(|error| format!("Отказ от автопатча не получен из сохранённых настроек; отмена файлов не начиналась: {error}"))?;
            #[cfg(windows)]
            disable_client_patch_received(ctx, None)?;
            #[cfg(not(windows))]
            disable_client_patch_received(ctx)?;
        }
        (Cap::Watchdog, on) => {
            let mut choices = vec![TransportChoice::AutoPatch(on)];
            // Auto-patch switched on is the newer wish, and it means "keep
            // Antigravity patched" - a patch declined earlier would otherwise
            // leave the switch on and the watchdog doing nothing.
            if on {
                choices.push(TransportChoice::PatchDeclined(false));
            }
            commit_transport(ctx, choices)?;
            set_watchdog_effect(ctx, on)?;
        }
        (Cap::Dns, on) => {
            commit_transport(ctx, [TransportChoice::Dns(on)])?;
            if on {
                enable_dns_effect(ctx)?;
            } else {
                disable_dns_effect(ctx)?;
            }
        }
        (Cap::LocalProxy, on) => {
            commit_transport(ctx, [TransportChoice::LocalProxy(on)])?;
            #[cfg(windows)]
            if matches!(ctx.settings.transport_profile,
                crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::SystemTcp)) {
                if on { repair(ctx)?; }
                else {
                    let expected = ctx.settings.transport_requirements()?.active_config;
                    match crate::settings::checked_transport_intent() {
                        crate::settings::TransportIntent::Explicit { requirements, .. } if requirements.active_config == expected => {}
                        _ => return Err("Сохранённый режим подключения не подтверждён; отключение службы не начиналось.".into()),
                    }
                    disable_local_proxy_effect(ctx)?;
                    reconcile_explicit_carrier(ctx, expected, None)?;
                }
                return Ok(());
            }
            #[cfg(windows)]
            if matches!(ctx.settings.transport_profile,
                crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::ExistingConfigured)) {
                let requirements = ctx.settings.transport_requirements()?;
                if !on { disable_local_proxy_effect(ctx)?; }
                background_changes_effect(ctx, Some(requirements.carrier), None,
                    background::ImageDemand::DeliverSelectedImage, Some(requirements.active_config))?;
                if on { enable_local_proxy_effect(ctx)?; }
                return Ok(());
            }
            if on {
                enable_local_proxy_effect(ctx)?;
            } else {
                disable_local_proxy_effect(ctx)?;
            }
        }
        (Cap::OwnProxy, on) => {
            if on {
                let text = ctx.settings.own_proxy.clone();
                if text.trim().is_empty() {
                    return Err("Впишите адрес прокси, затем включите переключатель.".into());
                } else {
                    set_own_proxy(ctx, &text)?;
                }
            } else {
                let value = ctx.settings.own_proxy.clone();
                save_own_proxy(ctx, value, false)?;
            }
        }
        (Cap::DnsRotation, on) => {
            ctx.settings.rotate_providers = on;
            ctx.settings.save();
            reapply_dns_rules_checked(ctx)?;
            ctx.log(
                Level::Ok,
                if on {
                    "Ротация включена — запрос идёт ко всем включённым серверам, ответ сверяется с эталонным."
                        .to_string()
                } else {
                    match first_enabled_provider(&ctx.settings) {
                        Some(name) => format!(
                            "Ротация выключена — используется только {}. Запасных серверов не будет.",
                            name
                        ),
                        None => "Ротация выключена, но все серверы отключены.".to_string(),
                    }
                },
            );
        }
        (Cap::BuiltinExits, on) => {
            commit_transport(ctx, [TransportChoice::BuiltinExits(on)])?;
            #[cfg(windows)]
            if matches!(ctx.settings.transport_profile,
                crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::SystemTcp)) {
                ctx.log(Level::Info, "Выбор встроенных выходов сохранён; системное подключение их не использует.");
                return Ok(());
            }
            ctx.log(
                Level::Ok,
                if on {
                    "Встроенные выходы включены."
                } else {
                    "Встроенные выходы отключены."
                },
            );
            if on {
                ensure_route_carrier(ctx)?;
            } else {
                release_route_carrier(ctx)?;
            }
        }
        (Cap::GroupProxy, on) => {
            commit_transport(ctx, [TransportChoice::GroupProxy(on)])?;
            #[cfg(windows)]
            if matches!(ctx.settings.transport_profile,
                crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::SystemTcp)) {
                ctx.log(Level::Info, "Выбор группового прокси сохранён; системное подключение его не использует.");
                return Ok(());
            }
            ctx.log(
                Level::Ok,
                if on {
                    "Прокси из группы включён."
                } else {
                    "Прокси из группы выключен."
                },
            );
            if on {
                ensure_route_carrier(ctx)?;
            } else {
                release_route_carrier(ctx)?;
            }
        }
    }
    Ok(())
}

// --- the two buttons --------------------------------------------------------

/// Reconcile acknowledged intent through existing effect owners. This action
/// never aliases EnableAll/Repair and never derives wanted booleans from an
/// effect result. The owning job serializes Ctx while the command loop can
/// still receive cancellation and close requests.
#[cfg(windows)]
#[derive(Debug)]
pub(crate) enum ApplyPlanError { Cancelled, Receiving(String), GatewayRecoveryRequired(GatewayApplyRecovery), VendorMetadataRecoveryRequired(VendorApplyRecovery) }
#[cfg(windows)]
pub(crate) struct GatewayApplyRecovery {
    pub(crate) observation: crate::windows_coordinator::windows_installation::GatewayPendingObservation,
    pub(crate) target: crate::instances::GuiReplacementTarget,
    pub(crate) bound: crate::windows_coordinator::windows_installation::BoundInstallation,
}
#[cfg(windows)]
impl std::fmt::Debug for GatewayApplyRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayApplyRecovery").field("observation", &self.observation).finish_non_exhaustive()
    }
}
#[cfg(windows)]
pub(crate) struct VendorApplyRecovery {
    pub(crate) observation: crate::windows_coordinator::windows_installation::VendorPendingObservation,
    pub(crate) target: crate::instances::GuiReplacementTarget,
    pub(crate) bound: crate::windows_coordinator::windows_installation::BoundInstallation,
    pub(crate) saved_sha256: [u8; 32],
}

#[cfg(windows)]
#[derive(PartialEq, Eq)]
struct InstallationRecoveryTarget {
    target: crate::instances::GuiReplacementTarget,
    observation: crate::windows_coordinator::windows_installation::VendorPendingObservation,
    executable_sha256: String,
    archive_sha256: [u8; 32],
    deployment_sha256: Option<[u8; 32]>,
    context: Option<crate::windows_coordinator::windows_installation::AncestorContextIdentity>,
}

#[cfg(windows)]
struct InstallationRecoveryProposal {
    id: String,
    target: InstallationRecoveryTarget,
    settings: Settings,
    saved_sha256: [u8; 32],
}

#[cfg(windows)]
impl InstallationRecoveryProposal {
    fn preview(&self) -> InstallationRecoveryPreview {
        InstallationRecoveryPreview { proposal_id: self.id.clone(), path: self.target.target.root_path.clone(),
            operation_id: self.target.observation.operation_id.clone() }
    }
}

#[cfg(windows)]
fn take_installation_recovery(slot: &mut Option<InstallationRecoveryProposal>, id: &str) -> Result<InstallationRecoveryProposal, String> {
    if slot.as_ref().is_some_and(|proposal| proposal.id == id) {
        return slot.take().ok_or_else(|| "Предложение восстановления не получено.".into());
    }
    Err("Предложение восстановления устарело. Проверьте выбранную установку снова.".into())
}

#[cfg(windows)]
fn receive_installation_recovery_dismissal(slot: &mut Option<InstallationRecoveryProposal>, command: &mut Option<Cmd>) -> bool {
    let Some(Cmd::DismissInstallationRecovery { proposal_id }) = command.as_ref() else { return false; };
    let dismissed = take_installation_recovery(slot, proposal_id).is_ok();
    *command = None;
    dismissed
}

#[cfg(windows)]
fn recovery_deployment_digest() -> Result<Option<[u8; 32]>, String> {
    use crate::windows_coordinator::windows_installation as owner;
    use sha2::{Digest, Sha256};
    let path = owner::saved_deployment_data_path()?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(Sha256::digest(owner::read_deployment_data(&path)?).into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("saved recovery deployment observation: {error}")),
    }
}

#[cfg(windows)]
fn receive_installation_recovery_target(path: &Path) -> Result<Option<(InstallationRecoveryTarget,
    crate::windows_coordinator::windows_installation::BoundInstallation)>, crate::windows_coordinator::windows_installation::ApplyCurrentReadError> {
    use crate::{instances::{GuiReplacementTarget, GuiTargetKind}, windows_coordinator::{self as coordinator, windows_installation as owner}};
    use owner::ApplyCurrentReadError::Failed;
    use sha2::{Digest, Sha256};
    let root = owner::CheckedPath::open(path, owner::PathKind::Directory, owner::PathPurpose::Source)?;
    let layout = crate::receive_installation_layout(root.as_path())?;
    if layout.kind != crate::InstallationKind::Desktop { return Err(Failed("Восстановление доступно для подтверждённой установки Desktop.".into())); }
    let anchor = owner::CheckedPath::open(&layout.anchor, owner::PathKind::File, owner::PathPurpose::ReplaceSource)?;
    let mut bound = owner::BoundInstallation::open(anchor.as_path())?;
    if bound.native_root_id() != root.native_id() || bound.native_executable_id() != anchor.native_id() {
        return Err(Failed("Выбранная установка Desktop изменилась при проверке.".into()));
    }
    let deployment_sha256 = recovery_deployment_digest()?;
    let context = coordinator::receive_saved_context(&bound)?;
    if context.is_some() != deployment_sha256.is_some() { return Err(Failed("Контекст выбранной установки изменился при проверке.".into())); }
    let context_identity = context.as_ref().map(owner::AncestorAccessContext::confirmation_identity).transpose()?;
    if let Some(context) = context { bound.attach_ancestor_context(context)?; }
    let observation = match owner::observe_apply_current_attempt(&bound)? {
        owner::ApplyCurrentObservation::VendorPending(observation) => observation,
        owner::ApplyCurrentObservation::Absent | owner::ApplyCurrentObservation::Settled { .. } => return Ok(None),
        owner::ApplyCurrentObservation::GatewayPending(_) => return Err(Failed("Выбранная установка ожидает завершения операции шлюза, а не восстановления метаданных Desktop.".into())),
        owner::ApplyCurrentObservation::VendorReplacement(_) => return Err(Failed("Версия выбранной установки изменилась. Незавершённое восстановление метаданных не подтверждено.".into())),
    };
    root.recheck()?;
    anchor.recheck()?;
    bound.revalidate_context()?;
    if recovery_deployment_digest()? != deployment_sha256 { return Err(Failed("Контекст выбранной установки изменился при проверке.".into())); }
    let target = GuiReplacementTarget { kind: GuiTargetKind::Desktop, root_path: root.as_path().to_owned(),
        native_root_id: root.native_id(), anchor_path: anchor.as_path().to_owned(), anchor_native_id: anchor.native_id() };
    Ok(Some((InstallationRecoveryTarget { target, observation, executable_sha256: bound.executable_digest().to_owned(),
        archive_sha256: Sha256::digest(bound.bytes()).into(), deployment_sha256, context: context_identity }, bound)))
}

#[cfg(windows)]
fn installation_recovery_wait_text(lease: crate::windows_coordinator::windows_installation::ApplyCurrentLease) -> &'static str {
    use crate::windows_coordinator::windows_installation::ApplyCurrentLease;
    match lease {
        ApplyCurrentLease::Namespace => "Ожидаю завершения другой операции с установками Desktop",
        ApplyCurrentLease::Slot => "Ожидаю завершения другой операции с выбранной установкой Desktop",
    }
}

#[cfg(windows)]
fn installation_recovery_cancelled(cancel: &AtomicBool, lifetime: &GuiLifetime) -> bool {
    cancel.load(Ordering::SeqCst) || lifetime.abort_requested.load(Ordering::SeqCst)
        || lifetime.channel_lost.load(Ordering::SeqCst) || lifetime.handoff_requested.load(Ordering::SeqCst)
}

#[cfg(windows)]
fn recheck_installation_recovery_input(settings: &Settings, saved: [u8; 32], cancel: &AtomicBool, lifetime: &GuiLifetime) -> Result<(), String> {
    if installation_recovery_cancelled(cancel, lifetime) { return Err("Восстановление отменено до начала.".into()); }
    if crate::settings::saved_intent_sha256(settings)? != saved { return Err("Сохранённые настройки изменились.".into()); }
    if installation_recovery_cancelled(cancel, lifetime) { return Err("Восстановление отменено до начала.".into()); }
    Ok(())
}

#[cfg(windows)]
fn wait_for_installation_recovery_read<T>(check: impl Fn() -> Result<(), String>,
    mut receive: impl FnMut() -> Result<T, crate::windows_coordinator::windows_installation::ApplyCurrentReadError>,
    waiting: impl FnOnce(crate::windows_coordinator::windows_installation::ApplyCurrentLease)) -> Result<T, String> {
    use crate::windows_coordinator::windows_installation::ApplyCurrentReadError;
    let mut notify = Some(waiting);
    loop {
        check()?;
        match receive() {
            Ok(value) => { check()?; return Ok(value); }
            Err(ApplyCurrentReadError::Failed(error)) => return Err(error),
            Err(ApplyCurrentReadError::Busy(lease)) => {
                if let Some(waiting) = notify.take() { waiting(lease); }
                // The receipt attempt has returned, including all of its
                // namespace/slot leases and temporary installation handles.
                std::thread::sleep(crate::wsl_runtime::OWNER_OBSERVATION_CADENCE);
            }
        }
    }
}

#[cfg(windows)]
fn prepare_installation_recovery(path: &Path, settings: &Settings, cancel: &AtomicBool, lifetime: &GuiLifetime,
    waiting: impl FnOnce(crate::windows_coordinator::windows_installation::ApplyCurrentLease)) -> Result<Option<InstallationRecoveryProposal>, String> {
    let saved_sha256 = crate::settings::saved_intent_sha256(settings)?;
    let settings = crate::settings::receive_saved_intent(&saved_sha256)?;
    let Some((target, bound)) = wait_for_installation_recovery_read(
        || recheck_installation_recovery_input(&settings, saved_sha256, cancel, lifetime),
        || receive_installation_recovery_target(path), waiting)? else { return Ok(None); };
    drop(bound);
    let id = crate::windows_coordinator::windows_installation::new_request_id()?;
    Ok(Some(InstallationRecoveryProposal { id, target, settings, saved_sha256 }))
}

#[cfg(windows)]
fn receive_prepared_installation_recovery(ctx: &Ctx, slot: &mut Option<InstallationRecoveryProposal>, command: &Option<Cmd>,
    prepared: Option<InstallationRecoveryProposal>, check_current: impl FnOnce(&InstallationRecoveryProposal) -> Result<(), String>) {
    // A user command already received in this loop owns the next intent.
    // Observations may coexist with the completed read-only proposal.
    if installation_recovery_cancelled(&ctx.native_cancel, &ctx.lifetime)
        || !matches!(command, None | Some(Cmd::RefreshWsl | Cmd::RemeasureVpn | Cmd::Probed { .. } | Cmd::DeepRefresh)) {
        return;
    }
    let Some(proposal) = prepared else { ctx.log(Level::Info, "Незавершённая операция не обнаружена"); return; };
    if let Err(error) = check_current(&proposal) {
        ctx.log(Level::Warn, format!("Предложение восстановления больше недействительно: {error}"));
        return;
    }
    let preview = proposal.preview();
    *slot = Some(proposal);
    ctx.emit(Event::InstallationRecoveryPrepared(preview));
}

#[cfg(windows)]
fn complete_installation_recovery(ctx: &mut Ctx, proposal: InstallationRecoveryProposal) -> Result<NativeCompletion, String> {
    let receive = || -> Result<_, String> {
        recheck_installation_recovery_input(&ctx.settings, proposal.saved_sha256, &ctx.native_cancel, &ctx.lifetime)?;
        let Some((actual, bound)) = wait_for_installation_recovery_read(
            || recheck_installation_recovery_input(&proposal.settings, proposal.saved_sha256, &ctx.native_cancel, &ctx.lifetime),
            || receive_installation_recovery_target(&proposal.target.target.root_path),
            |lease| ctx.busy(Some(installation_recovery_wait_text(lease))))? else {
            return Err("Незавершённая операция больше не обнаружена.".into());
        };
        if actual != proposal.target { return Err("Выбранная установка или данные незавершённой операции изменились.".into()); }
        Ok(bound)
    };
    let bound = receive().map_err(|error| format!("Подтверждение восстановления больше недействительно: {error}"))?;
    let was_held = matches!(ctx.startup, Startup::Held(_));
    if was_held {
        ctx.lifetime.clear_automatic_hold()?;
        ctx.startup = Startup::Explicit;
    }
    match crate::wsl_runtime::recover_apply_vendor_metadata(bound, &proposal.target.target,
        &proposal.target.observation, &proposal.settings, proposal.saved_sha256, &ctx.native_cancel) {
        Ok(outcome) => { ctx.log(Level::Ok, outcome); Ok(NativeCompletion::Retired) }
        Err(error) => {
            let detail = format!("Восстановление выбранной установки Desktop не завершено: {error}");
            if was_held {
                hold_apply(ctx, detail);
                return Ok(NativeCompletion::Retired);
            }
            Err(detail)
        }
    }
}
#[cfg(windows)]
impl std::fmt::Debug for VendorApplyRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VendorApplyRecovery").field("observation", &self.observation).finish_non_exhaustive()
    }
}
#[cfg(windows)]
impl From<String> for ApplyPlanError { fn from(value: String) -> Self { Self::Receiving(value) } }
#[cfg(windows)]
impl std::fmt::Display for ApplyPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Cancelled => f.write_str("Применение отменено."), Self::Receiving(error) => f.write_str(error),
            Self::GatewayRecoveryRequired(_) => f.write_str("RecoveryRequired: selected Desktop has an exact Pending gateway prerequisite"),
            Self::VendorMetadataRecoveryRequired(_) => f.write_str("RecoveryRequired: selected Desktop has an exact Pending vendor metadata prerequisite") }
    }
}

#[cfg(windows)]
pub(crate) struct ApplyInstallation {
    kind: crate::InstallationKind,
    root: crate::windows_coordinator::windows_installation::CheckedPath,
    anchor: crate::windows_coordinator::windows_installation::CheckedPath,
    expectation: crate::instances::GuiTargetExpectation,
}
#[cfg(windows)]
impl ApplyInstallation {
    pub(crate) fn root(&self) -> &std::path::Path { self.root.as_path() }
    pub(crate) fn anchor(&self) -> &std::path::Path { self.anchor.as_path() }
    pub(crate) fn is_vendor_update(&self) -> bool {
        matches!(&self.expectation.current, crate::instances::GuiCurrentExpectation::VendorUpdate { .. })
    }
    fn recheck(&self) -> Result<(), String> {
        self.root.recheck()?;
        self.anchor.recheck()?;
        let layout = crate::receive_installation_layout(self.root())?;
        if layout.kind != self.kind { return Err("installation effect kind changed".into()); }
        let anchor = crate::windows_coordinator::windows_installation::CheckedPath::open(&layout.anchor,
            crate::windows_coordinator::windows_installation::PathKind::File,
            crate::windows_coordinator::windows_installation::PathPurpose::ReplaceSource)?;
        if anchor.native_id() != self.anchor.native_id() { return Err("installation effect anchor changed".into()); }
        Ok(())
    }
    pub(crate) fn desktop_binding(&self) -> Result<crate::windows_coordinator::windows_installation::BoundInstallation, String> {
        if self.kind != crate::InstallationKind::Desktop { return Err("WSL requires a received Desktop target".into()); }
        self.recheck()?;
        bind_checked_desktop(&self.root, &self.anchor)
    }
    pub(crate) fn receive_acknowledged_desktop_current(&self) -> Result<(
        crate::windows_coordinator::windows_installation::BoundInstallation,
        crate::windows_coordinator::windows_installation::ApplyCurrentObservation,
    ), String> {
        use crate::windows_coordinator::windows_installation as owner;
        let bound = self.desktop_binding()?;
        let current = acknowledged_desktop_observation(&self.expectation.current, owner::observe_apply_current(&bound)?)?;
        Ok((bound, current))
    }
    pub(crate) fn recheck_desktop_current(&self) -> Result<(), String> {
        self.receive_acknowledged_desktop_current().map(|_| ())
    }
}

#[cfg(windows)]
struct RetirementInput {
    descriptor: crate::instances::GuiRetirementInputRef,
    file: crate::windows_coordinator::windows_installation::CheckedPath,
    selection: crate::windows_coordinator::windows_installation::gateway_rules::GatewayRetirementSelectionV1,
}
#[cfg(windows)]
impl RetirementInput {
    fn receive(descriptor: crate::instances::GuiRetirementInputRef) -> Result<Self, String> {
        use crate::windows_coordinator::windows_installation::{CheckedPath, PathKind, PathPurpose};
        use sha2::{Digest, Sha256};
        let file = CheckedPath::open(&descriptor.path, PathKind::File, PathPurpose::Source)?;
        if file.native_id() != descriptor.native_id { return Err("retirement input native identity changed".into()); }
        let bytes = file.read_snapshot()?;
        if Sha256::digest(&bytes).as_slice() != descriptor.sha256 { return Err("retirement input digest differs".into()); }
        let selection = serde_json::from_slice(&bytes).map_err(|e| format!("retirement input: {e}"))?;
        Ok(Self { descriptor, file, selection })
    }
    fn recheck(&self) -> Result<(), String> {
        self.file.recheck()?;
        use sha2::{Digest, Sha256};
        if Sha256::digest(self.file.read_snapshot()?).as_slice() != self.descriptor.sha256 { return Err("retirement input changed".into()); }
        Ok(())
    }
}
#[cfg(windows)]
pub(crate) fn retirement_input_ref(path: std::path::PathBuf, digest: &str) -> Result<crate::instances::GuiRetirementInputRef, String> {
    use crate::windows_coordinator::windows_installation::{CheckedPath, PathKind, PathPurpose};
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("retirement input digest must be lowercase SHA-256".into()); }
    let mut sha256 = [0; 32]; hex::decode_to_slice(digest, &mut sha256).map_err(|e| e.to_string())?;
    let file = CheckedPath::open(&path, PathKind::File, PathPurpose::Source)?;
    let descriptor = crate::instances::GuiRetirementInputRef { path, native_id: file.native_id(), sha256 };
    RetirementInput::receive(descriptor.clone())?;
    Ok(descriptor)
}
#[cfg(windows)]
pub(crate) struct AllTargetApplyPlan {
    wanted: Settings,
    saved_sha256: [u8; 32],
    targets: Vec<ApplyInstallation>,
    native: NativeApplyPlan,
    client_patch: Option<bool>,
    wsl: Option<crate::wsl_runtime::WslApplyPreparation>,
    retirement_input: Option<RetirementInput>,
}
#[cfg(windows)]
impl AllTargetApplyPlan {
    pub(crate) fn wanted(&self) -> &Settings { &self.wanted }
    pub(crate) fn saved_sha256(&self) -> &[u8; 32] { &self.saved_sha256 }
    pub(crate) fn retirement_for(&self, expected: &crate::windows_coordinator::windows_installation::VendorUpdateObservation) -> Result<Option<&crate::windows_coordinator::windows_installation::gateway_rules::GatewayRetirementSelectionV1>, String> {
        match &self.retirement_input {
            Some(input) if input.selection.slot_id == expected.slot_id => { input.recheck()?; input.selection.validate_binding(expected, &self.saved_sha256)?; Ok(Some(&input.selection)) },
            _ => Ok(None),
        }
    }
    pub(crate) fn wsl(&self) -> Result<&crate::wsl_runtime::WslApplyPreparation, String> {
        self.wsl.as_ref().ok_or_else(|| "WSL requirements were not received".into())
    }
    pub(crate) fn wsl_desktops(&self) -> impl Iterator<Item = &ApplyInstallation> {
        self.targets.iter().filter(|target| target.kind == crate::InstallationKind::Desktop)
    }
    fn has_vendor_update(&self) -> bool { self.targets.iter().any(ApplyInstallation::is_vendor_update) }
    fn expectations(&self) -> Vec<crate::instances::GuiTargetExpectation> {
        self.targets.iter().map(|target| target.expectation.clone()).collect()
    }
    fn recheck(&self) -> Result<(), String> {
        if let Some(input) = &self.retirement_input { input.recheck()?; }
        if crate::settings::saved_intent_sha256(&self.wanted)? != self.saved_sha256 { return Err("saved Apply input changed".into()); }
        for target in &self.targets {
            target.recheck()?;
            if target.kind == crate::InstallationKind::Desktop { target.recheck_desktop_current()?; }
        }
        Ok(())
    }
    fn continuation(&self) -> Result<crate::instances::GuiApplyContinuation, String> {
        self.recheck()?;
        Ok(crate::instances::GuiApplyContinuation { request_id: crate::windows_coordinator::windows_installation::new_request_id()?,
            saved_settings_sha256: self.saved_sha256, targets: self.expectations(), retirement_input: self.retirement_input.as_ref().map(|input| input.descriptor.clone()) })
    }
}

#[cfg(windows)]
fn acknowledged_desktop_observation(expected: &crate::instances::GuiCurrentExpectation,
    observation: crate::windows_coordinator::windows_installation::ApplyCurrentObservation)
    -> Result<crate::windows_coordinator::windows_installation::ApplyCurrentObservation, String> {
    if gui_current_expectation(observation.clone())? != *expected {
        return Err("Desktop Current changed before execution".into());
    }
    Ok(observation)
}

#[cfg(windows)]
fn gui_current_expectation(observation: crate::windows_coordinator::windows_installation::ApplyCurrentObservation)
    -> Result<crate::instances::GuiCurrentExpectation, String> {
    use crate::{instances::GuiCurrentExpectation as Gui, windows_coordinator::windows_installation::ApplyCurrentObservation as Current};
    Ok(match observation {
        Current::Absent => Gui::Absent {},
        Current::Settled { slot_id, current_sha256 } => Gui::Present { slot_id, current_sha256 },
        Current::GatewayPending(_) | Current::VendorPending(_) => return Err("RecoveryRequired: continuation target has unresolved Current".into()),
        Current::VendorReplacement(value) => Gui::VendorUpdate { slot_id: value.slot_id,
            prior_current_sha256: value.prior_current_sha256, new_parent_id: value.new_parent_id,
            new_resources_id: value.new_resources_id, new_archive_id: value.new_archive_id,
            new_executable_sha256: value.new_executable_sha256, new_archive_sha256: value.new_archive_sha256,
            new_binding_sha256: value.new_binding_sha256 },
    })
}

// Read-only prerequisite receiving precedes every selected-image/native plan.
// It takes no package capability; the adapter later revalidates this exact data.
#[cfg(windows)]
pub(crate) fn receive_desktop_apply_current(bound: crate::windows_coordinator::windows_installation::BoundInstallation,
    target: &crate::instances::GuiReplacementTarget, saved_sha256: [u8; 32])
    -> Result<crate::instances::GuiCurrentExpectation, ApplyPlanError> {
    use crate::windows_coordinator::windows_installation as owner;
    if target.kind != crate::instances::GuiTargetKind::Desktop || bound.native_root_id() != target.native_root_id
        || bound.native_executable_id() != target.anchor_native_id || !owner::same_windows_path(bound.executable().as_path(), &target.anchor_path)? {
        return Err("RecoveryRequired: Apply target anchor changed before prerequisite receiving".to_owned().into());
    }
    match owner::observe_apply_current(&bound)? {
        owner::ApplyCurrentObservation::GatewayPending(observation) => Err(ApplyPlanError::GatewayRecoveryRequired(
            GatewayApplyRecovery { observation, target: target.clone(), bound })),
        owner::ApplyCurrentObservation::VendorPending(observation) => Err(ApplyPlanError::VendorMetadataRecoveryRequired(
            VendorApplyRecovery { observation, target: target.clone(), bound, saved_sha256 })),
        observation => gui_current_expectation(observation).map_err(ApplyPlanError::from),
    }
}

#[cfg(windows)]
fn apply_target_key(target: &crate::instances::GuiTargetExpectation) -> (u8, u64, [u8; 16], u64, [u8; 16]) {
    use crate::instances::GuiTargetKind;
    let kind = match target.target.kind { GuiTargetKind::Desktop => 0, GuiTargetKind::Ide => 1, GuiTargetKind::Cli => 2 };
    (kind, target.target.native_root_id.volume, target.target.native_root_id.file,
        target.target.anchor_native_id.volume, target.target.anchor_native_id.file)
}

#[cfg(windows)]
pub(crate) fn receive_all_target_apply_plan(lifetime: &GuiLifetime, wanted: Settings, cancel: &AtomicBool,
    descriptor: Option<crate::instances::GuiRetirementInputRef>,
    image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>) -> Result<AllTargetApplyPlan, ApplyPlanError> {
    let call = lifetime.new_command_scope()?;
    let result = call.with_classified(|owner| receive_all_target_apply_plan_inner(owner, wanted, cancel, descriptor, image),
        |result| result.as_ref().err().map(ToString::to_string));
    lifetime.receive_command_results();
    result
}

#[cfg(windows)]
fn receive_all_target_apply_plan_inner(command_owner: &mut crate::utils::CommandOutcome, wanted: Settings, cancel: &AtomicBool,
    descriptor: Option<crate::instances::GuiRetirementInputRef>,
    image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>) -> Result<AllTargetApplyPlan, ApplyPlanError> {
    use crate::{instances::{GuiCurrentExpectation, GuiReplacementTarget, GuiTargetExpectation, GuiTargetKind},
        windows_coordinator::{self as coordinator, windows_installation as owner}};
    let saved_sha256 = crate::settings::saved_intent_sha256(&wanted)?;
    let retirement_input = descriptor.map(RetirementInput::receive).transpose()?;
    let mut roots = crate::find_all_installs_checked(command_owner, cancel)?;
    for root in &wanted.manual_paths { if !roots.contains(root) { roots.push(root.clone()); } }
    let mut targets: Vec<ApplyInstallation> = Vec::new();
    let mut all_patched = !roots.is_empty();
    let mut any_patched = false;
    for path in roots {
        if cancel.load(Ordering::SeqCst) { return Err(ApplyPlanError::Cancelled); }
        let root = owner::CheckedPath::open(&path, owner::PathKind::Directory, owner::PathPurpose::Source)?;
        let layout = crate::receive_installation_layout(root.as_path())?;
        let anchor = owner::CheckedPath::open(&layout.anchor, owner::PathKind::File, owner::PathPurpose::ReplaceSource)?;
        let state = patch_binary::inspect_install(root.as_path());
        for (_, state) in &state.files {
            if let patch_binary::FileState::Unreadable(error) = state { return Err(error.clone().into()); }
        }
        all_patched &= state.fully_patched();
        any_patched |= state.files.iter().any(|(_, state)| matches!(state, patch_binary::FileState::Patched));
        let kind = match layout.kind { crate::InstallationKind::Desktop => GuiTargetKind::Desktop,
            crate::InstallationKind::Ide => GuiTargetKind::Ide, crate::InstallationKind::Cli => GuiTargetKind::Cli };
        let target = GuiReplacementTarget { kind, root_path: root.as_path().to_owned(),
            native_root_id: root.native_id(), anchor_path: anchor.as_path().to_owned(), anchor_native_id: anchor.native_id() };
        let current = if layout.kind == crate::InstallationKind::Desktop {
            let mut bound = owner::BoundInstallation::open(anchor.as_path())?;
            if let Some(context) = coordinator::receive_saved_context(&bound)? { bound.attach_ancestor_context(context)?; }
            receive_desktop_apply_current(bound, &target, saved_sha256)?
        } else { GuiCurrentExpectation::NotApplicable {} };
        let expectation = GuiTargetExpectation { target, current };
        if let Some(prior) = targets.iter().find(|prior| prior.root.native_id() == root.native_id()) {
            if apply_target_key(&prior.expectation) != apply_target_key(&expectation) || prior.expectation.current != expectation.current {
                return Err("target aliases have conflicting kind/anchor/Current observations".to_owned().into());
            }
        } else { targets.push(ApplyInstallation { kind: layout.kind, root, anchor, expectation }); }
    }
    targets.sort_by_key(|target| apply_target_key(&target.expectation));
    if let Some(input) = &retirement_input {
        let count = targets.iter().filter(|target| matches!(&target.expectation.current,
            GuiCurrentExpectation::VendorUpdate { slot_id, prior_current_sha256, new_binding_sha256, .. }
            if target.kind == crate::InstallationKind::Desktop && slot_id == &input.selection.slot_id
                && hex::encode(prior_current_sha256) == input.selection.prior_current_sha256
                && hex::encode(new_binding_sha256) == input.selection.new_binding_sha256)).count();
        if count != 1 || input.selection.saved_settings_sha256 != hex::encode(saved_sha256) || wanted.wsl.is_none() {
            return Err("retirement input does not bind exactly one selected vendor update".to_owned().into());
        }
    }
    let Some(mut native) = inspect_native_apply(command_owner, &wanted, cancel, image)? else { return Err(ApplyPlanError::Cancelled); };
    let client_patch = if wanted.client_patch && !all_patched { Some(true) }
        else if !wanted.client_patch && any_patched { Some(false) } else { None };
    native.revert_services = client_patch == Some(false) && native.services_present;
    let mut plan = AllTargetApplyPlan { wanted, saved_sha256, targets, native, client_patch, wsl: None, retirement_input };
    plan.wsl = Some(crate::wsl_runtime::inspect_selection(&plan, cancel)?);
    if plan.retirement_input.is_some() && !matches!(&plan.wsl, Some(crate::wsl_runtime::WslApplyPreparation::Selected(_))) {
        return Err("retirement input requires a selected WSL vendor update".to_owned().into());
    }
    plan.recheck()?;
    Ok(plan)
}

#[cfg(windows)]
fn receive_apply_continuation(lifetime: &GuiLifetime, intent: &crate::instances::GuiApplyContinuation, cancel: &AtomicBool,
    image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>)
    -> Result<AllTargetApplyPlan, String> {
    use crate::{instances::{GuiCurrentExpectation, GuiTargetKind}, windows_coordinator::windows_installation as owner};
    owner::validate_request_id(&intent.request_id)?;
    let wanted = crate::settings::receive_saved_intent(&intent.saved_settings_sha256)?;
    let plan = receive_all_target_apply_plan(lifetime, wanted, cancel, intent.retirement_input.clone(), image).map_err(|error| error.to_string())?;
    let mut expected = intent.targets.clone();
    expected.sort_by_key(apply_target_key);
    if expected.windows(2).any(|pair| apply_target_key(&pair[0]) == apply_target_key(&pair[1])) {
        return Err("Apply target expectations are duplicated".into());
    }
    for expectation in &expected {
        let root = owner::CheckedPath::open(&expectation.target.root_path, owner::PathKind::Directory, owner::PathPurpose::Source)?;
        let anchor = owner::CheckedPath::open(&expectation.target.anchor_path, owner::PathKind::File, owner::PathPurpose::ReplaceSource)?;
        if root.native_id() != expectation.target.native_root_id || anchor.native_id() != expectation.target.anchor_native_id {
            return Err("Apply target native identity changed".into());
        }
        let layout = crate::receive_installation_layout(root.as_path())?;
        let kind = match layout.kind { crate::InstallationKind::Desktop => GuiTargetKind::Desktop,
            crate::InstallationKind::Ide => GuiTargetKind::Ide, crate::InstallationKind::Cli => GuiTargetKind::Cli };
        let actual_anchor = owner::CheckedPath::open(&layout.anchor, owner::PathKind::File, owner::PathPurpose::ReplaceSource)?;
        if kind != expectation.target.kind || actual_anchor.native_id() != anchor.native_id() {
            return Err("Apply target kind/anchor binding changed".into());
        }
        if !matches!((kind, &expectation.current),
            (GuiTargetKind::Desktop, GuiCurrentExpectation::Absent {} | GuiCurrentExpectation::Present { .. } | GuiCurrentExpectation::VendorUpdate { .. })
            | (GuiTargetKind::Ide | GuiTargetKind::Cli, GuiCurrentExpectation::NotApplicable {})) {
            return Err("Apply target Current applicability differs from its kind".into());
        }
    }
    let actual = plan.expectations();
    if actual.len() != expected.len() || actual.iter().zip(&expected)
        .any(|(actual, expected)| apply_target_key(actual) != apply_target_key(expected) || actual.current != expected.current) {
        return Err("Apply target set or canonical Current changed during handoff".into());
    }
    plan.recheck()?;
    Ok(plan)
}

#[cfg(windows)]
fn receive_settled_vendor_plan(before: &AllTargetApplyPlan, after: &AllTargetApplyPlan,
    received: &[(String, [u8; 32])]) -> Result<(), String> {
    use crate::instances::GuiCurrentExpectation;
    if before.saved_sha256 != after.saved_sha256 || before.targets.len() != after.targets.len() {
        return Err("Apply target domain or saved intent changed after vendor update".into());
    }
    let mut matched = 0usize;
    for (old, new) in before.targets.iter().zip(&after.targets) {
        if old.expectation.target != new.expectation.target {
            return Err("Apply selected target changed after vendor update".into());
        }
        match (&old.expectation.current, &new.expectation.current) {
            (GuiCurrentExpectation::VendorUpdate { slot_id: old_slot, .. },
             GuiCurrentExpectation::Present { slot_id: new_slot, current_sha256 }) if old_slot == new_slot => {
                if !vendor_result_received(received, new_slot, current_sha256) {
                    return Err("Apply Current differs from the actual vendor owner result".into());
                }
                matched += 1;
            },
            (old, new) if !matches!(old, GuiCurrentExpectation::VendorUpdate { .. }) && old == new => {},
            _ => return Err("Apply Current changed outside the received vendor update".into()),
        }
    }
    if matched != received.len() { return Err("Apply vendor result count differs from the selected targets".into()); }
    Ok(())
}

#[cfg(windows)]
fn vendor_result_received(received: &[(String, [u8; 32])], slot: &str, digest: &[u8; 32]) -> bool {
    received.iter().filter(|(actual_slot, actual_digest)| actual_slot == slot && actual_digest == digest).count() == 1
}

#[cfg(windows)]
struct NativeApplyFacts {
    core_rules: bool,
    owned_rules: bool,
    relay_task: bool,
    relay: Option<NativeRelayFacts>,
    watchdog: background::RoleObservation,
    program_outdated: Option<bool>,
}

#[cfg(windows)]
struct NativeRelayFacts {
    running: bool,
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
struct NativeApplyPlan {
    update_shared_program: bool,
    ensure_relay: bool,
    enable_dns: bool,
    disable_dns: bool,
    stop_relay: bool,
    watchdog: Option<bool>,
    services_present: bool,
    revert_services: bool,
}

#[cfg(windows)]
fn specified_wish(wish: &crate::settings::TransportWish) -> Option<bool> {
    match wish {
        crate::settings::TransportWish::Set(value) => Some(*value),
        crate::settings::TransportWish::Unspecified | crate::settings::TransportWish::Inactive => None,
    }
}

#[cfg(windows)]
fn watchdog_change(wish: Option<bool>, observed: background::RoleObservation) -> Option<bool> {
    wish.filter(|wish| !matches!((*wish, observed),
        (true, background::RoleObservation::Running) | (false, background::RoleObservation::Absent)))
}

#[cfg(windows)]
fn dispatch_system_apply<T>(plan: &NativeApplyPlan, expected: crate::settings::ActiveTransportConfig,
    reconcile: impl FnOnce(crate::settings::ActiveTransportConfig, Option<bool>) -> Result<T, String>) -> Result<T, String> {
    reconcile(expected, plan.watchdog)
}

#[cfg(windows)]
impl NativeApplyPlan {
    fn receive(wanted: &Settings, facts: &NativeApplyFacts) -> Result<Self, String> {
        let effects = wanted.checked_transport_effects()?;
        Self::receive_with_effects(facts, &effects)
    }

    fn receive_with_effects(facts: &NativeApplyFacts, effects: &crate::settings::TransportEffects) -> Result<Self, String> {
        let relay_wish = specified_wish(&effects.carrier);
        let dns_wish = specified_wish(&effects.dns);
        let watchdog_wish = specified_wish(&effects.watchdog);
        let wants_relay = relay_wish == Some(true);
        let update_shared_program = if wants_relay || watchdog_wish == Some(true) {
            facts.program_outdated.ok_or("selected background executable generation was not received")?
        } else { false };
        let ensure_relay = if wants_relay {
            let relay = facts.relay.as_ref().ok_or("selected relay health was not received")?;
            !relay.running
        } else { false };
        let disable_dns = dns_wish == Some(false) && facts.owned_rules;
        Ok(Self {
            update_shared_program,
            ensure_relay,
            enable_dns: dns_wish == Some(true) && !facts.core_rules,
            disable_dns,
            stop_relay: relay_wish == Some(false) && !disable_dns && facts.relay_task,
            watchdog: watchdog_change(watchdog_wish, facts.watchdog),
            services_present: facts.relay_task || !matches!(facts.watchdog, background::RoleObservation::Absent),
            revert_services: false,
        })
    }

    fn requires_elevation(&self) -> bool {
        self.update_shared_program || self.ensure_relay || self.enable_dns || self.disable_dns || self.stop_relay || self.watchdog.is_some() || self.revert_services
    }
}

#[cfg(windows)]
fn inspect_native_apply(owner: &mut crate::utils::CommandOutcome, wanted: &Settings, cancellation: &AtomicBool,
    image: Result<Arc<crate::windows_coordinator::process_identity::CurrentImage>, String>) -> Result<Option<NativeApplyPlan>, String> {
    if cancellation.load(Ordering::SeqCst) { return Ok(None); }
    let rules = dns::checked_nrpt_state(owner)?;
    if cancellation.load(Ordering::SeqCst) { return Ok(None); }
    let effects = wanted.checked_transport_effects()?;
    let wish = specified_wish(&effects.carrier);
    let needs_image = wish == Some(true) || specified_wish(&effects.watchdog) == Some(true);
    let observation = background::observe_background(cancellation,
        if needs_image { Some(image?) } else { None }, false, false)?;
    if cancellation.load(Ordering::SeqCst) { return Ok(None); }
    let wants_relay = wish == Some(true);
    let relay = if wants_relay {
        Some(NativeRelayFacts { running: matches!(&observation.relay, background::RoleObservation::Running) })
    } else { None };
    NativeApplyPlan::receive_with_effects(&NativeApplyFacts {
        core_rules: rules.core_applied, owned_rules: rules.owned_rules_present,
        relay_task: !matches!(&observation.relay, background::RoleObservation::Absent), relay,
        watchdog: observation.watchdog,
        program_outdated: observation.selected_delivery_required,
    }, &effects).map(Some)
}

fn apply_acknowledged(ctx: &mut Ctx, wanted: Settings, cancellation: &AtomicBool,
    #[cfg(windows)] resume: Option<crate::instances::GuiApplyContinuation>) -> Result<NativeCompletion, String> {
    #[cfg(windows)]
    let mut recovery_results = Vec::new();
    let result = (|| {
        if cancellation.load(Ordering::SeqCst) { return Ok(NativeCompletion::Retired); }
        #[cfg(windows)]
        {
            let received = match resume.as_ref() {
                Some(intent) => receive_apply_continuation(&ctx.lifetime, intent, cancellation, ctx.lifetime.retained_image()),
                None => {
                    let mut attempted = std::collections::BTreeSet::new();
                    loop {
                        if cancellation.load(Ordering::SeqCst) { break Err("Применение отменено до следующих действий.".into()); }
                        let descriptor = ctx.lifetime.retirement_input.lock().map_err(|_| "retirement input lock poisoned")?.as_ref().map(|input| input.descriptor.clone());
                        match receive_all_target_apply_plan(&ctx.lifetime, wanted.clone(), cancellation, descriptor, ctx.lifetime.retained_image()) {
                            Ok(plan) => break Ok(plan),
                            Err(ApplyPlanError::GatewayRecoveryRequired(prerequisite)) => {
                                if let Err(error) = receive_gateway_prerequisite_once(&mut attempted, &prerequisite.observation, cancellation) { break Err(error); }
                                match crate::wsl_runtime::recover_apply_gateway(prerequisite.bound, &prerequisite.target,
                                    &prerequisite.observation, cancellation) {
                                    Ok(outcome) => { ctx.log(Level::Ok, outcome.clone()); recovery_results.push(outcome); }
                                    Err(error) => {
                                        let received = format!("recovery prerequisite {:?}; {error}", prerequisite.observation);
                                        ctx.log(Level::Err, received.clone()); recovery_results.push(received);
                                        break Err(error);
                                    }
                                }
                                // Same acknowledged intent and discovery owner;
                                // no native/profile effect before a full new plan.
                            }
                            Err(ApplyPlanError::VendorMetadataRecoveryRequired(prerequisite)) => {
                                if let Err(error) = receive_pending_prerequisite_once(&mut attempted, &prerequisite.observation.slot_id,
                                    &prerequisite.observation.operation_id, prerequisite.observation.current_sha256, cancellation) { break Err(error); }
                                match crate::wsl_runtime::recover_apply_vendor_metadata(prerequisite.bound, &prerequisite.target,
                                    &prerequisite.observation, &wanted, prerequisite.saved_sha256, cancellation) {
                                    Ok(outcome) => { ctx.log(Level::Ok, outcome.clone()); recovery_results.push(outcome); }
                                    Err(error) => {
                                        let received = format!("vendor metadata prerequisite {:?}; {error}", prerequisite.observation);
                                        ctx.log(Level::Err, received.clone()); recovery_results.push(received);
                                        break Err(error);
                                    }
                                }
                                // Only this recorded operation settled. A new
                                // whole plan still owns package/readers/UAC.
                            }
                            Err(error) => break Err(error.to_string()),
                        }
                    }
                },
            };
            let mut plan = match received {
                Ok(plan) => plan,
                Err(error) => {
                    let error = apply_receiving_failure(&error, &recovery_results);
                    if !cancellation.load(Ordering::SeqCst) { hold_apply(ctx, error.clone()); }
                    return Err(error);
                },
            };
            if (plan.native.requires_elevation() && !is_admin()) || plan.wsl()?.requires_elevation() {
                return Ok(NativeCompletion::NeedsElevation(plan.continuation()?));
            }
            if plan.has_vendor_update() {
                plan.recheck()?;
                let vendor_results = crate::wsl_runtime::apply_vendor_prerequisites(&plan, cancellation)?;
                *ctx.lifetime.retirement_input.lock().map_err(|_| "retirement input lock poisoned")? = None;
                let next = receive_all_target_apply_plan(&ctx.lifetime, wanted.clone(), cancellation, None, ctx.lifetime.retained_image()).map_err(|error| error.to_string())?;
                receive_settled_vendor_plan(&plan, &next, &vendor_results)?;
                if (next.native.requires_elevation() && !is_admin()) || next.wsl()?.requires_elevation() {
                    return Err("UpdatePending: Apply requirements changed after vendor update".into());
                }
                ctx.log(Level::Ok, "Обновление WSL Desktop получено; остальные настройки проверены повторно.");
                plan = next;
            }
            let plan = Arc::new(plan);
            reconcile_native(ctx, &wanted, cancellation, &plan)?;
            if !cancellation.load(Ordering::SeqCst) { ctx.wsl.request_apply(plan)?; }
            return Ok(NativeCompletion::Retired);
        }
        #[cfg(not(windows))]
        {
        reconcile_native(ctx, &wanted, cancellation)?;
        if !cancellation.load(Ordering::SeqCst) { ctx.wsl.request_apply(wanted.clone())?; }
        Ok(NativeCompletion::Retired)
        }
    })();
    if cancellation.load(Ordering::SeqCst) {
        if ctx.wsl.is_pending() { ctx.wsl.request_cancel(); }
        else { ctx.wsl.cancelled_before_apply(wanted.wsl.as_ref()); }
        result.map(|_| NativeCompletion::Retired)
    } else { result }
}

#[cfg(windows)]
fn receive_gateway_prerequisite_once(
    attempted: &mut std::collections::BTreeSet<(String, String, [u8; 32])>,
    observation: &crate::windows_coordinator::windows_installation::GatewayPendingObservation,
    cancellation: &AtomicBool,
) -> Result<(), String> {
    receive_pending_prerequisite_once(attempted, &observation.slot_id, &observation.operation_id, observation.current_sha256, cancellation)
}
#[cfg(windows)]
fn receive_pending_prerequisite_once(attempted: &mut std::collections::BTreeSet<(String, String, [u8; 32])>,
    slot_id: &str, operation_id: &str, current_sha256: [u8; 32], cancellation: &AtomicBool) -> Result<(), String> {
    if cancellation.load(Ordering::SeqCst) { return Err("Cancelled: Pending prerequisite not started".into()); }
    if !attempted.insert((slot_id.to_owned(), operation_id.to_owned(), current_sha256)) {
        return Err("RecoveryRequired: the same Pending prerequisite remains unresolved; no automatic retry".into());
    }
    Ok(())
}
#[cfg(windows)]
fn apply_receiving_failure(error: &str, recovery_results: &[String]) -> String {
    if recovery_results.is_empty() { format!("Применение остановлено до изменений: {error}") }
    else { format!("Применение остановлено; полученные результаты восстановления сохранены: [{}]; незавершённый остаток: {error}", recovery_results.join("; ")) }
}

fn reconcile_native(ctx: &mut Ctx, wanted: &Settings, cancellation: &AtomicBool,
    #[cfg(windows)] plan: &AllTargetApplyPlan) -> Result<(), String> {
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    #[cfg(target_os = "macos")]
    let mac_proxy_wish = endpoint::mac_proxy_wish(wanted)?;
    #[cfg(target_os = "macos")]
    let mac_relay_migrated = mac_proxy_wish == Some(false)
        && reconcile_mac_off_for_routes(ctx, routes_want_relay_without_proxy_var(wanted))?;
    #[cfg(windows)]
    let Some(mut native) = ctx.with_command(|owner| inspect_native_apply(owner, wanted, cancellation, ctx.lifetime.retained_image()))? else { return Ok(()); };
    #[cfg(windows)]
    { plan.recheck()?; native.revert_services = plan.client_patch == Some(false) && native.services_present; }
    #[cfg(windows)]
    if native.requires_elevation() && !is_admin() {
        return Err("Состояние Windows изменилось после проверки прав; оставшиеся действия остановлены. Повторите «Применить».".into());
    }
    #[cfg(windows)]
    if native.disable_dns {
        // A client undo may retire the shared relay before its file operation.
        // Receive removal of our no-longer-wanted rules before that transition.
        remove_dns_rules_effect(ctx)?;
        native.disable_dns = false;
        native.stop_relay = wanted.checked_carrier_wish()? == Some(false) && native.services_present;
    }
    #[cfg(windows)]
    match plan.client_patch {
        Some(true) => { enable_client_patch_received(ctx, Some(plan))?; },
        Some(false) => disable_client_patch_received(ctx, Some(plan))?,
        None => {},
    }
    #[cfg(not(windows))]
    {
    let observed = read_status(ctx, false, None, #[cfg(target_os = "macos")] None);
    if wanted.client_patch && observed.client_patch != State::On {
        enable_client_patch(ctx);
    } else if !wanted.client_patch && observed.client_patch.is_on() {
        #[cfg(target_os = "macos")]
        disable_client_patch_received(ctx)?;
        #[cfg(not(target_os = "macos"))]
        disable_client_patch(ctx);
    }
    }
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    #[cfg(windows)]
    let own_wish = specified_wish(&wanted.checked_transport_effects()?.own_proxy_enabled);
    #[cfg(not(windows))]
    let own_wish = Some(wanted.own_proxy_enabled);
    if let Some(own_wish) = own_wish {
    let configured = upstream::configured();
    if own_wish {
        match upstream::parse(&wanted.own_proxy) {
            Ok(upstream) if configured.as_ref() != Some(&upstream) => {
                upstream::save(&upstream).map_err(|error| format!("Свой прокси не сохранился: {error}"))?;
            }
            Ok(_) => {},
            Err(error) => return Err(format!("Параметры своего прокси не подтверждены: {error}")),
        }
    } else if configured.is_some() { upstream::clear()?; }
    }
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    #[cfg(windows)]
    {
        if matches!(wanted.transport_profile,
            crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::SystemTcp)) {
            let expected = wanted.transport_requirements()?.active_config;
            match crate::settings::checked_transport_intent() {
                crate::settings::TransportIntent::Explicit { requirements, .. } if requirements.active_config == expected => {}
                _ => return Err("Сохранённый режим подключения не подтверждён; служба не изменялась.".into()),
            }
            return dispatch_system_apply(&native, expected, |expected, watchdog| reconcile_explicit_carrier(ctx, expected, watchdog));
        }
        if native.disable_dns { disable_dns_effect(ctx)?; }
        if native.enable_dns { enable_dns_effect(ctx)?; }
        let relay = if native.enable_dns { None } else if native.ensure_relay { Some(true) } else if native.stop_relay { Some(false) } else { None };
        if (native.update_shared_program && !native.enable_dns) || relay.is_some() || native.watchdog.is_some() {
            let expected = if relay.is_some() { expected_transport_config(wanted)? } else { None };
            background_changes_effect(ctx, relay, native.watchdog, background::ImageDemand::DeliverSelectedImage, expected)?;
        }
        if cancellation.load(Ordering::SeqCst) { return Ok(()); }
        if let Some(local_wish) = specified_wish(&wanted.checked_transport_effects()?.local_proxy) {
            let local_applied = ctx.proxy_env_is_ours()?;
            if local_wish && !local_applied { enable_local_proxy_effect(ctx)?; }
            else if !local_wish && local_applied { disable_local_proxy_effect(ctx)?; }
        }
        if cancellation.load(Ordering::SeqCst) { return Ok(()); }
        return Ok(());
    }
    #[cfg(not(windows))]
    {
    #[cfg(not(target_os = "macos"))]
    let rules = ctx.with_command(dns::is_nrpt_applied)?;
    #[cfg(not(target_os = "macos"))]
    let relay = background::is_running();
    #[cfg(not(target_os = "macos"))]
    let relay_outdated = background::relay_is_outdated();
    #[cfg(not(target_os = "macos"))]
    if Cap::Dns.supported() && wanted.dns && (!rules || !relay || relay_outdated) {
        if cfg!(windows) && !is_admin() { ctx.log(Level::Warn, "Для применения DNS нужны права администратора."); }
        else { enable_dns_effect(ctx)?; }
    } else if Cap::Dns.supported() && !wanted.dns && rules { disable_dns_effect(ctx)?; }
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    #[cfg(not(target_os = "macos"))]
    let local_applied = endpoint::proxy_env_is_ours();
    #[cfg(target_os = "macos")]
    {
        if routes_want_relay(wanted) && !mac_relay_migrated {
            background::ensure_running().map_err(|error| format!("Служба обхода не запустилась: {error}"))?;
        }
        if cancellation.load(Ordering::SeqCst) { return Ok(()); }
        if mac_proxy_wish == Some(true) { enable_local_proxy_effect(ctx)?; }
    }
    #[cfg(not(target_os = "macos"))]
    if wanted.local_proxy && (!local_applied || !background::is_running() || background::relay_is_outdated()) {
        if background::is_running() && !background::relay_is_outdated() { enable_local_proxy_effect(ctx)?; }
        else { ensure_route_carrier(ctx)?; }
    } else if !wanted.local_proxy && local_applied { disable_local_proxy_effect(ctx)?; }
    if cancellation.load(Ordering::SeqCst) { return Ok(()); }
    let watchdog = watchdog_checked()?;
    #[cfg(target_os = "macos")]
    let wanted_watchdog = wanted.auto_patch_wanted();
    #[cfg(not(target_os = "macos"))]
    let wanted_watchdog = wanted.auto_patch;
    if wanted_watchdog != watchdog {
        if cfg!(windows) && !is_admin() { ctx.log(Level::Warn, "Для применения автопатча нужны права администратора."); }
        else { set_watchdog_effect(ctx, wanted_watchdog)?; }
    }
    Ok(())
    }
}

/// «Включить всё». Each part only if it is not on already, and in the order the
/// switches themselves need: the patch first (it closes Antigravity, so nothing
/// is holding a file), then the relay (I5 - the rules name it), the proxy
/// variable only once something answers on its port (I53), and auto-patch last,
/// because it runs out of the relay's install directory.
#[cfg(windows)]
fn enable_all(ctx: &mut Ctx) -> Result<(), String> {
    let transport_received = matches!(crate::settings::read(), crate::settings::Read::Parsed(_));
    if !patch_is_on(ctx) { apply(ctx, Cap::ClientPatch, true)?; }
    if !transport_received { return Err("Патч проверен; способ подключения ещё не получен. Выберите системное подключение.".into()); }
    repair(ctx)
}

#[cfg(not(windows))]
fn enable_all(ctx: &mut Ctx) -> Result<(), String> {
    let admin = is_admin() || !cfg!(target_os = "windows");
    // "Everything" includes the patch on installs that do not exist yet.
    let mut choices = vec![TransportChoice::PatchDeclined(false), TransportChoice::GroupProxy(true)];
    if proxy::exits_available() { choices.push(TransportChoice::BuiltinExits(true)); }
    commit_transport(ctx, choices)?;
    // Only when it is not already on everywhere: patching closes Antigravity,
    // and closing it for a no-op is exactly the kind of surprise this button
    // must not have.
    if !patch_is_on(ctx) {
        apply(ctx, Cap::ClientPatch, true)?;
    }
    // Nothing but a line in settings.json, so it needs nobody's permission.
    // The service they ride on is brought up below, with DNS.
    #[cfg(not(windows))]
    let dns_on =
        ctx.with_command(dns::is_nrpt_applied)? && background::is_running() && !{
            #[cfg(target_os = "macos")]
            { background::checked_relay_outdated().map_err(|error| format!("Версия службы не подтверждена: {error}"))? }
            #[cfg(not(target_os = "macos"))]
            { background::relay_is_outdated() }
        };
    #[cfg(windows)]
    let dns_on = {
        let rules = ctx.with_command(dns::checked_nrpt_state)?;
        let observation = background::observe_background(&ctx.native_cancel,
            Some(ctx.lifetime.retained_image()?), false, true)?;
        let ready = observation.dns_ready.ok_or("DNS readiness was not received")??;
        let delivery_required = observation.selected_delivery_required
            .ok_or("selected background executable generation was not received")?;
        rules.core_applied && ready && !delivery_required
    };
    if Cap::Dns.supported() && !dns_on {
        if !admin {
            // Said only when it is actually missing: the card offers this button
            // for a patch that is off too, with the bypass already running.
            return Err("Обход ошибки 400 не включён: нужны права администратора. Нажмите «Перезапустить от имени администратора».".into());
        }
        apply(ctx, Cap::Dns, true)?;
    }
    // A proxy the user set up themselves stays theirs (G33): `enable_local_proxy`
    // says so and leaves ours off, which also keeps the loopback door shut.
    if !Cap::Dns.supported() {
        #[cfg(target_os = "macos")]
        if endpoint::mac_proxy_wish(&ctx.settings)?.is_none() {
            commit_transport(ctx, [TransportChoice::LocalProxy(true)])?;
        }
        ensure_route_carrier(ctx)?;
    } else if !ctx.proxy_env_is_ours()? {
        apply(ctx, Cap::LocalProxy, true)?;
    }
    // Whether or not the patch found anything to patch: auto-patch is what
    // patches the Antigravity installed after this click (D27).
    if watchdog_allowed(admin) && !watchdog_checked()? {
        apply(ctx, Cap::Watchdog, true)?;
    }
    ctx.log(
        Level::Ok,
        "Готово. Откройте Antigravity и напишите что-нибудь в чат — здесь появится подтверждение, что модель ответила.",
    );
    Ok(())
}

fn patch_is_on(ctx: &Ctx) -> bool {
    ctx.last
        .as_ref()
        .is_some_and(|s| s.client_patch == State::On)
}

/// «Починить». The service is the part that can stop on its own - a crash the
/// task's restart policy gave up on, a relay older than this build, an antivirus
/// that ate the copy in `%ProgramData%` - and every one of those is fixed by
/// installing it again and putting its rules and variable back.
#[cfg(windows)]
fn repair(ctx: &mut Ctx) -> Result<(), String> {
    match crate::settings::read() {
        crate::settings::Read::Parsed(settings) => ctx.settings = settings,
        crate::settings::Read::Missing => return Err("Сначала выберите способ подключения.".into()),
        crate::settings::Read::Broken | crate::settings::Read::Unavailable => return Err("Настройки подключения не получены; восстановление не начиналось.".into()),
    }
    if matches!(ctx.settings.transport_profile,
        crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::SystemTcp)) {
        let expected = ctx.settings.transport_requirements()?.active_config;
        match crate::settings::checked_transport_intent() {
            crate::settings::TransportIntent::Explicit { requirements, .. } if requirements.active_config == expected => {}
            _ => return Err("Сохранённый режим подключения не подтверждён; восстановление не начиналось.".into()),
        }
        let rules_present = ctx.with_command(dns::checked_nrpt_state)?.owned_rules_present;
        let observed = background::observe_background_for_transport(&ctx.native_cancel,
            Some(ctx.lifetime.retained_image()?), expected)?;
        let watchdog = watchdog_change(specified_wish(&ctx.settings.checked_transport_effects()?.watchdog), observed.background.watchdog);
        let proxy_is_ours = ctx.proxy_env_is_ours()?;
        let mode_ready = if expected.tcp_proxy {
            matches!(observed.tcp_proxy, background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready))
                && observed.tcp_proxy_port.is_some_and(|port| port != 0)
                && matches!(observed.dns, background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled))
                && matches!(observed.dns_alias, background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled))
                && proxy_is_ours
        } else {
            matches!(observed.background.relay, background::RoleObservation::Absent) && !proxy_is_ours
        };
        if !rules_present && mode_ready && watchdog.is_none()
            && (!expected.tcp_proxy || observed.background.selected_delivery_required == Some(false)) { return Ok(()); }
        if !is_admin() { return Err("Нужны права администратора. Нажмите «Перезапустить от имени администратора».".into()); }
        if rules_present {
            remove_dns_rules_effect(ctx)?;
        }
        if !expected.client_proxy && proxy_is_ours { disable_local_proxy_effect(ctx)?; }
        return reconcile_explicit_carrier(ctx, expected, watchdog);
    }
    if !is_admin() { return Err("Нужны права администратора. Нажмите «Перезапустить от имени администратора».".into()); }
    let effects = ctx.settings.checked_transport_effects()?;
    if let Some(relay) = specified_wish(&effects.carrier) {
        let expected = expected_transport_config(&ctx.settings)?;
        background_changes_effect(ctx, Some(relay), None, background::ImageDemand::DeliverSelectedImage, expected)?;
    }
    match specified_wish(&effects.dns) {
        Some(true) => enable_dns_effect(ctx)?,
        Some(false) if ctx.with_command(dns::checked_nrpt_state)?.owned_rules_present => remove_dns_rules_effect(ctx)?,
        _ => {}
    }
    if let Some(wish) = specified_wish(&effects.local_proxy) {
        let ours = ctx.proxy_env_is_ours()?;
        if wish && !ours { enable_local_proxy_effect(ctx)?; }
        else if !wish && ours { disable_local_proxy_effect(ctx)?; }
    }
    Ok(())
}

#[cfg(not(windows))]
fn repair(ctx: &mut Ctx) -> Result<(), String> {
    if cfg!(target_os = "windows") && !is_admin() {
        return Err("Нужны права администратора. Нажмите «Перезапустить от имени администратора».".into());
    }
    #[cfg(target_os = "macos")]
    {
        let proxy_wish = endpoint::mac_proxy_wish(&ctx.settings)?;
        let other_route = routes_want_relay_without_proxy_var(&ctx.settings);
        let migrated = proxy_wish == Some(false) && reconcile_mac_off_for_routes(ctx, other_route)?;
        if !routes_want_relay(&ctx.settings) {
            return Err("Нет выбранных поддерживаемых маршрутов для восстановления.".into());
        }
        if !migrated { background::enable().map_err(|error| format!("Служба обхода не подготовлена: {error}"))?; }
        if proxy_wish == Some(true) {
            enable_local_proxy_effect(ctx)?;
        }
        return Ok(());
    }
    // DNS is put back only when it was wanted, or when nothing else is: a user
    // running just their own proxy must not get DNS rules from a repair.
    let with_dns = ctx.settings.dns || !routes_want_relay(&ctx.settings);
    if with_dns {
        commit_transport(ctx, [TransportChoice::Dns(true)])?;
    }
    let reconciled = background::enable();
    reconciled.map_err(|error| format!("Служба обхода не подготовлена: {error}"))?;
    ctx.log(Level::Ok, "Выбранное состояние служб обхода подтверждено.");
    if with_dns {
        enable_dns_effect(ctx)?;
    } else {
        ensure_route_carrier(ctx)?;
    }
    Ok(())
}

// --- client patch ----------------------------------------------------------

/// Settles `patch_declined` for a settings file an older build wrote (D27).
///
/// Before D27 a patch switched off by hand left two traces: `client_patch`
/// false, and the standalone watchdog task removed (`disable_client_patch`).
/// `parse` could only read the first and so took every patch-off file as
/// declined. The task is the second trace, and only this side can ask for it:
/// with it still registered the user saw auto-patch *on*, and it may act -
/// which is the owner's own machine (G55). Written back at once, so the relay
/// reads the settled answer and this runs once per machine.
fn settle_decline(ctx: &mut Ctx) {
    if !ctx.settings.decline_unrecorded {
        return;
    }
    let watchdog = match watchdog_checked() {
        Ok(value) => value,
        Err(error) => { ctx.log(Level::Err, format!("Состояние автопатча не получено: {error}")); return; }
    };
    let mut staged = ctx.settings.clone();
    let declined = !staged.client_patch && !watchdog;
    if let Err(error) = staged.set_transport_choice(TransportChoice::PatchDeclined(declined)) {
        ctx.log(Level::Err, format!("Состояние автопатча не сохранено: {error}"));
        return;
    }
    staged.decline_unrecorded = false;
    match save_received_settings(&staged) {
        Ok(received) => ctx.settings = received,
        Err(error) => ctx.log(Level::Err, format!("Состояние автопатча не получено из сохранённых настроек: {error}")),
    }
}

/// Auto-patch from the window (D27): every install the last deep scan found
/// unpatched is patched now, without a click, while auto-patch is on and the
/// patch was not switched off by hand. True when something was written, so the
/// caller knows the dots need a deep re-read.
///
/// Uses the watchdog's selected-file writer. On Windows a busy native file is
/// held for a normal application close; this operation owns no process-kill
/// capability. Its cancellation and first write failure stop later files.
fn auto_patch_found(ctx: &mut Ctx) -> bool {
    // Only while the switch is drawn on («при включенной опции»). Its state is
    // the standalone task, which a user without admin rights cannot have and
    // which `disable_dns` takes down with the relay («вернётся вместе с
    // обходом»); patching behind a switch that reads off is the surprise the
    // switch exists to rule out.
    let switch_on = ctx.last.as_ref().is_some_and(|s| s.watchdog.is_on());
    if !switch_on || !ctx.settings.auto_patch_wanted() {
        return false;
    }
    let found: Vec<(&'static str, PathBuf)> = ctx
        .last
        .as_ref()
        .map(|s| {
            s.installs
                .iter()
                .filter(|r| r.patched == Some(false))
                .filter_map(|r| Some((r.label, r.path.clone()?)))
                .collect()
        })
        .unwrap_or_default();
    let patched = patch_found(ctx, found);
    #[cfg(windows)]
    let vendor_updated = {
        let mut updated = false;
        if crate::wsl_runtime::automatic_vendor_update_wanted(&ctx.settings) {
            let roots: Vec<_> = ctx.last.as_ref().map(|status| status.installs.iter()
                .filter_map(|row| row.path.clone()).collect()).unwrap_or_default();
            for root in roots {
                if ctx.native_cancel.load(Ordering::SeqCst) { break; }
                match crate::wsl_runtime::automatic_vendor_update(&root, &ctx.settings, &ctx.native_cancel) {
                    Ok(true) => { updated = true; ctx.log(Level::Ok, "Обновлён WSL-хук Desktop."); },
                    Ok(false) => {},
                    Err(error) => ctx.log(Level::Warn, format!("Автообновление WSL отложено: {error}")),
                }
            }
        }
        updated
    };
    #[cfg(not(windows))]
    let vendor_updated = false;
    patched || vendor_updated
}

/// Patches the given installs without closing anything. The shared body of
/// auto-patch and of the row's «Пропатчить» button, which is what a user is left
/// with when the automatic pass could not write.
fn patch_found(ctx: &mut Ctx, found: Vec<(&'static str, PathBuf)>) -> bool {
    if found.is_empty() {
        return false;
    }

    ctx.busy(Some("Автопатч"));
    let mut wrote = false;
    for (label, inst) in found {
        if ctx.native_cancel.load(Ordering::SeqCst) { break; }
        // Never a password prompt nobody asked for: the automatic pass leaves a
        // root-owned install to the button, which asks.
        if crate::elevate::needs_root(&inst) {
            ctx.log(
                Level::Warn,
                format!(
                    "Автопатч: {} — установка принадлежит root. Нажмите «Включить всё» и введите пароль.",
                    label
                ),
            );
            continue;
        }
        let mut patched = 0usize;
        let mut unknown = 0usize;
        let mut failed: Option<String> = None;
        #[cfg(not(target_os = "macos"))]
        let mut permission_denied = false;
        for (_, outcome) in crate::watchdog::patch_now_received(&inst, &ctx.native_cancel) {
            match outcome {
                patch_binary::RepatchOutcome::Repatched(_) => patched += 1,
                patch_binary::RepatchOutcome::AlreadyPatched => {}
                patch_binary::RepatchOutcome::SignatureMissing => unknown += 1,
                patch_binary::RepatchOutcome::PermissionDenied(e) => {
                    #[cfg(not(target_os = "macos"))]
                    { permission_denied = true; }
                    failed = Some(e.to_string());
                },
                patch_binary::RepatchOutcome::Failed(e) => failed = Some(e),
            }
        }
        let where_ = crate::utils::mask_path(&inst.display().to_string());
        if patched > 0 {
            wrote = true;
            ctx.log(
                Level::Ok,
                format!("Автопатч: {} — патч наложен ({})", label, where_),
            );
        }
        if let Some(e) = failed {
            #[cfg(target_os = "macos")]
            let message = format!("Автопатч: {} — операция отложена или не завершена ({}).", label, e);
            #[cfg(not(target_os = "macos"))]
            let message = if permission_denied {
                format!("Автопатч: {} — отказано в записи ({}).", label, e)
            } else {
                format!("Автопатч: {} — не удалось записать ({}).", label, e)
            };
            ctx.log(Level::Warn, message);
            break;
        } else if unknown > 0 && patched == 0 {
            // The watchdog's rule (I19): a build this patcher does not know is
            // left exactly as it is, so Antigravity shows its own error.
            ctx.log(
                Level::Warn,
                format!(
                    "Автопатч: {} — эта сборка Antigravity анлокеру ещё не знакома, файлы не тронуты. Нужна новая версия анлокера.",
                    label
                ),
            );
        }
    }
    if wrote {
        // What the switch falls back to before the next deep read, and what an
        // older build reading this file takes as the user's wish.
        ctx.settings.client_patch = true;
        ctx.settings.save();
    }
    // Left raised: every caller re-reads the installs next and lowers it after.
    wrote
}

#[cfg(not(windows))]
fn enable_client_patch(ctx: &mut Ctx) -> bool {
    let result = enable_client_patch_received(ctx);
    match result { Ok(value) => value, Err(error) => { ctx.log(Level::Err, error); false } }
}

fn legacy_client_targets(ctx: &Ctx) -> Result<Vec<PathBuf>, String> {
    let mut targets = ctx.with_command(crate::find_all_installs)?;
    for path in &ctx.settings.manual_paths { if !targets.contains(path) { targets.push(path.clone()); } }
    Ok(targets)
}

fn enable_client_patch_received(ctx: &mut Ctx, #[cfg(windows)] plan: Option<&AllTargetApplyPlan>) -> Result<bool, String> {
    ctx.log(Level::Step, "Патч клиента Antigravity");
    #[cfg(all(not(windows), not(target_os = "macos")))]
    patch_binary::kill_affected_processes();

    #[cfg(windows)]
    let targets = match plan { Some(plan) => plan.targets.iter().map(|target| target.root().to_owned()).collect(), None => legacy_client_targets(ctx)? };
    #[cfg(not(windows))]
    let targets = legacy_client_targets(ctx)?;

    if targets.is_empty() {
        ctx.log(
            Level::Err,
            "Установки Antigravity не найдены. Укажите путь вручную (карандаш).",
        );
        return Ok(false);
    }

    // Recomputed every run: see Ctx::proxy_var_carried.
    ctx.proxy_var_carried = Some(false);
    ctx.proxy_var_retryable = false;

    let mut ok = 0usize;
    for inst in &targets {
        if ctx.native_cancel.load(Ordering::SeqCst) {
            return Err(format!("Патч отменён перед следующей установкой; завершено установок: {ok}."));
        }
        #[cfg(windows)]
        let expected = if let Some(plan) = plan {
            let target = plan.targets.iter().find(|target| target.root() == inst).ok_or("planned target is missing")?;
            target.recheck()?;
            Some(target.kind)
        } else { Some(crate::receive_installation_layout(inst)?.kind) };
        #[cfg(not(windows))]
        let expected = None;
        // A root-owned Linux install: only this write is done as root, behind
        // the desktop's password prompt (`elevate`).
        if crate::elevate::needs_root(inst) {
            let where_ = crate::utils::mask_path(&inst.display().to_string());
            ctx.log(
                Level::Step,
                format!("{where_} принадлежит root — запрашиваю пароль для записи патча"),
            );
            match crate::elevate::patch_as_root(inst) {
                Ok(done) => {
                    ok += 1;
                    if done.proxy_var {
                        ctx.proxy_var_carried = Some(true);
                    }
                    if done.proxy_var_retryable {
                        ctx.proxy_var_retryable = true;
                    }
                    ctx.log(Level::Ok, format!("{} — {}", done.label, where_));
                    for w in done.warnings {
                        ctx.log(Level::Warn, w);
                    }
                }
                Err(e) => ctx.log(Level::Err, format!("{where_} — {e}")),
            }
            continue;
        }
        match ctx.with_command(|owner| crate::process_install_received(owner, inst, expected)) {
            Ok(outcome) => {
                ok += 1;
                if outcome.summary.proxy_var > 0 {
                    ctx.proxy_var_carried = Some(true);
                }
                if outcome.summary.proxy_var_retryable {
                    ctx.proxy_var_retryable = true;
                }
                ctx.log(
                    Level::Ok,
                    format!(
                        "{} — {}",
                        outcome.label,
                        crate::utils::mask_path(&inst.display().to_string())
                    ),
                );
                for w in outcome.warnings {
                    ctx.log(Level::Warn, w);
                }
            }
            Err(e) => {
                #[cfg(windows)]
                return Err(format!("Запись установки остановлена; завершено установок: {ok}; {} — {e}", crate::utils::mask_path(&inst.display().to_string())));
                #[cfg(not(windows))]
                ctx.log(Level::Err, format!("{} — {e}", crate::utils::mask_path(&inst.display().to_string())));
            },
        }
    }

    if ok == 0 {
        ctx.log(Level::Err, "Ни одна установка не пропатчена.");
        return Ok(false);
    }

    // I39: the legacy CA comes out last, and `remove_legacy_ca` itself refuses
    // while the relay is still an older build.
    ctx.with_command(crate::remove_legacy_ca_quiet)?;

    ctx.log(Level::Ok, format!("Пропатчено установок: {}", ok));
    Ok(true)
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn disable_client_patch(ctx: &mut Ctx) {
    let result = disable_client_patch_received(ctx);
    if let Err(error) = result { ctx.log(Level::Err, error); }
}

fn disable_client_patch_received(ctx: &mut Ctx, #[cfg(windows)] plan: Option<&AllTargetApplyPlan>) -> Result<(), String> {
    #[cfg(windows)]
    {
        if plan.is_none() && specified_wish(&ctx.settings.checked_transport_effects()?.dns) == Some(false)
            && ctx.with_command(dns::checked_nrpt_state)?.owned_rules_present {
            remove_dns_rules_effect(ctx)?;
        }
        let cancellation = ctx.native_cancel.clone();
        if plan.is_none_or(|plan| plan.native.revert_services) {
            let image = ctx.lifetime.retained_image();
            let receiving = background::with_suspended_background_changes(
                background::BackgroundChanges { relay: None, watchdog: None },
                &cancellation, image, || revert_client_primary(ctx, plan));
            let primary = receiving.primary;
            let restoration = ctx.retain_background_receiving(receiving.background);
            return receive_client_undo(primary, restoration);
        }
        return receive_client_undo(Some(revert_client_primary(ctx, plan)), Ok(()));
    }
    #[cfg(target_os = "macos")]
    {
        // The proxy is a separate launchd role with its own generation and intent.
        stop_watchdog_checked()?;
        receive_client_undo(Some(revert_client_primary(ctx)), Ok(()))
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        stop_watchdog_checked()?;
        background::disable()?;
        let primary = revert_client_primary(ctx);
        let restoration = if ctx.settings.dns || routes_want_relay(&ctx.settings) { background::ensure_running() } else { Ok(()) };
        receive_client_undo(Some(primary), restoration)
    }
}

fn receive_client_undo(primary: Option<Result<crate::elevate::Reverted, crate::elevate::Reverted>>,
    restoration: Result<(), String>) -> Result<(), String> {
    let primary_error = match primary {
        Some(Ok(_)) => None,
        Some(Err(outcome)) => Some(format!("Отмена файлов: подтверждено {}; предупреждения {}; ошибки {}",
            outcome.files, outcome.warnings.join("; "), outcome.errors.join("; "))),
        None => Some("Отмена файлов не вызывалась: владение/приостановка не получены.".into()),
    };
    match (primary_error, restoration) {
        (None, Ok(())) => Ok(()),
        (Some(primary), Ok(())) => Err(primary),
        (None, Err(restoration)) => Err(format!("Файлы получены, но восстановление служб не завершено: {restoration}")),
        (Some(primary), Err(restoration)) => Err(format!("{primary}; восстановление служб: {restoration}")),
    }
}

fn revert_client_primary(ctx: &mut Ctx, #[cfg(windows)] plan: Option<&AllTargetApplyPlan>)
    -> Result<crate::elevate::Reverted, crate::elevate::Reverted> {
    ctx.log(Level::Step, "Снятие патча клиента");
    let mut receiving = crate::elevate::Reverted::default();
    let primary = (|| -> Result<(), String> {

    #[cfg(all(not(windows), not(target_os = "macos")))]
    patch_binary::kill_affected_processes();


    #[cfg(windows)]
    let targets = match plan { Some(plan) => plan.targets.iter().map(|target| target.root().to_owned()).collect(), None => legacy_client_targets(ctx)? };
    #[cfg(not(windows))]
    let targets = legacy_client_targets(ctx)?;

    // Independent file work stops on its first actual failure. I20 restoration
    // is received by the surrounding background owner on every granted exit.
    for inst in &targets {
        if ctx.native_cancel.load(Ordering::SeqCst) {
            let error = if cfg!(target_os = "macos") { "Отмена файлов прервана пользователем." }
                else { "Отмена файлов прервана пользователем; восстановление служб обязательно." };
            return Err(error.into());
        }
        #[cfg(windows)]
        if let Some(plan) = plan {
            plan.targets.iter().find(|target| target.root() == inst).ok_or("planned target is missing")?.recheck()?;
        }
        let where_ = crate::utils::mask_path(&inst.display().to_string());
        // Each file is judged on its own (I45), and a failure is said out loud:
        // a count alone turned "one of two files could not be written" into a
        // clean revert, and the user kept a half-patched install. A root-owned
        // install (`/opt`) is reverted through pkexec, as it was patched: written
        // from here it only ever failed with `Permission denied`.
        // Asked only when there is something to take off: a clean root-owned
        // install does not deserve a password prompt.
        let patched_here = patch_binary::inspect_install(inst)
            .files
            .iter()
            .any(|(_, st)| *st == patch_binary::FileState::Patched);
        let done = if patched_here && crate::elevate::needs_root(inst) {
            ctx.log(
                Level::Info,
                format!("{} — установка принадлежит root, запрашиваю пароль", where_),
            );
            match crate::elevate::unpatch_as_root(inst) {
                Ok(d) => d,
                Err(e) => {
                    #[cfg(target_os = "macos")]
                    return Err(format!("{where_} — {e}"));
                    #[cfg(not(target_os = "macos"))]
                    {
                        ctx.log(Level::Err, format!("{} — {}", where_, e));
                        continue;
                    }
                }
            }
        } else {
            #[cfg(windows)]
            {
                match crate::elevate::revert_files_checked(inst) {
                    Ok(done) => done,
                    Err(done) => {
                        receiving.files += done.files;
                        receiving.warnings.extend(done.warnings);
                        return Err(done.errors.join("; "));
                    },
                }
            }
            #[cfg(not(windows))]
            { crate::elevate::revert_files(inst) }
        };
        for e in &done.errors {
            receiving.errors.push(e.clone());
            ctx.log(Level::Err, format!("{} — {}", where_, e));
        }
        for w in &done.warnings {
            receiving.warnings.push(w.clone());
            ctx.log(Level::Warn, format!("{} — {}", where_, w));
        }
        let reverted = done.files;
        receiving.files += reverted;
        if let Err(e) = endpoint::remove_ide(inst) {
            #[cfg(windows)]
            return Err(format!("Откат файлов получен, но оверрайд не снят: {e}"));
            #[cfg(not(windows))]
            ctx.log(Level::Warn, format!("Оверрайд эндпоинта не снят: {}", e));
        }
        ctx.log(
            Level::Ok,
            format!("{} — возвращено файлов: {}", where_, reverted),
        );
    }
    #[cfg(windows)]
    let cli_removal = ctx.with_command(endpoint::remove_cli);
    #[cfg(not(windows))]
    let cli_removal = endpoint::remove_cli();
    if let Err(e) = cli_removal {
        #[cfg(windows)]
        return Err(format!("Откат файлов получен, но переменная CLI не снята: {e}"));
        #[cfg(not(windows))]
        ctx.log(Level::Warn, format!("Переменная CLI не снята: {}", e));
    }

    // On Windows, clearing the proxy variable needs an explicit off wish;
    // an unselected transport component keeps its existing state.
    #[cfg(windows)]
    if specified_wish(&ctx.settings.checked_transport_effects()?.local_proxy) == Some(false) {
        disable_local_proxy_effect(ctx)?;
    }
    #[cfg(target_os = "macos")]
    if endpoint::mac_proxy_wish(&ctx.settings)? == Some(false) {
        disable_local_proxy_effect(ctx)?;
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    disable_local_proxy_effect(ctx)?;
    ctx.proxy_var_carried = Some(false);
    Ok(())
    })();
    if let Err(error) = primary { receiving.errors.push(error); }
    if receiving.errors.is_empty() { Ok(receiving) } else { Err(receiving) }
}

// --- watchdog --------------------------------------------------------------

#[cfg(windows)]
fn background_changes_effect(ctx: &mut Ctx, relay: Option<bool>, watchdog: Option<bool>, demand: background::ImageDemand,
    expected: Option<crate::settings::ActiveTransportConfig>) -> Result<(), String> {
    let cancellation = ctx.native_cancel.clone();
    let image = ctx.lifetime.retained_image();
    let receiving = background::reconcile_changes_with_receiving(background::BackgroundChanges { relay, watchdog }, demand, &cancellation, image, expected);
    ctx.retain_background_receiving(receiving)
}

#[cfg(windows)]
fn expected_transport_config(settings: &Settings) -> Result<Option<crate::settings::ActiveTransportConfig>, String> {
    match &settings.transport_profile {
        crate::settings::TransportProfileSetting::Absent => Ok(None),
        crate::settings::TransportProfileSetting::Explicit(_) => Ok(Some(settings.transport_requirements()?.active_config)),
        crate::settings::TransportProfileSetting::Invalid(_) => Err("Режим подключения не распознан".into()),
    }
}

fn set_watchdog_effect(ctx: &mut Ctx, on: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        let cancellation = ctx.native_cancel.clone();
        let receiving = background::reconcile_changes_with_receiving(
            background::BackgroundChanges { relay: None, watchdog: Some(on) },
            if on { background::ImageDemand::DeliverSelectedImage } else { background::ImageDemand::KeepCompatible },
            &cancellation, ctx.lifetime.retained_image(), None);
        return ctx.retain_background_receiving(receiving);
    }
    #[cfg(not(windows))]
    {
    #[cfg(target_os = "macos")]
    if on && !ctx.settings.save() { return Err("Настройки автопатча не сохранены; служба не запущена.".into()); }
    if !on {
        stop_watchdog_checked()?;
        ctx.log(Level::Ok, "Автовосстановление патча отключено.");
        return Ok(());
    }
    // The task launches the copy in %ProgramData%, so it has to be there - but
    // only the file: starting the relay here switched the 400 bypass on for a
    // user who asked for auto-patch alone.
    background::ensure_installed().map_err(|error| format!("Копия для автопатча не установлена: {error}"))?;
    background::enable_watchdog().map_err(|error| format!("Автопатч не включён: {error}"))?;
    ctx.log(Level::Ok, "Автовосстановление патча включено.");
    Ok(())
    }
}

// --- DNS -------------------------------------------------------------------

fn enable_dns_effect(ctx: &mut Ctx) -> Result<(), String> {
    ctx.log(Level::Step, "Обход через DNS");

    // I5: the rules name the relay as their first nameserver, so it has to be
    // answering before they are written.
    #[cfg(windows)]
    {
        let expected = expected_transport_config(&ctx.settings)?;
        background_changes_effect(ctx, Some(true), None, background::ImageDemand::DeliverSelectedImage, expected)
            .map_err(|error| format!("Служба DNS не запустилась: {error}"))?;
    }
    #[cfg(not(windows))]
    background::ensure_running().map_err(|error| format!("Служба DNS не запустилась: {error}"))?;
    ctx.log(Level::Ok, "Локальная служба DNS запущена.");
    if ctx.native_cancel.load(Ordering::SeqCst) {
        return Err("Служба получена; создание правил DNS отменено.".into());
    }

    #[cfg(windows)]
    if let Some(expected) = expected_transport_config(&ctx.settings)? {
        return apply_dns_rules_after_explicit_ready(ctx, expected);
    } else {
        background::receive_dns_ready(&ctx.native_cancel).map_err(|error| format!("Локальная служба DNS не подтверждена; правила не изменены: {error}"))?;
    }
    apply_dns_rules(ctx)?;

    #[cfg(windows)]
    let local_wanted = specified_wish(&ctx.settings.checked_transport_effects()?.local_proxy) == Some(true);
    #[cfg(not(windows))]
    let local_wanted = ctx.settings.local_proxy;
    if local_wanted && !ctx.proxy_env_is_ours()? { enable_local_proxy_effect(ctx)?; }
    #[cfg(not(windows))]
    if ctx.settings.auto_patch_wanted() && !watchdog_checked()? { set_watchdog_effect(ctx, true)?; }
    Ok(())
}

#[cfg(windows)]
fn apply_dns_rules_after_explicit_ready(ctx: &mut Ctx, expected: crate::settings::ActiveTransportConfig) -> Result<(), String> {
    let received = background::observe_background_for_transport(&ctx.native_cancel,
        Some(ctx.lifetime.retained_image()?), expected)?;
    match received.dns {
        background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready) => apply_dns_rules(ctx),
        background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Failed(error)) => Err(format!("DNS не подтверждён; правила не изменены: {error}")),
        _ => Err("DNS для сохранённого режима ещё не подтверждён; правила не изменены.".into()),
    }
}

fn apply_dns_rules(ctx: &mut Ctx) -> Result<(), String> {
    let outcome = ctx.with_command(dns::setup_dns_nrpt).map_err(|error| format!("Служба подготовлена; результат правил DNS не подтверждён: {error}"))?;
            dns::invalidate_cache();
            // The rules are in; what the client cached before them is not ours
            // to keep (G75). The relay does the same at its own start.
            if outcome.stood_down_for_vpn {
                // Not a failure, and not "on" either: with the client measured
                // inside a tunnel the rules would override the resolver the user
                // turned on, and the substituted address is reached through the
                // tunnel anyway (D13, G26, G29).
                return Err("Правила DNS не создавались: применение отложено владельцем DNS.".into());
            } else {
                ctx.log(Level::Ok, "Правила DNS установлены.");
            }
            if !dns::flush_client_cache() { return Err("Правила DNS установлены, но очистка кэша клиента не завершилась.".into()); }
            match ctx.with_command(|owner| dns::outcome_note(owner, &outcome)) {
                Ok(Some(note)) => ctx.log(Level::Info, strip_ansi(&note)),
                Ok(None) => {},
                Err(error) => ctx.log(Level::Warn, format!("Правила установлены; дополнительное наблюдение недоступно: {error}")),
            }

    Ok(())
}

fn disable_dns_effect(ctx: &mut Ctx) -> Result<(), String> {
    ctx.log(Level::Step, "Отключение обхода через DNS");

    // The relay is also the carrier of every route (local proxy, own proxy,
    // group, exits): it stays while any of them is wanted, and only the rules
    // come off.
    #[cfg(windows)]
    let relay_wish = specified_wish(&ctx.settings.checked_transport_effects()?.carrier);
    #[cfg(not(windows))]
    let relay_wish = Some(routes_want_relay(&ctx.settings));

    // First, because the listener is about to stop existing: the local proxy
    // runs *inside* the relay, so stopping the relay leaves `AG_LS_PROXY`
    // naming a port nothing answers on, and Antigravity loses its sign-in with
    // `dial tcp 127.0.0.1: ... actively refused` (I53, G31). The user's wish for
    // the proxy is kept in settings, so it comes back when the relay does.
    if relay_wish == Some(false) && ctx.proxy_env_is_ours()? {
        disable_local_proxy_effect(ctx)?;
    }

    #[cfg(windows)]
    remove_dns_rules_effect(ctx)?;
    if relay_wish == Some(true) {
        #[cfg(windows)]
        if let Some(expected) = expected_transport_config(&ctx.settings)? {
            background_changes_effect(ctx, Some(true), None, background::ImageDemand::DeliverSelectedImage, Some(expected))?;
        }
        ctx.log(
            Level::Info,
            "Служба осталась запущенной: она нужна включённым прокси и выходам.",
        );
    } else if relay_wish == Some(false) {
        stop_relay_effect(ctx)?;
        // Again, after: the relay's own maintainer re-reads the settings on a
        // timer and may have put the variable back between the removal above and
        // the stop, leaving it on a port nothing answers (the window's switch
        // read off while Antigravity still died on `actively refused`).
        if ctx.proxy_env_is_ours()? {
            disable_local_proxy_effect(ctx)?;
        }
    } else { ctx.log(Level::Info, "Состояние службы сохранено: выбор других маршрутов не получен."); }
    Ok(())
}

#[cfg(windows)]
fn remove_dns_rules_effect(ctx: &mut Ctx) -> Result<(), String> {
    ctx.with_command(dns::remove_dns_nrpt_checked)?;
    dns::invalidate_cache();
    if ctx.with_command(dns::checked_nrpt_state)?.owned_rules_present {
        return Err("Собственные правила DNS всё ещё присутствуют; удаление не подтверждено.".into());
    }
    ctx.log(Level::Ok, "Правила DNS сняты.");
    Ok(())
}

/// Takes the relay service down for good, with auto-patch kept.
///
/// The standalone watchdog task launches the copy of this exe that
/// `background::disable` is about to delete. It is taken down first and put
/// back after, on a copy of its own: auto-patch is not part of the bypass,
/// and switching the bypass off must not switch it off too.
fn stop_relay_effect(ctx: &mut Ctx) -> Result<(), String> {
    #[cfg(windows)]
    {
        let expected = expected_transport_config(&ctx.settings)?;
        return background_changes_effect(ctx, Some(false), None, background::ImageDemand::KeepCompatible, expected);
    }
    #[cfg(not(windows))]
    {
    let watchdog_enabled = watchdog_checked()?;
    #[cfg(target_os = "macos")]
    let restore_watchdog = watchdog_enabled;
    #[cfg(not(target_os = "macos"))]
    let restore_watchdog = ctx.settings.auto_patch && watchdog_enabled;
    if restore_watchdog {
        stop_watchdog_checked()?;
        ctx.log(Level::Ok, "Автопатч временно остановлен перед отключением службы.");
    }
    background::disable().map_err(|error| format!("Отключение службы не завершено; следующие действия остановлены: {error}"))?;
    ctx.log(Level::Ok, "Локальная служба DNS остановлена.");
    if restore_watchdog {
        set_watchdog_effect(ctx, true)?;
    }
    Ok(())
    }
}

/// Whether something other than the DNS rules needs the relay running: the
/// proxy listener and every route it serves live inside it.
fn routes_want_relay(s: &Settings) -> bool {
    #[cfg(target_os = "macos")]
    let local = endpoint::mac_proxy_wish(s) == Ok(Some(true));
    #[cfg(not(target_os = "macos"))]
    let local = s.local_proxy;
    local || routes_want_relay_without_proxy_var(s)
}

#[cfg(target_os = "macos")]
fn receive_mac_off_for_routes(other_route: bool, mut off: impl FnMut() -> Result<bool, endpoint::MacProxyFailure>,
    migrate: impl FnOnce() -> Result<(), String>) -> Result<bool, String>
{
    match off() {
        Ok(_) => Ok(false),
        Err(error @ endpoint::MacProxyFailure::LegacyUnbound) if other_route => {
            migrate().map_err(|migration| format!("{error}; служба другого выбранного маршрута: {migration}"))?;
            off().map_err(|retry| format!("служба маршрута получена, но прокси не снят: {retry}"))?;
            Ok(true)
        }
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(target_os = "macos")]
fn reconcile_mac_off_for_routes(ctx: &Ctx, other_route: bool) -> Result<bool, String> {
    let cancel = &ctx.native_cancel;
    let migrated = receive_mac_off_for_routes(other_route,
        || endpoint::attempt_mac_proxy(endpoint::MacProxyAction::Disable, Some(cancel)),
        || {
            if cancel.load(Ordering::SeqCst) { return Err("Подготовка службы отменена.".into()); }
            background::ensure_running()
        })?;
    ctx.log(Level::Ok, "Локальный прокси отключён.");
    Ok(migrated)
}

/// A route that was switched on by itself has to have something to ride on.
///
/// The routes (own proxy, group, exits) are chosen by the local proxy, which
/// lives in the relay, and the client reaches that proxy by its variable or by
/// the loopback door. With DNS off neither exists, so a route switched on alone
/// carried nothing - which is exactly how «свой прокси» "did not work" with the
/// other ways off. Starts the service and points the client at it; the DNS
/// rules are not touched.
fn ensure_route_carrier(ctx: &mut Ctx) -> Result<(), String> {
    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Подготовка службы отменена.".into()); }
    if cfg!(target_os = "windows") && !is_admin() {
        return Err("Служба обхода не запущена: нужны права администратора. Нажмите «Перезапустить от имени администратора».".into());
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    if !ctx.settings.local_proxy {
        commit_transport(ctx, [TransportChoice::LocalProxy(true)])?;
        ctx.carrier_set_proxy = true;
    }
    #[cfg(target_os = "macos")]
    if endpoint::mac_proxy_wish(&ctx.settings)? == Some(false) {
        commit_transport(ctx, [TransportChoice::LocalProxy(true)])?;
        ctx.carrier_set_proxy = true;
    }
    #[cfg(windows)]
    let reconciled = {
        let expected = expected_transport_config(&ctx.settings)?;
        background_changes_effect(ctx, Some(true), None, background::ImageDemand::DeliverSelectedImage, expected)
    };
    #[cfg(not(windows))]
    let reconciled = background::ensure_running();
    reconciled.map_err(|error| format!("Служба обхода не запустилась: {error}"))?;
    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Служба получена; настройка прокси отменена.".into()); }
    // Wanted, whatever `enable_local_proxy` manages below: the relay writes the
    // variable itself once its listener answers, and the door opens only while
    // this is set (`loopback::is_up`).
    #[cfg(windows)]
    let local_wanted = specified_wish(&ctx.settings.checked_transport_effects()?.local_proxy) == Some(true);
    #[cfg(all(not(windows), not(target_os = "macos")))]
    let local_wanted = true;
    #[cfg(not(target_os = "macos"))]
    if local_wanted && !ctx.proxy_env_is_ours()? {
        enable_local_proxy_effect(ctx)?;
    }
    #[cfg(target_os = "macos")]
    if endpoint::mac_proxy_wish(&ctx.settings)? == Some(true) { enable_local_proxy_effect(ctx)?; }
    Ok(())
}

/// The counterpart: a route went off, and if nothing else wants the service it
/// goes too. Not while DNS is on - then it is the DNS layer's.
#[cfg(windows)]
fn release_route_carrier(ctx: &mut Ctx) -> Result<(), String> {
    if specified_wish(&ctx.settings.checked_transport_effects()?.carrier) != Some(false) { return Ok(()); }
    if !is_admin() { return Err("Отключение службы требует прав администратора.".into()); }
    stop_relay_effect(ctx)
}

#[cfg(not(windows))]
fn release_route_carrier(ctx: &mut Ctx) -> Result<(), String> {
    if ctx.settings.dns || routes_want_relay_without_proxy_var(&ctx.settings) {
        return Ok(());
    }
    if cfg!(target_os = "windows") && !is_admin() {
        return Err("Отключение службы требует прав администратора.".into());
    }
    if ctx.carrier_set_proxy {
        commit_transport(ctx, [TransportChoice::LocalProxy(false)])?;
        ctx.carrier_set_proxy = false;
        #[cfg(not(target_os = "macos"))]
        if ctx.proxy_env_is_ours()? {
            disable_local_proxy_effect(ctx)?;
        }
        #[cfg(target_os = "macos")]
        disable_local_proxy_effect(ctx)?;
    }
    // The local proxy switched on by the user keeps the service.
    if ctx.settings.local_proxy {
        return Ok(());
    }
    stop_relay_effect(ctx)
}

/// `routes_want_relay` minus the proxy variable's own wish: a route's carrier
/// sets that wish itself, so it must not count against letting go of it.
fn routes_want_relay_without_proxy_var(s: &Settings) -> bool {
    s.own_proxy_enabled || s.group_proxy || (s.builtin_exits && proxy::exits_available())
}

/// Re-writes the NRPT rules when the pool they name has changed.
///
/// A rule lists one address per enabled provider, so switching a provider off —
/// or turning rotation off, which narrows the list to one — changes what Windows
/// is pointed at. Without this the switch looks like it did nothing: the pool
/// stops asking that provider, but the machine keeps it as a nameserver until
/// the DNS switch is toggled off and on again.
/// Returns whether it actually went near the system — the caller uses that to
/// decide whether the following refresh has anything new to read.
fn reapply_dns_rules(ctx: &mut Ctx) -> bool {
    match reapply_dns_rules_checked(ctx) {
        Ok(changed) => changed,
        Err(error) => { ctx.log(Level::Warn, error); false },
    }
}

fn reapply_dns_rules_checked(ctx: &mut Ctx) -> Result<bool, String> {
    if ctx.native_cancel.load(Ordering::SeqCst) { return Err("Изменение правил DNS отменено.".into()); }
    if !ctx.with_command(dns::is_nrpt_applied)? {
        return Ok(false);
    }
    if !is_admin() && cfg!(target_os = "windows") {
        return Err("Список DNS сохранён, но правила не переписаны — нужны права администратора.".into());
    }
    #[cfg(windows)]
    background::receive_dns_ready(&ctx.native_cancel).map_err(|error| format!("Локальная служба DNS не подтверждена; правила не изменены: {error}"))?;
    #[cfg(windows)]
    {
        // This owner also serves the synchronous SetProvider command, which
        // does not pass through either spawned native-job prologue.
        invalidate_background_observation(ctx);
        push_status(ctx, Scan::Settings);
    }
    let outcome = ctx.with_command(dns::setup_dns_nrpt).map_err(|error| format!("Результат изменения правил DNS не подтверждён: {error}"))?;
    if outcome.stood_down_for_vpn { return Err("Изменение правил отложено владельцем DNS.".into()); }
    dns::invalidate_cache();
    if !dns::flush_client_cache() { return Err("Правила DNS переписаны, но кэш клиента не очищен.".into()); }
    ctx.log(Level::Ok, "Правила DNS переписаны под новый список.");
    Ok(true)
}

// --- local proxy -----------------------------------------------------------

fn enable_local_proxy_effect(ctx: &mut Ctx) -> Result<(), String> {
    ctx.log(Level::Step, "Локальный прокси");
    let url = proxy::proxy_url();

    // 1. Windows and Linux clean up legacy user-wide values before enabling our
    //    private variable (D19). macOS leaves the standard variables alone.
    #[cfg(windows)]
    let legacy = ctx.with_command(|owner| endpoint::remove_legacy_proxy_env(owner, &url));
    #[cfg(not(windows))]
    let legacy = endpoint::remove_legacy_proxy_env(&url);
    match legacy {
        Ok(true) => ctx.log(Level::Ok, "Прежняя общесистемная HTTPS_PROXY снята."),
        Ok(false) => {}
        Err(e) => {
            return Err(format!("Прежняя HTTPS_PROXY не снята: {e}"));
        }
    }

    // 2. Measured (G33): ours outranks theirs inside the patched server. A user
    //    who configured their own proxy must keep it, so ours comes off — this
    //    is not a "skip".
    #[cfg(windows)]
    let foreign = ctx.with_command(|owner| endpoint::foreign_proxy(owner, &url))?;
    #[cfg(all(not(windows), not(target_os = "macos")))]
    let foreign = endpoint::foreign_proxy(&url);
    #[cfg(target_os = "macos")]
    let foreign = endpoint::checked_mac_foreign_proxy(&url)?.then_some(());
    if foreign.is_some() {
        #[cfg(windows)]
        ctx.with_command(|owner| endpoint::remove_proxy(owner, &url, "")).map_err(|error| format!("Своя переменная прокси не снята при чужом прокси: {error}"))?;
        #[cfg(all(not(windows), not(target_os = "macos")))]
        endpoint::remove_proxy(&url, "").map_err(|error| format!("Своя переменная прокси не снята при чужом прокси: {error}"))?;
        #[cfg(target_os = "macos")]
        endpoint::reconcile_mac_proxy(endpoint::MacProxyAction::Foreign, Some(&ctx.native_cancel))
            .map_err(|error| format!("Своя переменная прокси не снята при чужом прокси: {error}"))?;
        return Err("В системе задан свой прокси — наш не включён, чтобы не перехватывать чужой. Выбор сохранён.".into());
    }

    // 3. The variable has a private name that only a patched binary reads. If
    //    the rename did not land, writing it is writing into nothing.
    if ctx.proxy_var_carried == Some(false) {
        return Err(if ctx.proxy_var_retryable {
                "Файл был занят — закройте Antigravity полностью и включите переключатель заново."
            } else {
                "В этой сборке Antigravity нет места для переменной прокси — \
                 вероятно, вышла новая версия и нужен более новый анлокер."
            }.into());
    }

    // 4. I53/G31: never name a listener that is not there. A variable pointing
    //    at a dead port takes the sign-in down with it.
    //    Named by the port that answered, not the one read above: the relay can
    //    move the proxy while this waits (P26), and a URL for the port it left
    //    would be a dead one no watchdog takes back off.
    #[cfg(windows)]
    let listener = if let Some(expected) = expected_transport_config(&ctx.settings)? {
        let received = background::observe_background_for_transport(&ctx.native_cancel,
            Some(ctx.lifetime.retained_image()?), expected)?;
        if expected.profile == crate::settings::TransportProfile::SystemTcp
            && (!matches!(received.dns, background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled))
            || !matches!(received.dns_alias, background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled))) {
            return Err("Отключение DNS и его локальных адресов для текущей службы ещё не подтверждено.".into());
        }
        match received.tcp_proxy {
            background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready) => received.tcp_proxy_port,
            background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Failed(error)) => return Err(format!("Локальный прокси не подтверждён: {error}")),
            _ => return Err("Локальный прокси для сохранённого режима ещё не подтверждён.".into()),
        }
    } else {
        background::receive_proxy_ready(&ctx.native_cancel, Duration::from_secs(3))?
    };
    #[cfg(not(windows))]
    let listener = proxy::wait_for_our_listener(&ctx.lifetime.commands, Duration::from_secs(3))?;
    let Some(port) = listener else {
        #[cfg(windows)]
        if matches!(ctx.settings.transport_profile,
            crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::SystemTcp)) {
            return Err("Локальный прокси для системного подключения ещё не подтверждён.".into());
        }
        return Err("Локальный прокси не отвечает — сначала включите «Обход через DNS».".into());
    };
    #[cfg(windows)]
    if port == 0 { return Err("Получен недопустимый порт локального прокси.".into()); }
    #[cfg(not(target_os = "macos"))]
    let url = proxy::url_at(port);

    #[cfg(windows)]
    ctx.with_command(|owner| endpoint::apply_proxy(owner, &url, "")).map_err(|error| format!("Локальный прокси не включён: {error}"))?;
    #[cfg(all(not(windows), not(target_os = "macos")))]
    endpoint::apply_proxy(&url, "").map_err(|error| format!("Локальный прокси не включён: {error}"))?;
    #[cfg(target_os = "macos")]
    endpoint::reconcile_mac_proxy(endpoint::MacProxyAction::Enable, Some(&ctx.native_cancel))
        .map_err(|error| format!("Локальный прокси не включён: {error}"))?;
    ctx.log(Level::Ok, "Локальный прокси включён.");
    Ok(())
}

fn disable_local_proxy_effect(ctx: &mut Ctx) -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    let url = proxy::proxy_url();
    // I45 again: `remove_proxy` collects its own failures and joins them, so a
    // half-failed removal still takes off everything it can.
    #[cfg(windows)]
    ctx.with_command(|owner| endpoint::remove_proxy(owner, &url, "")).map_err(|error| format!("Снято не полностью: {error}"))?;
    #[cfg(all(not(windows), not(target_os = "macos")))]
    endpoint::remove_proxy(&url, "").map_err(|error| format!("Снято не полностью: {error}"))?;
    #[cfg(target_os = "macos")]
    endpoint::reconcile_mac_proxy(endpoint::MacProxyAction::Disable, Some(&ctx.native_cancel))
        .map_err(|error| format!("Снято не полностью: {error}"))?;
    ctx.log(Level::Ok, "Локальный прокси отключён.");
    Ok(())
}

// --- own proxy -------------------------------------------------------------

/// Saves the user's own DNS server(s). Anything that is not an IPv4 address is
/// refused with the reason; the slot stays as it was.
fn set_custom_dns(ctx: &mut Ctx, text: &str) {
    let text = text.trim();
    if text.is_empty() {
        ctx.settings.custom_dns.clear();
        ctx.settings.set_provider_enabled("свой DNS", true);
        ctx.log(Level::Ok, "Свой DNS убран.");
        return;
    }
    let Some(found) = crate::resolvers::parse_custom_dns_setting(text) else {
        ctx.log(
            Level::Err,
            "Нужны IPv4-адреса DNS-серверов через пробел или запятую (не 127.x и не 0.0.0.0), например 77.88.8.8.",
        );
        return;
    };
    ctx.settings.custom_dns = found
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    ctx.settings.set_provider_enabled("свой DNS", true);
    ctx.log(
        Level::Ok,
        format!(
            "Свой DNS сохранён ({}). Он участвует в пуле наравне с остальными: ответ сверяется с эталонным.",
            ctx.settings.custom_dns
        ),
    );
}

fn set_own_proxy(ctx: &mut Ctx, text: &str) -> Result<(), String> {
    let value = text.trim().to_string();
    let enabled = !value.is_empty();
    save_own_proxy(ctx, value, enabled)
}

fn save_own_proxy(ctx: &mut Ctx, value: String, enabled: bool) -> Result<(), String> {
    let requested = if enabled {
        Some(upstream::parse(&value).map_err(|error| format!("Адрес не разобран: {error}"))?)
    } else { None };
    let mut staged = ctx.settings.clone();
    staged.own_proxy = value;
    staged.set_transport_choice(TransportChoice::OwnProxyEnabled(enabled))?;
    if enabled { staged.own_proxy_at = crate::gate::now_unix(); }
    staged.encode_for_save()?;
    let before = upstream::configured_checked()
        .map_err(|error| format!("Предыдущее состояние runtime-прокси не получено; запись не начиналась: {error}"))?;
    let written = match &requested { Some(upstream) => upstream::save(upstream), None => upstream::clear() };
    let actual = upstream::configured_checked();
    if let Err(error) = written {
        let observation = match &actual {
            Ok(actual) => format!("matches_previous={}, matches_requested={}, absent={}",
                actual == &before, actual == &requested, actual.is_none()),
            Err(_) => "runtime readback unavailable".into(),
        };
        return Err(format!("Запись runtime-прокси завершилась ошибкой; Settings не изменялись, runtime может быть частичным: {error}; {observation}"));
    }
    let actual = actual.map_err(|error| format!("Runtime-прокси записан, но не подтверждён; Settings не изменялись: {error}"))?;
    if actual != requested {
        return Err("Runtime-прокси после записи не совпал; Settings не изменялись, активация не начиналась.".into());
    }
    match save_received_settings(&staged) {
        Ok(received) => ctx.settings = received,
        Err(error) => {
            // The runtime write already happened. Receive only an actual parsed
            // Settings snapshot; never promote the attempted candidate on error.
            match crate::settings::checked_transport_intent() {
                crate::settings::TransportIntent::Legacy(received)
                | crate::settings::TransportIntent::Explicit { settings: received, .. } => ctx.settings = received,
                _ => {}
            }
            return Err(format!("Runtime-прокси изменён и получен; Settings не подтверждены, активация не начиналась: {error}"));
        }
    }
    if matches!(ctx.settings.transport_profile,
        crate::settings::TransportProfileSetting::Explicit(crate::settings::TransportProfile::SystemTcp)) {
        ctx.log(Level::Info, "Предпочтение своего прокси сохранено; системный TCP-профиль его не активирует.");
        return Ok(());
    }
    let Some(upstream) = requested else {
        ctx.log(Level::Ok, "Свой прокси отключён; runtime и Settings получены.");
        return release_route_carrier(ctx);
    };
    ctx.log(Level::Ok, format!("Свой прокси настроен: {}", upstream.display()));
    ensure_route_carrier(ctx)?;
    ctx.log(Level::Info, "Проверяю прокси…");
    match upstream::probe(&upstream) {
        Ok(()) => ctx.log(Level::Ok, "Прокси отвечает."),
        Err(error) => ctx.log(Level::Warn, format!("Прокси настроен, но проверка не пройдена: {error}")),
    }
    Ok(())
}

/// Strips SGR escapes from a string built for a terminal.
///
/// `dns::outcome_note` returns text with colour codes baked in — it was written
/// to be printed. Rendering it in a window would show the raw `ESC[33m`.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Drop until the final byte of the sequence (a letter).
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether a path looks like an install root, for the manual "pencil" dialog.
pub fn resolve_manual_path(raw: &Path) -> Option<PathBuf> {
    crate::resolve_install_root(raw)
}

#[cfg(test)]
mod tests {
    #[test]
    fn installation_patch_observation_labels_follow_displayed_path() {
        use super::*;

        let path = PathBuf::from("synthetic-install");
        let mut row = InstallRow {
            path: Some(path.clone()),
            label: "Synthetic install",
            patched: None,
            manual: false,
            #[cfg(windows)]
            observed_kind: None,
            #[cfg(any(windows, target_os = "macos"))]
            coverage: InstallCoverage::Complete,
        };
        for (patched, label) in [
            (Some(true), "пропатчена"),
            (Some(false), "не полностью пропатчена"),
            (None, "патч не проверен"),
        ] {
            row.patched = patched;
            assert_eq!(row.patch_observation_label(), Some(label));
            #[cfg(any(windows, target_os = "macos"))]
            assert_eq!(row.unconfirmed_patch_note(), patched.is_none().then_some(label));
        }

        row.path = None;
        row.patched = Some(true);
        assert_eq!(row.patch_observation_label(), None);

        #[cfg(target_os = "macos")]
        {
            row.path = Some(path.clone());
            row.coverage = InstallCoverage::ObservedStandard(path);
            assert_eq!(row.patch_observation_label(), None);
            row.patched = None;
            assert_eq!(row.unconfirmed_patch_note(), None);
        }
    }

    #[cfg(windows)]
    #[test]
    fn vendor_publication_failure_keeps_original_and_actual_receipt() {
        use super::*;

        let digest = "12".repeat(32);
        let mut failure = vendor_records::MetadataFailure::unacquired("fixture publication", "original failure".into());
        failure.evidence = serde_json::json!({"stageRenameResult": true,
            "postEffectReceiving": {"result":"received", "receiptSha256":digest,
                "disposition":{"result":"fixture owner released"}}});
        let mut actual = VendorPublicationFailure { failure, dispositions: vec![serde_json::json!({"result":"fixture stage finished"})] };
        let message = actual.message();
        assert!(message.contains("original failure") && message.contains(&digest));
        assert!(!message.contains("Итоговая проверка не завершена"));
        assert_eq!(actual.dispositions[0]["result"].as_str(), Some("fixture stage finished"));

        actual.failure.evidence["postEffectReceiving"] = serde_json::json!({"result":"held", "cause":"fixture remains held"});
        let message = actual.message();
        assert!(message.contains("original failure") && message.contains("Итоговая проверка не завершена"));
        assert!(!message.contains(&digest));
    }

    #[cfg(windows)]
    #[test]
    fn stopped_delivery_worker_panic_is_terminal_after_actual_join() {
        use super::*;

        for received in [StoppedDeliveryStatus::Running, StoppedDeliveryStatus::Finished(Err("prior error".into()))] {
            let lifetime = GuiLifetime::default();
            let previously_failed = matches!(&received, StoppedDeliveryStatus::Finished(Err(_)));
            *lifetime.stopped_delivery.lock().unwrap() = received;
            lifetime.started.store(true, Ordering::SeqCst);
            *lifetime.worker.lock().unwrap() = Some(std::thread::spawn(|| panic!("synthetic worker failure")));
            while !lifetime.poll_close().unwrap() { std::thread::yield_now(); }
            assert!(lifetime.worker.lock().unwrap().is_none());
            assert_eq!(lifetime.poll_close(), Ok(true));
            let StoppedDeliveryStatus::Finished(Err(error)) = lifetime.stopped_delivery_status() else {
                panic!("joined failed worker must publish a terminal result");
            };
            assert!(error.contains("Рабочий поток обновления аварийно завершился"));
            assert!(!error.contains("synthetic worker failure"));
            if previously_failed { assert!(error.starts_with("prior error")); }
            let panics = lifetime.take_command_panics();
            assert_eq!(panics.len(), 1);
            assert_eq!(panics[0].downcast_ref::<&str>().copied(), Some("synthetic worker failure"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn stopped_delivery_retry_requires_the_exact_observed_hold() {
        use super::*;

        let lifetime = GuiLifetime::default();
        *lifetime.stopped_delivery.lock().unwrap() = StoppedDeliveryStatus::Running;
        lifetime.request_shutdown();
        assert!(lifetime.abort_requested.load(Ordering::SeqCst));

        let first = Arc::new("synthetic resource hold".to_owned());
        *lifetime.stopped_delivery.lock().unwrap() = StoppedDeliveryStatus::ResourceHeld(first.clone());
        assert!(matches!(lifetime.stopped_delivery_status(), StoppedDeliveryStatus::ResourceHeld(active) if Arc::ptr_eq(&active, &first)));
        lifetime.retry_stopped_delivery_hold(&first);
        assert!(matches!(lifetime.stopped_delivery_status(), StoppedDeliveryStatus::Running));

        let next = Arc::new(first.as_ref().clone());
        *lifetime.stopped_delivery.lock().unwrap() = StoppedDeliveryStatus::ResourceHeld(next.clone());
        lifetime.retry_stopped_delivery_hold(&first);
        assert!(matches!(lifetime.stopped_delivery_status(), StoppedDeliveryStatus::ResourceHeld(active) if Arc::ptr_eq(&active, &next)));
        lifetime.retry_stopped_delivery_hold(&next);
        assert!(matches!(lifetime.stopped_delivery_status(), StoppedDeliveryStatus::Running));
    }

    #[cfg(windows)]
    #[test]
    fn selected_recovery_read_wait_retries_only_typed_busy_and_checks_cancel() {
        use super::*;
        use crate::windows_coordinator::windows_installation::{ApplyCurrentLease, ApplyCurrentReadError};
        use std::cell::Cell;

        let attempts = Cell::new(0);
        let notified = Cell::new(false);
        let result = wait_for_installation_recovery_read(|| Ok(()), || {
            attempts.set(attempts.get() + 1);
            if attempts.get() == 1 { Err(ApplyCurrentReadError::Busy(ApplyCurrentLease::Slot)) }
            else { Ok("read-only proof") }
        }, |_| notified.set(true)).unwrap();
        assert_eq!(result, "read-only proof");
        assert_eq!(attempts.get(), 2);
        assert!(notified.get());

        let cancellation = Cell::new(false);
        attempts.set(0);
        let result = wait_for_installation_recovery_read(
            || if cancellation.get() { Err("cancelled before another receipt".into()) } else { Ok(()) },
            || { attempts.set(attempts.get() + 1); Err::<(), _>(ApplyCurrentReadError::Busy(ApplyCurrentLease::Namespace)) },
            |_| cancellation.set(true));
        assert_eq!(result.unwrap_err(), "cancelled before another receipt");
        assert_eq!(attempts.get(), 1);

        let result = wait_for_installation_recovery_read(|| Ok(()),
            || Err::<(), _>(ApplyCurrentReadError::Failed("maintenance-pending diagnostic from another owner".into())),
            |_| panic!("untyped errors must not trigger another receipt"));
        assert_eq!(result.unwrap_err(), "maintenance-pending diagnostic from another owner");
    }

    #[cfg(windows)]
    #[test]
    fn selected_recovery_consumes_only_live_id_and_keeps_hold_on_cancel() {
        use super::*;
        use crate::instances::{GuiReplacementTarget, GuiTargetKind};
        use crate::windows_coordinator::windows_installation::{NativeObjectId, VendorPendingObservation};
        let (shared, events) = probe_test_ctx();
        let mut ctx = shared.lock().unwrap();
        let reason = "original startup hold".to_owned();
        ctx.startup = Startup::Held(reason.clone());
        ctx.lifetime.hold_automatic_effects(reason.clone()).unwrap();
        let path = PathBuf::from(r"C:\Synthetic\Selected Desktop");
        let proposal = |id: &str| InstallationRecoveryProposal { id: id.into(), settings: Settings::default(), saved_sha256: [7; 32],
            target: InstallationRecoveryTarget { target: GuiReplacementTarget { kind: GuiTargetKind::Desktop,
                root_path: path.clone(), native_root_id: NativeObjectId { volume: 7, file: [1; 16] },
                anchor_path: path.join("Antigravity.exe"), anchor_native_id: NativeObjectId { volume: 7, file: [2; 16] } },
                observation: VendorPendingObservation { slot_id: "slot".into(), operation_id: "operation".into(), current_sha256: [3; 32] },
                executable_sha256: "fixture".into(), archive_sha256: [4; 32], deployment_sha256: None, context: None } };
        let pending = proposal("selected-proposal");
        let preview = pending.preview();
        assert_eq!((&preview.path, preview.operation_id.as_str()), (&path, "operation"));
        let mut slot = Some(pending);
        assert!(take_installation_recovery(&mut slot, "other-worker-proposal").is_err());
        let mut command = Some(Cmd::DismissInstallationRecovery { proposal_id: "other-worker-proposal".into() });
        assert!(!receive_installation_recovery_dismissal(&mut slot, &mut command));
        assert!(command.is_none() && slot.is_some());
        assert!(matches!(&ctx.startup, Startup::Held(actual) if actual == &reason));
        let selected = take_installation_recovery(&mut slot, &preview.proposal_id).unwrap();
        assert!(take_installation_recovery(&mut slot, &preview.proposal_id).is_err());
        ctx.native_cancel.store(true, Ordering::SeqCst);
        assert!(matches!(complete_installation_recovery(&mut ctx, selected), Err(error) if error.contains("отменено до начала")));
        assert!(matches!(&ctx.startup, Startup::Held(actual) if actual == &reason));
        assert_eq!(ctx.lifetime.fallback_hold(), Some(reason));

        slot = Some(proposal("dismissed-proposal"));
        let mut command = Some(Cmd::DismissInstallationRecovery { proposal_id: "dismissed-proposal".into() });
        assert!(receive_installation_recovery_dismissal(&mut slot, &mut command));
        assert!(command.is_none() && slot.is_none());
        let mut late = Some(Cmd::ConfirmInstallationRecovery { proposal_id: "dismissed-proposal".into() });
        assert!(!receive_installation_recovery_dismissal(&mut slot, &mut late));
        let Some(Cmd::ConfirmInstallationRecovery { proposal_id }) = late else { panic!("confirmation reaches its own receiver"); };
        assert!(take_installation_recovery(&mut slot, &proposal_id).is_err());

        ctx.native_cancel.store(false, Ordering::SeqCst);
        for command in [Cmd::CancelWsl, Cmd::Shutdown, Cmd::Stop, Cmd::Set(Cap::Dns, false), Cmd::SetWslEnabled(false),
            Cmd::SetWslDistro { name: "fixture".into(), selected: false }, Cmd::RequestElevation,
            Cmd::Elevate(crate::instances::GuiReplacementAction::ShowMain {})] {
            let command = Some(command);
            receive_prepared_installation_recovery(&ctx, &mut slot, &command, Some(proposal("late-ready")),
                |_| panic!("a competing intent must prevent publication before checking the settings"));
            assert!(slot.is_none());
            assert!(events.try_recv().is_err());
            assert!(command.is_some(), "the normal dispatcher still owns the queued command");
        }
        let command = Some(Cmd::DeepRefresh);
        receive_prepared_installation_recovery(&ctx, &mut slot, &command, Some(proposal("stale")), |_| Err("changed settings".into()));
        assert!(slot.is_none());
        assert!(matches!(events.try_recv(), Ok(Event::Log(Level::Warn, reason)) if reason.contains("changed settings")));
        receive_prepared_installation_recovery(&ctx, &mut slot, &command, Some(proposal("current")), |_| Ok(()));
        assert!(matches!(events.try_recv(), Ok(Event::InstallationRecoveryPrepared(preview)) if preview.proposal_id == "current"));
        assert!(matches!(command, Some(Cmd::DeepRefresh)));
    }

    #[cfg(windows)]
    #[test]
    fn wsl_apply_eligibility_uses_typed_desktop_and_current_selection() {
        use super::*;
        use crate::wsl_api::{RegistrationFreshness, RegistrationState, RegisteredDistro, WslPreferences, WslStatus};
        let mut settings = Settings::default();
        settings.client_patch = true;
        settings.wsl = Some(WslPreferences { enabled: true, distros: vec!["fixture".into()] });
        let mut status = WslStatus { preferences: settings.wsl.clone(), registration_freshness: RegistrationFreshness::Current,
            distributions: vec![RegisteredDistro { name: "fixture".into(), registration: RegistrationState::Present, selected: true, running: None }],
            desktop_target: desktop_kind_result([Ok(crate::InstallationKind::Cli)]), ..WslStatus::default() };
        assert!(wsl_apply_eligibility(&status, &settings).unwrap_err().contains("Desktop"));
        status.desktop_target = desktop_kind_result([Ok(crate::InstallationKind::Ide), Ok(crate::InstallationKind::Desktop)]);
        assert!(status.show_configuration());
        assert!(wsl_apply_eligibility(&status, &settings).is_ok());
        status.desktop_target = desktop_kind_result([Err("first classification error".into()), Ok(crate::InstallationKind::Desktop), Err("later error".into())]);
        assert!(status.show_configuration());
        assert_eq!(wsl_apply_eligibility(&status, &settings).unwrap_err(), "Не удалось проверить все установки Antigravity: first classification error");
        status.desktop_target = desktop_kind_result([Err("discovery error".into()), Ok(crate::InstallationKind::Ide)]);
        assert!(!status.show_configuration());
        assert_eq!(wsl_apply_eligibility(&status, &settings).unwrap_err(), "Установка Desktop не проверена: discovery error");
        status.desktop_target = DesktopDiscovery::Present;
        status.registration_freshness = RegistrationFreshness::Stale;
        assert!(wsl_apply_eligibility(&status, &settings).is_err());
        status.registration_freshness = RegistrationFreshness::Current;
        status.pending = true;
        assert!(wsl_apply_eligibility(&status, &settings).is_err());
        status.pending = false;
        status.preferences.as_mut().unwrap().enabled = false;
        assert!(wsl_apply_eligibility(&status, &settings).is_err());
        assert!(status.can_set_distro("fixture", false));
    }

    #[cfg(windows)]
    #[test]
    fn wsl_candidate_paths_flow_into_cached_and_fresh_status() {
        use super::*;
        use crate::wsl_api::WslPreferences;
        use crate::windows_coordinator::{DiscoveryObservation, Registration};
        let root = crate::wsl_discovery_contract_cases::fixture_dir("wsl-eligibility");
        let cli = root.join("cli");
        let desktop = root.join("desktop");
        let incomplete = root.join("incomplete");
        let extension = root.join(".vscode/extensions/google.google-antigravity-1.13.0/package.json");
        crate::wsl_discovery_contract_cases::fixture_file(&cli.join("agy.exe"), b"fixture");
        crate::wsl_discovery_contract_cases::fixture_file(&extension, VSCODE_ANTIGRAVITY_MANIFEST);
        crate::wsl_discovery_contract_cases::fixture_file(&desktop.join("resources/app/dist/main.js"), b"fixture");
        crate::wsl_discovery_contract_cases::fixture_file(&desktop.join("Antigravity.exe"), b"fixture");
        crate::wsl_discovery_contract_cases::fixture_file(&incomplete.join("resources/app/dist/main.js"), b"fixture");
        let (shared, _) = probe_test_ctx();
        let mut ctx = shared.lock().unwrap();
        ctx.settings.client_patch = true;
        ctx.settings.wsl = Some(WslPreferences { enabled: true, distros: vec!["fixture".into()] });
        crate::wsl_controller::test_receive_observation(&mut ctx.wsl, DiscoveryObservation {
            registrations: vec![Registration { name: "fixture".into(), running: None }], error: None,
        });
        let mut previous = ctx.last.clone().unwrap();
        previous.background_observation_error = Some("retained background observation".into());
        previous.rules_observed = Some(true);
        let vscode_antigravity = observe_vscode_antigravity(Some(&root));
        assert_eq!(vscode_antigravity, VsCodeAntigravityObservation::Found);
        let extension_only = status_with_installation_observation(&ctx, previous.clone(),
            project_install_discovery(&ctx.settings, Ok(Vec::new()), Vec::new), vscode_antigravity);
        assert!(extension_only.installs.iter().all(|row| row.path.is_none() && row.patched.is_none()));
        assert!(!extension_only.wsl.show_configuration() && !extension_only.wsl.can_apply());
        let observation = project_install_discovery(&ctx.settings, Ok(vec![cli.clone()]), Vec::new);
        let observed = status_with_installation_observation(&ctx, previous.clone(), observation, vscode_antigravity);
        assert_eq!(observed.vscode_antigravity, VsCodeAntigravityObservation::Found);
        assert_eq!(observed.wsl.desktop_target, DesktopDiscovery::Absent);
        assert!(observed.installs.iter().any(|row| row.path.as_ref() == Some(&cli)
            && row.observed_kind == Some(crate::InstallationKind::Cli)));
        assert!(!observed.wsl.show_configuration() && !observed.wsl.can_apply());
        assert_eq!(observed.background_observation_error, previous.background_observation_error);
        assert_eq!(observed.rules_observed, previous.rules_observed);
        ctx.settings.manual_paths.push(desktop.clone());
        let (rows, target) = project_install_discovery(&ctx.settings, Ok(vec![cli.clone()]), Vec::new);
        assert_eq!(target, DesktopDiscovery::Present);
        assert!(rows.iter().any(|row| row.recovery_path() == Some(desktop.as_path())));
        let current = status_with_installation_observation(&ctx, previous, (rows, target), vscode_antigravity);
        assert!(current.wsl.can_apply());
        assert_eq!(current.vscode_antigravity, VsCodeAntigravityObservation::Found);
        ctx.last = Some(current);
        assert!(wsl_status(&ctx).can_apply(), "settings-only status retains the received target");
        ctx.settings.client_patch = false;
        ctx.settings.dns = false; ctx.settings.local_proxy = false; ctx.settings.builtin_exits = false;
        ctx.settings.group_proxy = false; ctx.settings.own_proxy_enabled = false;
        assert!(!wsl_status(&ctx).can_apply(), "no-work intent recomputes against the retained target");
        ctx.settings.client_patch = true;
        ctx.settings.manual_paths.clear();
        let (_, target) = project_install_discovery(&ctx.settings, Ok(vec![cli.clone()]), Vec::new);
        assert_eq!(target, DesktopDiscovery::Absent);
        assert!(!wsl_status_with_target(&ctx, target).can_apply());
        let (_, target) = project_install_discovery(&ctx.settings, Ok(vec![cli.clone(), desktop.clone()]), Vec::new);
        assert_eq!(target, DesktopDiscovery::Present);
        ctx.settings.manual_paths.push(incomplete.clone());
        let (_, target) = project_install_discovery(&ctx.settings, Ok(Vec::new()), Vec::new);
        assert!(matches!(&target, DesktopDiscovery::Incomplete { desktop_found: false, .. }));
        let error = target.error().unwrap().to_owned();
        ctx.settings.manual_paths.push(desktop.clone());
        let (rows, target) = project_install_discovery(&ctx.settings, Ok(vec![incomplete]), Vec::new);
        assert_eq!(target, DesktopDiscovery::Incomplete { desktop_found: true, error: error.clone() });
        assert!(rows.iter().any(|row| row.recovery_path() == Some(desktop.as_path())));
        let incomplete = status_with_installation_observation(
            &ctx, ctx.last.clone().unwrap(), (rows, target), vscode_antigravity,
        );
        assert!(incomplete.wsl.show_configuration() && !incomplete.wsl.can_apply());
        assert!(incomplete.wsl.apply_eligibility.as_ref().unwrap_err().contains(error.as_str()));
        ctx.last = Some(incomplete);
        let cached = wsl_status(&ctx);
        assert!(cached.show_configuration() && !cached.can_apply());
        ctx.settings.manual_paths.clear();
        assert_eq!(project_install_discovery(&ctx.settings, Ok(Vec::new()), Vec::new).1, DesktopDiscovery::Absent);
        let (empty, _) = project_install_discovery(&ctx.settings, Ok(Vec::new()), Vec::new);
        assert!(empty.iter().all(|row| row.path.is_none() && row.discovery_note().is_none()));

        let (unavailable, _) = project_install_discovery(&ctx.settings, Err("discovery failed".into()), Vec::new);
        assert!(unavailable.iter().all(|row| row.path.is_none() && row.discovery_note().as_deref() == Some("не удалось проверить")));

        let (observed, target) = project_install_discovery(&ctx.settings, Err("discovery failed".into()),
            || crate::observe_standard_install_kinds([cli], &AtomicBool::new(false)));
        assert_eq!(target, DesktopDiscovery::Incomplete { desktop_found: false, error: "discovery failed".into() });
        let cli = observed.iter().find(|row| row.label == INSTALL_KINDS[2]).unwrap();
        assert_eq!(cli.coverage, InstallCoverage::ObservedStandard);
        assert!(cli.path.is_none() && cli.observed_kind.is_none() && cli.patched.is_none() && cli.recovery_path().is_none());
        assert!(!wsl_status_with_target(&ctx, target).can_apply());
    }
    #[cfg(windows)]
    #[test]
    fn default_lifetime_never_constructs_a_source_image() {
        assert!(super::GuiLifetime::default().retained_image().is_err());
    }
    #[cfg(windows)]
    #[test]
    fn fallback_lifetime_retains_the_same_received_image() {
        let image = std::sync::Arc::new(crate::windows_coordinator::process_identity::CurrentImage::capture().unwrap());
        let original = super::GuiLifetime::with_image(Ok(image.clone()));
        let fallback = super::GuiLifetime::with_image(original.retained_image());
        assert!(std::sync::Arc::ptr_eq(&image, &fallback.retained_image().unwrap()));
    }
    #[test]
    #[cfg(windows)]
    fn vendor_current_requires_exact_unique_owner_result() {
        let values = vec![("slot".to_owned(), [7; 32])];
        assert!(super::vendor_result_received(&values, "slot", &[7; 32]));
        assert!(!super::vendor_result_received(&values, "slot", &[8; 32]));
        assert!(!super::vendor_result_received(&values, "other", &[7; 32]));
        assert!(!super::vendor_result_received(&[values[0].clone(), values[0].clone()], "slot", &[7; 32]));
    }
    #[test]
    #[cfg(windows)]
    fn later_plan_failure_or_cancel_preserves_recovery_results_including_error_after_publish() {
        let completed = vec!["scope A: RecoverySettled; actualCurrent=Settled digest=A".to_owned()];
        for later in ["selected target B failed", "Cancelled: fresh plan receiving"] {
            let message = apply_receiving_failure(later, &completed);
            assert!(message.contains(&completed[0]) && message.contains(later));
            assert!(!message.contains("до изменений"));
        }
        let partial = vec!["scope A: readiness Err after publish; actualCurrent=Settled digest=P".to_owned()];
        let message = apply_receiving_failure("NotReady", &partial);
        assert!(message.contains(&partial[0]) && !message.contains("до изменений"));
        assert!(apply_receiving_failure("read-only failure", &[]).contains("до изменений"));
    }
    #[test]
    #[cfg(windows)]
    fn positive_apply_pending_tuple_is_once_per_intent_and_cancel_is_effect_free() {
        let mut attempted = std::collections::BTreeSet::new();
        let cancel = AtomicBool::new(false);
        let pending = crate::windows_coordinator::windows_installation::GatewayPendingObservation {
            slot_id: "a".repeat(32), operation_id: "b".repeat(32), current_sha256: [7;32],
        };
        receive_gateway_prerequisite_once(&mut attempted, &pending, &cancel).unwrap();
        assert!(receive_gateway_prerequisite_once(&mut attempted, &pending, &cancel).unwrap_err().contains("same Pending"));
        assert_eq!(attempted.len(), 1);
        cancel.store(true, Ordering::SeqCst);
        let other = crate::windows_coordinator::windows_installation::GatewayPendingObservation {
            slot_id: "c".repeat(32), ..pending.clone()
        };
        assert!(receive_gateway_prerequisite_once(&mut attempted, &other, &cancel).unwrap_err().starts_with("Cancelled:"));
        assert_eq!(attempted.len(), 1);
        let mut fresh_positive_apply = std::collections::BTreeSet::new();
        cancel.store(false, Ordering::SeqCst);
        receive_gateway_prerequisite_once(&mut fresh_positive_apply, &pending, &cancel).unwrap();
        let vendor = crate::windows_coordinator::windows_installation::VendorPendingObservation {
            slot_id: "d".repeat(32), operation_id: "e".repeat(32), current_sha256: [9; 32],
        };
        receive_pending_prerequisite_once(&mut attempted, &vendor.slot_id, &vendor.operation_id, vendor.current_sha256, &cancel).unwrap();
        assert!(receive_pending_prerequisite_once(&mut attempted, &vendor.slot_id, &vendor.operation_id, vendor.current_sha256, &cancel).unwrap_err().contains("same Pending"));
        assert!(gui_current_expectation(crate::windows_coordinator::windows_installation::ApplyCurrentObservation::VendorPending(vendor)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn acknowledged_vendor_current_rejects_another_archive_in_the_same_slot() {
        use crate::windows_coordinator::windows_installation::{
            ApplyCurrentObservation::{Absent, Settled, VendorPending, VendorReplacement},
            NativeObjectId, VendorPendingObservation, VendorUpdateObservation,
        };
        let id = |tag| NativeObjectId { volume: 7, file: [tag; 16] };
        let selected = VendorUpdateObservation {
            slot_id: "a".repeat(32),
            prior_current_sha256: [1; 32],
            new_parent_id: id(2),
            new_resources_id: id(3),
            new_archive_id: id(4),
            new_executable_sha256: [5; 32],
            new_archive_sha256: [6; 32],
            new_binding_sha256: [7; 32],
        };
        let received = VendorReplacement(selected.clone());
        let expected = gui_current_expectation(received.clone()).unwrap();
        assert_eq!(acknowledged_desktop_observation(&expected, received.clone()).unwrap(), received);

        let replacement = VendorUpdateObservation {
            new_archive_id: id(8), new_archive_sha256: [9; 32], new_binding_sha256: [10; 32],
            ..selected.clone()
        };
        for observation in [
            VendorReplacement(replacement),
            Settled { slot_id: selected.slot_id.clone(), current_sha256: selected.prior_current_sha256 },
            Absent,
        ] {
            assert_eq!(acknowledged_desktop_observation(&expected, observation).unwrap_err(),
                "Desktop Current changed before execution");
        }
        let pending = VendorPending(VendorPendingObservation {
            slot_id: selected.slot_id, operation_id: "b".repeat(32), current_sha256: [11; 32],
        });
        assert_eq!(acknowledged_desktop_observation(&expected, pending).unwrap_err(),
            "RecoveryRequired: continuation target has unresolved Current");
    }

    #[test]
    fn refresh_waits_for_owned_native_settlement_and_coalesces() {
        use std::sync::mpsc;
        let (release, wait) = mpsc::channel::<()>();
        let (entered, received) = mpsc::channel();
        let job = std::thread::spawn(move || { entered.send(()).unwrap(); wait.recv().unwrap(); });
        received.recv().unwrap();
        let mut requested = Some(DiscoveryOrigin::Startup);
        assert!(super::receive_wsl_refresh_command(&mut requested, &Some(super::Cmd::RefreshWsl)));
        assert!(super::receive_wsl_refresh_command(&mut requested, &Some(super::Cmd::RefreshWsl)));
        assert_eq!(super::take_wsl_refresh(&mut requested, job.is_finished(), &None, &None), None);
        assert_eq!(requested, Some(DiscoveryOrigin::Manual));
        release.send(()).unwrap();
        job.join().unwrap();
        assert_eq!(super::take_wsl_refresh(&mut requested, true, &None, &None), Some(DiscoveryOrigin::Manual));
        assert_eq!(super::take_wsl_refresh(&mut requested, true, &None, &None), None);
        requested = Some(DiscoveryOrigin::Manual);
        assert!(!super::receive_wsl_refresh_command(&mut requested, &Some(super::Cmd::CancelWsl)));
        assert_eq!(super::take_wsl_refresh(&mut requested, true, &None, &None), None);
        requested = Some(DiscoveryOrigin::Manual);
        assert!(!super::receive_wsl_refresh_command(&mut requested, &Some(super::Cmd::Shutdown)));
        assert_eq!(super::take_wsl_refresh(&mut requested, true, &None, &None), None);
    }

    #[test]
    fn received_commands_precede_coalesced_refresh() {
        use super::{Cmd, receive_wsl_refresh_command, take_wsl_refresh};
        let mut requested = Some(DiscoveryOrigin::Startup);
        assert_eq!(take_wsl_refresh(&mut requested, true, &Some(Cmd::RequestElevation), &None), None);
        #[cfg(windows)]
        assert_eq!(take_wsl_refresh(&mut requested, true, &None,
            &Some(Cmd::Elevate(crate::instances::GuiReplacementAction::ShowMain {}))), None);
        assert_eq!(take_wsl_refresh(&mut requested, true,
            &Some(Cmd::SetWslDistro { name: "Ubuntu".into(), selected: false }), &None), None);
        assert_eq!(take_wsl_refresh(&mut requested, true, &None, &None), Some(DiscoveryOrigin::Startup));
        assert!(receive_wsl_refresh_command(&mut requested, &Some(Cmd::RefreshWsl)));
        assert!(receive_wsl_refresh_command(&mut requested, &Some(Cmd::RefreshWsl)));
        assert_eq!(take_wsl_refresh(&mut requested, true, &None, &None), Some(DiscoveryOrigin::Manual));
        assert_eq!(take_wsl_refresh(&mut requested, true, &None, &None), None);
    }

    use super::*;

    const VSCODE_ANTIGRAVITY_MANIFEST: &[u8] =
        br#"{"publisher":"google","name":"google-antigravity","version":"1.13.0"}"#;

    struct VsCodeProfileFixture(PathBuf);

    impl VsCodeProfileFixture {
        fn new(name: &str) -> Self {
            let parent = std::env::temp_dir().canonicalize().unwrap();
            let root = crate::patch_binary::temp_path(&parent.join(name));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn write(&self, relative: &str, bytes: &[u8]) {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }

        fn observe(&self) -> VsCodeAntigravityObservation {
            observe_vscode_antigravity(Some(&self.0))
        }
    }

    impl Drop for VsCodeProfileFixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("remove owned VS Code profile fixture");
        }
    }

    #[test]
    fn vscode_antigravity_finds_exact_manifest_without_cli_or_directory_name_hint() {
        let profile = VsCodeProfileFixture::new("ag-vscode-found");
        profile.write(".vscode/extensions/renamed-directory/package.json", VSCODE_ANTIGRAVITY_MANIFEST);
        assert!(!profile.0.join(".gemini/bin").exists());
        assert_eq!(profile.observe(), VsCodeAntigravityObservation::Found);
    }

    #[test]
    fn vscode_antigravity_reports_absent_roots_and_rejects_decoy_manifests() {
        let profile = VsCodeProfileFixture::new("ag-vscode-absent");
        assert_eq!(profile.observe(), VsCodeAntigravityObservation::NotFound);
        profile.write(".vscode/extensions/extensions.json", b"[]");
        profile.write(".vscode/extensions/google.google-antigravity-1.13.0/package.json",
            br#"{"publisher":"Google","name":"google-antigravity"}"#);
        profile.write(".vscode-insiders/extensions/other/package.json",
            br#"{"publisher":"google","name":"antigravity"}"#);
        assert_eq!(profile.observe(), VsCodeAntigravityObservation::NotFound);
    }

    #[test]
    fn vscode_antigravity_leaves_unavailable_or_malformed_coverage_incomplete() {
        let profile = VsCodeProfileFixture::new("ag-vscode-incomplete");
        assert_eq!(observe_vscode_antigravity(None), VsCodeAntigravityObservation::Incomplete);
        assert_eq!(observe_vscode_antigravity(Some(Path::new("relative"))), VsCodeAntigravityObservation::Incomplete);
        assert_eq!(observe_vscode_antigravity(Some(&profile.0.join("missing-profile"))), VsCodeAntigravityObservation::Incomplete);
        profile.write(".vscode/extensions", b"not a directory");
        assert_eq!(profile.observe(), VsCodeAntigravityObservation::Incomplete);
        std::fs::remove_file(profile.0.join(".vscode/extensions")).unwrap();
        let manifest = ".vscode-insiders/extensions/google.google-antigravity-1.13.0/package.json";
        for malformed in [b"{".as_slice(), br#"{"publisher":"google","name":5}"#,
            br#"["google","google-antigravity"]"#,
            br#"{"publisher":"decoy","publisher":"google","name":"google-antigravity"}"#]
        {
            profile.write(manifest, malformed);
            assert_eq!(profile.observe(), VsCodeAntigravityObservation::Incomplete);
        }
        profile.write(".vscode/extensions", b"not a directory");
        profile.write(manifest, VSCODE_ANTIGRAVITY_MANIFEST);
        assert_eq!(profile.observe(), VsCodeAntigravityObservation::Found);
    }

    #[test]
    fn vscode_idle_poll_receives_install_and_removal_with_bounded_reads() {
        use VsCodeAntigravityObservation::{Found, NotFound};

        let profile = VsCodeProfileFixture::new("ag-vscode-idle");
        let manifest = ".vscode/extensions/extension/package.json";
        let mut last = std::time::Instant::now();
        let first_due = last + VSCODE_OBSERVATION_INTERVAL;
        assert_eq!(profile.observe(), NotFound);
        profile.write(manifest, VSCODE_ANTIGRAVITY_MANIFEST);
        assert_eq!(poll_vscode_antigravity(&mut last, first_due - Duration::from_millis(1), NotFound,
            || panic!("manifest read before the deadline")), None);
        assert_eq!(poll_vscode_antigravity(&mut last, first_due, NotFound, || profile.observe()), Some(Found));
        let next_due = first_due + VSCODE_OBSERVATION_INTERVAL;
        assert_eq!(poll_vscode_antigravity(&mut last, next_due, Found, || profile.observe()), None);
        assert_eq!(last, next_due, "an unchanged observation still advances the read cadence");
        let installed = profile.0.join(manifest);
        std::fs::remove_file(&installed).unwrap();
        std::fs::remove_dir(installed.parent().unwrap()).unwrap();
        assert_eq!(poll_vscode_antigravity(&mut last, next_due + VSCODE_OBSERVATION_INTERVAL, Found,
            || profile.observe()), Some(NotFound));
    }

    #[cfg(unix)]
    #[test]
    fn vscode_antigravity_rejects_a_linked_root_or_manifest() {
        use std::os::unix::fs::symlink;
        let profile = VsCodeProfileFixture::new("ag-vscode-links");
        profile.write("other-root/extensions/extension/package.json", VSCODE_ANTIGRAVITY_MANIFEST);
        let linked_root = profile.0.join(".vscode");
        symlink(profile.0.join("other-root"), linked_root).unwrap();
        assert_eq!(profile.observe(), VsCodeAntigravityObservation::Incomplete);
        std::fs::remove_file(profile.0.join(".vscode")).unwrap();
        std::fs::create_dir_all(profile.0.join(".vscode-insiders/extensions/extension")).unwrap();
        symlink(profile.0.join("other-root/extensions/extension/package.json"),
            profile.0.join(".vscode-insiders/extensions/extension/package.json")).unwrap();
        assert_eq!(profile.observe(), VsCodeAntigravityObservation::Incomplete);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_inventory_shows_typed_passive_locations_without_changing_effect_paths() {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let root = crate::patch_binary::temp_path(&parent.join("ag-mac-passive-inventory"));
        std::fs::create_dir(&root).unwrap();
        let ide = root.join("Antigravity IDE.app");
        let second_ide = root.join("Second IDE.app");
        let desktop = root.join("Antigravity.app");
        let unresolved = root.join("Unresolved.app");
        for path in [&ide, &second_ide] {
            std::fs::create_dir_all(path.join("Contents/Resources/app/out")).unwrap();
        }
        let resources = desktop.join("Contents/Resources");
        std::fs::create_dir_all(&resources).unwrap();
        std::fs::write(resources.join("app.asar"), b"").unwrap();
        std::fs::create_dir_all(unresolved.join("Contents/MacOS")).unwrap();
        let discovered = [ide.clone(), second_ide.clone(), desktop.clone(), unresolved.clone()];
        let mut rows = install_rows_from_discovery(&Settings::default(), discovered.to_vec());
        let effect_paths: Vec<_> = rows.iter().map(|row| (row.path.clone(), row.label, row.patched, row.manual)).collect();

        let classify = crate::observe_mac_installation_kind;
        receive_mac_inventory(&mut rows, &discovered, &[], classify);
        for (row, expected) in [(&rows[0], &desktop), (&rows[1], &ide)] {
            assert_eq!(&row.coverage, &InstallCoverage::ObservedStandard(expected.clone()));
            let masked = crate::utils::mask_path(&expected.to_string_lossy());
            let note = row.discovery_note().unwrap();
            assert!(note.contains("только просмотр"));
            assert!(note.ends_with(masked.as_str()));
            assert!(row.display_path().is_none() && row.saved_path().is_none());
        }
        assert_eq!(rows[0].path.as_ref(), Some(&ide), "keep the legacy effect slot untouched");
        assert!(rows[1].path.is_none() && rows[2].path.is_none());
        assert_eq!(rows[2].coverage, InstallCoverage::Incomplete);
        assert_eq!(rows[2].discovery_note().as_deref(), Some("не удалось проверить"));
        let first_coverage = rows[1].coverage.clone();

        receive_mac_inventory(&mut rows, &[second_ide.clone(), desktop, unresolved.clone()], &[], classify);
        assert_eq!(rows[1].coverage, InstallCoverage::ObservedStandard(second_ide));
        assert_ne!(rows[1].coverage, first_coverage, "idle coverage equality must see relocation");
        receive_mac_inventory(&mut rows, &[unresolved.clone()], &[], classify);
        assert_eq!(rows[1].coverage, InstallCoverage::Incomplete);
        assert!(rows.iter().all(|row| row.display_path().is_none() && row.saved_path().is_none()));
        let final_effect_paths: Vec<_> = rows.iter().map(|row| (row.path.clone(), row.label, row.patched, row.manual)).collect();
        assert_eq!(final_effect_paths, effect_paths);

        let applications = root.join("Applications");
        let extra_ide = applications.join("Renamed Antigravity.app");
        std::fs::create_dir_all(extra_ide.join("Contents/Resources/app/out")).unwrap();
        let wrong_scope = applications.join("Antigravity CLI style.app");
        std::fs::create_dir(&wrong_scope).unwrap();
        std::fs::write(wrong_scope.join("agy"), b"").unwrap();
        std::os::unix::fs::symlink(&extra_ide, applications.join("Antigravity alias.app")).unwrap();
        let candidates = mac_user_application_candidates(&root);
        assert_eq!(candidates, [wrong_scope, extra_ide.clone()]);
        receive_mac_inventory(&mut rows, &discovered, &candidates, classify);
        assert_eq!(rows[1].coverage, InstallCoverage::ObservedStandard(ide.clone()));
        receive_mac_inventory(&mut rows, &[], &candidates, classify);
        assert_eq!(rows[1].coverage, InstallCoverage::ObservedStandard(extra_ide));
        assert_eq!(rows[2].coverage, InstallCoverage::Incomplete);
        assert!(rows[1].path.is_none() && rows[1].display_path().is_none() && rows[1].saved_path().is_none());
        let prior = rows.clone();
        receive_mac_inventory(&mut rows, &[], &[], classify);
        carry_mac_user_inventory(&mut rows, &prior, &root);
        assert_eq!(rows[1].coverage, prior[1].coverage);
        receive_mac_inventory(&mut rows, &discovered, &[], classify);
        carry_mac_user_inventory(&mut rows, &prior, &root);
        assert_eq!(rows[1].coverage, InstallCoverage::ObservedStandard(ide.clone()));

        let linked_home = root.join("linked-home");
        std::fs::create_dir(&linked_home).unwrap();
        std::os::unix::fs::symlink(applications, linked_home.join("Applications")).unwrap();
        assert!(mac_user_application_candidates(&linked_home).is_empty());

        let mut settings = Settings::default();
        settings.manual_paths.push(discovered[2].clone());
        let mut manual = install_rows_from_discovery(&settings, discovered.to_vec());
        receive_mac_inventory(&mut manual, &discovered, &[], classify);
        assert_eq!(manual[0].coverage, InstallCoverage::Complete);
        assert_eq!(manual[0].display_path(), Some(discovered[2].as_path()));
        assert_eq!(manual[0].saved_path(), Some(discovered[2].as_path()));
        assert!(manual[0].discovery_note().is_none());

        let outside_discovery = root.join("Outside.app");
        let mut unknown = manual[0].clone();
        unknown.path = Some(unresolved.clone());
        let mut outside = unknown.clone();
        outside.path = Some(outside_discovery.clone());
        let mut repeated = [unknown.clone(), outside.clone(), unknown, outside];
        let mut calls = Vec::new();
        receive_mac_inventory(&mut repeated, &[unresolved.clone(), unresolved.clone()], &[], |path| {
            let repeated = calls.iter().any(|seen| seen == path);
            calls.push(path.to_path_buf());
            repeated.then_some(crate::InstallationKind::Desktop)
        });
        assert_eq!(calls, [unresolved, outside_discovery]);
        assert!(repeated.iter().all(|row| row.coverage == InstallCoverage::Incomplete));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_observation_reuses_stable_snapshot_and_rejects_unstable_scan() {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let root = parent.join(format!("ag-mac-observation-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let target = root.join("agy");
        let replacement = root.join("replacement");
        std::fs::write(&target, b"ineligible").unwrap();
        let mut observation = MacObservation::default();
        let mut scans = 0;
        assert_eq!(mac_observe_with(&root, true, &mut observation, |path| {
            scans += 1; patch_binary::inspect_file(path)
        }), Some(false));
        assert_eq!(mac_observe_with(&root, false, &mut observation, |_| {
            scans += 1; panic!("unchanged snapshot must not scan")
        }), Some(false));
        assert_eq!(scans, 1);
        std::fs::write(&replacement, b"inexigible").unwrap();
        std::fs::rename(&replacement, &target).unwrap();
        assert_eq!(mac_observe_with(&root, false, &mut observation, |_| panic!("first change must settle")), None);
        observation.pending_ready = true;
        assert_eq!(mac_observe_with(&root, false, &mut observation, |path| {
            scans += 1; patch_binary::inspect_file(path)
        }), Some(true));
        assert_eq!(scans, 2);
        std::fs::write(&replacement, b"ineligible").unwrap();
        assert_eq!(mac_observe_with(&root, true, &mut observation, |path| {
            std::fs::rename(&replacement, &target).unwrap();
            patch_binary::inspect_file(path)
        }), None, "replacement during structural read must stay unknown");
        assert!(observation.settled.is_none());
        assert_eq!(mac_observe_with(&root, true, &mut observation, |_| {
            patch_binary::FileState::Unreadable("synthetic denial".into())
        }), None);
        assert!(observation.settled.is_some(), "stable unreadable result may be cached as unknown");
        assert_eq!(mac_observe_with(&root, false, &mut observation, |_| panic!("cached unknown must not rescan")), None);
        let stage = patch_binary::temp_path(&target); std::fs::create_dir(&stage).unwrap();
        assert_eq!(mac_observe_install(&root, true, &mut observation), None);
        std::fs::remove_dir(stage).unwrap();
        std::fs::remove_file(target).unwrap(); std::fs::remove_dir(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires an unprivileged native user and a private temporary fixture"]
    fn mac_observation_unreadable_target_stays_unknown() {
        use std::os::unix::fs::PermissionsExt;
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                if let Err(error) = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o600)) {
                    eprintln!("owned fixture permission restoration: {error}");
                }
            }
        }
        assert_ne!(unsafe { libc::geteuid() }, 0);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!("ag-mac-unreadable-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let target = root.join("agy"); std::fs::write(&target, b"ineligible").unwrap();
        let restore = Restore(target.clone());
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0)).unwrap();
        let mut observation = MacObservation::default();
        assert_eq!(mac_observe_install(&root, true, &mut observation), None);
        assert!(observation.settled.as_ref().is_some_and(|(_, result)| result.is_none()));
        drop(restore);
        std::fs::remove_file(target).unwrap(); std::fs::remove_dir(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires AG_MAC_CACHE_TEST_ROOT and XDG_DATA_HOME inside that private root"]
    fn mac_core_idle_system_publishes_external_replacement_without_deep_refresh() {
        use std::fs::{self, FileTimes};
        let parent = PathBuf::from(std::env::var_os("AG_MAC_CACHE_TEST_ROOT").expect("private fixture root")).canonicalize().unwrap();
        let xdg = PathBuf::from(std::env::var_os("XDG_DATA_HOME").expect("private XDG")).canonicalize().unwrap();
        assert!(xdg.starts_with(&parent), "XDG must be inside the admitted private root");
        let root = parent.join(format!("ag-mac-core-observation-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let target = root.join("agy"); let replacement = root.join("replacement");
        fs::write(&target, b"ineligible").unwrap(); fs::write(&replacement, b"inexigible").unwrap();
        let timestamp = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        for path in [&target, &replacement] {
            fs::OpenOptions::new().write(true).open(path).unwrap()
                .set_times(FileTimes::new().set_modified(timestamp)).unwrap();
        }
        let (events, received) = mpsc::channel();
        let mut settings = Settings::default(); settings.manual_paths = vec![root.clone()];
        let mut ctx = Ctx { received_command_results: Mutex::new(Vec::new()),
            events, wake: Arc::new(Mutex::new(Box::new(|| {}))), settings,
            wsl: crate::wsl_controller::WslController::default(),
            native_apply_pending: Arc::new(AtomicBool::new(false)), native_cancel: Arc::new(AtomicBool::new(false)),
            lifetime: Arc::new(GuiLifetime::default()), vpn_job: None, vpn_unsettled: false,
            startup: Startup::Explicit, proxy_var_carried: None, proxy_var_retryable: false,
            patched_seen: HashMap::new(), vpn: Some(VpnSeen::None), relay_egress: None,
            last: None, dns_probe: initial_dns_probe(), carrier_set_proxy: false,
        };
        for row in install_rows(&ctx.settings) {
            if let Some(path) = row.path {
                if path != root {
                    if let Ok(snapshot) = patch_binary::mac_target_snapshot(&path) {
                        ctx.patched_seen.entry(path).or_default().settled = Some((snapshot, None));
                    }
                }
            }
        }
        assert_eq!(mac_observe_install(&root, true, ctx.patched_seen.entry(root.clone()).or_default()), Some(false));
        ctx.last = Some(read_status(&mut ctx, false, Some(VsCodeAntigravityObservation::Found), None));
        let selected = |status: &Status| status.installs.iter().find(|row| row.path.as_ref() == Some(&root)).unwrap().patched;
        assert_eq!(selected(ctx.last.as_ref().unwrap()), Some(false));
        assert!(mac_idle_observation(&mut ctx).is_none());
        assert!(received.try_recv().is_err());
        fs::rename(&replacement, &target).unwrap();
        let rows = mac_idle_observation(&mut ctx).expect("idle replacement observation");
        push_mac_idle_status(&mut ctx, rows);
        match received.recv().unwrap() {
            Event::Status(status) => {
                assert_eq!(selected(&status), None);
                assert_eq!(status.vscode_antigravity, VsCodeAntigravityObservation::Found);
            },
            _ => panic!("unexpected event"),
        }
        let rows = mac_idle_observation(&mut ctx).expect("settled idle replacement observation");
        push_mac_idle_status(&mut ctx, rows);
        match received.recv().unwrap() { Event::Status(status) => assert_eq!(selected(&status), Some(true)), _ => panic!("unexpected event") }
        assert!(mac_idle_observation(&mut ctx).is_none());
        assert!(received.try_recv().is_err());
        let stage = patch_binary::temp_path(&target); fs::create_dir(&stage).unwrap();
        let rows = mac_idle_observation(&mut ctx).expect("idle observation of the staging state");
        push_mac_idle_status(&mut ctx, rows);
        match received.recv().unwrap() { Event::Status(status) => assert_eq!(selected(&status), None), _ => panic!("unexpected event") }
        assert!(mac_idle_observation(&mut ctx).is_none());
        assert!(mac_idle_observation(&mut ctx).is_none());
        assert!(received.try_recv().is_err(), "unchanged unknown state must not flood events");
        fs::remove_dir(stage).unwrap();
        fs::remove_file(&target).unwrap(); fs::remove_dir(&root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires an unprivileged user, private AG_MAC_CACHE_TEST_ROOT and XDG_DATA_HOME inside it"]
    fn mac_core_keeps_unresolved_roots_unknown_until_absence_is_proved() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                if let Err(error) = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700)) {
                    eprintln!("owned fixture permission restoration: {error}");
                }
            }
        }
        fn prime(ctx: &mut Ctx, lost: &Path, steady: &Path) {
            ctx.settings.manual_paths = vec![lost.to_path_buf(), steady.to_path_buf()];
            ctx.patched_seen.clear(); ctx.last = None;
            let status = read_status(ctx, true, None, None);
            assert_eq!(status.client_patch, State::On);
            assert_eq!(status.installs.iter().find(|row| row.path.as_deref() == Some(lost)).unwrap().patched, Some(true));
            assert_eq!(status.installs.iter().find(|row| row.path.as_deref() == Some(steady)).unwrap().patched, Some(true));
            ctx.last = Some(status);
            ctx.last.as_mut().unwrap().installs.iter_mut().find(|row| row.path.as_deref() == Some(lost)).unwrap().manual = false;
            ctx.settings.manual_paths = vec![steady.to_path_buf()];
        }
        fn expect_unknown(ctx: &mut Ctx, events: &Receiver<Event>, lost: &Path, steady: &Path) {
            let rows = mac_idle_observation(ctx).expect("idle observation of an unconfirmed root");
            push_mac_idle_status(ctx, rows);
            let status = match events.recv().unwrap() { Event::Status(status) => status, _ => panic!("unexpected event") };
            assert_eq!(status.installs.iter().find(|row| row.path.as_deref() == Some(lost)).unwrap().patched, None);
            assert_eq!(status.installs.iter().find(|row| row.path.as_deref() == Some(steady)).unwrap().patched, Some(true));
            assert_ne!(status.client_patch, State::On, "unknown root must block an all-patched aggregate");
            assert!(mac_idle_observation(ctx).is_none());
            assert!(events.try_recv().is_err(), "unchanged unknown must not flood events");
        }
        assert_ne!(unsafe { libc::geteuid() }, 0);
        let parent = PathBuf::from(std::env::var_os("AG_MAC_CACHE_TEST_ROOT").expect("private fixture root")).canonicalize().unwrap();
        let xdg = PathBuf::from(std::env::var_os("XDG_DATA_HOME").expect("private XDG")).canonicalize().unwrap();
        assert!(xdg.starts_with(&parent), "XDG must be inside the admitted private root");
        let base = parent.join(format!("ag-mac-unresolved-roots-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let real = base.join("real"); let steady = base.join("steady");
        std::fs::create_dir(&real).unwrap(); std::fs::create_dir(&steady).unwrap();
        std::fs::write(steady.join("agy"), b"inexigible").unwrap();
        let actual = real.join("lost"); std::fs::create_dir(&actual).unwrap();
        std::fs::write(actual.join("agy"), b"inexigible").unwrap();
        let link = base.join("link"); symlink(&real, &link).unwrap();
        let through = link.join("lost");
        let (events, received) = mpsc::channel();
        let mut ctx = Ctx { received_command_results: Mutex::new(Vec::new()),
            events, wake: Arc::new(Mutex::new(Box::new(|| {}))), settings: Settings::default(),
            wsl: crate::wsl_controller::WslController::default(),
            native_apply_pending: Arc::new(AtomicBool::new(false)), native_cancel: Arc::new(AtomicBool::new(false)),
            lifetime: Arc::new(GuiLifetime::default()), vpn_job: None, vpn_unsettled: false,
            startup: Startup::Explicit, proxy_var_carried: None, proxy_var_retryable: false,
            patched_seen: HashMap::new(), vpn: Some(VpnSeen::None), relay_egress: None,
            last: None, dns_probe: initial_dns_probe(), carrier_set_proxy: false,
        };
        prime(&mut ctx, &through, &steady);
        let saved = real.join("saved"); std::fs::rename(&actual, &saved).unwrap();
        symlink(real.join("missing"), &actual).unwrap();
        expect_unknown(&mut ctx, &received, &through, &steady);
        std::fs::remove_file(&actual).unwrap(); std::fs::rename(&saved, &actual).unwrap();

        prime(&mut ctx, &through, &steady);
        std::fs::remove_file(&link).unwrap(); symlink(base.join("missing-parent"), &link).unwrap();
        expect_unknown(&mut ctx, &received, &through, &steady);
        std::fs::remove_file(&link).unwrap(); symlink(&real, &link).unwrap();

        prime(&mut ctx, &actual, &steady);
        std::fs::rename(&actual, &saved).unwrap();
        let rows = mac_idle_observation(&mut ctx).expect("idle observation of a removed root");
        push_mac_idle_status(&mut ctx, rows);
        let status = match received.recv().unwrap() { Event::Status(status) => status, _ => panic!("unexpected event") };
        assert!(status.installs.iter().all(|row| row.path.as_ref() != Some(&actual)), "genuine absence may be removed");
        assert_eq!(status.client_patch, State::On);
        std::fs::rename(&saved, &actual).unwrap();

        let denied = base.join("denied"); std::fs::create_dir(&denied).unwrap();
        let denied_root = denied.join("lost"); std::fs::create_dir(&denied_root).unwrap();
        std::fs::write(denied_root.join("agy"), b"inexigible").unwrap();
        prime(&mut ctx, &denied_root, &steady);
        let restore = Restore(denied.clone());
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0)).unwrap();
        expect_unknown(&mut ctx, &received, &denied_root, &steady);
        drop(restore);
        std::fs::remove_file(denied_root.join("agy")).unwrap(); std::fs::remove_dir(&denied_root).unwrap(); std::fs::remove_dir(&denied).unwrap();
        std::fs::remove_file(&link).unwrap(); std::fs::remove_file(actual.join("agy")).unwrap();
        std::fs::remove_dir(&actual).unwrap(); std::fs::remove_dir(&real).unwrap();
        std::fs::remove_file(steady.join("agy")).unwrap(); std::fs::remove_dir(&steady).unwrap(); std::fs::remove_dir(&base).unwrap();
    }

    #[test]
    fn client_undo_keeps_primary_and_required_restoration_failures() {
        let primary = crate::elevate::Reverted { files: 1,
            errors: vec!["first file I/O failure".into()], warnings: vec!["retained warning".into()] };
        let error = receive_client_undo(Some(Err(primary)), Err("wanted relay resume failure".into())).unwrap_err();
        assert!(error.contains("подтверждено 1"));
        assert!(error.contains("first file I/O failure") && error.contains("retained warning"));
        assert!(error.contains("wanted relay resume failure"));
        assert!(receive_client_undo(None, Ok(())).unwrap_err().contains("не вызывалась"));
    }

    #[test]
    fn retired_worker_cannot_restart_renderer_or_commit_from_ui_poll() {
        let lifetime = GuiLifetime::default();
        assert!(lifetime.can_start_fallback());
        lifetime.started.store(true, Ordering::SeqCst);
        lifetime.shutdown_ready.store(true, Ordering::SeqCst);
        *lifetime.worker.lock().unwrap() = Some(std::thread::spawn(|| {}));
        while !lifetime.poll_close().unwrap() { std::thread::yield_now(); }
        assert!(!lifetime.can_retry_renderer());
        assert!(!lifetime.can_start_fallback());
        assert!(!lifetime.arming_started.load(Ordering::SeqCst));
        assert!(!lifetime.replacement_committed());
        assert!(lifetime.finalize_exit().unwrap());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an explicit vacant owned AG_GUI_LIFETIME_TEST_ROOT"]
    fn actual_save_failure_accepts_a_fresh_close_and_joins_before_exit() {
        let root = PathBuf::from(std::env::var_os("AG_GUI_LIFETIME_TEST_ROOT").expect("owned fixture root required"));
        crate::windows_coordinator::windows_installation::WindowsLocalPath::parse(root.as_os_str()).unwrap();
        assert!(!root.exists(), "fixture leaf must be vacant");
        std::fs::create_dir(&root).unwrap();
        let local = root.join("local-appdata");
        std::fs::write(&local, b"owned not-a-directory precondition").unwrap();
        let previous = std::env::var_os("LOCALAPPDATA");
        // The exact test runs alone. This worker only calls the shutdown owner;
        // it never runs startup, discovery, system probes or selected effects.
        unsafe { std::env::set_var("LOCALAPPDATA", &local); }
        let lifetime = Arc::new(GuiLifetime::default());
        struct Restore { lifetime: Arc<GuiLifetime>, previous: Option<std::ffi::OsString> }
        impl Drop for Restore {
            fn drop(&mut self) {
                self.lifetime.command.lock().unwrap().take();
                if let Some(worker) = self.lifetime.worker.lock().unwrap().take() {
                    if worker.join().is_err() { eprintln!("owned close fixture worker panicked"); }
                }
                unsafe { match &self.previous {
                    Some(previous) => std::env::set_var("LOCALAPPDATA", previous),
                    None => std::env::remove_var("LOCALAPPDATA"),
                } }
            }
        }
        let _restore = Restore { lifetime: lifetime.clone(), previous };
        let (events, received) = mpsc::channel();
        let (command, commands) = mpsc::channel();
        *lifetime.command.lock().unwrap() = Some(command);
        let worker_lifetime = lifetime.clone();
        let settings = Settings::default();
        let expected = settings.clone();
        let worker = std::thread::spawn(move || {
            let mut ctx = Ctx { received_command_results: Mutex::new(Vec::new()), events, wake: Arc::new(Mutex::new(Box::new(|| {}))), settings,
                wsl: crate::wsl_controller::WslController::default(), native_apply_pending: Arc::new(AtomicBool::new(false)),
                native_cancel: Arc::new(AtomicBool::new(false)), background_receivings: Vec::new(), #[cfg(windows)] background_finish_reported: false,
                lifetime: worker_lifetime.clone(), vpn_job: None, vpn_unsettled: false, startup: Startup::Explicit,
                proxy_var_carried: None, proxy_var_retryable: false, patched_seen: HashMap::new(), vpn: None,
                relay_egress: None, last: None, dns_probe: initial_dns_probe(), carrier_set_proxy: false };
            while commands.recv().is_ok() { if finish_shutdown(&mut ctx, &worker_lifetime) { return; } }
        });
        *lifetime.worker.lock().unwrap() = Some(worker);
        lifetime.started.store(true, Ordering::SeqCst);
        lifetime.request_shutdown();
        loop {
            match received.recv().unwrap() {
                Event::Log(Level::Err, _) => break,
                Event::ShutdownReady => panic!("failed actual save cannot acknowledge retirement"),
                _ => {},
            }
        }
        while !lifetime.save_failed.load(Ordering::SeqCst) { std::thread::yield_now(); }
        assert!(lifetime.poll_close().is_err());
        assert!(!lifetime.shutdown_ready.load(Ordering::SeqCst));
        std::fs::remove_file(&local).unwrap();
        std::fs::create_dir(&local).unwrap();
        lifetime.request_shutdown();
        while !lifetime.poll_close().unwrap() { std::thread::yield_now(); }
        assert!(crate::settings::saved_intent_sha256(&expected).is_ok());
        assert!(!lifetime.can_start_fallback());
        assert!(!lifetime.arming_started.load(Ordering::SeqCst));
        assert!(lifetime.finalize_exit().unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn native_apply_plan_requires_real_rule_and_relay_noops() {
        let mut wanted = Settings::default();
        for choice in [TransportChoice::Dns(true), TransportChoice::LocalProxy(false),
            TransportChoice::OwnProxyEnabled(false), TransportChoice::GroupProxy(false),
            TransportChoice::BuiltinExits(false), TransportChoice::AutoPatch(true),
            TransportChoice::PatchDeclined(false)] { wanted.set_transport_choice(choice).unwrap(); }
        let mut facts = NativeApplyFacts { core_rules: true, owned_rules: true, relay_task: true,
            relay: Some(NativeRelayFacts { running: true }), watchdog: background::RoleObservation::Running, program_outdated: Some(false) };
        assert!(!NativeApplyPlan::receive(&wanted, &facts).unwrap().requires_elevation());
        facts.watchdog = background::RoleObservation::Registered;
        assert_eq!(NativeApplyPlan::receive(&wanted, &facts).unwrap().watchdog, Some(true));
        facts.watchdog = background::RoleObservation::Running;
        facts.program_outdated = Some(true);
        let delivery = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(delivery.update_shared_program && delivery.requires_elevation());
        assert!(!delivery.ensure_relay && delivery.watchdog.is_none());
        facts.program_outdated = Some(false);
        facts.relay.as_mut().unwrap().running = false;
        assert!(NativeApplyPlan::receive(&wanted, &facts).unwrap().ensure_relay);
        facts.relay.as_mut().unwrap().running = true;
        wanted.set_transport_choice(TransportChoice::Dns(false)).unwrap();
        facts.core_rules = false;
        let partial_owned = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(partial_owned.disable_dns);
        assert!(!partial_owned.stop_relay);
        assert!(partial_owned.requires_elevation());
        facts.owned_rules = false;
        assert!(NativeApplyPlan::receive(&wanted, &facts).unwrap().stop_relay);
        wanted.set_transport_choice(TransportChoice::OwnProxyEnabled(true)).unwrap();
        let retained_carrier = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(!retained_carrier.stop_relay);
        assert!(!retained_carrier.ensure_relay);
        assert!(!wanted.local_proxy);
        wanted.set_transport_choice(TransportChoice::OwnProxyEnabled(false)).unwrap();
        facts.relay_task = false;
        facts.relay = None;
        // The watchdog has the same image name. That observation alone is not
        // a positive relay-stop requirement.
        assert!(!NativeApplyPlan::receive(&wanted, &facts).unwrap().requires_elevation());
        wanted.set_transport_choice(TransportChoice::LocalProxy(true)).unwrap();
        assert!(NativeApplyPlan::receive(&wanted, &facts).is_err());
        wanted.set_transport_choice(TransportChoice::LocalProxy(false)).unwrap();
        facts.program_outdated = Some(true);
        let watchdog_only = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(watchdog_only.update_shared_program && watchdog_only.requires_elevation());
        assert_eq!(watchdog_only.watchdog, None, "generation update must retain the wanted running watchdog");
        facts.program_outdated = None;
        assert!(NativeApplyPlan::receive(&wanted, &facts).is_err());
        wanted.set_transport_choice(TransportChoice::PatchDeclined(true)).unwrap();
        let declined = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert_eq!(declined.watchdog, Some(false), "explicit decline owns effective watchdog intent");
    }

    #[cfg(windows)]
    #[test]
    fn native_apply_plan_does_not_use_omitted_dns_as_a_wish() {
        let wanted = Settings::default();
        let facts = NativeApplyFacts { core_rules: false, owned_rules: true, relay_task: true,
            relay: None, watchdog: background::RoleObservation::Running, program_outdated: Some(false) };
        let plan = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(!plan.enable_dns && !plan.disable_dns && !plan.ensure_relay && !plan.stop_relay);
    }

    #[cfg(windows)]
    #[test]
    fn full_apply_dispatch_forwards_selected_watchdog_change_to_system_reconciler() {
        let mut wanted = Settings::default();
        wanted.select_system_tcp().unwrap();
        wanted.set_transport_choice(TransportChoice::AutoPatch(true)).unwrap();
        wanted.set_transport_choice(TransportChoice::PatchDeclined(false)).unwrap();
        let expected = wanted.transport_requirements().unwrap().active_config;
        let mut facts = NativeApplyFacts { core_rules: false, owned_rules: false, relay_task: true,
            relay: Some(NativeRelayFacts { running: true }), watchdog: background::RoleObservation::Registered,
            program_outdated: Some(false) };
        let plan = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        let mut received = None;
        dispatch_system_apply(&plan, expected, |config, watchdog| { received = Some((config, watchdog)); Ok(()) }).unwrap();
        assert_eq!(received, Some((expected, Some(true))));
        facts.watchdog = background::RoleObservation::Running;
        let plan = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        assert!(!plan.requires_elevation());
        dispatch_system_apply(&plan, expected, |config, watchdog| { received = Some((config, watchdog)); Ok(()) }).unwrap();
        assert_eq!(received, Some((expected, None)));
        wanted.set_transport_choice(TransportChoice::AutoPatch(false)).unwrap();
        let plan = NativeApplyPlan::receive(&wanted, &facts).unwrap();
        dispatch_system_apply(&plan, expected, |config, watchdog| { received = Some((config, watchdog)); Ok(()) }).unwrap();
        assert_eq!(received, Some((expected, Some(false))));
    }

    #[test]
    fn terminal_colours_do_not_reach_the_window() {
        let coloured = "\x1b[33mвнимание\x1b[0m\x1b[92m: правило";
        assert_eq!(strip_ansi(coloured), "внимание: правило");
    }

    #[test]
    fn a_capability_that_edits_system_policy_asks_for_admin_on_windows() {
        // The trap this guards: without elevation `remove_dns_nrpt` and
        // `background::disable` do not fail, they silently do nothing — so an
        // unelevated OFF switch would render as off while the rules stayed.
        assert_eq!(Cap::Dns.needs_admin(), cfg!(target_os = "windows"));
        assert!(!Cap::ClientPatch.needs_admin(), "the patch needs no UAC");
        assert!(!Cap::OwnProxy.needs_admin());
    }

    /// G74: the window drew the local-proxy switch from the environment alone,
    /// so a variable that outlived a failed removal showed «вкл» while the relay
    /// logged «выключена в настройках» in the same minute. The setting is what
    /// the relay obeys, so the setting is what the switch may never contradict.
    #[test]
    fn the_local_proxy_switch_never_reads_on_while_the_setting_is_off() {
        for ours in [true, false] {
            assert!(
                !local_proxy_state(false, ours).is_on(),
                "switch on with the setting off (variable present: {ours})"
            );
        }
        assert_eq!(local_proxy_state(true, true), State::On);
        assert_eq!(local_proxy_state(false, false), State::Off);
        // Both mismatches say which way round they are, rather than going quiet.
        assert!(local_proxy_state(true, false).note().is_some());
        assert!(local_proxy_state(false, true).note().is_some());
        // And each stays switchable the other way (G41): asked-for reads as on
        // so it can be turned off, left-over reads as off so it can be turned on.
        assert!(local_proxy_state(true, false).is_on());
        assert!(!local_proxy_state(false, true).is_on());
    }

    #[test]
    fn with_rotation_off_the_one_that_answers_is_the_first_one_left_on() {
        let names = crate::resolvers::provider_names();
        assert!(names.len() >= 2, "the test needs a pool to narrow");

        let mut s = Settings::default();
        assert_eq!(first_enabled_provider(&s), Some(names[0]));

        // Turning the head off must move the choice down the list, not leave it
        // pointing at a provider that is switched off.
        s.set_provider_enabled(names[0], false);
        assert_eq!(first_enabled_provider(&s), Some(names[1]));

        for n in &names {
            s.set_provider_enabled(n, false);
        }
        assert_eq!(first_enabled_provider(&s), None);
        assert!(all_providers_disabled(&s));
    }

    #[test]
    fn a_partial_state_still_reads_as_on() {
        // Half-patched must not draw as off: the user would flip it on and get
        // a no-op on the installs that are already done.
        assert!(State::Partial("x".into()).is_on());
        assert!(!State::Blocked("нет прав".into()).is_on());
        assert!(!State::Off.is_on());
    }

    /// The bug this pins: «Сверять TLS» and «Ротация» described their *off*
    /// state with a note, the note was a `Partial`, and `Partial` reads as on —
    /// so the switch sprang back the moment the worker's snapshot arrived and
    /// neither could be turned off, while the log said they had been.
    #[test]
    fn a_switch_that_is_off_with_a_note_is_off() {
        let mut s = Settings::default();
        s.rotate_providers = false;
        s.builtin_exits = false;
        let st = blank_status().with_settings_switches(&s);

        assert!(!st.dns_rotation.is_on());
        assert!(!st.builtin_exits.is_on());
        // The note itself must survive — it is what the row says underneath.
        assert!(st.dns_rotation.note().is_some());

        let on = blank_status().with_settings_switches(&Settings::default());
        assert!(on.dns_rotation.is_on());
        assert_eq!(on.builtin_exits.is_on(), proxy::exits_available());
    }

    #[cfg(not(exits))]
    #[test]
    fn unavailable_builtin_exit_preserves_saved_wish() {
        assert!(!proxy::exits_available());
        let mut settings = Settings::default();
        settings.builtin_exits = true;
        let status = blank_status().with_settings_switches(&settings);
        assert!(matches!(status.builtin_exits, State::Blocked(_)));
        assert!(settings.builtin_exits);
        settings.local_proxy = false;
        settings.own_proxy_enabled = false;
        settings.group_proxy = false;
        assert!(!routes_want_relay(&settings));
    }

    #[cfg(all(windows, not(exits)))]
    #[test]
    fn unavailable_builtin_exit_rejects_direct_replay_and_mixed_batch() {
        assert!(!proxy::exits_available());
        let (ctx, _events) = probe_test_ctx();
        let mut ctx = ctx.lock().unwrap();
        ctx.settings.builtin_exits = true;
        let before = ctx.settings.encode_for_save().unwrap();
        for choices in [
            vec![TransportChoice::BuiltinExits(true)],
            vec![TransportChoice::BuiltinExits(true)],
            vec![TransportChoice::GroupProxy(false), TransportChoice::BuiltinExits(true)],
        ] {
            let error = commit_transport(&mut ctx, choices).unwrap_err();
            assert!(error.contains("недоступны"));
            assert_eq!(ctx.settings.encode_for_save().unwrap(), before);
            assert!(ctx.settings.builtin_exits);
        }
    }

    /// A settings-only refresh must produce the same switches a full one does,
    /// or a flip would answer differently depending on which path drew it.
    #[test]
    fn the_cheap_refresh_and_the_full_one_agree_about_the_settings_switches() {
        let mut s = Settings::default();
        s.rotate_providers = false;
        let a = blank_status().with_settings_switches(&s);
        let b = blank_status().with_settings_switches(&s);
        assert_eq!(a.dns_rotation, b.dns_rotation);
        assert_eq!(a.providers.len(), crate::resolvers::provider_names().len());
    }

    /// A switch that only writes `settings.json` must not send the worker back
    /// to Windows for scheduled tasks and environment variables.
    #[test]
    fn only_the_switches_that_touch_the_system_pay_for_a_system_scan() {
        assert_eq!(scan_after(Cap::BuiltinExits), Scan::Settings);
        assert_eq!(scan_after(Cap::GroupProxy), Scan::Settings);
        assert_eq!(scan_after(Cap::Dns), Scan::System);
        assert_eq!(scan_after(Cap::LocalProxy), Scan::System);
        assert_eq!(scan_after(Cap::ClientPatch), Scan::Deep);
    }

    /// Any single way can be the only one on: the master switch follows it
    /// instead of reading off (which is what unset it under the user's own proxy).
    #[test]
    fn any_single_way_keeps_the_master_switch_on() {
        let blank = blank_status();
        assert!(!blank.bypass_on());
        for set in [
            |s: &mut Status| s.own_proxy = State::On,
            |s: &mut Status| s.group_proxy = State::On,
            |s: &mut Status| s.builtin_exits = State::On,
            |s: &mut Status| s.local_proxy = State::On,
            |s: &mut Status| s.dns = State::On,
        ] {
            let mut s = blank_status();
            set(&mut s);
            assert!(s.bypass_on());
        }
    }

    /// The master switch off lets go of every way, DNS last (the service dies
    /// with it) and the user's own proxy included, or it would draw itself on again.
    #[test]
    fn master_off_takes_every_way_down_and_on_never_picks_the_users_proxy() {
        let off = bypass_order(false);
        if Cap::Dns.supported() { assert_eq!(off.last(), Some(&Cap::Dns)); }
        else { assert!(!off.contains(&Cap::Dns) && !bypass_order(true).contains(&Cap::Dns)); }
        assert!(off.contains(&Cap::OwnProxy) && off.contains(&Cap::GroupProxy));
        assert!(!bypass_order(true).contains(&Cap::OwnProxy));
    }

    /// A service kept up for a route is not a half-installed DNS layer: with the
    /// DNS switch off it reads off, with it on it is still a fault.
    #[test]
    fn a_service_running_for_a_route_does_not_pin_the_dns_switch_on() {
        let off = dns_state(true, false, true, None, true, false);
        assert!(!off.is_on());
        let broken = dns_state(true, false, true, None, true, true);
        if Cap::Dns.supported() { assert!(broken.is_on()); }
        else { assert!(matches!(broken, State::Blocked(_))); }
    }

    #[test]
    fn the_service_is_wanted_while_any_route_is() {
        let mut s = Settings::default();
        s.local_proxy = false;
        s.builtin_exits = false;
        s.group_proxy = false;
        s.own_proxy_enabled = false;
        assert!(!routes_want_relay(&s));
        s.own_proxy_enabled = true;
        assert!(routes_want_relay(&s));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_apply_starts_selected_routes_without_selecting_local_proxy() {
        let mut s = Settings::default();
        s.local_proxy = false;
        s.own_proxy_enabled = false;
        s.group_proxy = false;
        s.builtin_exits = false;
        assert!(!routes_want_relay(&s));
        let selectors: [fn(&mut Settings); 2] = [
            |s: &mut Settings| s.own_proxy_enabled = true,
            |s: &mut Settings| s.group_proxy = true,
        ];
        for select in selectors {
            let mut wanted = s.clone();
            select(&mut wanted);
            assert!(routes_want_relay(&wanted));
            assert!(!wanted.local_proxy);
        }
        s.builtin_exits = true;
        assert_eq!(routes_want_relay(&s), proxy::exits_available());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_currentness_receiving_keeps_unknown_diagnostic_and_off_intent() {
        assert_eq!(receive_relay_currentness(Ok(true)), (true, None));
        assert_eq!(receive_relay_currentness(Ok(false)), (false, None));
        let (outdated, diagnostic) = receive_relay_currentness(Err("invalid saved version".into()));
        assert!(!outdated && diagnostic.unwrap().contains("invalid saved version"));
        let mut off = Settings::default();
        off.local_proxy = false;
        off.own_proxy_enabled = false;
        off.group_proxy = false;
        off.builtin_exits = false;
        assert!(!routes_want_relay(&off));
        off.group_proxy = true;
        assert!(routes_want_relay(&off));
    }

    /// Live: what a switch actually costs, which is the complaint this was built
    /// to answer («слишком много времени»). Prints, asserts only the shape.
    ///
    ///     cargo test what_a_refresh_costs -- --ignored --nocapture
    #[test]
    #[ignore = "times real helper processes; run on Windows with --ignored"]
    fn what_a_refresh_costs() {
        let (tx, _rx) = mpsc::channel();
        let mut ctx = Ctx { received_command_results: Mutex::new(Vec::new()),
            events: tx,
            wake: Arc::new(Mutex::new(Box::new(|| {}))),
            settings: Settings::load(),
            wsl: crate::wsl_controller::WslController::default(),
            native_apply_pending: Arc::new(AtomicBool::new(false)),
            native_cancel: Arc::new(AtomicBool::new(false)),
            #[cfg(windows)]
            background_receivings: Vec::new(), #[cfg(windows)] background_finish_reported: false,
            lifetime: Arc::new(GuiLifetime::default()),
            vpn_job: None,
            vpn_unsettled: false,
            startup: Startup::Ordinary,
            proxy_var_carried: None,
            proxy_var_retryable: false,
            patched_seen: HashMap::new(),
            vpn: Some(VpnSeen::None),
            relay_egress: None,
            last: None,
            dns_probe: initial_dns_probe(),
            carrier_set_proxy: false,
        };

        let t = std::time::Instant::now();
        let full = read_status(&mut ctx, false, None, #[cfg(target_os = "macos")] None);
        let system = t.elapsed();
        ctx.last = Some(full);

        let t = std::time::Instant::now();
        let _ = settings_only_status(&ctx, ctx.last.clone().unwrap());
        let settings = t.elapsed();

        println!("Scan::System   {:?}", system);
        println!("Scan::Settings {:?}", settings);
        assert!(
            settings < system,
            "the cheap path is not cheaper: {:?} vs {:?}",
            settings,
            system
        );
    }

    fn blank_status() -> Status {
        Status {
            wsl: crate::wsl_api::WslStatus::default(),
            admin: true,
            installs: Vec::new(),
            vscode_antigravity: VsCodeAntigravityObservation::Incomplete,
            client_patch: State::Off,
            watchdog: State::Off,
            dns: State::Off,
            local_proxy: State::Off,
            own_proxy: State::Off,
            builtin_exits: State::Off,
            group_proxy: State::Off,
            dns_rotation: State::Off,
            transport_view: TransportView::LegacyOrMissing,
            transport_choices: Err("Настройки подключения ещё не получены".into()),
            transport_ready: None,
            vpn: None,
            own_proxy_text: String::new(),
            custom_dns_text: String::new(),
            relay_outdated: false,
            #[cfg(windows)]
            selected_delivery: Err("Сравнение выбранного пакета ещё не получено".into()),
            relay_running: false,
            background_observation_error: None,
            rules: false,
            rules_observed: None,
            providers: Vec::new(),
            relay_egress: None,
        }
    }

    #[cfg(windows)]
    fn probe_test_ctx() -> (Mutex<Ctx>, Receiver<Event>) {
        let (events, receiver) = mpsc::channel();
        let ctx = Ctx { received_command_results: Mutex::new(Vec::new()), events, wake: Arc::new(Mutex::new(Box::new(|| {}))), settings: Settings::default(),
            wsl: crate::wsl_controller::WslController::default(), native_apply_pending: Arc::new(AtomicBool::new(false)),
            native_cancel: Arc::new(AtomicBool::new(false)), background_receivings: Vec::new(), background_finish_reported: false,
            lifetime: Arc::new(GuiLifetime::default()), vpn_job: None, vpn_unsettled: false, startup: Startup::Ordinary,
            proxy_var_carried: None, proxy_var_retryable: false, patched_seen: HashMap::new(), vpn: Some(VpnSeen::None),
            relay_egress: Some(crate::egress::ClientEgress::Physical), last: Some(blank_status()), dns_probe: initial_dns_probe(), carrier_set_proxy: false };
        (Mutex::new(ctx), receiver)
    }

    #[cfg(windows)]
    #[test]
    fn custom_dns_setting_validates_every_address_and_collapses_duplicates() {
        let (shared, events) = probe_test_ctx();
        let mut ctx = shared.lock().unwrap();
        ctx.settings.custom_dns = "9.9.9.9".into();
        ctx.settings.set_provider_enabled("свой DNS", false);

        for invalid in [
            "8.8.4.4 junk 8.8.4.4",
            "8.8.4.4 127.0.0.53",
            "8.8.4.4 0.0.0.0",
            "8.8.4.4 224.0.0.1",
            ", ;",
        ] {
            set_custom_dns(&mut ctx, invalid);
            assert_eq!(ctx.settings.custom_dns, "9.9.9.9");
            assert!(!ctx.settings.provider_enabled("свой DNS"));
            assert!(matches!(events.try_recv(), Ok(Event::Log(Level::Err, _))));
        }

        set_custom_dns(&mut ctx, " \t ");
        assert!(ctx.settings.custom_dns.is_empty());
        assert!(ctx.settings.provider_enabled("свой DNS"));
        assert!(matches!(events.try_recv(), Ok(Event::Log(Level::Ok, _))));

        ctx.settings.set_provider_enabled("свой DNS", false);
        set_custom_dns(&mut ctx, "8.8.4.4, 1.1.1.1; 8.8.4.4\t9.9.9.9 1.1.1.1");
        assert_eq!(ctx.settings.custom_dns, "8.8.4.4 1.1.1.1 9.9.9.9");
        assert!(ctx.settings.provider_enabled("свой DNS"));
        assert!(matches!(events.try_recv(), Ok(Event::Log(Level::Ok, _))));
    }

    #[cfg(windows)]
    fn probe_test_observation(rules: bool) -> WindowsSystemObservation {
        WindowsSystemObservation { rules: Ok((rules, rules)), transport: None, transport_error: None, selected_delivery: Ok(false), background: Ok(background::BackgroundObservation {
            relay: background::RoleObservation::Absent, watchdog: background::RoleObservation::Absent,
            selected_delivery_required: Some(false), proxy_ready: Some(Ok(false)), dns_ready: Some(Ok(false)),
        })}
    }

    #[cfg(windows)]
    #[test]
    fn unsuccessful_manual_install_patch_preserves_background_status() {
        let (shared, events) = probe_test_ctx();
        let mut ctx = shared.lock().unwrap();
        ctx.settings.dns = true;
        ctx.settings.auto_patch = true;
        ctx.settings.local_proxy = true;
        let saved = ctx.settings.encode_for_save().unwrap();
        let mut observed = probe_test_observation(true);
        let background = observed.background.as_mut().unwrap();
        background.relay = background::RoleObservation::Running;
        background.watchdog = background::RoleObservation::Running;
        background.proxy_ready = Some(Ok(true));
        background.dns_ready = Some(Ok(true));
        ctx.dns_probe = Ok(observed);
        let mut prior = blank_status();
        prior.local_proxy = State::On;
        ctx.last = Some(settings_only_status(&ctx, prior));
        let assert_observed = |status: &Status| {
            assert_eq!((&status.dns, &status.watchdog, &status.local_proxy), (&State::On, &State::On, &State::On));
            assert_eq!(status.rules_observed, Some(true));
            assert!(status.relay_running && status.background_observation_error.is_none());
        };
        assert_observed(ctx.last.as_ref().unwrap());

        let id = crate::windows_coordinator::windows_installation::new_request_id().unwrap();
        let install = std::env::temp_dir().join(format!("ag-manual-patch-status-{id}"));
        std::fs::create_dir(&install).unwrap();
        let command = Cmd::PatchInstall(install.clone());
        begin_owned_command(&mut ctx, &command);
        let began_busy = matches!(events.try_recv(), Ok(Event::Busy(Some(_))));
        let extra_begin_event = events.try_recv().ok();
        let during = settings_only_status(&ctx, ctx.last.clone().unwrap());
        let result = dispatch_owned_command(&mut ctx, command);
        std::fs::remove_dir(&install).unwrap();

        assert!(began_busy && extra_begin_event.is_none());
        assert_observed(&during);
        assert!(matches!(result, Err(error) if error.contains("патч не записан")));
        push_status(&mut ctx, Scan::Settings);
        let finished = events.try_iter().find_map(|event| match event { Event::Status(status) => Some(status), _ => None }).unwrap();
        assert_observed(&finished);
        assert_eq!(ctx.settings.encode_for_save().unwrap(), saved);
    }

    #[cfg(windows)]
    #[test]
    fn gui_receives_each_completed_operation_in_the_current_batch() {
        let (ctx, _events) = probe_test_ctx();
        let ctx = ctx.lock().unwrap();
        assert!(ctx.lifetime.new_command_scope().unwrap().with_result::<()>(|_| Err("mutation A failed".into())).is_err());
        assert!(ctx.lifetime.new_command_scope().unwrap().with_result::<()>(|_| Err("observation B failed".into())).is_err());
        ctx.receive_command_results();
        let received = ctx.received_command_results.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert!(received[0].contains("mutation A failed"));
        assert!(received[1].contains("observation B failed"));
        assert!(ctx.lifetime.command_scopes_settled());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires outer creator Job and private U04_FIXTURE_EXE/U04_FIXTURE_DIR"]
    fn readonly_stale_probe_receives_real_nonzero_before_discarding_result() {
        let executable = std::path::PathBuf::from(std::env::var_os("U04_FIXTURE_EXE").expect("absolute actor"));
        let directory = std::path::PathBuf::from(std::env::var_os("U04_FIXTURE_DIR").expect("private fixture directory"));
        let (ctx, _events) = probe_test_ctx();
        let mut ctx = ctx.lock().unwrap();
        let (back, _commands) = mpsc::channel();
        let command = ctx.lifetime.new_command_scope().unwrap();
        let retained = command.clone();
        start_readonly_probe_with(&mut ctx, back, Some(retained), move |_| {
            let result = command.with_result::<()>(|outcome| {
                let prepared = crate::utils::PreparedExec::fixture_absolute(&executable).unwrap().args(["--fixture", "nonzero"]).arg(&directory);
                let observed = crate::utils::bounded_output(outcome, prepared, Duration::from_secs(5));
                assert_eq!(observed, crate::utils::CommandObservation::Complete);
                Err("original read-only failure".into())
            });
            ProbeCompletion { vpn: VpnSeen::Unmeasured, relay_egress: None,
                observation: Err(result.unwrap_err()) }
        });
        ctx.vpn_job.as_mut().unwrap().valid = false;
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while !ctx.vpn_job.as_ref().unwrap().handle.is_finished() {
            assert!(std::time::Instant::now() < until);
            std::thread::yield_now();
        }
        receive_probe_completion(&mut ctx);
        assert!(ctx.vpn_job.is_none());
        assert!(ctx.lifetime.command_scopes_settled());
        let errors = ctx.received_command_results.lock().unwrap();
        assert!(errors.iter().any(|error| error.contains("original read-only failure") && error.contains("exit=Some(7)")));
    }

    #[cfg(windows)]
    #[test]
    fn readonly_dispatch_owns_notifications_reaping_and_independent_cancellation() {
        let (shared, received) = probe_test_ctx();
        let (back, notifications) = mpsc::channel();
        let notify = || Some(Cmd::Probed { vpn: VpnSeen::CarryingClient, relay: true,
            relay_egress: Some(crate::egress::ClientEgress::Tunnel) });
        let mut refresh = false;
        let mut command = notify();
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, false, false, |_| panic!("no request"));
        assert!(command.is_none() && received.try_recv().is_err());
        assert_eq!(shared.lock().unwrap().vpn, Some(VpnSeen::None));

        // The command is retained without waiting on the native job's Ctx guard.
        let guard = shared.lock().unwrap();
        command = Some(Cmd::RemeasureVpn);
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, true, false, |_| panic!("native owns Ctx"));
        assert!(refresh && command.is_none());
        drop(guard);
        {
            let mut ctx = shared.lock().unwrap();
            ctx.startup = Startup::Held("native operation needs recovery".into());
            ctx.native_apply_pending.store(true, Ordering::SeqCst);
            ctx.native_cancel.store(true, Ordering::SeqCst);
        }
        let (entered, entry) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        // No logical native hold is passed to this lane. A fresh query owns a
        // different cancellation token even when mutation cancellation latched.
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, false, false, |ctx| {
            start_readonly_probe_with(ctx, back.clone(), None, move |cancel| {
                assert!(!cancel.load(Ordering::SeqCst));
                entered.send(()).unwrap();
                wait.recv().unwrap();
                assert!(!cancel.load(Ordering::SeqCst));
                ProbeCompletion { vpn: VpnSeen::CarryingClient,
                    relay_egress: Some(crate::egress::ClientEgress::Tunnel),
                    observation: Ok(probe_test_observation(true)) }
            });
        });
        entry.recv_timeout(Duration::from_secs(5)).unwrap();
        command = notify();
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, true, false, |_| panic!("unfinished query"));
        assert!(shared.lock().unwrap().vpn_job.is_some());
        assert!(received.try_recv().is_err());
        release.send(()).unwrap();
        while !shared.lock().unwrap().vpn_job.as_ref().unwrap().handle.is_finished() { std::thread::yield_now(); }
        // A finished owned query is received during an active native operation,
        // without consuming or trusting the notification queued by that query.
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, true, false, |_| panic!("native active"));
        {
            let ctx = shared.lock().unwrap();
            assert!(ctx.vpn_job.is_none() && ctx.native_apply_pending.load(Ordering::SeqCst));
            assert!(matches!(ctx.startup, Startup::Held(_)));
            assert_eq!(ctx.vpn, Some(VpnSeen::CarryingClient));
            assert_eq!(ctx.dns_probe.as_ref().unwrap().rules.as_ref(), Ok(&(true, true)));
        }
        assert!(received.try_iter().any(|event| matches!(event, Event::Status(_))));
        command = Some(notifications.recv_timeout(Duration::from_secs(5)).unwrap());
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, false, false, |_| panic!("repeated notification"));
        assert!(received.try_recv().is_err());

        // The real spawner panics before its send and measuring-flag cleanup.
        command = Some(Cmd::RemeasureVpn);
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, false, false, |ctx| {
            start_readonly_probe_with(ctx, back.clone(), None, |_| panic!("probe failed before notification"));
        });
        while !shared.lock().unwrap().vpn_job.as_ref().unwrap().handle.is_finished() { std::thread::yield_now(); }
        assert!(notifications.try_recv().is_err());
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, false, false, |_| panic!("no new request"));
        assert!(shared.lock().unwrap().vpn_job.is_none());
        assert!(shared.lock().unwrap().dns_probe.is_err());
        assert!(received.try_iter().any(|event| matches!(event, Event::Status(status) if status.background_observation_error.is_some())));

        let (entered, entry) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        command = Some(Cmd::RemeasureVpn);
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, false, false, |ctx| {
            start_readonly_probe_with(ctx, back, None, move |cancel| {
                assert!(!cancel.load(Ordering::SeqCst));
                entered.send(()).unwrap();
                wait.recv().unwrap();
                assert!(cancel.load(Ordering::SeqCst));
                ProbeCompletion { vpn: VpnSeen::None, relay_egress: None, observation: Err("owned cancellation".into()) }
            });
        });
        entry.recv_timeout(Duration::from_secs(5)).unwrap();
        command = Some(Cmd::Shutdown);
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, false, false, |_| panic!("shutdown starts no query"));
        release.send(()).unwrap();
        while !shared.lock().unwrap().vpn_job.as_ref().unwrap().handle.is_finished() { std::thread::yield_now(); }
        dispatch_readonly_probe(&shared, &mut command, &mut refresh, false, false, |_| panic!("shutdown starts no query"));
        assert!(matches!(command, Some(Cmd::Shutdown)));
        assert!(shared.lock().unwrap().vpn_job.is_none());
        assert_eq!(shared.lock().unwrap().dns_probe.as_ref().err().map(String::as_str), Some("owned cancellation"));
    }

    #[cfg(windows)]
    #[test]
    fn readonly_dispatch_rejects_whole_mutation_window_and_preserves_newer_cache() {
        let (shared, received) = probe_test_ctx();
        let mut refresh = false;
        let mut command = None;
        for newer_cache in [false, true] {
            let (release, wait) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                wait.recv().unwrap();
                ProbeCompletion {
                    vpn: VpnSeen::CarryingClient, relay_egress: Some(crate::egress::ClientEgress::Tunnel),
                    observation: Ok(probe_test_observation(false)),
                }
            });
            {
                let mut ctx = shared.lock().unwrap();
                ctx.vpn_job = Some(ProbeJob { handle, valid: true, cancel: Arc::new(AtomicBool::new(false)), command_receipt: None });
                ctx.dns_probe = Ok(probe_test_observation(false));
                begin_native_change(&mut ctx, "controlled native change");
                assert!(!ctx.vpn_job.as_ref().unwrap().valid && ctx.dns_probe.is_err());
                assert!(matches!(received.recv().unwrap(), Event::Busy(Some(_))));
                assert!(matches!(received.recv().unwrap(), Event::Status(status) if status.background_observation_error.is_some()));
                // A completed Deep/System read may now be newer than the still
                // running job. Its cache must survive receipt of the old job.
                if newer_cache {
                    let mut newer = probe_test_observation(true);
                    newer.selected_delivery = Err("directory case mode: os error 87".into());
                    newer.background = Ok(background::BackgroundObservation {
                        relay: background::RoleObservation::Running, watchdog: background::RoleObservation::Running,
                        selected_delivery_required: None, proxy_ready: Some(Ok(true)), dns_ready: Some(Ok(true)),
                    });
                    receive_system_observation(&mut ctx, Ok(newer));
                }
            }
            release.send(()).unwrap();
            while !shared.lock().unwrap().vpn_job.as_ref().unwrap().handle.is_finished() { std::thread::yield_now(); }
            dispatch_readonly_probe(&shared, &mut command, &mut refresh, true, false, |_| panic!("native still active"));
            {
                let ctx = shared.lock().unwrap();
                assert!(ctx.vpn_job.is_none());
                assert_eq!(ctx.vpn, Some(VpnSeen::None));
                assert!(matches!(ctx.relay_egress, Some(crate::egress::ClientEgress::Physical)));
                if newer_cache {
                    let packet = ctx.dns_probe.as_ref().unwrap();
                    assert_eq!(packet.rules.as_ref(), Ok(&(true, true)));
                    assert_eq!(packet.selected_delivery.as_ref().err().map(String::as_str), Some("directory case mode: os error 87"));
                    let status = ctx.last.as_ref().unwrap();
                    assert_eq!(status.selected_delivery.as_ref().err().map(String::as_str), Some("directory case mode: os error 87"));
                    assert!(!status.relay_outdated && status.relay_running);
                    let facts = crate::gui::status::Facts::read(status, &crate::gate::View::default(), Duration::ZERO);
                    let headline = crate::gui::status::headline(&facts);
                    assert_ne!(headline.action, Some(crate::gui::status::Action::Repair));
                    assert!(headline.detail.contains("os error 87"));
                }
                else { assert!(ctx.dns_probe.is_err() && refresh); }
            }
            if newer_cache {
                command = Some(Cmd::Probed { vpn: VpnSeen::CarryingClient, relay: true, relay_egress: None });
                dispatch_readonly_probe(&shared, &mut command, &mut refresh, true, false, |_| panic!("old notification must not start a query"));
                assert!(command.is_none());
                let ctx = shared.lock().unwrap();
                assert_eq!(ctx.dns_probe.as_ref().unwrap().selected_delivery.as_ref().err().map(String::as_str), Some("directory case mode: os error 87"));
                let status = ctx.last.as_ref().unwrap();
                assert_eq!(status.selected_delivery.as_ref().err().map(String::as_str), Some("directory case mode: os error 87"));
                assert!(!status.relay_outdated);
            }
            let _ = received.try_iter().count();
            refresh = false;
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_ctx_job_preserves_original_panic_and_unpoisoned_stored_state() {
        let (shared, _received) = probe_test_ctx();
        let shared = Arc::new(shared);
        let worker_shared = shared.clone();
        let original = Arc::new(());
        let thrown = original.clone();
        let handle = std::thread::spawn(move || {
            let ctx = worker_shared.lock().unwrap();
            run_ctx_job(ctx, |ctx| {
                ctx.dns_probe = Err("stored before original unwind".into());
                std::panic::panic_any(thrown);
            });
        });
        let payload = handle.join().expect_err("native job must still panic");
        let received = payload.downcast::<Arc<()>>().expect("exact original payload type");
        assert!(Arc::ptr_eq(&original, &received));
        let ctx = shared.lock().expect("Ctx guard dropped normally before original unwind resumed");
        assert_eq!(ctx.dns_probe.as_ref().err().map(String::as_str), Some("stored before original unwind"));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit owned private fixture parent; real creation/unwind/finish, no product task or settings effects"]
    fn early_creation_panic_reaches_stored_core_owner_before_original_join_panic() {
        let parent = PathBuf::from(std::env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT").expect("explicit qualified parent"));
        let root = crate::windows_coordinator::windows_installation::context_fixture_directory(&parent).unwrap();
        let packet = background::test_early_creation_panic_packet(root.clone());
        assert_eq!(packet.live_resources.len(), 1);
        let (shared, received) = probe_test_ctx();
        let shared = Arc::new(shared);
        let worker_shared = shared.clone();
        let handle = std::thread::spawn(move || {
            let ctx = worker_shared.lock().unwrap();
            run_ctx_job(ctx, |ctx| {
                ctx.startup = Startup::Held("synthetic creation panic fixture".into());
                let _ = ctx.retain_background_receiving(packet);
                panic!("pending original panic was not resumed");
            });
        });
        let payload = handle.join().expect_err("native job must retain the original unwind");
        assert_eq!(payload.downcast_ref::<&'static str>().copied(), Some("owned-creation-unwind-fixture"));
        let mut ctx = shared.lock().expect("packet handoff must not poison Ctx");
        assert_eq!(ctx.background_receivings.len(), 1);
        assert_eq!(ctx.background_receivings[0].live_resources.len(), 1);
        assert!(ctx.background_receivings[0].result.is_err());
        let lifetime = ctx.lifetime.clone();
        receive_shutdown_request(&mut ctx, &Some(Cmd::Shutdown));
        assert!(finish_shutdown(&mut ctx, &lifetime));
        assert!(ctx.background_receivings[0].live_resources.is_empty());
        assert!(received.try_iter().any(|event| matches!(event, Event::ShutdownReady)));
        eprintln!("owned Core creation-unwind root={}, original payload and same packet received through production finish", root.display());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit owned private fixture parent; no product task or settings effects"]
    fn early_creation_failure_reaches_core_and_holds_shutdown_until_settled() {
        let parent = PathBuf::from(std::env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT").expect("explicit qualified parent"));
        let root = crate::windows_coordinator::windows_installation::context_fixture_directory(&parent).unwrap();
        let mut packet = background::test_early_creation_packet(root.clone());
        assert!(packet.result.is_err() && packet.diagnostic_journal.is_none());
        assert_eq!(packet.live_resources.len(), 1);
        assert!(serde_json::to_value(&packet).unwrap().get("live_resources").is_none());
        // This test alone writes a byte to its unpublished fixture object so a
        // real creator-owned writable mapping can block native disposition.
        use std::io::Write;
        let witness = &mut packet.live_resources[0];
        let id = witness.fixture_identity().unwrap();
        witness.fixture_file_mut().write_all(b"owned fixture").unwrap();
        witness.fixture_file_mut().sync_all().unwrap();
        let view = crate::windows_coordinator::windows_installation::fixture_writable_mapping(witness.fixture_file_mut()).unwrap();
        let (events, receiver) = mpsc::channel();
        let lifetime = Arc::new(GuiLifetime::default());
        let mut ctx = Ctx { received_command_results: Mutex::new(Vec::new()), events, wake: Arc::new(Mutex::new(Box::new(|| {}))), settings: Settings::default(),
            wsl: crate::wsl_controller::WslController::default(), native_apply_pending: Arc::new(AtomicBool::new(false)),
            native_cancel: Arc::new(AtomicBool::new(false)), background_receivings: Vec::new(), background_finish_reported: false,
            lifetime: lifetime.clone(), vpn_job: None, vpn_unsettled: false, startup: Startup::Held("synthetic fixture".into()),
            proxy_var_carried: None, proxy_var_retryable: false, patched_seen: HashMap::new(), vpn: None,
            relay_egress: None, last: None, dns_probe: initial_dns_probe(), carrier_set_proxy: false };
        assert!(ctx.retain_background_receiving(packet).is_err());
        assert_eq!(ctx.background_receivings[0].live_resources.len(), 1);
        let native_hold = ctx.background_receivings[0].effects.iter().find_map(|event| match event {
            background::BackgroundEffect::ResourceFinishHeld { cause } => Some(cause.clone()),
            _ => None,
        }).expect("actual mapped disposition hold received");
        assert!(native_hold.contains("os error 5"), "unexpected native hold: {native_hold}");
        eprintln!("actual mapped disposition hold: {native_hold}");
        assert!(!finish_shutdown(&mut ctx, &lifetime));
        assert!(!lifetime.shutdown_ready.load(Ordering::SeqCst));
        let held_events = ctx.background_receivings[0].effects.len();
        view.close().unwrap();
        // Polling alone must not retry even after the underlying condition is
        // fixed. Only a fresh real Stop/Shutdown command opens another attempt.
        for _ in 0..2 {
            receive_shutdown_request(&mut ctx, &None);
            assert!(!finish_shutdown(&mut ctx, &lifetime));
            assert_eq!(ctx.background_receivings[0].effects.len(), held_events);
        }
        receive_shutdown_request(&mut ctx, &Some(Cmd::Shutdown));
        assert!(finish_shutdown(&mut ctx, &lifetime));
        assert!(ctx.background_receivings[0].live_resources.is_empty());
        eprintln!("owned Core fixture root={}, actualId={id:?}, same packet received handle disposition after owned view release", root.display());
        assert!(lifetime.shutdown_ready.load(Ordering::SeqCst));
        assert!(receiver.try_iter().any(|event| matches!(event, Event::ShutdownReady)));
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit owned private fixture parent; real partial stage and mapped disposition"]
    fn partial_stage_disposition_retries_only_on_fresh_shutdown_request() {
        use crate::windows_coordinator::windows_installation as owner;
        let parent = PathBuf::from(std::env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT").expect("explicit qualified parent"));
        let root = owner::context_fixture_directory(&parent).unwrap();
        let foreign_path = root.join("independent.bin");
        owner::write_deployment_data(&foreign_path, b"independent fixture bytes").unwrap();
        let foreign_pin = owner::CheckedPath::open(&foreign_path, owner::PathKind::File, owner::PathPurpose::Review).unwrap();
        let foreign_id = foreign_pin.native_id();
        let foreign_security = foreign_pin.security_digest().unwrap();
        let mut packet = background::test_partial_stage_packet(root.clone());
        let original_error = packet.result.as_ref().unwrap_err().clone();
        let canonical = root.join("fixture-gate.json");
        let canonical_pin = owner::CheckedPath::open(&canonical, owner::PathKind::File, owner::PathPurpose::Review).unwrap();
        let canonical_id = canonical_pin.native_id();
        let canonical_security = canonical_pin.security_digest().unwrap();
        let witness = packet.live_resources.iter_mut().find(|witness| witness.fixture_is_partial_noeffect_stage())
            .expect("actual partial stage with received no-effect duty");
        let stage_id = witness.fixture_identity().unwrap();
        let view = owner::fixture_writable_mapping(witness.fixture_file_mut()).unwrap();
        let (shared, events) = probe_test_ctx();
        let mut ctx = shared.lock().unwrap();
        ctx.startup = Startup::Held("synthetic fixture".into());
        let lifetime = ctx.lifetime.clone();
        assert_eq!(ctx.retain_background_receiving(packet).unwrap_err(), original_error);
        let held = ctx.background_receivings[0].effects.iter().find_map(|event| match event {
            background::BackgroundEffect::ResourceFinishHeld { cause } => Some(cause.clone()), _ => None,
        }).expect("actual mapped disposition failure retained");
        assert!(held.contains("os error 5"), "unexpected native hold: {held}");
        assert!(!finish_shutdown(&mut ctx, &lifetime));
        let event_count = ctx.background_receivings[0].effects.len();
        view.close().unwrap();
        for _ in 0..2 {
            receive_shutdown_request(&mut ctx, &None);
            assert!(!finish_shutdown(&mut ctx, &lifetime));
            assert_eq!(ctx.background_receivings[0].effects.len(), event_count);
        }
        receive_shutdown_request(&mut ctx, &Some(Cmd::Shutdown));
        assert!(finish_shutdown(&mut ctx, &lifetime));
        assert!(ctx.background_receivings[0].live_resources.is_empty());
        assert_eq!(ctx.background_receivings[0].result.as_ref().unwrap_err(), &original_error);
        assert_eq!(std::fs::read(&canonical).unwrap(), b"original fixture bytes");
        assert_eq!(owner::CheckedPath::open(&canonical, owner::PathKind::File, owner::PathPurpose::Review).unwrap().native_id(), canonical_id);
        assert_eq!(canonical_pin.security_digest().unwrap(), canonical_security);
        assert_eq!(std::fs::read(&foreign_path).unwrap(), b"independent fixture bytes");
        assert_eq!(owner::CheckedPath::open(&foreign_path, owner::PathKind::File, owner::PathPurpose::Review).unwrap().native_id(), foreign_id);
        assert_eq!(foreign_pin.security_digest().unwrap(), foreign_security);
        assert!(events.try_iter().any(|event| matches!(event, Event::ShutdownReady)));
        eprintln!("owned partial-stage Core fixture root={}, stageId={stage_id:?}, first disposition={held}; original failure retained", root.display());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "explicit owned private fixture parent; complete stage and real mapped disposition"]
    fn complete_stage_disposition_retries_only_on_fresh_shutdown_request() {
        use crate::windows_coordinator::windows_installation as owner;
        let parent = PathBuf::from(std::env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT").expect("explicit qualified parent"));
        let root = owner::context_fixture_directory(&parent).unwrap();
        let mut packet = background::test_complete_stage_packet(root.clone());
        let original_error = packet.result.as_ref().unwrap_err().clone();
        let foreign_path = root.join("fixture-gate.json");
        let foreign_pin = owner::CheckedPath::open(&foreign_path, owner::PathKind::File, owner::PathPurpose::Review).unwrap();
        let foreign_id = foreign_pin.native_id();
        let foreign_security = foreign_pin.security_digest().unwrap();
        let foreign_bytes = foreign_pin.read_snapshot().unwrap();
        let witness = packet.live_resources.iter_mut().find(|witness| witness.fixture_is_complete_noeffect_stage())
            .expect("actual complete stage with received no-effect duty");
        let stage_id = witness.fixture_identity().unwrap();
        let view = owner::fixture_writable_mapping(witness.fixture_file_mut()).unwrap();
        let (shared, events) = probe_test_ctx();
        let mut ctx = shared.lock().unwrap();
        ctx.startup = Startup::Held("synthetic fixture".into());
        let lifetime = ctx.lifetime.clone();
        assert_eq!(ctx.retain_background_receiving(packet).unwrap_err(), original_error);
        let held = ctx.background_receivings[0].effects.iter().find_map(|event| match event {
            background::BackgroundEffect::ResourceFinishHeld { cause } => Some(cause.clone()), _ => None,
        }).expect("actual mapped disposition failure retained");
        assert!(held.contains("os error 5"), "unexpected native hold: {held}");
        assert!(!finish_shutdown(&mut ctx, &lifetime));
        let event_count = ctx.background_receivings[0].effects.len();
        view.close().unwrap();
        for _ in 0..2 {
            receive_shutdown_request(&mut ctx, &None);
            assert!(!finish_shutdown(&mut ctx, &lifetime));
            assert_eq!(ctx.background_receivings[0].effects.len(), event_count);
        }
        receive_shutdown_request(&mut ctx, &Some(Cmd::Shutdown));
        assert!(finish_shutdown(&mut ctx, &lifetime));
        assert!(ctx.background_receivings[0].live_resources.is_empty());
        assert_eq!(ctx.background_receivings[0].result.as_ref().unwrap_err(), &original_error);
        foreign_pin.recheck().unwrap();
        assert_eq!(foreign_pin.native_id(), foreign_id);
        assert_eq!(foreign_pin.security_digest().unwrap(), foreign_security);
        assert_eq!(foreign_pin.read_snapshot().unwrap(), foreign_bytes);
        assert!(events.try_iter().any(|event| matches!(event, Event::ShutdownReady)));
        eprintln!("owned complete-stage Core fixture root={}, stageId={stage_id:?}, first disposition={held}; foreign and original failure retained", root.display());
    }

    #[cfg(windows)]
    #[test]
    fn unknown_background_observation_does_not_reuse_stale_boolean_claims() {
        for prior in [false, true] {
            let mut status = blank_status();
            status.relay_running = prior;
            status.relay_outdated = prior;
            status.rules = prior;
            let unknown = apply_windows_observation(status, &Err(String::new()), &Settings::default(), None);
            assert_eq!(unknown.background_observation_error.as_deref(), Some(""));
            assert_eq!((unknown.relay_running, unknown.relay_outdated, unknown.rules), (prior, false, prior));
            let facts = crate::gui::status::Facts::read(&unknown, &crate::gate::View::default(), Duration::ZERO);
            let headline = crate::gui::status::headline(&facts);
            assert_eq!(headline.tone, crate::gui::status::Tone::Wait);
            assert_eq!(headline.action, Some(crate::gui::status::Action::Repair));
            let text = crate::gui::report::test_status_part(&unknown);
            assert!(text.contains("Служба и правила DNS: состояние не проверено"));
            assert!(!text.contains("Служба: запущена") && !text.contains("Служба: НЕ запущена"));
        }
        let mut prior = blank_status();
        prior.background_observation_error = Some("old".into());
        let complete = WindowsSystemObservation { rules: Ok((false, false)), transport: None, transport_error: None, selected_delivery: Ok(false), background: Ok(background::BackgroundObservation {
            relay: background::RoleObservation::Absent, watchdog: background::RoleObservation::Absent,
            selected_delivery_required: Some(false), proxy_ready: Some(Ok(false)), dns_ready: Some(Ok(false)),
        })};
        let known = apply_windows_observation(prior, &Ok(complete), &Settings::default(), None);
        assert!(known.background_observation_error.is_none());
        let incomplete = WindowsSystemObservation { rules: Ok((false, false)), transport: None, transport_error: None, selected_delivery: Err("source unavailable".into()), background: Ok(background::BackgroundObservation {
            relay: background::RoleObservation::Absent, watchdog: background::RoleObservation::Absent,
            selected_delivery_required: None, proxy_ready: Some(Ok(false)), dns_ready: Some(Ok(false)),
        })};
        let unknown = apply_windows_observation(known, &Ok(incomplete), &Settings::default(), None);
        assert!(unknown.background_observation_error.is_none());
        assert!(unknown.selected_delivery.is_err());
        let mut unrelated = blank_status();
        unrelated.dns = State::Blocked("другое известное ограничение".into());
        let text = crate::gui::report::test_status_part(&unrelated);
        assert!(text.contains("Служба: НЕ запущена"));
        assert!(!text.contains("Служба и правила DNS: состояние не проверено"));
    }

    #[cfg(windows)]
    #[test]
    fn legacy_readiness_keeps_validated_roles_and_channels_independent() {
        let mut settings = Settings::default();
        settings.dns = true;
        settings.local_proxy = true;
        let cases = [
            (Some(Err("резолвер не ответил".into())), Some(Ok(true)),
             State::Blocked("DNS: резолвер не ответил".into()), State::On,
             Some("DNS: резолвер не ответил")),
            (Some(Ok(true)), Some(Err("listener identity changed".into())),
             State::On, State::Blocked("Локальный прокси: listener identity changed".into()),
             Some("TCP: listener identity changed")),
            (None, Some(Ok(false)), State::Blocked("Состояние DNS ещё не подтверждено".into()),
             State::Partial("локальный прокси ещё не подтверждён".into()), None),
            (Some(Ok(false)), None, State::Partial("правила стоят, служба не запущена".into()),
             State::Blocked("Локальный прокси ещё не подтверждён".into()), None),
        ];
        for (dns_ready, proxy_ready, dns, proxy, failure) in cases {
            let packet = Ok(WindowsSystemObservation {
                rules: Ok((true, true)), transport: None, transport_error: None,
                selected_delivery: Ok(false), background: Ok(background::BackgroundObservation {
                    relay: background::RoleObservation::Running, watchdog: background::RoleObservation::Running,
                    selected_delivery_required: None, proxy_ready, dns_ready,
                }),
            });
            let mut prior = blank_status();
            prior.local_proxy = State::On;
            assert_eq!(observation_failure(&packet).as_deref(), failure);
            let status = apply_windows_observation(prior, &packet, &settings, None);
            assert_eq!(status.watchdog, State::On);
            assert!(status.relay_running && status.rules);
            assert_eq!(status.rules_observed, Some(true));
            assert!(status.background_observation_error.is_none());
            assert_eq!(status.dns, dns);
            assert_eq!(status.local_proxy, proxy);
        }
    }

    #[cfg(windows)]
    #[test]
    fn source_failure_and_native_failure_remain_independent_in_status() {
        let source = r"R:\private\package.exe: directory case mode: os error 87";
        let packet = WindowsSystemObservation {
            rules: Ok((true, true)), transport: None, transport_error: None,
            selected_delivery: Err(source.into()),
            background: Ok(background::BackgroundObservation {
                relay: background::RoleObservation::Running, watchdog: background::RoleObservation::Running,
                selected_delivery_required: None, proxy_ready: Some(Ok(true)), dns_ready: Some(Ok(true)),
            }),
        };
        let mut previous = blank_status();
        previous.client_patch = State::On;
        previous.relay_outdated = true;
        let status = apply_windows_observation(previous, &Ok(packet), &Settings::default(), None);
        assert_eq!(status.selected_delivery.as_ref().err().map(String::as_str), Some(source));
        assert!(status.background_observation_error.is_none());
        assert!(status.relay_running && !status.relay_outdated);
        assert_eq!(status.watchdog, State::On);
        let facts = crate::gui::status::Facts::read(&status, &crate::gate::View::default(), Duration::ZERO);
        let headline = crate::gui::status::headline(&facts);
        assert!(headline.detail.contains("os error 87"));
        assert_ne!(headline.action, Some(crate::gui::status::Action::Repair));
        let report = crate::gui::report::test_status_part(&status);
        assert!(report.contains("os error 87") && report.contains("Служба: запущена"));
        assert!(!report.contains(r"R:\private\package.exe") && !headline.detail.contains(r"R:\private\package.exe"));
        let packet = WindowsSystemObservation {
            rules: Ok((false, false)), transport: None, transport_error: None,
            selected_delivery: Err(source.into()), background: Err("open process: os error 5".into()),
        };
        let packet = Ok(packet);
        let causes = observation_failure(&packet).unwrap();
        assert!(causes.contains("os error 87") && causes.contains("os error 5"));
        let status = apply_windows_observation(status, &packet, &Settings::default(), None);
        assert_eq!(status.selected_delivery.as_ref().err().map(String::as_str), Some(source));
        assert!(status.background_observation_error.as_deref().unwrap().contains("os error 5"));
        let blocked = State::Blocked("Состояние службы не проверено: open process: os error 5".into());
        assert_eq!(status.watchdog, blocked);
        assert_eq!(status.dns, blocked);
        assert_eq!(status.local_proxy, blocked);
        assert!(!status.relay_outdated);
        let report = crate::gui::report::test_status_part(&status);
        assert!(report.contains("os error 5") && report.contains("os error 87"));
        assert!(report.contains("собственные правила DNS: НЕТ"));
    }

    #[cfg(windows)]
    #[test]
    fn source_failure_survives_initial_sync_and_invalidation_receivers() {
        let source = "directory case mode: os error 87";
        let (shared, _) = probe_test_ctx();
        let mut ctx = shared.lock().unwrap();
        ctx.lifetime = Arc::new(GuiLifetime::with_image(Err(source.into())));
        let initial = settings_only_status(&ctx, blank_status());
        assert_eq!(initial.selected_delivery.as_ref().err().map(String::as_str), Some(source));
        let mut observation = probe_test_observation(true);
        observation.selected_delivery = Err(source.into());
        receive_system_observation(&mut ctx, Ok(observation));
        let received = settings_only_status(&ctx, blank_status());
        assert_eq!(received.selected_delivery.as_ref().err().map(String::as_str), Some(source));
        let (back, _notifications) = mpsc::channel();
        start_readonly_probe_with(&mut ctx, back, None, |_| {
            let mut packet = probe_test_observation(true);
            packet.selected_delivery = Err("directory case mode: os error 87".into());
            packet.background = Err("open process: os error 5".into());
            ProbeCompletion { vpn: VpnSeen::Unmeasured, relay_egress: None, observation: Ok(packet) }
        });
        drop(ctx);
        while !shared.lock().unwrap().vpn_job.as_ref().unwrap().handle.is_finished() { std::thread::yield_now(); }
        let mut ctx = shared.lock().unwrap();
        receive_probe_completion(&mut ctx);
        let packet = ctx.dns_probe.as_ref().unwrap();
        assert!(packet.background.as_ref().err().unwrap().contains("os error 5"));
        assert_eq!(packet.selected_delivery.as_ref().err().map(String::as_str), Some(source));
        invalidate_background_observation(&mut ctx);
        let invalidated = settings_only_status(&ctx, received);
        assert_eq!(invalidated.selected_delivery.as_ref().err().map(String::as_str), Some(source));
        assert!(!invalidated.relay_outdated);
    }

    #[cfg(windows)]
    #[test]
    fn system_tcp_status_keeps_dns_observation_separate_from_tcp() {
        let mut settings = Settings::default();
        settings.select_system_tcp().unwrap();
        let expected = settings.transport_requirements().unwrap().active_config;
        let observed = WindowsSystemObservation {
            rules: Err("synthetic NRPT observation failure".into()),
            transport_error: None,
            selected_delivery: Ok(false), background: Ok(background::BackgroundObservation {
                relay: background::RoleObservation::Running, watchdog: background::RoleObservation::Running,
                selected_delivery_required: Some(false), proxy_ready: None, dns_ready: None,
            }),
            transport: Some((expected,
                background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled),
                background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready),
                background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled), Some(12345))),
        };
        let mut prior = blank_status();
        prior.local_proxy = State::On;
        let status = apply_windows_observation(prior, &Ok(observed), &settings, None);
        assert!(matches!(status.dns, State::Blocked(_)));
        assert_eq!(status.local_proxy, State::On);
        assert_eq!(status.transport_ready, Some(true));
        assert!(status.background_observation_error.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn unknown_transport_preserves_independently_observed_watchdog() {
        let observed = WindowsSystemObservation {
            rules: Ok((false, false)), transport: None, transport_error: Some("режим неизвестен".into()),
            selected_delivery: Ok(false), background: Ok(background::BackgroundObservation {
                relay: background::RoleObservation::Absent, watchdog: background::RoleObservation::Running,
                selected_delivery_required: Some(false), proxy_ready: None, dns_ready: None,
            }),
        };
        let status = apply_windows_observation(blank_status(), &Ok(observed), &Settings::default(), None);
        assert_eq!(status.watchdog, State::On);
        assert!(matches!(status.local_proxy, State::Blocked(_)));
        assert!(status.background_observation_error.is_none());
        assert!(matches!(observed_watchdog_state(background::RoleObservation::Registered), State::Partial(_)));
    }

    #[cfg(windows)]
    #[test]
    fn system_tcp_does_not_promote_tcp_when_dns_disable_is_unknown() {
        let mut settings = Settings::default();
        settings.select_system_tcp().unwrap();
        let expected = settings.transport_requirements().unwrap().active_config;
        let observed = WindowsSystemObservation {
            rules: Ok((false, false)), transport_error: None,
            selected_delivery: Ok(false), background: Ok(background::BackgroundObservation {
                relay: background::RoleObservation::Running, watchdog: background::RoleObservation::Running,
                selected_delivery_required: Some(false), proxy_ready: None, dns_ready: None,
            }),
            transport: Some((expected, background::TransportChannelObservation::Unknown("unreceived DNS disable".into()),
                background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready),
                background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled), Some(12345))),
        };
        let mut prior = blank_status();
        prior.local_proxy = State::On;
        let mut status = apply_windows_observation(prior, &Ok(observed), &settings, None);
        status.transport_view = TransportView::SystemTcp;
        assert!(status.transport_ready.is_none());
        assert!(!status.bypass_on());
    }

    #[cfg(windows)]
    #[test]
    fn system_tcp_does_not_promote_ready_without_received_port() {
        let mut settings = Settings::default();
        settings.select_system_tcp().unwrap();
        let expected = settings.transport_requirements().unwrap().active_config;
        let observed = WindowsSystemObservation {
            rules: Ok((false, false)), transport_error: None,
            selected_delivery: Ok(false), background: Ok(background::BackgroundObservation {
                relay: background::RoleObservation::Running, watchdog: background::RoleObservation::Running,
                selected_delivery_required: Some(false), proxy_ready: None, dns_ready: None,
            }),
            transport: Some((expected,
                background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled),
                background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready),
                background::TransportChannelObservation::Received(crate::gate::CapabilityObservation::Disabled), None)),
        };
        let mut status = apply_windows_observation(blank_status(), &Ok(observed), &settings, None);
        status.transport_view = TransportView::SystemTcp;
        status.local_proxy = State::On;
        assert!(!status.bypass_on());
    }

    #[cfg(windows)]
    #[test]
    fn system_tcp_preserves_optional_wishes_but_does_not_use_them_for_carrier() {
        let mut settings = Settings::default();
        settings.set_transport_choice(TransportChoice::BuiltinExits(true)).unwrap();
        settings.set_transport_choice(TransportChoice::GroupProxy(true)).unwrap();
        settings.set_transport_choice(TransportChoice::OwnProxyEnabled(true)).unwrap();
        let before_watchdog = settings.auto_patch_wanted();
        settings.select_system_tcp().unwrap();
        assert!(!settings.dns && settings.local_proxy);
        assert!(settings.builtin_exits && settings.group_proxy && settings.own_proxy_enabled);
        let effects = settings.checked_transport_effects().unwrap();
        assert!(matches!(effects.own_proxy_enabled, crate::settings::TransportWish::Inactive));
        assert!(matches!(effects.group_proxy, crate::settings::TransportWish::Inactive));
        assert!(matches!(effects.builtin_exits, crate::settings::TransportWish::Inactive));
        assert_eq!(settings.auto_patch_wanted(), before_watchdog);
        assert_eq!(specified_wish(&settings.checked_transport_effects().unwrap().carrier), Some(true));
        settings.set_transport_choice(TransportChoice::LocalProxy(false)).unwrap();
        assert_eq!(specified_wish(&settings.checked_transport_effects().unwrap().carrier), Some(false));
        assert!(settings.set_transport_choice(TransportChoice::Dns(true)).is_err());
        let mut status = blank_status();
        status.transport_view = TransportView::SystemTcp;
        status.builtin_exits = State::On;
        status.group_proxy = State::On;
        status.own_proxy = State::On;
        assert!(!status.bypass_on());
        status.local_proxy = State::On;
        status.rules_observed = Some(false);
        status.transport_ready = Some(true);
        assert!(status.bypass_on());
    }

    #[cfg(windows)]
    #[test]
    fn configured_profile_requires_all_five_explicit_choices() {
        let mut choices = crate::settings::TransportChoices::default();
        assert!(configured_values(choices).is_err());
        choices.dns = Some(false); choices.local_proxy = Some(false);
        choices.builtin_exits = Some(false); choices.group_proxy = Some(false);
        assert!(configured_values(choices).is_err());
        choices.own_proxy_enabled = Some(false);
        assert_eq!(configured_values(choices).unwrap(), (false, false, false, false, false));
    }

    /// The regression the `Unmeasured` variant exists for: a tunnel is up and
    /// the client has not dialled out, which is what a window opened before
    /// Antigravity almost always sees. Reading that as "the client is outside
    /// the tunnel" is the indicator claiming a measurement nobody took.
    #[test]
    fn a_tunnel_with_nothing_to_read_is_not_a_client_outside_it() {
        use crate::egress::ClientEgress;
        let seen = |client| match client {
            ClientEgress::Tunnel => VpnSeen::CarryingClient,
            ClientEgress::Mixed => VpnSeen::PartlyCarryingClient,
            ClientEgress::Physical => VpnSeen::NotCarryingClient,
            ClientEgress::ViaLocalProxy => VpnSeen::ViaLocalProxy,
            ClientEgress::Unknown => VpnSeen::Unmeasured,
        };
        assert_eq!(seen(ClientEgress::Unknown), VpnSeen::Unmeasured);
        assert_ne!(seen(ClientEgress::Unknown), VpnSeen::NotCarryingClient);
        // The state the proxy route puts a patched client in: measured, and not
        // the same answer as "nothing to read".
        assert_eq!(seen(ClientEgress::ViaLocalProxy), VpnSeen::ViaLocalProxy);
        assert_ne!(seen(ClientEgress::ViaLocalProxy), VpnSeen::Unmeasured);
        // And an unmeasured tunnel must not block the DNS row: it takes evidence
        // to stand down, not the absence of it (S37).
        if Cap::Dns.supported() { assert_eq!(
            dns_state(true, true, true, Some(VpnSeen::Unmeasured), true, true),
            State::On
        );
        // A client in a tunnel no longer blocks the row either (D25).
        assert_eq!(
            dns_state(true, true, true, Some(VpnSeen::CarryingClient), true, true),
            State::On
        ); } else {
            assert!(matches!(dns_state(true, true, true, Some(VpnSeen::CarryingClient), true, true), State::Blocked(_)));
        }
    }
}
