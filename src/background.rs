// Keeping the DNS relay alive across reboots.
//
// The Windows implementation is a logon-triggered scheduled task; the Linux
// implementation is, for now, a set of honest stubs - the DNS/relay layer is the
// last part of the port (kb/patch.md), and until it lands the binary/JS patch is
// what lifts the gate on a permitted exit (kb/rivals.md Fact 2). The stubs report
// "not running / nothing to do" so menu 1's DNS branch is simply skipped rather
// than half-run.

/// Hidden flag that turns the unlocker into the relay. Handled before any UI.
pub const FORWARDER_FLAG: &str = "--dns-forwarder";
/// Hidden flag that runs ONLY the update watchdog - no relay, no DNS, no network.
/// Handled before any UI, same as the relay flag.
pub const WATCHDOG_FLAG: &str = "--watchdog";
/// Hidden flag that runs ONLY the local CONNECT proxy (`proxy::run`) - the Linux
/// phase-2 region route. No DNS listener, so no systemd-resolved conflict.
pub const PROXY_FLAG: &str = "--proxy";

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(target_os = "macos")]
pub use macos_impl::*;

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub use unix_impl::*;

#[cfg(target_os = "windows")]
mod windows_impl {
    mod task_scheduler { include!("background/task_scheduler.rs"); }
    mod prior_transition { include!("background/prior_transition.rs"); }
    pub(crate) use prior_transition::VendorForegroundOwner;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    use crate::dns_forwarder;
    use crate::windows_coordinator::{self, process_identity::ProcessIdentity};
    use crate::windows_coordinator::windows_installation::{self, CheckedPath, PathKind, PathPurpose};
    use super::{FORWARDER_FLAG, WATCHDOG_FLAG};
    use crate::utils::{bounded_output, no_window, CommandOutcome, CommandObservation, PreparedExec};
    fn receive_command(outcome: &CommandOutcome, observation: CommandObservation) -> Result<(), String> {
        match observation {
            CommandObservation::Complete if outcome.complete() && outcome.releasable() && outcome.exit().is_some_and(|status| status.success()) => Ok(()),
            CommandObservation::NotStarted => Err("background helper did not start; actual failure retained".into()),
            CommandObservation::Complete => Err("background helper failed or status is unknown".into()),
            CommandObservation::Deadline => Err("background helper deadline expired; outcome retained".into()),
            CommandObservation::Failed => Err("background helper failed; outcome retained".into()),
            CommandObservation::Pending => Err("background helper remains pending".into()),
        }
    }
    #[cfg(test)]
    use crate::utils::powershell;

    // A scheduled task rather than a real service: a Windows service has to
    // implement StartServiceCtrlDispatcher and a control handler or the SCM kills
    // the process after ~30 seconds, which is a protocol to maintain for exactly
    // the same result. A logon-triggered task is a plain background process, and
    // enable/disable is one cmdlet each.
    //
    // Registered through the ScheduledTasks cmdlets, not schtasks.exe: the
    // defaults of the latter are wrong here in two ways that only surface on a
    // laptop weeks later - a task is stopped when the machine goes on battery, and
    // it is killed after a 72-hour execution limit. Both are switched off below.
    //
    // It also restarts on failure. The relay is compiled with `panic = "abort"`,
    // so any thread that goes down takes the whole process with it - and with it
    // the DNS the routed names depend on, until the next logon. A restart policy
    // is the only backstop available for that, since the panic cannot be caught.

    const TASK_NAME: &str = "AG Unlocker DNS";
    /// The watchdog's own logon task, separate from the relay's. Decoupling the
    /// re-patch survival from the relay is what lets it keep working when the relay
    /// is stopped (menu 4), has died, or was never installed (a future patch-only
    /// machine) - the case G9 describes today, where no relay means no watchdog.
    const WATCHDOG_TASK_NAME: &str = "AG Unlocker Watchdog";

    /// ProgramData, **not** LOCALAPPDATA. Measured on a real machine: a scheduled
    /// task launching anything out of `%LOCALAPPDATA%` fails with 0x80070002, and a
    /// stock `ping.exe` copied there fails identically - it is an anti-persistence
    /// heuristic (a task autostarting an exe from AppData is the classic malware
    /// shape), not something about our binary. The same probe from ProgramData and
    /// Program Files starts cleanly.
    pub fn install_dir() -> Result<PathBuf, String> {
        Ok(windows_installation::background_locations()?.managed_directory().to_path_buf())
    }

    pub fn installed_exe() -> Result<PathBuf, String> {
        Ok(windows_installation::background_locations()?.managed_program().to_path_buf())
    }
    pub(crate) fn relay_process_name() -> String {
        // The native owner supplies one static UTF-8 filename. Both existing
        // consumers require its stem: Get-Process uses it directly, while the
        // tasklist caller appends exactly one executable extension.
        Path::new(windows_installation::background_process_name())
            .file_stem().and_then(|stem| stem.to_str())
            .expect("canonical native background filename must have a UTF-8 stem")
            .to_owned()
    }

    /// Limit for the small status helpers here. Short, because
    /// they answer in milliseconds when they answer at all - and this runs on the
    /// path a user is watching.
    const HELPER_LIMIT: Duration = Duration::from_secs(15);

    /// Whether the scheduled task exists, asked of `schtasks.exe` rather than of
    /// PowerShell.
    ///
    /// Same question, same answer, roughly a tenth of the wall clock: starting
    /// PowerShell costs several hundred milliseconds before it reads the first
    /// character of the script, and this is asked twice on every status refresh —
    /// which is a large part of why flipping a switch took seconds. `schtasks` is
    /// a plain Win32 binary shipped with every Windows since XP; it exits 0 when
    /// the task is there and non-zero when it is not, and the task is registered
    /// in the root folder, so the bare name is the whole query.
    fn task_exists(owner: &mut CommandOutcome, task_name: &str) -> Result<bool, String> {
        // The task's own file first: no process to spawn, so no timeout to
        // misread. A `schtasks` that did not answer in time once read as "no
        // task", and `ensure_installed` then killed a working relay to copy a
        // file and never started it again (field report, 2.19.1).
        let tasks = PathBuf::from(env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("Tasks");
        if tasks.join(task_name).exists() {
            return Ok(true);
        }
        let cmd = PreparedExec::system(Path::new("schtasks.exe"))?.args(["/Query", "/TN", task_name]);
        let receipt = bounded_output(owner, cmd, HELPER_LIMIT);
        receive_command(owner, receipt)?;
        drop(std::mem::take(owner));
        Ok(true)
    }

    /// Uncached scheduler evidence used before privileged mutations.
    pub(crate) struct TaskState {
        pub(crate) relay_enabled: bool,
        pub(crate) watchdog_enabled: bool,
    }
    #[derive(Clone, Copy, Debug, serde::Serialize)]
    pub(crate) struct BackgroundDesired {
        pub(crate) relay: bool,
        pub(crate) watchdog: bool,
    }
    /// None preserves the independently received native role state.
    #[derive(Clone, Copy, Debug, serde::Serialize)]
    pub(crate) struct BackgroundChanges {
        pub(crate) relay: Option<bool>,
        pub(crate) watchdog: Option<bool>,
    }
    impl From<BackgroundDesired> for BackgroundChanges {
        fn from(value: BackgroundDesired) -> Self {
            Self { relay: Some(value.relay), watchdog: Some(value.watchdog) }
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum ImageDemand { KeepCompatible, DeliverSelectedImage }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum RoleObservation { Absent, Registered, Running }

    #[derive(Debug)]
    pub(crate) struct BackgroundObservation {
        pub(crate) relay: RoleObservation,
        pub(crate) watchdog: RoleObservation,
        pub(crate) selected_delivery_required: Option<bool>,
        // None means the caller did not request a probe. An error belongs to
        // that listener; the scheduler roles are qualified separately.
        pub(crate) proxy_ready: Option<Result<bool, String>>,
        pub(crate) dns_ready: Option<Result<bool, String>>,
    }

    /// A channel result is usable for mode receiving only after the report,
    /// selected task instance and held listener process have been associated.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub(crate) enum TransportChannelObservation {
        Unknown(String),
        Received(crate::gate::CapabilityObservation),
    }

    #[derive(Debug)]
    pub(crate) struct TransportBackgroundObservation {
        pub(crate) background: BackgroundObservation,
        pub(crate) expected: crate::settings::ActiveTransportConfig,
        pub(crate) dns: TransportChannelObservation,
        pub(crate) tcp_proxy: TransportChannelObservation,
        pub(crate) dns_alias: TransportChannelObservation,
        pub(crate) tcp_proxy_port: Option<u16>,
        pub(crate) instance: Option<crate::gate::TransportInstance>,
    }

    struct BoundTransportObservation {
        configuration_matches: bool,
        channels: [TransportChannelObservation; 3],
        tcp_proxy_port: Option<u16>,
        instance: Option<crate::gate::TransportInstance>,
    }

    fn unknown_transport_channels(reason: &str) -> [TransportChannelObservation; 3] {
        [TransportChannelObservation::Unknown(reason.into()), TransportChannelObservation::Unknown(reason.into()),
         TransportChannelObservation::Unknown(reason.into())]
    }

    #[derive(serde::Serialize, Debug)]
    pub(crate) enum BackgroundEffect {
        CompatibleNoop,
        DirectoryCreateRequested,
        DirectoryCreateReturnedSuccess,
        ProgramCreateRequested,
        ProgramCreateReturnedSuccess,
        ProgramReadbackReceived { program: PathBuf, program_native_id: windows_installation::NativeObjectId,
            source_native_id: windows_installation::NativeObjectId, sha256: String, generation: u32 },
        CurrentProgramReceived { program_native_id: windows_installation::NativeObjectId, sha256: String },
        StoppedDeliveryInputsReceived { program_native_id: windows_installation::NativeObjectId, program_sha256: String,
            source_native_id: windows_installation::NativeObjectId, source_sha256: String },
        PriorDeliveryAuthenticated { provenance: serde_json::Value },
        SelectedDeliveryOriginalReceived { program_native_id: windows_installation::NativeObjectId, sha256: String },
        SelectedDeliveryRestorationImageReceived { program_native_id: windows_installation::NativeObjectId, replacement: bool },
        TaskInstancesRetired(Vec<String>),
        TransportModeUnreceived { cause: String },
        TransportObserved { dns: TransportChannelObservation, tcp_proxy: TransportChannelObservation,
            dns_alias: TransportChannelObservation },
        GenerationObserved { metadata: Result<Option<u32>, String>, runtime: Option<u32> },
        GenerationWriteRequested,
        ResourceFinished { evidence: serde_json::Value },
        ResourceFinishHeld { cause: String },
    }
    #[derive(serde::Serialize, Debug)]
    pub(crate) struct BackgroundNativeReceiving {
        pub(crate) role: String,
        pub(crate) started: bool,
        pub(crate) exit_observed: bool,
        pub(crate) exit_code: Option<i32>,
        pub(crate) stdout: Vec<u8>,
        pub(crate) stderr: Vec<u8>,
        pub(crate) errors: Vec<String>,
        pub(crate) stdout_file: Option<DiagnosticFileRef>,
        pub(crate) stderr_file: Option<DiagnosticFileRef>,
    }
    /// Returned to the existing operation worker on every path. The worker
    /// persists actual progress/partial native outcomes before interpretation;
    /// no mutable global last-result or fabricated completion frame is used.
    #[derive(serde::Serialize, Debug)]
    pub(crate) struct BackgroundReceiving {
        pub(crate) operation: &'static str,
        pub(crate) result: Result<(), String>,
        pub(crate) effects: Vec<BackgroundEffect>,
        pub(crate) native: Vec<BackgroundNativeReceiving>,
        pub(crate) replacements: Vec<serde_json::Value>,
        pub(crate) generation_writes: Vec<serde_json::Value>,
        pub(crate) generation_reads: Vec<serde_json::Value>,
        pub(crate) diagnostic_journal: Option<DiagnosticFileRef>,
        pub(crate) diagnostic: Option<DiagnosticFileRef>,
        pub(crate) persistence_errors: Vec<String>,
        pub(crate) cancellation_received: bool,
        pub(crate) restoration_pending: bool,
        pub(crate) primary_result: Option<serde_json::Value>,
        pub(crate) restoration_result: Option<Result<(), String>>,
        pub(crate) task_events: Vec<task_scheduler::Event>,
        #[serde(skip)]
        pub(crate) live_resources: Vec<windows_installation::AcquiredCreation>,
        #[serde(skip)]
        pending_metadata: Vec<windows_installation::PendingUserMetadataPublication>,
        #[serde(skip)]
        pending_unwind: Option<DeferredUnwind>,
        #[serde(skip)]
        secondary_unwinds: Vec<DeferredUnwind>,
    }
    struct DeferredUnwind(Box<dyn std::any::Any + Send>);
    impl std::fmt::Debug for DeferredUnwind {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("DeferredUnwind") }
    }
    impl BackgroundReceiving {
        fn receive_metadata_failure(&mut self, failure: &mut windows_installation::MetadataFailure) {
            self.live_resources.append(&mut failure.live);
            if let Some(pending) = failure.pending.take() { self.pending_metadata.push(pending); }
            if let Some(unwind) = failure.unwind.take() {
                if self.pending_unwind.is_none() { self.pending_unwind = Some(DeferredUnwind(unwind.0)); }
                else { self.secondary_unwinds.push(DeferredUnwind(unwind.0)); }
            }
            for unwind in failure.secondary_unwinds.drain(..) { self.secondary_unwinds.push(DeferredUnwind(unwind.0)); }
        }
        fn receive_unwind(&mut self, payload: Box<dyn std::any::Any + Send>) {
            if self.pending_unwind.is_none() { self.pending_unwind = Some(DeferredUnwind(payload)); }
            else { self.secondary_unwinds.push(DeferredUnwind(payload)); }
        }
        pub(crate) fn take_pending_unwind(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
            self.pending_unwind.take().map(|value| value.0)
        }
        pub(crate) fn finish_live_resources(&mut self) -> Vec<Result<serde_json::Value, String>> {
            let mut results = Vec::new();
            let mut pending_index = 0;
            while pending_index < self.pending_metadata.len() {
                let pending = &mut self.pending_metadata[pending_index];
                let field = pending.field();
                let actual = windows_installation::receive_pending_user_metadata(pending, field);
                if pending.restoration_owed() {
                    results.push(Err("metadata restoration remains owed".into()));
                    pending_index += 1;
                    continue;
                }
                let published = match actual {
                    windows_installation::PendingMetadataReceiving::PublishedReceived => true,
                    windows_installation::PendingMetadataReceiving::CanonicalUnchangedReceived => false,
                    windows_installation::PendingMetadataReceiving::Held { cause, actual } => {
                        results.push(Err(format!("{cause}; actual={actual:?}")));
                        pending_index += 1;
                        continue;
                    }
                };
                self.pending_metadata[pending_index].release_received(published, &mut self.live_resources);
                self.pending_metadata.remove(pending_index);
            }
            let mut index = 0;
            while index < self.live_resources.len() {
                match self.live_resources[index].finish() {
                    Ok(evidence) => {
                        self.effects.push(BackgroundEffect::ResourceFinished { evidence: evidence.clone() });
                        results.push(Ok(evidence));
                        self.live_resources.remove(index);
                    }
                    Err(cause) => {
                        if !self.effects.iter().any(|event| matches!(event, BackgroundEffect::ResourceFinishHeld { cause: previous } if previous == &cause)) {
                            self.effects.push(BackgroundEffect::ResourceFinishHeld { cause: cause.clone() });
                        }
                        results.push(Err(cause));
                        index += 1;
                    }
                }
            }
            results
        }
    }
    fn empty_receiving(operation: &'static str) -> BackgroundReceiving {
        BackgroundReceiving { operation, result: Ok(()), effects: Vec::new(), native: Vec::new(), replacements: Vec::new(), generation_writes: Vec::new(), generation_reads: Vec::new(),
            diagnostic_journal: None, diagnostic: None, persistence_errors: Vec::new(), cancellation_received: false, restoration_pending: false,
            primary_result: None, restoration_result: None, task_events: Vec::new(), live_resources: Vec::new(), pending_metadata: Vec::new(),
            pending_unwind: None, secondary_unwinds: Vec::new() }
    }
    struct BackgroundRun<'a> {
        received: BackgroundReceiving,
        cancelled: &'a AtomicBool,
        diagnostic: BackgroundDiagnostic,
        lease: Option<&'a windows_installation::BackgroundLease>,
        program_directory: PathBuf,
        selected_program: PathBuf,
        primary_unwind: Option<Box<dyn std::any::Any + Send>>,
        restoring: bool,
        created_directory: Option<CheckedPath>,
        created_program: Option<CreatedManagedProgram>,
        image: Option<Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>>,
        source_leases: Vec<std::sync::Arc<windows_installation::BackgroundLease>>,
        metadata_publications: Vec<windows_installation::UserMetadataPublication>,
        delivery_selected: bool,
        prior_transition: Option<ExactExistingTransition>,
        #[cfg(test)]
        scheduler_fixture: Option<SchedulerFixture>,
    }
    /// Constructed only after this live operation's successful CREATE_NEW and
    /// independent receiving; never decoded from a diagnostic or path/ACL.
    struct CreatedManagedProgram { guard: CheckedPath, source_sha256: String }
    /// Created only after the two live affirmations. The owner keeps it within
    /// this receiving run together with the original TaskSet and file pins.
    struct ExactExistingTransition {
        serial: String,
        program_id: windows_installation::NativeObjectId,
        original: windows_installation::SourceSnapshot,
        source: std::sync::Arc<windows_installation::BackgroundLease>,
        roles: Vec<task_scheduler::DefinitionView>,
        before_task_events: usize,
        authenticated: prior_transition::ApprovedPrior,
    }
    #[derive(Clone, Copy)]
    enum OccupancyOwnership { CurrentManagedBinding, LiveCreator, Unproved }
    fn require_owned_occupancy(proof: OccupancyOwnership) -> Result<(), String> {
        match proof { OccupancyOwnership::CurrentManagedBinding | OccupancyOwnership::LiveCreator => Ok(()),
            OccupancyOwnership::Unproved => Err("OccupiedStateHold: no current managed binding or same-live creator capability".into()) }
    }
    impl std::ops::Deref for BackgroundRun<'_> {
        type Target = BackgroundReceiving;
        fn deref(&self) -> &Self::Target { &self.received }
    }
    impl std::ops::DerefMut for BackgroundRun<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target { &mut self.received }
    }
    impl<'a> BackgroundRun<'a> {
        fn lease(&self) -> Result<&'a windows_installation::BackgroundLease, String> {
            self.lease.ok_or_else(|| "background program lease unavailable".into())
        }
        fn context(&self) -> Option<&'a windows_installation::AncestorAccessContext> {
            self.lease.and_then(|lease| lease.context())
        }
        fn program_path(&self) -> PathBuf { self.selected_program.clone() }
        fn ready(&mut self) -> Result<(), String> {
            if self.cancelled.load(Ordering::SeqCst) {
                self.received.cancellation_received = true;
                if !self.received.restoration_pending {
                    return Err("Cancelled: preserve actual background tasks and received partial effects; health is unverified".into());
                }
            }
            if !self.persistence_errors.is_empty() && !self.restoring { return Err("Diagnostic retention failed: no next independent background effect is granted".into()); }
            Ok(())
        }
        fn record(&mut self, event: &str) -> Result<(), String> {
            if let Err(error) = self.diagnostic.record(event, &self.received) {
                self.received.persistence_errors.push(error.clone());
                return Err(error);
            }
            Ok(())
        }
        fn effect(&mut self, effect: BackgroundEffect) -> Result<(), String> {
            self.received.effects.push(effect);
            self.record("effect")
        }
        fn task_state(&self) -> Result<TaskState, String> {
            #[cfg(test)]
            if let Some(fixture) = &self.scheduler_fixture { return Ok(TaskState {
                relay_enabled: fixture.relay_present, watchdog_enabled: fixture.watchdog_present }); }
            if self.restoration_pending { checked_task_state() }
            else { checked_task_state_with_cancel(self.cancelled) }
        }
        fn relay_compatible(&self) -> Result<bool, String> {
            checked_relay_compatible_with_cancel(self.cancelled)
        }
    }
    impl task_scheduler::Receiving for BackgroundRun<'_> {
        fn check_cancel(&mut self) -> Result<(), String> { self.ready() }
        fn before_retirement(&mut self, participants: &task_scheduler::TransitionParticipants<'_>) -> Result<(), String> {
            self.ready()?;
            check_selected_delivery_now(self, participants)?;
            if !self.restoration_pending {
                self.record("exactInstanceRetirementGrantPending")?;
                self.ready()?;
                self.restoration_pending = true;
            }
            Ok(())
        }
        fn receive(&mut self, event: task_scheduler::Event) -> Result<(), String> {
            self.task_events.push(event);
            match self.record("nativeTaskOutcome") {
                Err(_) if self.restoring => Ok(()),
                result => result,
            }
        }
    }
    fn prepare_background_diagnostic(received: &mut BackgroundReceiving, operation: &str, directory: PathBuf,
        context: Option<&windows_installation::AncestorAccessContext>) -> Option<BackgroundDiagnostic> {
        let mut diagnostic = match BackgroundDiagnostic::begin(operation, directory, context) {
            Ok(value) => value,
            Err(mut error) => {
                received.receive_metadata_failure(&mut error);
                let message = format!("{error}; actual={}", error.evidence);
                received.persistence_errors.push(message.clone()); received.result = Err(message); return None;
            }
        };
        match diagnostic.journal_reference() {
            Ok(reference) => { received.diagnostic_journal = Some(reference); Some(diagnostic) }
            Err(cause) => {
                if let Some(journal) = diagnostic.journal.take() { received.live_resources.push(journal.into_acquired()); }
                received.result = Err(cause); None
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn test_early_creation_packet(directory: PathBuf) -> BackgroundReceiving {
        let mut packet = empty_receiving("syntheticEarlyConstructor");
        windows_installation::fail_next_acquired_receiving_with_retained_witness();
        if let Some(mut diagnostic) = prepare_background_diagnostic(&mut packet, "syntheticEarlyConstructor", directory, None) {
            if let Some(journal) = diagnostic.journal.take() { packet.live_resources.push(journal.into_acquired()); }
            packet.result = Err("synthetic creation failure did not occur".into());
        }
        packet
    }
    #[cfg(test)]
    pub(crate) fn test_early_creation_panic_packet(directory: PathBuf) -> BackgroundReceiving {
        let mut packet = empty_receiving("syntheticEarlyConstructorPanic");
        windows_installation::panic_next_acquired_receiving_with_retained_witness();
        if let Some(mut diagnostic) = prepare_background_diagnostic(&mut packet, "syntheticEarlyConstructorPanic", directory, None) {
            if let Some(journal) = diagnostic.journal.take() { packet.live_resources.push(journal.into_acquired()); }
            packet.result = Err("synthetic creation panic did not occur".into());
        }
        packet
    }
    #[cfg(test)]
    pub(crate) fn test_partial_stage_packet(directory: PathBuf) -> BackgroundReceiving {
        let mut packet = empty_receiving("syntheticPartialMetadataStage");
        let path = directory.join("fixture-gate.json");
        let mut initial = windows_installation::publish_user_metadata(windows_installation::UserMetadataField::GateReport,
            &path, b"original fixture bytes").unwrap();
        initial.settle().unwrap();
        drop(initial);
        windows_installation::fail_next_metadata_partial_write(2);
        let mut failure = match windows_installation::publish_user_metadata(windows_installation::UserMetadataField::GateReport,
            &path, b"new fixture bytes") {
            Ok(_) => panic!("actual partial-stage failure required"), Err(value) => value,
        };
        assert_eq!(failure.evidence["canonicalUnchangedReceived"], true);
        packet.result = Err(failure.to_string());
        packet.receive_metadata_failure(&mut failure);
        packet
    }
    #[cfg(test)]
    pub(crate) fn test_complete_stage_packet(directory: PathBuf) -> BackgroundReceiving {
        let mut packet = empty_receiving("syntheticCompleteMetadataStage");
        let path = directory.join("fixture-gate.json");
        windows_installation::occupy_next_metadata_vacancy();
        let mut failure = match windows_installation::publish_user_metadata(windows_installation::UserMetadataField::GateReport,
            &path, b"complete fixture stage") {
            Ok(_) => panic!("foreign occupancy failure required"), Err(value) => value,
        };
        assert_eq!(failure.evidence["canonicalUnchangedReceived"], false);
        assert_eq!(failure.evidence["ownCanonicalEffectAbsentReceived"], true);
        packet.result = Err(failure.to_string());
        packet.receive_metadata_failure(&mut failure);
        packet
    }
    fn receiving(operation: &'static str, cancelled: &AtomicBool,
        image: Option<Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>>,
        action: impl FnOnce(&mut BackgroundRun<'_>) -> Result<(), String>) -> BackgroundReceiving {
        let mut received = empty_receiving(operation);
        let locations = match windows_installation::background_locations() {
            Ok(locations) => locations,
            Err(error) => { received.result = Err(error); return received; }
        };
        let directory = locations.managed_directory().to_path_buf();
        let selected_program = locations.managed_program().to_path_buf();
        let diagnostic_parent = dns_forwarder::log_dir();
        let prepared = (|| {
            let inputs = windows_installation::background_inputs(
                locations.managed_root(), &directory,
                None, &diagnostic_parent)?;
            windows_installation::background_lease(inputs, None)
        })();
        let lease = match prepared {
            Ok(lease) => lease,
            Err(error) => { received.result = Err(error); return received; }
        };
        let diagnostic = match prepare_background_diagnostic(&mut received, operation, diagnostic_parent, lease.context()) {
            Some(value) => value,
            None => return received,
        };
        let mut run = BackgroundRun { received, cancelled, diagnostic, lease: Some(&lease), program_directory: directory, selected_program, primary_unwind: None, restoring: false, created_directory: None, created_program: None, image, source_leases: Vec::new(), delivery_selected: false,
            metadata_publications: Vec::new(), prior_transition: None, #[cfg(test)] scheduler_fixture: None };
        perform_receiving(&mut run, action);
        run.received
    }
    fn perform_receiving(run: &mut BackgroundRun<'_>, action: impl FnOnce(&mut BackgroundRun<'_>) -> Result<(), String>) {
        let action_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.ready().and_then(|_| action(run))));
        if let Some(payload) = run.primary_unwind.take() {
            if let Some(later) = run.received.pending_unwind.replace(DeferredUnwind(payload)) {
                run.received.secondary_unwinds.push(later);
            }
        }
        match action_result {
            Ok(result) => run.received.result = result,
            Err(payload) => { run.received.result = Err("background operation unwound; actual receiving retained".into()); run.received.receive_unwind(payload); }
        }
        if run.cancelled.load(Ordering::SeqCst) {
            run.received.cancellation_received = true;
            if run.received.result.is_ok() {
                run.received.result = Err("Cancelled: actual background transition is retained; stop subsequent independent actions".into());
            }
        }
        let final_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| finalize_receiving(run)));
        if let Err(payload) = final_result {
            run.received.receive_unwind(payload);
            if let Some(journal) = run.diagnostic.journal.take() { run.received.live_resources.push(journal.into_acquired()); }
            if let Some(terminal) = run.diagnostic.terminal.take() { run.received.live_resources.push(terminal.into_acquired()); }
            while !run.metadata_publications.is_empty() {
                let publication = run.metadata_publications.remove(0);
                let mut failure = publication.into_failure("metadata-finalization-unwind", "finalization unwound".into(), true, run.received.restoration_pending);
                run.received.receive_metadata_failure(&mut failure);
            }
        }
    }
    fn finalize_receiving(run: &mut BackgroundRun<'_>) {
        if run.received.result.is_ok() && !run.received.restoration_pending {
            while !run.metadata_publications.is_empty() {
                match run.metadata_publications[0].settle() {
                    Ok(evidence) => {
                        run.received.generation_writes.push(evidence);
                        run.metadata_publications.remove(0);
                    }
                    Err(cause) => {
                        let publication = run.metadata_publications.remove(0);
                        let mut error = publication.into_failure("metadata-settlement", cause, false, false);
                        run.received.generation_writes.push(metadata_failure_evidence(&error));
                        let message = format!("metadata settlement failed: {error}; actual={}", error.evidence);
                        run.received.receive_metadata_failure(&mut error);
                        run.received.result = Err(message);
                    }
                }
            }
        } else {
            while !run.metadata_publications.is_empty() {
                let publication = run.metadata_publications.remove(0);
                let mut failure = publication.into_failure("metadata-operation-unsettled",
                    "background operation did not finish metadata settlement".into(), true, run.received.restoration_pending);
                run.received.generation_writes.push(metadata_failure_evidence(&failure));
                run.received.receive_metadata_failure(&mut failure);
            }
        }
        match run.diagnostic.finish(&mut run.received, run.lease.as_ref().and_then(|lease| lease.context())) {
            Ok(reference) => {
                run.received.diagnostic = Some(reference);
                if let Ok(journal) = run.diagnostic.journal_reference() { run.received.diagnostic_journal = Some(journal); }
            }
            Err(mut error) => {
                run.received.receive_metadata_failure(&mut error);
                let message = format!("{error}; actual={}", error.evidence);
                run.received.persistence_errors.push(message.clone());
                run.received.result = Err(match &run.received.result {
                    Ok(()) => message,
                    Err(previous) => format!("{previous}; diagnostic terminal retention: {message}"),
                });
            }
        }
        if !run.received.persistence_errors.is_empty() {
            if let Some(journal) = run.diagnostic.journal.take() {
                run.received.live_resources.push(journal.into_acquired());
            }
        }
    }

    fn uncancelled_receiving(operation: &'static str, action: impl FnOnce(&mut BackgroundRun<'_>) -> Result<(), String>) -> BackgroundReceiving {
        receiving(operation, &AtomicBool::new(false), None, action)
    }

    #[derive(Clone, Debug, serde::Serialize)]
    pub(crate) struct DiagnosticFileRef {
        pub(crate) path: PathBuf,
        pub(crate) native_id: windows_installation::NativeObjectId,
        pub(crate) sha256: Option<String>,
    }
    struct BackgroundDiagnostic {
        id: String,
        directory: PathBuf,
        journal: Option<windows_installation::BackgroundDiagnosticFile>,
        journal_digest: Option<String>,
        terminal: Option<windows_installation::BackgroundDiagnosticFile>,
        next_output: u64,
        effects_written: usize,
        replacements_written: usize,
        generations_written: usize,
        generation_reads_written: usize,
        task_events_written: usize,
        persistence_errors_written: usize,
        #[cfg(test)]
        injected_write_failure: bool,
    }
    impl BackgroundDiagnostic {
        fn begin(operation: &str, directory: PathBuf, context: Option<&windows_installation::AncestorAccessContext>) -> Result<Self, windows_installation::MetadataFailure> {
            windows_installation::WindowsLocalPath::parse(directory.as_os_str()).map_err(|cause| windows_installation::MetadataFailure::unacquired("diagnostic-path", cause))?;
            let id = windows_installation::new_request_id().map_err(|cause| windows_installation::MetadataFailure::unacquired("diagnostic-id", cause))?;
            let journal = windows_installation::create_background_diagnostic_file(&directory.join(format!("background-{id}.jsonl")), context)?;
            let mut diagnostic = Self { id, directory, journal: Some(journal), journal_digest: None, terminal: None, next_output: 0, effects_written: 0,
                replacements_written: 0, generations_written: 0, generation_reads_written: 0, task_events_written: 0, persistence_errors_written: 0,
                #[cfg(test)] injected_write_failure: false };
            let begin = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| diagnostic.write(&serde_json::json!({"event":"begin","operation":operation,"operationId":diagnostic.id}))));
            let (result, unwind) = match begin {
                Ok(result) => (result, None),
                Err(payload) => (Err("diagnostic begin unwound".into()), Some(payload)),
            };
            if let Err(cause) = result {
                let mut failure = match diagnostic.journal.take() {
                    Some(file) => windows_installation::MetadataFailure::with_capture("diagnostic-begin", cause, file),
                    None => windows_installation::MetadataFailure::unacquired("diagnostic-begin", cause),
                };
                failure.set_unwind(unwind);
                return Err(failure);
            }
            Ok(diagnostic)
        }
        fn journal_reference(&self) -> Result<DiagnosticFileRef, String> {
            let journal = self.journal.as_ref().ok_or("diagnostic journal ownership absent")?;
            Ok(DiagnosticFileRef { path: journal.path.clone(), native_id: journal.native_id.clone(), sha256: self.journal_digest.clone() })
        }
        fn write(&mut self, value: &serde_json::Value) -> Result<(), String> {
            #[cfg(test)]
            if self.injected_write_failure { return Err("injected diagnostic write failure; actual outcomes retained".into()); }
            let mut bytes = serde_json::to_vec(value).map_err(|e| format!("background diagnostic serialization: {e}"))?;
            bytes.push(b'\n');
            self.journal_digest = None;
            let journal = self.journal.as_mut().ok_or("diagnostic journal ownership absent")?;
            journal.write_authored(&bytes)
                .map_err(|e| format!("background diagnostic write/flush {}: {e}; preserve actual receipt", journal.path.display()))
        }
        fn record(&mut self, event: &str, received: &BackgroundReceiving) -> Result<(), String> {
            // Incremental facts, rather than repeatedly serializing all older
            // native streams during a pending health poll. The full terminal
            // receiving is written exactly once by finish.
            self.write(&serde_json::json!({"event":event,"operation":received.operation,
                "effects":&received.effects[self.effects_written..],
                "replacements":&received.replacements[self.replacements_written..],
                "generationWrites":&received.generation_writes[self.generations_written..],
                "generationReads":&received.generation_reads[self.generation_reads_written..],
                "taskEvents":&received.task_events[self.task_events_written..],
                "persistenceErrors":&received.persistence_errors[self.persistence_errors_written..],
                "nativeIndex":received.native.len().checked_sub(1),"native":received.native.last(),
                "result":received.result,"primary":received.primary_result,"restoration":received.restoration_result,
                "cancelled":received.cancellation_received,"restorationPending":received.restoration_pending}))?;
            self.effects_written = received.effects.len();
            self.replacements_written = received.replacements.len();
            self.generations_written = received.generation_writes.len();
            self.generation_reads_written = received.generation_reads.len();
            self.task_events_written = received.task_events.len();
            self.persistence_errors_written = received.persistence_errors.len();
            Ok(())
        }
        fn output_file(&mut self, stream: &str, context: Option<&windows_installation::AncestorAccessContext>) -> Result<windows_installation::BackgroundDiagnosticFile, windows_installation::MetadataFailure> {
            let index = self.next_output;
            self.next_output = self.next_output.checked_add(1).ok_or_else(|| windows_installation::MetadataFailure::unacquired("diagnostic-output", "background diagnostic output identity overflow".into()))?;
            windows_installation::create_background_diagnostic_file(&self.directory.join(format!("background-{}-{index}-{stream}.bin", self.id)), context)
        }
        fn finish(&mut self, received: &mut BackgroundReceiving, context: Option<&windows_installation::AncestorAccessContext>) -> Result<DiagnosticFileRef, windows_installation::MetadataFailure> {
            let journal_receiving = self.journal.as_mut().ok_or("diagnostic journal ownership absent".to_string())
                .and_then(|journal| journal.receive_authored());
            match journal_receiving {
                Ok(snapshot) => self.journal_digest = Some(snapshot.digest().to_owned()),
                Err(cause) => {
                    self.journal_digest = None;
                    let error = format!("diagnostic journal receiving: {cause}");
                    received.persistence_errors.push(error.clone());
                    received.result = Err(match &received.result {
                        Ok(()) => error,
                        Err(previous) => format!("{previous}; {error}"),
                    });
                }
            }
            let journal = self.journal_reference().map_err(|cause| windows_installation::MetadataFailure::unacquired("diagnostic-journal", cause))?;
            let bytes = serde_json::to_vec(&serde_json::json!({"operationId":self.id,"journal":journal,"receiving":received}))
                .map_err(|e| windows_installation::MetadataFailure::unacquired("diagnostic-terminal-serialization", format!("background terminal serialization: {e}")))?;
            self.terminal = Some(windows_installation::create_background_diagnostic_file(&self.directory.join(format!("background-{}-terminal.json", self.id)), context)?);
            let terminal = self.terminal.as_mut().unwrap();
            if let Err(error) = terminal.write_authored(&bytes) {
                return Err(windows_installation::MetadataFailure::with_capture("diagnostic-terminal-write", error, self.terminal.take().unwrap()));
            }
            let mut reference = DiagnosticFileRef { path: terminal.path.clone(), native_id: terminal.native_id.clone(), sha256: None };
            let actual = match terminal.receive_authored() {
                Ok(value) => value,
                Err(cause) => return Err(windows_installation::MetadataFailure::with_capture("diagnostic-terminal-readback", cause, self.terminal.take().unwrap())),
            };
            reference.sha256 = Some(actual.digest().to_owned());
            self.terminal.take();
            Ok(reference)
        }
    }

    /// Actual helpers remain creator-owned until physical exit. Their streams
    /// go directly to retained private files, with no off-path reader resources.
    struct NativeOwner {
        child: Child,
        exited: bool,
        exit_code: Option<i32>,
    }
    impl NativeOwner {
        fn settle(&mut self, errors: &mut Vec<String>) {
            self.settle_with_cancel(errors, None, false);
        }
        fn settle_with_cancel(&mut self, errors: &mut Vec<String>, cancelled: Option<&AtomicBool>, read_only: bool) {
            let mut cancellation_sent = false;
            while !self.exited {
                if !cancellation_sent && cancelled.is_some_and(|value| value.load(Ordering::SeqCst)) {
                    cancellation_sent = true;
                    self.child.stdin.take();
                    if read_only {
                        // Only the exact creator-owned read-only query child.
                        // An already-selected task instance is never killed.
                        if let Err(error) = self.child.kill() { errors.push(format!("native read-only cancellation request: {error}")); }
                    }
                }
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        self.exited = true;
                        self.child.stdin.take();
                        self.exit_code = status.code();
                        if !status.success() { errors.push(format!("scheduler helper exited {status}")); }
                    }
                    Ok(None) => thread::park_timeout(Duration::from_millis(20)),
                    Err(e) => {
                        let error = format!("scheduler helper exit observation: {e}");
                        if !errors.contains(&error) { errors.push(error); }
                        // Keep the creator's handle and readers. A query failure
                        // confers neither termination authority nor completion.
                        thread::park_timeout(Duration::from_millis(20));
                    }
                }
            }
        }
    }
    impl Drop for NativeOwner {
        fn drop(&mut self) { self.child.stdin.take(); self.settle(&mut Vec::new()); }
    }

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct TaskReceipt {
        present: bool,
        compatible: bool,
        instances: Vec<String>,
        created: bool,
        #[serde(deserialize_with = "required_option")]
        started: Option<String>,
        retired: Vec<String>,
        roles_present: Vec<String>,
    }
    fn required_option<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
        <Option<T> as serde::Deserialize>::deserialize(d)
    }

    /// The typed native adapter owns Scheduler truth. The private test transport
    /// below substitutes acquired outcomes without executing product tasks.
    fn scheduler(role: &str, create: bool, program: &CheckedPath, received: &mut BackgroundRun<'_>) -> Result<TaskReceipt, String> {
        scheduler_action(role, if create { "ensure" } else { "inspect" }, program, received)
    }
    fn scheduler_action(role: &str, operation: &str, program: &CheckedPath, received: &mut BackgroundRun<'_>) -> Result<TaskReceipt, String> {
        received.ready()?;
        #[cfg(test)]
        if received.scheduler_fixture.is_some() {
            let fixture = received.scheduler_fixture.as_mut().unwrap();
            fixture.calls.push((role.to_owned(), operation.to_owned()));
            fixture.program_native_ids.push(program.native_id());
            let reply = fixture.replies.pop_front().expect("explicit synthetic transport reply required");
            let latch = role == "shared" && operation == "retire";
            let cancel_after_retire = latch && fixture.cancel_after_retire;
            let fail_after_retire = latch && fixture.fail_after_retire;
            if latch { received.restoration_pending = true; }
            if cancel_after_retire { received.cancelled.store(true, Ordering::SeqCst); }
            if fail_after_retire { received.diagnostic.injected_write_failure = true; }
            if operation == "resume" {
                task_scheduler::Receiving::receive(received, task_scheduler::Event::Call(task_scheduler::Call {
                    operation: "syntheticRestoreRun", role: role.to_owned(), instance: None, returned_hresult: Some(0), output_returned: true,
                    error_info: task_scheduler::ErrorInfo::NoInfo { hresult: 1 },
                }))?;
            }
            return reply;
        }
        let scheduler = task_scheduler::Scheduler::connect()?;
        let programs = task_scheduler::Programs { managed: Some(program), legacy: None };
        let roles: &[&str] = if role == "shared" { &["relay", "watchdog"] } else { &[role] };
        match operation {
            "ensure" => scheduler.ensure(role, &programs, true, received),
            "inspect" => Ok(scheduler.receive(roles, &programs, received)?.receipt()),
            "remove" => scheduler.receive(roles, &programs, received)?.remove(&programs, received),
            _ => Err("unknown native background operation".into()),
        }
    }
    #[cfg(test)]
    struct SchedulerFixture {
        relay_present: bool,
        watchdog_present: bool,
        cancel_after_retire: bool,
        fail_after_retire: bool,
        replies: std::collections::VecDeque<Result<TaskReceipt, String>>,
        calls: Vec<(String, String)>,
        program_native_ids: Vec<windows_installation::NativeObjectId>,
    }
    #[cfg(test)]
    struct ControlledClosedFixtureRecipe { script: &'static str }
    #[cfg(test)]
    struct ControlledClosedFixtureWriter;
    #[cfg(test)]
    fn retain_unused_fixture_stream(received: &mut BackgroundRun<'_>, mut file: windows_installation::BackgroundDiagnosticFile) {
        if let Err(error) = file.mark_unused_fixture_before_spawn() {
            received.persistence_errors.push(format!("unused fixture stream classification: {error}"));
        }
        received.live_resources.push(file.into_acquired());
    }
    #[cfg(test)]
    fn native_output(recipe: ControlledClosedFixtureRecipe, request: Option<&[u8]>, program: Option<&CheckedPath>, role: &str, read_only: bool, starts_transition: bool,
        received: &mut BackgroundRun<'_>) -> Result<Vec<u8>, String> {
        received.ready()?;
        let host = windows_coordinator::system_powershell_program()?;
        let current = ProcessIdentity::current()?;
        host.recheck()?;
        let index = received.native.len();
        received.native.push(BackgroundNativeReceiving { role: role.to_owned(), started: false, exit_observed: false,
            exit_code: None, stdout: Vec::new(), stderr: Vec::new(), errors: Vec::new(), stdout_file: None, stderr_file: None });
        let context = received.lease.as_ref().and_then(|lease| lease.context());
        let stdout = match received.diagnostic.output_file("stdout", context) {
            Ok(value) => value,
            Err(mut failure) => {
                let message = format!("{failure}; actual={}", failure.evidence);
                received.receive_metadata_failure(&mut failure);
                return Err(message);
            }
        };
        received.native[index].stdout_file = Some(output_reference(&stdout));
        if let Err(error) = received.record("nativeStdoutPrepared") {
            retain_unused_fixture_stream(received, stdout);
            return Err(error);
        }
        let context = received.lease.as_ref().and_then(|lease| lease.context());
        let stderr = match received.diagnostic.output_file("stderr", context) {
            Ok(value) => value,
            Err(mut failure) => {
                let message = format!("{failure}; actual={}", failure.evidence);
                retain_unused_fixture_stream(received, stdout);
                received.receive_metadata_failure(&mut failure);
                return Err(message);
            }
        };
        received.native[index].stderr_file = Some(output_reference(&stderr));
        if let Err(error) = received.record("nativeStderrPrepared") {
            retain_unused_fixture_stream(received, stdout);
            retain_unused_fixture_stream(received, stderr);
            return Err(error);
        }
        let child = (|| -> Result<Child, String> {
            let mut command = Command::new(host.as_path());
            command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", recipe.script])
                .stdin(Stdio::piped())
                .stdout(Stdio::from(stdout.file.try_clone().map_err(|e| format!("clone native stdout file: {e}"))?))
                .stderr(Stdio::from(stderr.file.try_clone().map_err(|e| format!("clone native stderr file: {e}"))?));
            received.ready()?;
            no_window(&mut command).spawn().map_err(|e| format!("scheduler helper spawn: {e}"))
        })();
        let child = match child {
            Ok(value) => value,
            Err(error) => {
                retain_unused_fixture_stream(received, stdout);
                retain_unused_fixture_stream(received, stderr);
                return Err(error);
            }
        };
        received.native[index].started = true;
        let mut owner = NativeOwner { child, exited: false, exit_code: None };
        let mut errors = Vec::new();
        // Setup failure closes the still-ungranted stdin and observes real
        // helper exit. Inherited output files stay held throughout settlement.
        let setup = (|| -> Result<(), String> {
            use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
            use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            let mut duplicate = std::ptr::null_mut();
            if unsafe { DuplicateHandle(GetCurrentProcess(), owner.child.as_raw_handle(), GetCurrentProcess(), &mut duplicate, 0, 0, DUPLICATE_SAME_ACCESS) } == 0 {
                return Err(format!("scheduler helper handle receiving: {}", std::io::Error::last_os_error()));
            }
            let identity = ProcessIdentity::receive(unsafe { OwnedHandle::from_raw_handle(duplicate) })?;
            if identity.image() != host.as_path() || identity.sid() != current.sid() { return Err("scheduler helper identity mismatch".into()); }
            identity.recheck()?;
            host.recheck()?;
            if let Some(program) = program { program.recheck()?; }
            received.record("nativeHelperReceived")?;
            received.ready()?;
            if let Some(request) = request {
                if starts_transition {
                    // The JSON grant permits the first exact-instance Stop.
                    // Cancellation after this point is latched, never delivered
                    // as EOF until required wanted-role restoration settles.
                    received.record("sharedRetirementGrantPending")?;
                    received.ready()?;
                    received.restoration_pending = true;
                }
                let input = owner.child.stdin.as_mut().ok_or("scheduler stdin absent")?;
                input.write_all(request).and_then(|_| input.write_all(b"\n")).and_then(|_| input.flush())
                    .map_err(|e| format!("scheduler grant delivery: {e}"))?;
            }
            Ok(())
        })();
        if let Err(e) = setup { errors.push(e); owner.child.stdin.take(); }
        owner.settle_with_cancel(&mut errors,
            if received.restoration_pending { None } else { Some(received.cancelled) }, read_only);
        // This function has one test-only caller whose fixed script does not
        // spawn writers. Its command-owned duplicates were dropped at spawn,
        // and the creator-owned direct child has been observed exiting.
        let _closed = ControlledClosedFixtureWriter;
        assert!(owner.exited);
        let (out, out_ref, out_errors, out_held) = capture_file(stdout, received.context(), &_closed);
        let (err, err_ref, err_errors, err_held) = capture_file(stderr, received.context(), &_closed);
        if let Some(held) = out_held { received.live_resources.push(held); }
        if let Some(held) = err_held { received.live_resources.push(held); }
        errors.extend(out_errors);
        errors.extend(err_errors);
        received.native[index] = BackgroundNativeReceiving { role: role.to_owned(), started: true, exit_observed: owner.exited,
            exit_code: owner.exit_code, stdout: out.clone(), stderr: err.clone(), errors: errors.clone(),
            stdout_file: Some(out_ref), stderr_file: Some(err_ref) };
        // Output kernel writes are incremental. Terminal receiving is flushed
        // before interpretation; persistence failure never prevents settlement.
        received.record("nativeHelperRetired")?;
        if !errors.is_empty() {
            return Err(format!("{}; native stdout={}; native stderr={}", errors.join("; "),
                String::from_utf8_lossy(&out), String::from_utf8_lossy(&err)));
        }
        received.ready()?;
        Ok(out)
    }

    fn output_reference(file: &windows_installation::BackgroundDiagnosticFile) -> DiagnosticFileRef {
        DiagnosticFileRef { path: file.path.clone(), native_id: file.native_id.clone(), sha256: None }
    }
    #[cfg(test)]
    fn capture_file(mut file: windows_installation::BackgroundDiagnosticFile, _context: Option<&windows_installation::AncestorAccessContext>,
        _closed: &ControlledClosedFixtureWriter) -> (Vec<u8>, DiagnosticFileRef, Vec<String>, Option<windows_installation::AcquiredCreation>) {
        let mut reference = output_reference(&file);
        let mut errors = Vec::new();
        if let Err(error) = file.begin_closed_fixture_stream() { errors.push(error); }
        if let Err(error) = file.file.flush().and_then(|_| file.file.sync_all()) { errors.push(format!("native capture flush {}: {error}", reference.path.display())); }
        let (bytes, read_result) = file.read_closed_fixture_stream();
        let complete = match read_result {
            Ok(()) => true,
            Err(error) => { errors.push(format!("native capture read {}: {error}; acquired prefix retained", reference.path.display())); false }
        };
        if complete {
            match file.receive_observed_fixture_stream() {
                Ok(actual) => reference.sha256 = Some(actual.digest().to_owned()),
                Err(error) => errors.push(format!("native capture independent readback: {error}")),
            }
        }
        let held = if errors.is_empty() { None } else { Some(file.into_acquired()) };
        (bytes, reference, errors, held)
    }

    fn checked_json_with_cancel(script: &str, cancelled: &AtomicBool) -> Result<serde_json::Value, String> {
        let host = windows_coordinator::system_powershell_program()?;
        let mut command = Command::new(host.as_path());
        command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]);
        let stdout = windows_coordinator::runtime_metadata(&host, command, cancelled, false,
            windows_coordinator::MetadataContext::new(windows_coordinator::MetadataPurpose::BackgroundStateQuery, None))?;
        parse_checked_json(stdout.as_bytes())
    }

    fn parse_checked_json(stdout: &[u8]) -> Result<serde_json::Value, String> {
        let text = std::str::from_utf8(stdout).map_err(|_| "native query invalid UTF-8")?;
        let json = text.trim().strip_suffix("\nAG_END").ok_or("native query incomplete")?.trim();
        serde_json::from_str(json).map_err(|e| format!("invalid native query: {e}"))
    }

    pub(crate) fn checked_task_state() -> Result<TaskState, String> {
        checked_task_state_with_cancel(&AtomicBool::new(false))
    }
    pub(crate) fn checked_task_state_with_cancel(cancelled: &AtomicBool) -> Result<TaskState, String> {
        let script = format!(
            "$ErrorActionPreference='Stop'; $names=@(Get-ScheduledTask -TaskPath '\\' | \
             Where-Object {{ $_.TaskName -in @('{}','{}') }} | ForEach-Object {{ $_.TaskName }}); \
             ConvertTo-Json -InputObject $names -Compress; 'AG_END'", TASK_NAME, WATCHDOG_TASK_NAME
        );
        let names: Vec<String> = serde_json::from_value(checked_json_with_cancel(&script, cancelled)?)
            .map_err(|e| format!("invalid scheduler result: {e}"))?;
        if names.iter().any(|n| n != TASK_NAME && n != WATCHDOG_TASK_NAME) {
            return Err("unexpected scheduler task".into());
        }
        Ok(TaskState { relay_enabled: names.iter().any(|n| n == TASK_NAME),
                       watchdog_enabled: names.iter().any(|n| n == WATCHDOG_TASK_NAME) })
    }

    /// Existing relay health evidence; this does not grant a stop capability.
    pub(crate) fn checked_relay_compatible() -> Result<bool, String> {
        checked_relay_compatible_with_cancel(&AtomicBool::new(false))
    }
    pub(crate) fn checked_relay_compatible_with_cancel(cancelled: &AtomicBool) -> Result<bool, String> {
        Ok(observe_background(cancelled, None, false, false)?.relay == RoleObservation::Running)
    }

    pub(crate) fn checked_installed_copy_current() -> Result<bool, String> {
        let src = env::current_exe().map_err(|e| format!("current executable: {e}"))?;
        let current = fs::read(src).map_err(|e| format!("read current executable: {e}"))?;
        match fs::read(installed_exe()?) {
            Ok(installed) => Ok(current == installed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("read installed executable: {e}")),
        }
    }

    pub(crate) fn checked_relay_outdated() -> Result<bool, String> {
        checked_relay_outdated_with_cancel(&AtomicBool::new(false))
    }
    pub(crate) fn checked_relay_outdated_with_cancel(cancelled: &AtomicBool) -> Result<bool, String> {
        let image = std::sync::Arc::new(windows_coordinator::process_identity::CurrentImage::capture()?);
        observe_background(cancelled, Some(image), false, false)?.selected_delivery_required
            .ok_or_else(|| "selected delivery observation absent".into())
    }

    struct Inspection<'a>(&'a AtomicBool);
    impl task_scheduler::Receiving for Inspection<'_> {
        fn check_cancel(&mut self) -> Result<(), String> {
            if self.0.load(Ordering::SeqCst) { Err("Cancelled: background inspection".into()) } else { Ok(()) }
        }
        fn before_retirement(&mut self, _: &task_scheduler::TransitionParticipants<'_>) -> Result<(), String> { Err("read-only inspection cannot retire tasks".into()) }
        fn receive(&mut self, _: task_scheduler::Event) -> Result<(), String> { Ok(()) }
    }
    pub(crate) fn selected_delivery_required(cancelled: &AtomicBool,
        image: std::sync::Arc<windows_coordinator::process_identity::CurrentImage>) -> Result<bool, String> {
        observe_background(cancelled, Some(image), false, false)?.selected_delivery_required
            .ok_or_else(|| "selected delivery observation absent".into())
    }

    /// `expected` comes from the caller's saved/read-back settings snapshot.
    pub(crate) fn observe_background_for_transport(cancelled: &AtomicBool,
        image: Option<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>>,
        expected: crate::settings::ActiveTransportConfig) -> Result<TransportBackgroundObservation, String> {
        let background = observe_background(cancelled, image, false, false)?;
        let (channels, tcp_proxy_port, instance) = match receive_bound_transport(cancelled, expected, false) {
            Ok(value) => (value.channels, value.tcp_proxy_port, value.instance),
            Err(error) => (unknown_transport_channels(&error), None, None),
        };
        let [dns, tcp_proxy, dns_alias] = channels;
        Ok(TransportBackgroundObservation { background, expected, dns, tcp_proxy, dns_alias, tcp_proxy_port, instance })
    }

    pub(crate) fn observe_background(cancelled: &AtomicBool,
        image: Option<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>>,
        need_proxy: bool, need_dns: bool) -> Result<BackgroundObservation, String> {
        if cancelled.load(Ordering::SeqCst) { return Err("Cancelled: background observation".into()); }
        let locations = windows_installation::background_locations()?;
        let selected_image = image.is_some();
        let inputs = match image {
            Some(value) => windows_installation::background_inputs_selected(locations.managed_root(), locations.managed_directory(), value, &dns_forwarder::log_dir())?,
            None => windows_installation::background_inputs(locations.managed_root(), locations.managed_directory(), None, &dns_forwarder::log_dir())?,
        };
        let lease = windows_installation::background_lease(inputs, None)?;
        let scheduler = task_scheduler::Scheduler::connect()?;
        let legacy = if scheduler.references_program(locations.legacy_program())? {
            Some(windows_installation::legacy_background_input(&locations)?
                .ok_or("OwnershipRequired: selected legacy program is absent")?)
        } else { None };
        let managed_referenced = scheduler.references_program(locations.managed_program())?;
        let managed = match fs::symlink_metadata(locations.managed_program()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !managed_referenced => None,
            Err(error) => return Err(format!("installed executable metadata: {error}")),
            Ok(_) if managed_referenced || selected_image => Some(windows_installation::checked_background_path(&lease, locations.managed_program(), PathKind::File)?),
            Ok(_) => None,
        };
        let programs = task_scheduler::Programs { managed: managed.as_ref(), legacy: legacy.as_ref() };
        let selected = scheduler.receive(&["relay", "watchdog"], &programs, &mut Inspection(cancelled))?;
        let relay = selected.role_observation("relay");
        let watchdog = selected.role_observation("watchdog");
        let selected_delivery_required = if selected_image {
            let source = lease.source_bytes()?;
            if let Some(legacy) = &legacy {
                legacy.revalidate()?;
                let proof = generation_for_program(legacy.checked_file(), legacy.checked_file().read_snapshot()?.as_slice() == source);
                current_image_decision(&proof, false, ImageDemand::DeliverSelectedImage)?;
                legacy.revalidate()?;
            }
            match managed.as_ref() {
                None if legacy.is_none() => Some(false),
                None => Some(true),
                Some(program) => {
                    selected.managed_binding(program)?.ok_or("OccupiedStateHold: managed image has no current qualified task/program binding")?.revalidate()?;
                    let proof = generation_for_program(program, program.read_snapshot()?.as_slice() == source);
                    let decision = current_image_decision(&proof, false, ImageDemand::DeliverSelectedImage)?;
                    program.recheck()?;
                    Some(legacy.is_some() || decision == CurrentImageDecision::UpdateRequired)
                }
            }
        } else { None };
        let component = |probe: &dyn Fn(&CheckedPath) -> Result<(), String>| -> Result<bool, String> {
            if relay != RoleObservation::Running { return Ok(false); }
            let program = managed.as_ref().ok_or("OwnershipRequired: listener has no protected managed program")?;
            match probe(program) {
                Ok(()) => Ok(true),
                Err(error) if error.starts_with("UpdatePending: local listener is absent")
                    || error.starts_with("UpdatePending: proxy listener did not accept") => Ok(false),
                Err(error) => Err(error),
            }
        };
        let proxy_ready = need_proxy.then(|| component(&|program| probe_proxy_listener(program).map(|_| ())));
        let dns_ready = need_dns.then(|| component(&probe_dns_listener));
        selected.transition_participants(&programs)?;
        if selected_image { lease.source_bytes()?; }
        if cancelled.load(Ordering::SeqCst) { return Err("Cancelled: background observation".into()); }
        Ok(BackgroundObservation { relay, watchdog, selected_delivery_required, proxy_ready, dns_ready })
    }

    /// True when the logon task exists. Says nothing about whether the relay is
    /// running right now - `is_running` answers that.
    pub fn is_enabled(owner: &mut CommandOutcome) -> Result<bool, String> {
        task_exists(owner, TASK_NAME)
    }

    /// True when the watchdog's own logon task exists.
    #[allow(dead_code)]
    pub fn is_watchdog_enabled(owner: &mut CommandOutcome) -> Result<bool, String> {
        task_exists(owner, WATCHDOG_TASK_NAME)
    }

    pub fn is_running(owner: &mut CommandOutcome) -> Result<bool, String> {
        let name = format!("{}.exe", relay_process_name());
        let cmd = PreparedExec::system(Path::new("tasklist.exe"))?.args(["/FI", &format!("IMAGENAME eq {}", name), "/NH"]);
        let receipt = bounded_output(owner, cmd, HELPER_LIMIT);
        receive_command(owner, receipt)?;
        let running = String::from_utf8_lossy(owner.stdout()).contains(&name);
        drop(std::mem::take(owner));
        Ok(running)
    }

    /// Preserve a compatible running relay. Fresh installation is create-only;
    /// an existing unqualified generation is never retired by image name.
    pub fn enable() -> Result<(), String> {
        enable_with_receiving().result
    }
    pub(crate) fn enable_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("enableRelay", enable_inner)
    }
    fn enable_inner(received: &mut BackgroundRun<'_>) -> Result<(), String> {
        let before = received.task_state()?;
        if legacy_roles_already_running(received, BackgroundDesired { relay: true, watchdog: before.watchdog_enabled })? {
            return Ok(());
        }
        let program = ensure_program(received, BackgroundChanges { relay: Some(true), watchdog: None }, ImageDemand::KeepCompatible, false)?;
        let receipt = scheduler("relay", true, &program, received)?;
        require_running(&receipt, "relay")
    }
    fn with_managed_listener<T>(program: &CheckedPath, addr: std::net::SocketAddr,
        protocol: crate::portcheck::Proto, probe: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        with_managed_listener_processes(program, addr, protocol, |_| probe())
    }
    fn with_managed_listener_processes<T>(program: &CheckedPath, addr: std::net::SocketAddr,
        protocol: crate::portcheck::Proto, probe: impl FnOnce(&[(ProcessIdentity, CheckedPath)]) -> Result<T, String>) -> Result<T, String> {
        use windows_coordinator::process_identity::ProcessIdentity;
        let mut owners = crate::portcheck::listener_owners(addr, protocol)?;
        owners.sort_unstable();
        let mut pids = owners.iter().map(|(_, pid)| *pid).collect::<Vec<_>>();
        pids.sort_unstable();
        pids.dedup();
        if pids.is_empty() { return Err("UpdatePending: local listener is absent".into()); }
        let current = ProcessIdentity::current()?;
        let mut holders = Vec::with_capacity(pids.len());
        for &pid in &pids {
            let process = ProcessIdentity::open(pid)?;
            if !process.alive()? || process.sid() != current.sid() {
                return Err("OwnershipRequired: listener process user/lifetime differs".into());
            }
            let image = CheckedPath::open(process.image(), PathKind::File, PathPurpose::Executable)?;
            if image.native_id() != program.native_id() {
                return Err("OwnershipRequired: listener process image differs from managed program".into());
            }
            process.recheck()?;
            holders.push((process, image));
        }
        program.recheck()?;
        let result = probe(&holders);
        let mut after = crate::portcheck::listener_owners(addr, protocol)?;
        after.sort_unstable();
        if owners != after { return Err("ChangedInput: local listener owners changed during probe".into()); }
        for (process, image) in &holders {
            process.recheck()?;
            if !process.alive()? { return Err("ChangedInput: local listener process exited".into()); }
            image.recheck()?;
        }
        program.recheck()?;
        result
    }

    /// Retain each alias listener's process evidence until every address has
    /// been checked; unwinding rechecks every captured native listener row.
    /// The alias door is not contacted: accepting a connection could trigger
    /// an upstream route, which is outside this ownership observation.
    fn receive_alias_listener_owners(program: &CheckedPath, process: &ProcessIdentity,
        addresses: &[std::net::SocketAddr]) -> Result<(), String> {
        let Some((address, remaining)) = addresses.split_first() else { return Ok(()); };
        let expected_ip = match address.ip() { std::net::IpAddr::V4(ip) => ip, _ => return Err("alias address is not IPv4".into()) };
        let exact_row = || -> Result<bool, String> {
            Ok(crate::portcheck::listener_owners(*address, crate::portcheck::Proto::Tcp)?
                .iter().any(|(ip, pid)| *ip == expected_ip && *pid == process.pid()))
        };
        if !exact_row()? { return Err("exact alias listener row absent".into()); }
        let result = with_managed_listener_processes(program, *address, crate::portcheck::Proto::Tcp, |owners| {
            if owners.len() != 1 || owners[0].0.pid() != process.pid() || owners[0].0.creation() != process.creation() {
                return Err("alias listener process association changed".into());
            }
            receive_alias_listener_owners(program, process, remaining)
        });
        let after = exact_row().and_then(|present| if present { Ok(()) } else { Err("exact alias listener row changed".into()) });
        match (result, after) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(first), Ok(())) | (Ok(()), Err(first)) => Err(first),
            (Err(first), Err(after)) => Err(format!("{first}; alias recheck: {after}")),
        }
    }

    fn transport_report_for_instance(report: &crate::gate::Report, expected: crate::settings::ActiveTransportConfig,
        pid: u32, creation: u64) -> Result<(bool, crate::gate::TransportCapabilities), String> {
        if report.is_stale() || report.version != dns_forwarder::RELAY_VERSION { return Err("transport report is stale or wrong generation".into()); }
        let value = match &report.transport {
            crate::gate::TransportObservation::Valid(value) => value,
            crate::gate::TransportObservation::Absent => return Err("transport report absent".into()),
            crate::gate::TransportObservation::Invalid(error) => return Err(format!("invalid transport report: {error}")),
        };
        if pid == 0 || creation == 0 || value.schema != 1 || value.instance.pid != pid || value.instance.creation_time != creation {
            return Err("transport report process identity mismatch".into());
        }
        Ok((value.active_config == expected, value.observed.clone()))
    }

    fn receive_bound_transport(cancelled: &AtomicBool, expected: crate::settings::ActiveTransportConfig, allow_prior_anchor: bool)
        -> Result<BoundTransportObservation, String> {
        let locations = windows_installation::background_locations()?;
        let inputs = windows_installation::background_inputs(locations.managed_root(), locations.managed_directory(), None, &dns_forwarder::log_dir())?;
        let lease = windows_installation::background_lease(inputs, None)?;
        let program = windows_installation::checked_background_path(&lease, locations.managed_program(), PathKind::File)?;
        let scheduler = task_scheduler::Scheduler::connect()?;
        let programs = task_scheduler::Programs { managed: Some(&program), legacy: None };
        let selected = scheduler.receive(&["relay"], &programs, &mut Inspection(cancelled))?;
        let binding = selected.managed_binding(&program)?.ok_or("qualified relay program binding absent")?;
        binding.revalidate()?;
        let before = selected.relay_engine_pid(&programs)?;
        let dns_ip = dns_forwarder::LISTEN_IP.parse::<std::net::Ipv4Addr>().map_err(|error| format!("local DNS address: {error}"))?;
        let dns_addr = std::net::SocketAddr::from((dns_ip, dns_forwarder::LISTEN_PORT));
        let tcp_addr = crate::proxy::listen_addr();
        let receive = |addr, protocol| with_managed_listener_processes(&program, addr, protocol, |holders| {
            if holders.len() != 1 { return Err("ambiguous listener process association".into()); }
            let process = &holders[0].0;
            if process.pid() != before.1 || !process.alive()? { return Err("task engine and listener process differ".into()); }
            let report = crate::gate::receive_bound_report(&program)?;
            if !windows_installation::same_windows_path(Path::new(&report.exe), program.as_path())? {
                return Err("transport report program path mismatch".into());
            }
            match &report.installed_generation {
                crate::gate::InstalledGenerationObservation::Valid(binding) if binding.generation == dns_forwarder::RELAY_VERSION => (),
                _ => return Err("transport report program generation mismatch".into()),
            }
            let (configuration_matches, observed) = transport_report_for_instance(&report, expected, process.pid(), process.creation())?;
            if !configuration_matches {
                process.recheck()?;
                if !process.alive()? || selected.relay_engine_pid(&programs)? != before { return Err("relay task association changed".into()); }
                binding.revalidate()?;
                return Ok(BoundTransportObservation { configuration_matches: false,
                    channels: unknown_transport_channels("transport report configuration mismatch"), tcp_proxy_port: None, instance: None });
            }
            let channel = |wanted: bool, state: crate::gate::CapabilityObservation, addr, protocol,
                           probe: &dyn Fn() -> Result<(), String>| {
                use crate::gate::CapabilityObservation as C;
                if !wanted { return if state == C::Disabled { TransportChannelObservation::Received(state) }
                    else { TransportChannelObservation::Unknown("disabled capability report mismatch".into()) }; }
                if state == C::Disabled { return TransportChannelObservation::Unknown("requested capability reported disabled".into()); }
                if state != C::Ready { return TransportChannelObservation::Received(state); }
                let check = with_managed_listener_processes(&program, addr, protocol, |owners| {
                    if owners.len() != 1 || owners[0].0.pid() != process.pid() || owners[0].0.creation() != process.creation() {
                        return Err("listener process association changed".into());
                    }
                    probe()
                });
                match check {
                    Ok(()) => TransportChannelObservation::Received(C::Ready),
                    Err(error) => TransportChannelObservation::Unknown(error),
                }
            };
            let dns = channel(expected.dns, observed.dns, dns_addr, crate::portcheck::Proto::Udp,
                &|| crate::dns_client::probe_local_gate_dns(dns_ip, crate::loopback::HOSTS[0].0));
            let tcp = channel(expected.tcp_proxy, observed.tcp_proxy, tcp_addr, crate::portcheck::Proto::Tcp,
                &|| {
                    if crate::proxy::listen_addr() != tcp_addr { return Err("proxy address changed before protocol probe".into()); }
                    let result = crate::proxy::protocol_answers_at(tcp_addr, Duration::from_secs(1))
                        .map_err(|error| format!("proxy protocol probe: {error}"));
                    if crate::proxy::listen_addr() != tcp_addr {
                        return Err(match result { Ok(()) => "proxy address changed after protocol probe".into(),
                            Err(error) => format!("{error}; proxy address changed after protocol probe") });
                    }
                    result
                });
            let alias = if !expected.dns_alias && observed.dns_alias != crate::gate::CapabilityObservation::Disabled {
                TransportChannelObservation::Unknown("disabled alias report mismatch".into())
            } else if expected.dns_alias && observed.dns_alias == crate::gate::CapabilityObservation::Disabled {
                TransportChannelObservation::Unknown("requested alias reported disabled".into())
            } else if observed.dns_alias == crate::gate::CapabilityObservation::Ready {
                let addresses = crate::loopback::HOSTS.iter().map(|(_, ip)| std::net::SocketAddr::from((*ip, crate::loopback::PORT))).collect::<Vec<_>>();
                match receive_alias_listener_owners(&program, process, &addresses) {
                    Ok(()) => TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready),
                    Err(error) => TransportChannelObservation::Unknown(error),
                }
            } else { TransportChannelObservation::Received(observed.dns_alias) };
            if cancelled.load(Ordering::SeqCst) { return Err("Cancelled: transport receiving".into()); }
            process.recheck()?;
            if !process.alive()? { return Err("relay process exited during transport receiving".into()); }
            if selected.relay_engine_pid(&programs)? != before { return Err("relay task association changed".into()); }
            binding.revalidate()?;
            let tcp_proxy_port = if matches!(&tcp, TransportChannelObservation::Received(crate::gate::CapabilityObservation::Ready)) { Some(tcp_addr.port()) } else { None };
            let instance = crate::gate::TransportInstance { pid: process.pid(), creation_time: process.creation() };
            Ok(BoundTransportObservation { configuration_matches: true, channels: [dns, tcp, alias], tcp_proxy_port, instance: Some(instance) })
        });
        let mut errors = Vec::new();
        if expected.tcp_proxy || allow_prior_anchor { match receive(tcp_addr, crate::portcheck::Proto::Tcp) { Ok(value) => return Ok(value), Err(error) => errors.push(error) } }
        if expected.dns || allow_prior_anchor { match receive(dns_addr, crate::portcheck::Proto::Udp) { Ok(value) => return Ok(value), Err(error) => errors.push(error) } }
        if errors.is_empty() { errors.push("no enabled listener available for process association".into()); }
        Err(errors.join("; "))
    }
    fn probe_proxy_listener(program: &CheckedPath) -> Result<u16, String> {
        let addr = crate::proxy::listen_addr();
        with_managed_listener(program, addr, crate::portcheck::Proto::Tcp, || {
            if crate::proxy::listen_addr() != addr { return Err("ChangedInput: proxy address changed".into()); }
            if !crate::proxy::answers_at(addr) { return Err("UpdatePending: proxy listener did not accept a connection".into()); }
            if crate::proxy::listen_addr() != addr { return Err("ChangedInput: proxy address changed".into()); }
            Ok(addr.port())
        })
    }
    pub(crate) fn receive_proxy_ready(cancelled: &AtomicBool, budget: Duration) -> Result<Option<u16>, String> {
        let deadline = std::time::Instant::now() + budget;
        loop {
            if cancelled.load(Ordering::SeqCst) { return Err("Cancelled: local proxy readiness".into()); }
            match with_qualified_relay(cancelled, probe_proxy_listener) {
                Ok(port) => return Ok(Some(port)),
                Err(error) if error.starts_with("UpdatePending: local listener is absent")
                    || error.starts_with("UpdatePending: proxy listener did not accept") => {
                    if std::time::Instant::now() >= deadline { return Ok(None); }
                    thread::park_timeout(Duration::from_millis(100));
                },
                Err(error) => return Err(error),
            }
        }
    }
    fn with_qualified_relay<T>(cancelled: &AtomicBool, probe: impl FnOnce(&CheckedPath) -> Result<T, String>) -> Result<T, String> {
        let locations = windows_installation::background_locations()?;
        let inputs = windows_installation::background_inputs(locations.managed_root(),
            locations.managed_directory(), None, &dns_forwarder::log_dir())?;
        let lease = windows_installation::background_lease(inputs, None)?;
        let program = windows_installation::checked_background_path(&lease, locations.managed_program(), PathKind::File)?;
        let scheduler = task_scheduler::Scheduler::connect()?;
        let programs = task_scheduler::Programs { managed: Some(&program), legacy: None };
        let before = scheduler.receive(&["relay"], &programs, &mut Inspection(cancelled))?.receipt();
        require_running(&before, "relay")?;
        let result = probe(&program)?;
        let after = scheduler.receive(&["relay"], &programs, &mut Inspection(cancelled))?.receipt();
        require_running(&after, "relay")?;
        let mut first = before.instances;
        let mut second = after.instances;
        first.sort(); second.sort();
        if first != second { return Err("ChangedInput: relay task instances changed during probe".into()); }
        program.recheck()?;
        Ok(result)
    }
    pub(crate) fn receive_dns_ready(cancelled: &AtomicBool) -> Result<(), String> {
        loop {
            if cancelled.load(Ordering::SeqCst) { return Err("Cancelled: local DNS readiness".into()); }
            let result = with_qualified_relay(cancelled, probe_dns_listener);
            match result {
                Err(error) if error.starts_with("UpdatePending: local listener is absent") => thread::park_timeout(Duration::from_millis(100)),
                result => return result,
            }
        }
    }
    fn probe_dns_listener(program: &CheckedPath) -> Result<(), String> {
        let ip = dns_forwarder::LISTEN_IP.parse::<std::net::Ipv4Addr>()
            .map_err(|error| format!("local DNS address: {error}"))?;
        let addr = std::net::SocketAddr::from((ip, dns_forwarder::LISTEN_PORT));
        with_managed_listener(program, addr, crate::portcheck::Proto::Udp, ||
            crate::dns_client::probe_local_gate_dns(ip, crate::loopback::HOSTS[0].0))
    }

    /// True when a relay is installed and it is an older generation than this build
    /// ships - the case the user has to be told about, because the relay keeps
    /// running from `%ProgramData%` across reboots and a newer unlocker on its own
    /// changes nothing about it.
    ///
    /// This is advisory UI state; the checked receiver qualifies the actual
    /// installed image instead of treating a profile stamp as its generation.
    pub fn relay_is_outdated() -> bool {
        checked_relay_outdated().unwrap_or(false)
    }

    /// A qualified running relay can be reused. Replacing its image requires
    /// generation proof and an instance-bound stop capability.
    pub fn ensure_running() -> Result<(), String> {
        enable()
    }

    pub fn ensure_installed() -> Result<(), String> {
        ensure_installed_with_receiving().result
    }
    pub(crate) fn ensure_installed_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("ensureInstalled", |received| {
            ensure_program(received, BackgroundChanges { relay: None, watchdog: None }, ImageDemand::KeepCompatible, false).map(|_| ())
        })
    }

    /// The single quiesce/mutate/restore owner used by a required generation
    /// update and Core's temporary native undo window. Retire failure never
    /// grants the primary. Once its grant may have been delivered, restoration
    /// is attempted even after primary failure/cancellation/unwinding.
    fn invoke_primary<T: serde::Serialize>(received: &mut BackgroundRun<'_>, primary: impl FnOnce(&mut BackgroundRun<'_>) -> T)
        -> (Option<T>, Vec<String>) {
        let mut errors = Vec::new();
        let value = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| primary(received))) {
            Ok(value) => {
                match serde_json::to_value(&value) {
                    Ok(actual) => received.primary_result = Some(actual),
                    Err(error) => errors.push(format!("primary outcome serialization: {error}; typed actual outcome retained")),
                }
                Some(value)
            }
            Err(payload) => {
                received.primary_unwind = Some(payload);
                received.primary_result = Some(serde_json::json!({"execution":"unwound","nativeEffects":"unknown"}));
                errors.push("primary callback unwound; actual native effects unknown".into());
                None
            }
        };
        if let Err(error) = received.record("primaryReturned") { errors.push(error); }
        (value, errors)
    }
    fn owned_transition<T: serde::Serialize>(received: &mut BackgroundRun<'_>, program: CheckedPath,
        changes: BackgroundChanges, selected_source: Option<&windows_installation::BackgroundLease>,
        primary: impl FnOnce(&mut BackgroundRun<'_>, &CheckedPath, &mut Option<CheckedPath>) -> T)
        -> (Option<T>, Result<CheckedPath, String>) {
        #[cfg(test)]
        let synthetic = received.scheduler_fixture.is_some();
        #[cfg(not(test))]
        let synthetic = false;
        let scheduler = if synthetic { None } else {
            match task_scheduler::Scheduler::connect() {
                Ok(scheduler) => Some(scheduler),
                Err(error) => return (None, Err(error)),
            }
        };
        let mut selected = if let Some(scheduler) = &scheduler {
            let programs = task_scheduler::Programs { managed: Some(&program), legacy: None };
            match scheduler.receive(&["relay", "watchdog"], &programs, received) {
                Ok(selected) => Some(selected),
                Err(error) => return (None, Err(error)),
            }
        } else { None };
        owned_transition_selected(received, program, changes, selected.as_mut(), None, false, selected_source, primary)
    }
    /// One quiesce/update/restore body for normalized migration and ordinary
    /// image updates. A remains pinned; only an actual replacement result can
    /// supply B. The original restore capability is never rebound to B's ID.
    fn owned_transition_selected<T: serde::Serialize>(received: &mut BackgroundRun<'_>, program: CheckedPath,
        changes: BackgroundChanges, mut selected: Option<&mut task_scheduler::TaskSet<'_>>,
        legacy: Option<&windows_installation::LegacyBackgroundInput>, migration: bool,
        selected_source: Option<&windows_installation::BackgroundLease>,
        primary: impl FnOnce(&mut BackgroundRun<'_>, &CheckedPath, &mut Option<CheckedPath>) -> T)
        -> (Option<T>, Result<CheckedPath, String>) {
        let before = match received.task_state() {
            Ok(before) => before,
            Err(error) => return (None, Err(error)),
        };
        let programs = task_scheduler::Programs { managed: Some(&program), legacy };
        let restore_capability = if let Some(selected) = &selected {
            match selected.prepare_managed_restore(changes, &programs) {
                Ok(capability) => Some(capability),
                Err(error) => return (None, Err(error)),
            }
        } else { None };
        let desired = match &restore_capability {
            Some(capability) => capability.prepared_roles().desired(),
            None => match (changes.relay, changes.watchdog) {
                (Some(relay), Some(watchdog)) => BackgroundDesired { relay, watchdog },
                _ => return (None, Err("Keep restoration requires received task instances".into())),
            },
        };
        let original = match selected_source.map(|_| {
            program.recheck()?;
            let snapshot = program.read_checked_snapshot()?;
            program.recheck()?;
            received.effect(BackgroundEffect::SelectedDeliveryOriginalReceived {
                program_native_id: program.native_id(), sha256: snapshot.digest().to_owned(),
            })?;
            Ok::<_, String>(snapshot)
        }).transpose() {
            Ok(original) => original,
            Err(error) => return (None, Err(error)),
        };
        let mut replacement = None;
        let mut errors = Vec::new();
        let retired = if let Some(selected) = &mut selected {
            selected.retire(&programs, migration, restore_capability.as_ref().map(|value| value.prepared_roles()), received)
        } else { scheduler_action("shared", "retire", &program, received).map(|receipt| receipt.retired) };
        let retirement_returned = retired.is_ok();
        let mut primary_value = None;
        match retired {
            Ok(retired) => {
                if let Err(error) = received.effect(BackgroundEffect::TaskInstancesRetired(retired)) { errors.push(error); }
                if errors.is_empty() {
                    let quiescent = if let Some(selected) = &selected {
                        selected.quiescent(&programs)
                    } else { scheduler_action("shared", "quiescent", &program, received).map(|_| ()) };
                    if let Err(error) = quiescent { errors.push(error); }
                }
                // Cancellation may skip a primary not yet granted. Required
                // restoration still runs under the existing transition latch.
                if received.cancelled.load(Ordering::SeqCst) { received.cancellation_received = true; }
                else if errors.is_empty() {
                    if received.delivery_selected {
                        let check = match &selected {
                            Some(selected) => selected.transition_participants(&programs)
                                .and_then(|participants| check_selected_delivery_now(received, &participants)),
                            None => Err("OwnershipRequired: selected transition participants were not received".into()),
                        };
                        if let Err(error) = check { errors.push(error); }
                    }
                    if let Some(original) = &original {
                        let check = program.recheck().and_then(|()| program.read_checked_snapshot()).and_then(|actual| {
                            if original.matches(&actual) { program.recheck() }
                            else { Err("ChangedInput: selected delivery pre-retirement program snapshot changed".into()) }
                        });
                        if let Err(error) = check { errors.push(error); }
                    }
                    if errors.is_empty() {
                        let (value, primary_errors) = invoke_primary(received, |run| primary(run, &program, &mut replacement));
                        primary_value = value;
                        errors.extend(primary_errors);
                    }
                }
            }
            Err(error) => errors.push(error),
        }
        let restore_roles = received.restoration_pending || (migration && retirement_returned);
        let active = replacement.as_ref().unwrap_or(&program);
        let custody = match (selected_source, &original) {
            (Some(source), Some(original)) if restore_roles || replacement.is_some() => {
                (|| -> Result<(), String> {
                    let current = windows_installation::checked_background_path(received.lease()?, &received.program_path(), PathKind::File)?;
                    if current.native_id() != active.native_id() {
                        return Err("canonical program identity differs from the received restoration image".into());
                    }
                    let snapshot = current.read_checked_snapshot()?;
                    if replacement.is_some() {
                        if !snapshot.same_security(original) || snapshot.bytes() != source.source_bytes()? {
                            return Err("verified replacement bytes or security descriptor changed".into());
                        }
                    } else if !snapshot.matches(original) {
                        return Err("original program content or metadata changed and no replacement was received".into());
                    }
                    current.recheck()?;
                    active.recheck()
                })()
            }
            _ => Ok(()),
        }.map_err(|cause| format!("RecoveryRequired: selected delivery program custody unresolved before Run: {cause}"));
        if restore_roles {
            received.restoring = received.restoration_pending;
            let mut restoration_errors = Vec::new();
            // Fresh positive zero-instance receiving is required before Run.
            // An already-running qualified wanted role is preserved as a no-op;
            // absent-before roles are provisioned only by normal reconciliation.
            if let Err(cause) = custody {
                received.restoration_pending = true;
                restoration_errors.push(cause);
            } else {
                if original.is_some() {
                    if let Err(error) = received.effect(BackgroundEffect::SelectedDeliveryRestorationImageReceived {
                        program_native_id: active.native_id(), replacement: replacement.is_some(),
                    }) { errors.push(error); }
                }
                if let (Some(selected), Some(capability)) = (&selected, &restore_capability) {
                    let active_programs = task_scheduler::Programs { managed: Some(active), legacy: None };
                    let restored = if replacement.is_some() {
                        selected.restore_replaced(capability.prepared_roles(), desired, &active_programs, migration, received)
                    } else if migration {
                        selected.restore_migrated(capability, desired, &active_programs, received)
                    } else {
                        selected.restore_prepared(capability, desired, &active_programs, received)
                    };
                    if let Err(error) = restored { restoration_errors.push(error); }
                } else {
                    for (was_present, wanted, role) in [
                        (before.watchdog_enabled, desired.watchdog, "watchdog"),
                        (before.relay_enabled, desired.relay, "relay"),
                    ] {
                        if was_present && wanted {
                            if let Err(error) = scheduler_action(role, "resume", active, received)
                                .and_then(|receipt| require_running(&receipt, role)) {
                                restoration_errors.push(format!("{role}: {error}"));
                            }
                        }
                    }
                }
            }
            received.restoring = false;
            let restoration = if restoration_errors.is_empty() { Ok(()) } else { Err(restoration_errors.join("; ")) };
            received.restoration_result = Some(restoration.clone());
            if restoration.is_ok() {
                received.restoration_pending = false;
            } else if let Err(error) = restoration { errors.push(format!("required restoration: {error}")); }
            if let Err(error) = received.record("wantedRoleRestorationReceivedHealthUnverified") { errors.push(error); }
        } else if let Err(cause) = custody {
            // No role was retired. Hold later provisioning of a replacement
            // that could not be received, without inventing restoration debt.
            errors.push(cause);
        }
        if let Err(error) = received.ready() { errors.push(error); }
        drop(restore_capability);
        drop(programs);
        let program = replacement.unwrap_or(program);
        if errors.is_empty() { (primary_value, Ok(program)) }
        else { (primary_value, Err(errors.join("; "))) }
    }

    #[derive(serde::Serialize)]
    pub(crate) struct SuspendedBackgroundReceiving<T> {
        pub(crate) primary: Option<T>,
        pub(crate) background: BackgroundReceiving,
    }
    fn current_program_inputs(received: &BackgroundRun<'_>, scheduler: &task_scheduler::Scheduler)
        -> Result<(Option<CheckedPath>, Option<windows_installation::LegacyBackgroundInput>), String> {
        let locations = windows_installation::background_locations()?;
        let legacy = if scheduler.references_program(locations.legacy_program())? {
            Some(windows_installation::legacy_background_input(&locations)?
                .ok_or("OwnershipRequired: selected legacy program is absent")?)
        } else { None };
        let managed = if scheduler.references_program(locations.managed_program())? {
            Some(windows_installation::checked_background_path(received.lease()?, locations.managed_program(), PathKind::File)?)
        } else { None };
        Ok((managed, legacy))
    }

    fn legacy_roles_already_running(received: &mut BackgroundRun<'_>, desired: BackgroundDesired) -> Result<bool, String> {
        let scheduler = task_scheduler::Scheduler::connect()?;
        let (managed, legacy) = current_program_inputs(received, &scheduler)?;
        if legacy.is_none() { return Ok(false); }
        let programs = task_scheduler::Programs { managed: managed.as_ref(), legacy: legacy.as_ref() };
        for (wanted, role) in [(desired.relay, "relay"), (desired.watchdog, "watchdog")] {
            let receipt = scheduler.receive(&[role], &programs, received)?.receipt();
            if wanted {
                if !receipt.present || receipt.instances.is_empty() { return Ok(false); }
                require_running(&receipt, role)?;
            } else if receipt.present { return Ok(false); }
        }
        received.effect(BackgroundEffect::CompatibleNoop)?;
        Ok(true)
    }
    /// Core owns the callback's exact result type and external file effects.
    /// The background owner retains the same typed value, its diagnostic form,
    /// and the independent restoration outcome; None means never invoked.
    pub(crate) fn with_suspended_background<T: serde::Serialize>(desired: BackgroundDesired,
        cancelled: &AtomicBool, image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>,
        primary: impl FnOnce() -> T) -> SuspendedBackgroundReceiving<T> {
        with_suspended_background_changes(desired.into(), cancelled, image, primary)
    }

    pub(crate) fn with_suspended_background_changes<T: serde::Serialize>(changes: BackgroundChanges,
        cancelled: &AtomicBool, image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>,
        primary: impl FnOnce() -> T) -> SuspendedBackgroundReceiving<T> {
        let mut actual_primary = None;
        let background = receiving("suspendForNativeClientWork", cancelled, Some(image), |received| {
            received.ready()?;
            let before = received.task_state()?;
            if !before.relay_enabled && !before.watchdog_enabled {
                // No background actor needs suspension. Unrelated leftover
                // program bytes are not a prerequisite for native client work.
                received.ready()?;
                let (actual, errors) = invoke_primary(received, |_| primary());
                actual_primary = actual;
                return if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) };
            }
            let scheduler = task_scheduler::Scheduler::connect()?;
            let (managed, legacy) = current_program_inputs(received, &scheduler)?;
            let programs = task_scheduler::Programs { managed: managed.as_ref(), legacy: legacy.as_ref() };
            let mut selected = scheduler.receive(&["relay", "watchdog"], &programs, received)?;
            let restore_capability = selected.prepare_managed_restore(changes, &programs)?;
            let desired = restore_capability.prepared_roles().desired();
            let mut errors = Vec::new();
            match selected.retire(&programs, false, Some(restore_capability.prepared_roles()), received).and_then(|retired| {
                received.effect(BackgroundEffect::TaskInstancesRetired(retired))?;
                selected.quiescent(&programs)
            }) {
                Ok(()) => {
                    if received.cancelled.load(Ordering::SeqCst) { received.cancellation_received = true; }
                    else {
                        let (actual, primary_errors) = invoke_primary(received, |_| primary());
                        actual_primary = actual;
                        errors.extend(primary_errors);
                    }
                }
                Err(error) => errors.push(error),
            }
            if received.restoration_pending {
                received.restoring = true;
                let restoration = selected.restore_prepared(&restore_capability, desired, &programs, received);
                received.restoring = false;
                received.restoration_result = Some(restoration.clone());
                match restoration { Ok(()) => received.restoration_pending = false,
                    Err(error) => errors.push(format!("required original-role restoration: {error}")) }
                if let Err(error) = received.record("temporaryRoleRestorationReceived") { errors.push(error); }
            }
            if let Err(error) = received.ready() { errors.push(error); }
            if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
        });
        SuspendedBackgroundReceiving { primary: actual_primary, background }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ActualGeneration {
        NoInstallation,
        SameCurrentImage,
        Bound(u32),
        Unknown(String),
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CurrentImageDecision { ReuseCurrent, UpdateRequired }

    fn generation_for_program(program: &CheckedPath, same_selected_bytes: bool) -> ActualGeneration {
        if same_selected_bytes { return ActualGeneration::SameCurrentImage; }
        match crate::gate::receive_bound_generation(program) {
            crate::gate::BoundGeneration::Bound(value) => ActualGeneration::Bound(value),
            crate::gate::BoundGeneration::Unknown(cause) => ActualGeneration::Unknown(cause),
        }
    }
    fn current_image_decision(generation: &ActualGeneration, compatible: bool, demand: ImageDemand)
        -> Result<CurrentImageDecision, String> {
        if demand == ImageDemand::KeepCompatible && compatible { return Ok(CurrentImageDecision::ReuseCurrent); }
        match generation {
            ActualGeneration::NoInstallation => Ok(CurrentImageDecision::UpdateRequired),
            ActualGeneration::SameCurrentImage => Ok(CurrentImageDecision::ReuseCurrent),
            ActualGeneration::Bound(value) if *value > dns_forwarder::RELAY_VERSION =>
                Err("UpdatePending: installed generation is newer; downgrade was not admitted".into()),
            ActualGeneration::Bound(value) if *value == dns_forwarder::RELAY_VERSION && demand == ImageDemand::KeepCompatible =>
                Ok(CurrentImageDecision::ReuseCurrent),
            ActualGeneration::Bound(_) => Ok(CurrentImageDecision::UpdateRequired),
            ActualGeneration::Unknown(cause) => Err(format!("OwnershipRequired: installed generation unknown: {cause}")),
        }
    }
    fn record_generation_observation(received: &mut BackgroundRun<'_>, generation: &ActualGeneration) -> Result<(), String> {
        let metadata = match generation {
            ActualGeneration::NoInstallation => Ok(None),
            ActualGeneration::SameCurrentImage => Ok(Some(dns_forwarder::RELAY_VERSION)),
            ActualGeneration::Bound(value) => Ok(Some(*value)),
            ActualGeneration::Unknown(cause) => Err(cause.clone()),
        };
        received.effect(BackgroundEffect::GenerationObserved { metadata, runtime: None })
    }
    fn selected_retirement_decision(proofs: impl IntoIterator<Item = ActualGeneration>,
        mut record: impl FnMut(&ActualGeneration) -> Result<(), String>) -> Result<(), String> {
        for proof in proofs {
            record(&proof)?;
            current_image_decision(&proof, false, ImageDemand::DeliverSelectedImage)?;
        }
        Ok(())
    }
    fn receive_current_image_decision(received: &mut BackgroundRun<'_>, program: &CheckedPath,
        selected: &task_scheduler::TaskSet<'_>, demand: ImageDemand)
        -> Result<(CurrentImageDecision, Option<std::sync::Arc<windows_installation::BackgroundLease>>), String> {
        let binding = selected.managed_binding(program)?
            .ok_or("OccupiedStateHold: managed image has no current qualified task/program binding")?;
        binding.revalidate()?;
        require_owned_occupancy(OccupancyOwnership::CurrentManagedBinding)?;
        use sha2::Digest;
        let bytes = program.read_snapshot()?;
        binding.revalidate()?;
        received.effect(BackgroundEffect::CurrentProgramReceived { program_native_id: program.native_id(),
            sha256: hex::encode(sha2::Sha256::digest(&bytes)) })?;
        let compatible = received.relay_compatible()?;
        if demand == ImageDemand::KeepCompatible && compatible {
            received.effect(BackgroundEffect::CompatibleNoop)?;
            return Ok((CurrentImageDecision::ReuseCurrent, None));
        }
        let source = if demand == ImageDemand::DeliverSelectedImage { Some(receive_copy_source(received)?) } else { None };
        let same = source.as_ref().map(|lease| lease.source_bytes().map(|source| source == bytes.as_slice())).transpose()?.unwrap_or(false);
        let proof = generation_for_program(program, same);
        binding.revalidate()?;
        record_generation_observation(received, &proof)?;
        let decision = current_image_decision(&proof, compatible, demand)?;
        if compatible && decision == CurrentImageDecision::ReuseCurrent { received.effect(BackgroundEffect::CompatibleNoop)?; }
        Ok((decision, source))
    }
    fn metadata_failure_evidence(failure: &windows_installation::MetadataFailure) -> serde_json::Value {
        serde_json::json!({"phase":failure.phase,"cause":failure.cause,
            "replaceResult":failure.replace_result,"evidence":failure.evidence})
    }
    fn preflight_generation_publication() -> Result<(), String> {
        let gate = crate::gate::path().ok_or("metadata preflight (GateReport): canonical path absent")?;
        windows_installation::preflight_user_metadata(&gate)
            .map_err(|error| format!("metadata preflight (GateReport): {error}"))?;
        windows_installation::preflight_user_metadata(&dns_forwarder::version_path())
            .map_err(|error| format!("metadata preflight (RelayVersionProjection): {error}"))
    }
    fn record_published_generation(received: &mut BackgroundRun<'_>, program: &CheckedPath,
        source: &windows_installation::BackgroundLease) -> Result<(), String> {
        if program.read_snapshot()?.as_slice() != source.source_bytes()? {
            return Err("published program differs from the held selected image".into());
        }
        program.recheck()?;
        received.effect(BackgroundEffect::GenerationWriteRequested)?;
        record_generation_binding(received, program, None)?;
        source.source_bytes()?;
        program.recheck()?;
        record_generation_projection(received, None)?;
        source.source_bytes()?;
        program.recheck()
    }

    fn record_generation_binding(received: &mut BackgroundRun<'_>, program: &CheckedPath,
        preflight: Option<&windows_installation::UserMetadataPreflight>) -> Result<(), String> {
        received.ready()?;
        let binding = match crate::gate::publish_program_generation(program, preflight) {
            Ok(value) => value,
            Err(mut error) => {
                received.receive_metadata_failure(&mut error);
                let message = error.to_string();
                received.generation_writes.push(metadata_failure_evidence(&error));
                return Err(match received.record("generationBindingFailed") {
                    Ok(()) => message,
                    Err(retention) => format!("{message}; {retention}"),
                });
            }
        };
        received.metadata_publications.push(binding);
        let evidence = received.metadata_publications.last().unwrap().evidence().clone();
        received.generation_writes.push(evidence);
        received.record("generationBindingPublished")
    }

    fn record_generation_projection(received: &mut BackgroundRun<'_>,
        preflight: Option<&windows_installation::UserMetadataPreflight>) -> Result<(), String> {
        received.ready()?;
        let scalar = windows_installation::publish_user_metadata_checked(windows_installation::UserMetadataField::RelayVersionProjection,
            &dns_forwarder::version_path(), dns_forwarder::RELAY_VERSION.to_string().as_bytes(), preflight);
        match scalar {
            Ok(publication) => {
                received.metadata_publications.push(publication);
                let evidence = received.metadata_publications.last().unwrap().evidence().clone();
                received.generation_writes.push(evidence);
                received.record("generationProjectionPublished")
            }
            Err(mut error) => {
                received.receive_metadata_failure(&mut error);
                let message = error.to_string();
                received.generation_writes.push(metadata_failure_evidence(&error));
                Err(match received.record("generationWriteFailed") {
                    Ok(()) => message,
                    Err(retention) => format!("{message}; {retention}"),
                })
            }
        }
    }

    fn projection_generation(data: &[u8]) -> Result<u32, String> {
        let text = std::str::from_utf8(data).map_err(|_| "generation projection is not UTF-8")?;
        let value = text.trim().parse::<u32>().map_err(|_| "generation projection is invalid")?;
        if value == 0 { return Err("generation projection is zero".into()); }
        Ok(value)
    }

    fn require_current_generation_projection(path: &Path) -> Result<(), String> {
        let data = windows_installation::read_protected_user_metadata(path)?.ok_or("protected generation projection absent")?;
        if projection_generation(&data)? != dns_forwarder::RELAY_VERSION {
            return Err("protected generation projection differs from the selected image".into());
        }
        Ok(())
    }

    /// Called only by the ordinary, explicitly selected Windows Repair command.
    /// A handled result owns only metadata and never enters task reconciliation.
    pub(crate) fn repair_current_generation_with_receiving(cancelled: &AtomicBool,
        image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>) -> (bool, BackgroundReceiving) {
        let mut handled = false;
        let actual = receiving("repairCurrentGenerationMetadata", cancelled, Some(image), |run| {
            let locations = windows_installation::background_locations()?;
            let path = locations.managed_program();
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(format!("generation repair program observation: {error}")),
                Ok(_) => {}
            }
            let scheduler = task_scheduler::Scheduler::connect()?;
            if scheduler.references_program(locations.legacy_program())? { return Ok(()); }
            let program = windows_installation::checked_background_path(run.lease()?, path, PathKind::File)?;
            let source = receive_copy_source(run)?;
            if program.read_snapshot()?.as_slice() != source.source_bytes()? { return Ok(()); }
            let programs = task_scheduler::Programs { managed: Some(&program), legacy: None };
            let selected = scheduler.receive(&["relay", "watchdog"], &programs, run)?;
            let binding = selected.managed_binding(&program)?
                .ok_or("OwnershipRequired: current image has no qualified managed task binding")?;
            let recheck = || -> Result<(), String> {
                binding.revalidate()?;
                selected.transition_participants(&programs)?;
                if program.read_snapshot()?.as_slice() != source.source_bytes()? {
                    return Err("ChangedInput: selected image differs from the protected managed program".into());
                }
                Ok(())
            };
            recheck()?;
            handled = complete_current_generation(run, &program, recheck)?;
            Ok(())
        });
        (handled, actual)
    }

    fn complete_current_generation(run: &mut BackgroundRun<'_>, program: &CheckedPath,
        recheck: impl Fn() -> Result<(), String>) -> Result<bool, String> {
        let gate_path = crate::gate::path().ok_or("generation repair report path unavailable")?;
        let projection_path = dns_forwarder::version_path();
        let report = windows_installation::receive_user_metadata_preflight(&gate_path)
            .map_err(|error| format!("GateReport preflight: {error}"))?;
        let projection = windows_installation::receive_user_metadata_preflight(&projection_path)
            .map_err(|error| format!("RelayVersionProjection preflight: {error}"))?;
        let repair_report = crate::gate::generation_repair_required(&report, program)?;
        let repair_projection = match projection.bytes().map(projection_generation).transpose()? {
            None => true,
            Some(value) if value < dns_forwarder::RELAY_VERSION => true,
            Some(value) if value == dns_forwarder::RELAY_VERSION => {
                require_current_generation_projection(&projection_path)?;
                false
            }
            Some(_) => return Err("generation projection is newer than the selected image".into()),
        };
        recheck()?;
        if !repair_report && !repair_projection { return Ok(false); }
        run.effect(BackgroundEffect::GenerationWriteRequested)?;
        if repair_report { record_generation_binding(run, program, Some(&report))?; }
        let result = crate::gate::require_current_generation(program);
        run.generation_reads.push(serde_json::json!({"field":"GateReport","currentGeneration":result}));
        run.record("currentGenerationBindingReceived")?;
        result?;
        if repair_projection {
            recheck()?;
            record_generation_projection(run, Some(&projection))?;
        }
        let result = require_current_generation_projection(&projection_path);
        run.generation_reads.push(serde_json::json!({"field":"RelayVersionProjection","currentGeneration":result}));
        run.record("currentGenerationProjectionReceived")?;
        result?;
        recheck()?;
        Ok(true)
    }
    fn recheck_delivery_transition(received: &mut BackgroundRun<'_>, selected: &task_scheduler::TaskSet<'_>,
        programs: &task_scheduler::Programs<'_>) -> Result<(), String> {
        check_selected_delivery_now(received, &selected.transition_participants(programs)?)
    }
    fn require_absent_program(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("background program observation: {error}")),
            Ok(_) => Err("OccupiedStateHold: program exists without a selected task binding".into()),
        }
    }
    fn check_selected_delivery_now(received: &mut BackgroundRun<'_>, participants: &task_scheduler::TransitionParticipants<'_>) -> Result<(), String> {
        if !received.delivery_selected { return Ok(()); }
        received.ready()?;
        if let Some(prior) = &received.prior_transition {
            if prior.serial != received.diagnostic.id || prior.authenticated.serial() != prior.serial {
                return Err("ChangedInput: prior repair authorization belongs to another operation".into());
            }
            let actual = windows_installation::checked_background_path(received.lease()?, &received.program_path(), PathKind::File)?;
            if actual.native_id() != prior.program_id || !prior.original.matches(&actual.read_checked_snapshot()?) {
                return Err("ChangedInput: the protected original image changed after prior repair authorization".into());
            }
            actual.recheck()?;
            prior.source.source_capture()?;
            prior.authenticated.revalidate()?;
            require_unbound_prior_report(Some(prior.authenticated.generation()))?;
            let events = received.task_events.get(prior.before_task_events..).ok_or("prior repair task evidence changed")?;
            require_exact_prior_roles(&prior.roles, participants.current(), events)?;
            return Ok(());
        }
        let paths = participants.program_paths().map(Path::to_path_buf).collect::<Vec<_>>();
        if paths.is_empty() {
            require_absent_program(&received.program_path())?;
            return record_generation_observation(received, &ActualGeneration::NoInstallation);
        }
        let source = receive_copy_source(received)?;
        let locations = windows_installation::background_locations()?;
        let mut proofs = Vec::new();
        for path in paths {
            let proof = if windows_installation::same_windows_path(&path, locations.managed_program())? {
                let program = windows_installation::checked_background_path(received.lease()?, locations.managed_program(), PathKind::File)?;
                let same = program.read_snapshot()?.as_slice() == source.source_bytes()?;
                let proof = generation_for_program(&program, same);
                program.recheck()?;
                proof
            } else if windows_installation::same_windows_path(&path, locations.legacy_program())? {
                let legacy = windows_installation::legacy_background_input(&locations)?
                    .ok_or("OwnershipRequired: selected legacy program is absent")?;
                legacy.revalidate()?;
                let same = legacy.checked_file().read_snapshot()?.as_slice() == source.source_bytes()?;
                let proof = generation_for_program(legacy.checked_file(), same);
                legacy.revalidate()?;
                proof
            } else { ActualGeneration::Unknown("participant is outside received program owners".into()) };
            proofs.push(proof);
        }
        selected_retirement_decision(proofs, |proof| record_generation_observation(received, proof))?;
        source.source_bytes()?;
        Ok(())
    }

    fn require_unbound_prior_report(expected_generation: Option<u32>) -> Result<(), String> {
        let path = crate::gate::path().ok_or("prior repair generation report path unavailable")?;
        let current = windows_installation::receive_user_metadata_preflight(&path)?;
        let data = current.bytes().ok_or("PriorAuthenticationUnavailable: no old-format generation report was received")?;
        check_unbound_prior_report(data, expected_generation)
    }

    fn check_unbound_prior_report(data: &[u8], expected_generation: Option<u32>) -> Result<(), String> {
        let report: crate::gate::Report = serde_json::from_slice(data).map_err(|error| format!("invalid prior generation report: {error}"))?;
        match report.installed_generation {
            crate::gate::InstalledGenerationObservation::Absent => {}
            crate::gate::InstalledGenerationObservation::Invalid(cause) => return Err(format!("invalid prior generation binding: {cause}")),
            crate::gate::InstalledGenerationObservation::Valid(_) => return Err("ChangedInput: an installed generation binding is now present".into()),
        }
        if report.version == 0 || report.version > dns_forwarder::RELAY_VERSION
            || expected_generation.is_some_and(|generation| report.version != generation) {
            return Err("PriorAuthenticationUnavailable: old-format report does not agree with the selected and authenticated generations".into());
        }
        // The runtime version only corroborates the old-format observation.
        // It never proves the installed image or constructs a prior grant.
        Ok(())
    }

    fn require_exact_prior_roles(approved: &[task_scheduler::DefinitionView], current: &[task_scheduler::DefinitionView],
        events: &[task_scheduler::Event]) -> Result<(), String> {
        use task_scheduler::{ErrorInfo, Event};
        let stopped: std::collections::BTreeSet<_> = events.iter().filter_map(|event| match event {
            Event::Call(call) if call.operation == "StopExactInstance" && call.returned_hresult == Some(0)
                && matches!(&call.error_info, ErrorInfo::NoInfo { hresult: 1 }) => call.instance.as_deref(),
            _ => None,
        }).collect();
        let retired: std::collections::BTreeSet<_> = events.iter().filter_map(|event| match event {
            Event::InstanceRetired(instance) if stopped.contains(instance.guid.as_str()) => Some(instance.guid.as_str()),
            _ => None,
        }).collect();
        let mut expected = approved.to_vec();
        for role in &mut expected { role.instances.retain(|instance| !retired.contains(instance.guid.as_str())); }
        if current != expected.as_slice() {
            return Err("ChangedInput: task definitions, principals, security or instances changed after prior repair authorization".into());
        }
        Ok(())
    }
    fn apply_program_update(received: &mut BackgroundRun<'_>, program: &CheckedPath,
        source_lease: &windows_installation::BackgroundLease, same_bytes: bool,
        replacement: &mut Option<CheckedPath>) -> Result<(), String> {
        source_lease.source_bytes()?;
        if !same_bytes {
            receive_program_replacement(received, windows_installation::background_replace_program(source_lease, program), replacement)?;
        }
        source_lease.source_bytes()?;
        let published = replacement.as_ref().unwrap_or(program);
        record_published_generation(received, published, source_lease)
    }

    fn receive_program_replacement(received: &mut BackgroundRun<'_>, actual: Result<windows_installation::BackgroundReplacementReceiving,
        windows_installation::BackgroundReplacementFailure>, replacement: &mut Option<CheckedPath>) -> Result<(), String> {
        match actual {
            Ok(actual) => {
                received.replacements.push(actual.evidence);
                *replacement = Some(actual.program);
                received.record("programReplacementReceived")
            }
            Err(failure) => {
                let message = failure.to_string();
                received.replacements.push(serde_json::json!({"phase":failure.phase,"cause":failure.cause,
                    "replaceResult":failure.replace_result,"evidence":failure.evidence}));
                Err(match received.record("programReplacementFailed") {
                    Ok(()) => message,
                    Err(retention) => format!("{message}; {retention}"),
                })
            }
        }
    }
    fn receive_copy_source(received: &mut BackgroundRun<'_>) -> Result<std::sync::Arc<windows_installation::BackgroundLease>, String> {
        received.ready()?;
        let image = received.image.as_ref().ok_or("source-selection hold: current image was not received")?
            .clone().map_err(|error| format!("source-selection hold: {error}"))?;
        let inputs = windows_installation::background_inputs_selected(
            received.program_directory.parent().ok_or("background ProgramData parent absent")?,
            &received.program_directory, image, &received.diagnostic.directory)?;
        let observation = inputs.source_observation()?;
        // Same worker/thread and existing reentrant native namespace mutex.
        let lease = std::sync::Arc::new(windows_installation::background_lease(inputs, None)
            .map_err(|cause| format!("{cause}; rejected source observation: {observation}"))?);
        received.source_leases.push(lease.clone());
        Ok(lease)
    }

    fn create_managed_image(received: &mut BackgroundRun<'_>, source_lease: &windows_installation::BackgroundLease) -> Result<CheckedPath, String> {
        let destination = received.program_path();
        let (source_native_id, bytes) = source_lease.source_capture()?;
        use sha2::Digest;
        let source_sha256 = hex::encode(sha2::Sha256::digest(bytes));
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                let existing = windows_installation::checked_background_path(source_lease, &destination, PathKind::File)?;
                if let Some(created) = &received.created_program {
                    created.guard.recheck()?;
                    if created.guard.native_id() != existing.native_id() || created.source_sha256 != source_sha256 {
                        return Err("OccupiedStateHold: live creation identity/source receiving differs".into());
                    }
                    require_owned_occupancy(OccupancyOwnership::LiveCreator)?;
                } else { require_owned_occupancy(OccupancyOwnership::Unproved)?; }
                if existing.read_snapshot()? != bytes {
                    return Err("OccupiedStateHold: same-live created image differs from its received source".into());
                }
                return Ok(existing);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("managed program observation: {error}")),
        }
        let directory = received.program_directory.clone();
        match fs::symlink_metadata(&directory) {
            Ok(_) => {
                if received.created_directory.is_none() { require_owned_occupancy(OccupancyOwnership::Unproved)?; }
                let created = received.created_directory.as_ref().ok_or("occupied directory has no creator guard")?;
                created.recheck()?;
                let current = windows_installation::checked_background_path(source_lease, &directory, PathKind::Directory)?;
                if current.native_id() != created.native_id() { return Err("OccupiedStateHold: created directory identity changed".into()); }
                require_owned_occupancy(OccupancyOwnership::LiveCreator)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                source_lease.source_bytes()?;
                received.effect(BackgroundEffect::DirectoryCreateRequested)?;
                received.ready()?;
                windows_installation::create_background_directory(source_lease, &directory)?;
                received.created_directory = Some(windows_installation::checked_background_path(source_lease, &directory, PathKind::Directory)?);
                received.effect(BackgroundEffect::DirectoryCreateReturnedSuccess)?;
            }
            Err(error) => return Err(format!("managed directory observation: {error}")),
        }
        let parent = windows_installation::checked_background_path(source_lease, &directory, PathKind::Directory)?;
        source_lease.source_bytes()?;
        received.effect(BackgroundEffect::ProgramCreateRequested)?;
        received.ready()?;
        let mut output = windows_installation::create_background_executable(source_lease, &destination)?;
        received.effect(BackgroundEffect::ProgramCreateReturnedSuccess)?;
        source_lease.source_bytes()?;
        output.write_all(bytes).and_then(|_| output.sync_all()).map_err(|error| format!("PreparationIncomplete: managed image write: {error}; preserve it"))?;
        drop(output);
        source_lease.source_bytes()?;
        let installed = windows_installation::checked_background_path(source_lease, &destination, PathKind::File)?;
        if installed.read_snapshot()?.as_slice() != bytes { return Err("PreparationIncomplete: new managed image readback differs".into()); }
        parent.recheck()?;
        received.created_program = Some(CreatedManagedProgram {
            guard: windows_installation::checked_background_path(source_lease, &destination, PathKind::File)?, source_sha256,
        });
        received.effect(BackgroundEffect::ProgramReadbackReceived { program: installed.as_path().to_path_buf(),
            program_native_id: installed.native_id(), source_native_id,
            sha256: hex::encode(sha2::Sha256::digest(bytes)), generation: dns_forwarder::RELAY_VERSION })?;
        Ok(installed)
    }

    fn migrate_legacy(received: &mut BackgroundRun<'_>, changes: BackgroundChanges, demand: ImageDemand) -> Result<CheckedPath, String> {
        // Migration itself changes task associations and may retire an old
        // participant, even when the caller did not request a new image.
        received.delivery_selected = true;
        let locations = windows_installation::background_locations()?;
        let legacy = windows_installation::legacy_background_input(&locations)?
            .ok_or("OwnershipRequired: selected legacy task has no received legacy program")?;
        let scheduler = task_scheduler::Scheduler::connect()?;
        let existing = match fs::symlink_metadata(locations.managed_program()) {
            Ok(_) => Some(windows_installation::checked_background_path(received.lease()?, locations.managed_program(), PathKind::File)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("managed image inspection: {error}")),
        };
        let before = task_scheduler::Programs { managed: existing.as_ref(), legacy: Some(&legacy) };
        let mut selected = scheduler.receive(&["relay", "watchdog"], &before, received)?;
        if !selected.has_legacy() { return Err("ChangedInput: legacy migration association disappeared before preparation".into()); }
        recheck_delivery_transition(received, &selected, &before)?;
        drop(before);
        let mut created_source = None;
        let (managed, update) = match existing {
            Some(managed) => {
                let (decision, source) = receive_current_image_decision(received, &managed, &selected, demand)?;
                if decision == CurrentImageDecision::UpdateRequired || source.is_some() {
                    preflight_generation_publication()?;
                }
                match decision {
                    CurrentImageDecision::ReuseCurrent => {
                        created_source = source;
                        (managed, None)
                    }
                    CurrentImageDecision::UpdateRequired => {
                        let lease = match source { Some(lease) => lease, None => receive_copy_source(received)? };
                        let same_bytes = managed.read_snapshot()?.as_slice() == lease.source_bytes()?;
                        (managed, Some((lease, same_bytes)))
                    }
                }
            },
            None => {
                let lease = receive_copy_source(received)?;
                let programs = task_scheduler::Programs { managed: None, legacy: Some(&legacy) };
                recheck_delivery_transition(received, &selected, &programs)?;
                preflight_generation_publication()?;
                let managed = create_managed_image(received, &lease)?;
                lease.source_bytes()?;
                created_source = Some(lease);
                (managed, None)
            }
        };
        let programs = task_scheduler::Programs { managed: Some(&managed), legacy: Some(&legacy) };
        for lease in &received.source_leases { lease.source_bytes()?; }
        recheck_delivery_transition(received, &selected, &programs)?;
        if let Err(error) = selected.update_paths(&programs, received) {
            let observed = scheduler.receive(&["relay", "watchdog"], &programs, received);
            return Err(match observed { Ok(_) => error, Err(observation) => format!("{error}; current mixed-state receiving: {observation}") });
        }
        drop(programs);
        if let Some((lease, _)) = &update { lease.source_bytes()?; }
        let selected_source = update.as_ref().map(|(lease, _)| lease.as_ref());
        let (primary, outcome) = owned_transition_selected(received, managed, changes, Some(&mut selected), Some(&legacy), true, selected_source,
            |run, program, replacement| match &update {
                Some((lease, same_bytes)) => apply_program_update(run, program, lease, *same_bytes, replacement),
                None => Ok(()),
            });
        let program = outcome?;
        match primary {
            Some(Ok(())) => {
                if let Some(source) = created_source { record_published_generation(received, &program, &source)?; }
                Ok(program)
            },
            Some(Err(error)) => Err(error),
            None => Err("UpdatePending: association/update primary was not invoked; actual role restoration retained".into()),
        }
    }

    fn ensure_managed_program(received: &mut BackgroundRun<'_>, installed: CheckedPath, scheduler: &task_scheduler::Scheduler,
        changes: BackgroundChanges, demand: ImageDemand, explicit_prior_repair: bool,
        clean_only: bool) -> Result<Option<CheckedPath>, String> {
        let known = task_scheduler::Programs { managed: Some(&installed), legacy: None };
        let mut selected = scheduler.receive(&["relay", "watchdog"], &known, received)?;
        let (decision, source) = if explicit_prior_repair {
            selected.managed_binding(&installed)?.ok_or("OwnershipRequired: managed image has no current qualified task/program binding")?.revalidate()?;
            let source = receive_copy_source(received)?;
            let original = installed.read_checked_snapshot()?;
            if original.bytes() == source.source_bytes()? { return Ok(None); }
            let proof = generation_for_program(&installed, false);
            let ActualGeneration::Unknown(gate_failure) = &proof else { return Ok(None); };
            record_generation_observation(received, &proof)?;
            require_unbound_prior_report(None)?;
            selected.prepare_managed_restore(changes, &known)?;
            let current_roles = selected.transition_participants(&known)?.current().to_vec();
            let serial = received.diagnostic.id.clone();
            let authenticated = prior_transition::confirm(&installed, &source, &serial, &current_roles, changes, gate_failure)?;
            if authenticated.generation() == 0 || authenticated.generation() > dns_forwarder::RELAY_VERSION {
                return Err("UpdatePending: authenticated prior generation is incompatible with the selected image".into());
            }
            received.ready()?;
            let provenance = authenticated.provenance().clone();
            let before_task_events = received.task_events.len();
            received.prior_transition = Some(ExactExistingTransition { serial, program_id: installed.native_id(), original,
                source: source.clone(), roles: current_roles, before_task_events, authenticated });
            recheck_delivery_transition(received, &selected, &known)?;
            received.effect(BackgroundEffect::PriorDeliveryAuthenticated { provenance })?;
            (CurrentImageDecision::UpdateRequired, Some(source))
        } else {
            receive_current_image_decision(received, &installed, &selected, demand)?
        };
        if decision == CurrentImageDecision::ReuseCurrent { return Ok(Some(installed)); }
        if clean_only { return Err(CLEAN_INSTALL_REQUIRED.into()); }
        let source_lease = match source { Some(lease) => lease, None => receive_copy_source(received)? };
        let same_bytes = installed.read_snapshot()?.as_slice() == source_lease.source_bytes()?;
        if demand == ImageDemand::DeliverSelectedImage {
            recheck_delivery_transition(received, &selected, &known)?;
            preflight_generation_publication()?;
        }
        drop(known);
        let selected_source = (demand == ImageDemand::DeliverSelectedImage).then_some(source_lease.as_ref());
        let replace = |run: &mut BackgroundRun<'_>, program: &CheckedPath, replacement: &mut Option<CheckedPath>| {
            apply_program_update(run, program, &source_lease, same_bytes, replacement)
        };
        let (primary, outcome) = if explicit_prior_repair {
            owned_transition_selected(received, installed, changes, Some(&mut selected), None, false, selected_source, replace)
        } else {
            drop(selected);
            owned_transition(received, installed, changes, selected_source, replace)
        };
        drop(received.prior_transition.take());
        let program = outcome?;
        match primary {
            Some(Ok(())) => Ok(Some(program)),
            Some(Err(error)) => Err(error),
            None => Err("UpdatePending: executable update primary was not invoked; received roles were restored".into()),
        }
    }

    fn receive_stopped_tasks(run: &mut BackgroundRun<'_>, scheduler: &task_scheduler::Scheduler, program: &CheckedPath,
        expected: Option<&task_scheduler::StoppedManagedTasks>, phase: &'static str) -> Result<task_scheduler::StoppedManagedTasks, String> {
        let actual = scheduler.receive_stopped_managed(program, expected, |role, observation| {
            run.task_events.push(task_scheduler::Event::StoppedTaskObservation { phase, role, definition: observation.clone() });
        });
        match (actual, run.record(phase)) {
            (Ok(tasks), Ok(())) => Ok(tasks),
            (Err(error), Err(retention)) => Err(format!("{error}; {retention}")),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    fn receive_after_stopped_metadata<T>(metadata: Result<T, String>, receive_tasks: impl FnOnce() -> Result<(), String>) -> Result<T, String> {
        // A metadata error can follow a real publication. The task receipts
        // still describe the actual outcome and must not mask the first error.
        match (metadata, receive_tasks()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(tasks)) => Err(format!("stopped task receiving after metadata: {tasks}")),
            (Err(error), Err(tasks)) => Err(format!("{error}; stopped task receiving after metadata: {tasks}")),
        }
    }

    /// The selected, authenticated operator action replaces only an existing
    /// managed image whose two qualified logon roles have zero instances.
    /// No task lifecycle operation participates in this receiving path.
    pub(crate) fn deliver_stopped_managed_image_with_receiving(cancelled: &AtomicBool,
        image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>) -> BackgroundReceiving {
        receiving("deliverStoppedManagedImage", cancelled, Some(image), |run| {
            use sha2::Digest;

            let installed = windows_installation::checked_background_path(run.lease()?, &run.program_path(), PathKind::File)?;
            let scheduler = task_scheduler::Scheduler::connect()?;
            let tasks = receive_stopped_tasks(run, &scheduler, &installed, None, "stoppedDeliveryTasksBeforeConfirmation")?;
            let source = receive_copy_source(run)?;
            let original = installed.read_checked_snapshot()?;
            let (source_id, source_bytes) = source.source_capture()?;
            let installed_id = installed.native_id();
            let same_bytes = original.bytes() == source_bytes;
            run.effect(BackgroundEffect::StoppedDeliveryInputsReceived { program_native_id: installed_id.clone(),
                program_sha256: original.digest().to_string(), source_native_id: source_id.clone(),
                source_sha256: hex::encode(sha2::Sha256::digest(source_bytes)) })?;
            let generation = generation_for_program(&installed, same_bytes);
            record_generation_observation(run, &generation)?;
            let authenticate_old = matches!(&generation, ActualGeneration::Unknown(_));
            if authenticate_old { require_unbound_prior_report(None)?; }
            else { current_image_decision(&generation, false, ImageDemand::DeliverSelectedImage)?; }
            run.ready()?;

            let serial = run.diagnostic.id.clone();
            let mut confirmation = prior_transition::confirm_stopped(&installed, &original, &source, &serial, &tasks, authenticate_old)?;
            let authenticated_generation = if let Some((generation, provenance)) = confirmation.prior() {
                if generation == 0 || generation > dns_forwarder::RELAY_VERSION {
                    return Err("UpdatePending: authenticated prior generation is incompatible with the selected image".into());
                }
                run.effect(BackgroundEffect::PriorDeliveryAuthenticated { provenance: provenance.clone() })?;
                Some(generation)
            } else { None };
            run.record("stoppedDeliveryExactConfirmationReceived")?;
            run.ready()?;

            let check_cancel = || -> Result<(), String> {
                if cancelled.load(Ordering::SeqCst) { Err("Cancelled: stopped image delivery was cancelled".into()) } else { Ok(()) }
            };
            let check_original = || -> Result<(), String> {
                check_cancel()?;
                let (actual_source_id, actual_source_bytes) = source.source_capture()?;
                if actual_source_id != source_id || actual_source_bytes != source_bytes || installed.native_id() != installed_id
                    || !original.matches(&installed.read_checked_snapshot()?) {
                    return Err("ChangedInput: installed or selected image changed after stopped delivery confirmation".into());
                }
                installed.recheck()?;
                if let Some(prior) = authenticated_generation { require_unbound_prior_report(Some(prior))?; }
                else if generation_for_program(&installed, same_bytes) != generation {
                    return Err("ChangedInput: installed generation changed after stopped delivery confirmation".into());
                }
                Ok(())
            };
            if same_bytes {
                confirmation.consume(&serial)?;
                let recheck = || {
                    check_original()?;
                    scheduler.receive_stopped_managed(&installed, Some(&tasks), |_, _| {})?;
                    check_cancel()
                };
                recheck()?;
                let metadata = complete_current_generation(run, &installed, recheck);
                let completed = receive_after_stopped_metadata(metadata, || {
                    receive_stopped_tasks(run, &scheduler, &installed, Some(&tasks), "stoppedDeliveryTasksAfterMetadata").map(|_| ())
                })?;
                if !completed { run.effect(BackgroundEffect::CompatibleNoop)?; }
                return run.ready();
            }

            preflight_generation_publication()?;
            check_original()?;
            receive_stopped_tasks(run, &scheduler, &installed, Some(&tasks), "stoppedDeliveryTasksBeforeStage")?;
            run.ready()?;
            let mut final_observations = Vec::new();
            let actual = windows_installation::background_replace_program_guarded(&source, &installed, || {
                check_original()?;
                confirmation.consume(&serial)?;
                scheduler.receive_stopped_managed(&installed, Some(&tasks), |role, observation| {
                    final_observations.push(task_scheduler::Event::StoppedTaskObservation { phase: "stoppedDeliveryTasksBeforeReplace",
                        role, definition: observation.clone() });
                })?;
                check_cancel()
            });
            let attempted = actual.as_ref().map_or_else(|failure| failure.replace_result.is_some(), |_| true);
            run.task_events.extend(final_observations);
            let mut replacement = None;
            let native_result = receive_program_replacement(run, actual, &mut replacement);
            if !attempted { return native_result; }

            // Read both definitions even if the native result or its journal
            // failed. Observing the tasks never grants a retry or task action.
            let post = (|| {
                let current = windows_installation::checked_background_path(run.lease()?, &run.program_path(), PathKind::File)?;
                receive_stopped_tasks(run, &scheduler, &current, Some(&tasks), "stoppedDeliveryTasksAfterReplace")?;
                Ok(current)
            })();
            let published = match (native_result, post) {
                (Ok(()), Ok(current)) => current,
                (Err(error), Err(post)) => return Err(format!("{error}; stopped task receiving after replacement: {post}")),
                (Err(error), _) | (_, Err(error)) => return Err(error),
            };
            if replacement.as_ref().map(|actual| actual.native_id()) != Some(published.native_id()) {
                return Err("ChangedInput: independently received program differs from the native replacement".into());
            }
            run.ready()?;
            let metadata = record_published_generation(run, &published, &source).and_then(|()| {
                crate::gate::require_current_generation(&published)?;
                require_current_generation_projection(&dns_forwarder::version_path())
            });
            receive_after_stopped_metadata(metadata, || {
                receive_stopped_tasks(run, &scheduler, &published, Some(&tasks), "stoppedDeliveryTasksAfterMetadata").map(|_| ())
            })?;
            run.ready()
        })
    }

    pub(crate) fn require_stopped_delivery_elevation(image: &windows_coordinator::process_identity::CurrentImage) -> Result<(), String> {
        image.recheck()?;
        if !prior_transition::current_elevation()? {
            return Err("Для обновления запустите выбранный Unlocker от имени администратора в интерактивном сеансе Windows.".into());
        }
        Ok(())
    }

    pub(crate) fn require_vendor_supersession_actor(image: &windows_coordinator::process_identity::CurrentImage) -> Result<(), String> {
        image.recheck()?;
        if !prior_transition::current_interactive_user()? {
            return Err("Для записи истории Desktop запустите Unlocker в обычном сеансе Windows без повышения прав.".into());
        }
        Ok(())
    }

    /// Only an explicitly selected Repair dispatch may request historical
    /// preparation. A known or non-applicable current installation delegates
    /// back to that command's existing ordinary repair behavior.
    pub(crate) fn repair_prior_transition_with_receiving(changes: BackgroundChanges, cancelled: &AtomicBool,
        image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>) -> (bool, BackgroundReceiving) {
        let mut handled = false;
        let actual = receiving("repairPriorSelectedImage", cancelled, Some(image), |received| {
            let locations = windows_installation::background_locations()?;
            let destination = locations.managed_program();
            match fs::symlink_metadata(destination) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(format!("prior repair program observation: {error}")),
                Ok(_) => {}
            }
            let scheduler = task_scheduler::Scheduler::connect()?;
            if scheduler.references_program(locations.legacy_program())? { return Ok(()); }
            let installed = windows_installation::checked_background_path(received.lease()?, destination, PathKind::File)?;
            received.delivery_selected = true;
            handled = ensure_managed_program(received, installed, &scheduler, changes, ImageDemand::DeliverSelectedImage, true, false)?.is_some();
            Ok(())
        });
        (handled, actual)
    }

    /// Receive the single protected installation owner. CREATE_NEW preserves
    /// any collision, and actual identity/bytes are independently read back
    /// before the scheduler may observe the executable. No source-byte mismatch
    /// can authorize stopping an existing task or overwriting its image.
    fn ensure_program(received: &mut BackgroundRun<'_>, changes: BackgroundChanges, demand: ImageDemand,
        clean_only: bool) -> Result<CheckedPath, String> {
        received.ready()?;
        let destination = received.program_path();
        let locations = windows_installation::background_locations()?;
        let scheduler = task_scheduler::Scheduler::connect()?;
        if scheduler.references_program(locations.legacy_program())? {
            if clean_only { return Err(CLEAN_INSTALL_REQUIRED.into()); }
            return migrate_legacy(received, changes, demand);
        }
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                let installed = windows_installation::checked_background_path(received.lease()?, &destination, PathKind::File)?;
                let demand = if clean_only { ImageDemand::DeliverSelectedImage } else { demand };
                return ensure_managed_program(received, installed, &scheduler, changes, demand, false, clean_only)?
                    .ok_or_else(|| "managed program receiving was not applicable".into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("background executable observation: {error}")),
        }
        let tasks = received.task_state()?;
        if tasks.relay_enabled || tasks.watchdog_enabled {
            return Err("OwnershipRequired: existing background task references an absent program; preserve the task".into());
        }
        let source_lease = receive_copy_source(received)?;
        if demand == ImageDemand::DeliverSelectedImage {
            let programs = task_scheduler::Programs { managed: None, legacy: None };
            let selected = scheduler.receive(&["relay", "watchdog"], &programs, received)?;
            let participants = selected.transition_participants(&programs)?;
            check_selected_delivery_now(received, &participants)?;
        }
        let installed = create_managed_image(received, &source_lease)?;
        source_lease.source_bytes()?;
        record_published_generation(received, &installed, &source_lease)?;
        Ok(installed)
    }

    const CLEAN_INSTALL_REQUIRED: &str =
        "Существующая фоновая служба сохранена. Для запуска текущей версии нужна проверенная чистая установка.";

    fn requests_background_image(changes: BackgroundChanges) -> bool {
        changes.relay == Some(true) || changes.watchdog == Some(true)
    }

    fn require_running(receipt: &TaskReceipt, role: &str) -> Result<(), String> {
        if !receipt.present || !receipt.compatible {
            return Err(format!("OwnershipRequired: {role} definition was not received"));
        }
        if receipt.instances.is_empty() {
            return Err(format!("UpdatePending: {role} definition exists without a running instance; restart requires selected instance ownership"));
        }
        if let Some(started) = &receipt.started {
            if !receipt.instances.contains(started) {
                return Err(format!("PreparationIncomplete: {role} created instance retired or changed before readback; preserve definition"));
            }
        } else if receipt.created {
            return Err(format!("PreparationIncomplete: {role} created definition has no actual run receipt; preserve definition"));
        }
        Ok(())
    }

    /// Existing compatible watchdog instances are a no-op; a fresh definition is
    /// registered create-only and run through its actual COM instance receipt.
    pub fn enable_watchdog() -> Result<(), String> {
        enable_watchdog_with_receiving().result
    }
    pub(crate) fn enable_watchdog_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("enableWatchdog", |received| {
            let before = received.task_state()?;
            if legacy_roles_already_running(received, BackgroundDesired { relay: before.relay_enabled, watchdog: true })? {
                return Ok(());
            }
            let program = ensure_program(received, BackgroundChanges { relay: None, watchdog: Some(true) }, ImageDemand::KeepCompatible, false)?;
            let receipt = scheduler("watchdog", true, &program, received)?;
            require_running(&receipt, "watchdog")
        })
    }

    /// Preserve any task whose exact ownership and instance cannot be established.
    pub fn disable_watchdog() {
        if let Err(e) = disable_watchdog_checked() {
            eprintln!("{e}");
        }
    }

    pub(crate) fn disable_watchdog_checked() -> Result<(), String> {
        disable_watchdog_with_receiving().result
    }
    pub(crate) fn disable_watchdog_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("disableWatchdog", |received| disable_role("watchdog", received))
    }

    /// One full profile operation: the caller supplies both authoritative role
    /// values, including unchanged roles omitted from an Option-valued delta.
    pub(crate) fn reconcile_with_receiving(desired: BackgroundDesired, demand: ImageDemand, cancelled: &AtomicBool,
        image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>) -> BackgroundReceiving {
        reconcile_changes_with_receiving(desired.into(), demand, cancelled, image, None)
    }

    /// The expected transport tuple must come from the caller's committed,
    /// independently read-back settings. A task Run is not a mode receipt.
    pub(crate) fn reconcile_transport_with_receiving(desired: BackgroundDesired, demand: ImageDemand, cancelled: &AtomicBool,
        image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>,
        expected: crate::settings::ActiveTransportConfig) -> BackgroundReceiving {
        reconcile_changes_with_receiving(desired.into(), demand, cancelled, image, Some(expected))
    }

    pub(crate) fn reconcile_changes_with_receiving(changes: BackgroundChanges, demand: ImageDemand, cancelled: &AtomicBool,
        image: Result<std::sync::Arc<windows_coordinator::process_identity::CurrentImage>, String>,
        expected: Option<crate::settings::ActiveTransportConfig>) -> BackgroundReceiving {
        receiving("reconcileBackgroundProfile", cancelled, Some(image), |received| {
            let need_image = requests_background_image(changes);
            received.delivery_selected = need_image || demand == ImageDemand::DeliverSelectedImage;
            if need_image {
                let program = ensure_program(received, changes, ImageDemand::DeliverSelectedImage, true)?;
                for (wanted, role) in [(changes.watchdog, "watchdog"), (changes.relay, "relay")] {
                    let Some(wanted) = wanted else { continue; };
                    for lease in &received.source_leases { lease.source_bytes()?; }
                    if wanted {
                        if role == "relay" {
                            if let Some(expected) = expected {
                                reconcile_transport_relay(received, &program, expected)?;
                            } else {
                                let started = scheduler(role, true, &program, received)?;
                                require_running(&started, role)?;
                            }
                        } else {
                            let started = scheduler(role, true, &program, received)?;
                            require_running(&started, role)?;
                        }
                    } else {
                        disable_role(role, received)?;
                    }
                    for lease in &received.source_leases { lease.source_bytes()?; }
                }
                Ok(())
            } else {
                // Independent roles settle independently; preserve both actual
                // outcomes if one definition cannot be qualified.
                let relay = if changes.relay == Some(false) { disable_role("relay", received) } else { Ok(()) };
                let watchdog = if changes.watchdog == Some(false) { disable_role("watchdog", received) } else { Ok(()) };
                match (relay, watchdog) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                    (Err(relay), Err(watchdog)) => Err(format!("relay: {relay}; watchdog: {watchdog}")),
                }
            }
        })
    }

    fn relay_native_effect_attempted(events: &[task_scheduler::Event]) -> bool {
        events.iter().any(|event| matches!(event, task_scheduler::Event::Call(call)
            if call.role == "relay" && matches!(call.operation, "StopExactInstance" | "Run")))
    }

    fn reconcile_transport_relay(received: &mut BackgroundRun<'_>, program: &CheckedPath,
        expected: crate::settings::ActiveTransportConfig) -> Result<(), String> {
        received.ready()?;
        // Existing attempted native effects belong to this operation's receipt.
        // Do not issue another Stop/Run merely because mode publication is late.
        let prior_effect = relay_native_effect_attempted(&received.task_events);
        let current = scheduler("relay", false, program, received)?;
        if !prior_effect && (!current.present || current.instances.is_empty()) {
            let started = scheduler("relay", true, program, received)?;
            require_running(&started, "relay")?;
        } else if !prior_effect {
            require_running(&current, "relay")?;
            let reconcile = match receive_bound_transport(received.cancelled, expected, true) {
                Ok(mode) => !mode.configuration_matches,
                Err(cause) => {
                    // The genuine saved-profile/Repair command owns the
                    // lifecycle operation; Unknown is recorded, not proof.
                    received.effect(BackgroundEffect::TransportModeUnreceived { cause })?;
                    true
                }
            };
            if reconcile {
                let scheduler = task_scheduler::Scheduler::connect()?;
                let programs = task_scheduler::Programs { managed: Some(program), legacy: None };
                let mut selected = scheduler.receive(&["relay"], &programs, received)?;
                // Reuse the existing exact task retirement/restoration owner,
                // selecting relay only so watchdog is never retired for a mode change.
                let held_program = windows_installation::checked_background_path(received.lease()?, &received.program_path(), PathKind::File)?;
                if held_program.native_id() != program.native_id() { return Err("ChangedInput: relay program changed before mode transition".into()); }
                let (primary, outcome) = owned_transition_selected(received, held_program,
                    BackgroundChanges { relay: Some(true), watchdog: None }, Some(&mut selected), None, false, None,
                    |_, _, _| Ok::<(), String>(()));
                outcome?;
                match primary { Some(Ok(())) => (), Some(Err(error)) => return Err(error),
                    None => return Err("UpdatePending: relay mode transition did not complete".into()) }
            }
        }
        let actual = receive_bound_transport(received.cancelled, expected, false)
            .map_err(|error| format!("UpdatePending: current transport mode unreceived: {error}"))?;
        if !actual.configuration_matches { return Err("UpdatePending: current transport configuration differs".into()); }
        use crate::gate::CapabilityObservation as C;
        let [dns, tcp_proxy, dns_alias] = actual.channels;
        received.effect(BackgroundEffect::TransportObserved { dns: dns.clone(), tcp_proxy: tcp_proxy.clone(), dns_alias })?;
        // TCP can be received even when DNS is independently failed; the
        // retained observation still reports the DNS outcome explicitly.
        let required = if expected.tcp_proxy { &tcp_proxy } else if expected.dns { &dns }
            else { return Err("UpdatePending: no enabled listener available for transport receiving".into()); };
        if !matches!(required, TransportChannelObservation::Received(C::Ready)) {
            return Err(format!("UpdatePending: required transport capability unreceived: {required:?}"));
        }
        Ok(())
    }

    pub fn disable() -> Result<(), String> {
        disable_with_receiving().result
    }
    pub(crate) fn disable_with_receiving() -> BackgroundReceiving {
        uncancelled_receiving("disableRelay", |received| disable_role("relay", received))
    }
    fn disable_role(role: &str, received: &mut BackgroundRun<'_>) -> Result<(), String> {
        received.ready()?;
        let tasks = received.task_state()?;
        let present = match role { "relay" => tasks.relay_enabled, "watchdog" => tasks.watchdog_enabled,
            _ => return Err("invalid background role".into()) };
        if !present { return Ok(()); }
        let scheduler = task_scheduler::Scheduler::connect()?;
        let (managed, legacy) = current_program_inputs(received, &scheduler)?;
        let programs = task_scheduler::Programs { managed: managed.as_ref(), legacy: legacy.as_ref() };
        let retired = scheduler.receive(&[role], &programs, received)?.remove(&programs, received)?;
        received.effect(BackgroundEffect::TaskInstancesRetired(retired.retired))?;
        // The shared executable and diagnostic/version history stay preserved:
        // the other role may still need them and removing a task is no authority
        // to erase user diagnostics. No physical file deletion is claimed.
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn relay_reconciliation_keeps_attempted_native_effect_in_same_receiving() {
            let call = |role: &str, operation: &'static str, returned_hresult| task_scheduler::Event::Call(task_scheduler::Call {
                operation, role: role.into(), instance: None, returned_hresult,
                output_returned: false, error_info: task_scheduler::ErrorInfo::NotQueried,
            });
            assert!(!relay_native_effect_attempted(&[]));
            assert!(!relay_native_effect_attempted(&[call("watchdog", "Run", Some(0))]));
            assert!(relay_native_effect_attempted(&[call("relay", "Run", None)]), "unreturned Run remains owned and cannot replay");
            assert!(relay_native_effect_attempted(&[call("relay", "StopExactInstance", Some(0))]), "completed Stop still belongs to this operation");
        }
        #[test]
        fn transport_report_requires_exact_process_and_configuration() {
            use crate::gate::{CapabilityObservation as C, TransportCapabilities, TransportInstance, TransportObservation, TransportReport};
            use crate::settings::{ActiveTransportConfig, TransportProfile};
            let expected = ActiveTransportConfig { profile: TransportProfile::ExistingConfigured, dns: true, tcp_proxy: true, client_proxy: true, dns_alias: true };
            let mut report = crate::gate::Report { at: u64::MAX, version: dns_forwarder::RELAY_VERSION, ..Default::default() };
            assert!(transport_report_for_instance(&report, expected, 42, 77).is_err(), "missing transport stays unknown");
            report.transport = TransportObservation::Valid(TransportReport { schema: 1,
                instance: TransportInstance { pid: 42, creation_time: 77 }, active_config: expected,
                observed: TransportCapabilities { dns: C::Failed("UDP failed".into()), tcp_proxy: C::Ready, dns_alias: C::Starting } });
            assert!(transport_report_for_instance(&report, expected, 43, 77).is_err(), "same image and different PID");
            assert!(transport_report_for_instance(&report, expected, 42, 78).is_err(), "reused PID and different creation");
            assert!(transport_report_for_instance(&report, expected, 0, 0).is_err(), "missing identity");
            let mut other = expected; other.tcp_proxy = false;
            assert!(!transport_report_for_instance(&report, other, 42, 77).unwrap().0, "different configuration cannot be reused");
            let client_off = ActiveTransportConfig { profile: TransportProfile::ExistingConfigured, dns: false, tcp_proxy: true, client_proxy: false, dns_alias: false };
            let mut client_on = client_off; client_on.client_proxy = true;
            if let TransportObservation::Valid(value) = &mut report.transport { value.active_config = client_off; }
            assert!(!transport_report_for_instance(&report, client_on, 42, 77).unwrap().0, "same physical listener does not prove client wish");
            if let TransportObservation::Valid(value) = &mut report.transport { value.active_config = expected; }
            let (matches, received) = transport_report_for_instance(&report, expected, 42, 77).unwrap();
            assert!(matches);
            assert!(matches!(received.dns, C::Failed(_)));
            assert_eq!(received.tcp_proxy, C::Ready, "a DNS failure does not erase the independent TCP report");
            report.at = 0;
            assert!(transport_report_for_instance(&report, expected, 42, 77).is_err(), "stale report stays unknown");
        }
        #[test]
        fn alias_receiving_requires_every_owned_listener_without_connecting() {
            let executable = std::env::current_exe().unwrap();
            let program = CheckedPath::open(&executable, PathKind::File, PathPurpose::Executable).unwrap();
            let process = ProcessIdentity::current().unwrap();
            let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addresses = [first.local_addr().unwrap(), second.local_addr().unwrap()];
            receive_alias_listener_owners(&program, &process, &addresses).unwrap();
            drop(second);
            assert!(receive_alias_listener_owners(&program, &process, &addresses).is_err(), "one absent alias cannot be Ready");
            let wildcard = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
            let wildcard_port = wildcard.local_addr().unwrap().port();
            let alias = std::net::SocketAddr::from(([127, 0, 0, 1], wildcard_port));
            assert!(receive_alias_listener_owners(&program, &process, &[alias]).is_err(), "wildcard listener is not the owned alias door");
        }
        #[test]
        fn local_listener_receiving_binds_process_and_rechecks_owner_set() {
            let executable = std::env::current_exe().unwrap();
            let program = CheckedPath::open(&executable, PathKind::File, PathPurpose::Executable).unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            with_managed_listener(&program, addr, crate::portcheck::Proto::Tcp, || {
                std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3))
                    .map(|_| ()).map_err(|error| error.to_string())
            }).unwrap();
            assert!(with_managed_listener(&program, addr, crate::portcheck::Proto::Tcp, || {
                drop(listener);
                Ok(())
            }).is_err());
            let udp = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            let target = std::net::SocketAddr::from(([127, 0, 0, 1], udp.local_addr().unwrap().port()));
            assert!(with_managed_listener(&program, target, crate::portcheck::Proto::Udp, || {
                drop(udp);
                std::net::UdpSocket::bind(target).map_err(|error| error.to_string())
            }).is_err(), "same process changing wildcard to exact binding must not preserve the observed row set");
        }
        #[test]
        fn relay_process_stem_preserves_both_windows_query_contracts() {
            let filename = windows_installation::background_process_name();
            let stem = relay_process_name();
            assert!(!stem.is_empty());
            assert_eq!(format!("IMAGENAME eq {stem}.exe"), format!("IMAGENAME eq {filename}"),
                "tasklist must receive the canonical full filename, not a second extension");
            assert_ne!(stem, filename, "Get-Process must receive the stem instead of the full filename");
            assert_eq!(Path::new(filename).file_stem().and_then(|name| name.to_str()), Some(stem.as_str()),
                "egress must keep its documented Get-Process stem contract");
        }

        #[test]
        #[ignore = "read-only existing relay health probe; requires its running task/fresh report; never repairs or restarts"]
        fn native_existing_relay_health_uses_canonical_process_stem() {
            let script = format!("$ErrorActionPreference='Stop'; [int](Get-ScheduledTask -TaskPath '\\' -TaskName '{}').State | ConvertTo-Json -Compress; 'AG_END'", TASK_NAME);
            let state = checked_json_with_cancel(&script, &AtomicBool::new(false)).expect("existing relay task state must be readable");
            assert_eq!(state.as_u64(), Some(4), "existing relay task must already be running");
            let report = crate::gate::read_checked().expect("relay report must be readable").expect("existing report required");
            assert!(!report.is_stale(), "existing report must already be fresh");
            let mut owner = CommandOutcome::default();
            assert!(is_enabled(&mut owner).unwrap(), "existing relay task must be present");
            assert!(is_running(&mut owner).unwrap(), "corrected canonical process query must find the already-running relay image");
            assert!(checked_relay_compatible().expect("existing relay compatibility must be readable"));
            println!("existing running task/fresh report and canonical process-name health received; no repair/restart performed");
        }

        #[test]
        fn existing_managed_namespace_requires_owned_binding_not_appearance() {
            assert!(require_owned_occupancy(OccupancyOwnership::Unproved).is_err(), "empty protected directory or same-hash executable is not ownership");
            assert!(require_owned_occupancy(OccupancyOwnership::CurrentManagedBinding).is_ok());
            assert!(require_owned_occupancy(OccupancyOwnership::LiveCreator).is_ok());
        }

        fn fixture_receipt(running: bool) -> TaskReceipt {
            TaskReceipt { present: true, compatible: true,
                instances: if running { vec!["{11111111-1111-4111-8111-111111111111}".into()] } else { Vec::new() },
                created: false, started: if running { Some("{11111111-1111-4111-8111-111111111111}".into()) } else { None },
                retired: Vec::new(), roles_present: vec![TASK_NAME.into(), WATCHDOG_TASK_NAME.into()] }
        }

        #[test]
        #[ignore = "owned private fixture; normal BackgroundRun settlement I/O failure handoff"]
        fn background_settlement_open_failure_retains_accepted_publication() {
            let parent = PathBuf::from(env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT").expect("explicit qualified parent"));
            let directory = windows_installation::context_fixture_directory(&parent).unwrap();
            let path = directory.join("settlement-gate.json");
            let publication = windows_installation::publish_user_metadata(windows_installation::UserMetadataField::GateReport,
                &path, b"private background fixture").unwrap();
            let published_id = publication.test_published_native_id();
            let cancelled = AtomicBool::new(false);
            let mut run = BackgroundRun { received: empty_receiving("syntheticMetadataSettlement"), cancelled: &cancelled,
                diagnostic: BackgroundDiagnostic::begin("syntheticMetadataSettlement", directory.clone(), None).unwrap(),
                lease: None, program_directory: directory.clone(), selected_program: directory.join("unused"),
                primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None,
                source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: vec![publication], scheduler_fixture: None };
            windows_installation::test_reset_metadata_rename_trace();
            windows_installation::test_displace_during_metadata_settlement();
            finalize_receiving(&mut run);
            assert!(run.received.result.as_ref().unwrap_err().contains("published metadata settlement receiving"));
            assert_eq!(run.received.pending_metadata.len(), 1);
            let pending = &mut run.received.pending_metadata[0];
            assert!(pending.test_accepted_transition_retained());
            assert_eq!(pending.test_held_stage_id().unwrap(), published_id);
            assert!(!pending.test_stage_creation_differs_from_expected().unwrap());
            let calls = windows_installation::test_metadata_rename_count(&published_id);
            assert!(matches!(windows_installation::receive_pending_user_metadata(pending, windows_installation::UserMetadataField::GateReport),
                windows_installation::PendingMetadataReceiving::PublishedReceived));
            assert_eq!(windows_installation::test_metadata_rename_count(&published_id), calls);
            let finished = run.received.finish_live_resources();
            assert!(finished.iter().all(Result::is_ok));
            assert!(run.received.pending_metadata.is_empty());

            let cleanup_path = directory.join("cleanup-gate.json");
            windows_installation::publish_user_metadata(windows_installation::UserMetadataField::GateReport,
                &cleanup_path, b"old").unwrap().settle().unwrap();
            windows_installation::test_change_old_during_metadata_settlement();
            let publication = windows_installation::publish_user_metadata(windows_installation::UserMetadataField::GateReport,
                &cleanup_path, b"new").unwrap();
            let mut cleanup = BackgroundRun { received: empty_receiving("syntheticMetadataCleanup"), cancelled: &cancelled,
                diagnostic: BackgroundDiagnostic::begin("syntheticMetadataCleanup", directory.clone(), None).unwrap(),
                lease: None, program_directory: directory.clone(), selected_program: directory.join("unused"),
                primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None,
                source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: vec![publication], scheduler_fixture: None };
            finalize_receiving(&mut cleanup);
            assert!(cleanup.received.result.as_ref().unwrap_err().contains("displaced preimage changed"));
            assert!(cleanup.received.pending_metadata.is_empty());
            assert_eq!(cleanup.received.live_resources.len(), 2);
        }

        #[test]
        #[ignore = "explicit owned private fixture parent; authored capture failure receiving"]
        fn authored_capture_failures_keep_original_error_and_finish_exact_owned_bytes() {
            let parent = PathBuf::from(env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT").expect("explicit qualified parent"));
            let directory = windows_installation::context_fixture_directory(&parent).unwrap();

            windows_installation::fail_next_authored_capture_after_write();
            let mut first = empty_receiving("syntheticInitialCapture");
            assert!(prepare_background_diagnostic(&mut first, "syntheticInitialCapture", directory.clone(), None).is_none());
            assert!(first.result.as_ref().unwrap_err().contains("after actual write before flush"));
            assert_eq!(first.live_resources.len(), 1);
            let initial = first.finish_live_resources();
            assert_eq!(initial.len(), 1);
            assert!(initial[0].is_ok());
            assert_eq!(initial[0].as_ref().unwrap()["observations"]["writes"][0]["write"], true);
            assert!(initial[0].as_ref().unwrap()["observations"]["writes"][0]["flush"].is_null());
            assert_eq!(initial[0].as_ref().unwrap()["observations"]["receivings"][0]["exact"], true);
            assert!(first.live_resources.is_empty());
            assert!(first.result.as_ref().unwrap_err().contains("after actual write before flush"));

            let cancelled = AtomicBool::new(false);
            let mut run = BackgroundRun { received: empty_receiving("syntheticTerminalCapture"), cancelled: &cancelled,
                diagnostic: BackgroundDiagnostic::begin("syntheticTerminalCapture", directory.clone(), None).unwrap(),
                lease: None, program_directory: directory.clone(), selected_program: directory.join("unused"),
                primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None,
                source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: Vec::new(), scheduler_fixture: None };
            windows_installation::fail_next_authored_capture_after_write();
            finalize_receiving(&mut run);
            assert!(run.received.result.as_ref().unwrap_err().contains("after actual write before flush"));
            assert_eq!(run.received.live_resources.len(), 2);
            let terminal = run.received.finish_live_resources();
            assert_eq!(terminal.len(), 2);
            assert!(terminal.iter().all(Result::is_ok));
            assert!(terminal.iter().any(|entry| entry.as_ref().unwrap()["observations"]["writes"][0]["write"] == true
                && entry.as_ref().unwrap()["observations"]["writes"][0]["flush"].is_null()));
            assert!(run.received.live_resources.is_empty());
            assert!(run.received.result.as_ref().unwrap_err().contains("after actual write before flush"));

            let path = directory.join("mismatch.json");
            let mut mismatch = windows_installation::create_background_diagnostic_file(&path, None).unwrap();
            mismatch.write_authored(b"complete expected payload").unwrap();
            mismatch.file.set_len(3).unwrap();
            mismatch.file.sync_all().unwrap();
            let mut packet = empty_receiving("syntheticMismatchedCapture");
            packet.result = Err("original synthetic partial-write failure".into());
            packet.live_resources.push(mismatch.into_acquired());
            let held = packet.finish_live_resources();
            assert!(held[0].as_ref().unwrap_err().contains("actual bytes differ"));
            assert_eq!(packet.live_resources.len(), 1);
            assert_eq!(packet.result.as_ref().unwrap_err(), "original synthetic partial-write failure");

            let mut partial = BackgroundRun { received: empty_receiving("syntheticPartialJournal"), cancelled: &cancelled,
                diagnostic: BackgroundDiagnostic::begin("syntheticPartialJournal", directory.clone(), None).unwrap(),
                lease: None, program_directory: directory.clone(), selected_program: directory.join("unused"),
                primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None,
                source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: Vec::new(), scheduler_fixture: None };
            partial.diagnostic.journal.as_mut().unwrap().file.set_len(3).unwrap();
            partial.received.result = Err("original synthetic journal failure".into());
            finalize_receiving(&mut partial);
            assert!(partial.received.diagnostic.as_ref().and_then(|reference| reference.sha256.as_ref()).is_some());
            assert!(partial.received.result.as_ref().unwrap_err().contains("original synthetic journal failure"));
            assert!(partial.received.result.as_ref().unwrap_err().contains("actual bytes differ"));
            assert_eq!(partial.received.live_resources.len(), 1);
            assert!(partial.received.finish_live_resources()[0].is_err());
            assert_eq!(partial.received.live_resources.len(), 1);
            let unknown_path = directory.join("unknown-stream.bin");
            let mut unknown = windows_installation::create_background_diagnostic_file(&unknown_path, None).unwrap();
            unknown.file.write_all(b"unqualified writer output").unwrap();
            unknown.file.sync_all().unwrap();
            let mut unknown_packet = empty_receiving("syntheticUnknownWriter");
            unknown_packet.live_resources.push(unknown.into_acquired());
            assert!(unknown_packet.finish_live_resources()[0].is_err());
            assert_eq!(unknown_packet.live_resources.len(), 1);
            eprintln!("owned authored capture fixture root={}; mismatch remains held", directory.display());
        }

        #[test]
        #[ignore = "explicit owned private fixture parent; synthetic unwinds only"]
        fn outer_receiving_preserves_primary_and_secondary_panic_with_owned_witness() {
            let parent = PathBuf::from(env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT").expect("explicit qualified parent"));
            let directory = windows_installation::context_fixture_directory(&parent).unwrap();
            let cancelled = AtomicBool::new(false);
            let mut run = BackgroundRun { received: empty_receiving("syntheticOuterUnwind"), cancelled: &cancelled,
                diagnostic: BackgroundDiagnostic::begin("syntheticOuterUnwind", directory.clone(), None).unwrap(),
                lease: None, program_directory: directory.clone(), selected_program: directory.join("unused"),
                primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None,
                source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: Vec::new(), scheduler_fixture: None };
            windows_installation::fail_next_acquired_receiving_with_retained_witness();
            let mut failure = match run.diagnostic.output_file("fixture", None) {
                Ok(_) => panic!("injected creation receiving failure required"), Err(value) => value,
            };
            run.received.receive_metadata_failure(&mut failure);
            perform_receiving(&mut run, |run| {
                let _: (Option<()>, Vec<String>) = invoke_primary(run, |_| std::panic::panic_any("first-primary"));
                std::panic::panic_any("later-outer");
            });
            assert_eq!(run.received.pending_unwind.as_ref().unwrap().0.downcast_ref::<&'static str>(), Some(&"first-primary"));
            assert_eq!(run.received.secondary_unwinds.len(), 1);
            assert_eq!(run.received.secondary_unwinds[0].0.downcast_ref::<&'static str>(), Some(&"later-outer"));
            assert_eq!(run.received.live_resources.len(), 1);
            assert!(run.received.finish_live_resources().iter().all(Result::is_ok));
            assert!(run.received.live_resources.is_empty());
            eprintln!("owned outer unwind fixture root={}", directory.display());
        }

        #[test]
        #[ignore = "requires the explicit owned private AG_BACKGROUND_FIXTURE_ROOT; executes only a new controlled helper"]
        fn synthetic_native_file_capture_receiving() {
            let directory = PathBuf::from(env::var_os("AG_BACKGROUND_FIXTURE_ROOT").expect("explicit owned fixture root required"));
            let cancelled = AtomicBool::new(false);
            let mut received = BackgroundRun {
                received: empty_receiving("syntheticNativeCaptureOnly"), cancelled: &cancelled,
                diagnostic: BackgroundDiagnostic::begin("syntheticNativeCaptureOnly", directory.clone(), None).unwrap(),
                lease: None, program_directory: directory.clone(), selected_program: directory.join("synthetic-unused-program"), primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None, source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: Vec::new(), scheduler_fixture: None,
            };
            // Exceeds Core's 640-character presentation limit. This helper does
            // not connect to Task Scheduler or change product/user state.
            const SCRIPT: &str = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $request=[Console]::In.ReadLine(); if($request -cne '{}'){throw 'fixture grant mismatch'}; [Console]::Out.Write(('X'*641)); [Console]::Error.Write(('Y'*641)); exit 23";
            windows_installation::fail_next_closed_stream_first_read();
            let outcome = native_output(ControlledClosedFixtureRecipe { script: SCRIPT }, Some(b"{}"), None, "synthetic-capture", true, false, &mut received);
            assert!(outcome.is_err());
            let actual = &received.native[0];
            assert!(actual.started && actual.exit_observed);
            assert_eq!(actual.exit_code, Some(23));
            assert_eq!(actual.stdout, vec![b'X'; 3]);
            assert_eq!(actual.stderr, vec![b'Y'; 641]);
            assert!(actual.stdout_file.as_ref().unwrap().sha256.is_none());
            assert!(actual.stderr_file.as_ref().unwrap().sha256.is_some());
            assert!(actual.errors.iter().any(|error| error.contains("before EOF after actual prefix")));
            received.received.result = outcome.map(|_| ());
            assert_eq!(received.received.live_resources.len(), 1);
            let finished = received.received.finish_live_resources();
            assert!(finished[0].is_ok());
            assert_eq!(finished[0].as_ref().unwrap()["bytes"], 641);
            assert_eq!(finished[0].as_ref().unwrap()["observations"]["reads"][0], false);
            assert_eq!(finished[0].as_ref().unwrap()["observations"]["reads"][1], true);
            assert!(received.received.live_resources.is_empty());
            assert!(received.received.result.as_ref().unwrap_err().contains("exited"));
            let reference = received.diagnostic.finish(&mut received.received, None).unwrap();
            assert!(reference.sha256.is_some());
            let mut stopped = BackgroundRun {
                received: empty_receiving("syntheticUnusedCapture"), cancelled: &cancelled,
                diagnostic: BackgroundDiagnostic::begin("syntheticUnusedCapture", directory.clone(), None).unwrap(),
                lease: None, program_directory: directory.clone(), selected_program: directory.join("unused"),
                primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None,
                source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: Vec::new(), scheduler_fixture: None,
            };
            stopped.diagnostic.injected_write_failure = true;
            let stopped_result = native_output(ControlledClosedFixtureRecipe { script: SCRIPT }, Some(b"{}"), None,
                "synthetic-unused", true, false, &mut stopped);
            assert!(stopped_result.is_err());
            assert!(!stopped.received.native[0].started);
            assert_eq!(stopped.received.live_resources.len(), 1);
            let unused = stopped.received.finish_live_resources();
            assert!(unused[0].as_ref().unwrap()["result"].as_str().unwrap().contains("delete-pending received"));
            assert!(stopped.received.live_resources.is_empty());
            println!("controlled helper actual exit/capture/terminal retained at {}", reference.path.display());
        }

        #[test]
        #[ignore = "requires explicit owned private AG_BACKGROUND_FIXTURE_ROOT; synthetic source only"]
        fn source_capture_revalidation_failure_retains_actual_observation_and_cause() {
            let directory = PathBuf::from(env::var_os("AG_BACKGROUND_FIXTURE_ROOT").expect("explicit owned fixture root required"));
            let source = directory.join(format!("source-{}.exe", windows_installation::new_request_id().unwrap()));
            eprintln!("OWN_BACKGROUND_SOURCE_CAPTURE_FIXTURE {}", source.display());
            let mut created = fs::OpenOptions::new().write(true).create_new(true).open(&source).unwrap();
            created.write_all(b"MZ controlled source; never executed").unwrap();
            created.sync_all().unwrap(); drop(created);
            let image = std::sync::Arc::new(windows_coordinator::process_identity::CurrentImage::synthetic(&source).unwrap());
            for terminal_failure in [false, true] {
                let cancelled = AtomicBool::new(false);
                let mut run = BackgroundRun {
                    received: empty_receiving("syntheticSourceCaptureFailure"), cancelled: &cancelled,
                    diagnostic: BackgroundDiagnostic::begin("syntheticSourceCaptureFailure", directory.clone(), None).unwrap(),
                    lease: None, program_directory: directory.join("unused-program"), selected_program: directory.join("unused-program/ag_dns.exe"),
                    primary_unwind: None, restoring: false, created_directory: None, created_program: None,
                    image: Some(Ok(image.clone())), source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: Vec::new(), scheduler_fixture: None,
                };
                windows_installation::fail_next_source_capture_revalidation();
                let cause = match receive_copy_source(&mut run) { Ok(_) => panic!("controlled source failure missing"), Err(cause) => cause };
                assert!(cause.starts_with("synthetic source revalidation failure"));
                for key in ["nativeId=", "sha256=", "bytes=", "metadataSha256="] { assert!(cause.contains(key)); }
                assert!(run.received.effects.is_empty() && run.received.replacements.is_empty() && run.received.native.is_empty());
                assert!(run.received.primary_result.is_none());
                run.received.result = Err(cause.clone());
                if terminal_failure { run.diagnostic.directory = directory.join("missing-terminal-parent"); }
                finalize_receiving(&mut run);
                let actual = run.received.result.as_ref().unwrap_err();
                assert!(actual.starts_with(&cause));
                if terminal_failure {
                    assert!(!run.received.persistence_errors.is_empty());
                    assert!(actual.contains("diagnostic terminal retention"));
                } else {
                    let terminal = run.received.diagnostic.as_ref().unwrap();
                    let value: serde_json::Value = serde_json::from_slice(&fs::read(&terminal.path).unwrap()).unwrap();
                    assert_eq!(value["receiving"]["result"]["Err"], cause);
                    assert!(run.received.persistence_errors.is_empty());
                }
                assert!(run.received.effects.is_empty() && run.received.replacements.is_empty() && run.received.native.is_empty());
                assert!(run.received.primary_result.is_none());
            }
        }

        #[test]
        #[ignore = "requires an explicit AG_BACKGROUND_FIXTURE_ROOT owned synthetic directory; never uses product tasks or log_dir"]
        fn synthetic_transition_failure_and_cancellation_receiving() {
            let root = PathBuf::from(env::var_os("AG_BACKGROUND_FIXTURE_ROOT").expect("explicit owned fixture root required"));
            windows_installation::WindowsLocalPath::parse(root.as_os_str()).unwrap();
            for case in ["cancel-before-grant", "cancel-after-retire", "primary-and-restore-fail", "partial-retire-fails", "sink-after-stop", "sink-after-primary"] {
                let directory = root.clone();
                let mut output = windows_installation::create_background_diagnostic_file(&directory.join(format!("{}-{case}-synthetic-file-identity.bin", windows_installation::new_request_id().unwrap())), None).unwrap();
                output.file.write_all(b"synthetic file identity; never executed and grants no runtime authority").unwrap();
                output.file.sync_all().unwrap();
                let path = output.path.clone();
                drop(output.file);
                let program = CheckedPath::open(&path, PathKind::File, PathPurpose::ReplaceSource).unwrap();
                let cancelled = AtomicBool::new(case == "cancel-before-grant");
                let mut replies = std::collections::VecDeque::new();
                if case == "partial-retire-fails" {
                    replies.push_back(Err("synthetic relay retired, watchdog Stop returned failure".into()));
                    replies.push_back(Ok(fixture_receipt(true)));
                    replies.push_back(Ok(fixture_receipt(true)));
                } else if case != "cancel-before-grant" {
                    replies.push_back(Ok(fixture_receipt(false)));
                    if case != "sink-after-stop" { replies.push_back(Ok(fixture_receipt(false))); }
                    replies.push_back(if case == "primary-and-restore-fail" { Err("synthetic watchdog restore failed".into()) } else { Ok(fixture_receipt(true)) });
                    replies.push_back(Ok(fixture_receipt(true)));
                }
                let mut received = BackgroundRun {
                    received: empty_receiving("syntheticTransitionModelOnly"), cancelled: &cancelled,
                    diagnostic: BackgroundDiagnostic::begin("syntheticTransitionModelOnly", directory.clone(), None).unwrap(),
                    lease: None, program_directory: directory.clone(), selected_program: path.clone(), primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None, source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: Vec::new(),
                    scheduler_fixture: Some(SchedulerFixture { relay_present: true, watchdog_present: true,
                        cancel_after_retire: case == "cancel-after-retire", fail_after_retire: case == "sink-after-stop", replies, calls: Vec::new(), program_native_ids: Vec::new() }),
                };
                let first_backup = directory.join(format!("{}-first-backup-is-directory", windows_installation::new_request_id().unwrap()));
                fs::create_dir(&first_backup).unwrap();
                let mut invoked = 0;
                let (primary, outcome) = owned_transition(&mut received, program,
                     BackgroundDesired { relay: true, watchdog: true }.into(), None, |run, _, _| {
                        invoked += 1;
                        if case == "sink-after-primary" { run.diagnostic.injected_write_failure = true; }
                        let error = fs::write(&first_backup, b"first native file backup").unwrap_err();
                        Err::<usize, String>(format!("actual first-file I/O failure: {error}"))
                    });
                assert!(outcome.is_err(), "{case}");
                let calls = &received.scheduler_fixture.as_ref().unwrap().calls;
                if case == "cancel-before-grant" {
                    assert_eq!(invoked, 0);
                    assert!(primary.is_none());
                    assert!(calls.is_empty());
                    assert!(received.restoration_result.is_none());
                    assert!(!received.restoration_pending);
                } else {
                    assert_eq!(calls.iter().filter(|(_, action)| action == "resume").count(), 2, "both wanted roles receive restoration even after an earlier failure");
                    assert!(received.scheduler_fixture.as_ref().unwrap().replies.is_empty());
                    if case == "primary-and-restore-fail" {
                        assert_eq!(invoked, 1);
                        assert!(first_backup.is_dir());
                        assert!(primary.as_ref().unwrap().as_ref().unwrap_err().starts_with("actual first-file I/O failure: "));
                        assert_eq!(serde_json::to_value(&primary).unwrap(), serde_json::to_value(&received.primary_result).unwrap());
                        assert!(received.primary_result.as_ref().unwrap().get("Err").is_some());
                        assert!(received.restoration_result.as_ref().unwrap().is_err());
                        assert!(received.restoration_pending);
                    } else if case == "sink-after-primary" {
                        assert_eq!(invoked, 1);
                        assert!(primary.as_ref().unwrap().is_err());
                        assert!(received.restoration_result.as_ref().unwrap().is_ok());
                        assert!(!received.restoration_pending);
                    } else {
                        assert_eq!(invoked, 0);
                        assert!(primary.is_none());
                        assert!(received.restoration_result.as_ref().unwrap().is_ok());
                        assert!(!received.restoration_pending);
                    }
                }
                if case.starts_with("cancel-") { assert!(received.cancellation_received); }
                if case.starts_with("sink-") {
                    assert!(!received.persistence_errors.is_empty());
                    assert!(received.task_events.iter().filter(|event| matches!(event, task_scheduler::Event::Call(call) if call.operation == "syntheticRestoreRun")).count() == 2);
                    assert!(received.ready().is_err(), "independent next effect remains blocked after safe restoration");
                }
                received.received.result = outcome.map(|_| ());
                let reference = received.diagnostic.finish(&mut received.received, None).unwrap();
                assert!(reference.sha256.is_some());
                println!("{case}: synthetic transport only; owned terminal retained at {}", reference.path.display());
            }
        }

        #[test]
        fn installed_generation_requires_actual_image_proof_for_replacement() {
            let g = dns_forwarder::RELAY_VERSION;
            assert_eq!(current_image_decision(&ActualGeneration::NoInstallation, false, ImageDemand::DeliverSelectedImage).unwrap(), CurrentImageDecision::UpdateRequired);
            assert_eq!(current_image_decision(&ActualGeneration::SameCurrentImage, false, ImageDemand::DeliverSelectedImage).unwrap(), CurrentImageDecision::ReuseCurrent);
            assert_eq!(current_image_decision(&ActualGeneration::Bound(g - 1), false, ImageDemand::DeliverSelectedImage).unwrap(), CurrentImageDecision::UpdateRequired);
            assert!(current_image_decision(&ActualGeneration::Bound(g + 1), false, ImageDemand::DeliverSelectedImage).is_err());
            let unknown = ActualGeneration::Unknown("no bound record".into());
            assert!(current_image_decision(&unknown, false, ImageDemand::DeliverSelectedImage).is_err());
            assert_eq!(current_image_decision(&unknown, true, ImageDemand::KeepCompatible).unwrap(), CurrentImageDecision::ReuseCurrent);
            assert!(require_owned_occupancy(OccupancyOwnership::Unproved).is_err());
        }

        #[test]
        fn a_partial_watchdog_or_proxy_start_uses_the_shared_image() {
            assert!(requests_background_image(BackgroundChanges { relay: None, watchdog: Some(true) }));
            assert!(requests_background_image(BackgroundChanges { relay: Some(true), watchdog: None }));
            assert!(!requests_background_image(BackgroundChanges { relay: Some(false), watchdog: None }));
        }

        #[test]
        fn exact_prior_roles_require_unchanged_capture_or_this_runs_acknowledged_stop() {
            use task_scheduler::{Call, DefinitionView, ErrorInfo, Event, InstanceView, Origin};
            let instance = InstanceView { guid: "approved-instance".into(), path: "\\relay".into(),
                action_name: Ok("relay".into()), state: 4, image: "Unknown", engine_pid: Ok(15) };
            let approved = [DefinitionView { role: "relay".into(), program: PathBuf::from("managed.exe"),
                origin: Origin::Managed, xml: "current XML".into(), security: "current security".into(),
                principal: "current principal".into(), logon: 2, instances: vec![instance.clone()] }];
            require_exact_prior_roles(&approved, &approved, &[]).unwrap();
            let mut now = approved.clone();
            now[0].instances.clear();
            let absent = Event::InstanceRetired(instance.clone());
            assert!(require_exact_prior_roles(&approved, &now, &[absent.clone()]).is_err());
            let stop = Event::Call(Call { operation: "StopExactInstance", role: "relay".into(),
                instance: Some(instance.guid), returned_hresult: Some(0), output_returned: false,
                error_info: ErrorInfo::NoInfo { hresult: 1 } });
            assert!(require_exact_prior_roles(&approved, &now, &[stop.clone()]).is_err());
            require_exact_prior_roles(&approved, &now, &[stop.clone(), absent.clone()]).unwrap();
            now[0].security.push_str(" changed");
            assert!(require_exact_prior_roles(&approved, &now, &[stop, absent]).is_err());
        }

        #[test]
        fn prior_preparation_requires_received_old_format_without_conflicting_binding() {
            let generation = dns_forwarder::RELAY_VERSION - 1;
            let prior = serde_json::to_vec(&serde_json::json!({"version":generation})).unwrap();
            assert!(check_unbound_prior_report(&prior, None).is_ok());
            assert!(check_unbound_prior_report(&prior, Some(generation)).is_ok());
            assert!(check_unbound_prior_report(&prior, Some(generation - 1)).is_err());
            for rejected in [b"{}".as_slice(), b"{", br#"{"version":1,"installed_generation":{}}"#] {
                assert!(check_unbound_prior_report(rejected, None).is_err());
            }
            let file_id = [1u8; 16];
            let modern = serde_json::to_vec(&serde_json::json!({"version":generation,"installed_generation":{
                "schema":1,"generation":generation,"program_native_id":{"volume":1,"file":file_id},
                "program_sha256":"0".repeat(64),
            }})).unwrap();
            assert!(check_unbound_prior_report(&modern, None).is_err());
        }

        #[test]
        #[ignore = "explicit owned private fixture parent; no installed state"]
        fn no_installation_requires_actual_program_absence() {
            let parent = PathBuf::from(env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT").expect("explicit qualified parent"));
            let root = windows_installation::context_fixture_directory(&parent).unwrap();
            let pin = CheckedPath::open(&root, PathKind::Directory, PathPurpose::Review).unwrap();
            let candidate = root.join("program.bin");
            require_absent_program(&candidate).unwrap();
            let file = windows_installation::create_background_diagnostic_file(&candidate, None).unwrap();
            assert!(require_absent_program(&candidate).is_err());
            eprintln!("owned absence fixture root={}, rootId={:?}, programId={:?}", root.display(), pin.native_id(), file.native_id);
        }

        #[test]
        #[ignore = "requires explicit owned AG_BACKGROUND_FIXTURE_ROOT; synthetic Scheduler only, no product tasks/programs"]
        fn synthetic_current_image_reuse_and_update_receiving() {
            let root = PathBuf::from(env::var_os("AG_BACKGROUND_FIXTURE_ROOT").expect("explicit owned fixture root required"));
            windows_installation::WindowsLocalPath::parse(root.as_os_str()).unwrap();
            for update in [false, true] {
                let proof = if update { ActualGeneration::Bound(dns_forwarder::RELAY_VERSION) } else { ActualGeneration::SameCurrentImage };
                let decision = current_image_decision(&proof, true,
                    if update { ImageDemand::DeliverSelectedImage } else { ImageDemand::KeepCompatible }).unwrap();
                let make_program = |bytes: &[u8]| {
                    let path = root.join(format!("{}-current-image-model.bin", windows_installation::new_request_id().unwrap()));
                    let mut output = windows_installation::create_background_diagnostic_file(&path, None).unwrap();
                    output.file.write_all(bytes).unwrap(); output.file.sync_all().unwrap(); drop(output.file);
                    CheckedPath::open(&path, PathKind::File, PathPurpose::ReplaceSource).unwrap()
                };
                let program = make_program(b"owned synthetic A; never executable");
                let baseline_id = program.native_id();
                let mut source_receives = 0;
                let desired_program = if decision == CurrentImageDecision::UpdateRequired {
                    source_receives += 1;
                    Some(make_program(b"different desired synthetic B; never executable"))
                } else { None };
                let expected_id = desired_program.as_ref().map(|program| program.native_id()).unwrap_or_else(|| baseline_id.clone());
                let cancelled = AtomicBool::new(false);
                let replies = [Ok(fixture_receipt(false)), Ok(fixture_receipt(false)), Ok(fixture_receipt(true)), Ok(fixture_receipt(true))].into_iter().collect();
                let mut received = BackgroundRun {
                    received: empty_receiving("syntheticCurrentImageModelOnly"), cancelled: &cancelled,
                    diagnostic: BackgroundDiagnostic::begin("syntheticCurrentImageModelOnly", root.clone(), None).unwrap(),
                    lease: None, program_directory: root.clone(), selected_program: program.as_path().to_path_buf(),
                    primary_unwind: None, restoring: false, created_directory: None, created_program: None, image: None, source_leases: Vec::new(), delivery_selected: false, prior_transition: None, metadata_publications: Vec::new(),
                    scheduler_fixture: Some(SchedulerFixture { relay_present: true, watchdog_present: true, cancel_after_retire: false,
                        fail_after_retire: false, replies, calls: Vec::new(), program_native_ids: Vec::new() }),
                };
                let mut replacements = 0;
                let (primary, outcome) = owned_transition_selected(&mut received, program,
                    BackgroundDesired { relay: true, watchdog: true }.into(), None, None, true, None, |_, _, replacement| {
                        if let Some(actual) = desired_program { replacements += 1; *replacement = Some(actual); }
                        Ok::<(), String>(())
                    });
                let active = outcome.unwrap();
                assert!(matches!(primary, Some(Ok(()))));
                assert_eq!(active.native_id(), expected_id);
                assert_eq!((source_receives, replacements), if update { (1, 1) } else { (0, 0) });
                assert!(received.generation_writes.is_empty(), "the model never writes real version metadata");
                let fixture = received.scheduler_fixture.as_ref().unwrap();
                assert_eq!(fixture.calls, [("shared".into(), "retire".into()), ("shared".into(), "quiescent".into()),
                    ("watchdog".into(), "resume".into()), ("relay".into(), "resume".into())]);
                assert_eq!(fixture.program_native_ids, [baseline_id.clone(), baseline_id, expected_id.clone(), expected_id]);
                assert!(fixture.replies.is_empty());
                assert!(received.restoration_result.as_ref().unwrap().is_ok() && !received.restoration_pending);
                received.received.result = Ok(());
                received.diagnostic.finish(&mut received.received, None).unwrap();
                println!("{}: one modeled retirement cycle and both-role receiving on actual selected fixture pin; no native image replacement", if update { "UpdateRequired" } else { "ReuseCurrent" });
            }
        }

        #[test]
        fn stopped_metadata_failure_still_receives_tasks_and_keeps_the_first_error() {
            for (metadata, tasks, expected) in [
                (Ok(true), Ok(()), Ok(true)),
                (Err("projection write failed"), Ok(()), Err("projection write failed")),
                (Ok(false), Err("watchdog query failed"), Err("stopped task receiving after metadata: watchdog query failed")),
                (Err("projection write failed"), Err("watchdog query failed"),
                    Err("projection write failed; stopped task receiving after metadata: watchdog query failed")),
            ] {
                let mut observed = false;
                let actual = receive_after_stopped_metadata(metadata.map_err(str::to_owned), || {
                    observed = true;
                    tasks.map_err(str::to_owned)
                });
                assert!(observed);
                assert_eq!(actual, expected.map_err(str::to_owned));
            }
        }

        #[test]
        fn created_task_requires_its_actual_running_instance_receipt() {
            let mut receipt = TaskReceipt { present: true, compatible: true,
                instances: vec!["new-instance".into()], created: true, started: Some("new-instance".into()), retired: Vec::new(), roles_present: Vec::new() };
            assert!(require_running(&receipt, "relay").is_ok());
            receipt.started = Some("retired-instance".into());
            assert!(require_running(&receipt, "relay").is_err());
            receipt.started = None;
            assert!(require_running(&receipt, "relay").is_err());
            receipt.created = false;
            assert!(require_running(&receipt, "relay").is_ok());
            receipt.instances.clear();
            assert!(require_running(&receipt, "relay").is_err());
            receipt.instances.push("existing-instance".into());
            receipt.compatible = false;
            assert!(require_running(&receipt, "relay").is_err());
        }

        #[test]
        fn scheduler_receipt_missing_fields_do_not_weaken_the_guard() {
            let receipt = serde_json::json!({"present":true,"compatible":true,"instances":["instance"],"created":false,"started":null,"retired":[],"rolesPresent":[]});
            assert!(serde_json::from_value::<TaskReceipt>(receipt.clone()).is_ok());
            for key in ["present", "compatible", "instances", "created", "started", "retired", "rolesPresent"] {
                let mut incomplete = receipt.clone();
                incomplete.as_object_mut().unwrap().remove(key);
                assert!(serde_json::from_value::<TaskReceipt>(incomplete).is_err(), "missing {key}");
            }
            assert!(serde_json::from_value::<TaskReceipt>(serde_json::json!({})).is_err());
        }

        #[test]
        fn checked_native_wire_rejects_missing_or_malformed_data() {
            assert_eq!(parse_checked_json(b"[]\r\nAG_END\r\n").unwrap(), serde_json::json!([]));
            assert!(parse_checked_json(b"").is_err());
            assert!(parse_checked_json(b"[]").is_err());
            assert!(parse_checked_json(b"[\nAG_END").is_err());
            assert!(parse_checked_json(b"null\nAG_END").unwrap().as_array().is_none());
            assert!(parse_checked_json(&[0xff]).is_err());
        }

        /// A nonzero query result cannot distinguish an absent task from an
        /// unavailable query, so its actual outcome remains held as unknown.
        #[test]
        #[ignore = "requires a creator-owned outer Job for command and reader settlement"]
        fn a_nonzero_task_query_remains_unknown() {
            let mut owner = CommandOutcome::default();
            assert!(task_exists(&mut owner, "AG Unlocker no-such-task 4f2b9c").is_err());
            assert!(!owner.is_empty(), "a launched nonzero result must remain received by the owner");
        }

        /// Live: `schtasks` and PowerShell must give the same answer for the two
        /// real task names.
        ///
        /// The point of the swap is speed (35 ms against 830 ms, and it is asked
        /// twice per status refresh) and speed is only worth having if the answer
        /// is the same one — a reader that silently says "no task" would draw both
        /// switches off on a machine where they are on. Ignored because it can
        /// only assert anything on a machine that has actually installed the
        /// relay:
        ///
        ///     cargo test schtasks_and_powershell_agree -- --ignored --nocapture
        #[test]
        #[ignore = "needs the relay/watchdog tasks registered on this machine"]
        fn schtasks_and_powershell_agree_about_the_tasks() {
            let mut owner = CommandOutcome::default();
            for name in [TASK_NAME, WATCHDOG_TASK_NAME] {
                let receipt = powershell(&mut owner, &format!(
                    "if (Get-ScheduledTask -TaskName '{}' -ErrorAction SilentlyContinue) \
                     {{ 'yes' }} else {{ 'no' }}",
                    name
                ));
                receive_command(&owner, receipt).unwrap();
                let via_ps = String::from_utf8_lossy(owner.stdout()).trim() == "yes";
                drop(std::mem::take(&mut owner));
                let via_schtasks = task_exists(&mut owner, name).unwrap();
                println!("{name}: schtasks={via_schtasks} powershell={via_ps}");
                assert_eq!(via_schtasks, via_ps, "readers disagree about {name}");
            }
        }

        /// The exe must not sit under the user profile: a scheduled task cannot
        /// launch anything from there on a machine with anti-persistence
        /// heuristics.
        #[test]
        fn the_relay_is_installed_outside_the_user_profile() {
            let exe = installed_exe().unwrap();
            assert_eq!(exe.parent(), Some(install_dir().unwrap().as_path()));
            let locations = windows_installation::background_locations().unwrap();
            assert!(exe.starts_with(locations.managed_root()), "got {}", exe.display());

            if let Ok(local) = env::var("LOCALAPPDATA") {
                assert!(
                    !exe.starts_with(&local),
                    "the task would refuse to start it"
                );
            }
        }

        /// The log goes the other way round - the relay runs unelevated and cannot
        /// write next to an exe an administrator installed.
        #[test]
        fn the_log_stays_in_the_user_profile() {
            let log = dns_forwarder::log_path();
            let local = env::var("LOCALAPPDATA").unwrap_or_default();
            assert!(!local.is_empty());
            assert!(log.starts_with(&local), "got {}", log.display());
            assert_eq!(log.parent(), Some(dns_forwarder::log_dir().as_path()));
            assert_ne!(log.parent(), Some(install_dir().unwrap().as_path()));
        }
    }
}

// macOS: runs the local CONNECT proxy (`proxy::run`, via `--proxy`) as a
// LaunchAgent in ~/Library/LaunchAgents/com.antigravity.unlocker.proxy.plist.
// Unprivileged, no root required, auto-starts on user login.
#[cfg(target_os = "macos")]
mod macos_impl {
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    use super::{PROXY_FLAG, WATCHDOG_FLAG};

    const LABEL: &str = "com.antigravity.unlocker.proxy";
    const SOURCE_DIGEST: &str = "AG_UNLOCKER_SOURCE_SHA256";
    const HELPER_DIGEST: &str = "AG_UNLOCKER_HELPER_SHA256";

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Role { Proxy, Watchdog }
    impl Role {
        fn label(self) -> &'static str { match self { Self::Proxy => LABEL, Self::Watchdog => "com.antigravity.unlocker.watchdog" } }
        fn flag(self) -> &'static str { match self { Self::Proxy => PROXY_FLAG, Self::Watchdog => WATCHDOG_FLAG } }
        fn helper(self) -> &'static str { match self { Self::Proxy => "ag_proxy", Self::Watchdog => "ag_watchdog" } }
        fn helper_stage(self) -> &'static str { match self { Self::Proxy => "ag_proxy.stage", Self::Watchdog => "ag_watchdog.stage" } }
        fn plist(self) -> &'static str { match self { Self::Proxy => "com.antigravity.unlocker.proxy.plist", Self::Watchdog => "com.antigravity.unlocker.watchdog.plist" } }
        fn plist_stage(self) -> &'static str { match self { Self::Proxy => "com.antigravity.unlocker.proxy.plist.stage", Self::Watchdog => "com.antigravity.unlocker.watchdog.plist.stage" } }
        fn log(self) -> &'static str { match self { Self::Proxy => "proxy.log", Self::Watchdog => "watchdog.log" } }
    }

    fn recheck_directory(path: &Path, file: &fs::File, uid: u32) -> Result<(), String> {
        let held = file.metadata().map_err(|error| format!("проверка каталога службы: {error}"))?;
        let entry = fs::symlink_metadata(path).map_err(|error| format!("проверка каталога службы: {error}"))?;
        if !held.is_dir() || !entry.is_dir() || held.uid() != uid || held.mode() & 0o022 != 0
            || held.dev() != entry.dev() || held.ino() != entry.ino()
            || held.uid() != entry.uid() || held.mode() != entry.mode() {
            return Err("каталог службы изменён или не принадлежит текущему пользователю".into());
        }
        Ok(())
    }

    fn owned_directory(path: &Path, uid: u32) -> Result<fs::File, String> {
        let directory = fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY | libc::O_CLOEXEC)
            .open(path).map_err(|error| format!("открытие каталога службы: {error}"))?;
        recheck_directory(path, &directory, uid)?;
        Ok(directory)
    }

    pub(crate) fn in_owned_macos_directory<T>(path: &Path, action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let uid = unsafe { libc::geteuid() };
        let directory = owned_directory(path, uid)?;
        let result = action()?;
        recheck_directory(path, &directory, uid)?;
        Ok(result)
    }

    fn owned_child_directory(parent: &fs::File, parent_path: &Path, name: &str, uid: u32)
        -> Result<fs::File, String> {
        recheck_directory(parent_path, parent, uid)?;
        let name = std::ffi::CString::new(name).map_err(|_| "неверное имя каталога службы")?;
        let open = || unsafe {
            libc::openat(parent.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY |
                libc::O_NOFOLLOW | libc::O_CLOEXEC)
        };
        let mut fd = open();
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(format!("открытие каталога службы: {error}"));
            }
            let made = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
            if made != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(format!("создание каталога службы: {error}"));
                }
            }
            fd = open();
            if fd < 0 { return Err(format!("открытие каталога службы: {}", std::io::Error::last_os_error())); }
        }
        let directory = unsafe { fs::File::from_raw_fd(fd) };
        recheck_directory(parent_path, parent, uid)?;
        let path = parent_path.join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        recheck_directory(&path, &directory, uid)?;
        Ok(directory)
    }

    fn file_digest(file: &fs::File) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        let before = file.metadata().map_err(|error| format!("проверка файла службы: {error}"))?;
        let mut input = file.try_clone().map_err(|error| format!("копия дескриптора: {error}"))?;
        input.seek(SeekFrom::Start(0)).map_err(|error| format!("позиция файла: {error}"))?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = input.read(&mut buffer).map_err(|error| format!("чтение файла службы: {error}"))?;
            if count == 0 { break; }
            hash.update(&buffer[..count]);
        }
        let after = file.metadata().map_err(|error| format!("проверка файла службы: {error}"))?;
        if before.dev() != after.dev() || before.ino() != after.ino() || before.len() != after.len()
            || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() {
            return Err("файл изменился во время чтения".into());
        }
        Ok(format!("{:x}", hash.finalize()))
    }

    fn optional_owned_file(path: &Path, uid: u32) -> Result<Option<fs::File>, String> {
        match fs::symlink_metadata(path) {
            Ok(_) => checked_file(path, uid).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("проверка файла службы: {error}")),
        }
    }

    fn entry_id(path: &Path, uid: u32) -> Result<Option<(u64, u64)>, String> {
        match fs::symlink_metadata(path) {
            Ok(info) if info.is_file() && info.uid() == uid && info.nlink() == 1 && info.mode() & 0o022 == 0 =>
                Ok(Some((info.dev(), info.ino()))),
            Ok(_) => Err("файл службы не является безопасным собственным файлом".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("проверка файла службы: {error}")),
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum StagePosition { Before, Published, Conflict }

    fn stage_position(stage: Option<(u64, u64)>, live: Option<(u64, u64)>,
        staged: (u64, u64), prior: Option<(u64, u64)>) -> StagePosition {
        if stage == Some(staged) && live == prior { StagePosition::Before }
        else if live == Some(staged) && stage == prior { StagePosition::Published }
        else { StagePosition::Conflict }
    }

    struct StagedFile<'a> {
        parent: &'a fs::File,
        parent_path: &'a Path,
        live_name: &'static str,
        stage_name: &'static str,
        uid: u32,
        prior: Option<fs::File>,
        staged: fs::File,
    }

    impl<'a> StagedFile<'a> {
        fn create(parent: &'a fs::File, parent_path: &'a Path, live_name: &'static str,
            stage_name: &'static str, prior: Option<fs::File>, uid: u32, mode: u32) -> Result<Self, String> {
            recheck_directory(parent_path, parent, uid)?;
            let name = std::ffi::CString::new(stage_name).map_err(|_| "неверное имя временного файла")?;
            let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode) };
            if fd < 0 { return Err(format!("создание временного файла службы: {}", std::io::Error::last_os_error())); }
            let staged = unsafe { fs::File::from_raw_fd(fd) };
            let result = Self { parent, parent_path, live_name, stage_name, uid, prior, staged };
            if let Err(primary) = recheck_directory(parent_path, parent, uid)
                .and_then(|_| recheck_file(&parent_path.join(stage_name), &result.staged, uid)) {
                return match result.remove_exact(stage_name, &result.staged) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(format!("{primary}; временный файл сохранён: {cleanup}")),
                };
            }
            Ok(result)
        }

        fn stage_path(&self) -> PathBuf { self.parent_path.join(self.stage_name) }
        fn live_path(&self) -> PathBuf { self.parent_path.join(self.live_name) }

        fn position(&self) -> Result<StagePosition, String> {
            recheck_directory(self.parent_path, self.parent, self.uid)?;
            let stage = entry_id(&self.stage_path(), self.uid)?;
            let live = entry_id(&self.live_path(), self.uid)?;
            let staged = self.staged.metadata().map_err(|error| error.to_string())?;
            let staged = (staged.dev(), staged.ino());
            let prior = match &self.prior {
                Some(file) => { let info = file.metadata().map_err(|error| error.to_string())?; Some((info.dev(), info.ino())) },
                None => None,
            };
            Ok(stage_position(stage, live, staged, prior))
        }

        fn rename(&self, flags: libc::c_uint) -> Result<(), String> {
            let stage = std::ffi::CString::new(self.stage_name).map_err(|_| "неверное имя временного файла")?;
            let live = std::ffi::CString::new(self.live_name).map_err(|_| "неверное имя файла службы")?;
            if unsafe { libc::renameatx_np(self.parent.as_raw_fd(), stage.as_ptr(),
                self.parent.as_raw_fd(), live.as_ptr(), flags) } == 0 { Ok(()) }
            else { Err(format!("атомарная замена файла службы: {}", std::io::Error::last_os_error())) }
        }

        fn publish(&self) -> Result<(), String> {
            if self.position()? != StagePosition::Before { return Err("временный файл или прежний файл изменён".into()); }
            recheck_file(&self.stage_path(), &self.staged, self.uid)?;
            if let Some(prior) = &self.prior { recheck_file(&self.live_path(), prior, self.uid)?; }
            let result = self.rename(if self.prior.is_some() { libc::RENAME_SWAP } else { libc::RENAME_EXCL });
            let position = self.position();
            match (result, position) {
                (Ok(()), Ok(StagePosition::Published)) => Ok(()),
                (Err(error), Ok(actual)) => Err(format!("{error}; положение файлов: {actual:?}")),
                (Err(error), Err(readback)) => Err(format!("{error}; проверка положения: {readback}")),
                (Ok(()), Ok(actual)) => Err(format!("замена не подтверждена; положение файлов: {actual:?}")),
                (Ok(()), Err(readback)) => Err(format!("замена выполнена, но положение не проверено: {readback}")),
            }
        }

        fn remove_exact(&self, name: &str, file: &fs::File) -> Result<(), String> {
            recheck_directory(self.parent_path, self.parent, self.uid)?;
            let path = self.parent_path.join(name);
            recheck_file(&path, file, self.uid)?;
            let component = std::ffi::CString::new(name).map_err(|_| "неверное имя файла службы")?;
            let status = unsafe { libc::unlinkat(self.parent.as_raw_fd(), component.as_ptr(), 0) };
            let error = (status != 0).then(std::io::Error::last_os_error);
            let readback = recheck_directory(self.parent_path, self.parent, self.uid)
                .and_then(|_| entry_id(&path, self.uid));
            match (error, readback) {
                (None, Ok(None)) => Ok(()),
                (Some(error), Ok(actual)) => Err(format!("удаление проверенного файла: {error}; остаток: {actual:?}")),
                (Some(error), Err(readback)) => Err(format!("удаление проверенного файла: {error}; проверка: {readback}")),
                (None, Ok(actual)) => Err(format!("удаление не подтверждено; остаток: {actual:?}")),
                (None, Err(readback)) => Err(format!("удаление выполнено, но проверка не удалась: {readback}")),
            }
        }

        fn rollback(&self) -> Result<(), String> {
            match self.position()? {
                StagePosition::Before => self.remove_exact(self.stage_name, &self.staged),
                StagePosition::Published if self.prior.is_some() => {
                    let restored = self.rename(libc::RENAME_SWAP);
                    let position = self.position();
                    match (restored, position) {
                        (Ok(()), Ok(StagePosition::Before)) => self.remove_exact(self.stage_name, &self.staged),
                        (Err(error), Ok(actual)) => Err(format!("{error}; положение после восстановления: {actual:?}")),
                        (Err(error), Err(readback)) => Err(format!("{error}; проверка восстановления: {readback}")),
                        (Ok(()), Ok(actual)) => Err(format!("восстановление не подтверждено; положение: {actual:?}")),
                        (Ok(()), Err(readback)) => Err(format!("восстановление выполнено, но проверка не удалась: {readback}")),
                    }
                }
                StagePosition::Published => self.remove_exact(self.live_name, &self.staged),
                StagePosition::Conflict => Err("положение файлов службы неоднозначно; файлы сохранены".into()),
            }
        }

        fn settle_success(&self) -> Result<(), String> {
            if self.position()? != StagePosition::Published { return Err("итоговое положение файлов не подтверждено".into()); }
            if let Some(prior) = &self.prior { self.remove_exact(self.stage_name, prior)?; }
            Ok(())
        }
    }

    fn profile_snapshot(file: &fs::File) -> Result<(fs::Metadata, Vec<u8>), String> {
        let mut input = file.try_clone().map_err(|error| error.to_string())?;
        let before = input.metadata().map_err(|error| error.to_string())?;
        input.seek(SeekFrom::Start(0)).map_err(|error| error.to_string())?;
        let mut content = Vec::new();
        input.read_to_end(&mut content).map_err(|error| error.to_string())?;
        let after = input.metadata().map_err(|error| error.to_string())?;
        if !same_profile_stamp(&before, &after) {
            return Err("файл изменился во время чтения".into());
        }
        Ok((after, content))
    }

    fn same_profile_metadata(first: &fs::Metadata, second: &fs::Metadata) -> bool {
        first.uid() == second.uid() && first.gid() == second.gid() && first.mode() == second.mode()
            && first.mtime() == second.mtime() && first.mtime_nsec() == second.mtime_nsec()
    }

    fn same_profile_stamp(first: &fs::Metadata, second: &fs::Metadata) -> bool {
        same_profile_metadata(first, second) && first.len() == second.len()
            && first.ctime() == second.ctime() && first.ctime_nsec() == second.ctime_nsec()
    }

    /// Reuse the checked same-directory publisher for one user-owned text file.
    pub(crate) fn edit_owned_macos_file(
        directory: &Path, name: &'static str, stage_name: &'static str, apply: bool,
        edit: impl FnOnce(Option<&[u8]>) -> Result<Option<Vec<u8>>, String>,
        before_publish: impl FnOnce() -> Result<(), String>,
        after_publish: impl FnOnce() -> Result<(), String>,
    ) -> Result<bool, String> {
        let uid = unsafe { libc::geteuid() };
        let parent = owned_directory(directory, uid)?;
        let path = directory.join(name);
        let component = std::ffi::CString::new(name).map_err(|_| "неверное имя профиля")?;
        let fd = unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        let prior = if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound { None }
            else { return Err(format!("открытие профиля: {error}")); }
        } else {
            let file = unsafe { fs::File::from_raw_fd(fd) };
            recheck_file(&path, &file, uid)?;
            Some(file)
        };
        recheck_directory(directory, &parent, uid)?;
        let snapshot = prior.as_ref().map(profile_snapshot).transpose()?;
        let Some(replacement) = edit(snapshot.as_ref().map(|(_, bytes)| bytes.as_slice()))? else {
            recheck_directory(directory, &parent, uid)?;
            if let (Some(file), Some((metadata, bytes))) = (&prior, &snapshot) {
                recheck_file(&path, file, uid)?;
                let (current, content) = profile_snapshot(file)?;
                if !same_profile_metadata(metadata, &current) || content != *bytes {
                    return Err("содержимое профиля изменилось".into());
                }
            } else if entry_id(&path, uid)?.is_some() {
                return Err("профиль появился во время проверки".into());
            }
            if apply { after_publish()?; }
            return Ok(false);
        };
        if !apply { return Ok(true); }

        let mut stage = StagedFile::create(&parent, directory, name, stage_name, prior, uid, 0o600)?;
        let mut verified_publication = None;
        let publication = (|| -> Result<(), String> {
            write_stage(&mut stage, &replacement, 0o600)?;
            if let (Some(file), Some((metadata, _))) = (&stage.prior, &snapshot) {
                let status = unsafe { libc::fcopyfile(file.as_raw_fd(), stage.staged.as_raw_fd(),
                    std::ptr::null_mut(), libc::COPYFILE_METADATA) };
                if status != 0 { return Err(format!("копирование метаданных профиля: {}", std::io::Error::last_os_error())); }
                let (staged_metadata, _) = profile_snapshot(&stage.staged)?;
                if !same_profile_metadata(metadata, &staged_metadata) { return Err("метаданные профиля не сохранены".into()); }
                stage.staged.sync_all().map_err(|error| error.to_string())?;
            }
            if let (Some(file), Some((metadata, bytes))) = (&stage.prior, &snapshot) {
                let (current, content) = profile_snapshot(file)?;
                if !same_profile_stamp(metadata, &current) || content != *bytes {
                    return Err("исходный профиль изменился перед заменой".into());
                }
            }
            before_publish()?;
            // The boundary check may take time. Recheck the stable file stamp again
            // immediately before exchanging names.
            if let (Some(file), Some((metadata, _))) = (&stage.prior, &snapshot) {
                let current = file.metadata().map_err(|error| error.to_string())?;
                if !same_profile_stamp(metadata, &current) {
                    return Err("исходный профиль изменился перед заменой".into());
                }
            }
            stage.publish()?;
            let verify = || -> Result<(fs::Metadata, Option<fs::Metadata>), String> {
                recheck_file(&path, &stage.staged, uid)?;
                let (published, actual) = profile_snapshot(&stage.staged)?;
                if actual != replacement { return Err("новое содержимое профиля не подтверждено".into()); }
                let previous = if let (Some(file), Some((metadata, bytes))) = (&stage.prior, &snapshot) {
                    let (displaced, content) = profile_snapshot(file)?;
                    if !same_profile_metadata(metadata, &published) || !same_profile_metadata(metadata, &displaced) || content != *bytes {
                        return Err("метаданные или вытесненный профиль изменились при замене".into());
                    }
                    Some(displaced)
                } else { None };
                Ok((published, previous))
            };
            let (published, previous) = verify()?;
            verified_publication = Some((published.clone(), previous.clone()));
            after_publish()?;
            let (current, displaced) = verify()?;
            let same_displaced = match (previous, displaced) {
                (Some(before), Some(after)) => same_profile_stamp(&before, &after),
                (None, None) => true,
                _ => false,
            };
            if !same_profile_stamp(&published, &current) || !same_displaced {
                return Err("состояние профиля изменилось до завершения операции".into());
            }
            Ok(())
        })();
        if let Err(primary) = publication {
            let may_restore = stage.position().and_then(|position| {
                if position != StagePosition::Published { return Ok(()); }
                let (published, displaced) = verified_publication.as_ref()
                    .ok_or("прежнее и опубликованное состояния не подтверждены")?;
                recheck_file(&path, &stage.staged, uid)?;
                let (metadata, current) = profile_snapshot(&stage.staged)?;
                if current != replacement || !same_profile_stamp(published, &metadata) {
                    return Err("опубликованный профиль изменился".into());
                }
                match (&stage.prior, &snapshot, displaced) {
                    (Some(file), Some((_, before)), Some(stamp)) => {
                        recheck_file(&stage.stage_path(), file, uid)?;
                        let (metadata, contents) = profile_snapshot(file)?;
                        if contents != *before || !same_profile_stamp(stamp, &metadata) {
                            return Err("вытесненный исходный профиль изменился".into());
                        }
                    }
                    (None, None, None) => {},
                    _ => return Err("исходный профиль для восстановления не подтверждён".into()),
                }
                Ok(())
            });
            if let Err(readback) = may_restore {
                return Err(format!("{primary}; восстановление не начато, файлы сохранены: {readback}"));
            }
            return match stage.rollback() {
                Ok(()) => Err(primary),
                Err(rollback) => Err(format!("{primary}; профиль не восстановлен: {rollback}; положение: {:?}", stage.position())),
            };
        }
        stage.settle_success().map_err(|error| format!("новый профиль подтверждён, прежняя копия не закрыта: {error}"))?;
        Ok(true)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Profile { home: String, xdg: String }

    impl Profile {
        fn capture() -> Result<Self, String> {
            let (home, xdg) = crate::dns_forwarder::unix_launch_paths()?;
            Self::from_values(Some(home.into_os_string()), Some(xdg.into_os_string()))
        }

        fn from_values(home: Option<std::ffi::OsString>, xdg: Option<std::ffi::OsString>) -> Result<Self, String> {
            let home = home.ok_or("HOME не задан")?.into_string().map_err(|_| "HOME не является Unicode")?;
            if home.is_empty() || !Path::new(&home).is_absolute() { return Err("HOME должен быть непустым абсолютным путём".into()); }
            let xdg = match xdg {
                Some(value) => value.into_string().map_err(|_| "XDG_DATA_HOME не является Unicode")?,
                None => Path::new(&home).join(crate::dns_forwarder::UNIX_DATA_SUFFIX)
                    .to_str().ok_or("неверный каталог данных")?.to_owned(),
            };
            if xdg.is_empty() || !Path::new(&xdg).is_absolute() { return Err("XDG_DATA_HOME должен быть непустым абсолютным путём".into()); }
            Ok(Self { home, xdg })
        }

        fn install_dir(&self) -> PathBuf { install_dir_at(Path::new(&self.home)) }
        fn plist(&self, role: Role) -> PathBuf { role_plist_path(Path::new(&self.home), role) }
        fn log(&self, role: Role) -> PathBuf {
            match role {
                Role::Proxy => self.install_dir().join(role.log()),
                Role::Watchdog => Path::new(&self.xdg).join("agunlocker").join(role.log()),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum JobProfile { LegacyProxyUnbound, Bound { home: String, xdg: Option<String> } }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Generation { digests: Option<(String, String)>, profile: JobProfile }

    impl Generation {
        fn selected(profile: &Profile, source: String, helper: String) -> Self {
            Self { digests: Some((source, helper)), profile: JobProfile::Bound {
                home: profile.home.clone(), xdg: Some(profile.xdg.clone()),
            } }
        }

        fn helper_matches(&self, digest: &str) -> bool {
            self.digests.as_ref().is_none_or(|(_, expected)| expected == digest)
        }
    }

    fn definition_generation(role: Role, source: Option<&str>, helper: Option<&str>,
        home: Option<&str>, xdg: Option<&str>, selected: &Profile) -> Result<Generation, String> {
        let digests = match (source, helper) {
            (None, None) => None,
            (Some(source), Some(helper)) if valid_digest(source) && valid_digest(helper) => Some((source.to_owned(), helper.to_owned())),
            _ => return Err("неверные отпечатки окружения службы".into()),
        };
        let profile = match (home, xdg) {
            (None, None) if role == Role::Proxy => JobProfile::LegacyProxyUnbound,
            (Some(home), xdg) if digests.is_some() && (role == Role::Watchdog || xdg.is_some()) => {
                let effective = Profile::from_values(Some(home.into()), xdg.map(Into::into))?;
                if effective != *selected { return Err("окружение службы не совпадает с каталогом настроек".into()); }
                JobProfile::Bound { home: home.to_owned(), xdg: xdg.map(str::to_owned) }
            },
            _ => return Err("неполный профиль службы".into()),
        };
        Ok(Generation { digests, profile })
    }

    fn plist_value(role: Role, helper: &Path, log: &Path, source_digest: &str, helper_digest: &str, profile: &Profile)
        -> Result<serde_json::Value, String> {
        let helper = helper.to_str().ok_or("путь службы не поддерживается в plist")?;
        let log = log.to_str().ok_or("путь журнала не поддерживается в plist")?;
        let mut value = serde_json::json!({
            "Label": role.label(), "ProgramArguments": [helper, role.flag()],
            "RunAtLoad": true, "KeepAlive": true,
            "StandardOutPath": log, "StandardErrorPath": log,
            "EnvironmentVariables": { (SOURCE_DIGEST): source_digest, (HELPER_DIGEST): helper_digest,
                "HOME": profile.home, "XDG_DATA_HOME": profile.xdg }
        });
        if role == Role::Watchdog {
            value.as_object_mut().ok_or("неверный plist")?.remove("StandardOutPath");
            value.as_object_mut().ok_or("неверный plist")?.remove("StandardErrorPath");
        }
        Ok(value)
    }

    fn encode_plist(value: &serde_json::Value) -> Result<Vec<u8>, String> {
        use std::process::Stdio;
        let bytes = serde_json::to_vec(value).map_err(|error| format!("кодирование plist: {error}"))?;
        let mut child = Command::new("/usr/bin/plutil").args(["-convert", "xml1", "-o", "-", "--", "-"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().map_err(|error| format!("plutil не запущен: {error}"))?;
        let input = match child.stdin.take() {
            Some(mut input) => input.write_all(&bytes).map_err(|error| format!("передача plist в plutil: {error}")),
            None => Err("stdin plutil недоступен".to_owned()),
        };
        let output = child.wait_with_output().map_err(|error| format!("ожидание plutil: {error}"));
        match (input, output) {
            (Err(primary), Err(wait)) => Err(format!("{primary}; {wait}")),
            (Err(primary), Ok(output)) => Err(format!("{primary}; plutil завершён: {}", output.status)),
            (Ok(()), Err(wait)) => Err(wait),
            (Ok(()), Ok(output)) if !output.status.success() || !output.stderr.is_empty() || output.stdout.is_empty() =>
                Err(format!("преобразование plist не подтверждено: {}", output.status)),
            (Ok(()), Ok(output)) => Ok(output.stdout),
        }
    }

    fn read_plist(path: &Path, held: &fs::File, uid: u32) -> Result<serde_json::Value, String> {
        recheck_file(path, held, uid)?;
        let output = Command::new("/usr/bin/plutil").args(["-convert", "json", "-o", "-", "--"]).arg(path)
            .output().map_err(|error| format!("проверка plist: {error}"))?;
        recheck_file(path, held, uid)?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(format!("проверка plist не завершена: {}", output.status));
        }
        serde_json::from_slice(&output.stdout).map_err(|error| format!("неверный plist службы: {error}"))
    }

    fn valid_digest(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn plist_generation(role: Role, value: &serde_json::Value, helper: &Path, log: &Path, selected: &Profile)
        -> Result<Option<Generation>, String> {
        let helper = helper.to_str().ok_or("путь службы не поддерживается в plist")?;
        let log = log.to_str().ok_or("путь журнала не поддерживается в plist")?;
        let object = value.as_object().ok_or("plist службы не является словарём")?;
        if object.keys().any(|key| !["Label", "ProgramArguments", "RunAtLoad", "KeepAlive",
            "StandardOutPath", "StandardErrorPath", "EnvironmentVariables"].contains(&key.as_str()))
            || value.get("Label").and_then(|entry| entry.as_str()) != Some(role.label())
            || value.get("ProgramArguments") != Some(&serde_json::json!([helper, role.flag()]))
            || value.get("RunAtLoad").and_then(|entry| entry.as_bool()) != Some(true)
            || value.get("KeepAlive").and_then(|entry| entry.as_bool()) != Some(true)
            || (role == Role::Proxy && (value.get("StandardOutPath").and_then(|entry| entry.as_str()) != Some(log)
                || value.get("StandardErrorPath").and_then(|entry| entry.as_str()) != Some(log)))
            || (role == Role::Watchdog && (value.get("StandardOutPath").is_some() || value.get("StandardErrorPath").is_some())) {
            return Err("plist службы не совпадает с известной конфигурацией".into());
        }
        let environment = value.get("EnvironmentVariables").map(|entry|
            entry.as_object().ok_or("неверное окружение службы")).transpose()?;
        if environment.is_some_and(|environment| environment.iter().any(|(key, value)|
            ![SOURCE_DIGEST, HELPER_DIGEST, "HOME", "XDG_DATA_HOME"].contains(&key.as_str()) || !value.is_string())) {
            return Err("окружение службы содержит неизвестные значения".into());
        }
        let field = |key: &str| environment.and_then(|environment| environment.get(key)).and_then(|value| value.as_str());
        definition_generation(role, field(SOURCE_DIGEST), field(HELPER_DIGEST), field("HOME"), field("XDG_DATA_HOME"), selected).map(Some)
    }

    fn generation_is_current(plist: Option<&Generation>, loaded: Option<&Generation>,
        registered: bool, source_digest: &str, helper_digest: &str, selected: &Profile) -> Result<bool, String> {
        if registered && plist != loaded { return Err("окружение зарегистрированной службы не совпадает с plist".into()); }
        if !registered && loaded.is_some() { return Err("окружение отсутствующей службы неоднозначно".into()); }
        Ok(plist.is_some_and(|generation| generation == &Generation::selected(selected, source_digest.to_owned(), helper_digest.to_owned())))
    }

    fn write_stage(stage: &mut StagedFile<'_>, bytes: &[u8], mode: u32) -> Result<(), String> {
        recheck_directory(stage.parent_path, stage.parent, stage.uid)?;
        recheck_file(&stage.stage_path(), &stage.staged, stage.uid)?;
        stage.staged.set_permissions(fs::Permissions::from_mode(mode)).map_err(|error| format!("права временного файла: {error}"))?;
        stage.staged.write_all(bytes).map_err(|error| format!("запись временного файла: {error}"))?;
        stage.staged.sync_all().map_err(|error| format!("сохранение временного файла: {error}"))?;
        recheck_file(&stage.stage_path(), &stage.staged, stage.uid)
    }

    fn sign_helper_stage(stage: &mut StagedFile<'_>) -> Result<String, String> {
        recheck_directory(stage.parent_path, stage.parent, stage.uid)?;
        recheck_file(&stage.stage_path(), &stage.staged, stage.uid)?;
        let output = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--preserve-metadata=identifier,entitlements,flags,runtime"])
            .arg(stage.stage_path()).output().map_err(|error| format!("подпись файла службы не запущена: {error}"));
        let observed = recheck_directory(stage.parent_path, stage.parent, stage.uid)
            .and_then(|_| checked_file(&stage.stage_path(), stage.uid));
        match (output, observed) {
            (Err(primary), Err(readback)) => return Err(format!("{primary}; проверка временного файла: {readback}")),
            (Err(primary), Ok(file)) => { stage.staged = file; return Err(primary); },
            (Ok(output), Err(readback)) => return Err(format!("подпись завершена: {}; проверка временного файла: {readback}", output.status)),
            (Ok(output), Ok(file)) => {
                stage.staged = file;
                if !output.status.success() { return Err(format!("подпись файла службы не завершена: {}", output.status)); }
            }
        }
        let verify = Command::new("/usr/bin/codesign").args(["--verify", "--strict"]).arg(stage.stage_path())
            .output().map_err(|error| format!("проверка подписи службы: {error}"))?;
        recheck_directory(stage.parent_path, stage.parent, stage.uid)?;
        recheck_file(&stage.stage_path(), &stage.staged, stage.uid)?;
        if !verify.status.success() || !verify.stderr.is_empty() {
            return Err(format!("подпись файла службы не подтверждена: {}", verify.status));
        }
        file_digest(&stage.staged)
    }

    fn source_file(path: &Path) -> Result<fs::File, String> {
        let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW_ANY | libc::O_CLOEXEC)
            .open(path).map_err(|error| format!("открытие текущего приложения: {error}"))?;
        recheck_source(path, &file)?;
        Ok(file)
    }

    fn recheck_source(path: &Path, file: &fs::File) -> Result<(), String> {
        let held = file.metadata().map_err(|error| format!("проверка приложения: {error}"))?;
        let entry = fs::symlink_metadata(path).map_err(|error| format!("проверка приложения: {error}"))?;
        if !held.is_file() || !entry.is_file() || held.dev() != entry.dev() || held.ino() != entry.ino()
            || held.mode() != entry.mode() || held.len() != entry.len()
            || held.mtime() != entry.mtime() || held.mtime_nsec() != entry.mtime_nsec() {
            return Err("текущее приложение изменилось при подготовке службы".into());
        }
        Ok(())
    }

    fn prepare_helper(stage: &mut StagedFile<'_>, source_path: &Path, source: &fs::File,
        expected_digest: &str) -> Result<String, String> {
        recheck_source(source_path, source)?;
        recheck_file(&stage.stage_path(), &stage.staged, stage.uid)?;
        let mut input = source.try_clone().map_err(|error| format!("копия приложения: {error}"))?;
        input.seek(SeekFrom::Start(0)).map_err(|error| format!("позиция приложения: {error}"))?;
        stage.staged.set_permissions(fs::Permissions::from_mode(0o700)).map_err(|error| format!("права службы: {error}"))?;
        std::io::copy(&mut input, &mut stage.staged).map_err(|error| format!("копия приложения: {error}"))?;
        stage.staged.sync_all().map_err(|error| format!("сохранение копии приложения: {error}"))?;
        recheck_source(source_path, source)?;
        if file_digest(source)? != expected_digest || file_digest(&stage.staged)? != expected_digest {
            return Err("копия приложения или исходный файл изменились".into());
        }
        sign_helper_stage(stage)
    }

    fn prepare_plist(stage: &mut StagedFile<'_>, value: &serde_json::Value) -> Result<(), String> {
        let xml = encode_plist(value)?;
        write_stage(stage, &xml, 0o600)?;
        recheck_directory(stage.parent_path, stage.parent, stage.uid)?;
        if read_plist(&stage.stage_path(), &stage.staged, stage.uid)? != *value {
            return Err("содержимое подготовленного plist не совпадает с запросом".into());
        }
        recheck_directory(stage.parent_path, stage.parent, stage.uid)
    }

    pub fn install_dir() -> Result<PathBuf, String> {
        crate::dns_forwarder::unix_user_home().map(|home| install_dir_at(&home))
    }

    fn install_dir_at(home: &Path) -> PathBuf { home.join("Library").join("Application Support").join("AGUnlocker") }

    fn role_plist_path(home: &Path, role: Role) -> PathBuf { home.join("Library").join("LaunchAgents").join(role.plist()) }

    pub fn installed_exe() -> Result<PathBuf, String> {
        install_dir().map(|dir| dir.join("ag_proxy"))
    }

    pub fn is_enabled() -> bool {
        crate::dns_forwarder::unix_user_home().is_ok_and(|home| role_plist_path(&home, Role::Proxy).exists())
    }

    pub fn is_watchdog_enabled() -> bool {
        watchdog_running_checked().unwrap_or(false)
    }

    pub fn is_running() -> bool {
        owned_proxy_listener_at(crate::proxy::port()).unwrap_or(false)
    }

    fn outdated_version(version: Result<u32, String>) -> Result<bool, String> {
        version.map(|version| version < crate::dns_forwarder::RELAY_VERSION)
    }

    pub(crate) fn checked_relay_outdated() -> Result<bool, String> {
        outdated_version(crate::dns_forwarder::checked_installed_version())
    }

    // Legacy CA-removal guard: an unreceived version holds cleanup. This bool
    // is not a currentness, installation or repair authorization result.
    pub fn relay_is_outdated() -> bool {
        checked_relay_outdated().unwrap_or_else(|error| {
            eprintln!("Версия службы не подтверждена: {error}");
            true
        })
    }

    pub fn ensure_running() -> Result<(), String> {
        ensure_owned_running(crate::proxy::port())
    }

    pub fn enable() -> Result<(), String> {
        ensure_running()
    }

    pub fn enable_watchdog() -> Result<(), String> {
        ensure_role_running(Role::Watchdog, 0)
    }

    pub fn ensure_installed() -> Result<(), String> {
        Ok(())
    }

    pub fn disable_watchdog() { if let Err(error) = disable_watchdog_checked() { eprintln!("{error}"); } }

    pub fn disable_watchdog_checked() -> Result<(), String> { disable_role(Role::Watchdog) }

    pub fn watchdog_directory() -> Result<fs::File, String> {
        owned_directory(&install_dir()?, unsafe { libc::geteuid() })
    }

    pub fn recheck_watchdog_directory(directory: &fs::File) -> Result<(), String> {
        recheck_directory(&install_dir()?, directory, unsafe { libc::geteuid() })
    }

    pub fn open_watchdog_log() -> Result<fs::File, String> {
        open_watchdog_log_at(&crate::dns_forwarder::checked_log_dir()?)
    }

    fn open_watchdog_log_at(directory_path: &Path) -> Result<fs::File, String> {
        let uid = unsafe { libc::geteuid() };
        let directory = owned_directory(directory_path, uid)?;
        let path = directory_path.join(Role::Watchdog.log());
        let file = fs::OpenOptions::new().read(true).append(true).create(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW_ANY | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path).map_err(|error| format!("открытие журнала автопатча: {error}"))?;
        recheck_directory(directory_path, &directory, uid)?;
        recheck_file(&path, &file, uid)?;
        if file.metadata().map_err(|error| error.to_string())?.mode() & 0o077 != 0 {
            return Err("журнал автопатча доступен другим пользователям".into());
        }
        Ok(file)
    }

    pub fn watchdog_running_checked() -> Result<bool, String> {
        let role = Role::Watchdog;
        let uid = unsafe { libc::geteuid() };
        let profile = Profile::capture()?;
        let plist = profile.plist(role);
        let helper = profile.install_dir().join(role.helper());
        if disabled_override(role, uid)? { return Err("служба отключена в launchd".into()); }
        if received_job(role, uid, &plist, &helper, &profile)?.is_none() {
            if optional_owned_file(&plist, uid)?.is_some() || optional_owned_file(&helper, uid)?.is_some() {
                return Err("служба отсутствует, но её файлы сохранены".into());
            }
            return Ok(false);
        }
        let plist_file = checked_file(&plist, uid)?;
        let helper_file = checked_file(&helper, uid)?;
        let pair = plist_generation(role, &read_plist(&plist, &plist_file, uid)?, &helper, &profile.log(role), &profile)?;
        let plist_digest = file_digest(&plist_file)?;
        let helper_digest = file_digest(&helper_file)?;
        let prior = PriorWitness { plist: &plist_file, helper: &helper_file,
            plist_digest: &plist_digest, helper_digest: &helper_digest, pair: pair.as_ref() };
        if role_running_with_profile(role, 0, Some(&prior), &profile)? { Ok(true) }
        else { Err("готовность журнала автопатча не подтверждена".into()) }
    }

    fn ensure_owned_running(port: u16) -> Result<(), String> { ensure_role_running(Role::Proxy, port) }

    fn check_generation_presence(role: Role, helper: bool, plist: bool, registered: bool) -> Result<(), String> {
        if helper != plist || (registered && !helper)
            || (role == Role::Watchdog && !registered && helper) {
            return Err("файлы и регистрация службы не образуют проверенное поколение".into());
        }
        Ok(())
    }

    fn replacement_is_owned(bootstrap_attempted: bool, pair: Option<&Generation>, job: &OwnedJob,
        helper_position: StagePosition, plist_position: StagePosition) -> bool {
        bootstrap_attempted && helper_position == StagePosition::Published
            && plist_position == StagePosition::Published
            && pair.is_some_and(|pair| job.generation.as_ref() == Some(pair))
    }

    fn receive_newer_reuse(ready: Result<bool, String>) -> Result<(), String> {
        match ready {
            Ok(true) => Ok(()),
            Ok(false) => Err("Установлена более новая служба; её готовность не подтверждена, служба сохранена".into()),
            Err(error) => Err(format!("Установлена более новая служба; она сохранена: {error}")),
        }
    }

    fn ensure_role_running(role: Role, port: u16) -> Result<(), String> {
        if role == Role::Proxy {
            match crate::dns_forwarder::checked_installed_version() {
                Ok(version) if version > crate::dns_forwarder::RELAY_VERSION => {
                    return receive_newer_reuse(owned_proxy_listener_at(port));
                }
                Err(error) => eprintln!("Версия службы не подтверждена перед выбранным восстановлением: {error}"),
                _ => {}
            }
        }
        let uid = unsafe { libc::geteuid() };
        let profile = Profile::capture()?;
        let home = Path::new(&profile.home);
        let source_path = std::env::current_exe().map_err(|error| format!("нет пути к приложению: {error}"))?;
        let source = source_file(&source_path)?;
        let source_digest = file_digest(&source)?;
        let helper = profile.install_dir().join(role.helper()); let plist = profile.plist(role); let log = profile.log(role);
        if source_path == helper { return Err("служба не может обновлять собственный исполняемый файл".into()); }
        if disabled_override(role, uid)? { return Err("служба явно отключена в launchd; настройка сохранена".into()); }
        let old_job = received_job(role, uid, &plist, &helper, &profile)?;
        let old_helper = optional_owned_file(&helper, uid)?;
        let old_plist = optional_owned_file(&plist, uid)?;
        check_generation_presence(role, old_helper.is_some(), old_plist.is_some(), old_job.is_some())?;
        let home_dir = owned_directory(&home, uid)?;
        let library_path = home.join("Library");
        let library = owned_child_directory(&home_dir, &home, "Library", uid)?;
        let support_path = library_path.join("Application Support");
        let support = owned_child_directory(&library, &library_path, "Application Support", uid)?;
        let install_path = support_path.join("AGUnlocker");
        let install = owned_child_directory(&support, &support_path, "AGUnlocker", uid)?;
        let agents_path = library_path.join("LaunchAgents");
        let agents = owned_child_directory(&library, &library_path, "LaunchAgents", uid)?;
        let old_pair = match (&old_plist, &old_helper, &old_job) {
            (Some(plist_file), Some(helper_file), job) => {
                let pair = plist_generation(role, &read_plist(&plist, plist_file, uid)?, &helper, &log, &profile)?;
                if job.as_ref().is_some_and(|job| pair.as_ref() != job.generation.as_ref()) { return Err("окружение службы не совпадает с plist".into()); }
                let helper_digest = file_digest(helper_file)?;
                if pair.as_ref().is_some_and(|pair| !pair.helper_matches(&helper_digest)) { return Err("файл службы не совпадает с plist".into()); }
                if role == Role::Watchdog {
                    let plist_digest = file_digest(plist_file)?;
                    let prior = PriorWitness { plist: plist_file, helper: helper_file,
                        plist_digest: &plist_digest, helper_digest: &helper_digest, pair: pair.as_ref() };
                    if !role_running_with_profile(role, port, Some(&prior), &profile)? {
                        return Err("готовность существующего автопатча не подтверждена; служба сохранена".into());
                    }
                    recheck_file(&plist, plist_file, uid)?; recheck_file(&helper, helper_file, uid)?;
                    return Ok(());
                }
                if let Some(job) = job {
                    if generation_is_current(pair.as_ref(), job.generation.as_ref(), true, &source_digest, &helper_digest, &profile)? {
                        receive_ready(role, uid, &plist, &helper, pair.as_ref(), port, None, &profile)?;
                        recheck_source(&source_path, &source)?; recheck_file(&plist, plist_file, uid)?; recheck_file(&helper, helper_file, uid)?;
                        return Ok(());
                    }
                }
                pair
            },
            (None, None, None) => None,
            _ => return Err("неполная конфигурация службы".into()),
        };
        let old_digests = match (&old_plist, &old_helper) {
            (Some(plist_file), Some(helper_file)) => Some((file_digest(plist_file)?, file_digest(helper_file)?)),
            (None, None) => None,
            _ => return Err("неполные прежние файлы службы".into()),
        };
        if role == Role::Proxy {
            match crate::dns_forwarder::checked_installed_version() {
                Ok(version) if version > crate::dns_forwarder::RELAY_VERSION =>
                    return Err("Версия службы стала новее во время проверки; служба сохранена".into()),
                Err(error) => eprintln!("Версия службы не подтверждена перед подготовкой: {error}"),
                _ => {}
            }
        }
        let mut helper_stage = StagedFile::create(&install, &install_path, role.helper(), role.helper_stage(), old_helper, uid, 0o700)?;
        let mut plist_stage = match StagedFile::create(&agents, &agents_path, role.plist(), role.plist_stage(), old_plist, uid, 0o600) {
            Ok(stage) => stage,
            Err(primary) => return match helper_stage.rollback() { Ok(()) => Err(primary), Err(error) => Err(format!("{primary}; очистка копии: {error}")) },
        };
        let mut new_pair = None;
        let mut bootstrap_attempted = false;
        let attempt = (|| -> Result<(), String> {
            let helper_digest = prepare_helper(&mut helper_stage, &source_path, &source, &source_digest)?;
            let pair = Generation::selected(&profile, source_digest.clone(), helper_digest.clone());
            prepare_plist(&mut plist_stage, &plist_value(role, &helper, &log, &source_digest, &helper_digest, &profile)?)?;
            new_pair = Some(pair.clone());
            recheck_source(&source_path, &source)?;
            if file_digest(&source)? != source_digest || disabled_override(role, uid)? { return Err("исходное приложение или настройка службы изменились".into()); }
            if let Some(job) = &old_job {
                stop_owned_job(role, uid, &plist, &helper, job, plist_stage.prior.as_ref().ok_or("нет старого plist")?, helper_stage.prior.as_ref().ok_or("нет старой службы")?, &profile)?;
            } else if received_job(role, uid, &plist, &helper, &profile)?.is_some() { return Err("служба появилась во время подготовки".into()); }
            helper_stage.publish()?; plist_stage.publish()?;
            if received_job(role, uid, &plist, &helper, &profile)?.is_some() { return Err("служба появилась до загрузки нового поколения".into()); }
            bootstrap_attempted = true;
            bootstrap(uid, &plist)?;
            receive_ready(role, uid, &plist, &helper, Some(&pair), port, None, &profile)?;
            recheck_file(&helper, &helper_stage.staged, uid)?; recheck_file(&plist, &plist_stage.staged, uid)?;
            if !pair.helper_matches(&file_digest(&helper_stage.staged)?) { return Err("новый файл службы изменился".into()); }
            Ok(())
        })();
        if let Err(primary) = attempt {
            let mut errors = Vec::new();
            let mut may_restore = true;
            match received_job(role, uid, &plist, &helper, &profile) {
                Ok(Some(job)) if old_job.as_ref() != Some(&job) => {
                    let stop = (|| -> Result<(), String> {
                        if !replacement_is_owned(bootstrap_attempted, new_pair.as_ref(), &job,
                            helper_stage.position()?, plist_stage.position()?) {
                            return Err("регистрация службы изменилась; файлы сохранены".into());
                        }
                        stop_owned_job(role, uid, &plist, &helper, &job, &plist_stage.staged, &helper_stage.staged, &profile)
                    })();
                    if let Err(error) = stop {
                        errors.push(format!("остановка нового поколения: {error}")); may_restore = false;
                    }
                },
                Ok(Some(job)) if old_job.as_ref() == Some(&job) => {},
                Ok(None) => {},
                Ok(Some(_)) => { errors.push("регистрация службы изменилась; файлы сохранены".into()); may_restore = false; },
                Err(error) => { errors.push(format!("состояние службы: {error}")); may_restore = false; },
            }
            if may_restore && old_job.is_none() {
                match received_job(role, uid, &plist, &helper, &profile) {
                    Ok(None) => {},
                    Ok(Some(_)) => { errors.push("служба появилась до восстановления; файлы сохранены".into()); may_restore = false; },
                    Err(error) => { errors.push(format!("проверка отсутствия службы до восстановления: {error}")); may_restore = false; },
                }
            }
            if may_restore {
                if let Err(error) = plist_stage.rollback() { errors.push(format!("восстановление plist: {error}")); }
                if let Err(error) = helper_stage.rollback() { errors.push(format!("восстановление файла службы: {error}")); }
                if errors.is_empty() && old_job.is_some() {
                    let recovery = (|| -> Result<(), String> {
                        if disabled_override(role, uid)? { return Err("служба отключена; настройка сохранена".into()); }
                        if received_job(role, uid, &plist, &helper, &profile)?.is_none() { bootstrap(uid, &plist)?; }
                        let digests = old_digests.as_ref().ok_or("нет отпечатков прежней службы")?;
                        let prior = PriorWitness {
                            plist: plist_stage.prior.as_ref().ok_or("нет прежнего plist")?,
                            helper: helper_stage.prior.as_ref().ok_or("нет прежнего файла службы")?,
                            plist_digest: &digests.0, helper_digest: &digests.1, pair: old_pair.as_ref(),
                        };
                        receive_ready(role, uid, &plist, &helper, old_pair.as_ref(), port, Some(&prior), &profile)
                    })();
                    if let Err(error) = recovery { errors.push(format!("возобновление прежней службы: {error}")); }
                }
                if old_job.is_none() {
                    let recovery = (|| -> Result<(), String> {
                        match (&plist_stage.prior, &helper_stage.prior, &old_digests) {
                            (Some(plist_file), Some(helper_file), Some((plist_digest, helper_digest))) => {
                                recheck_file(&plist, plist_file, uid)?; recheck_file(&helper, helper_file, uid)?;
                                if file_digest(plist_file)? != *plist_digest || file_digest(helper_file)? != *helper_digest {
                                    return Err("прежние файлы службы изменились".into());
                                }
                            },
                            (None, None, None) => {
                                if entry_id(&plist, uid)?.is_some() || entry_id(&helper, uid)?.is_some() {
                                    return Err("файлы отсутствовавшей службы появились".into());
                                }
                            },
                            _ => return Err("неполные прежние файлы службы".into()),
                        }
                        if received_job(role, uid, &plist, &helper, &profile)?.is_some() {
                            return Err("служба появилась после восстановления файлов".into());
                        }
                        Ok(())
                    })();
                    if let Err(error) = recovery { errors.push(format!("восстановление отсутствовавшей регистрации: {error}")); }
                }
            }
            return if errors.is_empty() { Err(primary) } else { Err(format!("{primary}; {}", errors.join("; "))) };
        }
        let mut cleanup = Vec::new();
        if let Err(error) = plist_stage.settle_success() { cleanup.push(format!("старый plist: {error}")); }
        if let Err(error) = helper_stage.settle_success() { cleanup.push(format!("старый файл службы: {error}")); }
        if cleanup.is_empty() { Ok(()) } else { Err(format!("служба запущена, прежние файлы требуют проверки: {}", cleanup.join("; "))) }
    }

    fn check_lsof_warnings(stderr: &[u8]) -> Result<(), String> {
        let warnings = std::str::from_utf8(stderr).map_err(|_| "неверная диагностика lsof")?;
        if !warnings.is_empty() {
            if !warnings.ends_with('\n') { return Err(format!("неполная диагностика lsof: {warnings}")); }
            let mut lines = warnings.lines();
            while let Some(first) = lines.next() {
                let second = lines.next(); let third = lines.next();
                if !first.starts_with("lsof: WARNING: can't stat() ")
                    || second != Some("      Output information may be incomplete.")
                    || !third.is_some_and(|line| line.starts_with("      assuming \"dev=") && line.ends_with("\" from mount table")) {
                    return Err(format!("неподдерживаемая диагностика lsof: {warnings}"));
                }
            }
            eprint!("{warnings}");
        }
        Ok(())
    }

    fn listener_output(status: Option<i32>, stdout: &[u8], stderr: &[u8], pid: u32, port: u16) -> Result<bool, String> {
        check_lsof_warnings(stderr)?;
        let warnings = std::str::from_utf8(stderr).map_err(|_| "неверная диагностика lsof")?;
        if status == Some(1) && stdout.is_empty() { return Ok(false); }
        if status != Some(0) { return Err(format!("проверка сокета lsof не завершена: {status:?}; {warnings}")); }
        let text = std::str::from_utf8(stdout).map_err(|_| "неверный ответ lsof")?;
        if !text.ends_with('\n') { return Err("неполный ответ lsof".into()); }
        let mut lines = text.lines();
        let process = format!("p{pid}"); let address = format!("n127.0.0.1:{port}");
        if lines.next() != Some(process.as_str()) { return Err("неверный процесс в ответе lsof".into()); }
        let descriptor = lines.next().and_then(|line| line.strip_prefix('f')).ok_or("нет дескриптора сокета")?;
        if descriptor.is_empty() || !descriptor.bytes().all(|byte| byte.is_ascii_digit())
            || lines.next() != Some(address.as_str()) || lines.next().is_some() {
            return Err("неверный сокет в ответе lsof".into());
        }
        Ok(true)
    }

    fn watchdog_log_output(status: Option<i32>, stdout: &[u8], stderr: &[u8], pid: u32,
        dev: u64, ino: u64) -> Result<bool, String> {
        check_lsof_warnings(stderr)?;
        if status != Some(0) { return Err(format!("проверка журнала lsof не завершена: {status:?}")); }
        let text = std::str::from_utf8(stdout).map_err(|_| "неверный ответ lsof")?;
        if !text.ends_with('\n') { return Err("неполный ответ lsof".into()); }
        let mut lines = text.lines();
        if lines.next() != Some(format!("p{pid}").as_str()) { return Err("неверный процесс в ответе lsof".into()); }
        let mut fd: Option<&str> = None;
        let mut access: Option<&str> = None;
        let mut device: Option<&str> = None;
        let mut inode: Option<&str> = None;
        let mut found = std::collections::HashSet::new();
        let mut receive = |fd: Option<&str>, access: Option<&str>, device: Option<&str>, inode: Option<&str>| -> Result<(), String> {
            let Some(fd) = fd else { return Ok(()); };
            let Ok(number) = fd.parse::<u32>() else { return Ok(()); };
            if number <= 2 || !matches!(access, Some("w" | "u")) { return Ok(()); }
            let Some((device, inode)) = device.zip(inode) else { return Ok(()); };
            let device = device.strip_prefix("0x").and_then(|s| u64::from_str_radix(s, 16).ok()).ok_or("неверное устройство lsof")?;
            let inode = inode.parse::<u64>().map_err(|_| "неверный inode lsof")?;
            if device == dev && inode == ino && !found.insert(number) { return Err("повторный дескриптор журнала".into()); }
            Ok(())
        };
        for line in lines {
            if line.is_empty() || !line.as_bytes()[0].is_ascii() { return Err("неверное поле lsof".into()); }
            let (key, value) = line.split_at(1);
            match key {
                "f" => { receive(fd, access, device, inode)?; fd = Some(value); access = None; device = None; inode = None; },
                "a" => if access.replace(value).is_some() { return Err("повторный доступ lsof".into()); },
                "D" => if device.replace(value).is_some() { return Err("повторное устройство lsof".into()); },
                "i" => if inode.replace(value).is_some() { return Err("повторный inode lsof".into()); },
                _ => return Err("неизвестное поле lsof".into()),
            }
        }
        receive(fd, access, device, inode)?;
        Ok(found.len() >= 2)
    }

    fn observe_watchdog_log(pid: u32, log: &fs::File) -> Result<bool, String> {
        let info = log.metadata().map_err(|error| format!("проверка журнала: {error}"))?;
        let output = Command::new("/usr/sbin/lsof").args(["-a", "-p", &pid.to_string(), "-FpfaDi"])
            .output().map_err(|error| format!("проверка журнала не запущена: {error}"))?;
        watchdog_log_output(output.status.code(), &output.stdout, &output.stderr, pid, info.dev(), info.ino())
    }

    fn observe_listener(pid: u32, port: u16) -> Result<bool, String> {
        let output = Command::new("/usr/sbin/lsof").args(["-a", "-p", &pid.to_string(), &format!("-iTCP:{port}"),
            "-sTCP:LISTEN", "-nP", "-Fpfn"]).output().map_err(|error| format!("проверка сокета не запущена: {error}"))?;
        listener_output(output.status.code(), &output.stdout, &output.stderr, pid, port)
    }

    pub fn owned_proxy_listener_at(port: u16) -> Result<bool, String> {
        role_running(Role::Proxy, port, None)
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ProxyEnvironmentProfile { Qualified, LegacyUnbound }

    /// Receive the proxy generation's settings owner without probing its listener.
    pub(crate) fn check_proxy_environment_profile(home: &Path) -> Result<ProxyEnvironmentProfile, String> {
        let profile = Profile::capture()?;
        if Path::new(&profile.home) != home { return Err("Домашний каталог службы изменился.".into()); }
        let role = Role::Proxy;
        let uid = unsafe { libc::geteuid() };
        let plist = profile.plist(role);
        let helper = profile.install_dir().join(role.helper());
        let job = received_job(role, uid, &plist, &helper, &profile)?;
        if job.is_none() { return Ok(ProxyEnvironmentProfile::Qualified); }
        let plist_file = optional_owned_file(&plist, uid)?;
        let helper_file = optional_owned_file(&helper, uid)?;
        check_generation_presence(role, helper_file.is_some(), plist_file.is_some(), job.is_some())?;
        let binding = if let (Some(plist_file), Some(helper_file)) = (&plist_file, &helper_file) {
            let plist_digest = file_digest(plist_file)?;
            let document = read_plist(&plist, plist_file, uid)?;
            let pair = plist_generation(role, &document, &helper, &profile.log(role), &profile)?
                .ok_or("Поколение службы не подтверждено.")?;
            if job.as_ref().is_some_and(|job| job.generation.as_ref() != Some(&pair))
                || !pair.helper_matches(&file_digest(helper_file)?)
            {
                return Err("Поколение службы не совпадает с полученным профилем.".into());
            }
            recheck_file(&plist, plist_file, uid)?;
            recheck_file(&helper, helper_file, uid)?;
            if file_digest(plist_file)? != plist_digest {
                return Err("Определение службы изменилось во время проверки.".into());
            }
            match pair.profile {
                JobProfile::Bound { .. } => ProxyEnvironmentProfile::Qualified,
                JobProfile::LegacyProxyUnbound => ProxyEnvironmentProfile::LegacyUnbound,
            }
        } else { return Err("Файлы зарегистрированной службы не подтверждены.".into()); };
        let current = received_job(role, uid, &plist, &helper, &profile)?;
        if current.as_ref().map(|job| &job.generation) != job.as_ref().map(|job| &job.generation) {
            return Err("Регистрация службы изменилась во время проверки.".into());
        }
        Ok(binding)
    }

    struct PriorWitness<'a> {
        plist: &'a fs::File, helper: &'a fs::File,
        plist_digest: &'a str, helper_digest: &'a str, pair: Option<&'a Generation>,
    }

    impl PriorWitness<'_> {
        fn matches(&self, pair: Option<&Generation>, plist_digest: &str, helper_digest: &str) -> bool {
            pair == self.pair && plist_digest == self.plist_digest && helper_digest == self.helper_digest
        }
    }

    fn role_running(role: Role, port: u16, prior: Option<&PriorWitness<'_>>) -> Result<bool, String> {
        let profile = Profile::capture()?;
        role_running_with_profile(role, port, prior, &profile)
    }

    fn role_running_with_profile(role: Role, port: u16, prior: Option<&PriorWitness<'_>>, profile: &Profile) -> Result<bool, String> {
        let uid = unsafe { libc::geteuid() };
        let plist = profile.plist(role);
        let helper = profile.install_dir().join(role.helper());
        let Some(job) = received_job(role, uid, &plist, &helper, &profile)? else { return Ok(false); };
        let pid = job.pid.ok_or("нет PID зарегистрированной службы")?;
        if job.state != "running" { return Err("состояние зарегистрированной службы не подтверждено".into()); }
        let plist_file = checked_file(&plist, uid)?;
        let helper_file = checked_file(&helper, uid)?;
        let plist_digest = file_digest(&plist_file)?;
        let pair = plist_generation(role, &read_plist(&plist, &plist_file, uid)?, &helper, &profile.log(role), &profile)?;
        if job.generation.as_ref() != pair.as_ref() {
            return Err("поколение службы изменилось".into());
        }
        let helper_digest = file_digest(&helper_file)?;
        if pair.as_ref().is_some_and(|pair| !pair.helper_matches(&helper_digest)) {
            return Err("файл службы не совпадает с поколением".into());
        }
        let source = if let Some(prior) = prior {
            recheck_file(&plist, prior.plist, uid)?; recheck_file(&helper, prior.helper, uid)?;
            if !prior.matches(pair.as_ref(), &plist_digest, &helper_digest) {
                return Err("прежние файлы службы изменились".into());
            }
            None
        } else {
            let pair = pair.as_ref().ok_or("у службы нет проверенного поколения")?;
            let path = std::env::current_exe().map_err(|error| format!("путь приложения: {error}"))?;
            let file = source_file(&path)?;
            let digest = file_digest(&file)?;
            if !generation_is_current(Some(pair), job.generation.as_ref(), true, &digest, &helper_digest, profile)? {
                return Err("исходное приложение или профиль не совпадает с поколением службы".into());
            }
            Some((path, file, digest))
        };
        let identity = generation(pid, uid)?.ok_or("процесс службы завершился")?;
        check_process_image(pid, &helper)?;
        let log_path = profile.log(role);
        let log = if role == Role::Watchdog {
            let file = checked_file(&log_path, uid)?;
            if file.metadata().map_err(|error| error.to_string())?.mode() & 0o077 != 0 {
                return Err("журнал автопатча доступен другим пользователям".into());
            }
            Some(file)
        } else { None };
        let observation = if let Some(log) = &log { observe_watchdog_log(pid, log) } else { observe_listener(pid, port) };
        let recheck = (|| -> Result<(), String> {
            if let Some((path, file, digest)) = &source {
                recheck_source(path, file)?;
                if file_digest(file)? != *digest { return Err("исходное приложение изменилось".into()); }
            }
            recheck_file(&plist, &plist_file, uid)?; recheck_file(&helper, &helper_file, uid)?;
            if let Some(log) = &log { recheck_file(&log_path, log, uid)?; }
            if file_digest(&plist_file)? != plist_digest || file_digest(&helper_file)? != helper_digest
                || generation(pid, uid)? != Some(identity) || received_job(role, uid, &plist, &helper, &profile)?.as_ref() != Some(&job) {
                return Err("поколение службы изменилось при проверке сокета".into());
            }
            check_process_image(pid, &helper)
        })();
        match (observation, recheck) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(primary), Err(later)) => Err(format!("{primary}; повторная проверка: {later}")),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(later)) => Err(later),
        }
    }

    fn bootstrap(uid: u32, plist: &Path) -> Result<(), String> {
        let output = Command::new("/bin/launchctl").args(["bootstrap", &format!("gui/{uid}")]).arg(plist)
            .output().map_err(|error| format!("загрузка службы не запущена: {error}"))?;
        if !output.status.success() || !output.stderr.is_empty() {
            let stderr = match std::str::from_utf8(&output.stderr) {
                Ok(text) => format!("{text:?}"),
                Err(_) => format!("{:?}", output.stderr),
            };
            return Err(format!("загрузка службы не подтверждена: {}; stderr: {stderr}", output.status));
        }
        Ok(())
    }

    fn receive_ready(role: Role, uid: u32, plist: &Path, helper: &Path, pair: Option<&Generation>, port: u16, prior: Option<&PriorWitness<'_>>, profile: &Profile) -> Result<(), String> {
        let mut job = received_job(role, uid, plist, helper, profile)?.ok_or("служба не зарегистрирована")?;
        if job.generation.as_ref() != pair { return Err("поколение зарегистрированной службы не совпадает".into()); }
        if role == Role::Watchdog {
            let expected_pid = if job.state != "running" {
                let target = format!("gui/{uid}/{}", role.label());
                let output = Command::new("/bin/launchctl").args(["kickstart", "-p", &target]).output()
                    .map_err(|error| format!("запуск службы не выполнен: {error}"))?;
                if !output.status.success() || !output.stderr.is_empty() { return Err(format!("запуск службы не подтверждён: {}", output.status)); }
                Some(std::str::from_utf8(&output.stdout).map_err(|_| "неверный PID службы")?.trim()
                    .parse::<u32>().ok().filter(|pid| *pid != 0).ok_or("нет PID службы")?)
            } else { None };
            let deadline = std::time::Instant::now() + crate::dns_forwarder::PROXY_START_BUDGET;
            loop {
                let observed = (|| -> Result<(), String> {
                    let current = received_job(role, uid, plist, helper, profile)?.ok_or("служба не зарегистрирована")?;
                    if current.generation.as_ref() != pair || current.state != "running"
                        || expected_pid.is_some_and(|pid| current.pid != Some(pid)) {
                        return Err("поколение запуска службы не подтверждено".into());
                    }
                    if !role_running_with_profile(role, port, prior, profile)? { return Err("готовность журнала не подтверждена".into()); }
                    if received_job(role, uid, plist, helper, profile)?.as_ref() != Some(&current) {
                        return Err("процесс службы изменился при проверке готовности".into());
                    }
                    Ok(())
                })();
                match observed {
                    Ok(()) => return Ok(()),
                    Err(error) if std::time::Instant::now() >= deadline => return Err(format!("готовность службы не подтверждена: {error}")),
                    Err(_) => std::thread::sleep(crate::proxy::POLL_FOR_LISTENER),
                }
            }
        }
        if job.state != "running" || !role_running_with_profile(role, port, prior, profile)? {
            let target = format!("gui/{uid}/{}", role.label());
            let output = Command::new("/bin/launchctl").args(["kickstart", "-p", &target]).output()
                .map_err(|error| format!("запуск службы не выполнен: {error}"))?;
            if !output.status.success() || !output.stderr.is_empty() { return Err(format!("запуск службы не подтверждён: {}", output.status)); }
            let pid = std::str::from_utf8(&output.stdout).map_err(|_| "неверный PID службы")?.trim()
                .parse::<u32>().ok().filter(|pid| *pid != 0).ok_or("нет PID службы")?;
            let deadline = std::time::Instant::now() + crate::dns_forwarder::PROXY_START_BUDGET;
            loop {
                if role_running_with_profile(role, port, prior, profile)? { break; }
                if std::time::Instant::now() >= deadline { return Err("готовность службы не подтверждена".into()); }
                std::thread::sleep(crate::proxy::POLL_FOR_LISTENER);
            }
            job = received_job(role, uid, plist, helper, profile)?.ok_or("служба исчезла после запуска")?;
            if job.pid != Some(pid) { return Err("PID запущенной службы изменился".into()); }
        }
        if job.state != "running" || job.generation.as_ref() != pair { return Err("состояние службы изменилось".into()); }
        let pid = job.pid.ok_or("нет PID службы")?;
        let identity = generation(pid, uid)?.ok_or("процесс службы завершился")?;
        check_process_image(pid, helper)?;
        if generation(pid, uid)? != Some(identity) || received_job(role, uid, plist, helper, profile)?.as_ref() != Some(&job) {
            return Err("процесс службы изменился при проверке".into());
        }
        Ok(())
    }

    #[derive(Debug, PartialEq, Eq)]
    struct OwnedJob { pid: Option<u32>, state: String, generation: Option<Generation> }

    fn parse_owned_job(role: Role, text: &str, uid: u32, plist: &Path, helper: &Path, profile: &Profile) -> Result<OwnedJob, String> {
        let mut path = None; let mut program = None; let mut domain = None;
        let mut state = None; let mut pid = None; let mut arguments: Option<Vec<&str>> = None;
        let mut in_arguments = false;
        let mut in_environment = false; let mut environment_seen = false;
        let mut source_digest = None; let mut helper_digest = None;
        let mut job_home = None; let mut job_xdg = None;
        for line in text.lines() {
            if in_environment {
                if line == "\t}" { in_environment = false; continue; }
                let entry = line.strip_prefix("\t\t").ok_or("неверное окружение launchd")?;
                let (key, value) = entry.split_once(" => ").ok_or("неверное окружение launchd")?;
                let slot = match key { SOURCE_DIGEST => Some(&mut source_digest), HELPER_DIGEST => Some(&mut helper_digest),
                    "HOME" => Some(&mut job_home),
                    "XDG_DATA_HOME" => Some(&mut job_xdg), _ => None };
                if let Some(slot) = slot {
                    if slot.replace(value).is_some() { return Err("повторный отпечаток launchd".into()); }
                }
                continue;
            }
            if in_arguments {
                if line == "\t}" { in_arguments = false; continue; }
                let value = line.strip_prefix("\t\t").ok_or("неверные аргументы launchd")?;
                arguments.as_mut().ok_or("нет аргументов launchd")?.push(value);
                continue;
            }
            let Some(top) = line.strip_prefix('\t') else { continue; };
            if top.starts_with('\t') { continue; }
            let Some((key, value)) = top.split_once(" = ") else { continue; };
            let slot = match key {
                "path" => Some(&mut path), "program" => Some(&mut program), "domain" => Some(&mut domain),
                "state" => Some(&mut state), "pid" => Some(&mut pid),
                "arguments" if value == "{" => {
                    if arguments.is_some() { return Err("повторные аргументы launchd".into()); }
                    arguments = Some(Vec::new()); in_arguments = true; None
                },
                "arguments" => return Err("неверные аргументы launchd".into()),
                "environment" if value == "{" => {
                    if environment_seen { return Err("повторное окружение launchd".into()); }
                    environment_seen = true; in_environment = true; None
                },
                "environment" => return Err("неверное окружение launchd".into()),
                _ => None,
            };
            if let Some(slot) = slot {
                if value.is_empty() || slot.replace(value).is_some() { return Err("повторное поле launchd".into()); }
            }
        }
        let domain = domain.ok_or("нет домена launchd")?;
        let prefix = format!("gui/{uid} [");
        let valid_domain = domain.strip_prefix(&prefix).and_then(|rest| rest.strip_suffix(']'))
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()));
        let arguments = arguments.ok_or("нет аргументов launchd")?;
        if in_arguments || in_environment || !environment_seen || !valid_domain || path.map(Path::new) != Some(plist) || program.map(Path::new) != Some(helper)
            || arguments.len() != 2 || Path::new(arguments[0]) != helper || arguments[1] != role.flag() {
            return Err("служба launchd не совпадает с ожидаемой".into());
        }
        let state = state.ok_or("нет состояния launchd")?.to_owned();
        let pid = pid.map(|value| value.parse::<u32>().ok().filter(|pid| *pid != 0).ok_or("неверный PID launchd"))
            .transpose()?;
        if state == "running" && pid.is_none() { return Err("нет PID работающей службы".into()); }
        let generation = Some(definition_generation(role, source_digest, helper_digest, job_home, job_xdg, profile)?);
        Ok(OwnedJob { pid, state, generation })
    }

    fn parse_disabled_override(role: Role, text: &str) -> Result<bool, String> {
        let mut lines = text.lines().filter(|line| !line.is_empty());
        if lines.next() != Some("\tdisabled services = {") { return Err("неверный ответ launchd об отключённых службах".into()); }
        let target = format!("\t\t\"{}\" => ", role.label());
        let mut disabled = false;
        let mut closed = false;
        for line in lines {
            if closed { return Err("данные после списка отключённых служб".into()); }
            if line == "\t}" { closed = true; continue; }
            if !line.starts_with("\t\t\"") || !line.contains("\" => ") { return Err("неверная запись отключённой службы".into()); }
            if let Some(value) = line.strip_prefix(&target) {
                if disabled || value != "disabled" { return Err("неверное или повторное состояние службы".into()); }
                disabled = true;
            }
        }
        if !closed { return Err("неполный список отключённых служб".into()); }
        Ok(disabled)
    }

    fn disabled_override(role: Role, uid: u32) -> Result<bool, String> {
        let output = Command::new("/bin/launchctl").args(["print-disabled", &format!("gui/{uid}")]).output()
            .map_err(|error| format!("проверка отключения службы: {error}"))?;
        if !output.status.success() || !output.stderr.is_empty() { return Err(format!("состояние отключения не получено: {}", output.status)); }
        parse_disabled_override(role, std::str::from_utf8(&output.stdout).map_err(|_| "неверный ответ об отключении службы")?)
    }

    fn received_job(role: Role, uid: u32, plist: &Path, helper: &Path, profile: &Profile) -> Result<Option<OwnedJob>, String> {
        let target = format!("gui/{uid}/{}", role.label());
        let output = Command::new("/bin/launchctl").args(["print", &target]).output()
            .map_err(|error| format!("проверка launchd: {error}"))?;
        if output.status.success() {
            if !output.stderr.is_empty() { return Err("проверка launchd вернула предупреждение".into()); }
            return parse_owned_job(role, std::str::from_utf8(&output.stdout).map_err(|_| "неверный ответ launchd")?, uid, plist, helper, profile).map(Some);
        }
        let absent = format!("Bad request.\nCould not find service \"{}\" in domain for user gui: {uid}\n", role.label());
        if output.status.code() == Some(113) && output.stdout.is_empty() && output.stderr == absent.as_bytes() { return Ok(None); }
        Err(format!("состояние launchd не получено: {}", output.status))
    }

    fn checked_file(path: &Path, uid: u32) -> Result<fs::File, String> {
        let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path).map_err(|error| format!("проверка файла службы: {error}"))?;
        recheck_file(path, &file, uid)?;
        Ok(file)
    }

    fn recheck_file(path: &Path, file: &fs::File, uid: u32) -> Result<(), String> {
        let held = file.metadata().map_err(|error| error.to_string())?;
        let entry = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !held.is_file() || !entry.is_file() || held.uid() != uid || held.nlink() != 1 || held.mode() & 0o022 != 0
            || held.dev() != entry.dev() || held.ino() != entry.ino() || held.uid() != entry.uid()
            || held.mode() != entry.mode() || entry.nlink() != 1 {
            return Err("файл службы изменён или не принадлежит текущему пользователю".into());
        }
        Ok(())
    }

    fn generation(pid: u32, uid: u32) -> Result<Option<(u64, u64)>, String> {
        let pid = i32::try_from(pid).map_err(|_| "неверный PID службы")?;
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_bsdinfo>();
        unsafe { *libc::__error() = 0; }
        let read = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size as libc::c_int) };
        if read != size as libc::c_int {
            if read == 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) { return Ok(None); }
            return Err("идентификатор процесса службы не получен".into());
        }
        let info = unsafe { info.assume_init() };
        if info.pbi_pid != pid as u32 || info.pbi_uid != uid || info.pbi_start_tvsec == 0 {
            return Err("процесс службы не совпадает с текущим пользователем".into());
        }
        Ok(Some((info.pbi_start_tvsec, info.pbi_start_tvusec)))
    }

    fn check_process_image(pid: u32, helper: &Path) -> Result<(), String> {
        let mut bytes = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let read = unsafe { libc::proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
        if read <= 0 { return Err("путь процесса службы не получен".into()); }
        let raw = std::ffi::CStr::from_bytes_until_nul(&bytes).map_err(|_| "неверный путь процесса службы")?;
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(raw.to_bytes()));
        if fs::canonicalize(path).map_err(|error| error.to_string())? != fs::canonicalize(helper).map_err(|error| error.to_string())? {
            return Err("процесс службы запущен из другого файла".into());
        }
        Ok(())
    }

    pub fn disable() -> Result<(), String> { disable_role(Role::Proxy) }

    fn disable_role(role: Role) -> Result<(), String> {
        let profile = Profile::capture()?;
        let uid = unsafe { libc::geteuid() };
        let plist = profile.plist(role);
        let helper = profile.install_dir().join(role.helper());
        let Some(job) = received_job(role, uid, &plist, &helper, &profile)? else {
            if fs::symlink_metadata(&plist).is_ok() || fs::symlink_metadata(&helper).is_ok() {
                return Err("служба отсутствует, но её файлы требуют проверки владельца".into());
            }
            for path in [&plist, &helper] {
                if let Err(error) = fs::symlink_metadata(path) {
                    if error.kind() != std::io::ErrorKind::NotFound { return Err(format!("проверка файла службы: {error}")); }
                } else { return Err("файл службы появился во время проверки".into()); }
            }
            return Ok(());
        };
        let plist_file = checked_file(&plist, uid)?;
        let helper_file = checked_file(&helper, uid)?;
        stop_owned_job(role, uid, &plist, &helper, &job, &plist_file, &helper_file, &profile)?;
        recheck_file(&plist, &plist_file, uid)?;
        recheck_file(&helper, &helper_file, uid)?;
        fs::remove_file(&plist).map_err(|error| format!("служба остановлена, plist сохранён: {error}"))?;
        recheck_file(&helper, &helper_file, uid).map_err(|error| format!("plist удалён, файл службы сохранён: {error}"))?;
        fs::remove_file(&helper).map_err(|error| format!("plist удалён, файл службы сохранён: {error}"))?;
        Ok(())
    }

    fn stop_owned_job(role: Role, uid: u32, plist: &Path, helper: &Path, job: &OwnedJob,
        plist_file: &fs::File, helper_file: &fs::File, profile: &Profile) -> Result<(), String> {
        let plist_output = Command::new("/usr/bin/plutil").args(["-convert", "json", "-o", "-", "--"]).arg(&plist).output()
            .map_err(|error| format!("проверка plist: {error}"))?;
        recheck_file(&plist, &plist_file, uid)?;
        recheck_file(&helper, &helper_file, uid)?;
        if !plist_output.status.success() || !plist_output.stderr.is_empty() { return Err("plist службы не прочитан".into()); }
        let value: serde_json::Value = serde_json::from_slice(&plist_output.stdout).map_err(|error| format!("неверный plist службы: {error}"))?;
        let pair = plist_generation(role, &value, helper, &profile.log(role), profile)?;
        let helper_digest = file_digest(helper_file)?;
        if pair.as_ref() != job.generation.as_ref()
            || pair.as_ref().is_some_and(|pair| !pair.helper_matches(&helper_digest)) {
            return Err("поколение отключаемой службы не совпадает".into());
        }
        let original = match job.pid { Some(pid) => {
            let first = generation(pid, uid)?.ok_or("процесс службы уже завершился")?;
            check_process_image(pid, &helper)?;
            if generation(pid, uid)? != Some(first) { return Err("процесс службы изменился при проверке".into()); }
            Some((pid, first))
        }, None => None };
        if received_job(role, uid, &plist, &helper, &profile)?.as_ref() != Some(job) { return Err("служба изменилась до остановки".into()); }
        recheck_file(&plist, &plist_file, uid)?;
        recheck_file(&helper, &helper_file, uid)?;
        let target = format!("gui/{uid}/{}", role.label());
        let status = Command::new("/bin/launchctl").args(["bootout", &target]).status()
            .map_err(|error| format!("остановка службы не запущена: {error}"))?;
        if !status.success() { return Err(format!("остановка службы не завершена: {status}")); }
        let deadline = std::time::Instant::now() + crate::dns_forwarder::PROXY_START_BUDGET;
        loop {
            let absent = received_job(role, uid, &plist, &helper, &profile)?.is_none();
            let exited = match original {
                Some((pid, initial)) => generation(pid, uid)?.is_none_or(|now| now != initial),
                None => true,
            };
            if absent && exited { break; }
            if std::time::Instant::now() >= deadline { return Err("остановка службы не подтверждена; файлы сохранены".into()); }
            std::thread::sleep(crate::proxy::POLL_FOR_LISTENER);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fixture_profile() -> Profile {
            Profile::from_values(Some("/Users/example".into()), None).unwrap()
        }

        #[test]
        fn mac_version_currentness_distinguishes_missing_old_equal_new_and_error() {
            let current = crate::dns_forwarder::RELAY_VERSION;
            assert!(current >= 2);
            for version in [0, current - 2, current - 1] {
                assert_eq!(outdated_version(Ok(version)), Ok(true));
            }
            assert_eq!(outdated_version(Ok(current)), Ok(false));
            assert_eq!(outdated_version(Ok(current + 1)), Ok(false));
            assert_eq!(outdated_version(Err("read or parse failed".into())), Err("read or parse failed".into()));
        }

        #[test]
        fn newer_runtime_needs_owned_source_and_readiness_proof() {
            assert!(receive_newer_reuse(Ok(true)).is_ok());
            assert!(receive_newer_reuse(Ok(false)).unwrap_err().contains("сохранена"));
            let error = receive_newer_reuse(Err("ownership mismatch".into())).unwrap_err();
            assert!(error.contains("сохранена") && error.contains("ownership mismatch"));
        }

        #[test]
        fn persisted_proxy_admission_requires_a_complete_pair_and_preserves_watchdog_policy() {
            assert!(check_generation_presence(Role::Proxy, true, true, false).is_ok());
            assert!(check_generation_presence(Role::Proxy, false, false, false).is_ok());
            assert!(check_generation_presence(Role::Proxy, true, true, true).is_ok());
            assert!(check_generation_presence(Role::Proxy, true, false, false).is_err());
            assert!(check_generation_presence(Role::Proxy, false, true, false).is_err());
            assert!(check_generation_presence(Role::Proxy, false, false, true).is_err());
            assert!(check_generation_presence(Role::Watchdog, true, true, false).is_err());
            assert!(check_generation_presence(Role::Watchdog, true, true, true).is_ok());
        }

        #[test]
        fn replacement_stop_requires_bootstrap_and_both_published_file_identities() {
            let pair = Generation::selected(&fixture_profile(), "a".repeat(64), "b".repeat(64));
            let job = OwnedJob { pid: Some(123), state: "running".into(), generation: Some(pair.clone()) };
            let published = StagePosition::Published;
            assert!(replacement_is_owned(true, Some(&pair), &job, published, published));
            assert!(!replacement_is_owned(false, Some(&pair), &job, published, published));
            assert!(!replacement_is_owned(true, Some(&pair), &job, StagePosition::Before, published));
            assert!(!replacement_is_owned(true, Some(&pair), &job, published, StagePosition::Conflict));
            assert!(!replacement_is_owned(true, None, &job, published, published));
            let foreign = Generation::selected(&fixture_profile(), "c".repeat(64), "b".repeat(64));
            assert!(!replacement_is_owned(true, Some(&foreign), &job, published, published));
        }

        #[test]
        fn selected_profile_resolves_default_and_rejects_invalid_inputs() {
            use std::os::unix::ffi::OsStringExt;
            let default = fixture_profile();
            assert_eq!(default.xdg, "/Users/example/.local/share");
            let explicit = Profile::from_values(Some("/Users/example".into()), Some("/private/custom data".into())).unwrap();
            assert_eq!(explicit.xdg, "/private/custom data");
            for home in [None, Some("".into()), Some("relative".into()), Some(std::ffi::OsString::from_vec(vec![b'/', 255]))] {
                assert!(Profile::from_values(home, None).is_err());
            }
            for xdg in ["".into(), "relative".into(), std::ffi::OsString::from_vec(vec![b'/', 255])] {
                assert!(Profile::from_values(Some(default.home.clone().into()), Some(xdg)).is_err());
            }
        }

        #[test]
        fn both_roles_serialize_explicit_effective_profile_and_reject_foreign_fields() {
            for profile in [fixture_profile(), Profile::from_values(Some("/Users/example".into()), Some("/private/custom & data".into())).unwrap()] {
                for role in [Role::Proxy, Role::Watchdog] {
                    let helper = profile.install_dir().join(role.helper());
                    let log = profile.log(role);
                    let mut value = plist_value(role, &helper, &log, &"a".repeat(64), &"b".repeat(64), &profile).unwrap();
                    assert_eq!(value["EnvironmentVariables"]["HOME"], profile.home);
                    assert_eq!(value["EnvironmentVariables"]["XDG_DATA_HOME"], profile.xdg);
                    assert_eq!(plist_generation(role, &value, &helper, &log, &profile).unwrap(),
                        Some(Generation::selected(&profile, "a".repeat(64), "b".repeat(64))));
                    value["EnvironmentVariables"]["FOREIGN"] = "unexpected".into();
                    assert!(plist_generation(role, &value, &helper, &log, &profile).is_err());
                    value["EnvironmentVariables"].as_object_mut().unwrap().remove("FOREIGN");
                    value["EnvironmentVariables"]["HOME"] = 42.into();
                    assert!(plist_generation(role, &value, &helper, &log, &profile).is_err());
                }
            }
        }

        #[test]
        fn proxy_generation_compares_effective_xdg_profiles() {
            let home = fixture_profile().home;
            let default = Profile::from_values(Some(home.clone().into()), None).unwrap();
            let explicit = Profile::from_values(Some(home.clone().into()), Some(default.xdg.clone().into())).unwrap();
            let other = Profile::from_values(Some(home.clone().into()), Some(Path::new(&home).join("other-data").into_os_string())).unwrap();
            let digest = "a".repeat(64);
            let generation = |profile| definition_generation(Role::Proxy, Some(&digest), Some(&digest),
                Some(&home), Some(&default.xdg), profile);
            assert_eq!(generation(&default).unwrap(), generation(&explicit).unwrap());
            assert!(generation(&other).is_err());
        }

        #[test]
        fn legacy_proxy_needs_migration_and_partial_profiles_never_gain_ownership() {
            let profile = fixture_profile();
            let helper = profile.install_dir().join(Role::Proxy.helper());
            let log = profile.log(Role::Proxy);
            let source = "a".repeat(64); let binary = "b".repeat(64);
            let mut value = plist_value(Role::Proxy, &helper, &log, &source, &binary, &profile).unwrap();
            value["EnvironmentVariables"].as_object_mut().unwrap().remove("XDG_DATA_HOME");
            assert!(plist_generation(Role::Proxy, &value, &helper, &log, &profile).is_err());
            value["EnvironmentVariables"].as_object_mut().unwrap().remove("HOME");
            let legacy = plist_generation(Role::Proxy, &value, &helper, &log, &profile).unwrap().unwrap();
            assert_eq!(legacy.profile, JobProfile::LegacyProxyUnbound);
            assert!(!generation_is_current(Some(&legacy), Some(&legacy), true, &source, &binary, &profile).unwrap());
            value["EnvironmentVariables"]["XDG_DATA_HOME"] = profile.xdg.clone().into();
            assert!(plist_generation(Role::Proxy, &value, &helper, &log, &profile).is_err());
            value["EnvironmentVariables"] = serde_json::json!({"HOME": profile.home, "XDG_DATA_HOME": profile.xdg});
            assert!(plist_generation(Role::Proxy, &value, &helper, &log, &profile).is_err());
        }

        #[test]
        fn old_watchdog_witness_preserves_omitted_xdg_and_requires_matching_effective_root() {
            let profile = fixture_profile();
            let helper = profile.install_dir().join(Role::Watchdog.helper());
            let log = profile.log(Role::Watchdog);
            let mut value = plist_value(Role::Watchdog, &helper, &log, &"a".repeat(64), &"b".repeat(64), &profile).unwrap();
            value["EnvironmentVariables"].as_object_mut().unwrap().remove("XDG_DATA_HOME");
            let old = plist_generation(Role::Watchdog, &value, &helper, &log, &profile).unwrap().unwrap();
            assert_eq!(old.profile, JobProfile::Bound { home: profile.home.clone(), xdg: None });
            let selected = Generation::selected(&profile, "a".repeat(64), "b".repeat(64));
            assert_ne!(old, selected, "raw old definition remains distinct for rollback");
            assert!(!generation_is_current(Some(&old), Some(&old), true, &"c".repeat(64), &"b".repeat(64), &profile).unwrap());
            assert!(generation_is_current(Some(&old), Some(&selected), true, &"a".repeat(64), &"b".repeat(64), &profile).is_err());
            let custom = Profile::from_values(Some(profile.home.into()), Some("/private/other-data".into())).unwrap();
            assert!(plist_generation(Role::Watchdog, &value, &helper, &log, &custom).is_err());
        }

        #[test]
        fn retained_witness_checks_old_definition_and_files_without_current_source_identity() {
            let file = fs::File::open(std::env::current_exe().unwrap()).unwrap();
            for pair in [
                Generation { digests: None, profile: JobProfile::LegacyProxyUnbound },
                Generation { digests: Some(("a".repeat(64), "b".repeat(64))), profile: JobProfile::LegacyProxyUnbound },
                Generation { digests: Some(("a".repeat(64), "b".repeat(64))), profile: JobProfile::Bound { home: fixture_profile().home, xdg: None } },
            ] {
                let prior = PriorWitness { plist: &file, helper: &file, plist_digest: "old-plist", helper_digest: "old-helper", pair: Some(&pair) };
                assert!(prior.matches(Some(&pair), "old-plist", "old-helper"));
                assert!(!prior.matches(Some(&pair), "new-plist", "old-helper"));
                assert!(!prior.matches(Some(&pair), "old-plist", "new-helper"));
                assert!(!prior.matches(None, "old-plist", "old-helper"));
                let new = Generation::selected(&fixture_profile(), "c".repeat(64), "b".repeat(64));
                assert!(!prior.matches(Some(&new), "old-plist", "old-helper"));
            }
        }

        #[test]
        fn loaded_profile_identity_rejects_duplicates_partial_and_plist_mismatch() {
            let profile = fixture_profile();
            for role in [Role::Proxy, Role::Watchdog] {
                let plist = profile.plist(role);
                let helper = profile.install_dir().join(role.helper());
                let source = "a".repeat(64); let binary = "b".repeat(64);
                let entries = format!("\t\t{SOURCE_DIGEST} => {source}\n\t\t{HELPER_DIGEST} => {binary}\n\t\tHOME => {}\n\t\tXDG_DATA_HOME => {}\n", profile.home, profile.xdg);
                let text = format!("service = {{\n\tpath = {}\n\tprogram = {}\n\tdomain = gui/501 [100001]\n\tstate = running\n\tpid = 123\n\targuments = {{\n\t\t{}\n\t\t{}\n\t}}\n\tenvironment = {{\n{entries}\t\tXPC_SERVICE_NAME => fixture\n\t}}\n}}\n",
                    plist.display(), helper.display(), helper.display(), role.flag());
                let job = parse_owned_job(role, &text, 501, &plist, &helper, &profile).unwrap();
                let value = plist_value(role, &helper, &profile.log(role), &source, &binary, &profile).unwrap();
                assert_eq!(job.generation, plist_generation(role, &value, &helper, &profile.log(role), &profile).unwrap());
                for entry in entries.lines() {
                    let duplicate = text.replace(&format!("{entry}\n"), &format!("{entry}\n{entry}\n"));
                    assert!(parse_owned_job(role, &duplicate, 501, &plist, &helper, &profile).is_err());
                }
                let missing_home = text.replace(&format!("\t\tHOME => {}\n", profile.home), "");
                assert!(parse_owned_job(role, &missing_home, 501, &plist, &helper, &profile).is_err());
                let wrong_xdg = text.replace(&format!("\t\tXDG_DATA_HOME => {}\n", profile.xdg), "\t\tXDG_DATA_HOME => /wrong-data\n");
                assert!(parse_owned_job(role, &wrong_xdg, 501, &plist, &helper, &profile).is_err());
                let omitted = text.replace(&format!("\t\tXDG_DATA_HOME => {}\n", profile.xdg), "");
                if role == Role::Watchdog {
                    let old = parse_owned_job(role, &omitted, 501, &plist, &helper, &profile).unwrap();
                    assert_ne!(old.generation, job.generation);
                    assert!(generation_is_current(job.generation.as_ref(), old.generation.as_ref(), true, &source, &binary, &profile).is_err());
                } else {
                    assert!(parse_owned_job(role, &omitted, 501, &plist, &helper, &profile).is_err());
                }
            }
        }

        #[test]
        fn listener_witness_requires_exact_process_descriptor_and_address() {
            let warning = b"lsof: WARNING: can't stat() synthetic file system /test-fixtures\n      Output information may be incomplete.\n      assuming \"dev=123\" from mount table\n";
            assert_eq!(listener_output(Some(0), b"p42\nf3\nn127.0.0.1:1234\n", warning, 42, 1234).unwrap(), true);
            assert_eq!(listener_output(Some(1), b"", warning, 42, 1234).unwrap(), false);
            assert!(listener_output(Some(0), b"p43\nf3\nn127.0.0.1:1234\n", b"", 42, 1234).is_err());
            assert!(listener_output(Some(0), b"p42\nf3\nn*:1234\n", b"", 42, 1234).is_err());
            assert!(listener_output(Some(0), b"p42\nf3\nn127.0.0.1:1234", b"", 42, 1234).is_err());
            assert!(listener_output(Some(1), b"", b"permission denied\n", 42, 1234).is_err());
        }

        #[test]
        fn watchdog_witness_requires_two_distinct_writable_nonstandard_descriptors() {
            let sample = b"p42\nfcwd\na \nD0x10\ni11\nf2\naw\nD0x10\ni11\nf3\naw\nD0x10\ni11\nf4\nau\nD0x10\ni11\n";
            let warning = b"lsof: WARNING: can't stat() synthetic file system /test-fixtures\n      Output information may be incomplete.\n      assuming \"dev=123\" from mount table\n";
            assert!(watchdog_log_output(Some(0), sample, warning, 42, 16, 11).unwrap());
            assert!(!watchdog_log_output(Some(0), sample, b"", 42, 16, 12).unwrap());
            assert!(!watchdog_log_output(Some(0), b"p42\nf2\naw\nD0x10\ni11\nf3\naw\nD0x10\ni11\n", b"", 42, 16, 11).unwrap());
            assert!(watchdog_log_output(Some(0), sample, b"permission denied\n", 42, 16, 11).is_err());
            assert!(watchdog_log_output(Some(0), sample, b"", 43, 16, 11).is_err());
            assert!(watchdog_log_output(Some(1), sample, b"", 42, 16, 11).is_err());
        }

        #[test]
        fn staged_publication_requires_the_exact_prior_and_new_entries() {
            let fresh = (7, 11);
            let old = (7, 12);
            assert_eq!(stage_position(Some(fresh), Some(old), fresh, Some(old)), StagePosition::Before);
            assert_eq!(stage_position(Some(old), Some(fresh), fresh, Some(old)), StagePosition::Published);
            assert_eq!(stage_position(Some(fresh), None, fresh, None), StagePosition::Before);
            assert_eq!(stage_position(None, Some(fresh), fresh, None), StagePosition::Published);
            assert_eq!(stage_position(None, None, fresh, None), StagePosition::Conflict);
            assert_eq!(stage_position(Some(fresh), Some((7, 13)), fresh, Some(old)), StagePosition::Conflict);
            assert_eq!(stage_position(Some(old), Some(old), fresh, Some(old)), StagePosition::Conflict);
        }

        #[test]
        #[ignore = "requires a private AG_MAC_PROFILE_TEST_ROOT"]
        fn mac_profile_publisher_preserves_metadata_and_concurrent_preimage() {
            use std::os::unix::fs::DirBuilderExt;

            let parent = PathBuf::from(std::env::var_os("AG_MAC_PROFILE_TEST_ROOT").expect("private fixture parent"));
            let owned_parent = owned_directory(&parent, unsafe { libc::geteuid() }).unwrap();
            let root = parent.join(format!("ag-profile-fixture-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            recheck_directory(&parent, &owned_parent, unsafe { libc::geteuid() }).unwrap();
            let profile = root.join(".zprofile");
            let stage_name = ".zprofile.agunlocker-stage";
            fs::write(&profile, b"original\r\n").unwrap();
            fs::set_permissions(&profile, fs::Permissions::from_mode(0o640)).unwrap();
            let prior = fs::File::open(&profile).unwrap();
            let key = c"com.agunlocker.synthetic-profile";
            let attribute = b"fixture";
            assert_eq!(unsafe { libc::fsetxattr(prior.as_raw_fd(), key.as_ptr(), attribute.as_ptr().cast(), attribute.len(), 0, 0) }, 0);
            let metadata = prior.metadata().unwrap();

            assert!(edit_owned_macos_file(&root, ".zprofile", stage_name, true, |bytes| {
                assert_eq!(bytes, Some(b"original\r\n".as_slice()));
                Ok(Some(b"new\r\n".to_vec()))
            }, || Ok(()), || Ok(())).unwrap());
            let published = fs::File::open(&profile).unwrap();
            assert!(same_profile_metadata(&metadata, &published.metadata().unwrap()));
            let mut copied = [0u8; 7];
            assert_eq!(unsafe { libc::fgetxattr(published.as_raw_fd(), key.as_ptr(), copied.as_mut_ptr().cast(), copied.len(), 0, 0) }, 7);
            assert_eq!(&copied, attribute);
            assert_eq!(profile_snapshot(&prior).unwrap().1, b"original\r\n", "the open old descriptor retains its old inode");

            let error = edit_owned_macos_file(&root, ".zprofile", stage_name, true,
                |_| Ok(Some(b"temporary publication".to_vec())), || Ok(()), || {
                    assert_eq!(fs::read(&profile).unwrap(), b"temporary publication");
                    Err("synthetic later shared guard failure".into())
                }).unwrap_err();
            assert!(error.contains("synthetic later shared guard failure"));
            assert_eq!(fs::read(&profile).unwrap(), b"new\r\n");
            assert!(!root.join(stage_name).exists());

            let error = edit_owned_macos_file(&root, ".zprofile", stage_name, true,
                |_| Ok(Some(b"replacement".to_vec())),
                || fs::write(&profile, b"concurrent edit").map_err(|error| error.to_string()),
                || Ok(())).unwrap_err();
            assert!(error.contains("исходный профиль изменился"));
            assert_eq!(fs::read(&profile).unwrap(), b"concurrent edit");
            assert!(!root.join(stage_name).exists());

            let mut displaced_editor = fs::OpenOptions::new().read(true).write(true).open(&profile).unwrap();
            let error = edit_owned_macos_file(&root, ".zprofile", stage_name, true,
                |_| Ok(Some(b"published profile".to_vec())), || Ok(()), || {
                    displaced_editor.set_len(0).unwrap();
                    displaced_editor.write_all(b"external edit through retained descriptor").unwrap();
                    displaced_editor.sync_all().unwrap();
                    Err("synthetic later shared guard failure".into())
                }).unwrap_err();
            assert!(error.contains("synthetic later shared guard failure"));
            assert!(error.contains("вытесненный исходный профиль изменился"));
            assert_eq!(fs::read(&profile).unwrap(), b"published profile");
            assert_eq!(fs::read(root.join(stage_name)).unwrap(), b"external edit through retained descriptor");
            fs::remove_file(root.join(stage_name)).unwrap();
            fs::remove_file(profile).unwrap();
            fs::remove_dir(root).unwrap();
        }

        #[test]
        fn plist_generation_rejects_partial_or_foreign_metadata() {
            let helper = Path::new("/test-fixtures/ag_proxy");
            let log = Path::new("/test-fixtures/proxy.log");
            let source = "a".repeat(64);
            let binary = "b".repeat(64);
            let mut value = plist_value(Role::Proxy, helper, log, &source, &binary, &fixture_profile()).unwrap();
            assert_eq!(plist_generation(Role::Proxy, &value, helper, log, &fixture_profile()).unwrap(), Some(Generation::selected(&fixture_profile(), source, binary)));
            value["EnvironmentVariables"].as_object_mut().unwrap().remove(SOURCE_DIGEST);
            assert!(plist_generation(Role::Proxy, &value, helper, log, &fixture_profile()).is_err());
            value.as_object_mut().unwrap().remove("EnvironmentVariables");
            assert_eq!(plist_generation(Role::Proxy, &value, helper, log, &fixture_profile()).unwrap(),
                Some(Generation { digests: None, profile: JobProfile::LegacyProxyUnbound }));
            value["ProgramArguments"] = serde_json::json!(["/test-fixtures/foreign", PROXY_FLAG]);
            assert!(plist_generation(Role::Proxy, &value, helper, log, &fixture_profile()).is_err());
        }

        #[test]
        fn watchdog_plist_binds_role_and_actual_state_root() {
            let helper = Path::new("/test-fixtures/ag_watchdog");
            let log = Path::new("/test-fixtures/watchdog.log");
            let mut value = plist_value(Role::Watchdog, helper, log, &"a".repeat(64), &"b".repeat(64), &fixture_profile()).unwrap();
            assert!(value.get("StandardOutPath").is_none());
            assert!(value.get("StandardErrorPath").is_none());
            assert!(plist_generation(Role::Watchdog, &value, helper, log, &fixture_profile()).unwrap().is_some());
            value["StandardErrorPath"] = "/test-fixtures/foreign".into();
            assert!(plist_generation(Role::Watchdog, &value, helper, log, &fixture_profile()).is_err());
            value.as_object_mut().unwrap().remove("StandardErrorPath");
            value["ProgramArguments"][1] = PROXY_FLAG.into();
            assert!(plist_generation(Role::Watchdog, &value, helper, log, &fixture_profile()).is_err());
            value["ProgramArguments"][1] = WATCHDOG_FLAG.into();
            value["EnvironmentVariables"]["HOME"] = "/wrong-store".into();
            assert!(plist_generation(Role::Watchdog, &value, helper, log, &fixture_profile()).is_err());
        }

        #[test]
        fn watchdog_log_rejects_links_and_keeps_the_open_inode() {
            use std::os::unix::fs::symlink;
            let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
            let dir = temp.join(format!("ag-mac-log-{}", std::process::id()));
            fs::create_dir(&dir).unwrap();
            let log = dir.join("watchdog.log");
            let sentinel = dir.join("sentinel");
            fs::write(&sentinel, b"sentinel").unwrap();
            symlink(&sentinel, &log).unwrap();
            assert!(open_watchdog_log_at(&dir).is_err());
            fs::remove_file(&log).unwrap();
            fs::hard_link(&sentinel, &log).unwrap();
            assert!(open_watchdog_log_at(&dir).is_err());
            fs::remove_file(&log).unwrap();
            let mut file = open_watchdog_log_at(&dir).unwrap();
            let moved = dir.join("admitted.log");
            fs::rename(&log, &moved).unwrap();
            symlink(&sentinel, &log).unwrap();
            file.write_all(b"worker").unwrap();
            assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
            assert_eq!(fs::read(&moved).unwrap(), b"worker");
            drop(file);
            fs::remove_file(&log).unwrap(); fs::remove_file(&moved).unwrap();
            fs::remove_file(&sentinel).unwrap(); fs::remove_dir(&dir).unwrap();
        }

        #[test]
        fn watchdog_log_uses_selected_state_root() {
            const CHILD: &str = "AG_WATCHDOG_LOG_TEST_EXPECTED";
            if let Some(expected) = std::env::var_os(CHILD) {
                let expected = PathBuf::from(expected);
                assert_eq!(Profile::capture().unwrap().log(Role::Watchdog), expected);
                assert!(open_watchdog_log().unwrap_err().contains("открытие журнала автопатча"), "selected sentinel link must be rejected at open");
                assert_eq!(fs::read(expected.parent().unwrap().join("sentinel")).unwrap(), b"sentinel");
                return;
            }
            use std::os::unix::fs::symlink;
            let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
            let root = temp.join(format!("ag-mac-log-root-{}", std::process::id()));
            fs::create_dir(&root).unwrap();
            let home = root.join("home");
            let data = root.join("custom space & data");
            let default = home.join(".local").join("share").join("agunlocker");
            let custom = data.join("agunlocker");
            for dir in [&default, &custom] {
                fs::create_dir_all(dir).unwrap();
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
                let sentinel = dir.join("sentinel");
                fs::write(&sentinel, b"sentinel").unwrap();
                symlink(&sentinel, dir.join("watchdog.log")).unwrap();
                let mut child = Command::new(std::env::current_exe().unwrap());
                child.args(["--exact", "background::macos_impl::tests::watchdog_log_uses_selected_state_root", "--nocapture"])
                    .env("HOME", &home).env(CHILD, dir.join("watchdog.log"));
                if dir == &default { child.env_remove("XDG_DATA_HOME"); }
                else { child.env("XDG_DATA_HOME", &data); }
                let result = child.output().unwrap();
                assert!(result.status.success(), "child failed: {}", String::from_utf8_lossy(&result.stderr));
                assert!(String::from_utf8_lossy(&result.stdout).contains("running 1 test"), "child did not execute the fixture");
                assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
                fs::remove_file(dir.join("watchdog.log")).unwrap();
                fs::remove_file(sentinel).unwrap();
                fs::remove_dir(dir).unwrap();
            }
            fs::remove_dir(home.join(".local").join("share")).unwrap();
            fs::remove_dir(home.join(".local")).unwrap();
            fs::remove_dir(home).unwrap(); fs::remove_dir(data).unwrap(); fs::remove_dir(root).unwrap();
        }

        #[test]
        fn generation_currentness_binds_source_helper_and_loaded_definition() {
            let source = "a".repeat(64);
            let helper = "b".repeat(64);
            let pair = Generation::selected(&fixture_profile(), source.clone(), helper.clone());
            assert!(generation_is_current(Some(&pair), Some(&pair), true, &source, &helper, &fixture_profile()).unwrap());
            assert!(generation_is_current(Some(&pair), None, false, &source, &helper, &fixture_profile()).unwrap());
            assert!(!generation_is_current(Some(&pair), Some(&pair), true, &"c".repeat(64), &helper, &fixture_profile()).unwrap());
            assert!(!generation_is_current(Some(&pair), Some(&pair), true, &source, &"d".repeat(64), &fixture_profile()).unwrap());
            assert!(!generation_is_current(None, None, true, &source, &helper, &fixture_profile()).unwrap());
            assert!(generation_is_current(Some(&pair), None, true, &source, &helper, &fixture_profile()).is_err());
            assert!(generation_is_current(None, Some(&pair), true, &source, &helper, &fixture_profile()).is_err());
        }

        #[test]
        fn disabled_override_requires_complete_framing_and_exact_label() {
            assert!(parse_disabled_override(Role::Proxy, "").is_err());
            assert!(parse_disabled_override(Role::Proxy, "\n\tdisabled services = {\n").is_err());
            assert!(!parse_disabled_override(Role::Proxy, "\n\tdisabled services = {\n\t\t\"other\" => disabled\n\t}\n").unwrap());
            let selected = format!("\n\tdisabled services = {{\n\t\t\"{LABEL}\" => disabled\n\t}}\n");
            assert!(parse_disabled_override(Role::Proxy, &selected).unwrap());
            assert!(parse_disabled_override(Role::Proxy, &selected.replace("disabled\n", "unknown\n")).is_err());
        }

        #[test]
        fn stop_accepts_only_the_exact_owned_launchd_definition() {
            let plist = Path::new("/Users/example/Library/LaunchAgents/owned.plist");
            let helper = Path::new("/Users/example/Library/Application Support/AGUnlocker/ag_proxy");
            let text = "service = {\n\tpath = /Users/example/Library/LaunchAgents/owned.plist\n\tprogram = /Users/example/Library/Application Support/AGUnlocker/ag_proxy\n\tdomain = gui/501 [100001]\n\tstate = running\n\tpid = 123\n\targuments = {\n\t\t/Users/example/Library/Application Support/AGUnlocker/ag_proxy\n\t\t--proxy\n\t}\n\tenvironment = {\n\t\tXPC_SERVICE_NAME => fixture\n\t}\n}\n";
            assert_eq!(parse_owned_job(Role::Proxy, text, 501, plist, helper, &fixture_profile()).unwrap().pid, Some(123));
            assert!(parse_owned_job(Role::Proxy, text, 502, plist, helper, &fixture_profile()).is_err());
            assert!(parse_owned_job(Role::Proxy, &text.replace("--proxy", "--watchdog"), 501, plist, helper, &fixture_profile()).is_err());
            assert!(parse_owned_job(Role::Proxy, &text.replace("\tpid = 123\n", "\tpid = 123\n\tpid = 456\n"), 501, plist, helper, &fixture_profile()).is_err());
            assert!(parse_owned_job(Role::Proxy, &text.replace("\tpid = 123\n", ""), 501, plist, helper, &fixture_profile()).is_err());
            let source = "a".repeat(64); let binary = "b".repeat(64);
            let entries = format!("\t\t{SOURCE_DIGEST} => {source}\n\t\t{HELPER_DIGEST} => {binary}\n");
            let current = text.replace("\t\tXPC_SERVICE_NAME => fixture\n", &entries);
            assert_eq!(parse_owned_job(Role::Proxy, &current, 501, plist, helper, &fixture_profile()).unwrap().generation, Some(Generation { digests: Some((source, binary)), profile: JobProfile::LegacyProxyUnbound }));
            assert!(parse_owned_job(Role::Proxy, &current.replace(&format!("\t\t{HELPER_DIGEST} => {}\n", "b".repeat(64)), ""), 501, plist, helper, &fixture_profile()).is_err());
            assert!(parse_owned_job(Role::Proxy, &current.replace(&entries, &format!("{entries}{entries}")), 501, plist, helper, &fixture_profile()).is_err());
            assert!(parse_owned_job(Role::Proxy, &text.replace("\tenvironment = {\n\t\tXPC_SERVICE_NAME => fixture\n\t}\n", ""), 501, plist, helper, &fixture_profile()).is_err());
        }
    }
}

// Linux: phase 2 is the **proxy route**, not the DNS relay. This runs the local
// CONNECT proxy (`proxy::run`, via `--proxy`) as a systemd **user** unit - no
// root, no `:53` listener, so systemd-resolved is never touched. The DNS relay
// (phase 5) would be a separate, privileged story; this is deliberately the
// unprivileged half that already lifts the region gate through a permitted exit.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
mod unix_impl {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{PROXY_FLAG, WATCHDOG_FLAG};

    const UNIT_NAME: &str = "ag-unlocker-proxy.service";
    const WATCHDOG_UNIT_NAME: &str = "ag-unlocker-watchdog.service";
    const EXECUTABLE_NAME: &str = "ag_proxy";

    /// The proxy's own copy of the exe, under the XDG data dir - a user unit needs
    /// no root, so unlike Windows there is no `%ProgramData%` anti-persistence
    /// dance.
    pub fn install_dir() -> Result<PathBuf, String> {
        crate::dns_forwarder::checked_log_dir()
    }

    pub fn installed_exe() -> Result<PathBuf, String> {
        install_dir().map(|dir| dir.join(EXECUTABLE_NAME))
    }

    fn unit_path(name: &str) -> Result<PathBuf, String> {
        crate::dns_forwarder::unix_config_home().map(|home| home.join("systemd/user").join(name))
    }

    /// Runs `systemctl --user ...`; true on success. Best-effort: a machine
    /// without a user systemd manager (rare on a desktop) just fails the enable.
    fn systemctl(args: &[&str]) -> bool {
        Command::new("systemctl")
            .arg("--user")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// The unit file existing is what "enabled" means here.
    pub fn is_enabled() -> bool {
        unit_path(UNIT_NAME).is_ok_and(|path| path.exists())
    }

    /// The auto-patch watcher is a user unit of its own, beside the proxy's: the
    /// switch must be able to stand without the 400 bypass (it is the whole
    /// reason `ensure_installed` exists), and an update that replaces
    /// `language_server` under a running Antigravity is as real here as on
    /// Windows. The unit file existing is what "enabled" means, as for the proxy.
    pub fn is_watchdog_enabled() -> bool {
        unit_path(WATCHDOG_UNIT_NAME).is_ok_and(|path| path.exists())
    }

    pub fn is_running() -> bool {
        Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", UNIT_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// No versioned relay on Linux, so nothing to call outdated.
    pub fn relay_is_outdated() -> bool {
        false
    }

    /// Installs the exe under the XDG data dir, writes a systemd **user** unit that
    /// runs it with `--proxy`, and starts it. No root: `systemctl --user` targets
    /// the caller's own session manager, which is why the whole Linux flow runs
    /// unprivileged (and "Run as a Program" works without a password prompt).
    pub fn ensure_running() -> Result<(), String> {
        let dir = crate::dns_forwarder::unix_service_path(install_dir()?)?;
        let up = unit_path(UNIT_NAME)?;
        let unit = unit_text("Antigravity Unlocker local proxy", PROXY_FLAG, &dir)?;
        let replaced = install_copy(&dir)?;
        if let Some(p) = up.parent() {
            fs::create_dir_all(p).map_err(|e| format!("не создать {}: {}", p.display(), e))?;
        }
        // The window finds the service's `gate.json` through `log_dir()`, which
        // follows `XDG_DATA_HOME`. The systemd user manager does not always carry
        // the desktop session's value, and a service writing into a different
        // directory than the window reads leaves the card on «Служба запускается»
        // for good - so the unit is given the directory the window uses.
        // A unit from an older build lacks the data-dir line; running on under
        // it keeps the service writing where the window does not look.
        let unit_changed = fs::read_to_string(&up).map_or(true, |old| old != unit);
        fs::write(&up, unit).map_err(|e| format!("не записать юнит: {}", e))?;

        systemctl(&["daemon-reload"]);
        if !systemctl(&["enable", "--now", UNIT_NAME]) {
            return Err("не удалось запустить systemd-юнит (systemctl --user)".to_string());
        }
        // `enable --now` leaves a unit that is already running alone, so a copy
        // just replaced would sit unused until the next login.
        if (replaced || unit_changed) && !systemctl(&["restart", UNIT_NAME]) {
            return Err(
                "новая версия прокси записана, но служба не перезапустилась (systemctl --user)"
                    .to_string(),
            );
        }
        // The watcher runs the same copy: left on the old inode it would keep
        // the previous version's patch routines until the next login.
        if replaced && is_watchdog_enabled() {
            systemctl(&["restart", WATCHDOG_UNIT_NAME]);
        }
        Ok(())
    }

    /// A user unit running the installed copy with `flag`.
    fn unit_text(description: &str, flag: &str, directory: &Path) -> Result<String, String> {
        let data_home = directory
            .parent()
            .ok_or("Каталог данных службы недоступен")?;
        let data_home = unit_path_text(data_home)?;
        let exe = unit_path_text(&directory.join(EXECUTABLE_NAME))?;
        Ok(format!(
            "[Unit]\n\
             Description={description}\n\
             After=default.target\n\n\
             [Service]\n\
             Environment=\"XDG_DATA_HOME={data_home}\"\n\
             ExecStart=\"{exe}\" {flag}\n\
             Restart=on-failure\n\
             RestartSec=5\n\n\
             [Install]\n\
             WantedBy=default.target\n",
        ))
    }

    fn unit_path_text(path: &Path) -> Result<String, String> {
        Ok(path.to_str().ok_or("Путь службы не является Unicode")?
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t"))
    }

    #[cfg(test)]
    #[test]
    fn linux_units_share_the_resolved_state_directory() {
        let directory = Path::new("/fixture/relative launch %/agunlocker");
        for flag in [PROXY_FLAG, WATCHDOG_FLAG] {
            let definition = unit_text("synthetic", flag, directory).unwrap();
            assert!(definition.lines().any(|line| line == "Environment=\"XDG_DATA_HOME=/fixture/relative launch %%\""));
            assert!(definition.lines().any(|line| line == format!("ExecStart=\"/fixture/relative launch %%/agunlocker/ag_proxy\" {flag}")));
        }
    }

    /// Puts this exe where the units run it from. True when the copy on disk
    /// changed (a unit already running it then has to be restarted).
    fn install_copy(dir: &Path) -> Result<bool, String> {
        let src = std::env::current_exe().map_err(|e| format!("нет пути к exe: {}", e))?;
        let exe = dir.join(EXECUTABLE_NAME);
        fs::create_dir_all(dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
        // Copy self so the unit survives the download folder being moved/removed.
        //
        // Never *over* the installed copy: Linux will not open a file a process
        // is executing for writing - ETXTBSY, «Text file busy (os error 26)» -
        // and that is exactly the state every upgrade finds, the previous
        // version's unit being up. A new file beside it renamed over the name is
        // allowed: the running process keeps the old inode, the name now points at
        // the new one, and the restart below starts it. Skipped when the bytes are
        // already the same, so switching the bypass on again does not cut the
        // tunnels a running proxy is carrying.
        let replaced = src != exe && !same_contents(&src, &exe);
        if replaced {
            use std::os::unix::fs::PermissionsExt;
            let fresh = dir.join(".ag_proxy.new");
            fs::copy(&src, &fresh).map_err(|e| format!("копия exe: {}", e))?;
            let _ = fs::set_permissions(&fresh, fs::Permissions::from_mode(0o755));
            fs::rename(&fresh, &exe).map_err(|e| {
                let _ = fs::remove_file(&fresh);
                format!("замена exe: {}", e)
            })?;
        }
        Ok(replaced)
    }

    /// Whether two files hold the same bytes. Unreadable counts as different, so
    /// the copy is attempted and says what went wrong.
    fn same_contents(a: &std::path::Path, b: &std::path::Path) -> bool {
        match (fs::metadata(a), fs::metadata(b)) {
            (Ok(ma), Ok(mb)) if ma.len() == mb.len() => {}
            _ => return false,
        }
        match (fs::read(a), fs::read(b)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        }
    }

    pub fn enable() -> Result<(), String> {
        ensure_running()?;
        let _ = systemctl(&["restart", UNIT_NAME]);
        Ok(())
    }

    /// Writes the watcher's user unit and starts it. Only the file and the unit:
    /// the proxy unit is not touched, so auto-patch on its own never switches the
    /// 400 bypass on.
    pub fn enable_watchdog() -> Result<(), String> {
        let dir = crate::dns_forwarder::unix_service_path(install_dir()?)?;
        let up = unit_path(WATCHDOG_UNIT_NAME)?;
        let unit = unit_text("Antigravity Unlocker auto-patch", WATCHDOG_FLAG, &dir)?;
        let replaced = install_copy(&dir)?;
        if let Some(p) = up.parent() {
            fs::create_dir_all(p).map_err(|e| format!("не создать {}: {}", p.display(), e))?;
        }
        let unit_changed = fs::read_to_string(&up).map_or(true, |old| old != unit);
        fs::write(&up, unit).map_err(|e| format!("не записать юнит: {}", e))?;
        systemctl(&["daemon-reload"]);
        if !systemctl(&["enable", "--now", WATCHDOG_UNIT_NAME]) {
            return Err("не удалось запустить systemd-юнит (systemctl --user)".to_string());
        }
        if (replaced || unit_changed) && !systemctl(&["restart", WATCHDOG_UNIT_NAME]) {
            return Err(
                "автопатч записан, но служба не перезапустилась (systemctl --user)".to_string(),
            );
        }
        Ok(())
    }

    /// The copy the units run from has to be there before either of them starts.
    /// Starting the proxy here would switch the 400 bypass on behind the user's
    /// back, so this is only the file.
    pub fn ensure_installed() -> Result<(), String> {
        install_copy(&install_dir()?).map(|_| ())
    }

    pub fn disable_watchdog() {
        systemctl(&["disable", "--now", WATCHDOG_UNIT_NAME]);
        match unit_path(WATCHDOG_UNIT_NAME) {
            Ok(path) => { let _ = fs::remove_file(path); }
            Err(error) => eprintln!("Путь службы автопатча недоступен: {error}"),
        }
        systemctl(&["daemon-reload"]);
    }

    /// Stops and removes the user unit and the installed copy. Quiet success even
    /// when nothing was installed, so the undo menus never error.
    pub fn disable() -> Result<(), String> {
        let unit = unit_path(UNIT_NAME)?;
        let watchdog = unit_path(WATCHDOG_UNIT_NAME)?;
        systemctl(&["disable", "--now", UNIT_NAME]);
        let _ = fs::remove_file(unit);
        systemctl(&["daemon-reload"]);
        // The watcher runs the same copy: while its unit is there the file stays.
        if !watchdog.exists() {
            let dir = install_dir()?;
            let _ = fs::remove_file(dir.join(EXECUTABLE_NAME));
            let _ = fs::remove_dir(dir);
        }
        Ok(())
    }
}
