//! Actual command results retained by their existing operation/process roots.
use std::sync::{Arc, Mutex, TryLockError};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::utils::CommandOutcome;

pub(crate) enum Receiving { Ready, Pending(Vec<String>) }

/// Native facts safe for the existing operation error channel. Captures stay private.
pub(crate) fn command_details(command: &CommandOutcome) -> String {
    let native = |error: &std::io::Error| format!("{:?}/{:?}", error.kind(), error.raw_os_error());
    let exit = command.exit();
    format!("exit={:?}, signal={:?}, start={:?}, qualification={}, wait={:?}, later_wait={:?}, capture={:?}, later_capture={:?}, stop={:?}, deadline={}, invalid_deadline={}, limit={:?}, capture_eof={}, capture_unavailable={}, stdout_bytes={}, stderr_bytes={}",
        exit.and_then(|status| status.code()), exit.and_then(|status| status.signal()),
        command.start_error().map(&native), command.qualification_error().is_some(),
        command.wait_error().map(&native), command.later_wait_errors().iter().map(&native).collect::<Vec<_>>(),
        command.capture_error().map(&native), command.later_capture_errors().iter().map(&native).collect::<Vec<_>>(),
        command.stop_result().map(|result| result.as_ref().err().map(&native)),
        command.deadline_expired(), command.deadline_unrepresentable(), command.limit(),
        command.capture_eof(), command.capture_unavailable(), command.stdout().len(), command.stderr().len())
}

/// Enrich the same operation's failure before disposing its actual owning value.
/// A late zero exit cannot erase the original timeout/partial-effect result.
pub(crate) fn receive_failure(command: &CommandOutcome, failure: &mut Option<String>) -> Result<(), String> {
    if command.is_empty() { return Ok(()); }
    if failure.is_some() || !command.complete() || !command.exit().is_some_and(|status| status.success()) {
        let original = failure.as_deref().unwrap_or("command outcome failed or incomplete; effect may be partial");
        let details = command_details(command);
        if !original.ends_with(&details) { *failure = Some(format!("{original}; {details}")); }
    }
    Ok(())
}

/// The original value/panic and the one owning command remain outside receiving catches.
pub(crate) struct SavedCommand<T> {
    component: &'static str,
    pub(crate) command: CommandOutcome,
    original: Option<std::thread::Result<Result<T, String>>>,
    pub(crate) failure: Option<String>,
    pub(crate) receiving_error: Option<String>,
    pub(crate) receiving_panics: Vec<Box<dyn std::any::Any + Send>>,
    pub(crate) diagnostic_errors: Vec<std::io::Error>,
    received: bool,
}
impl<T> SavedCommand<T> {
    pub(crate) fn new() -> Self {
        Self { component: "command operation", command: CommandOutcome::default(), original: None, failure: None,
            receiving_error: None, receiving_panics: Vec::new(), diagnostic_errors: Vec::new(), received: false }
    }
    pub(crate) fn run(&mut self, action: impl FnOnce(&mut CommandOutcome) -> Result<T, String>) {
        assert!(self.original.is_none() && !self.received, "an operation cannot be replayed");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&mut self.command)));
        self.failure = match &result {
            Ok(Err(error)) => Some(error.clone()),
            Err(_) => Some("operation unwound; original panic retained".into()),
            Ok(Ok(_)) => None,
        };
        self.original = Some(result);
    }
    pub(crate) fn receive_with(&mut self,
        receiver: &mut impl FnMut(&CommandOutcome, &mut Option<String>) -> Result<(), String>) -> Result<bool, String> {
        if self.received { return Ok(true); }
        if self.original.is_none() { return Err("operation result has not returned".into()); }
        self.command.observe();
        if !self.command.releasable() { return Ok(false); }
        let mut projection = self.failure.clone();
        let receiving = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receiver(&self.command, &mut projection)));
        match receiving {
            Ok(Ok(())) => {
                self.failure = projection;
                self.command = CommandOutcome::default();
                self.received = true;
                Ok(true)
            }
            Ok(Err(error)) => { self.receiving_error.get_or_insert_with(|| error.clone()); Err(error) }
            Err(payload) => {
                self.receiving_panics.push(payload);
                let error = "command result receiver unwound; original value and command retained".to_owned();
                self.receiving_error.get_or_insert_with(|| error.clone());
                Err(error)
            }
        }
    }
    pub(crate) fn receive(&mut self) -> Result<bool, String> { self.receive_with(&mut receive_failure) }
    pub(crate) fn finish(mut self) -> Result<T, String> {
        assert!(self.received, "cannot discard an unreceived command operation");
        match self.original.take().expect("original operation result") {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => match self.failure.take() { Some(error) => Err(error), None => result },
        }
    }
}

/// One concurrent operation's actual command and its current failure/panic.
/// The process root owns this value before its worker can acquire a subprocess.
#[derive(Clone)]
pub(crate) struct PendingCommand(Arc<Mutex<SavedCommand<()>>>);
impl PendingCommand {
    pub(crate) fn with_result<T>(&self, action: impl FnOnce(&mut CommandOutcome) -> Result<T, String>) -> Result<T, String> {
        let mut saved = self.0.lock().unwrap_or_else(|error| error.into_inner());
        assert!(saved.original.is_none() && !saved.received, "a registered command operation cannot be replayed");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&mut saved.command)));
        match result {
            Ok(result) => {
                saved.failure = result.as_ref().err().cloned();
                saved.original = Some(Ok(result.as_ref().map(|_| ()).map_err(Clone::clone)));
                let _ = saved.receive();
                match &saved.failure {
                    Some(error) => Err(error.clone()),
                    None => result,
                }
            }
            Err(payload) => {
                saved.failure = Some("operation unwound; original panic retained by process root".into());
                saved.original = Some(Err(payload));
                let _ = saved.receive();
                Err(saved.failure.clone().unwrap())
            }
        }
    }
    pub(crate) fn with_classified<T>(&self, action: impl FnOnce(&mut CommandOutcome) -> T,
        failure: impl FnOnce(&T) -> Option<String>) -> T {
        let mut saved = self.0.lock().unwrap_or_else(|error| error.into_inner());
        assert!(saved.original.is_none() && !saved.received, "a registered command operation cannot be replayed");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(&mut saved.command)));
        match result {
            Ok(value) => {
                // The completed value stays outside the fallible classifier.
                // Register completion first so an unwind cannot make it look
                // like an unstarted operation or dispose that value.
                saved.original = Some(Ok(Ok(())));
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| failure(&value))) {
                    Ok(projection) => {
                        saved.failure = projection;
                        saved.original = Some(Ok(match &saved.failure { Some(error) => Err(error.clone()), None => Ok(()) }));
                    }
                    Err(payload) => {
                        let error = "operation classifier unwound; completed value retained by its caller".to_owned();
                        saved.failure = Some(error.clone());
                        saved.original = Some(Ok(Err(error.clone())));
                        saved.receiving_error = Some(error);
                        saved.receiving_panics.push(payload);
                    }
                }
                let _ = saved.receive();
                value
            }
            Err(payload) => {
                // The actual parent job receives this original payload; this
                // already-rooted command remains here across its unwind.
                saved.failure = Some("operation unwound; original payload returned to parent job".into());
                saved.original = Some(Ok(Err(saved.failure.clone().unwrap())));
                drop(saved);
                std::panic::resume_unwind(payload)
            }
        }
    }
    pub(crate) fn pending(&self) -> bool {
        match self.0.try_lock() {
            Ok(saved) => !saved.received,
            Err(TryLockError::Poisoned(error)) => !error.into_inner().received,
            Err(TryLockError::WouldBlock) => true,
        }
    }
    pub(crate) fn failure(&self) -> Option<String> {
        self.0.lock().unwrap_or_else(|error| error.into_inner()).failure.clone()
    }
}

/// Only actual concurrent current operations cross worker/process lifetimes here.
#[derive(Default)]
pub(crate) struct CommandLifetime {
    pending: Mutex<Vec<PendingCommand>>,
    closed: AtomicBool,
    completed_failures: Mutex<Vec<String>>,
    panics: Mutex<Vec<Box<dyn std::any::Any + Send>>>,
}
impl CommandLifetime {
    pub(crate) fn begin(self: &Arc<Self>, component: &'static str) -> Result<PendingCommand, String> {
        let mut pending = self.pending.lock().map_err(|_| "command root unavailable")?;
        if self.closed.load(Ordering::Acquire) { return Err("command admission closed".into()); }
        let mut saved = SavedCommand::new();
        saved.component = component;
        let command = PendingCommand(Arc::new(Mutex::new(saved)));
        pending.push(command.clone());
        Ok(command)
    }
    pub(crate) fn call<T>(self: &Arc<Self>, component: &'static str,
        action: impl FnOnce(&mut CommandOutcome) -> Result<T, String>) -> Result<Result<T, String>, String> {
        let command = self.begin(component)?;
        Ok(command.with_result(action))
    }
    pub(crate) fn call_with_outcome<T>(self: &Arc<Self>, component: &'static str,
        action: impl FnOnce(&mut CommandOutcome) -> Result<T, String>) -> Result<(Result<T, String>, PendingCommand), String> {
        let command = self.begin(component)?;
        let result = command.with_result(action);
        Ok((result, command))
    }
    pub(crate) fn close_admission(&self) { self.closed.store(true, Ordering::Release); }
    pub(crate) fn receive(&self) -> Receiving {
        let commands = self.pending.lock().unwrap_or_else(|error| error.into_inner()).clone();
        let mut completed = Vec::new();
        let mut holds = Vec::new();
        for command in commands {
            let mut saved = match command.0.try_lock() {
                Ok(saved) => saved,
                Err(TryLockError::Poisoned(error)) => error.into_inner(),
                Err(TryLockError::WouldBlock) => { holds.push("command operation active".into()); continue; }
            };
            // A registered-but-not-started worker still owns its result frame.
            if saved.original.is_none() {
                if Arc::strong_count(&command.0) > 2 { holds.push("command worker has not returned".into()); continue; }
                saved.original = Some(Ok(Ok(())));
            }
            match saved.receive() {
                Ok(true) => {
                    // Keep each completed operation associated with its result
                    // until the GUI/role consumer drains this current batch.
                    if let Some(error) = &saved.failure {
                        let mut failures = self.completed_failures.lock().unwrap_or_else(|error| error.into_inner());
                        if let Err(error) = failures.try_reserve(1) {
                            holds.push(format!("{}: result delivery unavailable: {error}", saved.component));
                            continue;
                        }
                        failures.push(format!("{}: {error}", saved.component));
                    }
                    if let Some(Err(payload)) = saved.original.take() {
                        self.panics.lock().unwrap_or_else(|error| error.into_inner()).push(payload);
                    }
                    self.panics.lock().unwrap_or_else(|error| error.into_inner()).append(&mut saved.receiving_panics);
                    completed.push(command.0.clone());
                }
                Ok(false) => holds.push(saved.failure.clone().unwrap_or_else(|| "command capture/process still pending".into())),
                Err(error) => holds.push(error),
            }
        }
        if !completed.is_empty() {
            self.pending.lock().unwrap_or_else(|error| error.into_inner())
                .retain(|command| !completed.iter().any(|done| Arc::ptr_eq(&command.0, done)));
        }
        if holds.is_empty() { Receiving::Ready } else { Receiving::Pending(holds) }
    }
    pub(crate) fn take_failures(&self) -> Vec<String> {
        std::mem::take(&mut *self.completed_failures.lock().unwrap_or_else(|error| error.into_inner()))
    }
    /// The current process-role result receives the whole completed batch.
    /// This replaces an already consumed batch, never an unread operation.
    pub(crate) fn receive_role_result(&self, current: &mut Result<(), String>) -> bool {
        self.receive();
        let completed = self.take_failures();
        if completed.is_empty() { return false; }
        *current = Err(completed.join("; "));
        true
    }
    pub(crate) fn take_panics(&self) -> Vec<Box<dyn std::any::Any + Send>> {
        std::mem::take(&mut *self.panics.lock().unwrap_or_else(|error| error.into_inner()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receiver_error_and_unwind_keep_original_until_later_receiving() {
        let mut saved = SavedCommand::<()>::new();
        saved.run(|_| Err("original domain failure".into()));
        assert!(saved.receive_with(&mut |_, failure| {
            *failure = Some("unreceived candidate error".into());
            Err("receiver failure".into())
        }).is_err());
        assert_eq!(saved.failure.as_deref(), Some("original domain failure"));
        assert!(saved.receive_with(&mut |_, failure| {
            *failure = Some("unreceived panic candidate".into());
            panic!("secondary receiving panic")
        }).is_err());
        assert_eq!(saved.receiving_panics.len(), 1);
        assert_eq!(saved.failure.as_deref(), Some("original domain failure"));
        assert!(saved.receive().unwrap());
        assert_eq!(saved.finish().unwrap_err(), "original domain failure");
    }
    #[test]
    fn original_panic_is_not_replaced_by_receiving_panic() {
        let mut saved = SavedCommand::<()>::new();
        let original: Box<dyn std::any::Any + Send> = Box::new(73u64);
        let address = original.as_ref() as *const _ as *const () as usize;
        saved.run(|_| std::panic::resume_unwind(original));
        assert!(saved.receive_with(&mut |_, failure| {
            *failure = Some("unreceived candidate".into());
            panic!("secondary receiving panic")
        }).is_err());
        assert_eq!(saved.receiving_panics.len(), 1);
        assert!(saved.receive().unwrap());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| saved.finish())).unwrap_err();
        assert_eq!(panic.as_ref() as *const _ as *const () as usize, address);
        assert_eq!(panic.downcast_ref::<u64>(), Some(&73));
    }
    #[test]
    fn classifier_unwind_preserves_the_completed_value_and_panic() {
        let root = Arc::new(CommandLifetime::default());
        let command = root.begin("classifier fixture").unwrap();
        let value = Box::new(91u64);
        let value_address = value.as_ref() as *const u64 as usize;
        let secondary: Box<dyn std::any::Any + Send> = Box::new(29u64);
        let panic_address = secondary.as_ref() as *const _ as *const () as usize;
        let returned = command.with_classified(|_| value, |_| std::panic::resume_unwind(secondary));
        assert_eq!(returned.as_ref() as *const u64 as usize, value_address);
        assert_eq!(*returned, 91);
        assert!(matches!(root.receive(), Receiving::Ready));
        assert!(root.take_failures()[0].contains("classifier unwound"));
        let panics = root.take_panics();
        assert_eq!(panics.len(), 1);
        assert_eq!(panics[0].as_ref() as *const _ as *const () as usize, panic_address);
    }
    #[test]
    fn completed_failure_batch_preserves_each_operation_until_delivery() {
        let root = Arc::new(CommandLifetime::default());
        assert!(root.begin("mutation A").unwrap().with_result::<()>(|_| Err("original A".into())).is_err());
        assert!(root.begin("observation B").unwrap().with_result::<()>(|_| Err("original B".into())).is_err());
        assert!(matches!(root.receive(), Receiving::Ready));
        assert!(matches!(root.receive(), Receiving::Ready));
        let failures = root.take_failures();
        assert_eq!(failures, ["mutation A: original A", "observation B: original B"]);
        assert!(root.take_failures().is_empty());
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "requires creator-owned Windows Job and rebuilt U04_FIXTURE_EXE/U04_FIXTURE_DIR"]
    fn multiple_late_outcomes_reach_the_production_batch_receiver_once() {
        use crate::utils::{bounded_output, CommandObservation, PreparedExec};
        use std::time::{Duration, Instant};
        use std::io::Write;
        let actor = std::path::PathBuf::from(std::env::var_os("U04_FIXTURE_EXE").expect("absolute actor"));
        let parent = std::path::PathBuf::from(std::env::var_os("U04_FIXTURE_DIR").expect("owned fixture parent"));
        let root = Arc::new(CommandLifetime::default());
        let mut directories = Vec::new();
        let mut actions = 0;
        for (name, code) in [("late-mutation-A", "3"), ("late-observation-B", "7")] {
            let directory = parent.join(name);
            std::fs::create_dir(&directory).unwrap();
            let command = root.begin(name).unwrap();
            assert!(command.with_result::<()>(|outcome| {
                actions += 1;
                let prepared = PreparedExec::fixture_absolute(&actor).unwrap()
                    .args(["--fixture", "parent"]).arg(directory.as_os_str()).arg(code);
                assert_eq!(bounded_output(outcome, prepared, Duration::from_millis(400)), CommandObservation::Deadline);
                assert!(!outcome.releasable());
                Err(format!("{name} incomplete"))
            }).is_err());
            assert!(command.pending());
            directories.push(directory);
        }
        for directory in directories {
            let mut release = std::fs::OpenOptions::new().write(true).create_new(true).open(directory.join("release")).unwrap();
            release.write_all(b"owned release").unwrap();
            release.sync_all().unwrap();
        }
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(root.receive(), Receiving::Ready) { break; }
            assert!(Instant::now() < until, "outer Job retains pending actors");
            std::thread::yield_now();
        }
        let mut result = Ok(());
        assert!(root.receive_role_result(&mut result));
        let error = result.unwrap_err();
        assert!(error.contains("late-mutation-A incomplete") && error.contains("exit=Some(3)"));
        assert!(error.contains("late-observation-B incomplete") && error.contains("exit=Some(7)"));
        assert_eq!(error.matches("capture_eof=true").count(), 2);
        assert_eq!(actions, 2);
        assert!(root.take_failures().is_empty());
    }
}
