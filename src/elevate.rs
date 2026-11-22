//! Patching an install this user may not write: root-owned Linux packages
//! (Arch puts Antigravity under `/opt` or `/usr/lib`), where the patch's
//! temp-then-rename fails with `Permission denied` before a byte is written.
//!
//! Only the write is elevated. The window, the service and every per-user file
//! (`~/.local/share/agunlocker`, the systemd user unit, `environment.d`) stay
//! with the user: run as a whole under `sudo`, all of those land in root's home
//! and the service is root's, not theirs. So the window asks polkit to start
//! this same exe as root with `--patch-root <install>`, which patches that one
//! install and exits, and reads what it did back from its stdout.
//!
//! A field report proposed the other shape - the whole GUI under sudo, the
//! install's permissions loosened for the session and restored on close. A
//! crash leaves them loosened, and the per-user state above is wrong for the
//! whole session, so it was not taken.

use std::path::Path;
#[cfg(not(target_os = "windows"))]
use std::path::PathBuf;

/// The helper's flag: patch the install that follows, print the result, exit.
pub const PATCH_ROOT_FLAG: &str = "--patch-root";

/// The helper's other flag: take the patch off the install that follows.
pub const UNPATCH_ROOT_FLAG: &str = "--unpatch-root";

/// What taking the patch off one install did, file by file.
#[derive(Debug, Default, PartialEq, serde::Serialize)]
pub struct Reverted {
    pub files: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Puts one install's own files back: the language server and CLI binaries, the
/// IDE's `main.js`, and the extracted `resources/app` of an older patch. Every
/// step runs and is judged on its own (I45) - a failure is reported, never a
/// reason to skip the rest. The user-level leftovers (`endpoint::remove_ide`,
/// the proxy variable) are not here: they belong to the user, not to the
/// install, and the root helper must not touch them.
pub fn revert_files(inst: &Path) -> Reverted {
    revert_files_run(inst, false)
}

pub(crate) fn revert_files_checked(inst: &Path) -> Result<Reverted, Reverted> {
    let out = revert_files_run(inst, true);
    if !out.errors.is_empty() {
        return Err(out);
    }
    Ok(out)
}

fn revert_files_run(inst: &Path, stop_on_failure: bool) -> Reverted {
    let mut out = Reverted::default();
    #[cfg(windows)]
    let canonical = match crate::windows_coordinator::windows_installation::canonical_installed(inst) {
        Ok(value) => value,
        Err(error) => { out.errors.push(error); return out; },
    };
    #[cfg(not(windows))]
    let canonical = false;
    if stop_on_failure {
        match crate::patch_binary::unpatch_all_binaries_checked(inst) {
            Ok(files) => out.files += files,
            Err(error) => { out.files += error.completed; out.errors.push(error.cause); return out; },
        }
    } else {
    for (label, res) in crate::patch_binary::unpatch_all_binaries(inst) {
        match res {
            Ok(0) => {}
            Ok(_) => out.files += 1,
            Err(e) => out.errors.push(format!("{label}: {e}")),
        }
    }
    }
    // A canonical Desktop operation is NativeBinaryOnly here. Archive/hook
    // revert belongs to its versioned installation owner, never this leaf.
    if canonical { return out; }
    if stop_on_failure {
        match crate::patch_ide::unpatch_ide_js_checked(inst) {
            Ok(results) => for (label, result) in results {
                match result {
                    crate::patch_ide::JsRestore::Unchanged => {},
                    crate::patch_ide::JsRestore::BackupRestored => out.files += 1,
                    crate::patch_ide::JsRestore::MarkerOnly => {
                        out.files += 1;
                        out.warnings.push(format!("{label}: бэкапа нет, снят только маркер"));
                    },
                }
            },
            Err(error) => {
                for (label, result) in error.completed {
                    match result {
                        crate::patch_ide::JsRestore::Unchanged => {},
                        crate::patch_ide::JsRestore::BackupRestored => out.files += 1,
                        crate::patch_ide::JsRestore::MarkerOnly => {
                            out.files += 1;
                            out.warnings.push(format!("{label}: бэкапа нет, снят только маркер"));
                        },
                    }
                }
                out.errors.push(error.cause); return out;
            },
        }
    } else {
    for (label, res) in crate::patch_ide::unpatch_ide_js(inst) {
        match res {
            Ok(true) => out.files += 1,
            Ok(false) => out
                .warnings
                .push(format!("{label}: бэкапа нет, снят только маркер")),
            Err(e) => out.errors.push(format!("{label}: {e}")),
        }
    }
    }
    if let Err(e) = crate::restore_pristine_asar(&inst.join("resources")) {
        if stop_on_failure { out.errors.push(format!("app.asar не восстановлен: {e}")); }
        else { out.warnings.push(format!("app.asar не восстановлен: {e}")); }
    }
    out
}

/// What the helper reported for its install.
#[derive(Debug, Default)]
pub struct Elevated {
    pub label: String,
    pub warnings: Vec<String>,
    pub proxy_var: bool,
    pub proxy_var_retryable: bool,
}

/// Whether patching `inst` needs root: a directory the patch writes into
/// refuses this user. Never for root itself, and never on Windows, where the
/// window is elevated already.
pub fn needs_root(inst: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let _ = inst;
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        !crate::utils::is_admin() && written_dirs(inst).iter().any(|d| !can_write(d))
    }
}

/// The directories the patch creates its temps in: beside each binary it
/// would rewrite, and beside the JS it would rewrite.
#[cfg(not(target_os = "windows"))]
fn written_dirs(inst: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = crate::patch_binary::binary_targets(inst)
        .into_iter()
        .filter(|t| t.is_file())
        .filter_map(|t| t.parent().map(Path::to_path_buf))
        .collect();
    let app = inst.join("resources").join("app");
    for js in [
        app.join("out").join("main.js"),
        app.join("dist").join("main.js"),
    ] {
        if let Some(dir) = js.parent().filter(|_| js.is_file()) {
            dirs.push(dir.to_path_buf());
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Asked by trying, not by mode bits: ACLs, read-only mounts and ownership all
/// answer the same question the rename will ask. Only a refusal counts - any
/// other failure is left for the patch itself to report.
#[cfg(not(target_os = "windows"))]
fn can_write(dir: &Path) -> bool {
    let probe = dir.join(format!(".ag_write_probe_{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(e) => e.kind() != std::io::ErrorKind::PermissionDenied,
    }
}

/// The command a user can run by hand when no password prompt can be shown.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub fn manual_command(inst: &Path) -> String {
    manual_command_for(PATCH_ROOT_FLAG, inst)
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
fn manual_command_for(flag: &str, inst: &Path) -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "./ag_unlocker".to_string());
    format!(
        "sudo {} {} {}",
        shell_quote(&exe),
        flag,
        shell_quote(&inst.display().to_string())
    )
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Patches `inst` through `pkexec`, which shows the desktop's own password
/// prompt. `--disable-internal-agent`: with no desktop agent (a TUI over SSH)
/// pkexec would otherwise ask on the terminal the TUI is drawing on, so it
/// fails instead and the caller shows `manual_command`.
#[cfg(not(target_os = "windows"))]
pub fn patch_as_root(inst: &Path) -> Result<Elevated, String> {
    use std::process::Command;
    let exe = std::env::current_exe().map_err(|e| format!("не найден путь к exe: {e}"))?;
    let out = Command::new("pkexec")
        .arg("--disable-internal-agent")
        .arg(&exe)
        .arg(PATCH_ROOT_FLAG)
        .arg(inst)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "установка принадлежит root, а pkexec в системе нет. Выполните в терминале: {}",
                    manual_command(inst)
                )
            } else {
                format!("pkexec не запустился: {e}")
            }
        })?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed = parse_report(&stdout);
    match (out.status.code(), parsed) {
        (Some(0), Ok(done)) => Ok(done),
        (_, Err(e)) if !e.is_empty() => Err(e),
        // pkexec's own codes: 126 - the prompt was dismissed or refused, 127 -
        // no agent to show it.
        (Some(126), _) => Err("пароль не введён — патч не наложен".to_string()),
        (Some(127), _) => Err(format!(
            "окно запроса пароля недоступно. Выполните в терминале: {}",
            manual_command(inst)
        )),
        (code, _) => Err(format!(
            "патч от имени root не удался (код {}): {}",
            code.map_or("—".to_string(), |c| c.to_string()),
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}

#[cfg(target_os = "windows")]
pub fn patch_as_root(_inst: &Path) -> Result<Elevated, String> {
    Err("не нужно на Windows".to_string())
}

/// The helper's side, run as root: patch one install, report in lines of
/// `KEY<TAB>value`, exit 0 on success.
pub fn run_helper(arg: Option<String>) -> ! {
    let (wire, code) = run_helper_root(arg, crate::process_install, &mut crate::command_lifetime::receive_failure, #[cfg(test)] None);
    print!("{wire}");
    std::process::exit(code);
}

fn run_helper_root(arg: Option<String>,
    action: impl FnOnce(&mut crate::utils::CommandOutcome, &std::path::Path) -> Result<crate::InstallOutcome, String>,
    receive: &mut impl FnMut(&crate::utils::CommandOutcome, &mut Option<String>) -> Result<(), String>,
    #[cfg(test)] on_hold: Option<&mut dyn FnMut()>) -> (String, i32) {
    run_helper_root_with_writer(arg, action, receive, &mut std::io::stderr(), #[cfg(test)] on_hold)
}

fn run_helper_root_with_writer(arg: Option<String>,
    action: impl FnOnce(&mut crate::utils::CommandOutcome, &std::path::Path) -> Result<crate::InstallOutcome, String>,
    receive: &mut impl FnMut(&crate::utils::CommandOutcome, &mut Option<String>) -> Result<(), String>,
    diagnostic: &mut impl std::io::Write,
    #[cfg(test)] mut on_hold: Option<&mut dyn FnMut()>) -> (String, i32) {
    let Some(inst) = arg.map(std::path::PathBuf::from).filter(|p| p.is_absolute() && p.is_dir())
    else { return ("ERR\tне указана папка установки\n".into(), 2); };
    let mut saved = crate::command_lifetime::SavedCommand::new();
    saved.run(|outcome| action(outcome, &inst));
    let mut held_reported = false;
    loop {
        match saved.receive_with(receive) {
            Ok(true) => break,
            Ok(false) => {
                if !held_reported {
                    if let Err(error) = writeln!(diagnostic, "helper command outcome remains pending") {
                        saved.diagnostic_errors.push(error);
                    }
                    #[cfg(test)]
                    if let Some(callback) = on_hold.as_mut() { callback(); }
                    held_reported = true;
                }
            }
            Err(error) => {
                if let Err(diagnostic_error) = writeln!(diagnostic, "helper result receiving held: {error}") {
                    saved.diagnostic_errors.push(diagnostic_error);
                }
                // Re-enter only the saved receiving step. The action is never
                // run again, and a failed projection has not been committed.
                match saved.receive_with(receive) {
                    Ok(true) => break,
                    Ok(false) => {},
                    Err(recovery) => {
                        // The production receiver has no external prerequisite.
                        // If receiving-only recovery itself violates that
                        // invariant, retain both failures without a panic loop.
                        if let Err(error) = writeln!(diagnostic, "helper receiving recovery remains held: {recovery}") {
                            saved.diagnostic_errors.push(error);
                        }
                        loop { std::thread::park_timeout(std::time::Duration::from_millis(10)); }
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    helper_wire(&saved.finish())
}

fn helper_wire(result: &Result<crate::InstallOutcome, String>) -> (String, i32) {
    match result {
        Ok(outcome) => {
            let mut wire = format!("OK\t{}\n", one_line(outcome.label));
            for warning in &outcome.warnings { wire.push_str(&format!("WARN\t{}\n", one_line(warning))); }
            wire.push_str(&format!("PROXYVAR\t{}\t{}\n", u8::from(outcome.summary.proxy_var > 0), u8::from(outcome.summary.proxy_var_retryable)));
            (wire, 0)
        }
        Err(error) => (format!("ERR\t{}\n", one_line(error)), 1),
    }
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r', '\t'], " ")
}

/// The helper's lines back into a result. `Err("")` when it said nothing at
/// all - pkexec refused before it ran - so the caller explains by exit code.
fn parse_report(stdout: &str) -> Result<Elevated, String> {
    let mut done = Elevated::default();
    let mut ok = false;
    for line in stdout.lines() {
        let mut parts = line.split('\t');
        match parts.next() {
            Some("OK") => {
                ok = true;
                done.label = parts.next().unwrap_or_default().to_string();
            }
            Some("WARN") => done
                .warnings
                .push(parts.next().unwrap_or_default().to_string()),
            Some("PROXYVAR") => {
                done.proxy_var = parts.next() == Some("1");
                done.proxy_var_retryable = parts.next() == Some("1");
            }
            Some("ERR") => return Err(parts.next().unwrap_or_default().to_string()),
            _ => {}
        }
    }
    if ok {
        Ok(done)
    } else {
        Err(String::new())
    }
}

/// Takes the patch off a root-owned install through `pkexec`, the way
/// `patch_as_root` puts it on. Without it the switch could be turned on for such
/// an install and never off: the revert failed with `Permission denied`, the
/// binary stayed patched, and the row read On again after every refresh.
#[cfg(not(target_os = "windows"))]
pub fn unpatch_as_root(inst: &Path) -> Result<Reverted, String> {
    use std::process::Command;
    let exe = std::env::current_exe().map_err(|e| format!("не найден путь к exe: {e}"))?;
    let out = Command::new("pkexec")
        .arg("--disable-internal-agent")
        .arg(&exe)
        .arg(UNPATCH_ROOT_FLAG)
        .arg(inst)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "установка принадлежит root, а pkexec в системе нет. Выполните в терминале: {}",
                    manual_command_for(UNPATCH_ROOT_FLAG, inst)
                )
            } else {
                format!("pkexec не запустился: {e}")
            }
        })?;
    match (
        out.status.code(),
        parse_reverted(&String::from_utf8_lossy(&out.stdout)),
    ) {
        (Some(0), Some(done)) => Ok(done),
        (Some(126), _) => Err("пароль не введён — патч не снят".to_string()),
        (Some(127), _) => Err(format!(
            "окно запроса пароля недоступно. Выполните в терминале: {}",
            manual_command_for(UNPATCH_ROOT_FLAG, inst)
        )),
        (code, _) => Err(format!(
            "снятие патча от имени root не удалось (код {}): {}",
            code.map_or("—".to_string(), |c| c.to_string()),
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}

#[cfg(target_os = "windows")]
pub fn unpatch_as_root(_inst: &Path) -> Result<Reverted, String> {
    Err("не нужно на Windows".to_string())
}

/// The helper's side of `unpatch_as_root`, run as root.
pub fn run_unpatch_helper(arg: Option<String>) -> ! {
    let Some(inst) = arg
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
    else {
        println!("ERR\tне указана папка установки");
        std::process::exit(2);
    };
    let done = revert_files(&inst);
    println!("FILES\t{}", done.files);
    for e in &done.errors {
        println!("BAD\t{}", one_line(e));
    }
    for w in &done.warnings {
        println!("WARN\t{}", one_line(w));
    }
    println!("DONE");
    std::process::exit(0);
}

/// `None` unless the helper got as far as `DONE`: output cut short is a failure.
fn parse_reverted(stdout: &str) -> Option<Reverted> {
    let mut done = Reverted::default();
    let mut finished = false;
    for line in stdout.lines() {
        let mut parts = line.split('\t');
        match (parts.next(), parts.next()) {
            (Some("FILES"), Some(n)) => done.files = n.parse().unwrap_or(0),
            (Some("BAD"), Some(m)) => done.errors.push(m.to_string()),
            (Some("WARN"), Some(m)) => done.warnings.push(m.to_string()),
            (Some("DONE"), _) => finished = true,
            _ => {}
        }
    }
    finished.then_some(done)
}

#[cfg(test)]
mod tests {
    struct BrokenDiagnostic(usize);
    impl std::io::Write for BrokenDiagnostic {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.0 += 1;
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    #[test]
    fn helper_fail_once_receiving_recovers_without_replaying_action() {
        let mut actions = 0;
        let mut receipts = 0;
        let mut diagnostic = BrokenDiagnostic(0);
        let (wire, code) = super::run_helper_root_with_writer(Some(std::env::temp_dir().to_string_lossy().into_owned()),
            |_, _| { actions += 1; Err("original helper error".into()) },
            &mut |command, failure| {
                receipts += 1;
                if receipts == 1 {
                    *failure = Some("unreceived candidate".into());
                    return Err("repairable receiving failure".into());
                }
                crate::command_lifetime::receive_failure(command, failure)
            }, &mut diagnostic, None);
        assert_eq!((actions, receipts), (1, 2));
        assert_eq!(diagnostic.0, 1);
        assert_eq!((wire.as_str(), code), ("ERR\toriginal helper error\n", 1));
    }
    #[test]
    fn helper_fail_once_receiver_unwind_resumes_the_same_original_box() {
        let original: Box<dyn std::any::Any + Send> = Box::new(43u64);
        let address = original.as_ref() as *const _ as *const () as usize;
        let mut receipts = 0;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::run_helper_root(Some(std::env::temp_dir().to_string_lossy().into_owned()),
                |_, _| std::panic::resume_unwind(original),
                &mut |command, failure| {
                    receipts += 1;
                    if receipts == 1 {
                        *failure = Some("unreceived receiver panic projection".into());
                        panic!("secondary helper receiver panic");
                    }
                    crate::command_lifetime::receive_failure(command, failure)
                }, None)
        })).unwrap_err();
        assert_eq!(receipts, 2);
        assert_eq!(panic.as_ref() as *const _ as *const () as usize, address);
        assert_eq!(panic.downcast_ref::<u64>(), Some(&43));
    }
    #[test]
    fn helper_receiving_preserves_original_and_secondary_panics() {
        let mut saved = crate::command_lifetime::SavedCommand::<()>::new();
        saved.run(|_| panic!("original helper panic"));
        assert!(saved.receive_with(&mut |_, _| panic!("receiver panic")).is_err());
        assert_eq!(saved.receiving_panics.len(), 1);
        assert!(saved.receive().unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| saved.finish()));
        assert_eq!(result.unwrap_err().downcast_ref::<&str>(), Some(&"original helper panic"));
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "requires creator-owned Windows Job and private U04_FIXTURE_EXE/U04_FIXTURE_DIR"]
    fn helper_receives_inherited_writer_before_final_wire() {
        let executable = std::path::PathBuf::from(std::env::var_os("U04_FIXTURE_EXE").expect("absolute actor"));
        let parent = std::path::PathBuf::from(std::env::var_os("U04_FIXTURE_DIR").expect("qualified fixture directory"));
        let directory = parent.join("helper-crate-inherited-writer");
        std::fs::create_dir(&directory).unwrap();
        let release = directory.join("release");
        let (send, receive) = std::sync::mpsc::channel();
        let releaser = std::thread::spawn(move || {
            use std::io::Write;
            receive.recv().unwrap();
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(release).unwrap();
            file.write_all(b"release").unwrap();
            file.sync_all().unwrap();
        });
        let mut held = || send.send(()).unwrap();
        let mut diagnostic = BrokenDiagnostic(0);
        let mut actions = 0;
        let (wire, code) = super::run_helper_root_with_writer(Some(directory.to_string_lossy().into_owned()), |outcome, path| {
            actions += 1;
            let prepared = crate::utils::PreparedExec::fixture_absolute(&executable).unwrap()
                .args(["--fixture", "parent"]).arg(path.as_os_str());
            assert_eq!(crate::utils::bounded_output(outcome, prepared, std::time::Duration::from_millis(400)),
                crate::utils::CommandObservation::Deadline);
            assert!(!outcome.releasable());
            Err("original helper failure".into())
        }, &mut crate::command_lifetime::receive_failure, &mut diagnostic, Some(&mut held));
        releaser.join().unwrap();
        assert_eq!(actions, 1);
        assert_eq!(diagnostic.0, 1);
        assert_eq!(code, 1);
        assert!(wire.starts_with("ERR\toriginal helper failure; "));
        assert!(wire.contains("capture_eof=true"));
    }
    #[test]
    fn the_unpatch_report_reads_back_and_needs_its_last_line() {
        let done = super::parse_reverted("FILES\t2\nBAD\tlanguage_server: отказано\nWARN\tapp.asar\nDONE\n")
            .expect("done");
        assert_eq!(done.files, 2);
        assert_eq!(done.errors, vec!["language_server: отказано".to_string()]);
        assert_eq!(done.warnings, vec!["app.asar".to_string()]);
        assert!(super::parse_reverted("FILES\t2\n").is_none());
    }

    use super::*;

    #[test]
    fn the_helpers_report_reads_back() {
        let done = parse_report("OK\tAntigravity IDE\nWARN\tоверрайд не снят\nPROXYVAR\t1\t0\n")
            .expect("ok");
        assert_eq!(done.label, "Antigravity IDE");
        assert_eq!(done.warnings, vec!["оверрайд не снят".to_string()]);
        assert!(done.proxy_var && !done.proxy_var_retryable);
        assert_eq!(
            parse_report("ERR\tСигнатура не найдена\n").err().as_deref(),
            Some("Сигнатура не найдена")
        );
        assert_eq!(parse_report("").err().as_deref(), Some(""));
    }

    /// A binary in a directory this user cannot write is what sends the patch
    /// through pkexec; one in a writable directory is patched in place.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn a_read_only_install_needs_root_and_a_writable_one_does_not() {
        use std::os::unix::fs::PermissionsExt;
        if crate::utils::is_admin() {
            return; // root writes anywhere; nothing to measure
        }
        let inst = std::env::temp_dir().join(format!("ag_elevate_{}", std::process::id()));
        let bin = inst.join("resources").join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("language_server_linux_x64"), b"x").unwrap();
        assert!(!needs_root(&inst));
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(needs_root(&inst));
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&inst);
    }

    #[test]
    fn the_manual_command_survives_a_quote_in_the_path() {
        assert_eq!(shell_quote("/opt/it's here"), "'/opt/it'\\''s here'");
    }
}
