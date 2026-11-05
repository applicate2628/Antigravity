pub(crate) use crate::binary_profile::{count_occurrences, field_signatures, proxy_var_original, replace_all};
#[allow(unused_imports)]
pub(crate) use crate::binary_profile::{prepare_profile, PatchProfile, ProfileError, ProfilePreparation};


use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePermissionDenied {
    pub operation: &'static str,
    pub kind: std::io::ErrorKind,
    pub raw_os_error: Option<i32>,
    pub detail: String,
}

impl std::fmt::Display for NativePermissionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: kind={:?}, raw={:?}: {}", self.operation, self.kind, self.raw_os_error, self.detail)
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
enum MacWriteError { PermissionDenied(NativePermissionDenied), Other(String) }

#[cfg(target_os = "macos")]
impl From<String> for MacWriteError { fn from(value: String) -> Self { Self::Other(value) } }
#[cfg(target_os = "macos")]
impl From<&str> for MacWriteError { fn from(value: &str) -> Self { Self::Other(value.to_owned()) } }
#[cfg(target_os = "macos")]
impl std::fmt::Display for MacWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::PermissionDenied(error) => std::fmt::Display::fmt(error, f), Self::Other(error) => f.write_str(error) }
    }
}

#[cfg(target_os = "macos")]
fn mac_stage_creation_error(error: std::io::Error) -> MacWriteError {
    let kind = error.kind(); let raw_os_error = error.raw_os_error();
    if kind == std::io::ErrorKind::PermissionDenied || matches!(raw_os_error, Some(libc::EPERM | libc::EACCES)) {
        MacWriteError::PermissionDenied(NativePermissionDenied {
            operation: "создание staging", kind, raw_os_error, detail: error.to_string(),
        })
    } else { MacWriteError::Other(format!("Файл не заменён: создание staging: {error}")) }
}

// Two edits are made to the native binaries, both same-length renames of a
// string literal. Same length means offsets, relocations and the PE layout are
// untouched, and the revert is byte-exact.
//
// 1. The protobuf field name `ineligible` (and `ineligible_tiers`) becomes a
//    same-length nonsense word. Both the descriptor and the matching Go struct
//    tag are rewritten, so they stay consistent; the JSON the client receives no
//    longer carries the field it gates on. This one is the patch - without it
//    nothing works, so a build where it does not match is a failure.
//
// 2. The environment variable the language server reads its proxy from is
//    renamed to a private name (`PROXY_VAR_*` below). This one is additive: a
//    build where it does not match still unlocks, it just has no local-proxy
//    route, so it is counted and reported, never fatal.
//
// The literals live inside obfstr! blocks so they don't show up as plain
// strings in this binary.

/// Writes the binary back atomically: a sibling temp on the same directory, then
/// a rename over the target. A crash or power loss mid-write leaves either the
/// old binary or the new one, never a truncated 135 MB executable that would fail
/// to launch. A locked Windows image requires a normal close; this module owns
/// no creator process handle and cannot terminate a process by image name.
#[cfg(not(target_os = "macos"))]
fn write_binary(bin_path: &Path, data: &[u8]) -> Result<(), String> {
    #[cfg(windows)]
    let canonical_guard = crate::windows_coordinator::windows_installation::admit_native_binary(bin_path,
        binary_targets, crate::windows_coordinator::receive_saved_context)?;
    match write_atomic(bin_path, data) {
        Ok(()) => {
            #[cfg(windows)]
            canonical_guard.recheck().map_err(|error| format!("Файл заменён, но каноническая проверка не завершилась: {error}"))?;
            return Ok(());
        },
        Err(error) => {
            #[cfg(windows)]
            return Err(format!("Файл не заменён; закройте использующее его приложение обычным способом: {error}"));
            #[cfg(all(not(windows), not(target_os = "macos")))]
            let _ = error;
        }
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
    kill_holder(bin_path);
    thread::sleep(Duration::from_millis(500));
    write_atomic(bin_path, data).map_err(|e| e.to_string())
    }
}

#[cfg(target_os = "macos")]
fn read_mac_preimage(path: &Path) -> Result<(fs::File, Vec<u8>), String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    mac_check_no_stage(path)?;
    let mut file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW)
        .open(path).map_err(|e| format!("исходный файл: {e}"))?;
    #[cfg(test)]
    mac_writer_test_barrier("OPENED")?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => "исходный файл занят".to_owned(),
        std::fs::TryLockError::Error(error) => format!("блокировка исходного файла: {error}"),
    })?;
    let held = file.metadata().map_err(|e| e.to_string())?;
    let named = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !held.is_file() || !named.is_file() || held.nlink() != 1 || held.dev() != named.dev() || held.ino() != named.ino() {
        return Err("неоднозначная идентичность исходного файла".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    let named_after = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if held.dev() != after.dev() || held.ino() != after.ino() || held.size() != after.size()
        || held.mtime() != after.mtime() || held.mtime_nsec() != after.mtime_nsec()
        || after.dev() != named_after.dev() || after.ino() != named_after.ino() {
        return Err("исходный файл изменился во время чтения".into());
    }
    #[cfg(test)]
    mac_writer_test_barrier("ADMITTED")?;
    Ok((file, bytes))
}

#[cfg(target_os = "macos")]
fn mac_check_no_stage(path: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let parent = path.parent().ok_or("нет родительского каталога")?;
    let name = path.file_name().ok_or("нет имени файла")?.as_bytes();
    for item in fs::read_dir(parent).map_err(|e| format!("проверка staging: {e}"))? {
        let item = item.map_err(|e| format!("проверка staging: {e}"))?;
        let file_name = item.file_name();
        let bytes = file_name.as_bytes();
        if bytes.starts_with(name) && bytes.get(name.len()) == Some(&b'.') && bytes.ends_with(TEMP_SUFFIX.as_bytes()) {
            return Err(format!("существует незавершённый staging: {}", item.path().display()));
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
fn mac_writer_test_barrier(phase: &str) -> Result<(), String> {
    use std::io::{BufRead, Write};
    if std::env::var_os("AG_MAC_WRITER_TEST_CHILD").is_none() { return Ok(()); }
    let phases = std::env::var("AG_MAC_WRITER_TEST_PHASES").unwrap_or_default();
    if !phases.split(',').any(|value| value == phase) { return Ok(()); }
    let mut output = std::io::stdout().lock();
    writeln!(output, "\nAG_WRITER_PHASE {phase}").and_then(|_| output.flush()).map_err(|error| format!("test phase output: {error}"))?;
    let mut reply = String::new();
    std::io::stdin().lock().read_line(&mut reply).map_err(|error| format!("test phase input: {error}"))?;
    if reply.trim_end() != "CONTINUE" { return Err("test phase input closed or invalid".into()); }
    Ok(())
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
enum MacTargetScope { AppBundle(PathBuf), StandaloneExecutable(PathBuf) }

#[cfg(target_os = "macos")]
fn mac_scope_contains_image(scope: &MacTargetScope, image: &Path) -> bool {
    match scope {
        MacTargetScope::AppBundle(bundle) => image.starts_with(bundle),
        MacTargetScope::StandaloneExecutable(target) => image == target,
    }
}

#[cfg(target_os = "macos")]
fn mac_target_scope(install: &Path, path: &Path) -> Result<MacTargetScope, String> {
    use std::os::unix::fs::MetadataExt;
    if crate::resolve_install_root(install).as_deref() != Some(install)
        || !binary_targets(install).iter().any(|candidate| candidate == path) {
        return Err("цель не принадлежит выбранной установке".into());
    }
    let info = fs::symlink_metadata(path).map_err(|error| format!("проверка цели: {error}"))?;
    if !info.is_file() || info.nlink() != 1 { return Err("цель не является обычным файлом".into()); }
    let path = fs::canonicalize(path).map_err(|error| format!("путь цели: {error}"))?;
    if let Some(bundle) = path.ancestors().find(|part| part.extension().is_some_and(|ext| ext == "app")) {
        return Ok(MacTargetScope::AppBundle(bundle.to_path_buf()));
    }
    let candidates = cli_target_candidates(install).into_iter().chain(extension_cli_targets(install));
    for candidate in candidates {
        if fs::canonicalize(candidate).ok().as_deref() == Some(path.as_path()) {
            return Ok(MacTargetScope::StandaloneExecutable(path));
        }
    }
    Err("вне пакета найден неподтверждённый исполняемый файл".into())
}

#[cfg(target_os = "macos")]
fn mac_target_inactive(scope: &MacTargetScope) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 { return Err(format!("список процессов недоступен: {}", std::io::Error::last_os_error())); }
    let mut pids = vec![0 as libc::pid_t; count as usize + 1];
    loop {
        let bytes = pids.len().checked_mul(std::mem::size_of::<libc::pid_t>()).and_then(|size| i32::try_from(size).ok())
            .ok_or("список процессов слишком велик")?;
        let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if count <= 0 { return Err(format!("список процессов недоступен: {}", std::io::Error::last_os_error())); }
        if count as usize >= pids.len() {
            let next = pids.len().checked_mul(2).ok_or("список процессов слишком велик")?;
            pids.resize(next, 0);
            continue;
        }
        pids.truncate(count as usize);
        break;
    }
    for pid in pids.into_iter().filter(|pid| *pid > 0) {
        let mut image = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        unsafe { *libc::__error() = 0; }
        let n = unsafe { libc::proc_pidpath(pid, image.as_mut_ptr().cast(), image.len() as u32) };
        if n <= 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) { continue; }
            return Err(format!("образ процесса {pid} недоступен: {error}"));
        }
        let image = std::ffi::CStr::from_bytes_until_nul(&image).map_err(|_| "неверный путь процесса")?;
        let image = Path::new(std::ffi::OsStr::from_bytes(image.to_bytes()));
        let image = fs::canonicalize(image).map_err(|error| format!("путь процесса {pid} недоступен: {error}"))?;
        if mac_scope_contains_image(scope, &image) { return Err(format!("выбранная цель используется процессом: {}", image.display())); }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_binary(bin_path: &Path, data: &[u8], preimage: &[u8], original: &mut fs::File, install: &Path, scope: &MacTargetScope) -> Result<(), MacWriteError> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

    fn open_checked(path: &Path, write: bool) -> Result<fs::File, String> {
        let file = fs::OpenOptions::new().read(true).write(write)
            .custom_flags(libc::O_NOFOLLOW).open(path).map_err(|e| e.to_string())?;
        let held = file.metadata().map_err(|e| e.to_string())?;
        let named = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !held.is_file() || !named.is_file() || held.nlink() != 1
            || held.dev() != named.dev() || held.ino() != named.ino() {
            return Err("неоднозначная идентичность файла".into());
        }
        Ok(file)
    }
    fn same(file: &fs::File, path: &Path) -> Result<(), String> {
        let held = file.metadata().map_err(|e| e.to_string())?;
        let named = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if held.dev() != named.dev() || held.ino() != named.ino() || named.file_type().is_symlink()
            || held.is_dir() != named.is_dir() || held.is_file() != named.is_file()
            || (held.is_file() && held.nlink() != 1) {
            return Err("идентичность пути изменилась".into());
        }
        Ok(())
    }
    fn read_all(file: &mut fs::File) -> Result<Vec<u8>, String> {
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        Ok(bytes)
    }
    fn native(command: &mut Command, label: &str) -> Result<(), String> {
        let output = command.output().map_err(|e| format!("{label}: запуск: {e}"))?;
        #[cfg(test)]
        let capture = (|| -> std::io::Result<()> {
            let mut stderr = std::io::stderr().lock();
            writeln!(stderr, "AG_MAC_NATIVE {label} status={:?}", output.status)?;
            stderr.write_all(b"AG_MAC_NATIVE_STDOUT_BEGIN\n")?;
            stderr.write_all(&output.stdout)?;
            stderr.write_all(b"\nAG_MAC_NATIVE_STDERR_BEGIN\n")?;
            stderr.write_all(&output.stderr)?;
            stderr.write_all(b"\nAG_MAC_NATIVE_END\n")
        })();
        if !output.status.success() {
            #[cfg(test)]
            let capture_detail = format!("; capture={capture:?}");
            #[cfg(not(test))]
            let capture_detail = "";
            return Err(format!("{label}: {:?}; stdout={:?}; stderr={:?}", output.status,
                String::from_utf8_lossy(&output.stdout), format!("{}{}", String::from_utf8_lossy(&output.stderr), capture_detail)));
        }
        #[cfg(test)]
        capture.map_err(|e| format!("{label}: status={:?}; capture: {e}", output.status))?;
        Ok(())
    }

    if std::env::args_os().any(|arg| arg == "--watchdog")
        && !crate::settings::watchdog_snapshot()?.auto_patch_wanted() {
        return Err("сохранённые настройки запрещают автопатч".into());
    }
    if mac_target_scope(install, bin_path)? != *scope { return Err("область цели изменилась".into()); }
    mac_target_inactive(scope)?;
    if data.len() != preimage.len() { return Err("Файл не заменён: длина подготовленных данных изменилась".into()); }
    let parent = bin_path.parent().ok_or("Файл не заменён: отсутствует родитель")?;
    let name = bin_path.file_name().ok_or("Файл не заменён: отсутствует имя")?;
    let mut ancestor = PathBuf::new();
    for part in parent.components() {
        ancestor.push(part.as_os_str());
        let m = fs::symlink_metadata(&ancestor).map_err(|e| format!("Файл не заменён: родитель: {e}"))?;
        if m.file_type().is_symlink() || !m.is_dir() { return Err("Файл не заменён: неоднозначный родитель".into()); }
    }
    let parent_handle = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW)
        .open(parent).map_err(|e| format!("Файл не заменён: родитель: {e}"))?;
    same(&parent_handle, parent).map_err(|e| format!("Файл не заменён: {e}"))?;
    same(original, bin_path).map_err(|e| format!("Файл не заменён: {e}"))?;
    let original_metadata = original.metadata().map_err(|e| format!("исходный файл: {e}"))?;
    if read_all(original)? != preimage { return Err("Файл не заменён: исходные данные изменились".into()); }
    let stage_dir = temp_path(bin_path);
    fs::DirBuilder::new().mode(0o700).create(&stage_dir)
        .map_err(mac_stage_creation_error)?;
    let staged = stage_dir.join(name);
    let operation = (|| -> Result<(), String> {
        let stage_parent = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW)
            .open(&stage_dir).map_err(|e| format!("staging parent: {e}"))?;
        same(&parent_handle, parent)?;
        same(&stage_parent, &stage_dir)?;
        let mut copy = Command::new("/usr/bin/ditto");
        copy.args(["--rsrc", "--extattr", "--qtn", "--acl"]).arg(bin_path).arg(&staged);
        for key in ["DITTOABORT", "DITTONORSRC", "DITTOKEEPBINARIESPATTERN", "DITTOKEEPBINARIESDIR", "DITTO_TEST_OPTIONS"] { copy.env_remove(key); }
        native(&mut copy, "ditto")?;
        same(&parent_handle, parent)?; same(&stage_parent, &stage_dir)?; same(original, bin_path)?;
        if read_all(original)? != preimage { return Err("исходные данные изменились после копирования".into()); }
        let mut stage = open_checked(&staged, true)?;
        if read_all(&mut stage)? != preimage { return Err("копия не соответствует исходным данным".into()); }
        stage.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        stage.write_all(data).map_err(|e| format!("запись staging: {e}"))?;
        stage.sync_all().map_err(|e| format!("синхронизация staging: {e}"))?;
        if read_all(&mut stage)? != data { return Err("проверка записи staging не прошла".into()); }
        same(&stage, &staged)?; same(&stage_parent, &stage_dir)?;
        native(Command::new("/usr/bin/codesign").args(["--force", "--sign", "-", "--preserve-metadata=identifier,entitlements,flags,runtime,launch-constraints,library-constraints"]).arg(&staged), "codesign")?;
        same(&stage_parent, &stage_dir)?;
        let mut signed = open_checked(&staged, false)?;
        signed.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => "подписанный staging занят".to_owned(),
            std::fs::TryLockError::Error(error) => format!("блокировка подписанного staging: {error}"),
        })?;
        let signed_bytes = read_all(&mut signed)?;
        native(Command::new("/usr/bin/codesign").args(["--verify", "--strict"]).arg(&staged), "stage verify")?;
        same(&signed, &staged)?; same(&stage_parent, &stage_dir)?; same(&parent_handle, parent)?; same(original, bin_path)?;
        if read_all(&mut signed)? != signed_bytes || read_all(original)? != preimage {
            return Err("данные изменились перед заменой".into());
        }
        // Save the admitted bytes before exchange: a noncooperating updater can
        // unlink the original between the last check and the exchange.
        let backup_path = stage_dir.join(".ag-original");
        let mut backup = fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW).open(&backup_path).map_err(|e| format!("сохранение исходных данных: {e}"))?;
        backup.write_all(preimage).map_err(|e| format!("сохранение исходных данных: {e}"))?;
        backup.sync_all().map_err(|e| format!("сохранение исходных данных: {e}"))?;
        if read_all(&mut backup)? != preimage { return Err("копия исходных данных не подтверждена".into()); }
        same(&backup, &backup_path)?; same(&stage_parent, &stage_dir)?;
        if mac_target_scope(install, bin_path)? != *scope { return Err("область цели изменилась".into()); }
        mac_target_inactive(scope)?;
        same(original, bin_path)?;
        if std::env::args_os().any(|arg| arg == "--watchdog")
            && !crate::settings::watchdog_snapshot()?.auto_patch_wanted() {
            return Err("сохранённые настройки запрещают автопатч".into());
        }
        let stage_name = std::ffi::CString::new(name.as_bytes()).map_err(|_| "неверное имя staging")?;
        let live_name = std::ffi::CString::new(name.as_bytes()).map_err(|_| "неверное имя файла")?;
        #[cfg(test)]
        mac_writer_test_barrier("PRE_SWAP")?;
        if unsafe { libc::renameatx_np(stage_parent.as_raw_fd(), stage_name.as_ptr(),
            parent_handle.as_raw_fd(), live_name.as_ptr(), libc::RENAME_SWAP) } != 0 {
            return Err(format!("атомарный обмен: {}", std::io::Error::last_os_error()));
        }
        #[cfg(test)]
        mac_writer_test_barrier("POST_SWAP").map_err(|error| format!("TARGET_CHANGED: test phase: {error}"))?;
        let received = (|| -> Result<(), String> {
            same(&parent_handle, parent)?; same(&stage_parent, &stage_dir)?;
            let mut displaced = open_checked(&staged, false)?;
            let displaced_metadata = displaced.metadata().map_err(|e| e.to_string())?;
            if displaced_metadata.dev() != original_metadata.dev() || displaced_metadata.ino() != original_metadata.ino()
                || displaced_metadata.mode() != original_metadata.mode() || displaced_metadata.uid() != original_metadata.uid()
                || displaced_metadata.gid() != original_metadata.gid() || displaced_metadata.size() != original_metadata.size()
                || displaced_metadata.mtime() != original_metadata.mtime() || displaced_metadata.mtime_nsec() != original_metadata.mtime_nsec()
                || read_all(&mut displaced)? != preimage {
                return Err(format!("конфликт обновления; вытесненный файл сохранён: {}", staged.display()));
            }
            let mut published = open_checked(bin_path, false)?;
            let signed_metadata = signed.metadata().map_err(|e| e.to_string())?;
            let published_metadata = published.metadata().map_err(|e| e.to_string())?;
            if signed_metadata.dev() != published_metadata.dev() || signed_metadata.ino() != published_metadata.ino() {
                return Err("опубликованное поколение изменилось".into());
            }
            if read_all(&mut published)? != signed_bytes { return Err("опубликованные данные отличаются".into()); }
            native(Command::new("/usr/bin/codesign").args(["--verify", "--strict"]).arg(bin_path), "published verify")?;
            same(&published, bin_path)?; same(&parent_handle, parent)?;
            if read_all(&mut published)? != signed_bytes { return Err("опубликованные данные изменились после проверки".into()); }
            same(&displaced, &staged)?;
            if read_all(&mut displaced)? != preimage { return Err("вытесненный исходный файл изменился".into()); }
            same(&backup, &backup_path)?;
            fs::remove_file(&staged).map_err(|e| format!("сохранён исходный файл: {e}"))?;
            fs::remove_file(&backup_path).map_err(|e| format!("сохранена копия исходных данных: {e}"))?;
            Ok(())
        })();
        if let Err(error) = received {
            let identity = |path: &Path| match fs::symlink_metadata(path) {
                Ok(meta) => format!("dev={} inode={} size={}", meta.dev(), meta.ino(), meta.size()),
                Err(error) => format!("недоступно: {error}"),
            };
            return Err(format!("TARGET_CHANGED: проверка после обмена не завершена: {error}; исходный dev={} inode={}; текущий {} [{}]; вытесненный {} [{}]; копия исходных данных {} [{}]",
                original_metadata.dev(), original_metadata.ino(), bin_path.display(), identity(bin_path),
                staged.display(), identity(&staged), backup_path.display(), identity(&backup_path)));
        }
        same(&stage_parent, &stage_dir).map_err(|e| format!("TARGET_CHANGED: staging cleanup: {e}"))?;
        fs::remove_dir(&stage_dir).map_err(|e| format!("TARGET_CHANGED: staging cleanup: {e}"))?;
        Ok(())
    })();
    operation.map_err(|e| MacWriteError::Other(if e.starts_with("TARGET_CHANGED:") { e } else { format!("Файл не заменён; staging сохранён {}: {e}", stage_dir.display()) }))
}

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
pub fn kill_holder(bin_path: &Path) {
    let name = bin_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    if !name.is_empty() {
        Command::new("pkill")
            .args(["-f", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok();
    }
}

/// Where a patched copy of `target` is written before it is renamed over it.
pub(crate) fn temp_path(target: &Path) -> PathBuf {
    let mut tmp = target.as_os_str().to_os_string();
    tmp.push(format!(".{}{}", std::process::id(), TEMP_SUFFIX));
    PathBuf::from(tmp)
}

/// The tail every patch temp carries, so a directory scan can tell one from the
/// file it is a copy of.
pub(crate) const TEMP_SUFFIX: &str = ".agtmp";

/// Removes the patch temps a writer killed mid-write left beside `target` -
/// `<target>.<pid>.agtmp`, and the single `<target>.agtmp` builds before D27
/// used. A shared name was overwritten by the next write; one per process is
/// not, and the relay is `taskkill`ed on every upgrade, possibly mid-patch.
///
/// Only temps older than any write takes: a younger one may be another
/// patcher's, being written this second.
pub(crate) fn sweep_stale_temps(target: &Path) {
    const STALE: Duration = Duration::from_secs(10 * 60);
    let (Some(dir), Some(name)) = (target.parent(), target.file_name().and_then(|n| n.to_str()))
    else {
        return;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let prefix = format!("{}.", name);
    for entry in entries.flatten() {
        let file = entry.file_name();
        let Some(file) = file.to_str() else { continue };
        if !(file.starts_with(&prefix) && file.ends_with(TEMP_SUFFIX)) {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > STALE);
        if stale {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Temp-on-same-dir + rename. The temp sits beside the target so the rename is a
/// same-volume move (atomic), not a cross-volume copy.
///
/// The temp is named per process. Up to three patchers can meet on one file -
/// the relay's watchdog thread, the standalone watchdog task and the window's
/// auto-patch (D27) - and with one shared name a second writer truncating the
/// temp while the first renamed it over the target could leave a torn 150 MB
/// binary in place. Separate temps make every rename a whole file.
fn write_atomic(bin_path: &Path, data: &[u8]) -> std::io::Result<()> {
    sweep_stale_temps(bin_path);
    let tmp = temp_path(bin_path);
    if let Err(e) = fs::write(&tmp, data) {
        // A full disk leaves a partial 150 MB copy; nothing else would remove it.
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // On Unix a fresh temp file is created 0644, and renaming it over the language
    // server would strip the execute bit - a non-executable binary the app then
    // cannot launch. Copy the original's mode onto the temp before the rename so
    // the patched file stays exactly as runnable as the one it replaces. No-op on
    // Windows, where executability is not a file-mode bit.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(bin_path)
            .map(|m| m.permissions().mode())
            .unwrap_or(0o755);
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
    }
    match fs::rename(&tmp, bin_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

enum RewriteFailure { MissingSignature, Io(String) }
impl std::fmt::Display for RewriteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::MissingSignature => f.write_str("Сигнатура не найдена"), Self::Io(error) => f.write_str(error) }
    }
}

fn rewrite(bin_path: &Path, from: &[u8], to: &[u8], #[cfg(target_os = "macos")] install: Option<&Path>) -> Result<usize, String> {
    rewrite_result(bin_path, from, to, #[cfg(target_os = "macos")] install).map_err(|error| error.to_string())
}

fn rewrite_result(bin_path: &Path, from: &[u8], to: &[u8], #[cfg(target_os = "macos")] install: Option<&Path>) -> Result<usize, RewriteFailure> {
    #[cfg(not(target_os = "macos"))]
    let mut data = fs::read(bin_path).map_err(|e| RewriteFailure::Io(e.to_string()))?;
    #[cfg(target_os = "macos")]
    let install = install.ok_or_else(|| RewriteFailure::Io("не выбрана установка цели".into()))?;
    #[cfg(target_os = "macos")]
    let scope = mac_target_scope(install, bin_path).map_err(RewriteFailure::Io)?;
    #[cfg(target_os = "macos")]
    let (mut original, mut data) = read_mac_preimage(bin_path).map_err(RewriteFailure::Io)?;
    #[cfg(target_os = "macos")]
    let preimage = data.clone();
    let replaced = replace_all(&mut data, from, to);
    if replaced == 0 {
        // Nothing to do - report whether the target state is already in place.
        return if count_occurrences(&data, to) > 0 {
            Ok(0)
        } else {
            Err(RewriteFailure::MissingSignature)
        };
    }
    write_binary(bin_path, &data, #[cfg(target_os = "macos")] &preimage,
        #[cfg(target_os = "macos")] &mut original, #[cfg(target_os = "macos")] install,
        #[cfg(target_os = "macos")] &scope).map_err(|error| RewriteFailure::Io(error.to_string()))?;
    Ok(replaced)
}

pub fn patch_binary(_inst: &Path, bin_path: &Path) -> Result<usize, String> {
    let (old_bytes, new_bytes) = field_signatures();
    rewrite(bin_path, &old_bytes, &new_bytes, #[cfg(target_os = "macos")] Some(_inst))
}

pub fn unpatch_binary(bin_path: &Path) -> Result<usize, String> {
    let (old_bytes, new_bytes) = field_signatures();
    rewrite(bin_path, &new_bytes, &old_bytes, #[cfg(target_os = "macos")] None)
}

/// The name the patched language server reads its proxy URL from, in place of
/// the standard lower-case `https_proxy`.
///
/// **Why this exists.** The local gate proxy is only useful if the language
/// server points at it, and the only channel a Go program offers is a proxy
/// variable in its environment. Nothing spawns the server for us - the IDE and
/// the Desktop shell do - so up to `2.11.0_4` the tool wrote `HTTPS_PROXY` into
/// the *user* environment, and every program on the machine that honours it
/// went through `127.0.0.1:53129` as well: shells, git, npm, package managers.
/// That breadth is what D14 accepted as a cost and what the owner rejected on
/// 2026-09-07 ("мешает в системе"). It is also what made a dead listener a
/// machine-wide outage (G20, G31) rather than an Antigravity one.
///
/// **Why a rename is the whole fix.** `golang.org/x/net/http/httpproxy` reads
/// `getEnvAny("HTTPS_PROXY", "https_proxy")` - two literals, both present in the
/// binary, and the language server carries a second copy of the pair in its own
/// code. Renaming the **lower-case** one hands this tool a channel that nothing
/// else on the machine reads. Windows environment lookups are case-insensitive
/// (`GetEnvironmentVariable`), so the upper-case literal still answers for either
/// spelling and a user's own `HTTPS_PROXY` keeps working untouched.
///
/// **Measured, not assumed** (`tools/proxyvar_probe.py`, 2026-09-07, LS 1.11.0).
/// The server logs the proxy it dialled per request, so all five runs are read
/// off `cloudcode-pa.googleapis.com` itself rather than off whichever telemetry
/// client happened to fire first:
///
/// | binary  | variables set              | gate host went via |
/// |---------|----------------------------|--------------------|
/// | stock   | `HTTPS_PROXY`              | that proxy         |
/// | stock   | `AG_LS_PROXY`              | direct - inert     |
/// | patched | `AG_LS_PROXY`              | **ours**           |
/// | patched | `HTTPS_PROXY`              | theirs - unbroken  |
/// | patched | both                       | **ours**           |
///
/// The last row corrects the reasoning this was built on. The order in
/// `getEnvAny` suggested `HTTPS_PROXY` would win when both are set; it does not,
/// because the copy that actually resolves the gate client's proxy consults the
/// lower-case name first. So the rename does not merely add a channel, it takes
/// **precedence** over a proxy the user set. That makes `foreign_proxy` load
/// bearing rather than cosmetic: `reconcile_gate_proxy` and `ensure_proxy_env`
/// must remove ours whenever one of theirs appears, and both do.
///
/// On Linux, where the environment is case-sensitive, a user who sets *only* the
/// lower-case `https_proxy` loses it inside the language server. That is the one
/// accepted regression.
///
/// Same length as the name it replaces, so this is the same class of edit as the
/// eligibility rename: no relocation moves, no size change, byte-exact revert.
pub use crate::binary_profile::PROXY_VAR_NEW;

/// Points the language server's proxy lookup at [`PROXY_VAR_NEW`].
///
/// Additive, so unlike `patch_binary` a miss is not fatal - `Ok(0)` when the
/// binary is already renamed, `Err` only when neither name is present, which
/// callers report rather than treat as a failed patch.
pub fn patch_proxy_var(bin_path: &Path) -> Result<usize, String> {
    patch_proxy_var_result(bin_path, #[cfg(target_os = "macos")] None).map_err(|error| error.to_string())
}
fn patch_proxy_var_result(bin_path: &Path, #[cfg(target_os = "macos")] install: Option<&Path>) -> Result<usize, RewriteFailure> {
    let old_bytes = proxy_var_original();
    rewrite_result(bin_path, &old_bytes, PROXY_VAR_NEW.as_bytes(), #[cfg(target_os = "macos")] install)
}

/// Puts the standard name back.
pub fn unpatch_proxy_var(bin_path: &Path) -> Result<usize, String> {
    let old_bytes = proxy_var_original();
    rewrite(bin_path, PROXY_VAR_NEW.as_bytes(), &old_bytes, #[cfg(target_os = "macos")] None)
}

/// What re-patching one binary found. The background watchdog needs to tell
/// these four apart where menu 1 only needs success/failure:
///
/// - `SignatureMissing` is deliberately distinct from `Failed`. A signature
///   that is simply gone means a new or broken build this patcher does not
///   understand, and the right thing is to **leave it alone** so Antigravity
///   launches and shows its own error - that is the user's cue to fetch a newer
///   patcher. A `Failed` is transient (the file was locked mid-update) and is
///   worth retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepatchOutcome {
    /// Already patched; nothing was done.
    AlreadyPatched,
    /// Was reverted (typically by an app auto-update) and is now patched again.
    Repatched(usize),
    /// The signature is absent - do not touch it, let the app show its error.
    SignatureMissing,
    /// A direct native write permission denial, held for this worker lifetime.
    PermissionDenied(NativePermissionDenied),
    /// A transient failure, usually a file locked mid-update. Retry later.
    Failed(String),
}

#[cfg(target_os = "macos")]
fn mac_repatch_error(error: MacWriteError) -> RepatchOutcome {
    match error {
        MacWriteError::PermissionDenied(error) => RepatchOutcome::PermissionDenied(error),
        MacWriteError::Other(error) => RepatchOutcome::Failed(error),
    }
}

/// Re-applies the rename to a binary that may have been reverted by an update.
///
/// Unlike `patch_binary`, this never conflates "nothing to patch because the
/// signature is gone" with "already patched": that distinction is the whole
/// point of the watchdog. Platform-specific write and process policies remain
/// with the selected writer.
pub fn repatch_if_needed(bin_path: &Path) -> RepatchOutcome {
    repatch_with_install(bin_path, #[cfg(target_os = "macos")] None)
}

#[cfg(target_os = "macos")]
pub(crate) fn repatch_for_install(install: &Path, bin_path: &Path) -> RepatchOutcome {
    repatch_with_install(bin_path, Some(install))
}

fn repatch_with_install(bin_path: &Path, #[cfg(target_os = "macos")] install: Option<&Path>) -> RepatchOutcome {
    let (from, to) = field_signatures();
    let proxy_from = proxy_var_original();
    #[cfg(not(target_os = "macos"))]
    let mut data = match fs::read(bin_path) {
        Ok(d) => d,
        Err(e) => return RepatchOutcome::Failed(e.to_string()),
    };
    #[cfg(target_os = "macos")]
    let install = match install { Some(install) => install, None => return RepatchOutcome::Failed("не выбрана установка цели".into()) };
    #[cfg(target_os = "macos")]
    let scope = match mac_target_scope(install, bin_path) { Ok(scope) => scope, Err(error) => return RepatchOutcome::Failed(error) };
    #[cfg(target_os = "macos")]
    let (mut original, mut data) = match read_mac_preimage(bin_path) {
        Ok(received) => received,
        Err(error) => return RepatchOutcome::Failed(error),
    };
    #[cfg(target_os = "macos")]
    let preimage = data.clone();
    let replaced = replace_all(&mut data, &from, &to);
    // Both renames ride in one read and one write. An update restores both at
    // once, and a machine upgrading from a build that only knew the first one
    // gets the second here without a second pass over 150 MB.
    let proxy = replace_all(&mut data, &proxy_from, PROXY_VAR_NEW.as_bytes());
    if replaced == 0 {
        if count_occurrences(&data, &to) == 0 {
            return RepatchOutcome::SignatureMissing;
        }
        // The patch is in place; only the proxy channel was missing. Write for
        // that alone, but report what the watchdog cares about: nothing about
        // the unlock itself changed.
        //
        // This additive change must not trigger the non-Mac retry that may
        // terminate a holder. Mac uses its preserving writer for both edits.
        if proxy > 0 {
            #[cfg(not(target_os = "macos"))]
            {
            #[cfg(windows)]
            let canonical_guard = match crate::windows_coordinator::windows_installation::admit_native_binary(bin_path,
                binary_targets, crate::windows_coordinator::receive_saved_context) {
                Ok(guard) => guard,
                Err(error) => return RepatchOutcome::Failed(error),
            };
            if let Err(error) = write_atomic(bin_path, &data) {
                return RepatchOutcome::Failed(format!("Добавочное изменение не записано: {error}"));
            }
            #[cfg(windows)]
            if let Err(error) = canonical_guard.recheck() { return RepatchOutcome::Failed(error); }
            }
            #[cfg(target_os = "macos")]
            if let Err(error) = write_binary(bin_path, &data, &preimage, &mut original, install, &scope) {
                return mac_repatch_error(error);
            }
        }
        return RepatchOutcome::AlreadyPatched;
    }
    match write_binary(bin_path, &data, #[cfg(target_os = "macos")] &preimage,
        #[cfg(target_os = "macos")] &mut original, #[cfg(target_os = "macos")] install,
        #[cfg(target_os = "macos")] &scope) {
        Ok(()) => RepatchOutcome::Repatched(replaced),
        #[cfg(target_os = "macos")]
        Err(e) => mac_repatch_error(e),
        #[cfg(not(target_os = "macos"))]
        Err(e) => RepatchOutcome::Failed(e),
    }
}

/// Native binaries that carry the eligibility check, for a given install root.
///
/// The list is cross-platform on purpose: a Windows install never has the Linux
/// names and vice versa, and everything is filtered by `exists()`, so one list
/// serves both. On Linux the language-server filename carries a
/// `_linux_x64`-style platform suffix that can drift between builds, so instead
/// of hardcoding it the two `bin` directories are globbed for any
/// `language_server*` file - whatever the exact suffix, the signature scan then
/// decides whether it is really a target.
fn cli_target_candidates(inst: &Path) -> Vec<PathBuf> {
    vec![inst.join("agy.exe"), inst.join("agy"), inst.join("bin").join("agy")]
}

fn extension_cli_targets(inst: &Path) -> Vec<PathBuf> {
    if !inst.join("resources").join("app").join("extensions").join("agy").is_dir() { return Vec::new(); }
    extension_cli_candidates()
}

fn extension_cli_candidates() -> Vec<PathBuf> {
    std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from).map(|home| {
            let bin = home.join(".gemini").join("bin");
            ["agy.exe", "agy"].into_iter().map(|name| bin.join(name)).collect()
        }).unwrap_or_default()
}

fn binary_target_candidates(inst: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let resources_bin = inst.join("resources").join("bin");
    let ext_bin = inst
        .join("resources")
        .join("app")
        .join("extensions")
        .join("antigravity")
        .join("bin");

    // macOS .app bundle locations
    let mac_resources_bin = inst.join("Contents").join("Resources").join("bin");
    let mac_ext_bin = inst
        .join("Contents")
        .join("Resources")
        .join("app")
        .join("extensions")
        .join("antigravity")
        .join("bin");
    let mac_macos_bin = inst.join("Contents").join("MacOS");

    let mut targets = cli_target_candidates(inst);
    targets.extend([
        // Desktop's own language server.
        resources_bin.join("language_server.exe"),
        resources_bin.join("language_server"),
        mac_resources_bin.join("language_server"),
        mac_resources_bin.join("language_server_macos_arm"),
        mac_resources_bin.join("language_server_macos_x64"),
        // IDE's bundled language server, Windows & macOS named.
        ext_bin.join("language_server_windows_x64.exe"),
        ext_bin.join("language_server.exe"),
        ext_bin.join("language_server_macos_arm"),
        ext_bin.join("language_server_macos_x64"),
        mac_ext_bin.join("language_server_macos_arm"),
        mac_ext_bin.join("language_server_macos_x64"),
        mac_ext_bin.join("language_server"),
        mac_macos_bin.join("language_server"),
        mac_macos_bin.join("language_server_macos_arm"),
    ]);

    (targets, vec![ext_bin, resources_bin, mac_ext_bin, mac_resources_bin, mac_macos_bin])
}

fn is_language_server_candidate(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|value| value.starts_with("language_server") && !value.ends_with(TEMP_SUFFIX))
}

pub fn binary_targets(inst: &Path) -> Vec<PathBuf> {
    let (mut targets, dirs) = binary_target_candidates(inst);
    // Any other `language_server*` in candidate bin dirs - catches the Linux/macOS
    // platform-suffixed names (`language_server_linux_x64`, `language_server_macos_arm`, …)
    // without pinning the exact spelling.
    for dir in &dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                // Never a patch temp: `language_server_linux_x64.<pid>.agtmp`
                // matches the prefix for the second or so it exists.
                let is_ls = path.file_name().is_some_and(is_language_server_candidate);
                if is_ls && path.is_file() && !targets.contains(&path) {
                    targets.push(path);
                }
            }
        }
    }

    // IDE 2.6.0 carries no language server of its own: its `agy` extension
    // downloads the backend into the user's `~/.gemini/bin`. That file is the
    // IDE's, so the IDE's row reads and patches it (G85).
    for p in extension_cli_targets(inst) {
        if !targets.contains(&p) { targets.push(p); }
    }

    targets.retain(|p| p.exists());

    // On Unix a CLI like `agy` is frequently a symlink in a PATH dir pointing at
    // the real binary; resolve it so the patch edits the actual file, and dedup by
    // the resolved path so the same file reached two ways is not patched twice.
    #[cfg(unix)]
    {
        let mut seen = std::collections::HashSet::new();
        targets = targets
            .into_iter()
            .map(|p| fs::canonicalize(&p).unwrap_or(p))
            .filter(|p| seen.insert(p.clone()))
            .collect();
    }

    targets.dedup();
    targets
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MacFileStamp {
    pub size: u64,
    pub modified: std::time::SystemTime,
    pub identity: (u64, u64),
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u64,
    pub changed: (i64, i64),
}

#[cfg(target_os = "macos")]
pub(crate) fn mac_file_stamp(path: &Path) -> Result<MacFileStamp, String> {
    use std::os::unix::fs::MetadataExt;
    let info = fs::symlink_metadata(path).map_err(|error| format!("метаданные {}: {error}", path.display()))?;
    Ok(MacFileStamp { size: info.size(), modified: info.modified().map_err(|error| error.to_string())?,
        identity: (info.dev(), info.ino()), mode: info.mode(), uid: info.uid(), gid: info.gid(),
        links: info.nlink(), changed: (info.ctime(), info.ctime_nsec()) })
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacTargetSnapshot {
    root: ((u64, u64), u32, u32, u32),
    pub targets: Vec<(PathBuf, MacFileStamp)>,
}

#[cfg(target_os = "macos")]
pub(crate) fn mac_confirm_absent(path: &Path, error: std::io::Error) -> Result<(), String> {
    if !matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) {
        return Err(format!("проверка {}: {error}", path.display()));
    }
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(info) if info.file_type().is_symlink() => return Err(format!("неразрешимая ссылка {}", candidate.display())),
            Ok(_) if candidate == path => return Err(format!("неразрешимый путь {}: {error}", path.display())),
            Ok(_) => return Ok(()),
            Err(absent) if matches!(absent.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => current = candidate.parent(),
            Err(other) => return Err(format!("проверка {}: {other}", candidate.display())),
        }
    }
    Err(format!("не подтверждено отсутствие {}", path.display()))
}

#[cfg(target_os = "macos")]
pub(crate) fn mac_target_snapshot(inst: &Path) -> Result<MacTargetSnapshot, String> {
    let root = mac_file_stamp(inst)?;
    if root.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR) { return Err("корень установки не является каталогом".into()); }
    let (mut candidates, dirs) = binary_target_candidates(inst);
    for dir in dirs {
        match fs::read_dir(&dir) {
            Ok(entries) => for entry in entries {
                let entry = entry.map_err(|error| format!("чтение {}: {error}", dir.display()))?;
                let path = entry.path();
                if is_language_server_candidate(&entry.file_name()) {
                    let metadata = fs::metadata(&path).map_err(|error| format!("метаданные {}: {error}", path.display()))?;
                    if metadata.is_file() && !candidates.contains(&path) { candidates.push(path); }
                }
            },
            Err(error) => mac_confirm_absent(&dir, error)?,
        }
    }
    let extension = inst.join("resources").join("app").join("extensions").join("agy");
    match fs::metadata(&extension) {
        Ok(info) if info.is_dir() => for path in extension_cli_candidates() {
            if !candidates.contains(&path) { candidates.push(path); }
        },
        Ok(_) => {},
        Err(error) => mac_confirm_absent(&extension, error)?,
    }
    let mut targets = Vec::new();
    for path in candidates {
        match fs::metadata(&path) {
            Ok(_) => {
                let path = fs::canonicalize(&path).map_err(|error| format!("путь {}: {error}", path.display()))?;
                let stamp = mac_file_stamp(&path)?;
                if stamp.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG) || stamp.links != 1 {
                    return Err(format!("неоднозначный файл {}", path.display()));
                }
                mac_check_no_stage(&path)?;
                targets.push((path, stamp));
            },
            Err(error) => mac_confirm_absent(&path, error)?,
        }
    }
    targets.sort_by(|a, b| a.0.cmp(&b.0));
    if targets.windows(2).any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1) {
        return Err("файл изменился при перечислении целей".into());
    }
    targets.dedup_by(|a, b| a.0 == b.0);
    let after = mac_file_stamp(inst)?;
    if (root.identity, root.mode, root.uid, root.gid) != (after.identity, after.mode, after.uid, after.gid) {
        return Err("корень установки изменился".into());
    }
    Ok(MacTargetSnapshot { root: (root.identity, root.mode, root.uid, root.gid), targets })
}

/// Closes Antigravity before a patch run.
///
/// Silent: the only caller left is the window's worker thread, which has no
/// console to print to and reports the step in the log pane itself. The one
/// second afterwards is functional, not cosmetic — `taskkill` returns before the
/// image handle is actually released.
#[cfg(all(not(windows), not(target_os = "macos")))]
pub fn kill_affected_processes() {
    kill_platform_processes();
    thread::sleep(Duration::from_millis(1000));
}

/// The Linux/macOS side. The language server is the process holding the file
/// open; it is matched by the binary's basename via `pkill -f` so whatever the
/// platform suffix is (`language_server_linux_x64`), it is caught. The `agy` CLI
/// and the two language-server basenames are killed; the editor shell is left
/// running, same rule as Windows.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn kill_platform_processes() {
    // -f matches against the whole command line, so a full install path still
    // matches; the patterns are the binary basenames the patcher targets.
    let patterns = ["language_server", "/agy"];
    for pat in patterns.iter() {
        Command::new("pkill")
            .args(["-f", pat])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok();
    }
}

/// Outcome of patching the native binaries of one install.
pub struct BinarySummary {
    /// Binaries that are now in the patched state (freshly patched or already so).
    pub ok: usize,
    /// Binaries where the signature could not be found or written.
    pub failed: usize,
    /// The last failure, so the caller can name it without this module printing.
    pub last_error: Option<String>,
    /// Binaries that now read the private proxy variable ([`PROXY_VAR_NEW`]).
    ///
    /// Tracked separately because it is the precondition for writing that
    /// variable at all: a build whose proxy literal this patcher does not
    /// recognise would otherwise get a variable no process ever reads, and the
    /// local-proxy route would be silently dead rather than reported.
    pub proxy_var: usize,
    /// True when a proxy-var rename failed for a reason that is **not** "the
    /// literal is not in this build".
    ///
    /// The two need telling apart because they need opposite advice. A missing
    /// literal means a new Antigravity this patcher does not understand: the
    /// user needs a newer unlocker. A locked file - antivirus holding
    /// `language_server.exe`, a denied write - means "close Antigravity and run
    /// it again". Reporting the second as the first sends the user looking for
    /// an update that does not exist.
    pub proxy_var_retryable: bool,
}

impl BinarySummary {
    pub fn total(&self) -> usize {
        self.ok + self.failed
    }
}

pub fn patch_all_binaries(inst: &Path) -> BinarySummary {
    patch_binary_batch(inst, false)
}

pub(crate) fn patch_all_binaries_checked(inst: &Path) -> Result<BinarySummary, String> {
    let summary = patch_binary_batch(inst, true);
    if summary.failed > 0 || summary.proxy_var_retryable {
        return Err(format!("Нативный пакет остановлен: успешно/без изменений {}, ошибки {}, канал прокси {}; {}",
            summary.ok, summary.failed, summary.proxy_var, summary.last_error.as_deref().unwrap_or("причина не получена")));
    }
    Ok(summary)
}

fn patch_binary_batch(inst: &Path, stop_on_failure: bool) -> BinarySummary {
    let mut summary = BinarySummary {
        ok: 0,
        failed: 0,
        last_error: None,
        proxy_var: 0,
        proxy_var_retryable: false,
    };
    for bin in binary_targets(inst) {
        let label = bin
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // Deliberately silent. The caller prints one progress line per install
        // and then its result on the same row; a line from here lands in the
        // middle of it and pushes the result onto its own. Failures are not
        // lost - they are counted here and named by `binary_failure_message`.
        match patch_binary(inst, &bin) {
            Ok(_) => summary.ok += 1,
            Err(e) => {
                summary.failed += 1;
                summary.last_error = Some(format!("{}: {}", label, e));
                if stop_on_failure { return summary; }
            }
        }
        // Additive and separately judged: a binary whose proxy literal is not
        // where this build expects it is still unlocked, so it never touches
        // `failed`. `Ok(0)` is "already renamed", which counts as carrying it.
        match patch_proxy_var_result(&bin, #[cfg(target_os = "macos")] Some(inst)) {
            Ok(_) => summary.proxy_var += 1,
            // `rewrite` says "Сигнатура не найдена" for a literal that is not
            // there and anything else for an I/O problem. Only the second is
            // worth telling the user to retry.
            Err(RewriteFailure::Io(error)) => {
                summary.proxy_var_retryable = true;
                summary.last_error = Some(format!("{label}: {error}"));
                if stop_on_failure { return summary; }
            },
            Err(RewriteFailure::MissingSignature) => {}
        }
    }
    summary
}

/// What a read-only look at one install found. Nothing here writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    /// The patched name is present - this file is done.
    Patched,
    /// The original name is present and the patched one is not.
    Unpatched,
    /// Neither name is there: a build we do not know how to patch.
    SignatureMissing,
    /// Could not be read at all (missing file, permissions).
    Unreadable(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallState {
    pub files: Vec<(std::path::PathBuf, FileState)>,
}

#[allow(dead_code)]
impl InstallState {
    /// True only when every native binary we know about is patched.
    pub fn fully_patched(&self) -> bool {
        !self.files.is_empty()
            && self
                .files
                .iter()
                .all(|(_, state)| *state == FileState::Patched)
    }

    /// True when some are patched and some are not - what an interrupted run
    /// or a half-finished auto-update leaves behind.
    pub fn partially_patched(&self) -> bool {
        let has_patched = self
            .files
            .iter()
            .any(|(_, state)| *state == FileState::Patched);
        let has_not_patched = self
            .files
            .iter()
            .any(|(_, state)| *state != FileState::Patched);
        has_patched && has_not_patched
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

const INSPECT_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB stream buffer

fn contains_subslice(data: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if data.len() < needle.len() {
        return false;
    }
    // First-byte skip rather than `windows(k).any(..)`. The Language Server is
    // ~150 MB and this runs over the whole of it twice per install, so the naive
    // form costs a comparison per byte per needle; anchoring on the first byte
    // turns almost all of them into one.
    let first = needle[0];
    let last = data.len() - needle.len();
    let mut i = 0;
    while i <= last {
        match data[i..=last].iter().position(|b| *b == first) {
            Some(off) => {
                let at = i + off;
                if &data[at..at + needle.len()] == needle {
                    return true;
                }
                i = at + 1;
            }
            None => return false,
        }
    }
    false
}

/// Inspects one binary file on disk in a streaming manner using a 1 MiB buffer
/// with overlap to prevent missing matches at buffer boundaries.
#[allow(dead_code)]
pub fn inspect_file(bin_path: &Path) -> FileState {
    inspect_file_stream(bin_path, INSPECT_CHUNK_SIZE)
}

fn inspect_file_stream(bin_path: &Path, chunk_size: usize) -> FileState {
    let (unpatched, patched) = field_signatures();
    let max_needle = unpatched.len().max(patched.len());
    let overlap_len = max_needle.saturating_sub(1);

    let mut file = match fs::File::open(bin_path) {
        Ok(f) => f,
        Err(e) => return FileState::Unreadable(e.to_string()),
    };

    use std::io::Read;
    let mut buf = vec![0u8; chunk_size.max(max_needle)];
    let mut overlap = 0;
    let mut found_unpatched = false;

    loop {
        let mut bytes_read = 0;
        while overlap + bytes_read < buf.len() {
            match file.read(&mut buf[overlap + bytes_read..]) {
                Ok(0) => break,
                Ok(n) => bytes_read += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return FileState::Unreadable(e.to_string()),
            }
        }

        if bytes_read == 0 {
            break;
        }

        let valid_len = overlap + bytes_read;
        let slice = &buf[..valid_len];
        if contains_subslice(slice, &patched) {
            return FileState::Patched;
        }
        if !found_unpatched && contains_subslice(slice, &unpatched) {
            found_unpatched = true;
        }

        if overlap + bytes_read < buf.len() {
            break;
        }

        overlap = overlap_len.min(valid_len);
        buf.copy_within(valid_len - overlap..valid_len, 0);
    }

    if found_unpatched {
        FileState::Unpatched
    } else {
        FileState::SignatureMissing
    }
}

/// Reads every native binary of one install and reports whether each carries the
/// patched name. Read-only: opens files for reading, writes nothing, spawns no
/// child process, kills no process.
#[allow(dead_code)]
pub fn inspect_install(install: &std::path::Path) -> InstallState {
    let targets = binary_targets(install);
    let mut files = Vec::with_capacity(targets.len());
    for target in targets {
        let state = inspect_file(&target);
        files.push((target, state));
    }
    InstallState { files }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_snapshot_tracks_replacement_target_set_root_and_unresolved_stage() {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let base = parent.join(format!("ag-mac-snapshot-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let root = base.join("cli"); fs::create_dir(&root).unwrap();
        let target = root.join("agy"); fs::write(&target, b"ineligible").unwrap();
        let initial = mac_target_snapshot(&root).unwrap();
        assert_eq!(initial.targets.len(), 1);
        let replacement = base.join("replacement"); fs::write(&replacement, b"inexigible").unwrap();
        fs::rename(&replacement, &target).unwrap();
        let changed = mac_target_snapshot(&root).unwrap();
        assert_ne!(initial, changed);
        let stage = temp_path(&target); fs::create_dir(&stage).unwrap();
        assert!(mac_target_snapshot(&root).is_err());
        fs::remove_dir(&stage).unwrap();
        fs::remove_file(&target).unwrap();
        assert!(mac_target_snapshot(&root).unwrap().targets.is_empty());
        std::os::unix::fs::symlink(base.join("missing"), &target).unwrap();
        assert!(mac_target_snapshot(&root).is_err());
        fs::remove_file(&target).unwrap();
        let old = base.join("old-root"); fs::rename(&root, &old).unwrap(); fs::create_dir(&root).unwrap();
        assert_ne!(mac_target_snapshot(&root).unwrap().root, changed.root);
        fs::remove_dir(&root).unwrap(); fs::remove_dir(&old).unwrap(); fs::remove_dir(&base).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_stage_permission_is_native_typed_and_not_inferred_from_text() {
        for code in [libc::EPERM, libc::EACCES] {
            let error = std::io::Error::from_raw_os_error(code);
            let kind = error.kind();
            match mac_stage_creation_error(error) {
                MacWriteError::PermissionDenied(received) => {
                    assert_eq!(received.operation, "создание staging");
                    assert_eq!(received.kind, kind);
                    assert_eq!(received.raw_os_error, Some(code));
                },
                other => panic!("expected native permission denial: {other:?}"),
            }
        }
        assert!(matches!(mac_stage_creation_error(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            MacWriteError::PermissionDenied(NativePermissionDenied { raw_os_error: None, .. })));
        assert!(matches!(mac_stage_creation_error(std::io::Error::other("Permission denied")), MacWriteError::Other(_)));
    }

    #[cfg(target_os = "macos")]
    mod mac_writer_race {
        use super::*;
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::fs::MetadataExt;
        use std::process::{Child, Stdio};
        use std::sync::mpsc::{self, Receiver};
        use std::thread::JoinHandle;

        fn err(error: impl std::fmt::Display) -> String { error.to_string() }
        fn require(value: bool, message: &str) -> Result<(), String> {
            if value { Ok(()) } else { Err(message.into()) }
        }

        struct OwnedChild {
            child: Option<Child>,
            reader: Option<JoinHandle<Result<(), String>>>,
            lines: Receiver<Vec<u8>>,
            stdout_path: PathBuf,
            stderr: fs::File,
            status_file: fs::File,
        }

        impl OwnedChild {
            fn spawn(case: &Path, evidence: &Path, label: &str, phases: &str) -> Result<Self, String> {
                let stdout_path = evidence.join(format!("{label}.stdout"));
                let stdout_file = fs::OpenOptions::new().write(true).create_new(true).open(&stdout_path).map_err(err)?;
                let stderr = fs::OpenOptions::new().write(true).create_new(true).open(evidence.join(format!("{label}.stderr"))).map_err(err)?;
                let mut status_file = fs::OpenOptions::new().write(true).create_new(true).open(evidence.join(format!("{label}.status"))).map_err(err)?;
                let stderr_child = stderr.try_clone().map_err(err)?;
                let mut child = Command::new(std::env::current_exe().map_err(err)?)
                    .args(["--exact", "patch_binary::tests::mac_writer_race::child", "--ignored", "--nocapture"])
                    .env("AG_MAC_WRITER_TEST_CHILD", "1").env("AG_MAC_WRITER_TEST_ROOT", case)
                    .env("AG_MAC_WRITER_TEST_PHASES", phases)
                    .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::from(stderr_child))
                    .spawn().map_err(err)?;
                let stdout = match child.stdout.take() {
                    Some(stdout) => stdout,
                    None => {
                        drop(child.stdin.take());
                        let status = child.wait();
                        let capture = stderr.sync_all();
                        let record = writeln!(status_file, "{status:?}").and_then(|_| status_file.sync_all());
                        return Err(format!("child stdout missing; exit={status:?}; stderr={capture:?}; status record={record:?}"));
                    },
                };
                let (tx, lines) = mpsc::channel();
                let reader = std::thread::Builder::new().spawn(move || -> Result<(), String> {
                    let mut file = stdout_file;
                    let mut input = BufReader::new(stdout);
                    loop {
                        let mut line = Vec::new();
                        if input.read_until(b'\n', &mut line).map_err(err)? == 0 { break; }
                        file.write_all(&line).and_then(|_| file.flush()).and_then(|_| file.sync_data()).map_err(err)?;
                        let _ = tx.send(line);
                    }
                    file.sync_all().map_err(err)
                });
                let reader = match reader {
                    Ok(reader) => reader,
                    Err(error) => {
                        drop(child.stdin.take());
                        let status = child.wait();
                        let capture = stderr.sync_all();
                        let record = writeln!(status_file, "{status:?}").and_then(|_| status_file.sync_all());
                        return Err(format!("stdout capture start: {error}; exit={status:?}; stderr={capture:?}; status record={record:?}"));
                    },
                };
                Ok(Self { child: Some(child), reader: Some(reader), lines, stdout_path, stderr, status_file })
            }

            fn phase(&self, expected: &str) -> Result<(), String> {
                let expected = format!("AG_WRITER_PHASE {expected}\n");
                while let Ok(line) = self.lines.recv() {
                    if line == expected.as_bytes() { return Ok(()); }
                    if line.starts_with(b"AG_WRITER_PHASE ") { return Err("unexpected writer phase".into()); }
                }
                Err("child exited before requested writer phase".into())
            }

            fn release(&mut self) -> Result<(), String> {
                let stdin = self.child.as_mut().and_then(|child| child.stdin.as_mut()).ok_or("child stdin missing")?;
                stdin.write_all(b"CONTINUE\n").and_then(|_| stdin.flush()).map_err(err)
            }

            fn settle(&mut self) -> Result<(std::process::ExitStatus, String), String> {
                let mut child = self.child.take().ok_or("child already received")?;
                drop(child.stdin.take());
                let status = match child.wait() {
                    Ok(status) => status,
                    Err(error) => {
                        let record = writeln!(self.status_file, "wait error: {error}").and_then(|_| self.status_file.sync_all());
                        let stderr = self.stderr.sync_all();
                        self.child = Some(child);
                        return Err(format!("owned child wait: {error}; status record={record:?}; stderr={stderr:?}; stdout capture pending"));
                    },
                };
                let capture = match self.reader.take() {
                    Some(reader) => match reader.join() { Ok(result) => result, Err(_) => Err("stdout capture panicked".into()) },
                    None => Err("stdout capture missing".into()),
                };
                let stderr = self.stderr.sync_all().map_err(err);
                let status_record = writeln!(self.status_file, "{status:?}")
                    .and_then(|_| self.status_file.sync_all()).map_err(err);
                let output = fs::read_to_string(&self.stdout_path).map_err(err);
                match (capture, stderr, status_record, output) {
                    (Ok(()), Ok(()), Ok(()), Ok(output)) => Ok((status, output)),
                    (capture, stderr, record, output) => Err(format!("child receiving: status={status:?}; stdout={capture:?}; stderr={stderr:?}; status record={record:?}; readback={output:?}")),
                }
            }

            fn finish(mut self) -> Result<String, String> {
                let (status, output) = self.settle()?;
                require(status.success(), &format!("child exit {status}"))?;
                Ok(output)
            }
        }

        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if self.child.is_some() {
                    if let Err(error) = self.settle() { eprintln!("owned writer child settlement: {error}"); }
                }
            }
        }

        fn native(evidence: &Path, label: &str, command: &mut Command) -> Result<(), String> {
            let output = command.output().map_err(err)?;
            let persist = |suffix: &str, data: &[u8]| -> std::io::Result<()> {
                let mut file = fs::OpenOptions::new().write(true).create_new(true)
                    .open(evidence.join(format!("{label}.{suffix}")))?;
                file.write_all(data)?; file.sync_all()
            };
            let stdout = persist("stdout", &output.stdout);
            let stderr = persist("stderr", &output.stderr);
            let status = persist("status", format!("{}\n", output.status).as_bytes());
            if stdout.is_err() || stderr.is_err() || status.is_err() {
                return Err(format!("{label} capture: stdout={stdout:?}; stderr={stderr:?}; status={status:?}; exit={}", output.status));
            }
            require(output.status.success(), &format!("{label}: {}", output.status))
        }

        fn sign(evidence: &Path, label: &str, path: &Path) -> Result<(), String> {
            native(evidence, label, Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-", "--identifier", label]).arg(path))
        }

        fn setup(base: &Path, fixture: &Path, name: &str) -> Result<PathBuf, String> {
            let case = base.join(name);
            fs::create_dir(&case).map_err(err)?;
            fs::copy(fixture, case.join("agy")).map_err(err)?;
            sign(base, &format!("{name}-original"), &case.join("agy"))?;
            Ok(case)
        }

        #[test]
        #[ignore = "private child entry for mac_native_writer_races"]
        fn child() {
            if std::env::var_os("AG_MAC_WRITER_TEST_CHILD").is_none() { return; }
            let root = PathBuf::from(std::env::var_os("AG_MAC_WRITER_TEST_ROOT").expect("child fixture root"));
            let outcome = repatch_for_install(&root, &root.join("agy"));
            println!("AG_WRITER_RESULT {outcome:?}");
        }

        fn run() -> Result<(), String> {
            let root = fs::canonicalize(PathBuf::from(std::env::var_os("AG_R3_FIXTURE_ROOT").ok_or("AG_R3_FIXTURE_ROOT missing")?)).map_err(err)?;
            let fixture = root.join("agy");
            let evidence = root.join("r3-writer-race-owned");
            fs::create_dir(&evidence).map_err(err)?;

            // Writer B must not pass the original inode lock while A holds it.
            let first = setup(&evidence, &fixture, "lock")?;
            let before = fs::read(first.join("agy")).map_err(err)?;
            let mut a = OwnedChild::spawn(&first, &evidence, "lock-a", "ADMITTED")?;
            a.phase("ADMITTED")?;
            let b = OwnedChild::spawn(&first, &evidence, "lock-b", "")?.finish()?;
            require(b.contains("AG_WRITER_RESULT Failed") && b.contains("занят"), "lock contender did not defer")?;
            require(fs::read(first.join("agy")).map_err(err)? == before, "contender changed locked bytes")?;
            a.release()?;
            require(a.finish()?.contains("AG_WRITER_RESULT Repatched"), "first writer did not patch")?;
            native(&evidence, "lock-verify", Command::new("/usr/bin/codesign").args(["--verify", "--strict"]).arg(first.join("agy")))?;

            // A stale pre-opened handle may acquire its inode lock after A's swap,
            // but must fail the existing path/nlink check before reading or writing.
            let stale = setup(&evidence, &fixture, "stale")?;
            let mut b = OwnedChild::spawn(&stale, &evidence, "stale-b", "OPENED")?;
            b.phase("OPENED")?;
            require(OwnedChild::spawn(&stale, &evidence, "stale-a", "")?.finish()?.contains("AG_WRITER_RESULT Repatched"), "stale-case writer did not patch")?;
            let patched = fs::read(stale.join("agy")).map_err(err)?;
            b.release()?;
            let result = b.finish()?;
            require(result.contains("AG_WRITER_RESULT Failed") && result.contains("идентичность"), "stale handle was not rejected")?;
            require(fs::read(stale.join("agy")).map_err(err)? == patched, "stale contender changed target")?;

            // Prepare C through the real writer, then bind distinct signed B/C.
            let seed = setup(&evidence, &fixture, "c-seed")?;
            require(OwnedChild::spawn(&seed, &evidence, "c-seed-writer", "")?.finish()?.contains("AG_WRITER_RESULT Repatched"), "C seed did not patch")?;
            let conflict = setup(&evidence, &fixture, "conflict")?;
            let target = conflict.join("agy");
            let original = fs::read(&target).map_err(err)?;
            let b_path = conflict.join("updater-b");
            let c_path = conflict.join("updater-c");
            fs::copy(&fixture, &b_path).map_err(err)?; sign(&evidence, "updater-b", &b_path)?;
            fs::copy(seed.join("agy"), &c_path).map_err(err)?; sign(&evidence, "updater-c", &c_path)?;
            native(&evidence, "updater-b-verify", Command::new("/usr/bin/codesign").args(["--verify", "--strict"]).arg(&b_path))?;
            native(&evidence, "updater-c-verify", Command::new("/usr/bin/codesign").args(["--verify", "--strict"]).arg(&c_path))?;
            let b_bytes = fs::read(&b_path).map_err(err)?; let c_bytes = fs::read(&c_path).map_err(err)?;
            let b_info = fs::metadata(&b_path).map_err(err)?; let c_info = fs::metadata(&c_path).map_err(err)?;
            require((b_info.dev(), b_info.ino()) != (c_info.dev(), c_info.ino()), "B and C are not distinct inodes")?;
            let (stock, patched_marker) = field_signatures();
            require(count_occurrences(&c_bytes, &stock) == 0 && count_occurrences(&c_bytes, &patched_marker) > 0,
                "C is not patched-looking")?;
            let mut a = OwnedChild::spawn(&conflict, &evidence, "conflict-a", "PRE_SWAP,POST_SWAP")?;
            a.phase("PRE_SWAP")?;
            fs::rename(&b_path, &target).map_err(err)?;
            a.release()?; a.phase("POST_SWAP")?;
            fs::rename(&c_path, &target).map_err(err)?;
            a.release()?;
            let result = a.finish()?;
            require(result.contains("AG_WRITER_RESULT Failed") && result.contains("TARGET_CHANGED"), "conflict was not reported as partially changed")?;
            require(fs::read(&target).map_err(err)? == c_bytes, "recovery changed updater C")?;
            let received_c = fs::metadata(&target).map_err(err)?;
            require((received_c.dev(), received_c.ino()) == (c_info.dev(), c_info.ino()), "recovery displaced updater C")?;
            let mut stages = Vec::new();
            for entry in fs::read_dir(&conflict).map_err(err)? {
                let entry = entry.map_err(err)?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("agy.") && name.ends_with(TEMP_SUFFIX) { stages.push(entry.path()); }
            }
            require(stages.len() == 1, "expected one retained conflict stage")?;
            require(fs::read(stages[0].join("agy")).map_err(err)? == b_bytes, "displaced updater B not retained")?;
            let retained_b = fs::metadata(stages[0].join("agy")).map_err(err)?;
            require((retained_b.dev(), retained_b.ino()) == (b_info.dev(), b_info.ino()), "retained B identity changed")?;
            require(fs::read(stages[0].join(".ag-original")).map_err(err)? == original, "original preimage not retained")?;
            let retry = OwnedChild::spawn(&conflict, &evidence, "conflict-reentry", "")?.finish()?;
            require(retry.contains("AG_WRITER_RESULT Failed") && retry.contains("staging"), "retained conflict did not hold re-entry")?;
            require(fs::read(&target).map_err(err)? == c_bytes, "re-entry changed updater C")?;
            Ok(())
        }

        #[test]
        #[ignore = "requires private AG_R3_FIXTURE_ROOT with the owned compiled agy_fixture as agy"]
        fn mac_native_writer_races() {
            let result = run();
            if let Err(error) = result { panic!("writer race fixture: {error}"); }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_scope_is_bound_to_discovered_target_and_exact_process_image() {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let root = parent.join(format!("ag-mac-scopes-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let cli = root.join("cli"); let other = root.join("other");
        let app = root.join("Fixture.app"); let macos = app.join("Contents").join("MacOS");
        fs::create_dir(&cli).unwrap(); fs::create_dir(&other).unwrap(); fs::create_dir_all(&macos).unwrap();
        let selected = cli.join("agy"); let unrelated = other.join("agy");
        let unknown = cli.join("unknown");
        let server = macos.join("language_server");
        for path in [&selected, &unrelated, &unknown, &server] { fs::write(path, b"ineligible https_proxy").unwrap(); }
        assert_eq!(crate::resolve_install_root(&selected), Some(cli.clone()));
        let standalone = mac_target_scope(&cli, &selected).unwrap();
        assert_eq!(standalone, MacTargetScope::StandaloneExecutable(selected.clone()));
        assert!(mac_scope_contains_image(&standalone, &selected));
        assert!(!mac_scope_contains_image(&standalone, &unrelated));
        assert!(mac_target_scope(&cli, &unrelated).is_err());
        assert!(mac_target_scope(&cli, &unknown).is_err());
        let bundle = mac_target_scope(&app, &server).unwrap();
        assert_eq!(bundle, MacTargetScope::AppBundle(app.clone()));
        assert!(mac_scope_contains_image(&bundle, &macos.join("other-process")));
        assert!(!mac_scope_contains_image(&bundle, &selected));
        for path in [&selected, &unrelated, &unknown, &server] { fs::remove_file(path).unwrap(); }
        fs::remove_dir(&macos).unwrap(); fs::remove_dir(app.join("Contents")).unwrap(); fs::remove_dir(&app).unwrap();
        fs::remove_dir(&cli).unwrap(); fs::remove_dir(&other).unwrap(); fs::remove_dir(&root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires AG_R3_FIXTURE_ROOT with the owned compiled agy_fixture as agy"]
    fn mac_standalone_scope_distinguishes_live_exact_image() {
        use std::io::{BufRead, BufReader};
        use std::process::{Child, Stdio};
        struct OwnedChild(Option<Child>);
        impl OwnedChild {
            fn finish(mut self) {
                let mut child = self.0.take().unwrap();
                drop(child.stdin.take());
                assert!(child.wait().expect("reap owned fixture").success());
            }
        }
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    drop(child.stdin.take());
                    if let Err(error) = child.wait() { eprintln!("owned fixture reap failed: {error}"); }
                }
            }
        }
        fn start(path: &Path) -> OwnedChild {
            let child = Command::new(path).arg("--hold").stdin(Stdio::piped()).stdout(Stdio::piped())
                .spawn().expect("start owned fixture");
            let mut owned = OwnedChild(Some(child));
            let mut line = String::new();
            BufReader::new(owned.0.as_mut().unwrap().stdout.take().unwrap()).read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "READY");
            owned
        }
        let root = PathBuf::from(std::env::var_os("AG_R3_FIXTURE_ROOT").expect("fixture root"));
        let root = fs::canonicalize(root).unwrap();
        let target = root.join("agy");
        let scope = mac_target_scope(&root, &target).unwrap();
        assert_eq!(scope, MacTargetScope::StandaloneExecutable(target.clone()));
        mac_target_inactive(&scope).expect("inactive selected fixture");
        let other_dir = root.join("r3-other-owned");
        fs::create_dir(&other_dir).expect("vacant other fixture directory");
        let other = other_dir.join("agy");
        fs::copy(&target, &other).unwrap();
        let other_child = start(&other);
        mac_target_inactive(&scope).expect("different same-name fixture must not block");
        let selected_child = start(&target);
        assert!(mac_target_inactive(&scope).unwrap_err().contains("используется процессом"));
        selected_child.finish(); other_child.finish();
        mac_target_inactive(&scope).expect("fixtures exited normally");
        fs::remove_file(&other).unwrap(); fs::remove_dir(&other_dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_writer_rejects_changed_preimage_and_occupied_stage() {
        let parent = std::env::temp_dir().canonicalize().expect("ordinary temp parent");
        let dir = parent.join(format!("ag-mac-writer-{}", std::process::id()));
        fs::create_dir(&dir).expect("vacant owned test directory");
        let target = dir.join("agy");
        fs::write(&target, b"original").unwrap();
        let scope = mac_target_scope(&dir, &target).unwrap();
        let (mut original, before) = read_mac_preimage(&target).unwrap();
        fs::write(&target, b"changed!").unwrap();
        assert!(write_binary(&target, b"modified", &before, &mut original, &dir, &scope).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"changed!");
        assert!(!temp_path(&target).exists());
        drop(original);
        let (mut original, current) = read_mac_preimage(&target).unwrap();
        let occupied = temp_path(&target);
        fs::create_dir(&occupied).unwrap();
        assert!(write_binary(&target, b"modified", &current, &mut original, &dir, &scope).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"changed!");
        assert!(occupied.is_dir());
        drop(original);
        fs::remove_dir(&occupied).unwrap();
        fs::remove_file(&target).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn checked_native_io_failure_stops_before_the_next_binary() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = crate::wsl_discovery_contract_cases::fixture_dir("native-first-failure");
        let state = root.join("state");
        let install = root.join("install");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&install).unwrap();
        let previous = std::env::var_os("AG_LEGACY_NATIVE_GUARD_TEST_BASE");
        struct RestoreEnv(Option<std::ffi::OsString>);
        impl Drop for RestoreEnv {
            fn drop(&mut self) { unsafe { match &self.0 {
                Some(value) => std::env::set_var("AG_LEGACY_NATIVE_GUARD_TEST_BASE", value),
                None => std::env::remove_var("AG_LEGACY_NATIVE_GUARD_TEST_BASE"),
            } } }
        }
        unsafe { std::env::set_var("AG_LEGACY_NATIVE_GUARD_TEST_BASE", &state); }
        let _restore = RestoreEnv(previous);
        let first = install.join("agy.exe");
        let second = install.join("agy");
        let (original, _) = field_signatures();
        let mut bytes = original.to_vec();
        bytes.extend_from_slice(&proxy_var_original());
        fs::write(&first, &bytes).unwrap();
        fs::write(&second, &bytes).unwrap();
        let held = fs::OpenOptions::new().read(true).share_mode(1 | 2).open(&first).unwrap();
        let failure = patch_all_binaries_checked(&install).err().expect("actual sharing failure required");
        assert!(failure.contains("Файл не заменён"), "must reach the native write, not fail admission: {failure}");
        assert_eq!(fs::read(&first).unwrap(), bytes);
        assert_eq!(fs::read(&second).unwrap(), bytes, "later native binary must remain unchanged");
        drop(held);
    }

    /// What this machine's installs look like right now, read-only.
    ///
    /// The one question a new Antigravity release asks: are both renames still
    /// there to make? `SignatureMissing` on a fresh install means the proto
    /// field moved and the patcher needs a new signature before the version is
    /// shipped (kb/patch.md); `Unpatched` means it is simply not applied yet.
    /// Reads and prints, asserts nothing about the answer - all four states are
    /// legitimate depending on what the user has done.
    ///
    ///     cargo test inspects_the_installs_on_this_machine -- --ignored --nocapture
    #[test]
    #[ignore = "reads the real installs on this machine; run with --ignored"]
    fn inspects_the_installs_on_this_machine() {
        let installs = crate::discover_installs_fast();
        println!("установок найдено: {}", installs.len());
        for install in &installs {
            println!(
                "\n{} — {}",
                crate::install_label(install),
                install.display()
            );
            for (path, state) in inspect_install(install).files {
                // The second rename is not part of `FileState` (it is not what
                // decides eligibility), and it is the half a new build is just
                // as free to move. Read straight off the bytes.
                let bytes = fs::read(&path).unwrap_or_default();
                let proxy = if contains_subslice(&bytes, PROXY_VAR_NEW.as_bytes()) {
                    "AG_LS_PROXY"
                } else if contains_subslice(&bytes, &proxy_var_original()) {
                    "не переименован"
                } else {
                    "ЛИТЕРАЛА НЕТ"
                };
                println!(
                    "  {:?}  прокси-переменная: {}  — {}",
                    state,
                    proxy,
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
            }
        }
    }

    #[test]
    fn replaces_every_occurrence() {
        let mut data = b"xxineligibleyyineligible".to_vec();
        assert_eq!(replace_all(&mut data, b"ineligible", b"inexigible"), 2);
        assert_eq!(&data, b"xxinexigibleyyinexigible");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn retained_stage_blocks_even_a_read_of_the_new_generation() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("ag-mac-stage-hold-{}", std::process::id()));
        fs::create_dir(&dir).expect("isolated fixture directory");
        let target = dir.join("target");
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&target).unwrap();
        file.write_all(b"replacement").unwrap();
        drop(file);
        let stage = temp_path(&target);
        fs::create_dir(&stage).unwrap();
        assert!(read_mac_preimage(&target).unwrap_err().contains("staging"));
        fs::remove_dir(&stage).unwrap();
        let (file, bytes) = read_mac_preimage(&target).unwrap();
        assert_eq!(bytes, b"replacement");
        drop(file);
        fs::remove_file(&target).unwrap();
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn matches_at_the_very_end_of_the_buffer() {
        // The previous implementation used `0..len - needle.len()`, which
        // silently skipped a match sitting at the last possible offset.
        let mut data = b"padineligible".to_vec();
        assert_eq!(replace_all(&mut data, b"ineligible", b"inexigible"), 1);
        assert_eq!(&data, b"padinexigible");
    }

    #[test]
    fn shorter_than_needle_is_not_a_panic() {
        let mut data = b"abc".to_vec();
        assert_eq!(replace_all(&mut data, b"ineligible", b"inexigible"), 0);
        assert_eq!(count_occurrences(&data, b"ineligible"), 0);
    }

    /// The watchdog's four outcomes, on real files. The signature strings are
    /// obfuscated in the binary but plain here in the test fixtures - the point
    /// is the classification, not the literals.
    #[test]
    fn repatch_classifies_each_case() {
        let dir = std::env::temp_dir().join("ag_repatch_test");
        fs::create_dir_all(&dir).expect("temp dir");

        // Reverted by an update: contains the original field name → re-patched.
        let reverted = dir.join("reverted.bin");
        fs::write(&reverted, b"..ineligible..ineligible..").unwrap();
        assert_eq!(repatch_if_needed(&reverted), RepatchOutcome::Repatched(2));
        // And now it reads back as patched, so a second pass is a no-op.
        assert_eq!(repatch_if_needed(&reverted), RepatchOutcome::AlreadyPatched);

        // A build whose signature is gone entirely: left untouched on purpose.
        let unknown = dir.join("unknown.bin");
        fs::write(&unknown, b"a totally different binary layout").unwrap();
        assert_eq!(
            repatch_if_needed(&unknown),
            RepatchOutcome::SignatureMissing
        );
        // Crucially it was NOT modified - the app must run and show its error.
        assert_eq!(
            fs::read(&unknown).unwrap(),
            b"a totally different binary layout"
        );

        // A path that does not exist is a failure, not a missing signature:
        // "retry", never "give up and hide the error".
        match repatch_if_needed(&dir.join("nope.bin")) {
            RepatchOutcome::Failed(_) => {}
            other => panic!("expected Failed, got {:?}", other),
        }

        fs::remove_dir_all(&dir).ok();
    }

    /// End-to-end check against the installed Language Server: patch a copy,
    /// confirm the signature is found, the file size is untouched and the
    /// revert is byte-exact. Heavy (copies ~140 MB), so run it explicitly:
    ///   cargo test --bin ag_unlocker -- --ignored
    ///
    /// The copy is reverted to stock first. Any machine that has actually run
    /// this tool has an already-patched Language Server, and without that step
    /// the test only ever passed on a pristine install - which is the machine
    /// least likely to be running it.
    #[test]
    #[ignore]
    fn patches_and_reverts_the_installed_language_server() {
        let Ok(local) = std::env::var("LOCALAPPDATA") else {
            return;
        };
        let src = Path::new(&local)
            .join("Programs")
            .join("Antigravity")
            .join("resources")
            .join("bin")
            .join("language_server.exe");
        if !src.exists() {
            return;
        }

        let tmp = std::env::temp_dir().join("ag_unlocker_ls_patch_test.exe");
        fs::copy(&src, &tmp).expect("copy language server");
        unpatch_proxy_var(&tmp).ok();
        unpatch_binary(&tmp).ok();
        let original = fs::read(&tmp).expect("read stock copy");
        assert!(
            count_occurrences(&original, b"ineligible") > 0,
            "could not get the copy back to stock"
        );

        let patched = patch_binary(Path::new(""), &tmp).expect("signature found");
        assert!(patched > 0, "no occurrences replaced");
        let after = fs::read(&tmp).expect("read patched");
        assert_eq!(after.len(), original.len(), "patch changed the file size");
        assert_eq!(count_occurrences(&after, b"ineligible"), 0);
        assert_eq!(count_occurrences(&after, b"inexigible"), patched);

        // The proxy channel, on the real Go binary: the lower-case literal that
        // `httpproxy.getEnvAny` reads second is renamed, the upper-case one it
        // reads first is left for the user, and nothing else moves.
        let proxied = patch_proxy_var(&tmp).expect("proxy literal found");
        assert!(proxied > 0, "no proxy literal replaced");
        let after = fs::read(&tmp).expect("read patched");
        assert_eq!(after.len(), original.len(), "proxy rename changed the size");
        assert_eq!(count_occurrences(&after, b"https_proxy"), 0);
        assert_eq!(
            count_occurrences(&after, b"HTTPS_PROXY"),
            count_occurrences(&original, b"HTTPS_PROXY"),
            "the user's own variable name must be untouched"
        );

        // Re-running must be a no-op, not an error.
        assert_eq!(patch_binary(Path::new(""), &tmp).expect("idempotent"), 0);
        assert_eq!(patch_proxy_var(&tmp).expect("idempotent"), 0);

        assert_eq!(unpatch_proxy_var(&tmp).expect("revert proxy"), proxied);
        assert_eq!(unpatch_binary(&tmp).expect("revert"), patched);
        assert_eq!(fs::read(&tmp).expect("read reverted"), original);

        let _ = fs::remove_file(&tmp);
    }

    /// The whole edit rests on the two names being the same length: a byte
    /// longer and every offset after it in a 150 MB PE moves. Cheap to assert,
    /// impossible to notice by eye when someone renames the variable.
    #[test]
    fn the_private_proxy_name_is_the_same_length_as_the_one_it_replaces() {
        assert_eq!(PROXY_VAR_NEW.len(), "https_proxy".len());
        // Upper-case `HTTPS_PROXY` stays untouched on purpose: it is looked up
        // first, so a proxy the user set themselves still wins (I54). The name
        // the tool writes is this same constant by definition
        // (`endpoint::PROXY_ENV_VAR`), so the two cannot drift apart.
        assert_ne!(PROXY_VAR_NEW, "HTTPS_PROXY");
        assert_ne!(PROXY_VAR_NEW, crate::endpoint::LEGACY_PROXY_ENV_VAR);
    }

    /// Both renames on one buffer, and back. The proxy rename must not disturb
    /// the eligibility one, and the revert must be byte-exact - the file is a
    /// signed-by-nobody 150 MB executable and a stray byte is unlaunchable.
    #[test]
    fn the_proxy_rename_round_trips_beside_the_eligibility_one() {
        let dir = std::env::temp_dir().join("ag_proxyvar_test");
        fs::create_dir_all(&dir).expect("temp dir");
        let bin = dir.join("both.bin");
        let original = b"..ineligible..https_proxy..HTTPS_PROXY..https_proxy..".to_vec();
        fs::write(&bin, &original).unwrap();

        assert_eq!(patch_binary(Path::new(""), &bin).expect("gate"), 1);
        assert_eq!(patch_proxy_var(&bin).expect("proxy var"), 2);
        let after = fs::read(&bin).unwrap();
        assert_eq!(after.len(), original.len(), "size changed");
        assert_eq!(count_occurrences(&after, b"https_proxy"), 0);
        assert_eq!(
            count_occurrences(&after, b"HTTPS_PROXY"),
            1,
            "the user's own variable name must survive"
        );
        // Re-running either one is a no-op, not an error.
        assert_eq!(patch_proxy_var(&bin).expect("idempotent"), 0);

        assert_eq!(unpatch_proxy_var(&bin).expect("revert proxy"), 2);
        assert_eq!(unpatch_binary(&bin).expect("revert gate"), 1);
        assert_eq!(fs::read(&bin).unwrap(), original);

        fs::remove_dir_all(&dir).ok();
    }

    /// A build whose proxy literal is missing is not a failed patch: the unlock
    /// still applies, only the local-proxy route is unavailable, and the caller
    /// has to be able to tell those apart to avoid writing a dead variable.
    #[test]
    fn a_missing_proxy_literal_is_an_error_not_a_silent_success() {
        let dir = std::env::temp_dir().join("ag_proxyvar_missing_test");
        fs::create_dir_all(&dir).expect("temp dir");
        let bin = dir.join("gate_only.bin");
        fs::write(&bin, b"..ineligible..").unwrap();

        assert!(patch_binary(Path::new(""), &bin).is_ok());
        assert!(patch_proxy_var(&bin).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    /// The watchdog's job after an update that restored both names, and after an
    /// upgrade from a build that only knew the eligibility one.
    #[test]
    fn repatch_restores_the_proxy_name_too() {
        let dir = std::env::temp_dir().join("ag_repatch_proxy_test");
        fs::create_dir_all(&dir).expect("temp dir");

        // An update put the stock binary back: both names are stock again.
        let updated = dir.join("updated.bin");
        fs::write(&updated, b"..ineligible..https_proxy..").unwrap();
        assert_eq!(repatch_if_needed(&updated), RepatchOutcome::Repatched(1));
        assert_eq!(
            count_occurrences(&fs::read(&updated).unwrap(), b"https_proxy"),
            0
        );

        // Patched by <= 2.11.0_4: unlocked, but on the stock proxy channel. The
        // unlock is unchanged, so the outcome stays `AlreadyPatched`, and the
        // proxy name is fixed up in the same pass.
        let legacy = dir.join("legacy.bin");
        fs::write(&legacy, b"..inexigible..https_proxy..").unwrap();
        assert_eq!(repatch_if_needed(&legacy), RepatchOutcome::AlreadyPatched);
        let after = fs::read(&legacy).unwrap();
        assert_eq!(count_occurrences(&after, b"https_proxy"), 0);
        assert_eq!(count_occurrences(&after, PROXY_VAR_NEW.as_bytes()), 1);
        // And a second pass writes nothing more.
        assert_eq!(repatch_if_needed(&legacy), RepatchOutcome::AlreadyPatched);
        assert_eq!(fs::read(&legacy).unwrap(), after);

        fs::remove_dir_all(&dir).ok();
    }

    /// A temp a killed writer left behind goes on the next write; one young
    /// enough to be another patcher's, and anything that is not a temp of this
    /// file, stay.
    #[test]
    fn a_stale_temp_is_swept_and_a_fresh_one_is_not() {
        let dir = std::env::temp_dir().join("ag_sweep_temps");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("language_server.exe");
        fs::write(&target, b"x").unwrap();
        let stale = dir.join("language_server.exe.1234.agtmp");
        let fresh = dir.join("language_server.exe.5678.agtmp");
        let other = dir.join("webm_encoder.exe.1234.agtmp");
        for f in [&stale, &fresh, &other] {
            fs::write(f, b"partial").unwrap();
        }
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        for f in [&stale, &other] {
            fs::File::options()
                .write(true)
                .open(f)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        sweep_stale_temps(&target);
        assert!(!stale.exists(), "an hour-old temp of this file is swept");
        assert!(fresh.exists(), "a young one may be another writer's");
        assert!(other.exists(), "another file's temp is not ours to judge");
        assert!(target.exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn round_trip_restores_the_original_bytes() {
        let original = b"a ineligible b ineligible_tiers c".to_vec();
        let mut data = original.clone();
        replace_all(&mut data, b"ineligible", b"inexigible");
        assert_ne!(data, original);
        replace_all(&mut data, b"inexigible", b"ineligible");
        assert_eq!(data, original);
    }

    #[test]
    fn inspect_matches_across_buffer_boundary() {
        let dir = std::env::temp_dir().join("ag_inspect_boundary_test");
        fs::create_dir_all(&dir).expect("temp dir");

        let chunk_size = 1024 * 1024;
        let file_len = chunk_size + 100;
        let mut data = vec![b'x'; file_len];

        let offset = chunk_size - 5;
        data[offset..offset + 10].copy_from_slice(b"inexigible");

        let bin = dir.join("boundary_patched.bin");
        fs::write(&bin, &data).expect("write file");
        assert_eq!(inspect_file(&bin), FileState::Patched);

        data[offset..offset + 10].copy_from_slice(b"ineligible");
        let bin_unpatched = dir.join("boundary_unpatched.bin");
        fs::write(&bin_unpatched, &data).expect("write file");
        assert_eq!(inspect_file(&bin_unpatched), FileState::Unpatched);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inspect_missing_signature_when_neither_present() {
        let dir = std::env::temp_dir().join("ag_inspect_missing_test");
        fs::create_dir_all(&dir).expect("temp dir");
        let bin = dir.join("neither.bin");
        fs::write(&bin, b"some content without any known signatures").expect("write");

        assert_eq!(inspect_file(&bin), FileState::SignatureMissing);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inspect_unreadable_on_nonexistent_path() {
        let missing = PathBuf::from("this_file_definitely_does_not_exist_xyz_12345.exe");
        match inspect_file(&missing) {
            FileState::Unreadable(reason) => {
                assert!(!reason.is_empty(), "reason should not be empty");
            }
            other => panic!("expected FileState::Unreadable, got {:?}", other),
        }
    }

    #[test]
    fn install_state_evaluates_fully_and_partially_patched() {
        // Empty
        let empty = InstallState { files: vec![] };
        assert!(empty.is_empty());
        assert!(!empty.fully_patched());
        assert!(!empty.partially_patched());

        // All patched
        let all_patched = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Patched),
                (PathBuf::from("b.exe"), FileState::Patched),
            ],
        };
        assert!(!all_patched.is_empty());
        assert!(all_patched.fully_patched());
        assert!(!all_patched.partially_patched());

        // None patched (all unpatched)
        let all_unpatched = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Unpatched),
                (PathBuf::from("b.exe"), FileState::Unpatched),
            ],
        };
        assert!(!all_unpatched.fully_patched());
        assert!(!all_unpatched.partially_patched());

        // Some patched, some unpatched
        let mixed = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Patched),
                (PathBuf::from("b.exe"), FileState::Unpatched),
            ],
        };
        assert!(!mixed.fully_patched());
        assert!(mixed.partially_patched());

        // Some patched, some signature missing
        let mixed_missing = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Patched),
                (PathBuf::from("b.exe"), FileState::SignatureMissing),
            ],
        };
        assert!(!mixed_missing.fully_patched());
        assert!(mixed_missing.partially_patched());

        // Some patched, some unreadable
        let mixed_unreadable = InstallState {
            files: vec![
                (PathBuf::from("a.exe"), FileState::Patched),
                (
                    PathBuf::from("b.exe"),
                    FileState::Unreadable("locked".to_string()),
                ),
            ],
        };
        assert!(!mixed_unreadable.fully_patched());
        assert!(mixed_unreadable.partially_patched());
    }
}

/// Reverses the binary patch so an install can be returned to stock without
/// reinstalling.
/// Reverts every native binary of one install and reports each outcome.
///
/// Returns results rather than a count, and prints nothing: a count cannot say
/// that one file failed, and the caller used to read "reverted 1 of 2" as a
/// clean revert. The window has no console for the difference to appear on
/// either.
pub fn unpatch_all_binaries(inst: &Path) -> Vec<(String, Result<usize, String>)> {
    unpatch_binary_batch(inst, false)
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct NativeUndoFailure { pub(crate) completed: usize, pub(crate) cause: String }

pub(crate) fn unpatch_all_binaries_checked(inst: &Path) -> Result<usize, NativeUndoFailure> {
    let mut completed = 0;
    for (label, result) in unpatch_binary_batch(inst, true) {
        match result {
            Ok(0) => {},
            Ok(_) => completed += 1,
            Err(error) => return Err(NativeUndoFailure { completed, cause: format!("{label}: {error}") }),
        }
    }
    Ok(completed)
}

fn unpatch_binary_batch(inst: &Path, stop_on_failure: bool) -> Vec<(String, Result<usize, String>)> {
    let mut results = Vec::new();
    for bin in binary_targets(inst) {
        let label = bin
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // The proxy rename first: it is the one that stops the binary reading
        // our variable, and a revert that failed halfway should at least leave
        // the language server on the stock proxy channel. Silent - a build that
        // never carried it is not an error to report.
        let original = proxy_var_original();
        let (proxy, proxy_error) = match rewrite_result(&bin, PROXY_VAR_NEW.as_bytes(), &original, #[cfg(target_os = "macos")] Some(inst)) {
            Ok(count) => (count, None),
            Err(RewriteFailure::MissingSignature) => (0, None),
            Err(RewriteFailure::Io(error)) => (0, Some(error)),
        };
        if stop_on_failure {
            if let Some(error) = proxy_error {
                results.push((label, Err(format!("Канал прокси не восстановлен: {error}"))));
                break;
            }
        }
        let (from, to) = field_signatures();
        let result = match (proxy_error, rewrite(&bin, &to, &from, #[cfg(target_os = "macos")] Some(inst))) {
            (None, Ok(count)) => Ok(if count == 0 && proxy > 0 { 1 } else { count }),
            (None, Err(error)) => Err(format!("Канал прокси: {proxy} замен; основной откат не завершён: {error}")),
            (Some(proxy_error), Ok(count)) => Err(format!("Основной откат: {count} замен; канал прокси не восстановлен: {proxy_error}")),
            (Some(proxy_error), Err(error)) => Err(format!("Канал прокси: {proxy_error}; основной откат: {error}")),
        };
        let failed = result.is_err();
        results.push((label, result));
        if stop_on_failure && failed { break; }
    }
    results
}
