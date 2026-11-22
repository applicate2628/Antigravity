use super::{task_scheduler::{DefinitionView, Origin}, BackgroundChanges};
use crate::windows_coordinator::windows_installation::{
    self, BackgroundLease, CheckedPath, NativeObjectId, PathKind, PathPurpose, SourceSnapshot, WindowsLocalPath,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::OsString,
    io,
    num::NonZeroIsize,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    ptr,
};
use windows::{
    core::{HRESULT, PWSTR},
    Win32::{
        Foundation::{ERROR_CANCELLED, HWND as DialogWindow},
        System::Com::{CoCreateInstance, CoGetApartmentType, CoTaskMemFree, APTTYPE_MAINSTA,
            APTTYPE_STA, CLSCTX_INPROC_SERVER},
        UI::Shell::{FileOpenDialog, IFileOpenDialog, FOS_ALLOWMULTISELECT, FOS_DONTADDTORECENT,
            FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR, FOS_NODEREFERENCELINKS,
            FOS_OKBUTTONNEEDSINTERACTION, FOS_PATHMUSTEXIST, SIGDN_FILESYSPATH},
    },
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_NO_TOKEN, HANDLE, HWND},
    Security::{GetTokenInformation, TokenElevation, TokenSessionId, TOKEN_ELEVATION, TOKEN_QUERY},
    Storage::FileSystem::GetVolumeNameForVolumeMountPointW,
    System::{
        StationsAndDesktops::{GetProcessWindowStation, GetThreadDesktop, GetUserObjectInformationW,
            UOI_FLAGS, UOI_IO, USEROBJECTFLAGS},
        Threading::{GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId,
            OpenProcessToken, OpenThreadToken},
    },
    UI::WindowsAndMessaging::{GetAncestor, GetForegroundWindow, GetWindowThreadProcessId,
        IsWindowVisible, MessageBoxW, GA_ROOT, IDNO, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO,
    },
};

type Result<T> = std::result::Result<T, String>;

// Each selection is fully read by the checked-path owner. Bound allocation in
// this elevated interactive operation before any of the four inputs is read.
const MAX_EVIDENCE_BYTES: u64 = 8 * 1024 * 1024;
const EVIDENCE_COUNT: u32 = 4;
const GENERATION_SOURCE: &str = "src/dns_forwarder.rs";

pub(super) struct ApprovedPrior {
    prior: OperatorAuthenticatedPrior,
    current: ExactCurrentGrant,
    inputs: Vec<HeldEvidence>,
}

struct OperatorAuthenticatedPrior {
    generation: u32,
    provenance: Value,
}

struct ExactCurrentGrant {
    serial: String,
}

impl ApprovedPrior {
    pub(super) fn generation(&self) -> u32 { self.prior.generation }

    pub(super) fn serial(&self) -> &str { &self.current.serial }

    pub(super) fn provenance(&self) -> &Value { &self.prior.provenance }

    pub(super) fn revalidate(&self) -> Result<()> {
        self.inputs.iter().try_for_each(HeldEvidence::revalidate)
    }
}

pub(super) fn confirm(
    program: &CheckedPath,
    source: &BackgroundLease,
    serial: &str,
    current_roles: &[DefinitionView],
    desired: BackgroundChanges,
    _gate_failure: &str,
) -> Result<ApprovedPrior> {
    windows_installation::validate_request_id(serial)?;
    let owner = InteractiveOwner::receive()?;
    let roles = role_preview(current_roles, program)?;
    let old = program.read_checked_snapshot()?;
    let (selected_id, selected_bytes) = source.source_capture()?;
    let selected_digest = hash(selected_bytes);
    let (prior, inputs) = authenticate_prior(&owner, program, source, &old)?;
    let current_summary = format!(
        "Текущая операция {serial}\nНазначение {}\n\n\
         Установленный файл, поколение {}\n{}\nSHA-256 {}\n\
         Выбранный файл{}\n{}\nSHA-256 {}\n\n\
         DNS: {}. Наблюдатель: {}.\n{}\n\n\
         Разрешить замену этого установленного файла выбранным в рамках текущего восстановления?",
        display(&program.as_path().to_string_lossy()), prior.generation,
        display_id(&program.native_id()), old.digest(),
        format_args!(" ({} байт)", selected_bytes.len()), display_id(&selected_id), selected_digest,
        desired_text(desired.relay), desired_text(desired.watchdog), roles,
    );
    let current = owner.confirm_current(serial, &current_summary)?;
    let approved = ApprovedPrior { prior, current, inputs };
    approved.revalidate()?;
    Ok(approved)
}

fn authenticate_prior(owner: &InteractiveOwner, program: &CheckedPath, source: &BackgroundLease,
    old: &SourceSnapshot) -> Result<(OperatorAuthenticatedPrior, Vec<HeldEvidence>)> {
    let mut inputs = Vec::with_capacity(EVIDENCE_COUNT as usize);
    let mut documents = Vec::with_capacity(EVIDENCE_COUNT as usize);
    for path in owner.select_paths()? {
        let (input, bytes) = HeldEvidence::receive(source, &path)?;
        if inputs.iter().any(|other: &HeldEvidence| other.pin.native_id() == input.pin.native_id()) {
            return Err("PriorAuthenticationUnavailable: duplicate selected file".into());
        }
        documents.push(Document::receive(&bytes, &input.digest)?);
        inputs.push(input);
    }
    let prior = PriorEvidence::join(documents, program, old.digest(), old.bytes().len() as u64)?;
    let prior_summary = format!(
        "Архивная операция {}\nЗамена {}\nПоколение службы DNS {}\n\n\
         Отчёт о замене SHA-256\n{}\nСведения о сборке SHA-256\n{}\n\
         Манифест исходников SHA-256\n{}\nИсходник версии SHA-256\n{}\n\n\
         Подтверждаете, что лично проверили подлинность этих архивных данных и их связь с прежней установкой?",
        prior.operation, prior.replacement, prior.generation, prior.terminal_digest,
        prior.package_digest, prior.manifest_digest, prior.generation_digest,
    );
    Ok((owner.authenticate(prior, &prior_summary)?, inputs))
}

pub(super) struct ApprovedStopped {
    current: Option<ExactCurrentGrant>,
    owner: InteractiveOwner,
    prior: Option<(OperatorAuthenticatedPrior, Vec<HeldEvidence>)>,
}

impl ApprovedStopped {
    pub(super) fn prior(&self) -> Option<(u32, &Value)> {
        self.prior.as_ref().map(|(prior, _)| (prior.generation, &prior.provenance))
    }

    pub(super) fn consume(&mut self, serial: &str) -> Result<()> {
        let grant = self.current.take().ok_or("ExactConfirmationUnavailable: stopped update confirmation already consumed")?;
        if grant.serial != serial { return Err("ChangedInput: stopped update confirmation belongs to another operation".into()); }
        if let Some((_, inputs)) = &self.prior { inputs.iter().try_for_each(HeldEvidence::revalidate)?; }
        self.owner.recheck()
    }
}

pub(super) fn confirm_stopped(program: &CheckedPath, original: &SourceSnapshot, source: &BackgroundLease,
    serial: &str, roles: &[DefinitionView; 2], authenticate_old: bool) -> Result<ApprovedStopped> {
    windows_installation::validate_request_id(serial)?;
    let owner = InteractiveOwner::receive()?;
    let preview = role_preview(roles, program)?;
    let (selected_id, selected) = source.source_capture()?;
    let prior = if authenticate_old { Some(authenticate_prior(&owner, program, source, original)?) } else { None };
    let action = if original.bytes() == selected { "Проверить и завершить запись поколения установленного файла?" }
        else { "Заменить установленный файл выбранным, сохранив обе задачи остановленными?" };
    let summary = format!(
        "Операция {serial}\nНазначение {}\n\n\
         Установленный файл {} ({} байт)\nSHA-256 {}\n\
         Выбранный файл {} ({} байт)\nSHA-256 {}\n\n\
         {}\nSHA-256 определения DNS {}\nSHA-256 определения наблюдателя {}\n\n{}",
        display(&program.as_path().to_string_lossy()), display_id(&program.native_id()), original.bytes().len(), original.digest(),
        display_id(&selected_id), selected.len(), hash(selected), preview, hash(roles[0].xml.as_bytes()), hash(roles[1].xml.as_bytes()), action,
    );
    let current = owner.confirm_current(serial, &summary)?;
    Ok(ApprovedStopped { current: Some(current), owner, prior })
}

fn desired_text(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "включить",
        Some(false) => "отключить",
        None => "сохранить текущее состояние",
    }
}

fn role_preview(roles: &[DefinitionView], program: &CheckedPath) -> Result<String> {
    let mut seen = HashSet::new();
    let mut text = Vec::new();
    for role in roles {
        let name = match role.role.as_str() {
            "relay" => "DNS",
            "watchdog" => "Наблюдатель",
            _ => return Err("ExactConfirmationUnavailable: unrecognized current role".into()),
        };
        if role.origin != Origin::Managed || role.principal.is_empty() || !seen.insert(name)
            || !windows_installation::same_windows_path(&role.program, program.as_path())?
        {
            return Err("ExactConfirmationUnavailable: current role association is ambiguous".into());
        }
        text.push(format!("{name}: {} (тип входа {}, экземпляров {})\nSHA-256 защиты задачи {}",
            display(&role.principal), role.logon, role.instances.len(), hash(role.security.as_bytes())));
    }
    Ok(text.join("\n"))
}

fn display(value: &str) -> String {
    // Escape control and display-direction characters supplied by a path or principal.
    value.escape_debug().to_string()
}

fn display_id(id: &NativeObjectId) -> String {
    format!("{:016x}/{}", id.volume, hex::encode(id.file))
}

fn hash(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

fn wide(text: &str) -> Vec<u16> { text.encode_utf16().chain(Some(0)).collect() }

struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) { unsafe { CloseHandle(self.0); } }
}

pub(super) fn current_elevation() -> Result<bool> {
    let (elevation, session) = current_token_state()?;
    Ok(elevation != 0 && session != 0)
}

pub(super) fn current_interactive_user() -> Result<bool> {
    let (elevation, session) = current_token_state()?;
    Ok(elevation == 0 && session != 0)
}

fn current_token_state() -> Result<(u32, u32)> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } != 0 {
        let _token = Token(raw);
        return Err("the confirmation thread is impersonating another token".into());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
        return Err(format!("inspect confirmation thread token: {error}"));
    }
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(format!("open current process token: {}", io::Error::last_os_error()));
    }
    let token = Token(raw);
    let mut elevation = TOKEN_ELEVATION::default();
    receive_token_value(&token, TokenElevation, &mut elevation)?;
    let mut session = 0u32;
    receive_token_value(&token, TokenSessionId, &mut session)?;
    Ok((elevation.TokenIsElevated, session))
}

fn receive_token_value<T>(token: &Token, class: i32, value: &mut T) -> Result<()> {
    let size = std::mem::size_of::<T>() as u32;
    let mut received = 0;
    if unsafe { GetTokenInformation(token.0, class, ptr::from_mut(value).cast(), size, &mut received) } == 0 {
        return Err(format!("read current token information: {}", io::Error::last_os_error()));
    }
    if received != size {
        return Err("current token returned an invalid information size".into());
    }
    Ok(())
}

fn on_input_desktop(thread: u32) -> bool {
    let desktop = unsafe { GetThreadDesktop(thread) };
    let mut input = 0i32;
    let mut received = 0;
    !desktop.is_null() && unsafe { GetUserObjectInformationW(desktop, UOI_IO,
        ptr::from_mut(&mut input).cast(), std::mem::size_of_val(&input) as u32, &mut received) } != 0
        && input != 0
}

struct InteractiveOwner(HWND);

pub(crate) struct VendorForegroundOwner {
    window: NonZeroIsize,
    thread: u32,
}

impl VendorForegroundOwner {
    pub(crate) fn receive(window: NonZeroIsize) -> Result<Self> {
        let thread = receive_vendor_foreground(window)?;
        if thread != unsafe { GetCurrentThreadId() } {
            return Err("Окно подтверждения принадлежит другому потоку.".into());
        }
        Ok(Self { window, thread })
    }

    pub(crate) fn recheck(self) -> Result<()> {
        if receive_vendor_foreground(self.window)? != self.thread {
            return Err("Окно подтверждения изменилось до записи.".into());
        }
        Ok(())
    }
}

fn receive_vendor_foreground(window: NonZeroIsize) -> Result<u32> {
    if !current_interactive_user()? { return Err("Требуется обычный интерактивный сеанс Windows без повышения прав.".into()); }
    receive_foreground_thread(window.get() as HWND).map_err(|error| format!("Окно подтверждения недоступно: {error}"))
}

fn receive_foreground_thread(window: HWND) -> Result<u32> {
    let mut process = 0;
    let thread = unsafe { GetWindowThreadProcessId(window, &mut process) };
    if window.is_null() || thread == 0 || process != unsafe { GetCurrentProcessId() }
        || unsafe { GetForegroundWindow() } != window
        || unsafe { GetAncestor(window, GA_ROOT) } != window
        || unsafe { IsWindowVisible(window) } == 0
        || !on_input_desktop(thread) || !on_input_desktop(unsafe { GetCurrentThreadId() })
    {
        return Err("foreground app window on the input desktop required".into());
    }
    let station = unsafe { GetProcessWindowStation() };
    let mut flags = USEROBJECTFLAGS::default();
    let mut received = 0;
    if station.is_null() || unsafe { GetUserObjectInformationW(station, UOI_FLAGS,
        ptr::from_mut(&mut flags).cast(), std::mem::size_of_val(&flags) as u32, &mut received) } == 0
        || flags.dwFlags & windows_sys::Win32::UI::WindowsAndMessaging::WSF_VISIBLE as u32 == 0
    {
        return Err("visible window station required".into());
    }
    Ok(thread)
}

impl InteractiveOwner {
    fn receive() -> Result<Self> {
        let mut apartment = Default::default();
        let mut qualifier = Default::default();
        unsafe { CoGetApartmentType(&mut apartment, &mut qualifier) }
            .map_err(|error| format!("ExactRepairIntakeUnavailable: scheduler COM apartment: {error}"))?;
        if apartment != APTTYPE_STA && apartment != APTTYPE_MAINSTA {
            return Err("ExactRepairIntakeUnavailable: scheduler thread is not a single-threaded COM apartment".into());
        }
        let owner = Self(unsafe { GetForegroundWindow() });
        owner.recheck()?;
        Ok(owner)
    }

    fn recheck(&self) -> Result<()> {
        if !current_elevation().map_err(|error| format!("ExactRepairIntakeUnavailable: {error}"))? {
            return Err("ExactRepairIntakeUnavailable: elevated interactive process token required".into());
        }
        receive_foreground_thread(self.0).map(|_| ()).map_err(|error| format!("ExactRepairIntakeUnavailable: {error}"))
    }

    fn select_paths(&self) -> Result<Vec<PathBuf>> {
        self.recheck()?;
        let dialog: IFileOpenDialog = unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) }
            .map_err(picker_error)?;
        unsafe {
            dialog.SetOptions(FOS_ALLOWMULTISELECT | FOS_DONTADDTORECENT | FOS_FILEMUSTEXIST
                | FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR | FOS_NODEREFERENCELINKS
                | FOS_OKBUTTONNEEDSINTERACTION | FOS_PATHMUSTEXIST).map_err(picker_error)?;
            dialog.SetTitle(windows::core::w!("Выберите 4 файла: отчёт, сведения о сборке, манифест и исходник версии"))
                .map_err(picker_error)?;
            dialog.Show(Some(DialogWindow(self.0))).map_err(picker_error)?;
            let items = dialog.GetResults().map_err(picker_error)?;
            if items.GetCount().map_err(picker_error)? != EVIDENCE_COUNT {
                return Err("PriorAuthenticationUnavailable: select exactly four archived evidence files".into());
            }
            (0..EVIDENCE_COUNT).map(|index| {
                let item = items.GetItemAt(index).map_err(picker_error)?;
                let path = ShellPath(item.GetDisplayName(SIGDN_FILESYSPATH).map_err(picker_error)?);
                if path.0.is_null() {
                    return Err("ExactRepairIntakeUnavailable: picker returned an empty filesystem path".into());
                }
                Ok(PathBuf::from(OsString::from_wide(path.0.as_wide())))
            }).collect()
        }
    }

    fn affirmative(&self, title: &str, message: &str, failure: &str) -> Result<()> {
        self.recheck()?;
        let message = wide(message);
        let title = wide(title);
        match unsafe { MessageBoxW(self.0, message.as_ptr(), title.as_ptr(),
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) } {
            IDYES => self.recheck(),
            IDNO => Err(format!("{failure}: declined")),
            _ => Err(format!("{failure}: native confirmation failed: {}", io::Error::last_os_error())),
        }
    }

    fn authenticate(&self, prior: PriorEvidence, summary: &str) -> Result<OperatorAuthenticatedPrior> {
        self.affirmative("Подлинность архивных данных", summary, "PriorAuthenticationUnavailable")?;
        Ok(OperatorAuthenticatedPrior { generation: prior.generation, provenance: prior.provenance() })
    }

    fn confirm_current(&self, serial: &str, summary: &str) -> Result<ExactCurrentGrant> {
        self.affirmative("Подтверждение восстановления", summary, "ExactConfirmationUnavailable")?;
        Ok(ExactCurrentGrant { serial: serial.to_owned() })
    }
}

fn picker_error(error: windows::core::Error) -> String {
    if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
        "PriorAuthenticationUnavailable: file selection cancelled".into()
    } else {
        format!("ExactRepairIntakeUnavailable: native file picker: {error}")
    }
}

struct ShellPath(PWSTR);

impl Drop for ShellPath {
    fn drop(&mut self) { unsafe { CoTaskMemFree(Some(self.0.0.cast())); } }
}

fn local_volume(path: &Path) -> Result<()> {
    let ordinary = WindowsLocalPath::parse(path.as_os_str())?;
    let disk = ordinary.as_path().as_os_str().encode_wide().next().ok_or("disk root missing")?;
    let root = [disk, b':' as u16, b'\\' as u16, 0];
    // A mounted volume name, unlike a drive-letter grammar alone, excludes
    // mapped network roots and substituted DOS paths.
    let mut volume = [0u16; 50]; // \\?\Volume{GUID}\ and the terminating NUL.
    if unsafe { GetVolumeNameForVolumeMountPointW(root.as_ptr(), volume.as_mut_ptr(), volume.len() as u32) } == 0 {
        return Err("PriorAuthenticationUnavailable: evidence requires an ordinary local volume".into());
    }
    Ok(())
}

struct HeldEvidence {
    pin: CheckedPath,
    digest: String,
    security: String,
    length: u64,
}

impl HeldEvidence {
    fn receive(source: &BackgroundLease, path: &Path) -> Result<(Self, Vec<u8>)> {
        local_volume(path)?;
        // Reuse the background owner's no-follow ancestor and file-integrity
        // admission before reading evidence bytes. A second same-object pin
        // shares reads alone and keeps the selected app evidence from moving.
        let admitted = windows_installation::checked_background_path(source, path, PathKind::File)
            .map_err(|error| format!("PriorAuthenticationUnavailable: evidence admission: {error}"))?;
        let pin = CheckedPath::open(admitted.as_path(), PathKind::File, PathPurpose::Review)?;
        if pin.native_id() != admitted.native_id() || pin.security_digest()? != admitted.security_digest()? {
            return Err("PriorAuthenticationUnavailable: evidence file changed during admission".into());
        }
        admitted.recheck()?;
        let security = pin.security_digest()?;
        let length = std::fs::symlink_metadata(pin.as_path())
            .map_err(|error| format!("PriorAuthenticationUnavailable: evidence size: {error}"))?.len();
        if length > MAX_EVIDENCE_BYTES {
            return Err("PriorAuthenticationUnavailable: an evidence file exceeds the 8 MiB intake budget".into());
        }
        let snapshot = pin.read_checked_snapshot()?;
        if snapshot.bytes().len() as u64 != length || pin.security_digest()? != security {
            return Err("PriorAuthenticationUnavailable: evidence changed while reading".into());
        }
        let bytes = snapshot.bytes().to_vec();
        Ok((Self { pin, digest: snapshot.digest().to_owned(), security, length }, bytes))
    }

    fn revalidate(&self) -> Result<()> {
        local_volume(self.pin.as_path())?;
        self.pin.recheck()?;
        if self.pin.security_digest()? != self.security {
            return Err("PriorAuthenticationUnavailable: evidence file security changed".into());
        }
        let snapshot = self.pin.read_checked_snapshot()?;
        if snapshot.digest() != self.digest || snapshot.bytes().len() as u64 != self.length
            || self.pin.security_digest()? != self.security
        {
            return Err("PriorAuthenticationUnavailable: held evidence changed".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Terminal {
    operation_id: String,
    receiving: Receiving,
}

#[derive(Deserialize)]
struct Receiving {
    operation: String,
    result: std::result::Result<(), String>,
    primary_result: Option<std::result::Result<(), String>>,
    restoration_result: Option<std::result::Result<(), String>>,
    restoration_pending: bool,
    cancellation_received: bool,
    persistence_errors: Vec<serde::de::IgnoredAny>,
    replacements: Vec<Replacement>,
    task_events: Vec<HistoricalEvent>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Replacement {
    schema: u32,
    kind: String,
    phase: String,
    operation_id: String,
    program: HistoricalPath,
    expected_program_native_id: NativeObjectId,
    source_native_id: NativeObjectId,
    program_observation: Observation,
    validated_source: Snapshot,
    replace_result: bool,
    work: ReplacementWork,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplacementWork {
    staged_observation: Observation,
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
enum Observation {
    Missing,
    Present { #[serde(rename = "nativeId")] native_id: NativeObjectId, snapshot: Snapshot },
}

#[derive(Deserialize)]
struct Snapshot {
    path: HistoricalPath,
    digest: String,
    metadata: SnapshotSize,
}

#[derive(Deserialize)]
struct SnapshotSize { size: u64 }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoricalPath {
    path: String,
    native_path_utf16: Vec<u16>,
}

impl HistoricalPath {
    fn parse(&self) -> Result<WindowsLocalPath> {
        if !self.path.encode_utf16().eq(self.native_path_utf16.iter().copied()) {
            return Err("historical path text and native locator disagree".into());
        }
        WindowsLocalPath::parse(&OsString::from_wide(&self.native_path_utf16))
    }
}

#[derive(Deserialize)]
enum HistoricalEvent {
    Definition(HistoricalRole),
    Call(serde::de::IgnoredAny),
    DefinitionsReadyForRetirement,
    InstanceRetired(serde::de::IgnoredAny),
    RoleRunning(serde::de::IgnoredAny),
}

#[derive(Deserialize)]
struct HistoricalRole {
    role: String,
    program: PathBuf,
    origin: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageReceiving {
    file_count: usize,
    files: Vec<FileEntry>,
    source_manifest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifest { files: Vec<FileEntry> }

#[derive(Deserialize)]
struct FileEntry {
    path: String,
    length: u64,
    sha256: String,
}

enum Document {
    Terminal(Terminal, String),
    Package(PackageReceiving, String),
    Manifest(SourceManifest, String),
    Generation(u32, u64, String),
}

impl Document {
    fn receive(bytes: &[u8], digest: &str) -> Result<Self> {
        let terminal = serde_json::from_slice::<Terminal>(bytes).ok();
        let package = serde_json::from_slice::<PackageReceiving>(bytes).ok();
        let manifest = serde_json::from_slice::<SourceManifest>(bytes).ok();
        let generation = relay_generation(bytes);
        let digest = digest.to_owned();
        match (terminal, package, manifest, generation) {
            (Some(value), None, None, None) => Ok(Self::Terminal(value, digest)),
            (None, Some(value), None, None) => Ok(Self::Package(value, digest)),
            (None, None, Some(value), None) => Ok(Self::Manifest(value, digest)),
            (None, None, None, Some(value)) => Ok(Self::Generation(value, bytes.len() as u64, digest)),
            _ => Err("PriorAuthenticationUnavailable: malformed or ambiguous archived evidence".into()),
        }
    }
}

fn relay_generation(bytes: &[u8]) -> Option<u32> {
    let mut declarations = std::str::from_utf8(bytes).ok()?.lines().filter_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == "pub const RELAY_VERSION: u32").then_some(value.trim())
    });
    let digits = declarations.next()?.strip_suffix(';')?.trim();
    if declarations.next().is_some() || !digits.bytes().all(|digit| digit.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|version| *version != 0)
}

fn matching_entry<'a>(files: &'a [FileEntry], path: &str) -> Result<&'a FileEntry> {
    let mut found = files.iter().filter(|entry| entry.path.eq_ignore_ascii_case(path));
    match (found.next(), found.next()) {
        (Some(entry), None) if entry.path == path => Ok(entry),
        _ => Err("missing or ambiguous archived file entry".into()),
    }
}

fn same_digest(left: &str, right: &str) -> bool {
    left.len() == 64 && right.len() == 64 && left.bytes().all(|byte| byte.is_ascii_hexdigit())
        && left.eq_ignore_ascii_case(right)
}

struct PriorEvidence {
    generation: u32,
    operation: String,
    replacement: String,
    terminal_digest: String,
    package_digest: String,
    manifest_digest: String,
    generation_digest: String,
    old_image_id: NativeObjectId,
    old_image_digest: String,
    old_image_length: u64,
}

impl PriorEvidence {
    fn join(documents: Vec<Document>, program: &CheckedPath, digest: &str, length: u64) -> Result<Self> {
        Self::checked_join(documents, program.as_path(), &program.native_id(), digest, length)
            .map_err(|error| format!("PriorAuthenticationUnavailable: {error}"))
    }

    fn checked_join(documents: Vec<Document>, program_path: &Path, program_id: &NativeObjectId,
        digest: &str, length: u64) -> Result<Self> {
        let (mut terminal, mut package, mut manifest, mut generation) = (None, None, None, None);
        for document in documents {
            let duplicate = match document {
                Document::Terminal(value, sha) => terminal.replace((value, sha)).is_some(),
                Document::Package(value, sha) => package.replace((value, sha)).is_some(),
                Document::Manifest(value, sha) => manifest.replace((value, sha)).is_some(),
                Document::Generation(value, size, sha) => generation.replace((value, size, sha)).is_some(),
            };
            if duplicate {
                return Err("multiple selected files have the same evidence role".into());
            }
        }
        let (terminal, terminal_digest) = terminal.ok_or("archived terminal receipt missing")?;
        let (package, package_digest) = package.ok_or("archived package receiving missing")?;
        let (manifest, manifest_digest) = manifest.ok_or("archived source manifest missing")?;
        let (generation, generation_length, generation_digest) = generation.ok_or("archived relay source missing")?;
        let receiving = terminal.receiving;
        windows_installation::validate_request_id(&terminal.operation_id)?;
        if receiving.operation != "reconcileBackgroundProfile" || receiving.result.is_err()
            || receiving.primary_result != Some(Ok(())) || receiving.restoration_result != Some(Ok(()))
            || receiving.restoration_pending || receiving.cancellation_received || !receiving.persistence_errors.is_empty()
        {
            return Err("archived operation did not receive a successful background transition".into());
        }
        let [replacement] = receiving.replacements.as_slice() else {
            return Err("archived receipt requires one unambiguous replacement result".into());
        };
        windows_installation::validate_request_id(&replacement.operation_id)?;
        let Observation::Present { native_id, snapshot } = &replacement.program_observation else {
            return Err("archived receipt lacks a positively received postimage".into());
        };
        if replacement.schema != 1 || replacement.kind != "background-program-native-replacement"
            || replacement.phase != "receiving" || !replacement.replace_result
            || !matches!(replacement.work.staged_observation, Observation::Missing)
            || native_id != program_id || replacement.expected_program_native_id == *program_id
            || replacement.source_native_id == *program_id
            || !windows_installation::same_windows_path(replacement.program.parse()?.as_path(), program_path)?
            || !windows_installation::same_windows_path(snapshot.path.parse()?.as_path(), program_path)?
            || length == 0 || snapshot.metadata.size != length || !same_digest(&snapshot.digest, digest)
            || replacement.validated_source.metadata.size != length
            || !same_digest(&replacement.validated_source.digest, digest)
        {
            return Err("archived successful postimage does not bind the exact current managed program".into());
        }
        let mut was_managed = false;
        for event in receiving.task_events {
            if let HistoricalEvent::Definition(role) = event {
                let program = WindowsLocalPath::parse(role.program.as_os_str())?;
                if role.origin == "Managed" && matches!(role.role.as_str(), "relay" | "watchdog")
                    && windows_installation::same_windows_path(program.as_path(), program_path)?
                {
                    was_managed = true;
                }
            }
        }
        if !was_managed {
            return Err("archived task evidence does not bind the managed postimage destination".into());
        }
        let source_path = replacement.validated_source.path.parse()?;
        let source_name = source_path.as_path().file_name().and_then(|name| name.to_str())
            .ok_or("archived selected executable name unavailable")?;
        if !source_path.as_path().extension().is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
            || package.file_count != package.files.len()
            || !same_digest(&package.source_manifest, &manifest_digest)
        {
            return Err("archived build receiving and source manifest disagree".into());
        }
        let package_exe = matching_entry(&package.files, source_name)?;
        let manifest_source = matching_entry(&manifest.files, GENERATION_SOURCE)?;
        if package_exe.length != length || !same_digest(&package_exe.sha256, digest) {
            return Err("archived build executable does not match the published postimage".into());
        }
        if manifest_source.length != generation_length || !same_digest(&manifest_source.sha256, &generation_digest) {
            return Err("archived generation source does not match the received source manifest".into());
        }
        Ok(Self { generation, operation: terminal.operation_id, replacement: replacement.operation_id.clone(),
            terminal_digest, package_digest, manifest_digest, generation_digest,
            old_image_id: program_id.clone(), old_image_digest: digest.to_owned(), old_image_length: length })
    }

    fn provenance(&self) -> Value {
        json!({
            "assurance": "OperatorAuthenticatedPrior",
            "priorOperationId": self.operation,
            "priorReplacementId": self.replacement,
            "generation": self.generation,
            "terminalSha256": self.terminal_digest,
            "packageReceivingSha256": self.package_digest,
            "sourceManifestSha256": self.manifest_digest,
            "generationSourceSha256": self.generation_digest,
            "priorPublishedPostimage": {
                "nativeId": self.old_image_id,
                "sha256": self.old_image_digest,
                "length": self.old_image_length,
            },
        })
    }
}
