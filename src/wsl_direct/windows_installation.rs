//! Single Windows installation authority. Unchecked choices become held
//! maintenance/run capabilities here; review placement never chooses authority.
#![cfg(windows)]
#[path = "windows_installation/ancestor_context.rs"]
mod ancestor_context;
#[path = "archive_install.rs"]
mod archive_install;
#[path = "windows_installation/context_native.rs"]
mod context_native;
#[path = "windows_installation/signature.rs"]
mod signature;
pub(crate) use ancestor_context::{
    owner_machine_wire, qualify_group, receive_ancestor_context, AncestorAccessContext,
    AncestorContextIdentity, AncestorInputs, DeploymentVerifier, OwnerScope, QualifiedGroup,
};
pub(crate) use native::{ObjectId as NativeObjectId, SourceSnapshot};
pub(crate) use signature::verify_signature;
#[path = "windows_installation/native.rs"]
mod native;
#[path = "windows_installation/background_program.rs"]
mod background_program;
#[cfg(test)]
pub(crate) use background_program::tests::fixture_writable_mapping;
pub(crate) use background_program::{BackgroundLocations, background_locations, background_process_name,
    LegacyBackgroundInput, legacy_background_input, BackgroundInputs, background_inputs, background_inputs_selected,
    BackgroundLease, BackgroundReplacementReceiving,
    BackgroundReplacementFailure, background_lease, wait_for_background_lease, checked_background_path,
    create_background_directory, create_background_executable, background_replace_program, background_replace_program_guarded};
#[cfg(test)]
pub(crate) use background_program::fail_next_source_capture_revalidation;
pub(crate) use native::{DiagnosticInputs, diagnostic_inputs,
    MetadataFailure, AcquiredCreation, OwnedUnwind,
    UserMetadataField, UserMetadataPublication, PendingUserMetadataPublication, PendingMetadataReceiving, PendingMetadataActual,
    receive_pending_user_metadata, preflight_user_metadata, publish_user_metadata, read_protected_user_metadata,
    receive_user_metadata_preflight, publish_user_metadata_checked, UserMetadataPreflight,
    PrivateCapturedFile as BackgroundDiagnosticFile,
    create_private_captured_file as create_background_diagnostic_file,
    read_private_captured_file as read_background_diagnostic_file};
#[cfg(test)]
pub(crate) use native::{fail_next_acquired_receiving_with_retained_witness, panic_next_acquired_receiving_with_retained_witness,
    fail_next_metadata_post_publish, test_reset_metadata_rename_trace, test_metadata_rename_count,
    fail_next_authored_capture_after_write, occupy_next_metadata_vacancy, fail_next_closed_stream_first_read,
    fail_next_metadata_partial_write, fail_metadata_rename_readback_after,
    change_creation_before_failed_metadata_rename_receiving, test_change_creation_during_metadata_settlement,
    test_displace_during_metadata_settlement, test_change_old_during_metadata_settlement};
#[path = "windows_installation/runtime_gate.rs"]
mod runtime_gate;
#[path = "windows_installation/runtime_deployment.rs"]
mod runtime_deployment;
use runtime_deployment::{DeploymentField, RuntimeDeployment};
#[path = "windows_installation/gateway_rules.rs"]
pub(crate) mod gateway_rules;
#[path = "windows_installation/runtime_upgrade.rs"]
mod runtime_upgrade;
pub(crate) use runtime_upgrade::{prepare_vendor_update, upgrade_runtime, rollback_runtime, VendorRuntimeInput, VendorUpdateCompletion};
#[path = "windows_installation/runtime_assets.rs"]
mod runtime_assets;
pub(crate) use runtime_assets::PackageAssets;
#[path = "windows_installation/legacy_guard.rs"]
mod legacy_guard;
pub(crate) use legacy_guard::{admit_legacy_write, admit_native_binary, canonical_installed, LegacyNativeWrite};
#[path = "../user_state_location.rs"]
mod user_state_location;
use super::desktop_hook;
pub(crate) use archive_install::MaintenanceWindow;
use native::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::atomic::{AtomicBool, Ordering};
type Result<T, E = String> = std::result::Result<T, E>;
const INSTALLATIONS_NAMESPACE: &str = "wsl-installations";
pub(crate) fn new_request_id() -> Result<String> { unique_id() }
pub(crate) fn validate_request_id(value: &str) -> Result<()> {
    if id_valid(value) { Ok(()) } else { Err("request ID must use the existing-owner 32-hex UUID encoding".into()) }
}
pub(crate) fn same_windows_path(a: &Path, b: &Path) -> Result<bool> {
    ordinal(&a.as_os_str().encode_wide().collect::<Vec<_>>(),
        &b.as_os_str().encode_wide().collect::<Vec<_>>())
}

/// Current-user product Settings writer, separate from installation/run roles.
/// The native lease is owned and released by this same GUI main thread.
pub(crate) struct SettingsWriterLease {
    _lease: Lease,
    _known: CheckedPath,
}
pub(crate) fn admit_settings_writer() -> Result<SettingsWriterLease> {
    let known = CheckedPath::open(&known_folder()?, PathKind::Directory, PathPurpose::Review)?;
    let lease = Lease::acquire(&known, "product_settings_v1")?;
    Ok(SettingsWriterLease { _lease: lease, _known: known })
}

/// Pure external namespace policy, shared by every Windows consumer.
#[derive(Clone, Debug)]
pub(crate) struct WindowsLocalPath(PathBuf);
impl WindowsLocalPath {
    /// A directory locator may carry a terminal directory separator. Decode
    /// that notation losslessly before applying the unchanged local-path
    /// grammar; interior components and file locators are never normalized.
    pub(crate) fn parse_directory_locator(value: &OsStr) -> Result<Self> {
        let mut units: Vec<_> = value.encode_wide().collect();
        while units.len() > 3 && units.last().is_some_and(|unit| *unit == 92 || *unit == 47) {
            units.pop();
        }
        Self::parse(OsString::from_wide(&units).as_os_str())
    }
    pub(crate) fn parse(value: &OsStr) -> Result<Self> {
        let p = Path::new(value);
        let units: Vec<_> = value.encode_wide().collect();
        if !p.is_absolute()
            || !matches!(p.components().next(), Some(Component::Prefix(x)) if matches!(x.kind(), Prefix::Disk(_)))
            || units
                .iter()
                .any(|c| *c < 32 || [34, 60, 62, 124, 63, 42].contains(c))
        {
            return Err("absolute ordinary local disk path required".into());
        }
        // Path::components normalizes interior '.'; inspect the original spelling too.
        for part in units
            .get(3..)
            .ok_or("missing disk root")?
            .split(|c| *c == 92 || *c == 47)
            .filter(|_| units.len() > 3)
        {
            if part.is_empty()
                || part == [46]
                || part == [46, 46]
                || part.contains(&58)
                || part.last().is_some_and(|c| *c == 32 || *c == 46)
            {
                return Err("empty/dot/stream/trailing alias component rejected".into());
            }
            let stem = part.split(|c| *c == 46).next().unwrap();
            let text = String::from_utf16_lossy(stem).to_ascii_uppercase();
            if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&text.as_str())
                || (["COM", "LPT"].iter().any(|p| {
                    text.strip_prefix(p).is_some_and(|n| {
                        ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"].contains(&n)
                    })
                }))
            {
                return Err("reserved device component rejected".into());
            }
        }
        Ok(Self(p.into()))
    }
    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}
#[derive(Clone, Debug)]
pub(crate) struct WindowsExecutablePath(WindowsLocalPath);
impl WindowsExecutablePath {
    pub(crate) fn parse(value: &OsStr) -> Result<Self> {
        let p = WindowsLocalPath::parse(value)?;
        if !p
            .0
            .extension()
            .is_some_and(|v| v.eq_ignore_ascii_case("exe"))
        {
            return Err("Windows .exe required".into());
        }
        Ok(Self(p))
    }
    pub(crate) fn as_path(&self) -> &Path {
        self.0.as_path()
    }
}
#[derive(Clone, Copy)]
pub(crate) enum PathKind {
    File,
    Directory,
}
#[derive(Clone, Copy)]
pub(crate) enum PathPurpose {
    Source,
    Executable,
    Review,
    ReplaceSource,
    ExternalLegacyInput,
}
pub(crate) struct CheckedPath {
    pub(super) file: File,
    _ancestors: Vec<File>,
    path: PathBuf,
    object: ObjectId,
    locator: Vec<u16>,
    purpose: PathPurpose,
}
impl CheckedPath {
    pub(crate) fn directory_locator_if_present(value: &OsStr) -> Result<Option<Self>> {
        let path = WindowsLocalPath::parse_directory_locator(value)?;
        match fs::symlink_metadata(NativeFsPath::from_path(path.as_path())?.as_path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io("directory locator observation", error)),
            Ok(_) => Self::open(path.as_path(), PathKind::Directory, PathPurpose::Source).map(Some),
        }
    }
    pub(crate) fn open(path: &Path, kind: PathKind, purpose: PathPurpose) -> Result<Self> {
        let directory_path;
        let path = if matches!(kind, PathKind::Directory) {
            directory_path = WindowsLocalPath::parse_directory_locator(path.as_os_str())?;
            directory_path.as_path()
        } else { path };
        validate_path(path)?;
        let ancestors = parents(path)?;
        let directory = matches!(kind, PathKind::Directory);
        let share = if directory {
            READ | WRITE
        } else if matches!(purpose, PathPurpose::ReplaceSource) {
            READ | DELETE
        } else {
            READ
        };
        let file = OpenOptions::new()
            .read(true)
            .share_mode(share)
            .custom_flags(OPEN_REPARSE | if directory { BACKUP_SEMANTICS } else { 0 })
            .open(NativeFsPath::from_path(path)?.as_path())
            .map_err(|e| io("open checked path", e))?;
        let info = information(&file)?;
        if info.attributes & REPARSE != 0 || (info.attributes & DIRECTORY != 0) != directory {
            return Err("reparse/type conflict".into());
        }
        if directory {
            case_insensitive(&file)?;
        } else if matches!(purpose, PathPurpose::Executable) {
            executable_identity(&file)?;
        } else {
            identity(&file)?;
        }
        let object = object_id(&file)?;
        let long = long_path(path)?;
        let reopened = OpenOptions::new()
            .read(true)
            .share_mode(share)
            .custom_flags(OPEN_REPARSE | if directory { BACKUP_SEMANTICS } else { 0 })
            .open(NativeFsPath::from_path(&long)?.as_path())
            .map_err(|e| io("open expanded path", e))?;
        if object_id(&reopened)? != object {
            return Err("expanded path identity conflict".into());
        }
        let locator = final_path(&file)?;
        Ok(Self {
            file,
            _ancestors: ancestors,
            path: long,
            object,
            locator,
            purpose,
        })
    }
    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn native_id(&self) -> ObjectId {
        self.object.clone()
    }
    pub(crate) fn security_digest(&self) -> Result<String> {
        Ok(hash(&security(self.file.as_raw_handle(), 1 | 4)?))
    }
    pub(crate) fn read_checked_snapshot(&self) -> Result<SourceSnapshot> {
        let mut file = self
            .file
            .try_clone()
            .map_err(|e| io("clone readonly input", e))?;
        read_checked_purpose(&mut file, &self.path, self.purpose)
    }
    pub(crate) fn read_snapshot(&self) -> Result<Vec<u8>> {
        Ok(self.read_checked_snapshot()?.bytes)
    }
    pub(crate) fn read(&mut self) -> Result<Vec<u8>> {
        Ok(read_checked_purpose(&mut self.file, &self.path, self.purpose)?.bytes)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        let kind = if information(&self.file)?.attributes & DIRECTORY != 0 {
            PathKind::Directory
        } else {
            PathKind::File
        };
        let fresh = Self::open(&self.path, kind, self.purpose)?;
        if fresh.object != self.object || !ordinal(&fresh.locator, &self.locator)? {
            return Err("checked path binding changed".into());
        }
        Ok(())
    }
    fn contains(&self, other: &CheckedPath) -> Result<bool> {
        if self.object == other.object {
            return Ok(true);
        }
        for handle in &other._ancestors {
            if object_id(handle)? == self.object {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
/// A not-yet-existing leaf is bound to its held real parent, never a guessed
/// file ID. Naming comparison is used only after native containment is proved.
#[derive(PartialEq, Eq)]
enum ProspectiveRelation {
    Outside,
    SameEntry,
    Descendant,
}
struct ProspectiveEntry {
    parent: CheckedPath,
    leaf: OsString,
}
impl ProspectiveEntry {
    fn open(path: &Path) -> Result<Self> {
        validate_path(path)?;
        absent(path)?;
        Ok(Self {
            parent: CheckedPath::open(
                path.parent().ok_or("prospective parent missing")?,
                PathKind::Directory,
                PathPurpose::Review,
            )?,
            leaf: path.file_name().ok_or("prospective leaf missing")?.into(),
        })
    }
    fn relation_to_reserved_directory(&self, reserved: &Path) -> Result<ProspectiveRelation> {
        let mut cursor = reserved.to_path_buf();
        let mut missing = Vec::<Vec<u16>>::new();
        let anchor = loop {
            match fs::symlink_metadata(NativeFsPath::from_path(&cursor)?.as_path()) {
                Ok(_) => {
                    break CheckedPath::open(&cursor, PathKind::Directory, PathPurpose::Review)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(
                        cursor
                            .file_name()
                            .ok_or("reserved location has no existing parent")?
                            .encode_wide()
                            .collect(),
                    );
                    cursor = cursor.parent().ok_or("reserved parent absent")?.into();
                }
                Err(e) => return Err(io("reserved directory observation", e)),
            }
        };
        if !anchor.contains(&self.parent)? {
            return Ok(ProspectiveRelation::Outside);
        }
        if missing.is_empty() {
            return Ok(ProspectiveRelation::Descendant);
        }
        fn parts(value: &[u16]) -> Vec<&[u16]> {
            value
                .split(|c| *c == 92)
                .filter(|p| !p.is_empty())
                .collect()
        }
        let base = parts(&anchor.locator);
        let parent = parts(&self.parent.locator);
        if parent.len() < base.len() {
            return Err("native prospective ancestry conflict".into());
        }
        for (a, b) in base.iter().zip(&parent) {
            if !ordinal(a, b)? {
                return Err("native prospective locator conflict".into());
            }
        }
        let mut relative = parent[base.len()..]
            .iter()
            .map(|p| p.to_vec())
            .collect::<Vec<_>>();
        relative.push(self.leaf.encode_wide().collect());
        missing.reverse();
        if relative.len() < missing.len() {
            return Ok(ProspectiveRelation::Outside);
        }
        for (a, b) in missing.iter().zip(&relative) {
            if !ordinal(a, b)? {
                return Ok(ProspectiveRelation::Outside);
            }
        }
        Ok(if relative.len() == missing.len() {
            ProspectiveRelation::SameEntry
        } else {
            ProspectiveRelation::Descendant
        })
    }
}
pub(crate) struct PreparedDeploymentOutput {
    entry: ProspectiveEntry,
}
pub(crate) struct BoundInstallation {
    executable: WindowsExecutablePath,
    exe: CheckedPath,
    parent: CheckedPath,
    root: CheckedPath,
    resources: CheckedPath,
    archive: CheckedPath,
    bytes: Vec<u8>,
    executable_digest: String,
    ancestor_context: Option<AncestorAccessContext>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    parent: ObjectId,
    root: ObjectId,
    resources: ObjectId,
    executable: ObjectId,
    archive: ObjectId,
    executable_digest: String,
    archive_digest: String,
    archive_metadata: FileIdentity,
}
impl Binding {
    fn contains_member(&self, id: &ObjectId) -> bool {
        &self.executable == id || &self.archive == id
    }
}
impl BoundInstallation {
    pub(crate) fn open(executable: &Path) -> Result<Self> {
        let parsed = WindowsExecutablePath::parse(executable.as_os_str())?;
        let mut exe = CheckedPath::open(parsed.as_path(), PathKind::File, PathPurpose::Executable)?;
        let executable = WindowsExecutablePath::parse(exe.as_path().as_os_str())?;
        let root = CheckedPath::open(
            exe.as_path().parent().ok_or("installation root")?,
            PathKind::Directory,
            PathPurpose::Source,
        )?;
        let parent = CheckedPath::open(
            root.as_path().parent().ok_or("installation parent")?,
            PathKind::Directory,
            PathPurpose::Source,
        )?;
        let resources = CheckedPath::open(
            &root.path.join("resources"),
            PathKind::Directory,
            PathPurpose::Source,
        )?;
        shadow_clear(&resources.path.join("app.asar"))?;
        let mut archive = CheckedPath::open(
            &resources.path.join("app.asar"),
            PathKind::File,
            PathPurpose::ReplaceSource,
        )?;
        let bytes = archive.read()?;
        let executable_digest = hash(&exe.read()?);
        Ok(Self {
            executable,
            exe,
            parent,
            root,
            resources,
            archive,
            bytes,
            executable_digest,
            ancestor_context: None,
        })
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn executable_digest(&self) -> &str {
        &self.executable_digest
    }
    pub(crate) fn executable(&self) -> &WindowsExecutablePath {
        &self.executable
    }
    pub(crate) fn native_root_id(&self) -> ObjectId { self.root.native_id() }
    pub(crate) fn native_executable_id(&self) -> ObjectId { self.exe.native_id() }
    pub(crate) fn resources(&self) -> &Path {
        &self.resources.path
    }
    pub(crate) fn recheck_archive(&mut self) -> Result<()> {
        if self.archive.read()? != self.bytes {
            return Err("MaintenanceRequired: selected archive changed".into());
        }
        shadow_clear(&self.archive.path)
    }
    fn binding(&self) -> Result<Binding> {
        Ok(Binding {
            parent: self.parent.object.clone(),
            root: self.root.object.clone(),
            resources: self.resources.object.clone(),
            executable: self.exe.object.clone(),
            archive: self.archive.object.clone(),
            executable_digest: self.executable_digest.clone(),
            archive_digest: hash(&self.bytes),
            archive_metadata: identity(&self.archive.file)?,
        })
    }
    fn outside(&self, path: &CheckedPath) -> Result<()> {
        if self.root.contains(path)? {
            Err("state/review/workspace is inside installation/updater tree".into())
        } else {
            Ok(())
        }
    }
    pub(crate) fn attach_ancestor_context(&mut self, context: AncestorAccessContext) -> Result<()> {
        context.revalidate()?;
        self.ancestor_context = Some(context);
        Ok(())
    }
    pub(crate) fn revalidate_context(&self) -> Result<()> {
        if let Some(c) = &self.ancestor_context {
            c.revalidate()?;
        }
        Ok(())
    }
    fn check_state_parent(&self, file: &File) -> Result<()> {
        if let Some(c) = &self.ancestor_context {
            if c.applies(file)? {
                return state_parent_context(file, c);
            }
        }
        state_parent(file)
    }
    fn check_ancestor(&self, file: &File) -> Result<()> {
        if let Some(c) = &self.ancestor_context {
            if c.applies(file)? {
                return c.check(file, true);
            }
        }
        ancestor_integrity(file)
    }
    pub(crate) fn ancestor_inputs(&self) -> Result<AncestorInputs> {
        let known = CheckedPath::open(&state_base()?, PathKind::Directory, PathPurpose::Review)?;
        self.outside(&known)?;
        let mut files = Vec::new();
        for p in [&known, &self.parent, &self.root, &self.resources] {
            for f in p._ancestors.iter().chain(std::iter::once(&p.file)) {
                files.push(
                    f.try_clone()
                        .map_err(|e| io("retain context ancestor", e))?,
                );
            }
        }
        let product = known.path.join(user_state_location::WINDOWS_STATE_LEAF);
        let namespace = product.join(INSTALLATIONS_NAMESPACE);
        for path in [&product, &namespace] {
            match fs::symlink_metadata(NativeFsPath::from_path(path)?.as_path()) {
                Ok(_) => {
                    let p = CheckedPath::open(path, PathKind::Directory, PathPurpose::Review)?;
                    self.outside(&p)?;
                    for f in p._ancestors.iter().chain(std::iter::once(&p.file)) {
                        files.push(
                            f.try_clone()
                                .map_err(|e| io("retain context state parent", e))?,
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io("context parent observation", e)),
            }
        }
        Ok(AncestorInputs::new(files))
    }
    #[cfg(test)]
    pub(crate) fn receive_state_parents_readonly(&self) -> Result<()> {
        namespace_paths(self).map(|_| ())
    }
    pub(crate) fn validate_deployment_output(
        &self,
        output: &Path,
    ) -> Result<PreparedDeploymentOutput> {
        let entry = ProspectiveEntry::open(output)?;
        self.outside(&entry.parent)?;
        let product = state_base()?.join(user_state_location::WINDOWS_STATE_LEAF);
        let namespace = product.join(INSTALLATIONS_NAMESPACE);
        if entry.relation_to_reserved_directory(&product)? == ProspectiveRelation::SameEntry {
            return Err("deployment DATA collides with reserved product root".into());
        }
        if entry.relation_to_reserved_directory(&namespace)? != ProspectiveRelation::Outside {
            return Err("deployment DATA collides with reserved installation namespace".into());
        }
        Ok(PreparedDeploymentOutput { entry })
    }
}
pub(crate) fn write_deployment_output(plan: PreparedDeploymentOutput, bytes: &[u8]) -> Result<()> {
    plan.entry.parent.recheck()?;
    write_private(&plan.entry.parent.path.join(&plan.entry.leaf), bytes)
}
pub(crate) fn write_deployment_data(path: &Path, bytes: &[u8]) -> Result<()> {
    write_private(path, bytes)
}
pub(crate) fn read_deployment_data(path: &Path) -> Result<Vec<u8>> {
    read_private(path)
}
/// One saved DATA location for all compositions. This performs no enrollment,
/// directory creation or actor qualification; the DATA receiver owns the latter.
pub(crate) fn saved_deployment_data_path() -> Result<PathBuf> {
    let known = CheckedPath::open(&state_base()?, PathKind::Directory, PathPurpose::Review)?;
    let product = known.path.join(user_state_location::WINDOWS_STATE_LEAF);
    match fs::symlink_metadata(NativeFsPath::from_path(&product)?.as_path()) {
        Ok(_) => {
            let parent = CheckedPath::open(&product, PathKind::Directory, PathPurpose::Review)?;
            Ok(parent
                .path
                .join(user_state_location::WINDOWS_WSL_DEPLOYMENT_DATA_LEAF))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(product.join(user_state_location::WINDOWS_WSL_DEPLOYMENT_DATA_LEAF))
        }
        Err(e) => Err(io("saved deployment DATA parent observation", e)),
    }
}
#[cfg(test)]
pub(crate) fn context_fixture_directory(parent: &Path) -> Result<PathBuf> {
    let p = CheckedPath::open(parent, PathKind::Directory, PathPurpose::Review)?;
    ancestor_integrity(&p.file)?;
    for f in &p._ancestors {
        ancestor_integrity(f)?;
    }
    let path = p.path.join(format!("context-check-{}", unique_id()?));
    create_private_dir(&path)?;
    Ok(path)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewManifest {
    schema: u32,
    operation: String,
    distro: String,
    version: String,
    desktop_sha256: String,
    preimage_sha256: String,
    candidate_sha256: String,
    preimage: String,
    candidate: String,
    input_hook_status: String,
    installed_mutation: bool,
}
pub(crate) struct ReviewedArchive {
    path: CheckedPath,
    _pins: Vec<CheckedPath>,
    preimage: Vec<u8>,
    candidate: desktop_hook::PreparedArchive,
    manifest_digest: String,
}
const LEGACY_FILES: [&str; 5] = [
    "manifest.json",
    "app.asar.preimage",
    "app.asar.candidate",
    "apply-intent.json",
    "apply-failure.json",
];
#[derive(Clone)]
pub(crate) struct ExpectedLegacyAttempt {
    digests: [String; 5],
}
impl ExpectedLegacyAttempt {
    pub(crate) fn from_hex(values: [&str; 5]) -> Result<Self> {
        let mut digests = Vec::new();
        for value in values {
            let bytes = hex::decode(value).map_err(|_| "malformed expected legacy SHA-256")?;
            if bytes.len() != 32 {
                return Err("expected legacy SHA-256 must contain exactly 32 bytes".into());
            }
            digests.push(hex::encode(bytes));
        }
        Ok(Self {
            digests: digests
                .try_into()
                .map_err(|_| "expected five legacy pins")?,
        })
    }
}
/// External evidence only. It cannot be passed to prepare_apply.
pub(crate) struct LegacyInput {
    directory: CheckedPath,
    directory_security: String,
    pins: Vec<CheckedPath>,
    identities: Vec<FileIdentity>,
    files: Vec<(String, Vec<u8>)>,
    expected: ExpectedLegacyAttempt,
}
impl LegacyInput {
    fn recheck(&self) -> Result<()> {
        self.directory.recheck()?;
        if self.directory.security_digest()? != self.directory_security {
            return Err("legacy input directory protection changed during receiving".into());
        }
        for (i, pin) in self.pins.iter().enumerate() {
            let fresh = CheckedPath::open(
                pin.as_path(),
                PathKind::File,
                PathPurpose::ExternalLegacyInput,
            )?;
            if fresh.object != pin.object || identity(&fresh.file)? != self.identities[i] {
                return Err("legacy original native identity/metadata changed".into());
            }
            let bytes = fresh.read_snapshot()?;
            if bytes != self.files[i].1 || hash(&bytes) != self.expected.digests[i] {
                return Err("legacy original bytes differ from caller-selected attempt".into());
            }
        }
        Ok(())
    }
}
pub(crate) fn receive_legacy_input(
    bound: &BoundInstallation,
    review: &Path,
    distro: &str,
    expected: &ExpectedLegacyAttempt,
) -> Result<LegacyInput> {
    let directory = CheckedPath::open(
        review,
        PathKind::Directory,
        PathPurpose::ExternalLegacyInput,
    )?;
    bound.outside(&directory)?;
    let directory_security = directory.security_digest()?;
    let mut pins = Vec::new();
    let mut identities = Vec::new();
    let mut files = Vec::new();
    for (i, name) in LEGACY_FILES.iter().enumerate() {
        let pin = CheckedPath::open(
            &directory.path.join(name),
            PathKind::File,
            PathPurpose::ExternalLegacyInput,
        )
        .map_err(|e| format!("legacy original {name}: {e}"))?;
        let before = identity(&pin.file)?;
        let bytes = pin.read_snapshot()?;
        if hash(&bytes) != expected.digests[i] || identity(&pin.file)? != before {
            return Err(format!(
                "legacy selected-attempt digest/native snapshot mismatch: {name}"
            ));
        }
        identities.push(before);
        files.push((name.to_string(), bytes));
        pins.push(pin);
    }
    validate_review_bytes(
        &bound.executable_digest,
        distro,
        &files[0].1,
        &files[1].1,
        &files[2].1,
    )?;
    let input = LegacyInput {
        directory,
        directory_security,
        pins,
        identities,
        files,
        expected: expected.clone(),
    };
    input.recheck()?;
    Ok(input)
}
fn validate_review_bytes(
    executable_digest: &str,
    distro: &str,
    manifest: &[u8],
    preimage: &[u8],
    candidate: &[u8],
) -> Result<desktop_hook::PreparedArchive> {
    let m: ReviewManifest =
        serde_json::from_slice(manifest).map_err(|e| format!("invalid review manifest: {e}"))?;
    let prepared = desktop_hook::prepare_archive(preimage).map_err(|e| e.to_string())?;
    if m.schema != 1
        || m.operation != "review-only"
        || m.installed_mutation
        || m.distro != distro
        || m.desktop_sha256 != executable_digest
        || m.preimage != "app.asar.preimage"
        || m.candidate != "app.asar.candidate"
        || m.preimage_sha256 != hash(preimage)
        || m.candidate_sha256 != hash(candidate)
        || m.input_hook_status != "Prepared"
        || prepared.version != m.version
        || prepared.bytes != candidate
        || prepared.hook_status != desktop_hook::HookStatus::Prepared
    {
        return Err("review binding/transform conflict".into());
    }
    Ok(prepared)
}
pub(crate) fn receive_review(
    bound: &BoundInstallation,
    review: &Path,
    distro: &str,
) -> Result<ReviewedArchive> {
    let path = CheckedPath::open(review, PathKind::Directory, PathPurpose::Review)?;
    bound.outside(&path)?;
    existing_private(&path.file)?;
    let mut pins = Vec::new();
    let mut bytes = Vec::new();
    for name in ["manifest.json", "app.asar.preimage", "app.asar.candidate"] {
        let mut p = CheckedPath::open(&path.path.join(name), PathKind::File, PathPurpose::Review)?;
        existing_private(&p.file)?;
        bytes.push(p.read()?);
        pins.push(p);
    }
    let prepared = validate_review_bytes(
        &bound.executable_digest,
        distro,
        &bytes[0],
        &bytes[1],
        &bytes[2],
    )?;
    Ok(ReviewedArchive {
        path,
        _pins: pins,
        preimage: bytes[1].clone(),
        candidate: prepared,
        manifest_digest: hash(&bytes[0]),
    })
}
pub(crate) fn stage_review(bound: &BoundInstallation, review: &Path, distro: &str) -> Result<()> {
    validate_path(review)?;
    absent(review)?;
    let parent = CheckedPath::open(
        review.parent().ok_or("review parent")?,
        PathKind::Directory,
        PathPurpose::Review,
    )?;
    bound.outside(&parent)?;
    let prepared = desktop_hook::prepare_archive(&bound.bytes).map_err(|e| e.to_string())?;
    create_private_dir(review)?;
    let result = (|| {
        let output = CheckedPath::open(review, PathKind::Directory, PathPurpose::Review)?;
        private(&output.file)?;
        bound.outside(&output)?;
        write_private(&output.path.join("app.asar.preimage"), &bound.bytes)?;
        write_private(&output.path.join("app.asar.candidate"), &prepared.bytes)?;
        let manifest = serde_json::json!({"schema":1,"operation":"review-only","distro":distro,"version":prepared.version,"desktopSha256":bound.executable_digest,"preimageSha256":prepared.pre_digest,"candidateSha256":prepared.post_digest,"preimage":"app.asar.preimage","candidate":"app.asar.candidate","inputHookStatus":format!("{:?}",prepared.hook_status),"installedMutation":false});
        write_private(&output.path.join("manifest.json"), &json(&manifest)?)?;
        receive_review(bound, review, distro)?;
        Ok(())
    })();
    result.map_err(|e: String| format!("{e}; retained partial/full review {}", review.display()))
}

struct NativeLayout {
    paths: InstallPaths,
    workspace: CheckedPath,
    resources: ObjectId,
    archive: ObjectId,
}
impl NativeLayout {
    fn verify(&self, target: &Path) -> Result<()> {
        self.workspace.recheck()?;
        for path in [
            &self.paths.staged,
            &self.paths.original_backup,
            &self.paths.displaced_backup,
        ] {
            absent(path)?;
        }
        let parent = CheckedPath::open(
            target.parent().ok_or("target parent")?,
            PathKind::Directory,
            PathPurpose::Source,
        )?;
        if CheckedPath::open(target, PathKind::File, PathPurpose::ReplaceSource)?.object
            != self.archive
        {
            return Err("prepared target native object changed".into());
        }
        if parent.object != self.resources || parent.object.volume != self.workspace.object.volume {
            return Err("native prepared layout binding/volume conflict".into());
        }
        Ok(())
    }
    #[cfg(test)]
    fn for_test(target: &Path, paths: InstallPaths) -> Result<Self> {
        let workspace = CheckedPath::open(
            paths.staged.parent().ok_or("test workspace")?,
            PathKind::Directory,
            PathPurpose::Review,
        )?;
        let resources = CheckedPath::open(
            target.parent().ok_or("target parent")?,
            PathKind::Directory,
            PathPurpose::Source,
        )?
        .object;
        let archive = CheckedPath::open(target, PathKind::File, PathPurpose::ReplaceSource)?.object;
        Ok(Self {
            paths,
            workspace,
            resources,
            archive,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceRef {
    path: String,
    digest: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Mode {
    Bootstrap,
    SettledUnchanged,
    SettledApplied,
    SettledReverted,
    Pending,
    Superseded,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum OperationKind {
    Apply,
    Revert,
    LegacyApply,
    UpgradeRuntime,
    RollbackRuntime,
    ConfigureGatewayRules,
    RetireGatewayRules,
    VendorUpdate,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operation {
    id: String,
    kind: OperationKind,
    intent: EvidenceRef,
    prior_current_digest: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetState {
    digest: String,
    metadata: FileIdentity,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Settled {
    target: TargetState,
    #[serde(deserialize_with = "required_option")]
    applied: Option<archive_install::AppliedArchive>,
    evidence: EvidenceRef,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Current {
    schema: u32,
    slot_id: String,
    revision: u64,
    locator: Vec<u16>,
    binding: Binding,
    mode: Mode,
    #[serde(deserialize_with = "required_option")]
    active_operation: Option<Operation>,
    #[serde(deserialize_with = "required_option")]
    settled: Option<Settled>,
    #[serde(default, skip_serializing_if = "DeploymentField::is_absent")]
    runtime_deployment: DeploymentField,
}
impl Current {
    fn require_operation_authority(&self) -> Result<()> {
        if self.mode == Mode::Superseded {
            return Err("MaintenanceRequired: canonical slot was superseded".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LayoutBinding {
    workspace: PathBuf,
    workspace_id: ObjectId,
    staged: PathBuf,
    original_backup: PathBuf,
    displaced_backup: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    schema: u32,
    slot_id: String,
    operation_id: String,
    kind: OperationKind,
    expected_current_digest: String,
    prior_current: EvidenceRef,
    binding: Binding,
    layout: LayoutBinding,
    preimage: EvidenceRef,
    #[serde(deserialize_with = "required_option")]
    candidate: Option<EvidenceRef>,
    #[serde(deserialize_with = "required_option")]
    review_manifest: Option<EvidenceRef>,
    #[serde(deserialize_with = "required_option")]
    review_manifest_digest: Option<String>,
    #[serde(deserialize_with = "required_option")]
    prior_applied: Option<archive_install::AppliedArchive>,
    #[serde(deserialize_with = "required_option")]
    legacy: Option<LegacyImport>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum NativeCall {
    NotCalled,
    ReturnedFailure,
    ReturnedSuccess,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum ResolutionDecision {
    NoNativeCallConfirmed,
    AppliedConfirmed,
    RevertedConfirmed,
    RestoredConfirmed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Outcome {
    schema: u32,
    slot_id: String,
    operation_id: String,
    intent: EvidenceRef,
    native_call: NativeCall,
    target: TargetState,
    #[serde(deserialize_with = "required_option")]
    applied: Option<archive_install::AppliedArchive>,
    layout: LayoutBinding,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Resolution {
    schema: u32,
    slot_id: String,
    resolves_operation_id: String,
    intent_digest: String,
    expected_current_digest: String,
    pending_current: EvidenceRef,
    #[serde(deserialize_with = "required_option")]
    failure: Option<EvidenceRef>,
    decision: ResolutionDecision,
    observations: Vec<(PathBuf, archive_install::FileObservation)>,
    outcome: Outcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Supersession {
    schema: u32,
    slot_id: String,
    pending_current: EvidenceRef,
    operation_id: String,
    intent: EvidenceRef,
    historical_success: EvidenceRef,
    observed_binding: Binding,
}

const SUPERSESSION_COMPANION: &str = "supersession.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SupersessionCompanion {
    pending_revision: u64,
    locator: Vec<u16>,
    evidence: Supersession,
}

struct SupersededHistory {
    pending: Binding,
    applied: Binding,
    runtime_objects: [ObjectId; 4],
}

struct ReceivedSlotCurrent {
    current: Current,
    digest: String,
    aliases: Vec<Binding>,
    runtime_objects: Vec<ObjectId>,
    companion_issue: Option<String>,
}
impl ReceivedSlotCurrent {
    fn keep_history(&mut self, history: SupersededHistory) {
        self.aliases.extend([history.pending, history.applied]);
        self.runtime_objects.extend(history.runtime_objects);
    }

    fn check_companion(&self) -> Result<()> {
        match &self.companion_issue {
            Some(cause) => Err(format!("RecoveryRequired: supersession companion is unconfirmed: {cause}")),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
enum Settlement {
    Enrollment(TargetState),
    Outcome(Outcome),
    Resolution(Resolution),
    RuntimeUpgrade(runtime_upgrade::UpgradeOutcome),
    GatewayRules(gateway_rules::GatewayOutcome),
    VendorUpdate(runtime_upgrade::VendorUpdateOutcome),
    Supersession(Supersession),
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value).map_err(|e| e.to_string())
}
fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| format!("canonical state/evidence invalid: {e}"))
}
fn object_state(snapshot: &SourceSnapshot) -> TargetState {
    TargetState {
        digest: snapshot.digest.clone(),
        metadata: snapshot.identity.clone(),
    }
}
fn id_valid(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
fn read_private(path: &Path) -> Result<Vec<u8>> {
    let mut p = CheckedPath::open(path, PathKind::File, PathPurpose::Review)?;
    private(&p.file)?;
    p.read()
}
fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(NativeFsPath::from_path(path)?.as_path()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io("vacancy observation", e)),
        Ok(_) => Err(format!("owned name occupied: {}", path.display())),
    }
}
fn shadow_clear(target: &Path) -> Result<()> {
    absent(&target.parent().ok_or("archive parent")?.join("app"))
        .map_err(|_| "MaintenanceRequired: resources/app shadow conflict".into())
}

/// No environment override exists in production; fixtures inject only here.
fn state_base() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_BASE.with(|v| v.borrow().clone()) {
        return Ok(path);
    }
    known_folder()
}
struct Authority {
    known: CheckedPath,
    _product: CheckedPath,
    namespace: CheckedPath,
    slot: CheckedPath,
    lease: Lease,
    current: Current,
    digest: String,
    runtime_write: Option<runtime_gate::WriteGate>,
}
fn namespace_paths(bound: &BoundInstallation) -> Result<(CheckedPath, PathBuf, PathBuf)> {
    bound.revalidate_context()?;
    let known = CheckedPath::open(&state_base()?, PathKind::Directory, PathPurpose::Review)?;
    bound.outside(&known)?;
    // Owner ancestry cannot be redirectable by a different ordinary account.
    bound.check_state_parent(&known.file)?;
    for ancestor in &known._ancestors {
        bound.check_ancestor(ancestor)?;
    }
    let product = known.path.join(user_state_location::WINDOWS_STATE_LEAF);
    let namespace = product.join(INSTALLATIONS_NAMESPACE);
    for path in [&product, &namespace] {
        match fs::symlink_metadata(NativeFsPath::from_path(path)?.as_path()) {
            Ok(_) => {
                let p = CheckedPath::open(path, PathKind::Directory, PathPurpose::Review)?;
                bound.outside(&p)?;
                if path == &product {
                    bound.check_state_parent(&p.file)?;
                } else {
                    private(&p.file)?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io("namespace observation", e)),
        }
    }
    Ok((known, product, namespace))
}
fn current_shape(c: &Current, id: &str) -> Result<()> {
    if !matches!(c.schema, 2 | 3) || c.slot_id != id || !id_valid(id) || c.revision == 0 || c.locator.is_empty()
    {
        return Err("canonical current binding/schema invalid".into());
    }
    c.runtime_deployment.validate_schema(c.schema)?;
    if matches!(c.runtime_deployment, DeploymentField::Present(Some(_)))
        && !matches!(c.mode, Mode::Pending | Mode::SettledApplied) {
        return Err("canonical runtime deployment/mode conflict".into());
    }
    match c.mode {
        Mode::Pending if c.active_operation.is_some() && c.settled.is_none() => {}
        Mode::Bootstrap if c.active_operation.is_none() && c.settled.is_none() => {}
        Mode::SettledApplied
            if c.active_operation.is_none()
                && c.settled.as_ref().is_some_and(|s| s.applied.is_some()) => {}
        Mode::SettledUnchanged | Mode::SettledReverted
            if c.active_operation.is_none()
                && c.settled.as_ref().is_some_and(|s| s.applied.is_none()) => {}
        Mode::Superseded
            if c.schema == 3
                && matches!(c.runtime_deployment, DeploymentField::Present(None))
                && c.active_operation.is_none()
                && c.settled.as_ref().is_some_and(|s| s.applied.is_none()) => {}
        _ => return Err("canonical current mode/evidence contradiction".into()),
    }
    Ok(())
}
fn reference(slot: &CheckedPath, r: &EvidenceRef) -> Result<Vec<u8>> {
    let relative = Path::new(&r.path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("evidence reference escape".into());
    }
    let path = slot.path.join(relative);
    let p = CheckedPath::open(&path, PathKind::File, PathPurpose::Review)?;
    if !slot.contains(&p)? {
        return Err("evidence outside slot".into());
    }
    private(&p.file)?;
    drop(p);
    let bytes = read_private(&path)?;
    if hash(&bytes) != r.digest {
        return Err("immutable evidence digest mismatch".into());
    }
    Ok(bytes)
}
fn validate_legacy_evidence(slot: &CheckedPath, intent: &Intent) -> Result<()> {
    if intent.kind != OperationKind::LegacyApply {
        return Ok(());
    }
    let legacy = intent
        .legacy
        .as_ref()
        .ok_or("legacy pending provenance absent")?;
    if legacy.files.len() != 5 || legacy.source_native_ids.len() != 5 || !legacy.missing.is_empty()
    {
        return Err("legacy selected-attempt evidence incomplete".into());
    }
    for (i, reference_value) in legacy.files.iter().enumerate() {
        if Path::new(&reference_value.path).file_name() != Some(OsStr::new(LEGACY_FILES[i]))
            || reference_value.digest != legacy.expected_files[i]
        {
            return Err("legacy canonical copy differs from caller expected five".into());
        }
        reference(slot, reference_value)?;
    }
    Ok(())
}
fn receive_current(slot: &CheckedPath) -> Result<(Current, String)> {
    let received = receive_current_with_supersession(slot)?;
    received.check_companion()?;
    Ok((received.current, received.digest))
}
fn receive_raw_current(slot: &CheckedPath) -> Result<ReceivedSlotCurrent> {
    let bytes = read_private(&slot.path.join("current.json"))?;
    let c: Current = decode(&bytes)?;
    current_shape(
        &c,
        slot.path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("slot identity encoding")?,
    )?;
    for entry in fs::read_dir(NativeFsPath::from_path(&slot.path)?.as_path()).map_err(|e| io("slot current residue", e))? {
        let entry = entry.map_err(|e| io("slot entry", e))?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("current.next.")
        {
            return Err(format!(
                "RecoveryRequired: unresolved metadata publication at {}",
                slot.path.display()
            ));
        }
    }
    if let Some(op) = &c.active_operation {
        if matches!(op.kind, OperationKind::VendorUpdate) {
            runtime_upgrade::receive_vendor_pending(slot, &c, op)?;
        } else if matches!(op.kind, OperationKind::UpgradeRuntime | OperationKind::RollbackRuntime) {
            runtime_upgrade::receive_pending(slot, &c, op)?;
        } else if matches!(op.kind, OperationKind::ConfigureGatewayRules | OperationKind::RetireGatewayRules) {
            gateway_rules::receive_pending(slot, &c, op)?;
        } else {
        let i: Intent = decode(&reference(slot, &op.intent)?)?;
        if i.schema != 2
            || i.slot_id != c.slot_id
            || i.operation_id != op.id
            || i.kind != op.kind
            || i.expected_current_digest != op.prior_current_digest
            || hash(&reference(slot, &i.prior_current)?) != i.expected_current_digest
        {
            return Err("pending operation/intent binding mismatch".into());
        }
        validate_legacy_evidence(slot, &i)?;
        reference(slot, &i.preimage)?;
        if let Some(r) = &i.candidate {
            reference(slot, r)?;
        }
        if let Some(r) = &i.review_manifest {
            reference(slot, r)?;
        }
        }
    }
    let history = if c.mode == Mode::Superseded {
        Some(receive_supersession(slot, &c)?)
    } else {
        if c.settled.is_some() { receive_settlement(slot, &c)?; }
        None
    };
    if c.mode == Mode::SettledApplied {
        if let DeploymentField::Present(Some(deployment)) = &c.runtime_deployment {
            deployment.receive_receipt(slot)?;
        }
    }
    let mut received = ReceivedSlotCurrent { current: c, digest: hash(&bytes), aliases: Vec::new(),
        runtime_objects: Vec::new(), companion_issue: None };
    if let Some(history) = history { received.keep_history(history); }
    Ok(received)
}
fn receive_supersession(slot: &CheckedPath, current: &Current) -> Result<SupersededHistory> {
    let settled = current.settled.as_ref().ok_or("supersession evidence absent")?;
    let Settlement::Supersession(evidence) = decode(&reference(slot, &settled.evidence)?)? else {
        return Err("supersession evidence kind conflict".into());
    };
    let pending: Current = decode(&reference(slot, &evidence.pending_current)?)?;
    if evidence.pending_current.path != format!("current.previous.{}.json", pending.revision) {
        return Err("supersession retained Pending path conflict".into());
    }
    validate_supersession(slot, current, &pending, &evidence)
}
fn validate_supersession(slot: &CheckedPath, current: &Current, pending: &Current, evidence: &Supersession)
    -> Result<SupersededHistory> {
    let settled = current.settled.as_ref().ok_or("supersession evidence absent")?;
    let observed = &evidence.observed_binding;
    let digest_valid = |value: &str| value.len() == 64
        && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if evidence.schema != 1 || evidence.slot_id != current.slot_id
        || observed != &current.binding || settled.target.digest != observed.archive_digest
        || settled.target.metadata != observed.archive_metadata
        || !digest_valid(&observed.executable_digest) || !digest_valid(&observed.archive_digest) {
        return Err("supersession observed binding conflict".into());
    }
    current_shape(pending, &current.slot_id)?;
    let operation = pending.active_operation.as_ref().ok_or("supersession retained Pending operation absent")?;
    if pending.mode != Mode::Pending || operation.kind != OperationKind::VendorUpdate
        || !id_valid(&operation.id) || operation.id != evidence.operation_id || operation.intent != evidence.intent
        || pending.locator != current.locator || pending.revision.checked_add(1) != Some(current.revision) {
        return Err("supersession retained Pending binding conflict".into());
    }
    let history = runtime_upgrade::receive_superseded_vendor_history(slot, pending, operation, &evidence.historical_success)?;
    if observed.executable_digest == history.applied.executable_digest
        && observed.archive_digest == history.applied.archive_digest {
        return Err("supersession observed bytes still match historical success".into());
    }
    Ok(history)
}

fn receive_companion_file(slot: &CheckedPath) -> Result<Option<(SupersessionCompanion, EvidenceRef)>> {
    let path = slot.path.join(SUPERSESSION_COMPANION);
    match fs::symlink_metadata(NativeFsPath::from_path(&path)?.as_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io("supersession companion observation", error)),
        Ok(_) => {}
    }
    let bytes = read_private(&path)?;
    let evidence = EvidenceRef { path: SUPERSESSION_COMPANION.into(), digest: hash(&bytes) };
    Ok(Some((decode(&bytes)?, evidence)))
}

fn companion_operation<'a>(pending: &'a Current, digest: &str, companion: &SupersessionCompanion) -> Result<&'a Operation> {
    let operation = pending.active_operation.as_ref().ok_or("supersession Pending operation absent")?;
    let evidence = &companion.evidence;
    if pending.mode != Mode::Pending || operation.kind != OperationKind::VendorUpdate
        || companion.pending_revision != pending.revision || companion.locator != pending.locator
        || evidence.slot_id != pending.slot_id || evidence.pending_current.path != "current.json"
        || evidence.pending_current.digest != digest || evidence.operation_id != operation.id || evidence.intent != operation.intent {
        return Err("supersession companion Pending binding conflict".into());
    }
    Ok(operation)
}

fn project_companion(slot: &CheckedPath, pending: &Current, digest: &str, companion: &SupersessionCompanion, evidence: EvidenceRef)
    -> Result<(Current, SupersededHistory)> {
    companion_operation(pending, digest, companion)?;
    let binding = companion.evidence.observed_binding.clone();
    let current = Current { schema: 3, slot_id: pending.slot_id.clone(),
        revision: pending.revision.checked_add(1).ok_or("supersession revision overflow")?,
        locator: pending.locator.clone(), mode: Mode::Superseded, active_operation: None,
        settled: Some(Settled { target: TargetState { digest: binding.archive_digest.clone(),
            metadata: binding.archive_metadata.clone() }, applied: None, evidence }),
        binding, runtime_deployment: DeploymentField::Present(None) };
    let history = validate_supersession(slot, &current, pending, &companion.evidence)?;
    Ok((current, history))
}

fn receive_current_with_supersession(slot: &CheckedPath) -> Result<ReceivedSlotCurrent> {
    let mut received = receive_raw_current(slot)?;
    let cause = match receive_companion_file(slot) {
        Ok(None) => return Ok(received),
        Ok(Some((companion, evidence))) => match project_companion(slot, &received.current, &received.digest, &companion, evidence) {
            Ok((current, history)) => {
                received.current = current;
                received.keep_history(history);
                return Ok(received);
            }
            Err(cause) => cause,
        },
        Err(cause) => cause,
    };
    if let Some(operation) = received.current.active_operation.as_ref().filter(|op| op.kind == OperationKind::VendorUpdate) {
        if let Ok(binding) = runtime_upgrade::receive_vendor_intended_binding(slot, &received.current, operation) {
            received.aliases.push(binding);
        }
        if let Ok(Some(evidence)) = runtime_upgrade::vendor_success_reference(slot, operation) {
            if let Ok(history) = runtime_upgrade::receive_superseded_vendor_history(slot, &received.current, operation, &evidence) {
                received.keep_history(history);
            }
        }
    }
    received.companion_issue = Some(cause);
    Ok(received)
}
fn receive_settlement(slot: &CheckedPath, c: &Current) -> Result<(TargetState, Option<archive_install::AppliedArchive>)> {
    c.require_operation_authority()?;
    let settled = c.settled.as_ref().ok_or("canonical settlement absent")?;
    let evidence: Settlement = decode(&reference(slot, &settled.evidence)?)?;
    let (target, applied) = match evidence {
        Settlement::Enrollment(target) if c.mode == Mode::SettledUnchanged => (target, None),
        Settlement::Outcome(outcome) => {
            validate_outcome(slot, c, &outcome)?;
            if outcome.native_call != NativeCall::ReturnedSuccess { return Err("settlement outcome native status invalid".into()); }
            (outcome.target, outcome.applied)
        }
        Settlement::Resolution(resolution) => {
            if resolution.schema != 2 || resolution.slot_id != c.slot_id
                || resolution.resolves_operation_id != resolution.outcome.operation_id
                || resolution.intent_digest != resolution.outcome.intent.digest
                || hash(&reference(slot, &resolution.pending_current)?) != resolution.expected_current_digest {
                return Err("settlement resolution binding invalid".into());
            }
            validate_outcome(slot, c, &resolution.outcome)?;
            let old: Current = decode(&reference(slot, &resolution.pending_current)?)?;
            let operation = old.active_operation.ok_or("resolution prior Pending operation absent")?;
            if old.mode != Mode::Pending || operation.id != resolution.resolves_operation_id
                || operation.intent != resolution.outcome.intent {
                return Err("resolution does not discharge exact prior operation".into());
            }
            (resolution.outcome.target, resolution.outcome.applied)
        }
        Settlement::RuntimeUpgrade(outcome) => runtime_upgrade::receive_settled(slot, c, &outcome)?,
        Settlement::GatewayRules(outcome) => gateway_rules::receive_settled(slot, c, &outcome)?,
        Settlement::VendorUpdate(outcome) => runtime_upgrade::receive_vendor_settled(slot, c, &outcome)?,
        _ => return Err("settlement evidence kind conflict".into()),
    };
    if target != settled.target || json(&applied)? != json(&settled.applied)? {
        return Err("settlement payload differs from current state".into());
    }
    Ok((target, applied))
}
fn validate_outcome(slot: &CheckedPath, current: &Current, outcome: &Outcome) -> Result<()> {
    let intent: Intent = decode(&reference(slot, &outcome.intent)?)?;
    validate_legacy_evidence(slot, &intent)?;
    if outcome.schema != 2
        || outcome.slot_id != current.slot_id
        || intent.slot_id != current.slot_id
        || intent.operation_id != outcome.operation_id
        || outcome.target.digest != current.binding.archive_digest
        || outcome.target.metadata != current.binding.archive_metadata
    {
        return Err("outcome/current/intent binding mismatch".into());
    }
    if hash(&reference(slot, &intent.preimage)?) != intent.binding.archive_digest {
        return Err("outcome retained full preimage mismatch".into());
    }
    if let Some(applied) = &outcome.applied {
        if applied.pre_digest != intent.binding.archive_digest
            && intent.kind != OperationKind::Revert
            || applied.post_digest != outcome.target.digest
            || applied.post != outcome.target.metadata
        {
            return Err("outcome applied source/result contradiction".into());
        }
    }
    Ok(())
}
fn lookup(
    namespace: &CheckedPath,
    bound: &BoundInstallation,
) -> Result<Option<(CheckedPath, Current, String)>> {
    let binding = bound.binding()?;
    let mut selected = None;
    for entry in fs::read_dir(NativeFsPath::from_path(&namespace.path)?.as_path()).map_err(|e| io("authority lookup", e))? {
        let entry = entry.map_err(|e| io("authority entry", e))?;
        let id = entry.file_name();
        if !id.to_str().is_some_and(id_valid) {
            return Err("AuthorityAmbiguous: unknown namespace entry".into());
        }
        let ordinary_path = namespace.path.join(&id);
        let slot = CheckedPath::open(&ordinary_path, PathKind::Directory, PathPurpose::Review)?;
        private(&slot.file)?;
        let received = receive_current_with_supersession(&slot)
            .map_err(|e| format!("BindingUnavailable: {}: {e}", ordinary_path.display()))?;
        let current = &received.current;
        let same_location = ordinal(&current.locator, &bound.root.locator)?;
        let same_leaf = ordinal(
            current
                .locator
                .rsplit(|c| *c == 92)
                .next()
                .ok_or("saved locator leaf")?,
            bound
                .root
                .locator
                .rsplit(|c| *c == 92)
                .next()
                .ok_or("selected locator leaf")?,
        )?;
        let same_object = current.binding.root == binding.root
            || current.binding.resources == binding.resources
            || (current.binding.parent == binding.parent && same_leaf);
        let superseded_alias = (!received.aliases.is_empty() || received.companion_issue.is_some()) &&
            std::iter::once(&current.binding).chain(&received.aliases).any(|protected| {
                protected.root == binding.root || protected.resources == binding.resources
                    || (same_leaf && protected.parent == binding.parent)
                    || protected.contains_member(&binding.executable) || protected.contains_member(&binding.archive)
            });
        if same_location || same_object || superseded_alias {
            received.check_companion()?;
            if selected.is_some() {
                return Err("AuthorityAmbiguous: multiple matching slots".into());
            }
            if !same_location {
                return Err("LocatorConflict: moved installation requires explicit rebind".into());
            }
            selected = Some((slot, received.current, received.digest));
        }
    }
    Ok(selected)
}
impl Authority {
    fn open(bound: &BoundInstallation, enroll: bool, recover: bool) -> Result<Self> {
        Self::open_inner(bound, enroll, recover, None).map_err(ApplyCurrentReadError::into_owner_error)
    }
    fn open_vendor_update(bound: &BoundInstallation, expected: &str) -> Result<Self> {
        Self::open_inner(bound, false, false, Some(expected)).map_err(ApplyCurrentReadError::into_owner_error)
    }
    fn open_inner(bound: &BoundInstallation, enroll: bool, recover: bool, vendor_expected: Option<&str>)
        -> Result<Self, ApplyCurrentReadError> {
        let (known, product_path, namespace_path) = namespace_paths(bound)?;
        let namespace_lock = Lease::try_acquire(&known, "wsl_namespace_v2")?
            .ok_or(ApplyCurrentReadError::Busy(ApplyCurrentLease::Namespace))?;
        if !enroll && !namespace_path.exists() {
            return Err("UnreceivedInstallation: canonical authority absent".into());
        }
        let mut footprint = Vec::new();
        let result = (|| -> Result<_, ApplyCurrentReadError> {
            for path in [&product_path, &namespace_path] {
                if !path.exists() {
                    if !enroll {
                        return Err("UnreceivedInstallation: canonical authority absent".into());
                    }
                    create_private_dir(path)?;
                    footprint.push(path.clone());
                }
            }
            #[cfg(test)]
            if TEST_BOOTSTRAP_FAILURE.with(|v| v.replace(false)) {
                return Err("injected B1 post-directory receiving failure".into());
            }
            let product =
                CheckedPath::open(&product_path, PathKind::Directory, PathPurpose::Review)?;
            bound.check_state_parent(&product.file)?;
            let namespace =
                CheckedPath::open(&namespace_path, PathKind::Directory, PathPurpose::Review)?;
            private(&namespace.file)?;
            let selected = lookup(&namespace, bound)?;
            let (slot, current, digest) = match selected {
                Some((slot, current, digest)) => {
                    current.require_operation_authority()?;
                    (slot, current, digest)
                }
                None => {
                    if !enroll {
                        return Err("UnreceivedInstallation: no canonical slot".into());
                    }
                    if desktop_hook::inspect_archive(&bound.bytes)
                        .map_err(|e| e.to_string())?
                        .hook_status
                        != desktop_hook::HookStatus::Prepared
                    {
                        return Err(
                            "UnreceivedInstallation: hooked/unknown target cannot enroll pristine"
                                .into(),
                        );
                    }
                    let id = unique_id()?;
                    let slot_path = namespace.path.join(&id);
                    create_private_dir(&slot_path)?;
                    footprint.push(slot_path.clone());
                    let slot =
                        CheckedPath::open(&slot_path, PathKind::Directory, PathPurpose::Review)?;
                    private(&slot.file)?;
                    let current = Current {
                        schema: 2,
                        slot_id: id,
                        revision: 1,
                        locator: bound.root.locator.clone(),
                        binding: bound.binding()?,
                        mode: Mode::Bootstrap,
                        active_operation: None,
                        settled: None,
                        runtime_deployment: DeploymentField::Absent,
                    };
                    let bytes = json(&current)?;
                    write_private(&slot.path.join("current.json"), &bytes)?;
                    (slot, current, hash(&bytes))
                }
            };
            #[cfg(test)]
            if TEST_BOOTSTRAP_SLOT_FAILURE.with(|v| v.replace(false)) {
                return Err("injected B1 post-current initialization receiving failure".into());
            }
            let lease = Lease::try_acquire(&slot, "wsl_slot_v2")?
                .ok_or(ApplyCurrentReadError::Busy(ApplyCurrentLease::Slot))?;
            Ok((product, namespace, slot, current, digest, lease))
        })();
        let (product, namespace, slot, current, digest, lease) = result.map_err(|e| {
            if footprint.is_empty() {
                e
            } else {
                format!("PreparationIncomplete: {}; preserved bootstrap footprint={footprint:?}", e.into_owner_error()).into()
            }
        })?;
        drop(namespace_lock);
        let mut a = Self {
            known,
            _product: product,
            namespace,
            slot,
            lease,
            current,
            digest,
            runtime_write: None,
        };
        if a.current.mode == Mode::Pending && !recover {
            return Err(format!(
                "RecoveryRequired: slot {} operation {} is Pending",
                a.current.slot_id,
                a.current.active_operation.as_ref().unwrap().id
            ).into());
        }
        if a.current.mode == Mode::Bootstrap && recover {
            return Ok(a);
        }
        if a.current.mode == Mode::Bootstrap {
            // Fresh initialization only; interrupted Bootstrap is never resumed implicitly.
            if !footprint.contains(&a.slot.path) {
                return Err("PreparationIncomplete: existing Bootstrap requires explicit initialization recovery".into());
            }
            let target = TargetState {
                digest: hash(&bound.bytes),
                metadata: identity(&bound.archive.file)?,
            };
            let evidence = a.evidence_dir("enrollment")?;
            let r = a.save(
                &evidence,
                "enrollment.json",
                &json(&Settlement::Enrollment(target.clone()))?,
            )?;
            let mut c = a.current.clone();
            c.revision = c
                .revision
                .checked_add(1)
                .ok_or("canonical revision overflow")?;
            c.mode = Mode::SettledUnchanged;
            c.settled = Some(Settled {
                target,
                applied: None,
                evidence: r,
            });
            a.publish(c)?;
        }
        if !recover {
            if let Some(expected) = vendor_expected {
                if a.digest != expected || a.current.mode != Mode::SettledApplied
                    || !ordinal(&a.current.locator, &bound.root.locator)?
                    || a.current.binding == bound.binding()? {
                    return Err("UpdatePending: selected vendor update does not bind the expected settled prior incarnation".into());
                }
                a.current.runtime_deployment.received()?.receive_receipt(&a.slot)?;
            } else {
                a.check_bound(bound)?;
            }
        }
        Ok(a)
    }
    fn check_bound(&self, bound: &BoundInstallation) -> Result<()> {
        if self.current.binding != bound.binding()? {
            return Err("UpdatePending: native installation incarnation changed".into());
        }
        if self.current.mode == Mode::Pending || self.current.mode == Mode::Bootstrap {
            return Err("RecoveryRequired: installation not settled".into());
        }
        Ok(())
    }
    fn admit_maintenance_gate(&mut self) -> Result<()> {
        if let DeploymentField::Present(Some(deployment)) = &self.current.runtime_deployment {
            if self.runtime_write.is_none() {
                self.runtime_write = Some(runtime_gate::write(&self.slot, &deployment.gate.native_id)?);
                let (_, digest) = receive_current(&self.slot)?;
                if digest != self.digest { return Err("RecoveryRequired: current changed during writer admission".into()); }
            }
        }
        Ok(())
    }
    fn evidence_dir(&self, prefix: &str) -> Result<PathBuf> {
        let path = self.slot.path.join(format!("{prefix}-{}", unique_id()?));
        create_private_dir(&path)?;
        Ok(path)
    }
    fn save(&self, dir: &Path, name: &str, bytes: &[u8]) -> Result<EvidenceRef> {
        let p = dir.join(name);
        write_private(&p, bytes)?;
        let relative = p
            .strip_prefix(&self.slot.path)
            .map_err(|_| "owned evidence location")?;
        Ok(EvidenceRef {
            path: relative
                .to_str()
                .ok_or("evidence path encoding")?
                .replace('\\', "/"),
            digest: hash(bytes),
        })
    }
    fn retain_current(&self) -> Result<EvidenceRef> {
        let path = self
            .slot
            .path
            .join(format!("current.previous.{}.json", self.current.revision));
        let bytes = read_private(&self.slot.path.join("current.json"))?;
        if hash(&bytes) != self.digest {
            return Err("current changed before prior-state retention".into());
        }
        match fs::symlink_metadata(NativeFsPath::from_path(&path)?.as_path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => write_private(&path, &bytes)?,
            Ok(_) => {
                if read_private(&path)? != bytes {
                    return Err("prior-current immutable evidence conflict".into());
                }
            }
            Err(e) => return Err(io("prior-current observation", e)),
        }
        Ok(EvidenceRef {
            path: path.file_name().unwrap().to_str().unwrap().into(),
            digest: hash(&bytes),
        })
    }
    fn publish(&mut self, next: Current) -> Result<()> {
        self.publish_with_namespace(next, None, || Ok(()))
    }
    fn publish_with_namespace(&mut self, next: Current, wait: Option<&dyn Fn() -> Result<()>>,
        before_write: impl FnOnce() -> Result<()>) -> Result<()> {
        self.current.require_operation_authority()?;
        next.require_operation_authority()?;
        if (matches!(self.current.runtime_deployment, DeploymentField::Present(Some(_)))
            || matches!(next.runtime_deployment, DeploymentField::Present(Some(_))))
            && self.runtime_write.is_none() {
            return Err("MaintenanceRequired: exclusive runtime gate is not retained".into());
        }
        let _namespace = match wait {
            Some(check) => wait_for_native_lease("publication namespace", check,
                || Lease::try_acquire(&self.known, "wsl_namespace_v2"))?,
            None => Lease::acquire(&self.known, "wsl_namespace_v2")?,
        };
        self.slot.recheck()?;
        self.namespace.recheck()?;
        let (actual, digest) = receive_current(&self.slot)?;
        if digest != self.digest || actual.revision != self.current.revision {
            return Err("RecoveryRequired: current changed before publication".into());
        }
        if next.revision
            != self
                .current
                .revision
                .checked_add(1)
                .ok_or("revision overflow")?
            || next.slot_id != self.current.slot_id
        {
            return Err("current publication binding conflict".into());
        }
        current_shape(&next, &next.slot_id)?;
        if let Some(check) = wait { check()?; }
        before_write()?;
        if let Some(check) = wait { check()?; }
        self.retain_current()?;
        let path = self
            .slot
            .path
            .join(format!("current.next.{}", next.revision));
        let bytes = json(&next)?;
        write_private(&path, &bytes)?;
        let checked: Current = decode(&read_private(&path)?)?;
        if json(&checked)? != bytes {
            return Err("current next receiving mismatch".into());
        }
        // No conflicting leaf handles remain; ancestors and slot lease are retained.
        let from = NativeFsPath::from_path(&path)?;
        let to = NativeFsPath::from_path(&self.slot.path.join("current.json"))?;
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1) } == 0 {
            return Err(io(
                "RecoveryRequired: current replacement",
                std::io::Error::last_os_error(),
            ));
        }
        let (actual, digest) = receive_current(&self.slot)?;
        if digest != hash(&bytes) {
            return Err("RecoveryRequired: current publication readback mismatch".into());
        }
        self.current = actual;
        self.digest = digest;
        Ok(())
    }

    fn recovery_completion(&self, message: &'static str) -> Result<RecoveryCompletion> {
        let current_sha256 = hex::decode(&self.digest).map_err(|_| "current digest encoding")?
            .try_into().map_err(|_| "current digest length")?;
        Ok(RecoveryCompletion { message, slot_id: self.current.slot_id.clone(), current_sha256 })
    }
}

pub(crate) struct PreparedMaintenance<'a, W: MaintenanceWindow> {
    bound: BoundInstallation,
    authority: Authority,
    layout: NativeLayout,
    review: Option<ReviewedArchive>,
    window: &'a mut W,
    kind: OperationKind,
    id: String,
}
struct ContextWindow<'a, W: MaintenanceWindow> {
    context: Option<&'a AncestorAccessContext>,
    window: &'a mut W,
}
impl<W: MaintenanceWindow> MaintenanceWindow for ContextWindow<'_, W> {
    fn ensure_held(&mut self) -> Result<()> {
        if let Some(c) = self.context {
            c.revalidate()?;
        }
        self.window.ensure_held()
    }
}
fn workspace_r0(bound: &BoundInstallation, parent: Option<&Path>) -> Result<Option<CheckedPath>> {
    let (known, _, _) = namespace_paths(bound)?;
    if let Some(parent) = parent {
        let p = CheckedPath::open(parent, PathKind::Directory, PathPurpose::Review)?;
        private(&p.file)?;
        bound.outside(&p)?;
        if p.object.volume != bound.resources.object.volume {
            return Err(
                "RejectedBeforeBootstrap: workspace must share actual target volume".into(),
            );
        }
        return Ok(Some(p));
    }
    if known.object.volume != bound.resources.object.volume {
        return Err("RejectedBeforeBootstrap: explicit existing private --workspace-parent on target volume required".into());
    }
    Ok(None)
}
fn prepare<'a, W: MaintenanceWindow>(
    bound: BoundInstallation,
    review: Option<ReviewedArchive>,
    parent: Option<&Path>,
    window: &'a mut W,
    kind: OperationKind,
) -> Result<PreparedMaintenance<'a, W>> {
    let workspace =
        workspace_r0(&bound, parent).map_err(|e| format!("RejectedBeforeBootstrap: {e}"))?;
    if let Some(review) = &review {
        review.path.recheck()?;
    }
    let mut authority = Authority::open(&bound, kind == OperationKind::Apply, false)?;
    authority.admit_maintenance_gate()?;
    if let Some(review) = &review {
        if review.preimage != bound.bytes {
            return Err("review preimage differs from actual target".into());
        }
    }
    if kind == OperationKind::Apply && authority.current.mode == Mode::SettledApplied {
        return Err("AlreadyApplied: no new native operation".into());
    }
    if kind == OperationKind::Revert && authority.current.mode != Mode::SettledApplied {
        return Err("RevertConflict: canonical state is not applied".into());
    }
    let workspace = match workspace {
        Some(p) => p,
        None => CheckedPath::open(
            &authority.slot.path,
            PathKind::Directory,
            PathPurpose::Review,
        )?,
    };
    private(&workspace.file)?;
    bound.outside(&workspace)?;
    if workspace.object.volume != bound.resources.object.volume {
        return Err(
            "PreparationIncomplete: actual slot/workspace volume differs from target".into(),
        );
    }
    let id = unique_id()?;
    let paths = InstallPaths {
        staged: workspace.path.join(format!("{id}.staged")),
        original_backup: workspace.path.join(format!("{id}.original")),
        displaced_backup: workspace.path.join(format!("{id}.displaced")),
    };
    for p in [
        &paths.staged,
        &paths.original_backup,
        &paths.displaced_backup,
    ] {
        absent(p)?;
    }
    window.ensure_held()?;
    bound.exe.recheck()?;
    bound.archive.recheck()?;
    let layout = NativeLayout {
        paths,
        workspace,
        resources: bound.resources.object.clone(),
        archive: bound.archive.object.clone(),
    };
    layout.verify(&bound.archive.path)?;
    Ok(PreparedMaintenance {
        bound,
        authority,
        layout,
        review,
        window,
        kind,
        id,
    })
}
pub(crate) fn prepare_apply<'a, W: MaintenanceWindow>(
    bound: BoundInstallation,
    review: ReviewedArchive,
    parent: Option<&Path>,
    window: &'a mut W,
) -> Result<PreparedMaintenance<'a, W>> {
    prepare(bound, Some(review), parent, window, OperationKind::Apply)
}
pub(crate) fn prepare_revert<'a, W: MaintenanceWindow>(
    bound: BoundInstallation,
    parent: Option<&Path>,
    window: &'a mut W,
) -> Result<PreparedMaintenance<'a, W>> {
    prepare(bound, None, parent, window, OperationKind::Revert).map_err(|e| {
        if e.starts_with("UpdatePending:") {
            format!("RevertConflict: {e}")
        } else {
            e
        }
    })
}
impl<W: MaintenanceWindow> PreparedMaintenance<'_, W> {
    pub(crate) fn execute(mut self) -> Result<()> {
        self.bound.revalidate_context()?;
        self.authority.check_bound(&self.bound)?;
        self.layout.verify(&self.bound.archive.path)?;
        self.window.ensure_held()?;
        let source = read_path(&self.bound.archive.path, READ | DELETE)?;
        let dir = self.authority.evidence_dir("operation")?;
        let prior = self.authority.retain_current()?;
        let preimage = self.authority.save(&dir, "preimage", &source.bytes)?;
        let (candidate, manifest, manifest_digest) = if let Some(r) = &self.review {
            (
                Some(self.authority.save(&dir, "candidate", &r.candidate.bytes)?),
                Some(
                    self.authority.save(
                        &dir,
                        "review-manifest.json",
                        &r._pins[0]
                            .file
                            .try_clone()
                            .map_err(|e| io("review clone", e))
                            .and_then(|mut f| {
                                read_checked(&mut f, &r._pins[0].path).map(|s| s.bytes)
                            })?,
                    )?,
                ),
                Some(r.manifest_digest.clone()),
            )
        } else {
            (None, None, None)
        };
        let layout = LayoutBinding {
            workspace: self.layout.workspace.path.clone(),
            workspace_id: self.layout.workspace.object.clone(),
            staged: self.layout.paths.staged.clone(),
            original_backup: self.layout.paths.original_backup.clone(),
            displaced_backup: self.layout.paths.displaced_backup.clone(),
        };
        let previous = self
            .authority
            .current
            .settled
            .as_ref()
            .and_then(|s| s.applied.clone());
        let intent = Intent {
            schema: 2,
            slot_id: self.authority.current.slot_id.clone(),
            operation_id: self.id.clone(),
            kind: self.kind.clone(),
            expected_current_digest: self.authority.digest.clone(),
            prior_current: prior,
            binding: self.bound.binding()?,
            layout: layout.clone(),
            preimage,
            candidate,
            review_manifest: manifest,
            review_manifest_digest: manifest_digest,
            prior_applied: previous.clone(),
            legacy: None,
        };
        let intent_ref = self.authority.save(&dir, "intent.json", &json(&intent)?)?;
        let mut pending = self.authority.current.clone();
        pending.revision = pending
            .revision
            .checked_add(1)
            .ok_or("canonical revision overflow")?;
        pending.mode = Mode::Pending;
        pending.settled = None;
        pending.active_operation = Some(Operation {
            id: self.id.clone(),
            kind: self.kind.clone(),
            intent: intent_ref.clone(),
            prior_current_digest: self.authority.digest.clone(),
        });
        self.authority.publish(pending)?;
        // All target leaf handles use replacement-compatible sharing. No raw caller
        // can reach the adapter or construct this held layout.
        let mut qualified_window = ContextWindow {
            context: self.bound.ancestor_context.as_ref(),
            window: self.window,
        };
        let runtime_host = match &self.authority.current.runtime_deployment {
            DeploymentField::Present(Some(value)) => Some(value.host.path.clone()),
            _ => None,
        };
        let profile = match &runtime_host {
            Some(path) => desktop_hook::HookProfile::GuiHost(path.to_str().ok_or("runtime host encoding")?),
            None => desktop_hook::HookProfile::Legacy,
        };
        let native = match self.kind {
            OperationKind::Apply => archive_install::apply(
                &source,
                &self.review.as_ref().ok_or("apply review absent")?.candidate,
                &self.layout,
                &mut qualified_window,
            )
            .map(|a| (Mode::SettledApplied, Some(a))),
            OperationKind::Revert => archive_install::revert_profile(
                &previous.ok_or("canonical applied record absent")?,
                &self.layout,
                &mut qualified_window,
                profile,
            )
            .map(|_| (Mode::SettledReverted, None)),
            _ => unreachable!(),
        };
        let (mode, applied) = match native {
            Ok(x) => x,
            Err(f) => {
                let saved = self.authority.save(&dir, "failure.json", &json(&f)?);
                return Err(format!("RecoveryRequired: {f}; immutable failure persistence={saved:?}; current remains Pending"));
            }
        };
        let target = archive_install::snapshot(&source.target)
            .map_err(|e| format!("RecoveryRequired: {e}"))?;
        let outcome = Outcome {
            schema: 2,
            slot_id: self.authority.current.slot_id.clone(),
            operation_id: self.id.clone(),
            intent: intent_ref.clone(),
            native_call: NativeCall::ReturnedSuccess,
            target: object_state(&target),
            applied: applied.clone(),
            layout,
        };
        #[cfg(test)]
        if TEST_OUTCOME_FAILURE.with(|v| v.replace(false)) {
            return Err("RecoveryRequired: injected actual-result persistence failure; current remains Pending".into());
        }
        let evidence=self.authority.save(&dir,"outcome.json",&json(&Settlement::Outcome(outcome))?).map_err(|e|format!("RecoveryRequired: native result received, outcome persistence failed: {e}; current remains Pending"))?;
        let mut c = self.authority.current.clone();
        c.revision = c
            .revision
            .checked_add(1)
            .ok_or("canonical revision overflow")?;
        c.mode = mode;
        if c.schema == 3 && c.mode == Mode::SettledReverted {
            c.runtime_deployment = DeploymentField::Present(None);
        }
        c.active_operation = None;
        c.binding.archive = object_id(&open_regular(&source.target, READ | DELETE)?)?;
        c.binding.archive_digest = target.digest.clone();
        c.binding.archive_metadata = target.identity.clone();
        c.settled = Some(Settled {
            target: object_state(&target),
            applied,
            evidence,
        });
        self.authority.publish(c)
    }
}
pub(crate) struct RunnableInstallation {
    bound: BoundInstallation,
    _authority: Authority,
}
impl RunnableInstallation {
    pub(crate) fn installation(&mut self) -> &mut BoundInstallation {
        &mut self.bound
    }
}
pub(crate) fn admit_run(bound: BoundInstallation) -> Result<RunnableInstallation> {
    let authority = Authority::open(&bound, false, false)?;
    if authority.current.mode != Mode::SettledApplied {
        return Err("MaintenanceRequired: canonical installation is not settled applied".into());
    }
    let applied = authority
        .current
        .settled
        .as_ref()
        .and_then(|s| s.applied.as_ref())
        .ok_or("applied binding absent")?;
    verify_applied(&bound, applied)?;
    Ok(RunnableInstallation {
        bound,
        _authority: authority,
    })
}
pub(crate) fn runtime_installed(bound: &BoundInstallation) -> Result<bool> {
    runtime_upgrade::runtime_installed(bound)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GatewayPendingObservation {
    pub(crate) slot_id: String,
    pub(crate) operation_id: String,
    pub(crate) current_sha256: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VendorPendingObservation {
    pub(crate) slot_id: String,
    pub(crate) operation_id: String,
    pub(crate) current_sha256: [u8; 32],
}

/// Confirmation for the canonical metadata keeper. This is not a recovery,
/// runtime or package-approval capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VendorSupersessionConfirmation {
    pub(crate) pending: VendorPendingObservation,
    pub(crate) historical_success_sha256: [u8; 32],
    pub(crate) observed_binding_sha256: [u8; 32],
}

#[derive(Debug)]
pub(crate) enum VendorSupersessionFailure {
    Admission(String),
    Publication(MetadataFailure),
}
impl From<String> for VendorSupersessionFailure {
    fn from(cause: String) -> Self { Self::Admission(cause) }
}
impl From<&str> for VendorSupersessionFailure {
    fn from(cause: &str) -> Self { Self::Admission(cause.into()) }
}
impl From<MetadataFailure> for VendorSupersessionFailure {
    fn from(failure: MetadataFailure) -> Self { Self::Publication(failure) }
}
impl std::fmt::Display for VendorSupersessionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admission(cause) => formatter.write_str(cause),
            Self::Publication(failure) => std::fmt::Display::fmt(failure, formatter),
        }
    }
}

fn recheck_supersession_target(bound: &BoundInstallation) -> Result<Binding> {
    bound.revalidate_context()?;
    for member in [&bound.parent, &bound.root, &bound.resources, &bound.exe, &bound.archive] {
        member.recheck()?;
    }
    shadow_clear(&bound.archive.path)?;
    if hash(&bound.exe.read_snapshot()?) != bound.executable_digest
        || bound.archive.read_snapshot()? != bound.bytes {
        return Err("RecoveryRequired: supersession observed member bytes changed".into());
    }
    bound.binding()
}

struct VerifiedVendorSupersession {
    _slot_lease: Lease,
    _namespace_lease: Lease,
    known: CheckedPath,
    namespace: CheckedPath,
    slot: CheckedPath,
    companion: SupersessionCompanion,
    confirmation: VendorSupersessionConfirmation,
    evidence: EvidenceRef,
    bytes: Vec<u8>,
    fingerprint: [u8; 32],
    already_published: bool,
}

fn check_supersession_cancelled(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::SeqCst) { return Err("supersession cancelled".into()); }
    Ok(())
}

fn receive_vendor_supersession_candidate(bound: &BoundInstallation, cancelled: &AtomicBool)
    -> Result<VerifiedVendorSupersession> {
    check_supersession_cancelled(cancelled)?;
    let (known, _, namespace_path) = namespace_paths(bound)?;
    let namespace_lease = Lease::acquire(&known, "wsl_namespace_v2")?;
    let namespace = CheckedPath::open(&namespace_path, PathKind::Directory, PathPurpose::Review)?;
    private(&namespace.file)?;
    let (slot, _, _) = lookup(&namespace, bound)?.ok_or("UnreceivedInstallation: no canonical slot")?;
    let slot_lease = Lease::acquire(&slot, "wsl_slot_v2")?;
    let raw = receive_raw_current(&slot)?;
    let pending = &raw.current;
    if pending.mode != Mode::Pending || !ordinal(&pending.locator, &bound.root.locator)? {
        return Err("RecoveryRequired: supersession requires the selected raw Pending slot".into());
    }
    let operation = pending.active_operation.as_ref().filter(|op| op.kind == OperationKind::VendorUpdate)
        .ok_or("RecoveryRequired: supersession requires a VendorPending operation")?;
    let historical_success = runtime_upgrade::vendor_success_reference(&slot, operation)?
        .ok_or("RecoveryRequired: supersession historical success absent")?;
    let observed = recheck_supersession_target(bound)?;
    let decode_sha256 = |digest: &str| -> Result<[u8; 32]> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(digest, &mut bytes).map_err(|_| "supersession evidence SHA-256 encoding differs")?;
        Ok(bytes)
    };
    let confirmation = VendorSupersessionConfirmation {
        pending: VendorPendingObservation { slot_id: pending.slot_id.clone(), operation_id: operation.id.clone(),
            current_sha256: decode_sha256(&raw.digest)? },
        historical_success_sha256: decode_sha256(&historical_success.digest)?,
        observed_binding_sha256: Sha256::digest(&json(&observed)?).into(),
    };
    let companion = SupersessionCompanion { pending_revision: pending.revision, locator: pending.locator.clone(),
        evidence: Supersession { schema: 1, slot_id: pending.slot_id.clone(),
            pending_current: EvidenceRef { path: "current.json".into(), digest: raw.digest.clone() },
            operation_id: operation.id.clone(), intent: operation.intent.clone(), historical_success,
            observed_binding: observed } };
    let bytes = json(&companion)?;
    let fingerprint: [u8; 32] = Sha256::digest(&bytes).into();
    let evidence = EvidenceRef { path: SUPERSESSION_COMPANION.into(), digest: hex::encode(fingerprint) };
    project_companion(&slot, pending, &raw.digest, &companion, evidence.clone())?;
    let already_published = match receive_companion_file(&slot)? {
        Some((_, existing)) if existing == evidence => true,
        Some(_) => return Err("RecoveryRequired: supersession companion already exists with different bytes".into()),
        None => false,
    };
    check_supersession_cancelled(cancelled)?;
    Ok(VerifiedVendorSupersession { _slot_lease: slot_lease, _namespace_lease: namespace_lease,
        known, namespace, slot, companion, confirmation, evidence, bytes, fingerprint, already_published })
}

/// Read-only observation for an explicit metadata-only confirmation.
pub(crate) fn observe_vendor_supersession(bound: &BoundInstallation, cancelled: &AtomicBool)
    -> Result<VendorSupersessionConfirmation> {
    Ok(receive_vendor_supersession_candidate(bound, cancelled)?.confirmation)
}

/// Metadata keeper only. The supplied confirmation must cover the exact
/// Pending, completed history, and selected replacement. Pending is retained.
pub(crate) fn record_vendor_supersession(bound: &BoundInstallation, confirmation: &VendorSupersessionConfirmation,
    cancelled: &AtomicBool, revalidate_authority: impl FnOnce() -> Result<()>)
    -> std::result::Result<[u8; 32], VendorSupersessionFailure> {
    let candidate = receive_vendor_supersession_candidate(bound, cancelled)?;
    let expected = &confirmation.pending;
    let actual = &candidate.confirmation;
    if actual.pending.slot_id != expected.slot_id || actual.pending.current_sha256 != expected.current_sha256 {
        return Err("RecoveryRequired: supersession Pending confirmation changed".into());
    }
    if actual.pending.operation_id != expected.operation_id {
        return Err("RecoveryRequired: supersession VendorPending operation confirmation differs".into());
    }
    if actual.historical_success_sha256 != confirmation.historical_success_sha256 {
        return Err("RecoveryRequired: supersession historical success confirmation differs".into());
    }
    if actual.observed_binding_sha256 != confirmation.observed_binding_sha256 {
        return Err("RecoveryRequired: supersession observed binding confirmation differs".into());
    }
    check_supersession_cancelled(cancelled)?;
    if candidate.already_published { return Ok(candidate.fingerprint); }
    let slot = &candidate.slot;
    let companion = &candidate.companion;
    let evidence = &candidate.evidence;
    let raw_digest = &companion.evidence.pending_current.digest;
    let observed = &companion.evidence.observed_binding;
    let stage = format!("supersession.stage.{}", unique_id()?);
    let leaf = OsStr::new(SUPERSESSION_COMPANION);
    let verify_currentness = || -> Result<()> {
        candidate.known.recheck()?;
        candidate.namespace.recheck()?;
        slot.recheck()?;
        let fresh = receive_raw_current(slot)?;
        if &fresh.digest != raw_digest || &recheck_supersession_target(bound)? != observed {
            return Err("RecoveryRequired: supersession Pending or observation changed".into());
        }
        project_companion(slot, &fresh.current, &fresh.digest, companion, evidence.clone())?;
        Ok(())
    };
    let id = match publish_immutable_slot_receipt(slot, OsStr::new(&stage), leaf, &candidate.bytes, || {
        verify_currentness()?;
        check_supersession_cancelled(cancelled)?;
        revalidate_authority()
    }) {
        Ok(id) => id,
        Err(mut failure) => {
            if failure.evidence["stageRenameResult"].as_bool() == Some(true) {
                let received = receive_published_slot_receipt(&mut failure, slot, leaf, &candidate.bytes, verify_currentness);
                failure.evidence["postEffectReceiving"] = match received {
                    Ok(release) => serde_json::json!({"result":"received","receiptSha256":evidence.digest,
                        "rawPendingSha256":raw_digest,"disposition":release}),
                    Err(cause) => serde_json::json!({"result":"held","cause":cause}),
                };
            }
            return Err(failure.into());
        }
    };
    let readback = (|| {
        let destination = CheckedPath::open(&slot.path.join(SUPERSESSION_COMPANION), PathKind::File, PathPurpose::Review)?;
        if destination.native_id() != id || destination.read_snapshot()? != candidate.bytes {
            return Err("supersession receipt identity or bytes differ".into());
        }
        let received = receive_current_with_supersession(slot)?;
        received.check_companion()?;
        if received.current.mode != Mode::Superseded || &received.digest != raw_digest
            || &received.current.binding != observed || &recheck_supersession_target(bound)? != observed {
            return Err("supersession companion readback does not bind the exact Pending and observation".into());
        }
        Ok(candidate.fingerprint)
    })();
    readback.map_err(|cause: String| MetadataFailure { phase: "supersession independent receiving", cause,
        replace_result: None, evidence: serde_json::json!({"stageRenameResult":true,"receiptNativeId":id,
            "receiptName":SUPERSESSION_COMPANION,"requestedSha256":evidence.digest,"rawPendingSha256":raw_digest}),
        live: Vec::new(), pending: None, unwind: None, secondary_unwinds: Vec::new() }.into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApplyCurrentObservation {
    Absent,
    Settled { slot_id: String, current_sha256: [u8; 32] },
    GatewayPending(GatewayPendingObservation),
    VendorPending(VendorPendingObservation),
    VendorReplacement(VendorUpdateObservation),
}

/// A changed, positively selected incarnation still tied to one settled slot.
/// This is a prerequisite observation, never permission to execute maintenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VendorUpdateObservation {
    pub(crate) slot_id: String,
    pub(crate) prior_current_sha256: [u8; 32],
    pub(crate) new_parent_id: ObjectId,
    pub(crate) new_resources_id: ObjectId,
    pub(crate) new_archive_id: ObjectId,
    pub(crate) new_executable_sha256: [u8; 32],
    pub(crate) new_archive_sha256: [u8; 32],
    pub(crate) new_binding_sha256: [u8; 32],
}

fn vendor_update_observation(bound: &BoundInstallation, slot: &CheckedPath, current: &Current,
    digest: &str) -> Result<VendorUpdateObservation> {
    let binding = bound.binding()?;
    if current.mode != Mode::SettledApplied || !ordinal(&current.locator, &bound.root.locator)?
        || current.binding == binding {
        return Err("UpdatePending: no distinct settled vendor incarnation".into());
    }
    let deployment = current.runtime_deployment.received()?;
    deployment.receive_receipt(slot)?;
    let _host = deployment.receive_host(slot)?;
    bound.exe.recheck()?;
    if hash(&bound.exe.read_snapshot()?) != bound.executable_digest || bound.archive.read_snapshot()? != bound.bytes {
        return Err("UpdatePending: selected vendor bytes changed".into());
    }
    let host = deployment.host.path.to_str().ok_or("runtime host encoding")?;
    if desktop_hook::prepare_gui_archive(&bound.bytes, host).map_err(|e| e.to_string())?.hook_status
        != desktop_hook::HookStatus::Prepared {
        return Err("UpdatePending: vendor update requires a supported pristine archive".into());
    }
    let decode_hash = |value: &str| -> Result<[u8; 32]> {
        hex::decode(value).map_err(|_| "digest encoding")?.try_into().map_err(|_| "digest length".into())
    };
    Ok(VendorUpdateObservation { slot_id: current.slot_id.clone(), prior_current_sha256: decode_hash(digest)?,
        new_parent_id: binding.parent.clone(), new_resources_id: binding.resources.clone(), new_archive_id: binding.archive.clone(),
        new_executable_sha256: decode_hash(&binding.executable_digest)?, new_archive_sha256: decode_hash(&binding.archive_digest)?,
        new_binding_sha256: decode_hash(&hash(&json(&binding)?))? })
}

pub(crate) fn observe_vendor_update(bound: &BoundInstallation) -> Result<VendorUpdateObservation> {
    match observe_apply_current(bound)? {
        ApplyCurrentObservation::VendorReplacement(value) => Ok(value),
        _ => Err("UpdatePending: no distinct settled vendor incarnation".into()),
    }
}
/// Read-only observation for positive Apply. This data grants no mutation;
/// recovery re-receives the same exact operation/digest/native binding.
pub(crate) fn observe_apply_current(bound: &BoundInstallation) -> Result<ApplyCurrentObservation> {
    observe_apply_current_attempt(bound).map_err(ApplyCurrentReadError::into_owner_error)
}

pub(crate) fn wait_for_apply_current(bound: &BoundInstallation, stage: &str, check: &dyn Fn() -> Result<()>)
    -> Result<ApplyCurrentObservation> {
    wait_for_current_admission(stage, check, || observe_apply_current_attempt(bound))
}

#[derive(Debug)]
pub(crate) enum ApplyCurrentLease { Namespace, Slot }

#[derive(Debug)]
pub(crate) enum ApplyCurrentReadError {
    Busy(ApplyCurrentLease),
    Failed(String),
}

impl ApplyCurrentReadError {
    fn into_owner_error(self) -> String {
        match self {
            Self::Busy(_) => Lease::BUSY.into(),
            Self::Failed(cause) => cause,
        }
    }
}

impl From<String> for ApplyCurrentReadError {
    fn from(value: String) -> Self { Self::Failed(value) }
}

impl From<&str> for ApplyCurrentReadError {
    fn from(value: &str) -> Self { Self::Failed(value.into()) }
}

fn wait_for_current_admission<T>(stage: &str, check: &dyn Fn() -> Result<()>,
    mut attempt: impl FnMut() -> Result<T, ApplyCurrentReadError>) -> Result<T> {
    wait_for_native_lease(stage, check, || match attempt() {
        Ok(value) => Ok(Some(value)),
        Err(ApplyCurrentReadError::Busy(_)) => Ok(None),
        Err(ApplyCurrentReadError::Failed(error)) => Err(error),
    })
}

/// One zero-wait read attempt. Busy carries no lease or partial observation.
pub(crate) fn observe_apply_current_attempt(bound: &BoundInstallation) -> std::result::Result<ApplyCurrentObservation, ApplyCurrentReadError> {
    let (known, _, namespace_path) = namespace_paths(bound)?;
    let _namespace = Lease::try_acquire(&known, "wsl_namespace_v2")?
        .ok_or(ApplyCurrentReadError::Busy(ApplyCurrentLease::Namespace))?;
    match fs::symlink_metadata(NativeFsPath::from_path(&namespace_path)?.as_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(ApplyCurrentObservation::Absent),
        Err(error) => return Err(io("continuation namespace observation", error).into()),
        Ok(_) => {},
    }
    let namespace = CheckedPath::open(&namespace_path, PathKind::Directory, PathPurpose::Review)?;
    private(&namespace.file)?;
    let Some((slot, _, _)) = lookup(&namespace, bound)? else { return Ok(ApplyCurrentObservation::Absent); };
    let _slot = Lease::try_acquire(&slot, "wsl_slot_v2")?
        .ok_or(ApplyCurrentReadError::Busy(ApplyCurrentLease::Slot))?;
    let (current, digest) = receive_current(&slot)?;
    current.require_operation_authority()?;
    let gateway_pending = current.mode == Mode::Pending && current.active_operation.as_ref().is_some_and(|operation|
        matches!(operation.kind, OperationKind::ConfigureGatewayRules | OperationKind::RetireGatewayRules));
    let vendor_pending = current.mode == Mode::Pending && current.active_operation.as_ref().is_some_and(|operation|
        operation.kind == OperationKind::VendorUpdate);
    if vendor_pending {
        let operation = current.active_operation.as_ref().unwrap();
        runtime_upgrade::receive_vendor_pending_target(&slot, &current, operation, bound)?;
        let current_sha256 = hex::decode(digest).map_err(|_| "current digest encoding".to_owned())?
            .try_into().map_err(|_| "current digest length".to_owned())?;
        return Ok(ApplyCurrentObservation::VendorPending(VendorPendingObservation {
            slot_id: current.slot_id, operation_id: operation.id.clone(), current_sha256,
        }));
    }
    if matches!(current.mode, Mode::Bootstrap | Mode::Pending) && !gateway_pending {
        return Err(ApplyCurrentReadError::Failed("RecoveryRequired: continuation target has unresolved Current".into()));
    }
    if current.binding != bound.binding()? {
        return Ok(ApplyCurrentObservation::VendorReplacement(vendor_update_observation(bound, &slot, &current, &digest)?));
    }
    let digest: [u8; 32] = hex::decode(digest).map_err(|_| "current digest encoding".to_owned())?
        .try_into().map_err(|_| "current digest length".to_owned())?;
    if gateway_pending {
        let operation = current.active_operation.as_ref().unwrap();
        gateway_rules::receive_pending(&slot, &current, operation)?;
        Ok(ApplyCurrentObservation::GatewayPending(GatewayPendingObservation {
            slot_id: current.slot_id, operation_id: operation.id.clone(), current_sha256: digest,
        }))
    } else { Ok(ApplyCurrentObservation::Settled { slot_id: current.slot_id, current_sha256: digest }) }
}
fn strict_current_expectation(observation: ApplyCurrentObservation) -> Result<Option<(String, [u8; 32])>> {
    match observation {
        ApplyCurrentObservation::Absent => Ok(None),
        ApplyCurrentObservation::Settled { slot_id, current_sha256 } => Ok(Some((slot_id, current_sha256))),
        ApplyCurrentObservation::GatewayPending(_) | ApplyCurrentObservation::VendorPending(_) => Err("RecoveryRequired: continuation target has unresolved Current".into()),
        ApplyCurrentObservation::VendorReplacement(_) => Err("UpdatePending: continuation target incarnation differs".into()),
    }
}

#[cfg(test)]
#[test]
#[ignore = "read-only receipt against an explicitly owned, stable Desktop Current fixture"]
fn selected_current_attempt_distinguishes_busy_leases_and_releases_namespace() {
    let executable = PathBuf::from(std::env::var_os("AG_SELECTED_RECOVERY_MUTEX_FIXTURE_EXE")
        .expect("explicit owned Desktop fixture executable"));
    let base = PathBuf::from(std::env::var_os("AG_SELECTED_RECOVERY_MUTEX_FIXTURE_BASE")
        .expect("explicit private fixture state base"));
    let context = PathBuf::from(std::env::var_os("AG_RUNTIME_UPGRADE_DEPLOYMENT_CONTEXT")
        .expect("explicit genuine registration path required"));

    let base = CheckedPath::open(&base, PathKind::Directory, PathPurpose::Review).unwrap();
    private(&base.file).unwrap();
    let fixture = CheckedPath::open(base.as_path().parent().expect("fixture state parent"), PathKind::Directory, PathPurpose::Review).unwrap();
    private(&fixture.file).unwrap();
    let executable = CheckedPath::open(&executable, PathKind::File, PathPurpose::Executable).unwrap();
    assert!(fixture.contains(&executable).unwrap(), "state and executable must belong to the same private fixture");
    assert!(!base.contains(&executable).unwrap(), "fixture executable must be outside its state base");
    let known = CheckedPath::open(&known_folder().unwrap(), PathKind::Directory, PathPurpose::Review).unwrap();
    let product = known.as_path().join(user_state_location::WINDOWS_STATE_LEAF);
    assert_ne!(base.native_id(), known.native_id(), "fixture cannot select the ordinary state base");
    assert!(!base.as_path().ancestors().any(|path| same_windows_path(path, &product).unwrap()),
        "fixture cannot select the installed product state");

    struct FixtureStateBase(Option<PathBuf>);
    impl FixtureStateBase {
        fn receive(path: &Path) -> Self { Self(TEST_BASE.with(|slot| slot.replace(Some(path.to_path_buf())))) }
    }
    impl Drop for FixtureStateBase {
        fn drop(&mut self) { TEST_BASE.with(|slot| { slot.replace(self.0.take()); }); }
    }
    fn receive_bound(path: &Path, context_path: &Path) -> BoundInstallation {
        let mut bound = BoundInstallation::open(path).unwrap();
        let context = super::windows_deployment::receive_for_installation(&bound, Some(context_path)).unwrap()
            .expect("explicit genuine fixture context was not received");
        bound.attach_ancestor_context(context).unwrap();
        bound
    }
    let _state = FixtureStateBase::receive(base.as_path());
    let bound = receive_bound(executable.as_path(), &context);
    let expected = observe_apply_current(&bound).unwrap();
    assert!(!matches!(&expected, ApplyCurrentObservation::Absent));
    let (known, _, namespace_path) = namespace_paths(&bound).unwrap();
    let namespace = CheckedPath::open(&namespace_path, PathKind::Directory, PathPurpose::Review).unwrap();
    let (slot, _, _) = lookup(&namespace, &bound).unwrap().expect("fixture has an enrolled slot");
    let observe = || {
        let executable = executable.as_path().to_path_buf();
        let base = base.as_path().to_path_buf();
        let context = context.clone();
        std::thread::spawn(move || {
            let _state = FixtureStateBase::receive(&base);
            observe_apply_current_attempt(&receive_bound(&executable, &context))
        }).join().unwrap()
    };
    let held_namespace = Lease::acquire(&known, "wsl_namespace_v2").unwrap();
    assert!(matches!(observe(), Err(ApplyCurrentReadError::Busy(ApplyCurrentLease::Namespace))));
    drop(held_namespace);

    let held_slot = Lease::acquire(&slot, "wsl_slot_v2").unwrap();
    assert!(matches!(observe(), Err(ApplyCurrentReadError::Busy(ApplyCurrentLease::Slot))));
    let namespace = Lease::try_acquire(&known, "wsl_namespace_v2").unwrap()
        .expect("slot contention released the already received namespace");
    drop(namespace);
    drop(held_slot);
    assert_eq!(observe().unwrap(), expected);
}
/// Continuation/startup readers remain strictly settled and never recover.
pub(crate) fn capture_current_expectation(bound: &BoundInstallation) -> Result<Option<(String, [u8; 32])>> {
    strict_current_expectation(observe_apply_current(bound)?)
}
#[cfg(test)]
mod apply_current_projection_tests {
    use super::*;
    #[test]
    fn strict_continuation_never_encodes_gateway_pending_as_present_or_absent() {
        assert_eq!(strict_current_expectation(ApplyCurrentObservation::Absent).unwrap(), None);
        assert_eq!(strict_current_expectation(ApplyCurrentObservation::Settled { slot_id: "a".repeat(32), current_sha256: [7;32] }).unwrap(), Some(("a".repeat(32), [7;32])));
        let pending = GatewayPendingObservation { slot_id: "a".repeat(32), operation_id: "b".repeat(32), current_sha256: [8;32] };
        assert!(strict_current_expectation(ApplyCurrentObservation::GatewayPending(pending)).unwrap_err().contains("unresolved Current"));
        let pending = VendorPendingObservation { slot_id: "a".repeat(32), operation_id: "c".repeat(32), current_sha256: [9;32] };
        assert!(strict_current_expectation(ApplyCurrentObservation::VendorPending(pending)).unwrap_err().contains("unresolved Current"));
        let id = ObjectId { volume: 1, file: [2; 16] };
        let vendor = VendorUpdateObservation { slot_id: "a".repeat(32), prior_current_sha256: [3; 32],
            new_parent_id: id.clone(), new_resources_id: id.clone(), new_archive_id: id,
            new_executable_sha256: [4; 32], new_archive_sha256: [5; 32], new_binding_sha256: [6; 32] };
        assert!(strict_current_expectation(ApplyCurrentObservation::VendorReplacement(vendor)).unwrap_err().contains("incarnation differs"));
    }
}

/// Retains independent native read exclusion and every received path pin while
/// releasing only the short canonical admission mutex.
pub(crate) struct RuntimeRead {
    bound: BoundInstallation,
    host: CheckedPath,
    _gate: runtime_gate::ReadGate,
    _state_pins: Vec<CheckedPath>,
    slot: CheckedPath,
    revision: u64,
    host_sha256: String,
}
impl RuntimeRead {
    pub(crate) fn installation(&self) -> &BoundInstallation { &self.bound }
    pub(crate) fn host(&self) -> &CheckedPath { &self.host }
    pub(crate) fn revision(&self) -> u64 { self.revision }
    pub(crate) fn host_sha256(&self) -> &str { &self.host_sha256 }
    pub(crate) fn server_version(&self) -> Result<String> {
        desktop_hook::inspect_gui_archive(&self.bound.bytes,
            self.host.path.to_str().ok_or("runtime host encoding")?).map(|inspection| inspection.version).map_err(|e| e.to_string())
    }
}
pub(crate) struct VendorLane {
    _lease: Lease,
    _vendor: super::process_identity::ProcessIdentity,
    _image: CheckedPath,
}
/// One observed-vendor lane for selected and passthrough consumers alike.
/// This coordination grants no installation, network or termination authority.
pub(crate) fn admit_vendor_lane(vendor: super::process_identity::ProcessIdentity, desktop: &Path) -> Result<VendorLane> {
    vendor.recheck()?;
    if !vendor.alive()? { return Err("vendor instance already retired".into()); }
    let current = super::process_identity::ProcessIdentity::current()?;
    let image = CheckedPath::open(vendor.image(), PathKind::File, PathPurpose::Executable)?;
    let requested = CheckedPath::open(desktop, PathKind::File, PathPurpose::Executable)?;
    if vendor.sid() != current.sid() || image.native_id() != requested.native_id() {
        return Err("vendor process user/image binding differs".into());
    }
    let scope = json(&(current.sid(), vendor.pid(), vendor.creation(), image.native_id()))?;
    let name = format!("Global\\AGUnlocker_vendor_start_v2_{}", hash(&scope));
    let lease = Lease::acquire_name(&name)?;
    Ok(VendorLane { _lease: lease, _vendor: vendor, _image: image })
}
pub(crate) fn admit_runtime_read(bound: BoundInstallation, runtime_revision: &str) -> Result<RuntimeRead> {
    let authority = Authority::open(&bound, false, false)?;
    if authority.current.schema != 3 || authority.current.mode != Mode::SettledApplied {
        return Err("MaintenanceRequired: settled V2 runtime deployment required".into());
    }
    let deployment = authority.current.runtime_deployment.received()?;
    if deployment.hook.revision != runtime_revision {
        return Err("MaintenanceRequired: unknown runtime revision".into());
    }
    let gate = runtime_gate::read(&authority.slot, &deployment.gate.native_id)?;
    let (_, digest) = receive_current(&authority.slot)?;
    if digest != authority.digest { return Err("RecoveryRequired: current changed during reader admission".into()); }
    let host = deployment.receive_host(&authority.slot)?;
    deployment.receive_receipt(&authority.slot)?;
    deployment.receive_hook(&bound.bytes)?;
    let applied = authority.current.settled.as_ref().and_then(|s| s.applied.as_ref())
        .ok_or("RecoveryRequired: V2 applied binding absent")?;
    verify_applied_profile(&bound, applied, desktop_hook::HookProfile::GuiHost(
        deployment.host.path.to_str().ok_or("runtime host encoding")?))?;
    let revision = authority.current.revision;
    let host_sha256 = deployment.host.sha256.clone();
    let Authority { known, _product, namespace, slot, lease, .. } = authority;
    drop(lease);
    Ok(RuntimeRead { bound, host, _gate: gate, _state_pins: vec![known, _product, namespace], slot, revision, host_sha256 })
}
fn verify_applied(bound: &BoundInstallation, a: &archive_install::AppliedArchive) -> Result<()> {
    verify_applied_profile(bound, a, desktop_hook::HookProfile::Legacy)
}
fn verify_applied_profile(bound: &BoundInstallation, a: &archive_install::AppliedArchive,
    profile: desktop_hook::HookProfile<'_>) -> Result<()> {
    if a.record_version != 1
        || a.post_digest != hash(&bound.bytes)
        || a.post != identity(&bound.archive.file)?
    {
        return Err("RevertConflict: target not exact owned postimage".into());
    }
    let original = read_path(&a.original_backup, READ)?;
    let displaced = read_path(&a.displaced_backup, READ)?;
    if original.identity != a.original_backup_identity
        || original.digest != a.pre_digest
        || displaced.identity != a.displaced_identity
        || displaced.identity != a.original
        || displaced.bytes != original.bytes
        || displaced.digest != a.pre_digest
    {
        return Err("RecoveryRequired: retained original/displaced binding conflict".into());
    }
    let prepared = desktop_hook::prepare_profile(&original.bytes, profile).map_err(|e| e.to_string())?;
    if prepared.bytes != bound.bytes {
        return Err("owned postimage transform mismatch".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyImport {
    files: Vec<EvidenceRef>,
    missing: Vec<String>,
    producer_digest: String,
    expected_files: [String; 5],
    source_native_ids: Vec<ObjectId>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyIntent {
    schema: u32,
    operation: String,
    state: String,
    target: PathBuf,
    source_digest: String,
    source_identity: FileIdentity,
    desktop_sha256: String,
    staged: PathBuf,
    original_backup: PathBuf,
    displaced_backup: PathBuf,
    review_manifest: String,
    review_preimage: String,
    review_candidate: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActualFailure {
    phase: String,
    cause: String,
    #[serde(deserialize_with = "required_option")]
    replace_result: Option<bool>,
    recovery: archive_install::RecoveryState,
}
const LEGACY_PRODUCER: &str = "ed5a6a8b8f1dd3ad2d34bfc54cae83fbbdd3768cf23277fb4d92ccdf0496ce2b";
pub(crate) fn import_legacy<W: MaintenanceWindow>(
    bound: BoundInstallation,
    review: &Path,
    distro: &str,
    producer: &Path,
    expected: &ExpectedLegacyAttempt,
    window: &mut W,
) -> Result<String> {
    let mut producer = CheckedPath::open(producer, PathKind::File, PathPurpose::Executable)?;
    let producer_digest = hash(&producer.read()?);
    if producer_digest != LEGACY_PRODUCER {
        return Err("legacy producer is not the exact received schema1 implementation".into());
    }
    let input = receive_legacy_input(&bound, review, distro, expected)?;
    let files = &input.files;
    let old: LegacyIntent = decode(&files[3].1)?;
    let selected = CheckedPath::open(&old.target, PathKind::File, PathPurpose::ReplaceSource)?;
    if old.schema != 1
        || old.operation != "apply"
        || old.state != "pending-native-operation"
        || selected.object != bound.archive.object
        || old.desktop_sha256 != bound.executable_digest
        || old.source_digest != hash(&input.files[1].1)
        || old.review_manifest != "manifest.json"
        || old.review_preimage != "app.asar.preimage"
        || old.review_candidate != "app.asar.candidate"
    {
        return Err("legacy operation does not bind selected target/review".into());
    }
    // Source paths and failure observations are received now, not trusted as proof.
    let mut old_parents = Vec::new();
    for p in [&old.staged, &old.original_backup, &old.displaced_backup] {
        validate_path(p)?;
        let parent = CheckedPath::open(
            p.parent().ok_or("legacy work parent")?,
            PathKind::Directory,
            PathPurpose::ExternalLegacyInput,
        )?;
        bound.outside(&parent)?;
        old_parents.push(parent);
    }
    let mut authority = Authority::open(&bound, true, true)?;
    if authority.current.schema != 2 {
        return Err("LegacyImportConflict: only a legacy schema2 slot accepts legacy import".into());
    }
    if authority.current.mode == Mode::Pending {
        return Err("RecoveryRequired: slot already contains a Pending operation".into());
    }
    window.ensure_held()?;
    let dir = authority.evidence_dir("legacy-import")?;
    let mut retained = Vec::new();
    for (name, bytes) in files {
        retained.push(authority.save(&dir, name, bytes)?);
    }
    let prior = authority.retain_current()?;
    let id = unique_id()?;
    let workspace = CheckedPath::open(
        old.staged.parent().ok_or("legacy parent")?,
        PathKind::Directory,
        PathPurpose::ExternalLegacyInput,
    )?;
    let intent = Intent {
        schema: 2,
        slot_id: authority.current.slot_id.clone(),
        operation_id: id.clone(),
        kind: OperationKind::LegacyApply,
        expected_current_digest: authority.digest.clone(),
        prior_current: prior,
        binding: Binding {
            archive_metadata: old.source_identity,
            archive_digest: old.source_digest,
            ..bound.binding()?
        },
        layout: LayoutBinding {
            workspace: workspace.path.clone(),
            workspace_id: workspace.object.clone(),
            staged: old.staged,
            original_backup: old.original_backup,
            displaced_backup: old.displaced_backup,
        },
        preimage: retained[1].clone(),
        candidate: Some(retained[2].clone()),
        review_manifest: Some(retained[0].clone()),
        review_manifest_digest: Some(retained[0].digest.clone()),
        prior_applied: None,
        legacy: Some(LegacyImport {
            files: retained,
            missing: Vec::new(),
            producer_digest,
            expected_files: expected.digests.clone(),
            source_native_ids: input.pins.iter().map(|p| p.object.clone()).collect(),
        }),
    };
    let intent_ref = authority.save(&dir, "intent.json", &json(&intent)?)?;
    // Preserve the exact original failure. Its null result alone settles nothing.
    let mut current = authority.current.clone();
    current.revision = current
        .revision
        .checked_add(1)
        .ok_or("canonical revision overflow")?;
    current.mode = Mode::Pending;
    current.settled = None;
    current.active_operation = Some(Operation {
        id: id.clone(),
        kind: OperationKind::LegacyApply,
        intent: intent_ref,
        prior_current_digest: authority.digest.clone(),
    });
    authority.publish(current)?;
    // These remain external originals, not managed review/evidence. Any final
    // failure after publication retains the actual canonical Pending and copies.
    input.recheck().map_err(|e| {
        format!("RecoveryRequired: original legacy readback failed after Pending: {e}")
    })?;
    for parent in &old_parents {
        parent
            .recheck()
            .map_err(|e| format!("RecoveryRequired: old work parent changed after Pending: {e}"))?;
    }
    Ok(format!(
        "LegacyImported: operation={id} expected-current-sha256={}; canonical Pending retained",
        authority.digest
    ))
}
fn observe_all(
    target: &Path,
    layout: &LayoutBinding,
) -> Vec<(PathBuf, archive_install::FileObservation)> {
    [
        target,
        &layout.staged,
        &layout.original_backup,
        &layout.displaced_backup,
    ]
    .into_iter()
    .map(|p| (p.into(), archive_install::observe(p)))
    .collect()
}
fn work_absent(observations: &[(PathBuf, archive_install::FileObservation)]) -> bool {
    observations
        .iter()
        .skip(1)
        .all(|(_, o)| matches!(o, archive_install::FileObservation::Missing))
}
pub(crate) struct GatewayRecoveryContext<'a> {
    pub(crate) runner: &'a mut dyn gateway_rules::GatewayRuleRunner,
    pub(crate) cancel: &'a AtomicBool,
}

/// Current received by the publishing authority before releasing its slot.
#[derive(Debug)]
pub(crate) struct RecoveryCompletion {
    pub(crate) message: &'static str,
    pub(crate) slot_id: String,
    pub(crate) current_sha256: [u8; 32],
}

pub(crate) fn recover<W: MaintenanceWindow>(
    bound: BoundInstallation,
    id: &str,
    expected: &str,
    gateway: Option<GatewayRecoveryContext<'_>>,
    window: &mut W,
) -> Result<RecoveryCompletion> {
    recover_inner(bound, id, expected, gateway, window, None)
}

pub(crate) fn recover_waiting_vendor_metadata<W: MaintenanceWindow>(
    bound: BoundInstallation,
    id: &str,
    expected: &str,
    gateway: GatewayRecoveryContext<'_>,
    window: &mut W,
    check: &dyn Fn() -> Result<()>,
) -> Result<RecoveryCompletion> {
    recover_inner(bound, id, expected, Some(gateway), window, Some(check))
}

fn recover_inner<W: MaintenanceWindow>(
    bound: BoundInstallation,
    id: &str,
    expected: &str,
    gateway: Option<GatewayRecoveryContext<'_>>,
    window: &mut W,
    wait: Option<&dyn Fn() -> Result<()>>,
) -> Result<RecoveryCompletion> {
    let mut authority = match wait {
        Some(check) => wait_for_current_admission("initial canonical admission", check,
            || Authority::open_inner(&bound, false, true, None))?,
        None => Authority::open(&bound, false, true)?,
    };
    if let Some(check) = wait { check()?; }
    authority.admit_maintenance_gate()?;
    let op = authority
        .current
        .active_operation
        .clone()
        .filter(|op| authority.current.mode == Mode::Pending && op.id == id)
        .ok_or("RecoveryRequired: exact current Pending operation required")?;
    if authority.digest != expected {
        return Err("RecoveryRequired: expectedCurrentDigest differs from held Pending".into());
    }
    if wait.is_some() && op.kind != OperationKind::VendorUpdate {
        return Err("RecoveryRequired: exact Pending VendorUpdate required for selected recovery".into());
    }
    if matches!(op.kind, OperationKind::ConfigureGatewayRules | OperationKind::RetireGatewayRules) {
        bound.revalidate_context()?;
        if authority.current.binding != bound.binding()? { return Err("RecoveryRequired: gateway recovery incarnation differs".into()); }
        gateway_rules::receive_pending(&authority.slot, &authority.current, &op)?;
        let context = gateway.ok_or("RecoveryRequired: gateway recovery capability required")?;
        if context.cancel.load(Ordering::SeqCst) { return Err("Cancelled: gateway recovery not started".into()); }
        // Release slot/G1 ownership before the existing gateway owner reacquires
        // and revalidates this exact Pending snapshot. Never nest writer gates.
        drop(authority);
        return gateway_rules::recover_gateway_rules(&bound, id, expected, context.runner, window, context.cancel)
            .map_err(|error| error.to_string());
    }
    if matches!(op.kind, OperationKind::VendorUpdate) {
        return runtime_upgrade::recover_vendor_update(bound, authority, op, gateway, window, wait);
    }
    if matches!(op.kind, OperationKind::UpgradeRuntime | OperationKind::RollbackRuntime) {
        return runtime_upgrade::recover(bound, authority, op, window);
    }
    let intent: Intent = decode(&reference(&authority.slot, &op.intent)?)?;
    if intent.binding.root != bound.root.object
        || intent.binding.resources != bound.resources.object
        || intent.binding.executable != bound.exe.object
        || intent.binding.executable_digest != bound.executable_digest
    {
        return Err("RecoveryRequired: incarnation rebind needs explicit provenance".into());
    }
    window.ensure_held()?;
    let old_workspace = if intent.kind == OperationKind::LegacyApply {
        let p = CheckedPath::open(
            &intent.layout.workspace,
            PathKind::Directory,
            PathPurpose::ExternalLegacyInput,
        )?;
        if p.object != intent.layout.workspace_id {
            return Err("RecoveryRequired: old workspace locator native identity changed".into());
        }
        Some(p)
    } else {
        None
    };
    let observations = observe_all(&bound.archive.path, &intent.layout);
    let preimage = reference(&authority.slot, &intent.preimage)?;
    let source = SourceSnapshot {
        target: bound.archive.path.clone(),
        bytes: preimage,
        digest: intent.binding.archive_digest.clone(),
        identity: intent.binding.archive_metadata.clone(),
    };
    let dir = authority.evidence_dir("recovery")?;
    let intent_path = authority.slot.path.join(&op.intent.path);
    let operation_dir = intent_path.parent().ok_or("intent directory")?;
    let failure_ref = if let Some(legacy) = &intent.legacy {
        legacy
            .files
            .iter()
            .find(|r| r.path.ends_with("apply-failure.json"))
            .cloned()
    } else {
        let path = operation_dir.join("failure.json");
        match fs::symlink_metadata(NativeFsPath::from_path(&path)?.as_path()) {
            Ok(_) => {
                let bytes = read_private(&path)?;
                Some(EvidenceRef {
                    path: path
                        .strip_prefix(&authority.slot.path)
                        .map_err(|_| "failure reference")?
                        .to_str()
                        .ok_or("failure encoding")?
                        .replace('\\', "/"),
                    digest: hash(&bytes),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io("failure observation", e)),
        }
    };
    let failure = match &failure_ref {
        Some(r) => Some(decode::<ActualFailure>(&reference(&authority.slot, r)?)?),
        None => None,
    };
    let actual = archive_install::snapshot(&bound.archive.path).map_err(|e| e.to_string())?;
    let (decision, mode, native_call, applied) = if actual.identity == source.identity
        && actual.digest == source.digest
        && actual.bytes == source.bytes
        && work_absent(&observations)
    {
        let f = failure.as_ref().ok_or(
            "RecoveryRequired: no actual NotCalled evidence; matching target alone proves nothing",
        )?;
        let guard_evidence = if op.kind == OperationKind::LegacyApply {
            intent
                .legacy
                .as_ref()
                .is_some_and(|l| l.producer_digest == LEGACY_PRODUCER)
                && f.phase == "preflight"
                && f.cause == "staging/recovery must share target volume"
                && CheckedPath::open(
                    &intent.layout.workspace,
                    PathKind::Directory,
                    PathPurpose::ExternalLegacyInput,
                )?
                .object
                .volume
                    != bound.resources.object.volume
        } else {
            ["preflight", "revert-preflight"].contains(&f.phase.as_str())
        };
        if f.replace_result.is_some() || !guard_evidence {
            return Err("RecoveryRequired: failure does not prove native call was avoided".into());
        }
        verify_failure_observations(f, &source, &intent.layout)?;
        (
            ResolutionDecision::NoNativeCallConfirmed,
            if intent.kind == OperationKind::Revert {
                Mode::SettledApplied
            } else {
                Mode::SettledUnchanged
            },
            NativeCall::NotCalled,
            intent.prior_applied.clone(),
        )
    } else if intent.kind == OperationKind::Apply {
        let candidate = reference(
            &authority.slot,
            intent
                .candidate
                .as_ref()
                .ok_or("candidate evidence missing")?,
        )?;
        let received = archive_install::receive_applied(
            &source,
            &candidate,
            &InstallPaths {
                staged: intent.layout.staged.clone(),
                original_backup: intent.layout.original_backup.clone(),
                displaced_backup: intent.layout.displaced_backup.clone(),
            },
        )?;
        (
            ResolutionDecision::AppliedConfirmed,
            Mode::SettledApplied,
            match failure.as_ref().and_then(|f| f.replace_result) {
                Some(true) => NativeCall::ReturnedSuccess,
                Some(false) => NativeCall::ReturnedFailure,
                None => NativeCall::Unknown,
            },
            Some(received),
        )
    } else if intent.kind == OperationKind::Revert {
        let record = intent
            .prior_applied
            .as_ref()
            .ok_or("revert original ownership record absent")?;
        let original = read_path(&record.original_backup, READ)?;
        if original.identity != record.original_backup_identity
            || original.digest != record.pre_digest
        {
            return Err("revert retained original binding conflict".into());
        }
        archive_install::receive_reverted(
            record,
            &original,
            &source,
            &InstallPaths {
                staged: intent.layout.staged.clone(),
                original_backup: intent.layout.original_backup.clone(),
                displaced_backup: intent.layout.displaced_backup.clone(),
            },
        )?;
        (
            ResolutionDecision::RevertedConfirmed,
            Mode::SettledReverted,
            match failure.as_ref().and_then(|f| f.replace_result) {
                Some(true) => NativeCall::ReturnedSuccess,
                Some(false) => NativeCall::ReturnedFailure,
                None => NativeCall::Unknown,
            },
            None,
        )
    } else {
        return Err("RecoveryRequired: observations do not prove complete unchanged/applied/reverted postconditions; conditional restoration/rebind needs its qualified operation".into());
    };
    let outcome = Outcome {
        schema: 2,
        slot_id: authority.current.slot_id.clone(),
        operation_id: op.id.clone(),
        intent: op.intent.clone(),
        native_call,
        target: object_state(&actual),
        applied: applied.clone(),
        layout: intent.layout,
    };
    let resolution = Resolution {
        schema: 2,
        slot_id: authority.current.slot_id.clone(),
        resolves_operation_id: op.id,
        intent_digest: op.intent.digest,
        expected_current_digest: authority.digest.clone(),
        pending_current: authority.retain_current()?,
        failure: failure_ref,
        decision,
        observations,
        outcome,
    };
    // Even a rejected observation is retained above only as a truthful footprint.
    let r = authority.save(
        &dir,
        "resolution.json",
        &json(&Settlement::Resolution(resolution))?,
    )?;
    window.ensure_held()?;
    let fresh = archive_install::snapshot(&bound.archive.path).map_err(|e| e.to_string())?;
    if object_state(&fresh) != object_state(&actual) {
        return Err("RecoveryRequired: recovery observation changed before publication".into());
    }
    if let Some(parent) = &old_workspace {
        parent.recheck()?;
    }
    let mut c = authority.current.clone();
    c.revision = c
        .revision
        .checked_add(1)
        .ok_or("canonical revision overflow")?;
    c.mode = mode;
    c.active_operation = None;
    c.binding = bound.binding()?;
    c.settled = Some(Settled {
        target: object_state(&actual),
        applied,
        evidence: r,
    });
    authority.publish(c)?;
    authority.recovery_completion(
        "RecoverySettled: exact Pending operation resolved; original immutable failure retained"
    )
}
pub(crate) fn recover_initialization<W: MaintenanceWindow>(
    bound: BoundInstallation,
    expected: &str,
    window: &mut W,
) -> Result<String> {
    let mut authority = Authority::open(&bound, false, true)?;
    if authority.current.mode != Mode::Bootstrap
        || authority.digest != expected
        || authority.current.binding != bound.binding()?
    {
        return Err(
            "PreparationIncomplete: exact original Bootstrap binding/digest required".into(),
        );
    }
    for entry in
        fs::read_dir(NativeFsPath::from_path(&authority.slot.path)?.as_path()).map_err(|e| io("initialization footprint", e))?
    {
        let entry = entry.map_err(|e| io("initialization footprint entry", e))?;
        if entry.file_name() != OsStr::new("current.json") {
            return Err("PreparationIncomplete: extra footprint requires specific evidence receiving; no implicit deletion or enrollment".into());
        }
    }
    if desktop_hook::inspect_archive(&bound.bytes)
        .map_err(|e| e.to_string())?
        .hook_status
        != desktop_hook::HookStatus::Prepared
    {
        return Err("Bootstrap target is not supported pristine source".into());
    }
    window.ensure_held()?;
    let dir = authority.evidence_dir("initialization-recovery")?;
    let target = TargetState {
        digest: hash(&bound.bytes),
        metadata: identity(&bound.archive.file)?,
    };
    let evidence = authority.save(
        &dir,
        "enrollment.json",
        &json(&Settlement::Enrollment(target.clone()))?,
    )?;
    let mut current = authority.current.clone();
    current.revision = current
        .revision
        .checked_add(1)
        .ok_or("canonical revision overflow")?;
    current.mode = Mode::SettledUnchanged;
    current.settled = Some(Settled {
        target,
        applied: None,
        evidence,
    });
    authority.publish(current)?;
    Ok("InitializationRecovered: original Bootstrap independently received; no native operation occurred".into())
}
fn verify_failure_observations(
    f: &ActualFailure,
    source: &SourceSnapshot,
    layout: &LayoutBinding,
) -> Result<()> {
    let target = CheckedPath::open(
        &f.recovery.target.0,
        PathKind::File,
        PathPurpose::ReplaceSource,
    )?;
    if object_id(&open_regular(&source.target, READ | DELETE)?)? != target.object {
        return Err("legacy failure target conflict".into());
    }
    if !matches!(&f.recovery.target.1,archive_install::FileObservation::Present{identity,digest} if *identity==source.identity&&*digest==source.digest)
    {
        return Err("failure source observation differs from retained preimage".into());
    }
    for (entry, path) in [
        (&f.recovery.staged, &layout.staged),
        (&f.recovery.original_backup, &layout.original_backup),
        (&f.recovery.displaced_backup, &layout.displaced_backup),
    ] {
        let (saved, o) = entry
            .as_ref()
            .ok_or("failure missing required work observation")?;
        validate_path(saved)?;
        let parent = CheckedPath::open(
            saved.parent().ok_or("failure parent")?,
            PathKind::Directory,
            PathPurpose::ExternalLegacyInput,
        )?;
        let expected = CheckedPath::open(
            path.parent().ok_or("layout parent")?,
            PathKind::Directory,
            PathPurpose::ExternalLegacyInput,
        )?;
        if parent.object != expected.object
            || !ordinal(
                &saved
                    .file_name()
                    .ok_or("work leaf")?
                    .encode_wide()
                    .collect::<Vec<_>>(),
                &path
                    .file_name()
                    .ok_or("work leaf")?
                    .encode_wide()
                    .collect::<Vec<_>>(),
            )?
            || !matches!(o, archive_install::FileObservation::Missing)
        {
            return Err("failure work observation binding conflict".into());
        }
    }
    Ok(())
}
#[cfg(test)]
thread_local! { static TEST_FIXTURE_PARENT:std::cell::RefCell<Option<PathBuf>>=const{std::cell::RefCell::new(None)};static TEST_BASE:std::cell::RefCell<Option<PathBuf>>=const{std::cell::RefCell::new(None)};static TEST_BOOTSTRAP_SLOT_FAILURE:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};static TEST_BOOTSTRAP_FAILURE:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};static TEST_DACL_STATUSES:std::cell::RefCell<Vec<u32>>=const{std::cell::RefCell::new(Vec::new())};static TEST_NATIVE_CALLS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};static TEST_OUTCOME_FAILURE:std::cell::Cell<bool>=const{std::cell::Cell::new(false)}; }
#[cfg(test)]
#[path = "windows_installation/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "windows_installation/context_tests.rs"]
mod context_tests;
