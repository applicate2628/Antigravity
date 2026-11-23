//! Shared Windows native path, identity, security and resource primitives.
use super::*;
use std::ffi::c_void;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;

/// Internal filesystem spelling of an already admitted ordinary disk path.
/// Persisted paths and native GUID locators keep their existing representations.
pub(super) struct NativeFsPath {
    path: PathBuf,
    units: Vec<u16>,
}
impl NativeFsPath {
    const DOS_PREFIX: [u16; 4] = [92, 92, 63, 92];

    pub(super) fn encode(path: &WindowsLocalPath) -> Result<Self> {
        let mut units = Self::DOS_PREFIX.to_vec();
        units.extend(path.as_path().as_os_str().encode_wide().map(|unit| {
            if unit == 47 { 92 } else { unit }
        }));
        let path = OsString::from_wide(&units).into();
        units.push(0);
        Ok(Self { path, units })
    }

    pub(super) fn from_path(path: &Path) -> Result<Self> {
        Self::encode(&WindowsLocalPath::parse(path.as_os_str())?)
    }

    pub(super) fn as_ptr(&self) -> *const u16 {
        self.units.as_ptr()
    }

    pub(super) fn as_path(&self) -> &Path {
        &self.path
    }

    fn receive_name(&self, units: &[u16]) -> Result<PathBuf> {
        // Only the DOS-disk prefix introduced by this owner may be removed.
        // Other namespaces still go through the unchanged external parser.
        let ordinary = if units.starts_with(&Self::DOS_PREFIX)
            && units.get(4).is_some_and(|c| (65..=90).contains(c) || (97..=122).contains(c))
            && units.get(5) == Some(&58)
            && units.get(6) == Some(&92)
        {
            &units[4..]
        } else {
            units
        };
        WindowsLocalPath::parse(&OsString::from_wide(ordinary)).map(|path| path.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObjectId {
    pub(crate) volume: u64,
    pub(crate) file: [u8; 16],
}
#[repr(C)]
struct FileIdInformation {
    volume: u64,
    file: [u8; 16],
}
#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit: i32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(
        file: *mut c_void,
        class: u32,
        data: *mut c_void,
        size: u32,
    ) -> i32;
    fn GetFinalPathNameByHandleW(file: *mut c_void, out: *mut u16, size: u32, flags: u32) -> u32;
    fn GetLongPathNameW(path: *const u16, out: *mut u16, size: u32) -> u32;
    #[cfg(test)]
    fn GetShortPathNameW(path: *const u16, out: *mut u16, size: u32) -> u32;
    fn CreateDirectoryW(path: *const u16, security: *mut SecurityAttributes) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *mut SecurityAttributes,
        creation: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    pub(super) fn LocalFree(memory: *mut c_void) -> *mut c_void;
    pub(super) fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CompareStringOrdinal(
        first: *const u16,
        n: i32,
        second: *const u16,
        m: i32,
        ignore: i32,
    ) -> i32;
}
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoCreateGuid(guid: *mut Guid) -> i32;
    fn CoTaskMemFree(memory: *mut c_void);
}
#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        id: *const Guid,
        flags: u32,
        token: *mut c_void,
        out: *mut *mut u16,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    pub(super) fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
    pub(super) fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        version: u32,
        out: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    pub(super) fn GetSecurityDescriptorDacl(
        sd: *mut c_void,
        present: *mut i32,
        acl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
    pub(super) fn IsWellKnownSid(sid: *mut c_void, kind: u32) -> i32;
    pub(super) fn GetSecurityDescriptorControl(
        sd: *mut c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorGroup(
        sd: *mut c_void,
        group: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn SetSecurityInfo(
        handle: *mut c_void,
        kind: u32,
        information: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
    fn SetKernelObjectSecurity(handle: *mut c_void, information: u32, descriptor: *mut c_void) -> i32;
    fn LookupAccountNameW(
        system: *const u16,
        name: *const u16,
        sid: *mut c_void,
        sid_size: *mut u32,
        domain: *mut u16,
        domain_size: *mut u32,
        kind: *mut u32,
    ) -> i32;
}
/// DACL-only metadata preservation on an already bound owned postimage handle.
/// Owner/group are observed and never assigned; the caller verifies full final SD.
pub(super) fn restore_received_dacl(file: &File, expected: &[u8]) -> Result<()> {
    let mut before = security(file.as_raw_handle(), 1 | 2 | 4)?;
    if before == expected {
        return Ok(());
    }
    let mut source = expected.to_vec();
    for group in [false, true] {
        let mut old = std::ptr::null_mut();
        let mut new = std::ptr::null_mut();
        let mut d = 0;
        let (a, b) = unsafe {
            if group {
                (
                    GetSecurityDescriptorGroup(source.as_mut_ptr().cast(), &mut old, &mut d),
                    GetSecurityDescriptorGroup(before.as_mut_ptr().cast(), &mut new, &mut d),
                )
            } else {
                (
                    GetSecurityDescriptorOwner(source.as_mut_ptr().cast(), &mut old, &mut d),
                    GetSecurityDescriptorOwner(before.as_mut_ptr().cast(), &mut new, &mut d),
                )
            }
        };
        if a == 0 || b == 0 || old.is_null() || new.is_null() || unsafe { EqualSid(old, new) } == 0
        {
            return Err("postimage owner/group changed; DACL restoration refused".into());
        }
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe {
        GetSecurityDescriptorControl(source.as_mut_ptr().cast(), &mut control, &mut revision)
    } == 0
    {
        return Err(io(
            "received descriptor control",
            std::io::Error::last_os_error(),
        ));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            source.as_mut_ptr().cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err("received DACL absent/null; restoration refused".into());
    }
    let protection = if control & 0x1000 != 0 {
        0x8000_0000
    } else {
        0x2000_0000
    };
    // Preserve the captured inheritance model, without changing identity or
    // masking flags. The FILE API retains AUTO_INHERITED; the existing private
    // path retains its proved non-auto-inherited descriptor contract.
    let (operation, failure) = if control & 0x0400 != 0 {
        let status = unsafe { SetSecurityInfo(file.as_raw_handle(), 1, 4 | protection,
            std::ptr::null_mut(), std::ptr::null_mut(), acl, std::ptr::null_mut()) };
        ("SetSecurityInfo FILE DACL restoration", if status == 0 { None } else { Some(std::io::Error::from_raw_os_error(status as i32)) })
    } else {
        let restored = unsafe { SetKernelObjectSecurity(file.as_raw_handle(), 4 | protection, source.as_mut_ptr().cast()) };
        ("SetKernelObjectSecurity DACL restoration", if restored == 0 { Some(std::io::Error::last_os_error()) } else { None })
    };
    #[cfg(test)]
    TEST_DACL_STATUSES.with(|v| v.borrow_mut().push(failure.as_ref().and_then(|error|error.raw_os_error()).unwrap_or(0) as u32));
    if let Some(error)=failure {
        return Err(io(operation,error));
    }
    if security(file.as_raw_handle(), 1 | 2 | 4)? != expected {
        return Err(
            format!("{operation} returned success but full received security descriptor differs"),
        );
    }
    Ok(())
}

// Only the vendor Recover receiver supplies this helper's admitted snapshots.
// Parse bounded self-relative components before comparing or passing a SID to FFI.
fn group_security_parts(sd: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    validate_captured_identity_descriptor(sd)?;
    let sid = |field: usize| -> Result<&[u8]> {
        let start = u32::from_le_bytes(sd[field..field + 4].try_into().unwrap()) as usize;
        let length = 8 + 4 * usize::from(sd[start + 1]);
        sd.get(start..start + length).ok_or_else(|| "group metadata SID bounds invalid".into())
    };
    let control = u16::from_le_bytes([sd[2], sd[3]]);
    let start = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
    let header = sd.get(start..).filter(|_| start >= 20).ok_or("group metadata DACL absent")?;
    if control & 4 == 0 || header.len() < 8 || sd[12..16] != [0; 4] {
        return Err("group metadata requires the captured non-null DACL and no SACL component".into());
    }
    let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let acl = header.get(..length).filter(|_| length >= 8).ok_or("group metadata ACL bounds invalid")?;
    Ok((sid(4)?, sid(8)?, acl))
}

pub(super) fn current_token_user_sid() -> Result<Vec<u8>> {
    let mut token = token_user()?;
    let pointer = user_sid(&mut token)? as usize;
    let start = pointer.checked_sub(token.as_ptr() as usize).ok_or("token SID outside buffer")?;
    let sid = token.get(start..).ok_or("token SID outside buffer")?;
    if sid.len() < 8 || sid[0] != 1 || sid[1] > 15 {
        return Err("token SID invalid".into());
    }
    Ok(sid.get(..8 + 4 * usize::from(sid[1])).ok_or("token SID truncated")?.to_vec())
}

/// Pure receiving shared by admission, persisted proof and final receiving.
/// True means the complete raw desired descriptor is already present.
pub(super) fn receive_group_metadata(actual: &[u8], recorded: &[u8], desired: &[u8], actor: &[u8]) -> Result<bool> {
    let (owner, group, dacl) = group_security_parts(actual)?;
    let (old_owner, old_group, old_dacl) = group_security_parts(recorded)?;
    let (wanted_owner, wanted_group, wanted_dacl) = group_security_parts(desired)?;
    if wanted_owner != wanted_group || wanted_owner != actor
        || owner != wanted_owner || old_owner != wanted_owner
        || actual[..4] != desired[..4] || recorded[..4] != desired[..4]
        || dacl != wanted_dacl || old_dacl != wanted_dacl
        || (group != old_group && group != wanted_group) {
        return Err("RecoveryRequired: vendor metadata is outside the exact group-only class".into());
    }
    if group == wanted_group && actual != desired {
        return Err("RecoveryRequired: desired group lacks exact full descriptor receiving".into());
    }
    Ok(actual == desired)
}

/// Keeps the exact no-follow object, data and ancestor guards until after return
/// and independent readback. It never adjusts token privileges or DACL/OWNER.
pub(super) struct GroupMetadataHandle {
    file: File,
    _parents: Vec<File>,
    expected: SourceSnapshot,
    object: ObjectId,
    recorded: Vec<u8>,
    desired: Vec<u8>,
    actor: Vec<u8>,
}
impl GroupMetadataHandle {
    pub(super) fn open(expected: &SourceSnapshot, object: &ObjectId, recorded: &[u8], desired: &[u8], actor: &[u8]) -> Result<Self> {
        let parents = parents(&expected.target)?;
        // FILE_READ_DATA/ATTRIBUTES for existing snapshot receiving, plus only
        // READ_CONTROL | WRITE_OWNER for security. No WRITE_DAC or SACL access.
        let file = OpenOptions::new().access_mode(0x000A_0081).share_mode(READ)
            .custom_flags(OPEN_REPARSE).open(NativeFsPath::from_path(&expected.target)?.as_path())
            .map_err(|e| io("vendor group READ_CONTROL/WRITE_OWNER (not called)", e))?;
        let mut received = Self { file, _parents: parents, expected: expected.clone(), object: object.clone(),
            recorded: recorded.to_vec(), desired: desired.to_vec(), actor: actor.to_vec() };
        received.recheck()?;
        Ok(received)
    }
    pub(super) fn recheck(&mut self) -> Result<()> {
        if current_token_user_sid()? != self.actor || object_id(&self.file)? != self.object
            || !same_snapshot(&read_checked(&mut self.file, &self.expected.target)?, &self.expected) {
            return Err("RecoveryRequired: group call actor/postimage changed before call".into());
        }
        receive_group_metadata(&self.expected.identity.security_descriptor, &self.recorded, &self.desired, &self.actor)?;
        Ok(())
    }
    /// The returned WinError is the acquired native outcome. Nothing fallible
    /// runs between the API and returning it to the durable result writer.
    pub(super) fn set_group(&mut self) -> u32 {
        let start = u32::from_le_bytes(self.desired[8..12].try_into().unwrap()) as usize;
        #[cfg(test)]
        TEST_GROUP_CALLS.with(|value| value.set(value.get() + 1));
        unsafe { SetSecurityInfo(self.file.as_raw_handle(), 1, 2, std::ptr::null_mut(),
            self.desired.as_mut_ptr().add(start).cast(), std::ptr::null_mut(), std::ptr::null_mut()) }
    }
    pub(super) fn readback(&mut self) -> Result<(SourceSnapshot, ObjectId)> {
        let snapshot = read_checked(&mut self.file, &self.expected.target)?;
        Ok((snapshot, object_id(&self.file)?))
    }
}
#[cfg(test)]
thread_local! { pub(super) static TEST_GROUP_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
pub(super) fn fixture_wrong_group_metadata(source: &FileIdentity) -> Result<FileIdentity> {
    #[link(name = "advapi32")]
    unsafe extern "system" { fn CheckTokenMembership(token: *mut c_void, sid: *mut c_void, member: *mut i32) -> i32; }
    let actor = current_token_user_sid()?;
    receive_group_metadata(&source.security_descriptor, &source.security_descriptor, &source.security_descriptor, &actor)?;
    let user = sid_text(actor.as_ptr() as *mut c_void)?;
    let text: Vec<_> = format!("O:{user}G:BU").encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    let mut length = 0;
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, &mut length) } == 0 {
        return Err(io("fixture differing group descriptor", std::io::Error::last_os_error()));
    }
    let descriptor = LocalMemory(descriptor);
    let mut group = std::ptr::null_mut();
    let mut defaulted = 0;
    let mut enabled = 0;
    if unsafe { GetSecurityDescriptorGroup(descriptor.0, &mut group, &mut defaulted) } == 0 || group.is_null()
        || unsafe { CheckTokenMembership(std::ptr::null_mut(), group, &mut enabled) } == 0 || enabled == 0
        || unsafe { EqualSid(group, actor.as_ptr() as *mut c_void) } != 0 {
        return Err("owned fixture requires an enabled differing Builtin Users group".into());
    }
    let mut metadata = source.clone();
    metadata.security_descriptor = unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length as usize) }.to_vec();
    Ok(metadata)
}
#[cfg(test)]
pub(super) fn initialize_token_group_fixture(path: &Path) -> Result<()> {
    let _parents = parents(path)?;
    let actor = current_token_user_sid()?;
    let before = read_path(path, READ | DELETE)?;
    let file = OpenOptions::new().access_mode(0x000A_0081).share_mode(READ | DELETE).custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(path)?.as_path()).map_err(|e| io("owned fixture group initialization", e))?;
    let status = unsafe { SetSecurityInfo(file.as_raw_handle(), 1, 2, std::ptr::null_mut(), actor.as_ptr() as *mut c_void,
        std::ptr::null_mut(), std::ptr::null_mut()) };
    if status != 0 { return Err(format!("owned fixture group initialization WinError={status}")); }
    let after = read_path(path, READ | DELETE)?;
    let (owner, group, dacl) = group_security_parts(&after.identity.security_descriptor)?;
    let (old_owner, _, old_dacl) = group_security_parts(&before.identity.security_descriptor)?;
    if owner != actor || group != actor || owner != old_owner || dacl != old_dacl
        || before.bytes != after.bytes || before.identity.index != after.identity.index || before.identity.size != after.identity.size
        || before.identity.volume != after.identity.volume || before.identity.attributes != after.identity.attributes
        || before.identity.creation != after.identity.creation || before.identity.write != after.identity.write {
        return Err("owned fixture group initialization changed another field".into());
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn initialize_inherited_fixture(path: &Path) -> Result<()> {
    set_fixture_protection(path, false)
}
#[cfg(test)]
pub(super) fn set_fixture_protection(path: &Path, protected: bool) -> Result<()> {
    let native_path = NativeFsPath::from_path(path)?;
    let file = OpenOptions::new()
        .access_mode(0x0006_0000)
        .share_mode(READ | DELETE)
        .custom_flags(OPEN_REPARSE)
        .open(native_path.as_path())
        .map_err(|e| io("owned fixture inheritance handle", e))?;
    let mut sd = security(file.as_raw_handle(), 1 | 2 | 4)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            sd.as_mut_ptr().cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err("fixture DACL unavailable".into());
    }
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            1,
            4 | if protected { 0x8000_0000 } else { 0x2000_0000 },
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(format!("fixture inheritance status {status}"));
    }
    let mut sd = security(file.as_raw_handle(), 1 | 2 | 4)?;
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(sd.as_mut_ptr().cast(), &mut control, &mut revision) }
        == 0
        || (control & 0x1000 != 0) != protected
        || (!protected && control & 0x400 == 0)
    {
        return Err("fixture source is not unprotected AutoInherited class".into());
    }
    Ok(())
}
pub(super) fn object_id(file: &File) -> Result<ObjectId> {
    let mut data = FileIdInformation {
        volume: 0,
        file: [0; 16],
    };
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            18,
            (&mut data as *mut FileIdInformation).cast(),
            std::mem::size_of::<FileIdInformation>() as u32,
        )
    } == 0
    {
        return Err(io("full native identity", std::io::Error::last_os_error()));
    }
    Ok(ObjectId {
        volume: data.volume,
        file: data.file,
    })
}
pub(super) fn case_insensitive(file: &File) -> Result<()> {
    let mut flags = 0u32;
    if unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), 23, (&mut flags as *mut u32).cast(), 4)
    } == 0
    {
        return Err(io("directory case mode", std::io::Error::last_os_error()));
    }
    if flags & 1 != 0 {
        return Err("case-sensitive directory unsupported".into());
    }
    Ok(())
}
pub(super) fn ordinal(a: &[u16], b: &[u16]) -> Result<bool> {
    let n = i32::try_from(a.len()).map_err(|_| "native locator length")?;
    let m = i32::try_from(b.len()).map_err(|_| "native locator length")?;
    match unsafe { CompareStringOrdinal(a.as_ptr(), n, b.as_ptr(), m, 1) } {
        0 => Err(io(
            "native ordinal comparison",
            std::io::Error::last_os_error(),
        )),
        2 => Ok(true),
        _ => Ok(false),
    }
}
pub(super) fn final_path(file: &File) -> Result<Vec<u16>> {
    let count =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), std::ptr::null_mut(), 0, 1) };
    if count == 0 {
        return Err(io("native locator length", std::io::Error::last_os_error()));
    }
    let mut out = vec![0u16; count as usize];
    let n = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), out.as_mut_ptr(), count, 1) };
    if n == 0 || n >= count {
        return Err("native locator receiving failed".into());
    }
    out.truncate(n as usize);
    Ok(out)
}
pub(super) fn long_path(path: &Path) -> Result<PathBuf> {
    let path = NativeFsPath::from_path(path)?;
    let count = unsafe { GetLongPathNameW(path.as_ptr(), std::ptr::null_mut(), 0) };
    if count == 0 {
        return Err(io("long path length", std::io::Error::last_os_error()));
    }
    let mut out = vec![0u16; count as usize];
    let n = unsafe { GetLongPathNameW(path.as_ptr(), out.as_mut_ptr(), count) };
    if n == 0 || n >= count {
        return Err("long path receiving failed".into());
    }
    out.truncate(n as usize);
    path.receive_name(&out)
}
#[cfg(test)]
pub(super) fn short_fixture_path(path: &Path) -> Result<PathBuf> {
    let input = NativeFsPath::from_path(path)?;
    let count = unsafe { GetShortPathNameW(input.as_ptr(), std::ptr::null_mut(), 0) };
    if count == 0 {
        return Err(io(
            "short-name fixture observation",
            std::io::Error::last_os_error(),
        ));
    }
    let mut out = vec![0; count as usize];
    let length = unsafe { GetShortPathNameW(input.as_ptr(), out.as_mut_ptr(), count) };
    if length == 0 || length >= count {
        return Err("short-name fixture receiving failed".into());
    }
    out.truncate(length as usize);
    input.receive_name(&out)
}
pub(super) fn unique_id() -> Result<String> {
    let mut g = Guid {
        a: 0,
        b: 0,
        c: 0,
        d: [0; 8],
    };
    if unsafe { CoCreateGuid(&mut g) } < 0 {
        return Err("OS operation identity unavailable".into());
    }
    Ok(format!(
        "{:08x}{:04x}{:04x}{}",
        g.a,
        g.b,
        g.c,
        hex::encode(g.d)
    ))
}
pub(super) fn known_folder() -> Result<PathBuf> {
    native_known_folder(NativeKnownFolder::LocalAppData)
}
pub(super) enum NativeKnownFolder {
    LocalAppData,
    ProgramFiles,
    ProgramData,
}
pub(super) fn native_known_folder(folder: NativeKnownFolder) -> Result<PathBuf> {
    // Windows SDK KnownFolders.h identifiers. ProgramFiles intentionally follows
    // the supported executing package architecture, not ProgramFilesX64/X86.
    let id = match folder {
        NativeKnownFolder::LocalAppData => Guid {
            a: 0xf1b32785,
            b: 0x6fba,
            c: 0x4fcf,
            d: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
        },
        NativeKnownFolder::ProgramFiles => Guid {
            a: 0x905e63b6,
            b: 0xc1bf,
            c: 0x494e,
            d: [0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a],
        },
        NativeKnownFolder::ProgramData => Guid {
            a: 0x62ab5d82,
            b: 0xfdc1,
            c: 0x4dc3,
            d: [0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97],
        },
    };
    let mut out = std::ptr::null_mut();
    let hr = unsafe { SHGetKnownFolderPath(&id, 0, std::ptr::null_mut(), &mut out) };
    if hr < 0 || out.is_null() {
        if !out.is_null() {
            unsafe { CoTaskMemFree(out.cast()) }
        }
        return Err(format!("KnownFolder unavailable: {hr:#x}"));
    }
    let mut n = 0;
    unsafe {
        while *out.add(n) != 0 {
            n += 1
        }
    }
    let path = PathBuf::from(unsafe { OsString::from_wide(std::slice::from_raw_parts(out, n)) });
    unsafe { CoTaskMemFree(out.cast()) }
    validate_path(&path)?;
    Ok(path)
}
pub(super) fn token_user() -> Result<Vec<u8>> {
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) } == 0 {
        return Err(io("current token", std::io::Error::last_os_error()));
    }
    let token = OwnedHandle(raw);
    let mut needed = 0;
    unsafe { GetTokenInformation(token.0, 1, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err("token user length unavailable".into());
    }
    let mut data = vec![0; needed as usize];
    if unsafe { GetTokenInformation(token.0, 1, data.as_mut_ptr().cast(), needed, &mut needed) }
        == 0
    {
        return Err(io("token user", std::io::Error::last_os_error()));
    }
    Ok(data)
}
pub(super) fn user_sid(data: &mut [u8]) -> Result<*mut c_void> {
    if data.len() < std::mem::size_of::<*mut c_void>() {
        return Err("invalid token user".into());
    }
    let sid = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<*mut c_void>()) };
    if sid.is_null() {
        return Err("missing token user".into());
    }
    Ok(sid)
}
pub(super) fn private(file: &File) -> Result<()> {
    check_access(file, true, false, true)
}
pub(super) fn existing_private(file: &File) -> Result<()> {
    check_access(file, false, false, true)
}
pub(super) fn state_parent(file: &File) -> Result<()> {
    check_access(file, false, false, false)
}
pub(super) fn state_parent_context(
    file: &File,
    context: &super::AncestorAccessContext,
) -> Result<()> {
    // Context qualifies ancestor ACL actors, never changes the required owner.
    let mut sd = security(file.as_raw_handle(), 1)?;
    let mut owner = std::ptr::null_mut();
    let mut d = 0;
    let mut token = token_user()?;
    if unsafe { GetSecurityDescriptorOwner(sd.as_mut_ptr().cast(), &mut owner, &mut d) } == 0
        || owner.is_null()
        || unsafe { EqualSid(owner, user_sid(&mut token)?) } == 0
    {
        return Err("state-parent owner conflict".into());
    }
    context.check(file, false)
}
pub(super) fn ancestor_integrity(file: &File) -> Result<()> {
    check_access(file, false, true, false)
}
pub(super) fn trusted_installer_sid() -> Result<Vec<u8>> {
    let name: Vec<_> = "NT SERVICE\\TrustedInstaller"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut size = 0;
    let mut domain_size = 0;
    let mut kind = 0;
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut kind,
        )
    };
    if size == 0 {
        return Err(io(
            "Windows Modules Installer identity unavailable",
            std::io::Error::last_os_error(),
        ));
    }
    let mut sid = vec![0; size as usize];
    let mut domain = vec![0; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut kind,
        )
    } == 0
    {
        return Err(io(
            "Windows Modules Installer identity resolution",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(sid)
}
fn check_access(
    file: &File,
    managed: bool,
    system_ancestor: bool,
    confidential: bool,
) -> Result<()> {
    let mut sd = security(file.as_raw_handle(), 1 | 4)?;
    let mut token = token_user()?;
    let sid = user_sid(&mut token)?;
    let trusted_service = if system_ancestor {
        Some(trusted_installer_sid()?)
    } else {
        None
    };
    let mut owner = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(sd.as_mut_ptr().cast(), &mut owner, &mut defaulted) }
        == 0
        || owner.is_null()
    {
        return Err("object owner unavailable".into());
    }
    if unsafe { EqualSid(owner, sid) } == 0 {
        if !system_ancestor {
            return Err("private/state-parent owner conflict".into());
        }
        if unsafe { IsWellKnownSid(owner, 22) } == 0 && unsafe { IsWellKnownSid(owner, 26) } == 0 {
            if !trusted_service
                .as_ref()
                .is_some_and(|t| unsafe { EqualSid(owner, t.as_ptr() as *mut c_void) } != 0)
            {
                return Err("ancestor owner can replace the state namespace".into());
            }
        }
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(sd.as_mut_ptr().cast(), &mut control, &mut revision) }
        == 0
    {
        return Err(io(
            "private protection control",
            std::io::Error::last_os_error(),
        ));
    }
    if managed && control & 0x1000 == 0 {
        return Err("managed DACL is not protected".into());
    }
    let mut present = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            sd.as_mut_ptr().cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err("private DACL absent/null".into());
    }
    if !confidential {
        return super::ancestor_context::check_empty(file, system_ancestor);
    }
    // ACL header's AceCount is a WORD at offset 4. GetAce validates each entry.
    let count = unsafe { std::ptr::read_unaligned((acl as *const u8).add(4).cast::<u16>()) };
    for i in 0..u32::from(count) {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(acl, i, &mut ace) } == 0 || ace.is_null() {
            return Err("private ACE unavailable".into());
        }
        let header = ace as *const u8;
        let kind = unsafe { *header };
        let size = unsafe { std::ptr::read_unaligned(header.add(2).cast::<u16>()) };
        if kind == 1 || unsafe { *header.add(1) } & 8 != 0 {
            continue;
        } // deny/inherit-only grants no current access.
        if kind != 0 || size < 12 {
            return Err("unsupported private ACL entry".into());
        }
        let principal = unsafe { header.add(8) } as *mut c_void;
        if unsafe { EqualSid(principal, sid) } == 0
            && unsafe { IsWellKnownSid(principal, 22) } == 0
            && unsafe { IsWellKnownSid(principal, 26) } == 0
            && !trusted_service
                .as_ref()
                .is_some_and(|t| unsafe { EqualSid(principal, t.as_ptr() as *mut c_void) } != 0)
        {
            let mask = unsafe { std::ptr::read_unaligned(header.add(4).cast::<u32>()) };
            // Directory sibling creation is not replacement of this held path.
            const REPLACEMENT_RIGHTS: u32 = 0x500D_0150;
            if confidential || mask & REPLACEMENT_RIGHTS != 0 {
                return Err("private/ancestor ACL grants foreign replacement access".into());
            }
        }
    }
    Ok(())
}
struct LocalMemory(*mut c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn private_descriptor() -> Result<LocalMemory> {
    private_descriptor_with_identity(None).map(|(descriptor, _)| descriptor)
}
fn sid_text(sid: *mut c_void) -> Result<String> {
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io(
            "current SID conversion",
            std::io::Error::last_os_error(),
        ));
    }
    let _text = LocalMemory(text.cast());
    let mut n = 0;
    unsafe {
        while *text.add(n) != 0 {
            n += 1
        }
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, n) })
        .map_err(|_| "SID text encoding".into())
}
fn validate_captured_identity_descriptor(descriptor: &[u8]) -> Result<()> {
    // GetSecurityDescriptorOwner/Group expect a complete self-relative header
    // and SID components. Check their bounds before passing captured bytes to FFI.
    if descriptor.len() < 20 || descriptor[0] != 1 ||
        u16::from_le_bytes([descriptor[2], descriptor[3]]) & 0x8000 == 0 {
        return Err("captured security descriptor is absent or invalid".into());
    }
    for field in [4, 8] {
        let offset = u32::from_le_bytes(descriptor[field..field + 4].try_into().unwrap()) as usize;
        let sid = descriptor.get(offset..).filter(|_| offset >= 20)
            .ok_or("captured owner/group is absent or invalid")?;
        // SID revision 1 permits at most 15 subauthorities (Windows SID format).
        if sid.len() < 8 || sid[0] != 1 || sid[1] > 15 || sid.len() < 8 + 4 * usize::from(sid[1]) {
            return Err("captured owner/group is absent or invalid".into());
        }
    }
    Ok(())
}
fn private_descriptor_with_identity(captured: Option<&[u8]>) -> Result<(LocalMemory, u32)> {
    let mut token = token_user()?;
    let user = sid_text(user_sid(&mut token)?)?;
    let identity = if let Some(captured) = captured {
        validate_captured_identity_descriptor(captured)?;
        let mut captured = captured.to_vec();
        let mut owner = std::ptr::null_mut();
        let mut group = std::ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorOwner(captured.as_mut_ptr().cast(), &mut owner, &mut defaulted) } == 0
            || unsafe { GetSecurityDescriptorGroup(captured.as_mut_ptr().cast(), &mut group, &mut defaulted) } == 0
            || owner.is_null() || group.is_null()
        {
            return Err("captured metadata owner/group unavailable before stage creation".into());
        }
        format!("O:{}G:{}", sid_text(owner)?, sid_text(group)?)
    } else {
        format!("O:{user}")
    };
    let sddl: Vec<_> = format!("{identity}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut sd = std::ptr::null_mut();
    let mut length = 0;
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut sd,
            &mut length,
        )
    } == 0
    {
        return Err(io("private descriptor", std::io::Error::last_os_error()));
    }
    let descriptor = LocalMemory(sd);
    if sd.is_null() || length == 0 {
        return Err("private descriptor bytes unavailable".into());
    }
    Ok((descriptor, length))
}
pub(super) fn create_private_dir(path: &Path) -> Result<()> {
    let native_path = NativeFsPath::from_path(path)?;
    let _parents = parents(path)?;
    let sd = private_descriptor()?;
    let mut sa = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: sd.0,
        inherit: 0,
    };
    if unsafe { CreateDirectoryW(native_path.as_ptr(), &mut sa) } == 0 {
        return Err(io(
            "exclusive private directory create",
            std::io::Error::last_os_error(),
        ));
    }
    let receiving = (|| {
        let p = CheckedPath::open(path, PathKind::Directory, PathPurpose::Review)?;
        private(&p.file)
    })();
    receiving.map_err(|e: String| format!("PreparationIncomplete: directory created at {}; actual identity/protection receiving failed: {e}; preserve it",path.display()))
}
pub(super) fn create_owned_file(path: &Path) -> Result<File> {
    create_owned_file_with_identity(path, None)
}
// A self-relative descriptor may pack its components in any order. This
// receiving is only for a fresh authored stage, not stored target snapshots.
fn authored_stage_descriptor_matches(actual: &[u8], authored: &[u8]) -> Result<bool> {
    let mut actual = actual.to_vec();
    let mut authored = authored.to_vec();
    let mut actual_control = 0;
    let mut authored_control = 0;
    let mut actual_revision = 0;
    let mut authored_revision = 0;
    if unsafe { GetSecurityDescriptorControl(actual.as_mut_ptr().cast(), &mut actual_control, &mut actual_revision) } == 0
        || unsafe { GetSecurityDescriptorControl(authored.as_mut_ptr().cast(), &mut authored_control, &mut authored_revision) } == 0
    {
        return Err(io("authored stage descriptor control", std::io::Error::last_os_error()));
    }
    if actual_control != authored_control || actual_revision != authored_revision
        || actual.get(..2) != authored.get(..2)
    {
        return Ok(false);
    }
    for group in [false, true] {
        let getter = if group { GetSecurityDescriptorGroup } else { GetSecurityDescriptorOwner };
        let mut actual_sid = std::ptr::null_mut();
        let mut authored_sid = std::ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { getter(actual.as_mut_ptr().cast(), &mut actual_sid, &mut defaulted) } == 0
            || unsafe { getter(authored.as_mut_ptr().cast(), &mut authored_sid, &mut defaulted) } == 0
            || actual_sid.is_null() || authored_sid.is_null()
        {
            return Err("authored stage owner/group unavailable".into());
        }
        if unsafe { EqualSid(actual_sid, authored_sid) } == 0 { return Ok(false); }
    }
    let acl = |sd: &mut [u8]| -> Result<(i32, i32, Vec<u8>)> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut pointer = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(sd.as_mut_ptr().cast(), &mut present, &mut pointer, &mut defaulted) } == 0
            || present == 0 || pointer.is_null()
        {
            return Err("authored private stage DACL unavailable".into());
        }
        // ACL.AclSize is the native byte size, including all ACE flags/order
        // and padding. Eight bytes is the Windows ACL header, not a policy cap.
        let size = unsafe { std::ptr::read_unaligned(pointer.cast::<u8>().add(2).cast::<u16>()) } as usize;
        if size < 8 { return Err("authored private stage ACL header invalid".into()); }
        Ok((present, defaulted, unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), size) }.to_vec()))
    };
    Ok(acl(&mut actual)? == acl(&mut authored)?)
}
fn create_owned_file_with_identity(path: &Path, captured: Option<&[u8]>) -> Result<File> {
    create_owned_file_with_access(path, captured, 0xC0000000, 0)
}
fn create_owned_file_with_access(path: &Path, captured: Option<&[u8]>, access: u32, share: u32) -> Result<File> {
    let (file, sd, descriptor_length) = create_owned_file_raw(path, captured, access, share)?;
    let receiving = if captured.is_some() {
        identity(&file).and_then(|_| {
            let expected = unsafe { std::slice::from_raw_parts(sd.0.cast::<u8>(), descriptor_length as usize) };
            if !authored_stage_descriptor_matches(&security(file.as_raw_handle(), 1 | 2 | 4)?, expected)? {
                return Err("captured metadata identity/private stage descriptor differs before publish".into());
            }
            Ok(())
        })
    } else {
        private(&file)
    };
    receiving.map_err(|e| {
        format!(
            "private file created at {}; protection receiving failed: {e}; preserve it",
            path.display()
        )
    })?;
    Ok(file)
}
fn create_owned_file_raw(path: &Path, captured: Option<&[u8]>, access: u32, share: u32) -> Result<(File, LocalMemory, u32)> {
    let native_path = NativeFsPath::from_path(path)?;
    let _parents = parents(path)?;
    let (sd, descriptor_length) = private_descriptor_with_identity(captured)?;
    let mut sa = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: sd.0,
        inherit: 0,
    };
    let raw = unsafe {
        CreateFileW(
            native_path.as_ptr(),
            access,
            share,
            &mut sa,
            1,
            OPEN_REPARSE,
            std::ptr::null_mut(),
        )
    };
    if raw as isize == -1 {
        return Err(io(
            "exclusive private file create",
            std::io::Error::last_os_error(),
        ));
    }
    Ok((unsafe { File::from_raw_handle(raw) }, sd, descriptor_length))
}
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_owned_file(path)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| {
            format!(
                "{}; retained actual file {}",
                io("private file persist", e),
                path.display()
            )
        })?;
    drop(file);
    let mut received = CheckedPath::open(path, PathKind::File, PathPurpose::Review)?;
    private(&received.file)?;
    if received.read()? != bytes {
        return Err("private file readback mismatch".into());
    }
    Ok(())
}
/// Same-thread, zero-wait ownership; abandonment is an unresolved operation.
pub(super) struct Lease {
    pub(super) mutex: OwnedHandle,
    pub(super) held: bool,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.held {
            unsafe {
                ReleaseMutex(self.mutex.0);
            }
        }
    }
}
impl Lease {
    pub(super) const BUSY: &'static str = "maintenance-pending: another owned operation holds lease";

    pub(super) fn acquire(directory: &CheckedPath, protocol: &str) -> Result<Self> {
        Self::try_acquire(directory, protocol)?.ok_or_else(|| Self::BUSY.into())
    }
    pub(super) fn try_acquire(directory: &CheckedPath, protocol: &str) -> Result<Option<Self>> {
        let name = format!(
            "Global\\AGUnlocker_{protocol}_{:016x}_{}",
            directory.object.volume,
            hex::encode(directory.object.file)
        );
        Self::try_acquire_name(&name)
    }
    pub(super) fn acquire_name(name: &str) -> Result<Self> {
        Self::try_acquire_name(name)?.ok_or_else(|| Self::BUSY.into())
    }
    fn try_acquire_name(name: &str) -> Result<Option<Self>> {
        use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
        if !name.starts_with("Global\\AGUnlocker_") || name.chars().any(char::is_control) {
            return Err("owned native lease namespace invalid".into());
        }
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let sd = private_descriptor()?;
        let mut attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: sd.0,
            inherit: 0,
        };
        let mutex = OwnedHandle(unsafe {
            CreateMutexW((&mut attributes as *mut SecurityAttributes).cast(), 0, name.as_ptr())
        });
        if mutex.0.is_null() {
            return Err(io("owned mutex create", std::io::Error::last_os_error()));
        }
        mutex_current_owner(mutex.0)?;
        match unsafe { WaitForSingleObject(mutex.0, 0) } {
            WAIT_OBJECT_0 => Ok(Some(Self { mutex, held: true })),
            WAIT_ABANDONED => {
                unsafe {
                    ReleaseMutex(mutex.0);
                };
                Err("RecoveryRequired: prior owner abandoned its mutex".into())
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(io("owned mutex wait", std::io::Error::last_os_error())),
        }
    }
}

/// Only a native timeout is represented by None. The attempt owns and releases
/// any partial acquisition before returning None to the waiter.
pub(super) fn wait_for_native_lease<T>(stage: &str, check: &dyn Fn() -> Result<()>,
    mut attempt: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    loop {
        check().map_err(|error| format!("{error}; vendor recovery stage={stage}"))?;
        if let Some(received) = attempt().map_err(|error| format!("{error}; vendor recovery stage={stage}"))? {
            return Ok(received);
        }
        std::thread::sleep(crate::windows_coordinator::OWNER_OBSERVATION_CADENCE);
    }
}

pub(super) const READ: u32 = 1;
pub(super) const WRITE: u32 = 2;
pub(super) const DELETE: u32 = 4;
pub(super) const REPARSE: u32 = 0x400;
pub(super) const DIRECTORY: u32 = 0x10;
pub(super) const OPEN_REPARSE: u32 = 0x0020_0000;
pub(super) const BACKUP_SEMANTICS: u32 = 0x0200_0000;

#[repr(C)]
#[derive(Default)]
pub(super) struct FileTime {
    pub(super) low: u32,
    pub(super) high: u32,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct FileInformation {
    pub(super) attributes: u32,
    pub(super) creation: FileTime,
    pub(super) access: FileTime,
    pub(super) write: FileTime,
    pub(super) volume: u32,
    pub(super) size_high: u32,
    pub(super) size_low: u32,
    pub(super) links: u32,
    pub(super) index_high: u32,
    pub(super) index_low: u32,
}
#[repr(C)]
pub(super) struct BasicInformation {
    pub(super) creation: i64,
    pub(super) access: i64,
    pub(super) write: i64,
    pub(super) change: i64,
    pub(super) attributes: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    pub(super) fn GetFileInformationByHandle(file: *mut c_void, info: *mut FileInformation) -> i32;
    pub(super) fn SetFileInformationByHandle(
        file: *mut c_void,
        class: u32,
        info: *const c_void,
        size: u32,
    ) -> i32;
    pub(super) fn ReplaceFileW(
        target: *const u16,
        replacement: *const u16,
        backup: *const u16,
        flags: u32,
        exclude: *mut c_void,
        reserved: *mut c_void,
    ) -> i32;
    pub(super) fn CreateMutexW(
        attributes: *mut c_void,
        owner: i32,
        name: *const u16,
    ) -> *mut c_void;
    pub(super) fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    pub(super) fn ReleaseMutex(handle: *mut c_void) -> i32;
    pub(super) fn CloseHandle(handle: *mut c_void) -> i32;
    pub(super) fn GetCurrentProcess() -> *mut c_void;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    pub(super) fn GetKernelObjectSecurity(
        object: *mut c_void,
        information: u32,
        descriptor: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    pub(super) fn OpenProcessToken(
        process: *mut c_void,
        access: u32,
        token: *mut *mut c_void,
    ) -> i32;
    pub(super) fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        data: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    pub(super) fn GetSecurityDescriptorOwner(
        descriptor: *mut c_void,
        owner: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn EqualSid(first: *mut c_void, second: *mut c_void) -> i32;
}

pub(super) struct OwnedHandle(pub(super) *mut c_void);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

pub(super) fn mutex_current_owner(handle: *mut c_void) -> Result<(), String> {
    let mut descriptor = security(handle, 1)?;
    let mut owner = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorOwner(descriptor.as_mut_ptr().cast(), &mut owner, &mut defaulted)
    } == 0
        || owner.is_null()
    {
        return Err(io("mutex security owner", std::io::Error::last_os_error()));
    }
    let mut raw_token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw_token) } == 0 {
        return Err(io("current token", std::io::Error::last_os_error()));
    }
    let token = OwnedHandle(raw_token);
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token.0, 1, std::ptr::null_mut(), 0, &mut needed);
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(122) || needed == 0 {
        return Err(io("token user length", std::io::Error::last_os_error()));
    }
    let mut user = vec![0u8; needed as usize];
    if unsafe { GetTokenInformation(token.0, 1, user.as_mut_ptr().cast(), needed, &mut needed) }
        == 0
    {
        return Err(io("token user", std::io::Error::last_os_error()));
    }
    if user.len() < std::mem::size_of::<*mut c_void>() {
        return Err("invalid current token user".into());
    }
    let sid = unsafe { std::ptr::read_unaligned(user.as_ptr().cast::<*mut c_void>()) };
    if sid.is_null() || unsafe { EqualSid(owner, sid) } == 0 {
        return Err("installation mutex owner collision".into());
    }
    Ok(())
}

/// Native identity and recovery-relevant metadata; last-access is deliberately
/// omitted because reading a file may update it. Security bytes stay in memory.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileIdentity {
    pub volume: u32,
    pub index: u64,
    pub size: u64,
    pub attributes: u32,
    pub creation: u64,
    pub write: u64,
    pub security_descriptor: Vec<u8>,
}
impl std::fmt::Debug for FileIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileIdentity")
            .field("volume", &self.volume)
            .field("index", &self.index)
            .field("size", &self.size)
            .field("attributes", &self.attributes)
            .field("creation", &self.creation)
            .field("write", &self.write)
            .field("security_descriptor_bytes", &self.security_descriptor.len())
            .finish()
    }
}
#[derive(Debug, Clone)]
pub(crate) struct SourceSnapshot {
    pub(super) target: PathBuf,
    pub(super) bytes: Vec<u8>,
    pub(super) digest: String,
    pub(super) identity: FileIdentity,
}
impl SourceSnapshot {
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }
    pub(crate) fn digest(&self) -> &str { &self.digest }
    pub(crate) fn matches(&self, other: &Self) -> bool { same_snapshot(self, other) }
    pub(crate) fn same_security(&self, other: &Self) -> bool {
        self.identity.security_descriptor == other.identity.security_descriptor
    }
}
#[derive(Debug, Clone)]
pub(super) struct InstallPaths {
    pub staged: PathBuf,
    pub original_backup: PathBuf,
    pub displaced_backup: PathBuf,
}
pub(super) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn io(context: &str, e: std::io::Error) -> String {
    format!("{context}: {e}")
}
pub(super) fn time(t: FileTime) -> u64 {
    (u64::from(t.high) << 32) | u64::from(t.low)
}
pub(super) fn information(file: &File) -> Result<FileInformation, String> {
    let mut info = FileInformation::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io("file identity", std::io::Error::last_os_error()));
    }
    Ok(info)
}
pub(super) fn identity(file: &File) -> Result<FileIdentity, String> {
    file_identity(file, true)
}
pub(super) fn executable_identity(file: &File) -> Result<FileIdentity, String> {
    file_identity(file, false)
}
fn file_identity(file: &File, single_link: bool) -> Result<FileIdentity, String> {
    let info = information(file)?;
    if info.attributes & (REPARSE | DIRECTORY) != 0
        || info.links == 0
        || (single_link && info.links != 1)
    {
        return Err("nonregular/reparse/hardlink conflict".into());
    }
    let security = security(file.as_raw_handle(), 1 | 2 | 4)?;
    Ok(FileIdentity {
        volume: info.volume,
        index: (u64::from(info.index_high) << 32) | u64::from(info.index_low),
        size: (u64::from(info.size_high) << 32) | u64::from(info.size_low),
        attributes: info.attributes,
        creation: time(info.creation),
        write: time(info.write),
        security_descriptor: security,
    })
}
pub(super) fn security(handle: *mut c_void, flags: u32) -> Result<Vec<u8>, String> {
    let mut needed = 0;
    let first =
        unsafe { GetKernelObjectSecurity(handle, flags, std::ptr::null_mut(), 0, &mut needed) };
    if first != 0 || std::io::Error::last_os_error().raw_os_error() != Some(122) || needed == 0 {
        return Err(io(
            "security descriptor length",
            std::io::Error::last_os_error(),
        ));
    }
    let mut security = vec![0u8; needed as usize];
    if unsafe {
        GetKernelObjectSecurity(
            handle,
            flags,
            security.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io("security descriptor", std::io::Error::last_os_error()));
    }
    security.truncate(needed as usize);
    Ok(security)
}
pub(super) fn validate_path(path: &Path) -> Result<(), String> {
    WindowsLocalPath::parse(path.as_os_str()).map(|_| ())
}
pub(super) fn parents(path: &Path) -> Result<Vec<File>, String> {
    validate_path(path)?;
    let mut handles = Vec::new();
    let mut current = PathBuf::new();
    let parts: Vec<_> = path.components().collect();
    for part in &parts[..parts.len() - 1] {
        current.push(part.as_os_str());
        if matches!(part, Component::Prefix(_)) {
            continue;
        }
        // Deny ancestor deletion, retaining its identity. Native ReplaceFileW
        // needs directory write sharing; this does not permit source writes.
        let handle = OpenOptions::new()
            .read(true)
            .share_mode(READ | WRITE)
            .custom_flags(OPEN_REPARSE | BACKUP_SEMANTICS)
            .open(NativeFsPath::from_path(&current)?.as_path())
            .map_err(|e| io("open ancestor", e))?;
        let info = information(&handle)?;
        if info.attributes & REPARSE != 0 || info.attributes & DIRECTORY == 0 {
            return Err("ancestor reparse/type conflict".into());
        }
        case_insensitive(&handle)?;
        handles.push(handle);
    }
    Ok(handles)
}
pub(super) fn open_regular(path: &Path, share: u32) -> Result<File, String> {
    let native_path = NativeFsPath::from_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(share)
        .custom_flags(OPEN_REPARSE)
        .open(native_path.as_path())
        .map_err(|e| io("open archive file", e))?;
    identity(&file)?;
    Ok(file)
}
pub(super) fn read_checked(file: &mut File, target: &Path) -> Result<SourceSnapshot, String> {
    read_checked_purpose(file, target, PathPurpose::Source)
}
pub(super) fn read_checked_purpose(
    file: &mut File,
    target: &Path,
    purpose: PathPurpose,
) -> Result<SourceSnapshot, String> {
    let identify = if matches!(purpose, PathPurpose::Executable) {
        executable_identity
    } else {
        identity
    };
    let before = identify(file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| io("seek archive", e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| io("read archive", e))?;
    let after = identify(file)?;
    if before != after || u64::try_from(bytes.len()).ok() != Some(before.size) {
        let digest = hash(&bytes);
        return Err(format!("source changed while reading; observations={}", serde_json::json!({
            "observedBytesLength":bytes.len(),
            "difference":SnapshotDifference::from_parts(&before, &after, &bytes, &bytes, &digest, &digest)
        })));
    }
    Ok(SourceSnapshot {
        target: target.into(),
        digest: hash(&bytes),
        bytes,
        identity: before,
    })
}
pub(super) fn read_path(path: &Path, share: u32) -> Result<SourceSnapshot, String> {
    let _parents = parents(path)?;
    read_checked(&mut open_regular(path, share)?, path)
}

#[cfg(test)]
mod filesystem_path_tests {
    use super::*;

    #[test]
    #[ignore = "new qualified owned fixture; actual common inherited FILE-dispatch primitive, no product effects"]
    fn inherited_metadata_restore_preserves_raw_sd_after_replace() -> Result<()> {
        let parent_path = PathBuf::from(std::env::var_os("AG_NATIVE_METADATA_IDENTITY_FIXTURE_PARENT")
            .ok_or("explicit owned metadata fixture parent required")?);
        let inputs = diagnostic_inputs(&parent_path)?;
        let context = crate::windows_coordinator::windows_deployment::receive_for_diagnostic(&inputs, None)?
            .ok_or("genuine fixture context required")?;
        inputs.receive_context(Some(&context))?;
        let root = parent_path.join(format!("metadata-inherited-{}", unique_id()?));
        eprintln!("SELECTED_METADATA_INHERITED_FIXTURE {}", root.display());
        absent(&root)?;
        create_private_dir(&root)?;
        eprintln!("OWN_METADATA_INHERITED_FIXTURE {}", root.display());
        let original = root.join("replacement44");
        write_private(&original, b"44")?;
        initialize_inherited_fixture(&original)?;
        let desired = read_path(&original, READ | DELETE)?;
        let mut control = 0;
        let mut revision = 0;
        let mut desired_sd = desired.identity.security_descriptor.clone();
        assert_ne!(unsafe { GetSecurityDescriptorControl(desired_sd.as_mut_ptr().cast(), &mut control, &mut revision) }, 0);
        assert_eq!(control, 0x8404);
        let target = root.join("current45");
        let mut current = create_owned_file(&target)?;
        current.write_all(b"45").and_then(|_| current.sync_all()).map_err(|error|io("fixture45 persist",error))?;
        let basic = BasicInformation { creation:i64::try_from(desired.identity.creation).map_err(|_|"fixture creation overflow")?, access:0, write:0, change:0, attributes:desired.identity.attributes };
        assert_ne!(unsafe { SetFileInformationByHandle(current.as_raw_handle(), 0, (&basic as *const BasicInformation).cast(), std::mem::size_of::<BasicInformation>() as u32) }, 0);
        drop(current);
        let mut token = token_user()?;
        let user = sid_text(user_sid(&mut token)?)?;
        let text: Vec<_> = format!("D:P(A;;RC;;;{user})(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").encode_utf16().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) }, 0);
        let descriptor = LocalMemory(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = std::ptr::null_mut();
        assert_ne!(unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }, 0);
        let access = |path: &Path| OpenOptions::new().access_mode(0x0006_0000).share_mode(READ | DELETE).custom_flags(OPEN_REPARSE).open(NativeFsPath::from_path(path)?.as_path()).map_err(|error|io("fixture DACL handle",error));
        let current = access(&target)?;
        assert_eq!(unsafe { SetSecurityInfo(current.as_raw_handle(), 1, 4 | 0x2000_0000, std::ptr::null_mut(), std::ptr::null_mut(), acl, std::ptr::null_mut()) }, 0);
        drop(current);
        let backup = root.join("retained45");
        absent(&backup)?;
        let mut called = None;
        replace_native_file(&target, &original, &backup, &mut called)?;
        assert_eq!(called, Some(true));
        assert_ne!(read_path(&target, READ | DELETE)?.identity.security_descriptor, desired.identity.security_descriptor);
        let current = access(&target)?;
        let result = restore_received_dacl(&current, &desired.identity.security_descriptor);
        write_private(&root.join("actual-restore-result.json"), &json(&result)?)?;
        result?;
        drop(current);
        let after = read_path(&target, READ | DELETE)?;
        assert_eq!(after.bytes, b"44");
        assert_eq!(after.identity, desired.identity);
        write_private(&root.join("inherited-result.json"), &json(&serde_json::json!({
            "replaceResult":called,"capturedControl":control,"fullRawSdPreserved":true,
            "beforeSdSha256":hash(&desired.identity.security_descriptor),"afterSdSha256":hash(&after.identity.security_descriptor),
            "scope":"actual common FILE dispatch inherited8404; owned fixture, not actual BA permissions"
        }))?)?;
        Ok(())
    }

    #[test]
    fn authored_stage_descriptor_accepts_layout_and_rejects_field_changes() {
        fn convert(text: &str) -> Vec<u8> {
            let text: Vec<_> = text.encode_utf16().chain(Some(0)).collect();
            let mut pointer = std::ptr::null_mut();
            let mut length = 0;
            assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut pointer, &mut length) }, 0);
            let owned = LocalMemory(pointer);
            unsafe { std::slice::from_raw_parts(owned.0.cast::<u8>(), length as usize) }.to_vec()
        }
        let mut token = token_user().unwrap();
        let user = sid_text(user_sid(&mut token).unwrap()).unwrap();
        let authored_text = format!("O:{user}G:BUD:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        let authored = convert(&authored_text);
        let offset = |field| u32::from_le_bytes(authored[field..field+4].try_into().unwrap()) as usize;
        assert_eq!(offset(12), 0); // No authored SACL in this private-stage profile.
        let mut repacked = authored[..20].to_vec(); // SECURITY_DESCRIPTOR_RELATIVE header.
        for field in [4, 8, 16] {
            let start = offset(field);
            let length = if field == 16 {
                u16::from_le_bytes(authored[start+2..start+4].try_into().unwrap()) as usize
            } else {
                8 + 4 * usize::from(authored[start+1]) // Native SID header/subauthorities.
            };
            let relocated = u32::try_from(repacked.len()).unwrap();
            repacked[field..field+4].copy_from_slice(&relocated.to_le_bytes());
            repacked.extend_from_slice(&authored[start..start+length]);
        }
        assert_ne!(repacked, authored);
        assert!(authored_stage_descriptor_matches(&repacked, &authored).unwrap());
        for changed in [
            authored_text.replacen(&format!("O:{user}"), "O:BA", 1),
            authored_text.replacen("G:BU", &format!("G:{user}"), 1),
            authored_text.replacen(";FA;", ";FR;", 1),
            authored_text.replacen("D:P", "D:", 1),
        ] {
            assert!(!authored_stage_descriptor_matches(&convert(&changed), &authored).unwrap());
        }
    }

    #[test]
    #[ignore = "explicit owned fixture parent; enabled-group identity variation, not an elevated BA-owner claim"]
    fn metadata_stage_preserves_captured_group_before_replace() -> Result<()> {
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn CheckTokenMembership(token: *mut c_void, sid: *mut c_void, member: *mut i32) -> i32;
        }
        let mut token = token_user()?;
        let user = sid_text(user_sid(&mut token)?)?;
        let text: Vec<_> = format!("O:{user}G:BU").encode_utf16().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        let mut length = 0;
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, &mut length) } == 0 {
            return Err(io("fixture identity descriptor", std::io::Error::last_os_error()));
        }
        let descriptor = LocalMemory(descriptor);
        let mut group = std::ptr::null_mut();
        let mut defaulted = 0;
        assert_ne!(unsafe { GetSecurityDescriptorGroup(descriptor.0, &mut group, &mut defaulted) }, 0);
        let mut enabled = 0;
        assert_ne!(unsafe { CheckTokenMembership(std::ptr::null_mut(), group, &mut enabled) }, 0);
        assert_ne!(enabled, 0, "fixture requires an actual enabled Builtin Users group; no skipped PASS");
        let parent_path = PathBuf::from(std::env::var_os("AG_NATIVE_METADATA_IDENTITY_FIXTURE_PARENT")
            .ok_or("explicit owned metadata fixture parent required")?);
        let inputs = diagnostic_inputs(&parent_path)?;
        let context = crate::windows_coordinator::windows_deployment::receive_for_diagnostic(&inputs, None)?
            .ok_or("genuine saved context required for metadata fixture parent")?;
        inputs.receive_context(Some(&context))?;
        let parent = CheckedPath::open(&parent_path, PathKind::Directory, PathPurpose::Review)?;
        if parent.object != inputs.directory.anchor.object {
            return Err("metadata fixture parent native identity changed".into());
        }
        check_private_namespace(&parent, Some(&context))?;
        let root = parent.path.join(format!("metadata-identity-{}", unique_id()?));
        eprintln!("SELECTED_METADATA_IDENTITY_FIXTURE {}", root.display());
        absent(&root)?;
        create_private_dir(&root)?;
        eprintln!("OWN_METADATA_IDENTITY_FIXTURE {}", root.display());
        let target = root.join("version");
        let captured = unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length as usize) };
        let mut file = create_owned_file_with_identity(&target, Some(captured))?;
        file.write_all(b"44").and_then(|_| file.sync_all()).map_err(|error|io("fixture old metadata persist",error))?;
        drop(file);
        let before = read_path(&target, READ | DELETE)?;
        let normal = create_owned_file(&root.join("normal-private"))?;
        let mut normal_sd = security(normal.as_raw_handle(), 1 | 2 | 4)?;
        let mut normal_group = std::ptr::null_mut();
        assert_ne!(unsafe { GetSecurityDescriptorGroup(normal_sd.as_mut_ptr().cast(), &mut normal_group, &mut defaulted) }, 0);
        assert_eq!(unsafe { EqualSid(group, normal_group) }, 0, "fixture group must differ from normal private creation");
        drop(normal);
        // Exercise the actual shared replacement-file constructor with the
        // received non-default group, including both backup and stage callers.
        let backup_path = root.join("replacement-backup");
        let stage_path = root.join("replacement-stage");
        let target_path = root.join("replacement-target");
        let displaced_path = root.join("replacement-displaced");
        let backup = create_replacement_file(&backup_path, &before.bytes, &before.identity)?;
        let stage = create_replacement_file(&stage_path, b"candidate", &before.identity)?;
        create_replacement_file(&target_path, &before.bytes, &before.identity)?;
        let identity_matches = |left: &[u8], right: &[u8]| -> Result<bool> {
            let mut left = left.to_vec();
            let mut right = right.to_vec();
            for get in [GetSecurityDescriptorOwner, GetSecurityDescriptorGroup] {
                let mut l = std::ptr::null_mut();
                let mut r = std::ptr::null_mut();
                let mut defaulted = 0;
                if unsafe { get(left.as_mut_ptr().cast(), &mut l, &mut defaulted) } == 0 ||
                    unsafe { get(right.as_mut_ptr().cast(), &mut r, &mut defaulted) } == 0 ||
                    l.is_null() || r.is_null() || unsafe { EqualSid(l, r) } == 0 { return Ok(false); }
            }
            Ok(true)
        };
        assert!(identity_matches(&backup.identity.security_descriptor, &before.identity.security_descriptor)?);
        assert!(identity_matches(&stage.identity.security_descriptor, &before.identity.security_descriptor)?);
        let mut missing = before.identity.clone();
        missing.security_descriptor.clear();
        let missing_path = root.join("replacement-missing-identity");
        assert!(create_replacement_file(&missing_path, b"no write", &missing).is_err());
        assert!(matches!(fs::symlink_metadata(&missing_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound));
        let mut malformed = before.identity.clone();
        malformed.security_descriptor[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let malformed_path = root.join("replacement-malformed-identity");
        assert!(create_replacement_file(&malformed_path, b"no write", &malformed).is_err());
        assert!(matches!(fs::symlink_metadata(&malformed_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound));
        let mut called = None;
        replace_native_file(&target_path, &stage_path, &displaced_path, &mut called)?;
        assert_eq!(called, Some(true));
        let replaced = read_path(&target_path, READ | DELETE)?;
        assert!(identity_matches(&replaced.identity.security_descriptor, &before.identity.security_descriptor)?);
        let access = OpenOptions::new().access_mode(0x0006_0000).share_mode(READ | DELETE)
            .custom_flags(OPEN_REPARSE).open(NativeFsPath::from_path(&target_path)?.as_path())
            .map_err(|error| io("replacement fixture DACL handle", error))?;
        restore_received_dacl(&access, &before.identity.security_descriptor)?;
        drop(access);
        let replaced = read_path(&target_path, READ | DELETE)?;
        assert_eq!(replaced.bytes, b"candidate");
        assert_eq!(replaced.identity.security_descriptor, before.identity.security_descriptor);
        let after = replaced;
        write_private(&root.join("identity-result.json"), &json(&serde_json::json!({
            "enabledGroupVariation":true,"fullSecurityDescriptorPreserved":true,
            "replaceResult":true,"beforeDigest":before.digest,"afterDigest":after.digest,
            "beforeSdSha256":hash(&before.identity.security_descriptor),
            "afterSdSha256":hash(&after.identity.security_descriptor),
            "actualElevatedBAOwnerCase":"not executed; separate Root oracle required"
        }))?)?;
        Ok(())
    }

    #[test]
    fn native_mutex_explicit_owner_excludes_other_thread_until_release() {
        let name = format!("Global\\AGUnlocker_mutex_test_{}", unique_id().unwrap());
        let lease = Lease::acquire_name(&name).unwrap();
        mutex_current_owner(lease.mutex.0).unwrap();
        let mut sd = security(lease.mutex.0, 1 | 4).unwrap();
        let aces = super::super::context_native::entries(&mut sd).unwrap();
        let user = super::super::context_native::current_user().unwrap();
        assert_eq!(aces.len(), 3);
        assert!(aces.iter().all(|ace| !ace.deny && ace.mask & 0x001f_0001 == 0x001f_0001));
        assert!(aces.iter().any(|ace| ace.sid == user));
        assert!(aces.iter().any(|ace| ace.sid.well_known(22)));
        assert!(aces.iter().any(|ace| ace.sid.well_known(26)));
        let busy_name = name.clone();
        let try_name = name.clone();
        std::thread::spawn(move || assert!(matches!(Lease::try_acquire_name(&try_name), Ok(None))))
            .join().unwrap();
        let busy = std::thread::spawn(move || Lease::acquire_name(&busy_name).map(drop))
            .join().unwrap().unwrap_err();
        assert!(busy.contains("maintenance-pending"), "{busy}");
        drop(lease);
        std::thread::spawn(move || {
            let lease = Lease::try_acquire_name(&name).unwrap().expect("released mutex is available");
            mutex_current_owner(lease.mutex.0).unwrap();
            drop(lease);
        }).join().unwrap();
    }

    #[test]
    fn vendor_recovery_lease_wait_progresses_after_release_and_stops_on_cancel() {
        use std::sync::{Arc, mpsc};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        for cancel_while_held in [false, true] {
            let name = format!("Global\\AGUnlocker_vendor_wait_test_{}", unique_id().unwrap());
            let mut held = Some(Lease::acquire_name(&name).unwrap());
            let cancelled = Arc::new(AtomicBool::new(false));
            let worker_cancel = cancelled.clone();
            let (blocked, first_timeout) = mpsc::channel();
            let (completed, outcome) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let mut first = Some(blocked);
                let check = || if worker_cancel.load(Ordering::SeqCst) { Err("Cancelled: fixture".into()) } else { Ok(()) };
                let result = wait_for_native_lease("test mutex", &check, || {
                    let attempt = Lease::try_acquire_name(&name)?;
                    if attempt.is_none() {
                        if let Some(signal) = first.take() { let _ = signal.send(()); }
                    }
                    Ok(attempt)
                }).map(drop);
                let _ = completed.send(result);
            });
            let blocked = first_timeout.recv_timeout(Duration::from_secs(10));
            if cancel_while_held { cancelled.store(true, Ordering::SeqCst); } else { drop(held.take()); }
            let result = outcome.recv_timeout(Duration::from_secs(10));
            drop(held);
            cancelled.store(true, Ordering::SeqCst);
            worker.join().unwrap();
            blocked.expect("worker reached the actual held mutex");
            let result = result.expect("waiter returned its terminal outcome");
            if cancel_while_held {
                assert_eq!(result.unwrap_err(), "Cancelled: fixture; vendor recovery stage=test mutex");
            } else {
                result.unwrap();
            }
        }
    }

    #[test]
    fn native_mutex_abandonment_is_not_contention() {
        let name = format!("Global\\AGUnlocker_mutex_test_{}", unique_id().unwrap());
        let mut witness = Lease::acquire_name(&name).unwrap();
        assert_ne!(unsafe { ReleaseMutex(witness.mutex.0) }, 0);
        witness.held = false;
        let worker_name = name.clone();
        std::thread::spawn(move || {
            let mut owner = Lease::acquire_name(&worker_name).unwrap();
            // Let the native ownership die with this test thread. The
            // independently held witness keeps the mutex object alive.
            owner.held = false;
        }).join().unwrap();
        let error = Lease::try_acquire_name(&name).err().expect("abandonment is a failure");
        assert!(error.contains("abandoned its mutex"), "{error}");
        assert!(Lease::try_acquire_name(&name).unwrap().is_some());
    }

    #[test]
    fn native_filesystem_encoder_preserves_ordinary_disk_policy_and_utf16() {
        for path in [r"C:\", "c:/native/Ж-λ-🚀.bin", r"D:\ordinary\file"] {
            let ordinary = WindowsLocalPath::parse(OsStr::new(path)).unwrap();
            let encoded = NativeFsPath::encode(&ordinary).unwrap();
            let expected: Vec<_> = NativeFsPath::DOS_PREFIX
                .into_iter()
                .chain(path.encode_utf16().map(|unit| if unit == 47 { 92 } else { unit }))
                .chain(Some(0))
                .collect();
            assert_eq!(encoded.units, expected);
            let received = encoded.receive_name(&encoded.units[..encoded.units.len() - 1]).unwrap();
            assert_eq!(
                received.as_os_str().encode_wide().collect::<Vec<_>>(),
                expected[4..expected.len() - 1]
            );
            assert!(WindowsLocalPath::parse(encoded.as_path().as_os_str()).is_err());
        }
        let unpaired = OsString::from_wide(&[67, 58, 92, 0xd800, 46, 98, 105, 110]);
        let encoded = NativeFsPath::from_path(Path::new(&unpaired)).unwrap();
        assert_eq!(&encoded.units[4..encoded.units.len() - 1], &[67, 58, 92, 0xd800, 46, 98, 105, 110]);
        for rejected in [
            r"relative\file", r"C:file", r"C:\a\.\file", r"C:\a\..\file",
            r"C:\file:stream", r"C:\trailing.", r"C:\trailing ", r"C:\NUL.txt",
            r"\\server\share\file", r"\\?\C:\file", r"\\.\C:\file",
        ] {
            assert!(NativeFsPath::from_path(Path::new(rejected)).is_err(), "{rejected}");
        }
        let encoded = NativeFsPath::from_path(Path::new(r"C:\ordinary")).unwrap();
        for rejected in [r"\\?\UNC\server\share\file", r"\\?\Volume{invalid}\file", r"\\.\C:\file"] {
            assert!(encoded.receive_name(&rejected.encode_utf16().collect::<Vec<_>>()).is_err());
        }
    }

    #[test]
    #[ignore = "requires an explicit vacant owned Windows fixture root"]
    fn native_long_private_create_open_and_name_receivers_preserve_identity() {
        let root = PathBuf::from(std::env::var_os("AG_NATIVE_PATH_TEST_ROOT").expect("explicit owned fixture root"));
        create_private_dir(&root).expect("vacant exact fixture root");
        let directory = root.join("native-private-long-component-".repeat(5));
        assert!(directory.as_os_str().encode_wide().count() > 248);
        create_private_dir(&directory).unwrap();
        let checked = CheckedPath::open(&directory, PathKind::Directory, PathPurpose::Review).unwrap();
        private(&checked.file).unwrap();
        let expanded = long_path(&directory).unwrap();
        let short = short_fixture_path(&directory).unwrap();
        for path in [&expanded, &short] {
            WindowsLocalPath::parse(path.as_os_str()).unwrap();
            assert_eq!(CheckedPath::open(path, PathKind::Directory, PathPurpose::Review).unwrap().native_id(), checked.native_id());
        }
        let file = directory.join("unicode-Ж-λ-🚀.bin");
        write_private(&file, b"owned long native path readback").unwrap();
        let checked = CheckedPath::open(&file, PathKind::File, PathPurpose::Review).unwrap();
        private(&checked.file).unwrap();
        assert_eq!(checked.read_snapshot().unwrap(), b"owned long native path readback");
        let snapshot = checked.read_checked_snapshot().unwrap();
        assert_eq!(snapshot.bytes(), b"owned long native path readback");
        assert_eq!(snapshot.digest(), format!("{:x}", Sha256::digest(snapshot.bytes())));
        assert_ne!(snapshot.digest(), "");
        let empty = directory.join("empty.bin");
        write_private(&empty, b"").unwrap();
        let empty_pin = CheckedPath::open(&empty, PathKind::File, PathPurpose::Review).unwrap();
        let empty_snapshot = empty_pin.read_checked_snapshot().unwrap();
        assert!(empty_snapshot.bytes().is_empty());
        assert_eq!(empty_snapshot.digest(), format!("{:x}", Sha256::digest(b"")));
        assert_ne!(empty_snapshot.digest(), "");
        assert!(CheckedPath::open(&directory.join("missing.bin"), PathKind::File, PathPurpose::Review).is_err());
        assert!(create_private_dir(&directory).is_err());
        assert!(create_owned_file(&file).is_err());
    }
}

/// Read-only namespace input. An absent future directory is bound to its real
/// nearest existing ancestor; IO/type/reparse errors never become absence.
pub(super) struct NativeDirectoryInput {
    requested: PathBuf,
    pub(super) anchor: CheckedPath,
    existed: bool,
    descriptors: Vec<(ObjectId, String)>,
}
impl NativeDirectoryInput {
    pub(super) fn capture(path: &Path) -> Result<Self> {
        validate_path(path)?;
        let mut cursor = path.to_owned();
        let mut existed = true;
        let anchor = loop {
            match fs::symlink_metadata(NativeFsPath::from_path(&cursor)?.as_path()) {
                Ok(_) => {
                    break CheckedPath::open(&cursor, PathKind::Directory, PathPurpose::Review)?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    existed = false;
                    cursor = cursor
                        .parent()
                        .ok_or("namespace has no existing ancestor")?
                        .to_owned();
                }
                Err(error) => return Err(io("namespace observation", error)),
            }
        };
        let descriptors = anchor
            ._ancestors
            .iter()
            .chain(std::iter::once(&anchor.file))
            .map(|file| {
                Ok((
                    object_id(file)?,
                    hash(&security(file.as_raw_handle(), 1 | 4)?),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            requested: path.to_owned(),
            anchor,
            existed,
            descriptors,
        })
    }
    pub(super) fn is_existing(&self) -> bool {
        self.existed
    }
    pub(super) fn files(&self) -> impl Iterator<Item = &File> {
        self.anchor
            ._ancestors
            .iter()
            .chain(std::iter::once(&self.anchor.file))
    }
    pub(super) fn recheck(&self, before_effects: bool) -> Result<()> {
        self.anchor.recheck()?;
        for (file, (id, sd)) in self.files().zip(&self.descriptors) {
            if object_id(file)? != *id || hash(&security(file.as_raw_handle(), 1 | 4)?) != *sd {
                return Err("namespace input identity/security descriptor changed".into());
            }
        }
        if before_effects {
            if self.existed {
                let current =
                    CheckedPath::open(&self.requested, PathKind::Directory, PathPurpose::Review)?;
                if current.object != self.anchor.object {
                    return Err("namespace input locator changed".into());
                }
            } else {
                absent(&self.requested)
                    .map_err(|error| format!("future namespace input became occupied: {error}"))?;
            }
        }
        Ok(())
    }
}

/// Opaque actual user-metadata namespace, projected only by the native owner.
pub(crate) struct DiagnosticInputs {
    directory: NativeDirectoryInput,
}
pub(crate) fn diagnostic_inputs(parent: &Path) -> Result<DiagnosticInputs> {
    Ok(DiagnosticInputs {
        directory: NativeDirectoryInput::capture(parent)?,
    })
}
impl DiagnosticInputs {
    pub(crate) fn ancestor_inputs(&self) -> Result<AncestorInputs> {
        Ok(AncestorInputs::new(
            self.directory
                .files()
                .map(|file| {
                    file.try_clone()
                        .map_err(|error| io("retain diagnostic namespace input", error))
                })
                .collect::<Result<Vec<_>>>()?,
        ))
    }
    pub(super) fn recheck(&self, before_effects: bool) -> Result<()> {
        self.directory.recheck(before_effects)
    }
    pub(super) fn files(&self) -> impl Iterator<Item = &File> {
        self.directory.files()
    }
    pub(super) fn receive_context(&self, context: Option<&AncestorAccessContext>) -> Result<()> {
        self.recheck(true)?;
        if let Some(context) = context {
            context.revalidate()?;
        }
        for file in self.files() {
            if let Some(context) = context {
                if !context.applies(file)? {
                    return Err("diagnostic context does not cover actual namespace".into());
                }
            }
            check_context_ancestor(file, context)?;
        }
        check_private_namespace(&self.directory.anchor, context)
    }
}

pub(super) fn check_context_ancestor(
    file: &File,
    context: Option<&AncestorAccessContext>,
) -> Result<()> {
    if let Some(context) = context {
        if context.applies(file)? {
            return context.check(file, true);
        }
    }
    ancestor_integrity(file)
}
fn check_private_namespace(
    parent: &CheckedPath,
    context: Option<&AncestorAccessContext>,
) -> Result<()> {
    if let Some(context) = context {
        context.revalidate()?;
    }
    for file in &parent._ancestors {
        check_context_ancestor(file, context)?;
    }
    if let Some(context) = context {
        if context.applies(&parent.file)? {
            return state_parent_context(&parent.file, context);
        }
    }
    // Existing user state is current-owner/integrity checked, not rewritten into
    // a managed DACL. Newly created private leaves retain the stricter rule.
    state_parent(&parent.file)
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AcquiredRole { Capture, MetadataStage, MetadataPreimage, DisplacedOriginal, PublishedCanonical, RestoredCanonical, UnresolvedOld }

#[derive(Debug)]
enum CaptureDuty {
    Unclassified,
    Authored { expected: Vec<u8>, sealed: bool, writes: Vec<CaptureWriteObservation>, receivings: Vec<CaptureReceivingObservation> },
    #[cfg(test)]
    ObservedClosed { expected: Option<Vec<u8>>, reads: Vec<Option<bool>>, receivings: Vec<CaptureReceivingObservation> },
    #[cfg(test)]
    UnusedClosedFixture,
}
#[derive(Debug, serde::Serialize)]
struct CaptureWriteObservation { write: Option<bool>, flush: Option<bool>, sync: Option<bool> }
#[derive(Debug, Default, serde::Serialize)]
struct CaptureReceivingObservation { flush: Option<bool>, sync: Option<bool>, exact: Option<bool> }

pub(crate) struct AcquiredCreation {
    file: File,
    parent: std::sync::Arc<CheckedPath>,
    path: Option<PathBuf>,
    role: AcquiredRole,
    native_id: Option<ObjectId>,
    access: u32,
    durable_snapshot: Option<SourceSnapshot>,
    retain_durable: bool,
    dispose_unneeded: bool,
    empty_unpublished: bool,
    unpublished_no_duty: bool,
    disposition_received: bool,
    hold_cause: Option<String>,
    capture_duty: Option<CaptureDuty>,
}
impl std::fmt::Debug for AcquiredCreation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcquiredCreation").field("role", &self.role)
            .field("native_id", &self.native_id).field("access", &self.access).finish_non_exhaustive()
    }
}
impl AcquiredCreation {
    fn verify_retained(&mut self) -> Result<SourceSnapshot> {
        self.parent.recheck()?;
        let expected = self.native_id.as_ref().ok_or("retained witness native ID absent")?;
        if &object_id(&self.file)? != expected { return Err("retained witness native ID changed".into()); }
        if matches!(self.role, AcquiredRole::MetadataStage | AcquiredRole::MetadataPreimage | AcquiredRole::PublishedCanonical) { private(&self.file)?; }
        let path = self.path.as_ref().ok_or("retained witness locator is unresolved")?;
        let snapshot = read_checked(&mut self.file, path)?;
        match self.durable_snapshot.as_ref() {
            None => return Err("retained witness full snapshot changed; expected snapshot absent".into()),
            Some(old) if !same_snapshot(&snapshot, old) => {
                return Err(format!("retained witness full snapshot changed; difference={}",
                    serde_json::json!(SnapshotDifference::between(old, &snapshot))));
            }
            Some(_) => {}
        }
        let current = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
            .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("retained witness locator", error))?;
        if &object_id(&current)? != expected { return Err("retained witness locator changed".into()); }
        self.parent.recheck()?;
        Ok(snapshot)
    }
    /// Consume only a proven durable artifact or a positively disposable owned object.
    pub(crate) fn finish(&mut self) -> Result<serde_json::Value> {
        if self.disposition_received {
            return Ok(serde_json::json!({"role":format!("{:?}",self.role),"nativeId":self.native_id,
                "path":self.path.as_ref().map(|path|path_evidence(path)),"result":"delete-pending received; owner handle closes on removal"}));
        }
        let capture_kind = match self.capture_duty.as_ref() {
            Some(CaptureDuty::Authored { .. }) => Some("authored"),
            #[cfg(test)]
            Some(CaptureDuty::ObservedClosed { .. }) => Some("observed closed stream"),
            _ => None,
        };
        if let Some(kind) = capture_kind {
            let path = self.path.as_ref().ok_or("authored capture locator absent")?;
            let id = self.native_id.as_ref().ok_or("authored capture identity absent")?;
            #[cfg(test)]
            if matches!(self.capture_duty.as_ref(), Some(CaptureDuty::ObservedClosed { expected: None, .. })) {
                let (observed, result) = read_closed_fixture_stream(&mut self.file, self.capture_duty.as_mut().unwrap());
                result?;
                let _ = observed;
            }
            let snapshot = receive_expected_capture(&mut self.file, &self.parent, path, id,
                self.capture_duty.as_mut().unwrap())?;
            let observations = match self.capture_duty.as_ref().unwrap() {
                CaptureDuty::Authored { writes, receivings, .. } => serde_json::json!({"writes":writes,"receivings":receivings}),
                #[cfg(test)]
                CaptureDuty::ObservedClosed { reads, receivings, .. } => serde_json::json!({"reads":reads,"receivings":receivings}),
                #[cfg(test)]
                CaptureDuty::UnusedClosedFixture => unreachable!(),
                CaptureDuty::Unclassified => unreachable!(),
            };
            return Ok(serde_json::json!({"role":"Capture","nativeId":self.native_id,
                "path":path_evidence(path),"sha256":snapshot.digest,"bytes":snapshot.bytes.len(),
                "observations":observations,
                "result":format!("actual {kind} bytes durably retained; original failure unchanged; pins released")}));
        }
        if !self.retain_durable && !self.dispose_unneeded {
            let cause = self.hold_cause.clone().unwrap_or_else(|| format!("live witness role={:?}, nativeId={:?}, locator={:?} still requires receiving or rollback",
                self.role, self.native_id, self.path));
            return Err(cause);
        }
        // A failed CREATE_NEW receiving still owns the uninterrupted creator
        // handle. Before any write or publication it can settle that exact
        // empty object even when optional numeric identity receiving failed.
        let snapshot = if self.empty_unpublished { None } else if self.unpublished_no_duty {
            if !matches!(self.role, AcquiredRole::MetadataStage | AcquiredRole::MetadataPreimage) {
                return Err("partial no-effect disposition role invalid".into());
            }
            self.parent.recheck()?;
            let id = self.native_id.as_ref().ok_or("partial no-effect identity absent")?;
            if &object_id(&self.file)? != id { return Err("partial no-effect held identity changed".into()); }
            private(&self.file)?;
            let path = self.path.as_ref().ok_or("partial no-effect locator absent")?;
            let current = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
                .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("partial no-effect locator receiving", error))?;
            if &object_id(&current)? != id { return Err("partial no-effect locator changed".into()); }
            self.parent.recheck()?;
            None
        } else { Some(self.verify_retained()?) };
        if self.dispose_unneeded {
            if !self.empty_unpublished && !matches!(self.role, AcquiredRole::MetadataStage | AcquiredRole::MetadataPreimage | AcquiredRole::DisplacedOriginal) {
                return Err("witness role is not an owned disposable metadata object".into());
            }
            use windows_sys::Win32::Storage::FileSystem::{FileDispositionInfo, FILE_DISPOSITION_INFO};
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            if unsafe { SetFileInformationByHandle(self.file.as_raw_handle(), FileDispositionInfo as u32,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(), std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32) } == 0 {
                let cause = io("owned metadata disposition", std::io::Error::last_os_error());
                    return Err(cause);
            }
            self.disposition_received = true;
            self.dispose_unneeded = false;
            return Ok(serde_json::json!({"role":format!("{:?}",self.role),"nativeId":self.native_id,
                "path":self.path.as_ref().map(|path|path_evidence(path)),"sha256":snapshot.as_ref().map(|value| &value.digest),
                "result":"delete-pending received; owner handle closes on removal"}));
        }
        Ok(serde_json::json!({"role":format!("{:?}",self.role),"nativeId":self.native_id,
            "path":self.path.as_ref().map(|path|path_evidence(path)),"sha256":snapshot.as_ref().map(|value| &value.digest),
            "result":"pins released; complete artifact retained; no replay or cleanup authority"}))
    }
}
#[cfg(test)]
impl AcquiredCreation {
    pub(crate) fn fixture_identity(&self) -> Result<ObjectId> { object_id(&self.file) }
    pub(crate) fn fixture_is_partial_noeffect_stage(&self) -> bool {
        matches!(self.role, AcquiredRole::MetadataStage) && self.unpublished_no_duty && self.dispose_unneeded
    }
    pub(crate) fn fixture_is_complete_noeffect_stage(&self) -> bool {
        matches!(self.role, AcquiredRole::MetadataStage) && self.durable_snapshot.is_some() && self.dispose_unneeded
    }
    pub(super) fn fixture_role_and_path(&self) -> (AcquiredRole, Option<&Path>) { (self.role, self.path.as_deref()) }
    pub(crate) fn fixture_file_mut(&mut self) -> &mut File { &mut self.file }
    pub(super) fn fixture_mark_disposable(&mut self) -> Result<()> {
        self.file.flush().and_then(|_| self.file.sync_all()).map_err(|error| io("fixture stage flush", error))?;
        let path = self.path.as_ref().ok_or("fixture stage path absent")?;
        self.durable_snapshot = Some(read_checked(&mut self.file, path)?);
        self.dispose_unneeded = true;
        Ok(())
    }
    pub(crate) fn fixture_settle(self) -> std::result::Result<(), (Self, String)> {
        use windows_sys::Win32::Storage::FileSystem::{FileDispositionInfo, FILE_DISPOSITION_INFO};
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe { SetFileInformationByHandle(self.file.as_raw_handle(), FileDispositionInfo as u32,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(), std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32) } == 0 {
            let cause = io("fixture owned disposition", std::io::Error::last_os_error());
            return Err((self, cause));
        }
        drop(self);
        Ok(())
    }
}
#[cfg(test)]
thread_local! { static TEST_ACQUIRED_RECEIVING_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TEST_ACQUIRED_DISPOSITION_HOLD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TEST_ACQUIRED_RECEIVING_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn fail_next_acquired_receiving_with_retained_witness() {
    TEST_ACQUIRED_RECEIVING_FAILURE.with(|value| value.set(true));
    TEST_ACQUIRED_DISPOSITION_HOLD.with(|value| value.set(true));
}
#[cfg(test)]
pub(crate) fn panic_next_acquired_receiving_with_retained_witness() {
    TEST_ACQUIRED_RECEIVING_PANIC.with(|value| value.set(true));
    TEST_ACQUIRED_DISPOSITION_HOLD.with(|value| value.set(true));
}

fn acquire_private_creation(path: &Path, parent: std::sync::Arc<CheckedPath>, role: AcquiredRole)
    -> std::result::Result<AcquiredCreation, MetadataFailure> {
    #[cfg(test)]
    let access = if matches!(role, AcquiredRole::MetadataStage)
        && TEST_METADATA_TRANSITION_FAULT.with(|value| value.get() == 3) { 0xC005_0000 } else { 0xC001_0000 };
    #[cfg(not(test))]
    let access = 0xC001_0000;
    let (file, _descriptor, _) = create_owned_file_raw(path, None, access, READ).map_err(|cause| MetadataFailure {
        phase: "creation-call", cause, replace_result: None,
        evidence: serde_json::json!({"role":format!("{role:?}"),"created":false}), live: Vec::new(), pending: None, unwind: None, secondary_unwinds: Vec::new(),
    })?;
    // The successfully returned File and the actual held parent become one
    // witness before any optional identity/protection receiving is attempted.
    let mut acquired = AcquiredCreation { file, parent, path: Some(path.to_owned()), role, native_id: None, access,
        durable_snapshot: None, retain_durable: false, dispose_unneeded: false, empty_unpublished: true, unpublished_no_duty: false, disposition_received: false, hold_cause: None, capture_duty: None };
    let received = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        #[cfg(test)]
        if TEST_ACQUIRED_RECEIVING_PANIC.with(|value| value.replace(false)) {
            std::panic::panic_any("owned-creation-unwind-fixture");
        }
        #[cfg(test)]
        if TEST_ACQUIRED_RECEIVING_FAILURE.with(|value| value.replace(false)) {
            return Err("injected receiving failure before optional native ID".into());
        }
        private(&acquired.file)?;
        acquired.native_id = Some(object_id(&acquired.file)?);
        acquired.parent.recheck()?;
        Ok(())
    }));
    let (received, unwind) = match received {
        Ok(result) => (result, None),
        Err(payload) => (Err("creation receiving unwound".into()), Some(OwnedUnwind(payload))),
    };
    if let Err(cause) = received {
        use windows_sys::Win32::Storage::FileSystem::{FileDispositionInfo, FILE_DISPOSITION_INFO};
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        #[cfg(test)]
        let injected_hold = TEST_ACQUIRED_DISPOSITION_HOLD.with(|value| value.replace(false));
        #[cfg(not(test))]
        let injected_hold = false;
        let settled = !injected_hold && unsafe { SetFileInformationByHandle(acquired.file.as_raw_handle(), FileDispositionInfo as u32,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(), std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32) } != 0;
        let settlement_error = if settled { None } else if injected_hold { Some("synthetic disposition hold; native call not invoked".into()) }
            else { Some(std::io::Error::last_os_error().to_string()) };
        let evidence = serde_json::json!({"role":format!("{role:?}"),"created":true,
            "path":path_evidence(path),"nativeId":acquired.native_id,"access":access,
            "emptyObjectDispositionReceived":settled,"dispositionError":settlement_error});
        let live = if settled { drop(acquired); Vec::new() } else { acquired.dispose_unneeded = true; vec![acquired] };
        return Err(MetadataFailure { phase: "creation-receiving", cause, replace_result: None,
            evidence, live, pending: None, unwind, secondary_unwinds: Vec::new() });
    }
    acquired.empty_unpublished = false;
    Ok(acquired)
}

/// Neutral private capture stream. The caller owns writer/child retirement,
/// sync and closing `file` before independent receiving; remaining parent pins
/// stay in scope across an owned partial move. No Drop impl prevents that move.
pub(crate) struct PrivateCapturedFile {
    pub(crate) path: PathBuf,
    pub(crate) file: File,
    pub(crate) native_id: ObjectId,
    _parent: std::sync::Arc<CheckedPath>,
    duty: CaptureDuty,
}
impl PrivateCapturedFile {
    /// Record the complete intended prefix before attempting an authored append.
    /// Once an append or durability call is uncertain, no later append may
    /// assume the cursor or prefix still matches that intention.
    pub(crate) fn write_authored(&mut self, bytes: &[u8]) -> Result<()> {
        if matches!(&self.duty, CaptureDuty::Unclassified) {
            self.duty = CaptureDuty::Authored { expected: Vec::new(), sealed: false,
                writes: Vec::new(), receivings: Vec::new() };
        }
        let CaptureDuty::Authored { expected, sealed, writes, .. } = &mut self.duty else { return Err("capture already has a different duty".into()) };
        if *sealed { return Err("authored capture is sealed after an uncertain write".into()); }
        let prior_len = expected.len();
        expected.extend_from_slice(bytes);
        writes.push(CaptureWriteObservation { write: None, flush: None, sync: None });
        let observation = writes.last_mut().unwrap();
        let cursor = self.file.stream_position().map_err(|error| io("authored capture cursor", error));
        let length = self.file.metadata().map(|value| value.len()).map_err(|error| io("authored capture length", error));
        if !matches!((&cursor, &length), (Ok(cursor), Ok(length)) if *cursor == prior_len as u64 && *length == prior_len as u64) {
            *sealed = true;
            return Err(format!("authored capture prior position unreceived: cursor={cursor:?}, length={length:?}, expected={prior_len}"));
        }
        if let Err(error) = self.file.write_all(bytes) {
            observation.write = Some(false); *sealed = true;
            return Err(io("authored capture write", error));
        }
        observation.write = Some(true);
        #[cfg(test)]
        if TEST_AUTHORED_CAPTURE_AFTER_WRITE_FAILURE.with(|value| value.replace(false)) {
            *sealed = true;
            return Err("injected authored capture failure after actual write before flush".into());
        }
        if let Err(error) = self.file.flush() {
            observation.flush = Some(false); *sealed = true;
            return Err(io("authored capture flush", error));
        }
        observation.flush = Some(true);
        if let Err(error) = self.file.sync_all() {
            observation.sync = Some(false); *sealed = true;
            return Err(io("authored capture sync", error));
        }
        observation.sync = Some(true);
        Ok(())
    }
    pub(crate) fn receive_authored(&mut self) -> Result<SourceSnapshot> {
        if !matches!(&self.duty, CaptureDuty::Authored { .. }) { return Err("capture has no authored-byte expectation".into()); }
        receive_expected_capture(&mut self.file, &self._parent, &self.path, &self.native_id, &mut self.duty)
    }
    #[cfg(test)]
    pub(crate) fn begin_closed_fixture_stream(&mut self) -> Result<()> {
        if !matches!(&self.duty, CaptureDuty::Unclassified) { return Err("capture duty already selected".into()); }
        self.duty = CaptureDuty::ObservedClosed { expected: None, reads: Vec::new(), receivings: Vec::new() };
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn read_closed_fixture_stream(&mut self) -> (Vec<u8>, Result<()>) {
        read_closed_fixture_stream(&mut self.file, &mut self.duty)
    }
    #[cfg(test)]
    pub(crate) fn receive_observed_fixture_stream(&mut self) -> Result<SourceSnapshot> {
        if !matches!(&self.duty, CaptureDuty::ObservedClosed { .. }) { return Err("closed fixture stream was not received".into()); }
        receive_expected_capture(&mut self.file, &self._parent, &self.path, &self.native_id, &mut self.duty)
    }
    #[cfg(test)]
    pub(crate) fn mark_unused_fixture_before_spawn(&mut self) -> Result<()> {
        if !matches!(&self.duty, CaptureDuty::Unclassified) { return Err("capture duty already selected".into()); }
        self._parent.recheck()?;
        if object_id(&self.file)? != self.native_id { return Err("unused fixture capture identity changed".into()); }
        private(&self.file)?;
        if self.file.metadata().map_err(|error| io("unused fixture capture metadata", error))?.len() != 0 {
            return Err("unused fixture capture is not empty".into());
        }
        self._parent.recheck()?;
        self.duty = CaptureDuty::UnusedClosedFixture;
        Ok(())
    }
    pub(crate) fn into_acquired(self) -> AcquiredCreation {
        #[cfg(test)]
        let unused_fixture = matches!(&self.duty, CaptureDuty::UnusedClosedFixture);
        #[cfg(not(test))]
        let unused_fixture = false;
        AcquiredCreation { file: self.file, parent: self._parent, path: Some(self.path),
            role: AcquiredRole::Capture, native_id: Some(self.native_id), access: 0xC001_0000,
            durable_snapshot: None, retain_durable: false, dispose_unneeded: unused_fixture, empty_unpublished: unused_fixture, unpublished_no_duty: false, disposition_received: false, hold_cause: None, capture_duty: Some(self.duty) }
    }
}

#[cfg(test)]
thread_local! { static TEST_AUTHORED_CAPTURE_AFTER_WRITE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static TEST_CLOSED_STREAM_FIRST_READ_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn fail_next_authored_capture_after_write() {
    TEST_AUTHORED_CAPTURE_AFTER_WRITE_FAILURE.with(|value| value.set(true));
}
#[cfg(test)]
pub(crate) fn fail_next_closed_stream_first_read() {
    TEST_CLOSED_STREAM_FIRST_READ_FAILURE.with(|value| value.set(true));
}
#[cfg(test)]
fn read_closed_fixture_stream(file: &mut File, duty: &mut CaptureDuty) -> (Vec<u8>, Result<()>) {
    let CaptureDuty::ObservedClosed { expected, reads, .. } = duty else {
        return (Vec::new(), Err("closed fixture stream provenance absent".into()));
    };
    reads.push(None);
    let mut bytes = Vec::new();
    let result = (|| -> Result<()> {
        file.seek(SeekFrom::Start(0)).map_err(|error| io("closed stream seek", error))?;
        if TEST_CLOSED_STREAM_FIRST_READ_FAILURE.with(|value| value.replace(false)) {
            file.take(3).read_to_end(&mut bytes).map_err(|error| io("closed stream partial read", error))?;
            return Err("injected closed stream failure before EOF after actual prefix".into());
        }
        file.read_to_end(&mut bytes).map_err(|error| io("closed stream full read", error))?;
        Ok(())
    })();
    *reads.last_mut().unwrap() = Some(result.is_ok());
    if result.is_ok() { *expected = Some(bytes.clone()); }
    (bytes, result)
}

fn receive_expected_capture(file: &mut File, parent: &CheckedPath, path: &Path, expected_id: &ObjectId,
    duty: &mut CaptureDuty) -> Result<SourceSnapshot> {
    let (expected, receivings) = match duty {
        CaptureDuty::Authored { expected, receivings, .. } => (expected, receivings),
        #[cfg(test)]
        CaptureDuty::ObservedClosed { expected: Some(expected), receivings, .. } => (expected, receivings),
        #[cfg(test)]
        CaptureDuty::ObservedClosed { expected: None, .. } => return Err("closed stream complete observation absent".into()),
        #[cfg(test)]
        CaptureDuty::UnusedClosedFixture => return Err("unused fixture stream has no evidence duty".into()),
        CaptureDuty::Unclassified => return Err("capture has no received byte expectation".into()),
    };
    receivings.push(CaptureReceivingObservation::default());
    let observation = receivings.last_mut().unwrap();
    parent.recheck()?;
    if &object_id(file)? != expected_id { return Err("authored capture held identity changed".into()); }
    private(file)?;
    if let Err(error) = file.flush() { observation.flush = Some(false); return Err(io("authored capture receiving flush", error)); }
    observation.flush = Some(true);
    if let Err(error) = file.sync_all() { observation.sync = Some(false); return Err(io("authored capture receiving sync", error)); }
    observation.sync = Some(true);
    let held = read_checked(file, path)?;
    if held.bytes != *expected { observation.exact = Some(false); return Err("authored capture actual bytes differ from expected prefix".into()); }
    let mut independent = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("authored capture independent receiving", error))?;
    private(&independent)?;
    if &object_id(&independent)? != expected_id { return Err("authored capture independent identity differs".into()); }
    let actual = read_checked(&mut independent, path)?;
    if !same_snapshot(&actual, &held) { return Err("authored capture independent snapshot differs".into()); }
    let current = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("authored capture locator recheck", error))?;
    if &object_id(&current)? != expected_id { return Err("authored capture locator changed".into()); }
    parent.recheck()?;
    observation.exact = Some(true);
    Ok(actual)
}

pub(crate) fn create_private_captured_file(
    path: &Path,
    _context: Option<&AncestorAccessContext>,
) -> std::result::Result<PrivateCapturedFile, MetadataFailure> {
    let parent_path = path.parent().ok_or_else(|| MetadataFailure::unacquired("capture-parent", "capture parent absent".into()))?;
    let parent = CheckedPath::open(
        parent_path,
        PathKind::Directory,
        PathPurpose::Review,
    ).map_err(|cause| MetadataFailure { phase: "capture-parent", cause, replace_result: None,
        evidence: serde_json::json!({"created":false}), live: Vec::new(), pending: None, unwind: None, secondary_unwinds: Vec::new() })?;
    let acquired = acquire_private_creation(path, std::sync::Arc::new(parent), AcquiredRole::Capture)?;
    let native_id = match acquired.native_id.clone() {
        Some(value) => value,
        None => return Err(MetadataFailure { phase: "capture-identity", cause: "capture identity absent after receiving".into(),
            replace_result: None, evidence: serde_json::json!({"created":true}), live: vec![acquired], pending: None, unwind: None, secondary_unwinds: Vec::new() }),
    };
    let AcquiredCreation { file, parent, .. } = acquired;
    Ok(PrivateCapturedFile {
        path: path.to_owned(),
        file,
        native_id,
        _parent: parent,
        duty: CaptureDuty::Unclassified,
    })
}

pub(crate) fn read_private_captured_file(
    path: &Path,
    expected: &ObjectId,
    _context: Option<&AncestorAccessContext>,
) -> Result<Vec<u8>> {
    let parent = CheckedPath::open(
        path.parent().ok_or("capture parent absent")?,
        PathKind::Directory,
        PathPurpose::Review,
    )?;
    parent.recheck()?;
    let mut file = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("capture readback", error))?;
    identity(&file)?;
    private(&file)?;
    if &object_id(&file)? != expected {
        return Err("private capture native identity changed".into());
    }
    let bytes = read_checked(&mut file, path)?.bytes;
    let current = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("capture readback recheck", error))?;
    if &object_id(&current)? != expected { return Err("private capture locator changed".into()); }
    parent.recheck()?;
    Ok(bytes)
}

#[derive(Debug, Serialize)]
pub(crate) struct MetadataFailure {
    pub(crate) phase: &'static str,
    pub(crate) cause: String,
    /// This describes REPLACE only. CREATE_NEW/write/flush effects are retained
    /// separately in evidence even when replacement was not called.
    pub(crate) replace_result: Option<bool>,
    pub(crate) evidence: serde_json::Value,
    #[serde(skip)]
    pub(crate) live: Vec<AcquiredCreation>,
    #[serde(skip)]
    pub(crate) pending: Option<PendingUserMetadataPublication>,
    #[serde(skip)]
    pub(crate) unwind: Option<OwnedUnwind>,
    #[serde(skip)]
    pub(crate) secondary_unwinds: Vec<OwnedUnwind>,
}
pub(crate) struct OwnedUnwind(pub(crate) Box<dyn std::any::Any + Send>);
impl std::fmt::Debug for OwnedUnwind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("OwnedUnwind") }
}
impl std::fmt::Display for MetadataFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "private metadata {}: {} (replacement {:?}; retained evidence)",
            self.phase, self.cause, self.replace_result
        )
    }
}
impl std::error::Error for MetadataFailure {}
impl MetadataFailure {
    pub(crate) fn set_unwind(&mut self, payload: Option<Box<dyn std::any::Any + Send>>) {
        self.unwind = payload.map(OwnedUnwind);
    }
    pub(crate) fn unacquired(phase: &'static str, cause: String) -> Self {
        Self { phase, cause, replace_result: None, evidence: serde_json::json!({"created":false}), live: Vec::new(), pending: None, unwind: None, secondary_unwinds: Vec::new() }
    }
    pub(crate) fn with_capture(phase: &'static str, cause: String, capture: PrivateCapturedFile) -> Self {
        let evidence = serde_json::json!({"created":true,"path":path_evidence(&capture.path),"nativeId":capture.native_id});
        Self { phase, cause, replace_result: None, evidence, live: vec![capture.into_acquired()], pending: None, unwind: None, secondary_unwinds: Vec::new() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserMetadataField { GateReport, RelayVersionProjection }

/// One still-owned publication whose canonical outcome requires receiving.
/// Its file handles and snapshots remain associated with the original field.
pub(crate) struct PendingUserMetadataPublication {
    field: UserMetadataField,
    parent: std::sync::Arc<CheckedPath>,
    canonical: PathBuf,
    old: Option<(File, ObjectId, PathBuf, SourceSnapshot)>,
    stage: Option<AcquiredCreation>,
    preimage: Option<AcquiredCreation>,
    produced: SourceSnapshot,
    stage_transition: MetadataRenameObservation,
    old_transition: MetadataRenameObservation,
    rollback_transition: MetadataRenameObservation,
    restore_owed: bool,
    old_call: Option<bool>,
    stage_call: Option<bool>,
    rollback_call: Option<bool>,
    old_disposition_received: bool,
    preimage_disposition_received: bool,
}
impl std::fmt::Debug for PendingUserMetadataPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingUserMetadataPublication").field("field", &self.field)
            .field("old_call", &self.old_call).field("stage_call", &self.stage_call)
            .field("rollback_call", &self.rollback_call).finish_non_exhaustive()
    }
}
pub(crate) enum PendingMetadataReceiving {
    CanonicalUnchangedReceived,
    PublishedReceived,
    Held { cause: String, actual: PendingMetadataActual },
}
#[derive(Debug, Default)]
pub(crate) struct PendingMetadataActual {
    pub(crate) canonical_id: Option<ObjectId>,
    pub(crate) observed_absent: bool,
}
impl PendingUserMetadataPublication {
    pub(crate) fn field(&self) -> UserMetadataField { self.field }
    pub(crate) fn restoration_owed(&self) -> bool { self.restore_owed }
    #[cfg(test)]
    pub(crate) fn test_held_stage_id(&self) -> Result<ObjectId> {
        let held = self.stage.as_ref().ok_or("pending stage witness absent")?;
        object_id(&held.file)
    }
    #[cfg(test)]
    pub(crate) fn test_invalidate_produced_snapshot(&mut self) {
        self.produced.identity.write ^= 1;
    }
    #[cfg(test)]
    pub(crate) fn test_stage_creation_differs_from_expected(&mut self) -> Result<bool> {
        let stage = self.stage.as_mut().ok_or("pending stage witness absent")?;
        let path = stage.path.as_ref().ok_or("pending stage path absent")?;
        Ok(read_checked(&mut stage.file, path)?.identity.creation != self.produced.identity.creation)
    }
    #[cfg(test)]
    pub(crate) fn test_accepted_transition_retained(&self) -> bool {
        self.stage_transition.before.is_some()
            && self.stage_transition.held.as_ref().is_some_and(|value| same_snapshot(value, &self.produced))
            && self.stage_transition.received.as_ref().is_some_and(|value| same_snapshot(value, &self.produced))
            && self.stage_transition.accepted.as_ref().is_some_and(|value| same_snapshot(value, &self.produced))
    }
    #[cfg(test)]
    pub(super) fn test_transition_was_unreceived(&self) -> bool { self.stage_transition.accepted.is_none() }
    #[cfg(test)]
    pub(super) fn test_stage_current_difference(&mut self) -> Result<serde_json::Value> {
        let stage = self.stage.as_mut().ok_or("pending stage witness absent")?;
        let path = stage.path.as_ref().ok_or("pending stage path absent")?;
        let actual = read_checked(&mut stage.file, path)?;
        Ok(serde_json::to_value(SnapshotDifference::between(&self.produced, &actual)).map_err(|error| error.to_string())?)
    }
    #[cfg(test)]
    pub(crate) fn test_change_stage_creation(&mut self) -> Result<()> {
        let stage = self.stage.as_mut().ok_or("pending stage witness absent")?;
        let path = stage.path.as_ref().ok_or("pending stage path absent")?;
        let current = read_checked(&mut stage.file, path)?;
        fixture_change_creation(&stage.file, current.identity.creation)
    }

    /// Called only after canonical receiving and the caller's source recheck.
    /// Cleanup remains a separate handle-bound operation on returned witnesses.
    pub(crate) fn release_received(&mut self, published: bool, resources: &mut Vec<AcquiredCreation>) {
        resources.reserve(3);
        if let Some((file, id, path, snapshot)) = self.old.take() {
            if published || self.restore_owed {
                resources.push(AcquiredCreation { file, parent: self.parent.clone(), path: Some(path),
                    role: AcquiredRole::DisplacedOriginal, native_id: Some(id), access: 0x8001_0000,
                    durable_snapshot: Some(snapshot), retain_durable: self.restore_owed, dispose_unneeded: !self.restore_owed,
                    empty_unpublished: false, unpublished_no_duty: false, disposition_received: self.old_disposition_received, hold_cause: None, capture_duty: None });
            }
        }
        if !published {
            if let Some(mut stage) = self.stage.take() {
                stage.dispose_unneeded = !self.restore_owed;
                resources.push(stage);
            }
        } else {
            self.stage.take();
        }
        if let Some(mut preimage) = self.preimage.take() {
            preimage.retain_durable = self.restore_owed;
            preimage.dispose_unneeded = !self.restore_owed;
            preimage.disposition_received = self.preimage_disposition_received;
            resources.push(preimage);
        }
    }
}

pub(crate) fn receive_pending_user_metadata(pending: &mut PendingUserMetadataPublication,
    expected_field: UserMetadataField) -> PendingMetadataReceiving {
    fn recheck_canonical(parent: &CheckedPath, path: &Path, expected: &ObjectId) -> Result<()> {
        let current = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
            .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("pending canonical recheck", error))?;
        if &object_id(&current)? != expected { return Err("pending canonical locator changed".into()); }
        parent.recheck()
    }
    let mut facts = PendingMetadataActual::default();
    let result = (|| -> Result<PendingMetadataReceiving> {
        if pending.field != expected_field { return Err("metadata field does not match pending receipt".into()); }
        let _lease = Lease::acquire(&pending.parent, "private_metadata_writer")?;
        pending.parent.recheck()?;
        let current = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
            .open(NativeFsPath::from_path(&pending.canonical)?.as_path());
        match current {
            Ok(mut current) => {
                facts.canonical_id = Some(object_id(&current)?);
                let snapshot = read_checked(&mut current, &pending.canonical)?;
                if same_snapshot(&snapshot, &pending.produced) {
                    let held = pending.stage.as_mut().ok_or("pending published witness absent")?;
                    let expected_id = held.native_id.clone().ok_or("pending published native ID absent")?;
                    if object_id(&held.file)? != expected_id || object_id(&current)? != expected_id {
                        return Err("pending published object identity changed".into());
                    }
                    held.verify_retained()?;
                    private(&current)?;
                    recheck_canonical(&pending.parent, &pending.canonical, &expected_id)?;
                    return Ok(PendingMetadataReceiving::PublishedReceived);
                }
                if !pending.restore_owed || pending.rollback_call == Some(true) {
                    if let Some((held_old, id, _, expected)) = &mut pending.old {
                        if object_id(&current)? == *id && same_snapshot(&snapshot, expected) {
                            if object_id(held_old)? != *id || !same_snapshot(&read_checked(held_old, &pending.canonical)?, expected) {
                                return Err("pending original object changed".into());
                            }
                            pending.stage.as_mut().ok_or("pending stage witness absent")?.verify_retained()?;
                            recheck_canonical(&pending.parent, &pending.canonical, id)?;
                            if pending.rollback_call == Some(true) { pending.restore_owed = false; }
                            return Ok(PendingMetadataReceiving::CanonicalUnchangedReceived);
                        }
                    }
                }
                let stage_id_equal = pending.stage.as_ref().and_then(|stage| stage.native_id.as_ref())
                    .zip(facts.canonical_id.as_ref()).map(|(expected, actual)| expected == actual);
                let old_difference = pending.old.as_ref().map(|(_, _, _, expected)| SnapshotDifference::between(expected, &snapshot));
                Err(format!("canonical metadata differs from both held expected snapshots; observations={}",
                    serde_json::json!({"stageIdEqual":stage_id_equal,
                        "producedDifference":SnapshotDifference::between(&pending.produced, &snapshot),
                        "oldDifference":old_difference})))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                facts.observed_absent = true;
                if pending.old.is_some() || pending.restore_owed { return Err("pending canonical metadata is absent".into()); }
                pending.stage.as_mut().ok_or("pending stage witness absent")?.verify_retained()?;
                absent(&pending.canonical)?;
                pending.parent.recheck()?;
                Ok(PendingMetadataReceiving::CanonicalUnchangedReceived)
            }
            Err(error) => Err(io("pending canonical receiving", error)),
        }
    })();
    result.unwrap_or_else(|cause| PendingMetadataReceiving::Held { cause, actual: facts })
}

/// The metadata writer retains displaced and preimage objects until its caller settles the
/// containing operation. This never confers deletion authority over a pathname.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PublishedReceivingDuty { Required, ReceivedForSettlement }

pub(crate) struct UserMetadataPublication {
    field: UserMetadataField,
    old: Option<(File, ObjectId, PathBuf, SourceSnapshot)>,
    preimage: Option<(File, ObjectId, PathBuf, SourceSnapshot)>,
    published: (File, ObjectId, PathBuf),
    published_snapshot: SourceSnapshot,
    published_receiving_duty: PublishedReceivingDuty,
    stage_transition: MetadataRenameObservation,
    old_transition: MetadataRenameObservation,
    _parent: std::sync::Arc<CheckedPath>,
    _lease: Lease,
    evidence: serde_json::Value,
    old_disposition_received: bool,
    preimage_disposition_received: bool,
}
impl UserMetadataPublication {
    pub(crate) fn evidence(&self) -> &serde_json::Value { &self.evidence }
    #[cfg(test)]
    pub(crate) fn test_published_native_id(&self) -> ObjectId { self.published.1.clone() }
    pub(crate) fn into_failure(self, phase: &'static str, cause: String, hold_published: bool, restore_owed: bool) -> MetadataFailure {
        let Self { field, old, preimage, published, published_snapshot, published_receiving_duty, stage_transition, old_transition, _parent: parent, _lease: lease, evidence,
            old_disposition_received, preimage_disposition_received } = self;
        if hold_published || published_receiving_duty == PublishedReceivingDuty::Required {
            let (file, native_id, path) = published;
            let stage = AcquiredCreation { file, parent: parent.clone(), path: Some(path.clone()),
                role: AcquiredRole::PublishedCanonical, native_id: Some(native_id), access: 0xC001_0000,
                durable_snapshot: Some(published_snapshot.clone()), retain_durable: false,
                dispose_unneeded: false, empty_unpublished: false, unpublished_no_duty: false, disposition_received: false, hold_cause: None, capture_duty: None };
            let preimage = preimage.map(|(file, id, path, snapshot)| AcquiredCreation { file, parent: parent.clone(),
                path: Some(path), role: AcquiredRole::MetadataPreimage, native_id: Some(id), access: 0xC001_0000,
                durable_snapshot: Some(snapshot), retain_durable: false, dispose_unneeded: false,
                empty_unpublished: false, unpublished_no_duty: false, disposition_received: false, hold_cause: None, capture_duty: None });
            let old_call = old.as_ref().map(|_| true);
            let pending = PendingUserMetadataPublication { field, parent, canonical: path, old, stage: Some(stage), preimage,
                stage_transition, old_transition, rollback_transition: MetadataRenameObservation::default(),
                produced: published_snapshot, restore_owed, old_call, stage_call: Some(true), rollback_call: None,
                old_disposition_received, preimage_disposition_received };
            drop(lease);
            return MetadataFailure { phase, cause, replace_result: None, evidence, live: Vec::new(), pending: Some(pending), unwind: None, secondary_unwinds: Vec::new() };
        }
        let mut live = Vec::new();
        if let Some((file, native_id, path, snapshot)) = old {
            live.push(AcquiredCreation { file, parent: parent.clone(), path: Some(path), role: AcquiredRole::DisplacedOriginal,
                native_id: Some(native_id), access: 0x8001_0000, durable_snapshot: Some(snapshot), retain_durable: !hold_published, dispose_unneeded: false, empty_unpublished: false, unpublished_no_duty: false, disposition_received: old_disposition_received, hold_cause: None, capture_duty: None });
        }
        if let Some((file, native_id, path, snapshot)) = preimage {
            live.push(AcquiredCreation { file, parent: parent.clone(), path: Some(path), role: AcquiredRole::MetadataPreimage,
                native_id: Some(native_id), access: 0xC001_0000, durable_snapshot: Some(snapshot), retain_durable: !hold_published, dispose_unneeded: false, empty_unpublished: false, unpublished_no_duty: false, disposition_received: preimage_disposition_received, hold_cause: None, capture_duty: None });
        }
        drop(published);
        drop(lease); // Mutex ownership remains on the creator thread.
        MetadataFailure { phase, cause, replace_result: None, evidence, live, pending: None, unwind: None, secondary_unwinds: Vec::new() }
    }
    pub(crate) fn settle(&mut self) -> Result<serde_json::Value> {
        self.published_receiving_duty = PublishedReceivingDuty::Required;
        #[cfg(test)]
        if TEST_METADATA_SETTLEMENT_CHANGE_CREATION.with(|value| value.replace(false)) {
            fixture_change_creation(&self.published.0, self.published_snapshot.identity.creation)?;
        }
        if self.old_disposition_received {
            self.evidence["oldDisposition"] = serde_json::json!("delete-pending requested; owner handle closed");
            drop(self.old.take());
        }
        if self.preimage_disposition_received {
            self.evidence["preimageDisposition"] = serde_json::json!("delete-pending requested; owner handle closed");
            drop(self.preimage.take());
        }
        let verify = (|| -> Result<()> {
            let (file, id, path) = &mut self.published;
            if object_id(file)? != *id || !same_snapshot(&read_checked(file, path)?, &self.published_snapshot) {
                return Err("published metadata changed before settlement".into());
            }
            #[cfg(test)]
            let displaced = if TEST_METADATA_SETTLEMENT_DISPLACE.with(|value| value.replace(false)) {
                let temporary = OsString::from(format!(".fixture-settlement-{}", unique_id()?));
                rename_user_metadata_object(file, &self._parent, &temporary, &mut None)?;
                Some(temporary)
            } else { None };
            let opened = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
                .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("published metadata settlement receiving", error));
            #[cfg(test)]
            if displaced.is_some() {
                rename_user_metadata_object(file, &self._parent, path.file_name().ok_or("fixture canonical leaf absent")?, &mut None)?;
            }
            let mut current = opened?;
            if object_id(&current)? != *id { return Err("published metadata settlement identity changed".into()); }
            private(&current)?;
            if !same_snapshot(&read_checked(&mut current, path)?, &self.published_snapshot) {
                return Err("published metadata settlement snapshot changed".into());
            }
            self._parent.recheck()?;
            self.published_receiving_duty = PublishedReceivingDuty::ReceivedForSettlement;
            if let Some((file, id, path, snapshot)) = self.old.as_mut() {
                #[cfg(test)]
                if TEST_METADATA_SETTLEMENT_CHANGE_OLD.with(|value| value.replace(false)) {
                    fixture_change_creation(file, snapshot.identity.creation)?;
                }
                if !same_snapshot(&read_checked(file, path)?, snapshot) { return Err("displaced preimage changed; protected capture retained".into()); }
                if object_id(file)? != *id { return Err("displaced object identity changed".into()); }
            }
            Ok(())
        })();
        if let Err(cause) = verify { return Err(cause); }
        use windows_sys::Win32::Storage::FileSystem::{FileDispositionInfo, FILE_DISPOSITION_INFO};
        for old_role in [true, false] {
            let owned = if old_role { self.old.as_ref().map(|(file, id, path, _)| (file, id, path)) }
                else { self.preimage.as_ref().map(|(file, id, path, _)| (file, id, path)) };
            if let Some((file, id, _)) = owned {
                let actual = match object_id(file) { Ok(value) => value, Err(cause) => return Err(cause) };
                if actual != *id { return Err("owned metadata object changed".into()); }
                let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
                if unsafe { SetFileInformationByHandle(file.as_raw_handle(), FileDispositionInfo as u32,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(), std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32) } == 0 {
                    return Err(io("owned metadata disposition", std::io::Error::last_os_error()));
                }
                if old_role { self.old_disposition_received = true; self.evidence["oldDisposition"] = serde_json::json!("delete-pending requested; owner handle closed"); drop(self.old.take()); }
                else { self.preimage_disposition_received = true; self.evidence["preimageDisposition"] = serde_json::json!("delete-pending requested; owner handle closed"); drop(self.preimage.take()); }
            }
        }
        Ok(self.evidence.clone())
    }
}

#[derive(Default)]
struct MetadataRenameObservation {
    before: Option<SourceSnapshot>,
    held: Option<SourceSnapshot>,
    received: Option<SourceSnapshot>,
    accepted: Option<SourceSnapshot>,
}

enum MetadataRenameSource<'a> {
    Original { file: &'a File, expected: &'a SourceSnapshot },
    FreshStage(&'a mut AcquiredCreation),
}

fn stage_rename_preserves_authored_snapshot(actual: &SourceSnapshot, expected: &SourceSnapshot) -> bool {
    let mut comparable = actual.clone();
    comparable.identity.creation = expected.identity.creation;
    same_snapshot(&comparable, expected)
}

fn rename_metadata_transition(source: MetadataRenameSource<'_>, parent: &CheckedPath, leaf: &OsStr,
    called: &mut Option<bool>, observation: &mut MetadataRenameObservation) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{FileRenameInfo, FILE_RENAME_INFO};
    let (file, expected, stage_id, fresh_stage) = match &source {
        MetadataRenameSource::Original { file, expected } => (*file, (*expected).clone(), None, false),
        MetadataRenameSource::FreshStage(stage) => {
            if !matches!(stage.role, AcquiredRole::MetadataStage) { return Err("metadata rename source is not a fresh stage".into()); }
            stage.parent.recheck()?;
            if object_id(&stage.parent.file)? != object_id(&parent.file)? { return Err("metadata stage parent differs".into()); }
            private(&stage.file)?;
            (&stage.file, stage.durable_snapshot.clone().ok_or("metadata stage authored snapshot absent")?,
                Some(stage.native_id.clone().ok_or("metadata stage native ID absent")?), true)
        }
    };
    parent.recheck()?;
    let mut name = final_path(&parent.file)?;
    if !ordinal(&name, &parent.locator)? { return Err("metadata parent locator changed".into()); }
    let leaf = leaf.encode_wide().collect::<Vec<_>>();
    if leaf.is_empty() || leaf.iter().any(|unit| *unit == 0 || *unit == 47 || *unit == 92) {
        return Err("invalid gate publication relative leaf".into());
    }
    let destination = parent.path.join(OsString::from_wide(&leaf));
    let mut held = file.try_clone().map_err(|error| io("metadata rename source duplicate", error))?;
    let expected_id = object_id(&held)?;
    if stage_id.as_ref().is_some_and(|id| id != &expected_id) { return Err("metadata stage native ID changed".into()); }
    if !same_snapshot(&read_checked(&mut held, &destination)?, &expected) { return Err("metadata rename source snapshot changed before call".into()); }
    observation.before = Some(expected.clone());
    if name.last() != Some(&92) { name.push(92); }
    name.extend(leaf);
    let byte_count = name.len().checked_mul(2).ok_or("gate rename name overflow")?;
    let expected_locator = name.clone();
    name.push(0);
    #[cfg(test)]
    name.extend([0xAA9D, 0x2018, 0xB303]);
    let buffer_bytes = name.len().checked_mul(2).ok_or("gate rename buffer overflow")?;
    let size = std::mem::offset_of!(FILE_RENAME_INFO, FileName).checked_add(buffer_bytes).ok_or("gate rename buffer overflow")?;
    let size_u32 = u32::try_from(size).map_err(|_| "gate rename buffer overflow")?;
    let mut buffer = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = u32::try_from(byte_count).map_err(|_| "gate rename name overflow")?;
        std::ptr::copy_nonoverlapping(name.as_ptr(), std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(), name.len());
        *called = Some(false);
        #[cfg(test)]
        TEST_METADATA_RENAME_TRACE.with(|trace| trace.borrow_mut().push(expected_id.clone()));
        if SetFileInformationByHandle(file.as_raw_handle(), FileRenameInfo as u32, info.cast(), size_u32) == 0 {
            return Err(io("gate object rename", std::io::Error::last_os_error()));
        }
        *called = Some(true);
    }
    #[cfg(test)]
    {
        let changed_incomplete = TEST_METADATA_RENAME_READBACK_FAILURE.with(|value| value.get() == 1)
            && TEST_METADATA_RENAME_CHANGE_CREATION.with(|value| value.replace(false));
        let changed_original = TEST_METADATA_ORIGINAL_CREATION_CHANGE.with(|value| {
            let remaining = value.get();
            if remaining == 0 { false } else { value.set(remaining - 1); remaining == 1 }
        });
        if changed_incomplete || changed_original { fixture_change_creation(file, expected.identity.creation)?; }
    }
    let held_id = object_id(&held);
    let held_qualified = held_id.as_ref().is_ok_and(|value| *value == expected_id);
    let held_snapshot = if held_qualified { read_checked(&mut held, &destination).map(Some) } else { Ok(None) };
    if let Ok(Some(snapshot)) = &held_snapshot { observation.held = Some(snapshot.clone()); }
    #[cfg(test)]
    if TEST_METADATA_RENAME_READBACK_FAILURE.with(|value| {
        let remaining = value.get();
        if remaining == 0 { false } else { value.set(remaining - 1); remaining == 1 }
    }) { return Err("synthetic receiving failure after successful native rename".into()); }
    #[cfg(test)]
    match TEST_METADATA_TRANSITION_FAULT.with(|value| value.replace(0)) {
        1 => {
            let temporary = OsString::from(format!(".fixture-foreign-{}", unique_id()?));
            rename_user_metadata_object(file, parent, &temporary, &mut None)?;
            write_private(&destination, b"independent foreign fixture")?;
        }
        2 => {
            let mut writer = file.try_clone().map_err(|error| io("fixture stage duplicate", error))?;
            writer.seek(SeekFrom::Start(0)).map_err(|error| io("fixture stage seek", error))?;
            writer.write_all(b"X").and_then(|_| writer.sync_all()).map_err(|error| io("fixture stage mutation", error))?;
        }
        3 => {
            let user = super::context_native::current_user()?.text()?;
            let sddl = format!("O:{user}D:P(D;;0x00000002;;;AN)(A;;FA;;;{user})(A;;FA;;;SY)(A;;FA;;;BA)");
            let text = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let mut descriptor = std::ptr::null_mut();
            if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) } == 0 {
                return Err(io("fixture descriptor conversion", std::io::Error::last_os_error()));
            }
            let descriptor = LocalMemory(descriptor);
            if unsafe { SetKernelObjectSecurity(file.as_raw_handle(), 4 | 0x8000_0000, descriptor.0) } == 0 {
                return Err(io("fixture stage descriptor mutation", std::io::Error::last_os_error()));
            }
        }
        _ => {}
    }
    let mut received = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(&destination)?.as_path()).map_err(|error| io("metadata rename destination receiving", error));
    let received_id = match &received { Ok(file) => object_id(file), Err(error) => Err(error.clone()) };
    // Do not inspect content or locator of an object whose native identity was
    // not received as the intended source; it may be a foreign occupant.
    let received_qualified = received_id.as_ref().is_ok_and(|value| *value == expected_id);
    let received_snapshot = if received_qualified { match &mut received {
        Ok(file) => read_checked(file, &destination).map(Some), Err(error) => Err(error.clone())
    } } else { Ok(None) };
    if let Ok(Some(snapshot)) = &received_snapshot { observation.received = Some(snapshot.clone()); }
    let allowed = |snapshot: &SourceSnapshot| if fresh_stage {
        stage_rename_preserves_authored_snapshot(snapshot, &expected)
    } else { same_snapshot(snapshot, &expected) };
    let received_locator = if received_qualified { match &received {
        Ok(file) => final_path(file).map(Some), Err(error) => Err(error.clone())
    } } else { Ok(None) };
    let held_locator = if held_qualified { final_path(&held).map(Some) } else { Ok(None) };
    if !received_id.as_ref().is_ok_and(|value| *value == expected_id)
        || !held_id.as_ref().is_ok_and(|value| *value == expected_id)
        || !held_snapshot.as_ref().is_ok_and(|value| value.as_ref().is_some_and(&allowed))
        || !received_snapshot.as_ref().is_ok_and(|value| value.as_ref().is_some_and(|snapshot| observation.held.as_ref().is_some_and(|held| same_snapshot(snapshot, held))))
        || !received_locator.as_ref().is_ok_and(|value| value.as_ref().is_some_and(|locator| *locator == expected_locator))
        || !held_locator.as_ref().is_ok_and(|value| value.as_ref().is_some_and(|locator| *locator == expected_locator)) {
        let id_observation = |value: &Result<ObjectId>| match value {
            Ok(actual) => serde_json::json!({"received":true,"equal":actual == &expected_id}),
            Err(error) => serde_json::json!({"received":false,"error":error}),
        };
        let snapshot_observation = |value: &Result<Option<SourceSnapshot>>| match value {
            Ok(None) => serde_json::json!({"received":false,"skipped":"identity not qualified"}),
            Ok(Some(actual)) if same_snapshot(actual, &expected) => serde_json::json!({"received":true,"equal":true}),
            Ok(Some(actual)) => serde_json::json!({"received":true,"equal":false,"difference":SnapshotDifference::between(&expected, actual)}),
            Err(error) => serde_json::json!({"received":false,"error":error}),
        };
        let locator_observation = |value: &Result<Option<Vec<u16>>>| match value {
            Ok(None) => serde_json::json!({"received":false,"skipped":"identity not qualified"}),
            Ok(Some(actual)) => {
                let expected_bytes = expected_locator.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<_>>();
                let actual_bytes = actual.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<_>>();
                serde_json::json!({"received":true,"equal":actual == &expected_locator,
                    "expectedUnits":expected_locator.len(),"actualUnits":actual.len(),
                    "expectedSha256":hash(&expected_bytes),"actualSha256":hash(&actual_bytes)})
            }
            Err(error) => serde_json::json!({"received":false,"error":error}),
        };
        return Err(format!("metadata rename exact destination receiving differs; observations={}", serde_json::json!({
            "receivedId":id_observation(&received_id),"heldId":id_observation(&held_id),
            "receivedSnapshot":snapshot_observation(&received_snapshot),"heldSnapshot":snapshot_observation(&held_snapshot),
            "receivedLocator":locator_observation(&received_locator),"heldLocator":locator_observation(&held_locator)
        })));
    }
    if fresh_stage {
        private(&held)?;
        private(received.as_ref().map_err(|error| error.clone())?)?;
    }
    if object_id(&held)? != expected_id
        || !same_snapshot(&read_checked(&mut held, &destination)?, observation.held.as_ref().ok_or("metadata held observation absent")?)
        || final_path(&held)? != expected_locator { return Err("metadata held poststate changed during receiving".into()); }
    let final_received = received.as_ref().map_err(|error| error.clone())?;
    if object_id(final_received)? != expected_id || final_path(final_received)? != expected_locator {
        return Err("metadata destination changed during receiving".into());
    }
    let current = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(&destination)?.as_path()).map_err(|error| io("metadata rename final locator receiving", error))?;
    if object_id(&current)? != expected_id || final_path(&current)? != expected_locator {
        return Err("metadata destination final locator changed".into());
    }
    parent.recheck()?;
    let accepted = observation.held.clone().ok_or("metadata held observation absent")?;
    observation.accepted = Some(accepted.clone());
    if let MetadataRenameSource::FreshStage(stage) = source { stage.durable_snapshot = Some(accepted); }
    Ok(())
}

/// Publishes a freshly authored private receipt without replacing any name.
/// Definite nonpublication settles the stage; uncertain ownership is returned.
pub(super) fn publish_immutable_slot_receipt(parent: &CheckedPath, stage: &OsStr, leaf: &OsStr,
    bytes: &[u8], before_rename: impl FnOnce() -> Result<()>) -> std::result::Result<ObjectId, MetadataFailure> {
    let held_parent = (|| -> Result<CheckedPath> {
        if stage == leaf || [stage, leaf].into_iter().any(|name| {
            let mut components = Path::new(name).components();
            !matches!(components.next(), Some(Component::Normal(value)) if value == name) || components.next().is_some()
        }) {
            return Err("invalid immutable receipt stage or destination leaf".into());
        }
        parent.recheck()?;
        private(&parent.file)?;
        let pin = CheckedPath::open(&parent.path, PathKind::Directory, PathPurpose::Review)?;
        if pin.object != parent.object { return Err("immutable receipt parent identity differs".into()); }
        Ok(pin)
    })().map_err(|cause| MetadataFailure::unacquired("immutable receipt preflight", cause))?;
    let path = parent.path.join(stage);
    let destination = parent.path.join(leaf);
    let mut acquired = acquire_private_creation(&path, std::sync::Arc::new(held_parent), AcquiredRole::MetadataStage)?;
    let id = acquired.native_id.clone();
    let mut moved = None;
    let mut observation = MetadataRenameObservation::default();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<ObjectId> {
        acquired.file.write_all(bytes).and_then(|_| acquired.file.sync_all())
            .map_err(|error| io("immutable receipt stage persistence", error))?;
        let snapshot = read_checked(&mut acquired.file, &path)?;
        if snapshot.bytes != bytes { return Err("immutable receipt stage bytes differ".into()); }
        acquired.durable_snapshot = Some(snapshot);
        let id = id.clone().ok_or("immutable receipt stage identity absent")?;
        before_rename()?;
        rename_metadata_transition(MetadataRenameSource::FreshStage(&mut acquired), parent, leaf, &mut moved, &mut observation)?;
        Ok(id)
    }));
    let (cause, unwind) = match result {
        Ok(Ok(id)) => return Ok(id),
        Ok(Err(cause)) => (cause, None),
        Err(payload) => ("immutable receipt publication unwound".into(), Some(OwnedUnwind(payload))),
    };
    let mut live = Vec::new();
    let disposition = if moved == Some(true) {
        acquired.role = AcquiredRole::PublishedCanonical;
        acquired.path = Some(destination.clone());
        acquired.hold_cause = Some("canonical receipt acquired; exact independent receiving remains required".into());
        live.push(acquired);
        serde_json::json!({"result":"canonical receipt retained for receiving"})
    } else {
        acquired.dispose_unneeded = true;
        acquired.unpublished_no_duty = acquired.durable_snapshot.is_none();
        match acquired.finish() {
            Ok(settled) => {
                drop(acquired);
                let absence = absent(&path);
                serde_json::json!({"settled":settled,"stageAbsent":absence.is_ok(),"absenceError":absence.err()})
            }
            Err(error) => {
                live.push(acquired);
                serde_json::json!({"result":"stage disposition held","error":error})
            }
        }
    };
    Err(MetadataFailure { phase: "immutable receipt publication", cause, replace_result: None,
        evidence: serde_json::json!({"kind":"immutable-slot-receipt","stageNativeId":id,
            "stagePath":path_evidence(&path),"receiptPath":path_evidence(&destination),
            "stageRenameResult":moved,"disposition":disposition}),
        live, pending: None, unwind, secondary_unwinds: Vec::new() })
}

/// Receives one already-published immutable receipt under the keeper's leases.
/// A failure leaves its original witness and duty in place.
pub(super) fn receive_published_slot_receipt(failure: &mut MetadataFailure, parent: &CheckedPath,
    leaf: &OsStr, bytes: &[u8], verify_currentness: impl FnOnce() -> Result<()>) -> Result<serde_json::Value> {
    let [witness] = failure.live.as_mut_slice() else {
        return Err("immutable receipt requires exactly one published witness".into());
    };
    let path = parent.path.join(leaf);
    if !matches!(witness.role, AcquiredRole::PublishedCanonical) || witness.dispose_unneeded
        || witness.path.as_deref() != Some(path.as_path()) || witness.parent.object != parent.object {
        return Err("immutable receipt published witness binding differs".into());
    }
    parent.recheck()?;
    witness.parent.recheck()?;
    private(&parent.file)?;
    let id = witness.native_id.clone().ok_or("immutable receipt witness native ID absent")?;
    let mut locator = parent.locator.clone();
    if locator.last() != Some(&92) { locator.push(92); }
    locator.extend(leaf.encode_wide());
    let exact = |file: &File| -> Result<()> {
        private(file)?;
        if object_id(file)? != id || final_path(file)? != locator {
            return Err("immutable receipt published native identity or locator differs".into());
        }
        Ok(())
    };
    exact(&witness.file)?;
    let held = read_checked(&mut witness.file, &path)?;
    let authored = witness.durable_snapshot.as_ref().ok_or("immutable receipt authored snapshot absent")?;
    if held.bytes != bytes || !stage_rename_preserves_authored_snapshot(&held, authored) {
        return Err("immutable receipt published bytes or protected metadata differ".into());
    }
    let mut independent = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(&path)?.as_path()).map_err(|error| io("immutable receipt independent receiving", error))?;
    exact(&independent)?;
    if !same_snapshot(&read_checked(&mut independent, &path)?, &held) {
        return Err("immutable receipt held and independent snapshots differ".into());
    }
    verify_currentness()?;
    witness.durable_snapshot = Some(held);
    witness.retain_durable = true;
    match witness.finish() {
        Ok(settled) => {
            failure.live.clear();
            Ok(settled)
        }
        Err(cause) => {
            witness.retain_durable = false;
            Err(cause)
        }
    }
}

#[cfg(test)]
pub(super) fn rename_user_metadata_object(file: &File, parent: &CheckedPath, leaf: &OsStr, called: &mut Option<bool>) -> Result<()> {
    let mut held = file.try_clone().map_err(|error| io("metadata rename fixture duplicate", error))?;
    let expected = read_checked(&mut held, &parent.path.join(leaf))?;
    rename_metadata_transition(MetadataRenameSource::Original { file, expected: &expected }, parent, leaf, called, &mut MetadataRenameObservation::default())
}

#[cfg(test)]
thread_local! { static TEST_METADATA_RENAME_READBACK_FAILURE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_TRANSITION_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(super) fn test_metadata_transition_fault(kind: u8) { TEST_METADATA_TRANSITION_FAULT.with(|value| value.set(kind)); }
#[cfg(test)]
thread_local! { static TEST_METADATA_RENAME_CHANGE_CREATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_ORIGINAL_CREATION_CHANGE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_STAGE_PRECALL_CHANGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_SETTLEMENT_CHANGE_CREATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_SETTLEMENT_DISPLACE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_SETTLEMENT_CHANGE_OLD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn test_change_creation_during_metadata_settlement() {
    TEST_METADATA_SETTLEMENT_CHANGE_CREATION.with(|value| value.set(true));
}
#[cfg(test)]
pub(crate) fn test_displace_during_metadata_settlement() {
    TEST_METADATA_SETTLEMENT_DISPLACE.with(|value| value.set(true));
}
#[cfg(test)]
pub(crate) fn test_change_old_during_metadata_settlement() {
    TEST_METADATA_SETTLEMENT_CHANGE_OLD.with(|value| value.set(true));
}
#[cfg(test)]
fn fixture_change_creation(file: &File, before: u64) -> Result<()> {
    let creation = before.checked_sub(10_000_000).ok_or("fixture creation underflow")?;
    let basic = BasicInformation { creation: i64::try_from(creation).map_err(|_| "fixture creation overflow")?,
        access: 0, write: 0, change: 0, attributes: 0 };
    if unsafe { SetFileInformationByHandle(file.as_raw_handle(), 0, (&basic as *const BasicInformation).cast(),
        std::mem::size_of::<BasicInformation>() as u32) } == 0 {
        return Err(io("fixture creation mutation", std::io::Error::last_os_error()));
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn change_metadata_original_creation_on_rename(number: usize) {
    TEST_METADATA_ORIGINAL_CREATION_CHANGE.with(|value| value.set(number));
}
#[cfg(test)]
pub(super) fn change_metadata_stage_creation_before_call() {
    TEST_METADATA_STAGE_PRECALL_CHANGE.with(|value| value.set(true));
}
#[cfg(test)]
thread_local! { static TEST_METADATA_PARTIAL_WRITE_FAILURE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn fail_next_metadata_partial_write(role: u8) {
    TEST_METADATA_PARTIAL_WRITE_FAILURE.with(|value| value.set(role));
}
#[cfg(test)]
thread_local! { static TEST_METADATA_RENAME_TRACE: std::cell::RefCell<Vec<ObjectId>> = const { std::cell::RefCell::new(Vec::new()) }; }
#[cfg(test)]
pub(crate) fn test_reset_metadata_rename_trace() { TEST_METADATA_RENAME_TRACE.with(|trace| trace.borrow_mut().clear()); }
#[cfg(test)]
pub(crate) fn test_metadata_rename_count(id: &ObjectId) -> usize {
    TEST_METADATA_RENAME_TRACE.with(|trace| trace.borrow().iter().filter(|actual| *actual == id).count())
}
#[cfg(test)]
pub(super) fn test_metadata_rename_total() -> usize {
    TEST_METADATA_RENAME_TRACE.with(|trace| trace.borrow().len())
}
#[cfg(test)]
pub(crate) fn fail_metadata_rename_readback_after(success_number: usize) {
    TEST_METADATA_RENAME_READBACK_FAILURE.with(|value| value.set(success_number));
}
#[cfg(test)]
pub(crate) fn change_creation_before_failed_metadata_rename_receiving() {
    TEST_METADATA_RENAME_CHANGE_CREATION.with(|value| value.set(true));
}

#[cfg(test)]
pub(super) fn create_gate_probe_file(path: &Path) -> Result<File> {
    create_owned_file_with_access(path, None, 0xC001_0000, READ)
}
#[cfg(test)]
pub(super) fn acquire_fixture_stage(path: &Path, parent: &CheckedPath) -> std::result::Result<AcquiredCreation, MetadataFailure> {
    let pin = CheckedPath::open(&parent.path, PathKind::Directory, PathPurpose::Review)
        .map_err(|cause| MetadataFailure::unacquired("fixture-parent", cause))?;
    if pin.object != parent.object { return Err(MetadataFailure::unacquired("fixture-parent", "parent identity differs".into())); }
    acquire_private_creation(path, std::sync::Arc::new(pin), AcquiredRole::MetadataStage)
}

#[cfg(test)]
thread_local! { static TEST_METADATA_VACANCY_OCCUPANT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_POST_PUBLISH_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_POST_PUBLISH_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_RETIRED_OCCUPANT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static TEST_METADATA_ROLLBACK_RECEIVING_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn occupy_next_metadata_vacancy() {
    TEST_METADATA_VACANCY_OCCUPANT.with(|flag| flag.set(true));
}
#[cfg(test)]
pub(crate) fn fail_next_metadata_post_publish() {
    TEST_METADATA_POST_PUBLISH_FAILURE.with(|flag| flag.set(true));
}
#[cfg(test)]
pub(super) fn panic_next_metadata_post_publish() {
    TEST_METADATA_POST_PUBLISH_PANIC.with(|flag| flag.set(true));
}
#[cfg(test)]
pub(super) fn occupy_next_metadata_retired_name() {
    TEST_METADATA_RETIRED_OCCUPANT.with(|flag| flag.set(true));
}
#[cfg(test)]
pub(super) fn fail_next_metadata_after_real_rollback() {
    TEST_METADATA_ROLLBACK_RECEIVING_FAILURE.with(|flag| flag.set(true));
}

fn metadata_publication_parent(path: &Path) -> Result<CheckedPath> {
    CheckedPath::open(path.parent().ok_or("metadata parent absent")?, PathKind::Directory, PathPurpose::Review)
}

fn open_metadata_original(path: &Path, for_publication: bool) -> Result<Option<(File, SourceSnapshot)>> {
    let native = NativeFsPath::from_path(path)?;
    match fs::symlink_metadata(native.as_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io("metadata old observation", error)),
        Ok(_) => {}
    }
    #[cfg(test)]
    let writer_access = if TEST_METADATA_ORIGINAL_CREATION_CHANGE.with(|value| value.get() != 0)
        || TEST_METADATA_SETTLEMENT_CHANGE_OLD.with(|value| value.get()) { 0x8001_0100 } else { 0x8001_0000 };
    #[cfg(not(test))]
    let writer_access = 0x8001_0000;
    let (access, share) = if for_publication { (writer_access, READ) } else { (0x8000_0000, READ | WRITE | DELETE) };
    let mut file = OpenOptions::new().access_mode(access).share_mode(share).custom_flags(OPEN_REPARSE)
        .open(native.as_path()).map_err(|error| io("gate old hold", error))?;
    let snapshot = read_checked(&mut file, path)?;
    let mut descriptor = snapshot.identity.security_descriptor.clone();
    let owner = super::context_native::descriptor_owner(&mut descriptor)?;
    if owner != super::context_native::current_user()? && !owner.well_known(22) && !owner.well_known(26) {
        return Err("metadata existing owner is foreign".into());
    }
    Ok(Some((file, snapshot)))
}

/// Advisory input. The publisher reacquires its own access and compares the
/// held destination with this exact snapshot before staging any bytes.
pub(crate) struct UserMetadataPreflight {
    path: PathBuf,
    parent: ObjectId,
    original: Option<(ObjectId, SourceSnapshot)>,
}
impl UserMetadataPreflight {
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        self.original.as_ref().map(|(_, snapshot)| snapshot.bytes.as_slice())
    }
    fn verify(&self, path: &Path, parent: &CheckedPath, original: Option<(&ObjectId, &SourceSnapshot)>) -> Result<()> {
        if self.path != path || self.parent != parent.object {
            return Err("metadata destination changed since preflight".into());
        }
        match (self.original.as_ref(), original) {
            (None, None) => Ok(()),
            (Some((expected, before)), Some((actual, now))) if expected == actual && same_snapshot(before, now) => Ok(()),
            _ => Err("metadata original changed since preflight".into()),
        }
    }
}

pub(crate) fn receive_user_metadata_preflight(path: &Path) -> Result<UserMetadataPreflight> {
    let parent = metadata_publication_parent(path)?;
    parent.recheck()?;
    // The old runtime can keep publishing while this read-only observation
    // runs. We neither take its writer mutex nor request DELETE access.
    let receive = || -> Result<_> {
        open_metadata_original(path, false)?.map(|(file, snapshot)| Ok((object_id(&file)?, snapshot))).transpose()
    };
    let observed = UserMetadataPreflight { path: path.to_owned(), parent: parent.object.clone(), original: receive()? };
    let again = receive()?;
    observed.verify(path, &parent, again.as_ref().map(|(id, snapshot)| (id, snapshot)))?;
    parent.recheck()?;
    Ok(observed)
}

pub(crate) fn preflight_user_metadata(path: &Path) -> Result<()> {
    receive_user_metadata_preflight(path).map(|_| ())
}

/// Publish one already serialized Gate report by held-object renames. Raw old
/// fields are never interpreted here and are not copied into the new report.
pub(crate) fn publish_user_metadata(field: UserMetadataField, path: &Path, bytes: &[u8]) -> std::result::Result<UserMetadataPublication, MetadataFailure> {
    publish_user_metadata_checked(field, path, bytes, None)
}

pub(crate) fn publish_user_metadata_checked(field: UserMetadataField, path: &Path, bytes: &[u8],
    preflight: Option<&UserMetadataPreflight>) -> std::result::Result<UserMetadataPublication, MetadataFailure> {
    let mut phase = "admission";
    let mut old_moved = false;
    let mut new_published = false;
    let mut old_call: Option<bool> = None;
    let mut stage_call: Option<bool> = None;
    let mut rollback_call: Option<bool> = None;
    let mut stage_transition = MetadataRenameObservation::default();
    let mut old_transition = MetadataRenameObservation::default();
    let mut rollback_transition = MetadataRenameObservation::default();
    let mut rollback: Option<std::result::Result<(), String>> = None;
    let mut old_id: Option<ObjectId> = None;
    let mut staged_id: Option<ObjectId> = None;
    let mut old_path: Option<PathBuf> = None;
    let mut stage_path: Option<PathBuf> = None;
    let mut capture_id: Option<ObjectId> = None;
    let mut capture_path: Option<PathBuf> = None;
    let mut creation_evidence = serde_json::Value::Null;
    let mut failed_creations = Vec::new();
    let mut held_parent: Option<std::sync::Arc<CheckedPath>> = None;
    let mut old: Option<(File, SourceSnapshot)> = None;
    let mut stage: Option<AcquiredCreation> = None;
    let mut preimage: Option<AcquiredCreation> = None;
    let mut captured_unwind: Option<OwnedUnwind> = None;
    let mut secondary_unwinds = Vec::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<UserMetadataPublication> {
        let parent = std::sync::Arc::new(metadata_publication_parent(path)?);
        held_parent = Some(parent.clone());
        let leaf = path.file_name().ok_or("metadata leaf absent")?;
        let lease = Lease::acquire(&parent, "private_metadata_writer")?;
        parent.recheck()?;
        let original = open_metadata_original(path, true)?;
        old_id = original.as_ref().map(|(file, _)| object_id(file)).transpose()?;
        if let Some(preflight) = preflight {
            preflight.verify(path, &parent, old_id.as_ref().zip(original.as_ref().map(|(_, snapshot)| snapshot)))?;
        }
        old = original;
        let nonce = unique_id()?;
        let old_leaf = OsString::from(format!("metadata-{nonce}.original"));
        let stage_leaf = OsString::from(format!("metadata-{nonce}.stage"));
        let original = parent.path.join(&old_leaf);
        let staged = parent.path.join(&stage_leaf);
        old_path = Some(original.clone()); stage_path = Some(staged.clone());
        absent(&original)?; absent(&staged)?;
        if let Some((_, snapshot)) = old.as_ref() {
            phase = "preimage-capture";
            let capture = parent.path.join(format!("metadata-{nonce}.preimage"));
            capture_path = Some(capture.clone());
            let acquired = match acquire_private_creation(&capture, parent.clone(), AcquiredRole::MetadataPreimage) {
                Ok(value) => value,
                Err(mut failure) => { creation_evidence = failure.evidence.clone(); failed_creations.append(&mut failure.live); captured_unwind = failure.unwind.take(); secondary_unwinds.append(&mut failure.secondary_unwinds); return Err(failure.to_string()); }
            };
            capture_id = acquired.native_id.clone();
            preimage = Some(acquired);
            let file = &mut preimage.as_mut().ok_or("metadata preimage witness absent")?.file;
            let payload = json(&serde_json::json!({"bytes":snapshot.bytes,"identity":snapshot.identity}))?;
            #[cfg(test)]
            if TEST_METADATA_PARTIAL_WRITE_FAILURE.with(|value| if value.get() == 1 { value.set(0); true } else { false }) {
                file.write_all(&payload[..payload.len().min(3)]).and_then(|_| file.sync_all()).map_err(|error| io("fixture preimage partial write", error))?;
                return Err("injected preimage persistence failure after actual partial write".into());
            }
            file.write_all(&payload).and_then(|_| file.sync_all()).map_err(|error| io("metadata preimage persist", error))?;
            let mut independent = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
                .open(NativeFsPath::from_path(&capture)?.as_path()).map_err(|error| io("metadata preimage readback", error))?;
            private(&independent)?;
            let captured = read_checked(&mut independent, &capture)?;
            if Some(object_id(&independent)?) != capture_id || captured.bytes != payload {
                return Err("metadata protected preimage readback differs".into());
            }
            preimage.as_mut().ok_or("metadata preimage witness absent")?.durable_snapshot = Some(captured);
        }
        phase = "stage-create";
        let acquired = match acquire_private_creation(&staged, parent.clone(), AcquiredRole::MetadataStage) {
            Ok(value) => value,
            Err(mut failure) => { creation_evidence = failure.evidence.clone(); failed_creations.append(&mut failure.live); captured_unwind = failure.unwind.take(); secondary_unwinds.append(&mut failure.secondary_unwinds); return Err(failure.to_string()); }
        };
        staged_id = acquired.native_id.clone();
        stage = Some(acquired);
        phase = "stage-persist";
        {
            let file = &mut stage.as_mut().ok_or("metadata stage witness absent")?.file;
            #[cfg(test)]
            if TEST_METADATA_PARTIAL_WRITE_FAILURE.with(|value| if value.get() == 2 { value.set(0); true } else { false }) {
                file.write_all(&bytes[..bytes.len().min(3)]).and_then(|_| file.sync_all()).map_err(|error| io("fixture stage partial write", error))?;
                return Err("injected stage persistence failure after actual partial write".into());
            }
            file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|error| io("metadata stage persist", error))?;
            let snapshot = read_checked(file, &staged)?;
            if snapshot.bytes != bytes { return Err("metadata stage readback differs".into()); }
            stage.as_mut().ok_or("metadata stage witness absent")?.durable_snapshot = Some(snapshot);
        }
        parent.recheck()?;
        if let Some((file, before)) = old.as_mut() {
            if !same_snapshot(&read_checked(file, path)?, before) { return Err("metadata old preimage changed".into()); }
            phase = "old-rename";
            #[cfg(test)]
            if TEST_METADATA_RETIRED_OCCUPANT.with(|flag| flag.replace(false)) {
                write_private(&original, b"independent retired-name occupant")?;
            }
            let renamed = rename_metadata_transition(MetadataRenameSource::Original { file, expected: before }, &parent,
                &old_leaf, &mut old_call, &mut old_transition);
            old_moved = old_call == Some(true);
            renamed?;
            parent.recheck()?;
        } else { absent(path)?; }
        phase = "stage-rename";
        #[cfg(test)]
        if TEST_METADATA_VACANCY_OCCUPANT.with(|flag| flag.replace(false)) { write_private(path, b"independent synthetic occupant")?; }
        #[cfg(test)]
        let inject_rollback = TEST_METADATA_ROLLBACK_RECEIVING_FAILURE.with(|flag| flag.replace(false));
        #[cfg(not(test))]
        let inject_rollback = false;
        let stage_result = if inject_rollback { Err("synthetic stage failure before native call".into()) }
            else {
                let value = stage.as_mut().ok_or("metadata stage witness absent")?;
                #[cfg(test)]
                if TEST_METADATA_STAGE_PRECALL_CHANGE.with(|flag| flag.replace(false)) {
                    let before = value.durable_snapshot.as_ref().ok_or("fixture stage snapshot absent")?.identity.creation;
                    fixture_change_creation(&value.file, before)?;
                }
                value.verify_retained().and_then(|_| rename_metadata_transition(MetadataRenameSource::FreshStage(value),
                    &parent, leaf, &mut stage_call, &mut stage_transition))
            };
        new_published = stage_call == Some(true);
        if new_published {
            let published = stage.as_mut().ok_or("metadata stage witness absent")?;
            published.role = AcquiredRole::PublishedCanonical;
            published.path = Some(path.to_owned());
        }
        if let Err(error) = stage_result {
            if !new_published { if let Some((file, snapshot)) = old.as_mut() {
                if old_moved {
                    rollback = Some(rename_metadata_transition(MetadataRenameSource::Original { file, expected: snapshot },
                        &parent, leaf, &mut rollback_call, &mut rollback_transition).and_then(|_| {
                        #[cfg(test)]
                        if inject_rollback {
                            return Err("synthetic receiving failure after actual rollback rename".into());
                        }
                        if !same_snapshot(&read_checked(file, path)?, snapshot) { return Err("restored metadata differs from captured preimage".into()); }
                        parent.recheck()
                    }));
                }
            } }
            return Err(error);
        }
        phase = "post-publication";
        #[cfg(test)]
        if TEST_METADATA_POST_PUBLISH_PANIC.with(|flag| flag.replace(false)) { std::panic::panic_any("native-post-publish-unwind"); }
        #[cfg(test)]
        if TEST_METADATA_POST_PUBLISH_FAILURE.with(|flag| flag.replace(false)) { return Err("synthetic post-publication receiving failure".into()); }
        parent.recheck()?;
        phase = "readback";
        let mut check = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
            .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("metadata published readback", error))?;
        private(&check)?;
        let published_snapshot = read_checked(&mut check, path)?;
        if Some(object_id(&check)?) != staged_id || published_snapshot.bytes != bytes
            || !stage_transition.accepted.as_ref().is_some_and(|expected| same_snapshot(&published_snapshot, expected)) {
            return Err("metadata published native identity/bytes differ".into());
        }
        parent.recheck()?;
        let evidence = serde_json::json!({"kind":"user-metadata-publication","field":format!("{field:?}"),"oldMoved":old_moved,"newPublished":new_published,
            "oldRenameResult":old_call,"stageRenameResult":stage_call,"rollbackRenameResult":rollback_call,
            "oldNativeId":old_id,"oldPath":old_path.as_ref().map(|p|path_evidence(p)),"newNativeId":staged_id,"readback":true,
            "preimageNativeId":capture_id,"preimagePath":capture_path.as_ref().map(|p|path_evidence(p))});
        let old_identity = if old.is_some() { Some(old_id.clone().ok_or("metadata old identity absent")?) } else { None };
        let preimage_identity = if preimage.is_some() { Some(capture_id.clone().ok_or("metadata preimage identity absent")?) } else { None };
        let published_identity = staged_id.clone().ok_or("metadata published identity absent")?;
        if stage.is_none() { return Err("metadata stage witness absent".into()); }
        let preimage_snapshot = if preimage.is_some() { Some(preimage.as_ref().and_then(|value| value.durable_snapshot.clone()).ok_or("metadata preimage readback absent")?) } else { None };
        let preimage_path = if preimage.is_some() { Some(capture_path.clone().ok_or("metadata preimage locator absent")?) } else { None };
        let old_value = old.take().zip(old_identity).map(|((file, snapshot), id)| (file, id, original, snapshot));
        let preimage_value = preimage.take().zip(preimage_identity).zip(preimage_snapshot).zip(preimage_path)
            .map(|(((value, id), snapshot), locator)| (value.file, id, locator, snapshot));
        let value = stage.take().ok_or("metadata stage witness absent")?;
        Ok(UserMetadataPublication { field, old: old_value, preimage: preimage_value, published: (value.file, published_identity, path.to_owned()), published_snapshot,
            published_receiving_duty: PublishedReceivingDuty::Required,
            stage_transition: std::mem::take(&mut stage_transition), old_transition: std::mem::take(&mut old_transition),
            _parent: parent, _lease: lease, evidence, old_disposition_received: false, preimage_disposition_received: false })
    }));
    let result = match result {
        Ok(result) => result,
        Err(payload) => {
            if captured_unwind.is_none() { captured_unwind = Some(OwnedUnwind(payload)); }
            else { secondary_unwinds.push(OwnedUnwind(payload)); }
            Err("metadata publication unwound".into())
        }
    };
    old_moved |= old_call == Some(true);
    new_published |= stage_call == Some(true);
    if new_published {
        if let Some(value) = stage.as_mut() {
            value.role = AcquiredRole::PublishedCanonical;
            value.path = Some(path.to_owned());
        }
    }
    match result {
        Ok(publication) => Ok(publication),
        Err(cause) => {
            let mut receiving_errors = Vec::new();
            let stage_unmoved = if stage_call.is_none() && phase != "stage-rename" { true } else if let Some(value) = stage.as_mut() {
                match value.verify_retained() { Ok(_) => true, Err(error) => { receiving_errors.push(error); false } }
            } else { receiving_errors.push("stage witness absent after attempted rename".into()); false };
            let old_unchanged = if old_moved {
                rollback.as_ref().is_some_and(|value| value.is_ok())
            } else if let (Some((file, snapshot)), Some(expected), Some(parent)) = (old.as_mut(), old_id.as_ref(), held_parent.as_ref()) {
                match (|| -> Result<bool> {
                    let mut current = OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
                        .open(NativeFsPath::from_path(path)?.as_path()).map_err(|error| io("metadata unchanged receiving", error))?;
                    let same = &object_id(&current)? == expected && &object_id(file)? == expected
                        && same_snapshot(&read_checked(file, path)?, snapshot)
                        && same_snapshot(&read_checked(&mut current, path)?, snapshot);
                    parent.recheck()?;
                    Ok(same)
                })() { Ok(value) => value, Err(error) => { receiving_errors.push(error); false } }
            } else if old.is_none() && held_parent.is_some() {
                match absent(path).and_then(|_| held_parent.as_ref().unwrap().recheck()) {
                    Ok(()) => true, Err(error) => { receiving_errors.push(error); false }
                }
            } else { false };
            let canonical_unchanged = !new_published && stage_unmoved && old_unchanged;
            // A foreign entry can independently appear at a formerly vacant
            // canonical name. Its presence is not "unchanged", but does not
            // invent a canonical move by this operation or a duty to keep an
            // otherwise unneeded private stage.
            let own_effect_absent = !old_moved && !new_published && old_call != Some(true)
                && stage_call != Some(true) && rollback_call.is_none() && stage_unmoved
                && (if old.is_some() { old_unchanged } else { held_parent.is_some() });
            let needs_pending = !canonical_unchanged && !own_effect_absent && (old_call.is_some() || stage_call.is_some() || old_moved || new_published)
                && held_parent.is_some() && stage.as_ref().and_then(|value| value.durable_snapshot.as_ref()).is_some()
                && (old.is_none() || (old_id.is_some() && old_path.is_some()));
            let pending = if needs_pending {
                let parent = held_parent.as_ref().unwrap().clone();
                let value = stage.take().unwrap();
                let produced = value.durable_snapshot.as_ref().unwrap().clone();
                let old_value = old.take().map(|(file, snapshot)| (file, old_id.clone().unwrap(), old_path.clone().unwrap(), snapshot));
                let restore_owed = old_moved && !new_published && stage_call != Some(true)
                    && !rollback.as_ref().is_some_and(|result| result.is_ok());
                Some(PendingUserMetadataPublication { field, parent, canonical: path.to_owned(), old: old_value,
                    stage: Some(value), preimage: preimage.take(), produced, stage_transition, old_transition, rollback_transition, restore_owed,
                    old_call, stage_call, rollback_call, old_disposition_received: false, preimage_disposition_received: false })
            } else { None };
            if let Some(mut value) = stage {
                value.dispose_unneeded = canonical_unchanged || own_effect_absent;
                value.unpublished_no_duty = (canonical_unchanged || own_effect_absent) && value.durable_snapshot.is_none();
                failed_creations.push(value);
            }
            if let Some(mut value) = preimage {
                value.dispose_unneeded = canonical_unchanged || own_effect_absent;
                value.unpublished_no_duty = (canonical_unchanged || own_effect_absent) && value.durable_snapshot.is_none();
                failed_creations.push(value);
            }
            if (old_moved && rollback.as_ref().is_none_or(|result| result.is_err())) || new_published
                || (old_call == Some(false) && !canonical_unchanged && !own_effect_absent) {
                if let (Some((file, _)), Some(parent), Some(id), Some(original)) = (old, held_parent, old_id.clone(), old_path.clone()) {
                    let restored = rollback_call == Some(true);
                    failed_creations.push(AcquiredCreation { file, parent,
                        path: if old_call == Some(false) { None } else if restored { Some(path.to_owned()) } else { Some(original) },
                        role: if old_call == Some(false) { AcquiredRole::UnresolvedOld } else if restored { AcquiredRole::RestoredCanonical } else { AcquiredRole::DisplacedOriginal },
                        native_id: Some(id), access: 0x8001_0000, durable_snapshot: None, retain_durable: false,
                        dispose_unneeded: false, empty_unpublished: false, unpublished_no_duty: false, disposition_received: false, hold_cause: None, capture_duty: None });
                }
            }
            Err(MetadataFailure { phase, cause, replace_result: None,
                evidence: serde_json::json!({"kind":"user-metadata-publication-failure","field":format!("{field:?}"),"oldMoved":old_moved,"newPublished":new_published,
                    "oldRenameResult":old_call,"stageRenameResult":stage_call,"rollbackRenameResult":rollback_call,
                    "canonicalUnchangedReceived":canonical_unchanged,"ownCanonicalEffectAbsentReceived":own_effect_absent,"noEffectReceivingErrors":receiving_errors,
                    "oldNativeId":old_id,"oldPath":old_path.as_ref().map(|p|path_evidence(p)),"stageNativeId":staged_id,
                    "stagePath":stage_path.as_ref().map(|p|path_evidence(p)),"preimageNativeId":capture_id,
                    "preimagePath":capture_path.as_ref().map(|p|path_evidence(p)),"creation":creation_evidence,"rollback":rollback}), live: failed_creations, pending, unwind: captured_unwind, secondary_unwinds })
        }
    }
}

/// Receive a protected produced metadata object; absence is not authority.
#[cfg(test)]
thread_local! { static TEST_METADATA_OBSERVER_BETWEEN_READS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None); }
#[cfg(test)]
pub(super) fn test_metadata_observer_between_reads(action: impl FnOnce() + 'static) {
    TEST_METADATA_OBSERVER_BETWEEN_READS.with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
}
#[cfg(test)]
pub(super) fn fixture_set_owned_dacl(path: &Path, sddl: &str, directory: bool) -> Result<()> {
    let text = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) } == 0 {
        return Err(io("fixture descriptor", std::io::Error::last_os_error()));
    }
    let descriptor = LocalMemory(descriptor);
    let directory = OpenOptions::new().access_mode(0x0004_0000).share_mode(READ | WRITE | DELETE)
        .custom_flags(OPEN_REPARSE | if directory { BACKUP_SEMANTICS } else { 0 }).open(NativeFsPath::from_path(path)?.as_path())
        .map_err(|error| io("fixture directory DACL open", error))?;
    if unsafe { SetKernelObjectSecurity(directory.as_raw_handle(), 4 | 0x8000_0000, descriptor.0) } == 0 {
        return Err(io("fixture directory DACL set", std::io::Error::last_os_error()));
    }
    Ok(())
}
pub(crate) fn read_protected_user_metadata(path: &Path) -> Result<Option<Vec<u8>>> {
    let parent = CheckedPath::open(path.parent().ok_or("metadata parent absent")?, PathKind::Directory, PathPurpose::Review)?;
    let _lease = Lease::acquire(&parent, "private_metadata_writer")?;
    parent.recheck()?;
    let native = NativeFsPath::from_path(path)?;
    let open = |candidate: &Path| OpenOptions::new().read(true).share_mode(READ | WRITE | DELETE).custom_flags(OPEN_REPARSE)
        .open(candidate);
    let mut first = match open(native.as_path()) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            absent(path)?;
            parent.recheck()?;
            return Ok(None);
        }
        Err(error) => return Err(io("protected metadata observation", error)),
    };
    private(&first)?;
    let first_id = object_id(&first)?;
    let first_locator = final_path(&first)?;
    let expanded = long_path(path)?;
    let expanded_native = NativeFsPath::from_path(&expanded)?;
    let expanded_pin = open(expanded_native.as_path()).map_err(|error| io("protected metadata expanded receiving", error))?;
    private(&expanded_pin)?;
    if object_id(&expanded_pin)? != first_id { return Err("protected metadata expanded identity differs".into()); }
    let mut expected_locator = final_path(&parent.file)?;
    if !ordinal(&expected_locator, &parent.locator)? { return Err("protected metadata parent locator changed".into()); }
    if expected_locator.last() != Some(&92) { expected_locator.push(92); }
    expected_locator.extend(expanded.file_name().ok_or("metadata leaf absent")?.encode_wide());
    if !ordinal(&first_locator, &expected_locator)? || !ordinal(&final_path(&expanded_pin)?, &first_locator)? {
        return Err("protected metadata locator differs".into());
    }
    let first_snapshot = read_checked(&mut first, path)?;
    #[cfg(test)]
    if let Some(action) = TEST_METADATA_OBSERVER_BETWEEN_READS.with(|slot| slot.borrow_mut().take()) { action(); }
    let mut second = open(expanded_native.as_path()).map_err(|error| io("protected metadata independent receiving", error))?;
    private(&second)?;
    if object_id(&second)? != first_id || !ordinal(&final_path(&second)?, &first_locator)? {
        return Err("protected metadata independent identity/locator differs".into());
    }
    let second_snapshot = read_checked(&mut second, path)?;
    if !same_snapshot(&first_snapshot, &second_snapshot) { return Err("protected metadata independent snapshot differs".into()); }
    let current = open(expanded_native.as_path()).map_err(|error| io("protected metadata locator recheck", error))?;
    if object_id(&current)? != first_id || !ordinal(&final_path(&current)?, &first_locator)? {
        return Err("protected metadata locator changed".into());
    }
    parent.recheck()?;
    Ok(Some(first_snapshot.bytes))
}

#[cfg(test)]
pub(super) fn check_nonsecret_file(
    file: &File,
    context: Option<&AncestorAccessContext>,
) -> Result<()> {
    identity(file)?;
    match context {
        Some(context) => context.check_nonsecret_metadata_file(file),
        None => super::ancestor_context::check_empty_nonsecret_metadata_file(file),
    }
}

// Neutral file replacement primitives; archive and background keep their own admission.
pub(super) fn create_replacement_file(
    path: &Path,
    bytes: &[u8],
    metadata: &FileIdentity,
) -> Result<SourceSnapshot, String> {
    {
        let mut file = create_owned_file_with_identity(path, Some(&metadata.security_descriptor))?;
        identity(&file)?;
        file.write_all(bytes).map_err(|e| io("stage write", e))?;
        let basic = BasicInformation {
            creation: i64::try_from(metadata.creation).map_err(|_| "creation time overflow")?,
            access: 0,
            write: i64::try_from(metadata.write).map_err(|_| "write time overflow")?,
            change: 0,
            attributes: metadata.attributes,
        };
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                0,
                (&basic as *const BasicInformation).cast(),
                std::mem::size_of::<BasicInformation>() as u32,
            )
        } == 0
        {
            return Err(io("stage metadata", std::io::Error::last_os_error()));
        }
        file.sync_all().map_err(|e| io("stage flush", e))?;
    }
    let actual = read_path(path, READ | DELETE)?;
    if actual.bytes != bytes {
        return Err("staged file readback mismatch".into());
    }
    Ok(actual)
}
pub(super) fn same_snapshot(actual: &SourceSnapshot, expected: &SourceSnapshot) -> bool {
    actual.identity == expected.identity
        && actual.digest == expected.digest
        && actual.bytes == expected.bytes
}

/// Failure-only description of the existing exact snapshot comparison. Raw
/// descriptors and payload bytes remain private and are never formatted here.
#[derive(Serialize)]
struct SnapshotDifference {
    volume: (u32, u32),
    index: (u64, u64),
    size: (u64, u64),
    attributes: (u32, u32),
    creation: (u64, u64),
    write: (u64, u64),
    descriptor_length: (usize, usize),
    descriptor_sha256: (String, String),
    descriptor_equal: bool,
    bytes_length: (usize, usize),
    bytes_sha256: (String, String),
    bytes_equal: bool,
    digest_equal: bool,
}
impl SnapshotDifference {
    fn between(expected: &SourceSnapshot, actual: &SourceSnapshot) -> Self {
        Self::from_parts(&expected.identity, &actual.identity, &expected.bytes, &actual.bytes, &expected.digest, &actual.digest)
    }
    fn from_parts(e: &FileIdentity, a: &FileIdentity, expected_bytes: &[u8], actual_bytes: &[u8],
        expected_digest: &str, actual_digest: &str) -> Self {
        Self {
            volume: (e.volume, a.volume), index: (e.index, a.index), size: (e.size, a.size),
            attributes: (e.attributes, a.attributes), creation: (e.creation, a.creation), write: (e.write, a.write),
            descriptor_length: (e.security_descriptor.len(), a.security_descriptor.len()),
            descriptor_sha256: (hash(&e.security_descriptor), hash(&a.security_descriptor)),
            descriptor_equal: e.security_descriptor == a.security_descriptor,
            bytes_length: (expected_bytes.len(), actual_bytes.len()),
            bytes_sha256: (expected_digest.to_owned(), actual_digest.to_owned()),
            bytes_equal: expected_bytes == actual_bytes, digest_equal: expected_digest == actual_digest,
        }
    }
}

#[cfg(test)]
#[test]
fn snapshot_difference_reports_changed_fields_without_raw_contents() {
    let expected = SourceSnapshot {
        target: PathBuf::from("synthetic"), bytes: b"private-original".to_vec(), digest: hash(b"private-original"),
        identity: FileIdentity { volume: 1, index: 2, size: 16, attributes: 32, creation: 3, write: 4,
            security_descriptor: b"private-descriptor".to_vec() },
    };
    let mut actual = expected.clone();
    actual.identity.write = 9;
    actual.identity.security_descriptor = b"different-descriptor".to_vec();
    actual.bytes = b"different-secret".to_vec();
    actual.digest = hash(&actual.bytes);
    let value = serde_json::to_value(SnapshotDifference::between(&expected, &actual)).unwrap();
    assert_eq!(value["write"], serde_json::json!([4, 9]));
    assert_eq!(value["attributes"], serde_json::json!([32, 32]));
    assert_eq!(value["descriptor_equal"], false);
    assert_eq!(value["descriptor_sha256"][0], hash(b"private-descriptor"));
    assert_eq!(value["descriptor_sha256"][1], hash(b"different-descriptor"));
    assert_eq!(value["bytes_equal"], false);
    assert_eq!(value["digest_equal"], false);
    let encoded = value.to_string();
    assert!(!encoded.contains("private-original") && !encoded.contains("different-secret"));
    assert!(!encoded.contains("private-descriptor") && !encoded.contains("different-descriptor"));
}

#[cfg(test)]
#[test]
fn fresh_stage_transition_accepts_only_creation_delta() {
    let expected = SourceSnapshot {
        target: PathBuf::from("synthetic"), bytes: b"payload".to_vec(), digest: hash(b"payload"),
        identity: FileIdentity { volume: 1, index: 2, size: 7, attributes: 32, creation: 3, write: 4,
            security_descriptor: b"descriptor".to_vec() },
    };
    let mut actual = expected.clone();
    actual.identity.creation += 1;
    assert!(stage_rename_preserves_authored_snapshot(&actual, &expected));
    assert!(!same_snapshot(&actual, &expected));
    actual.identity.write += 1;
    assert!(!stage_rename_preserves_authored_snapshot(&actual, &expected));
    actual = expected.clone();
    actual.identity.security_descriptor.push(1);
    assert!(!stage_rename_preserves_authored_snapshot(&actual, &expected));
    actual = expected.clone();
    actual.bytes.push(1);
    assert!(!stage_rename_preserves_authored_snapshot(&actual, &expected));
    actual = expected.clone();
    actual.identity.index += 1;
    assert!(!stage_rename_preserves_authored_snapshot(&actual, &expected));
}

#[cfg(test)]
#[test]
#[ignore = "explicit owned fixture parent; actual shared metadata rename and creation-time diagnostic"]
fn metadata_rename_creation_time_diagnostic() -> Result<()> {
    let parent = PathBuf::from(std::env::var_os("AG_BACKGROUND_NATIVE_FIXTURE_PARENT")
        .ok_or("explicit qualified fixture parent required")?);
    let root = super::context_fixture_directory(&parent)?;
    eprintln!("OWN_CREATION_DIAGNOSTIC_ROOT {}", root.display());
    let directory = CheckedPath::open(&root, PathKind::Directory, PathPurpose::Review)?;
    let canonical = root.join("gate.json");
    let stage = root.join("stage.json");
    let fresh_stage = root.join("fresh-stage.json");
    let fresh_name = root.join("fresh.json");
    write_private(&canonical, b"old synthetic record")?;
    write_private(&stage, b"new synthetic record")?;
    write_private(&fresh_stage, b"fresh synthetic control")?;
    let open_mutator = |path: &Path| -> Result<File> {
        OpenOptions::new().access_mode(0x8001_0100).share_mode(READ | WRITE | DELETE)
            .custom_flags(OPEN_REPARSE).open(NativeFsPath::from_path(path)?.as_path())
            .map_err(|error| io("creation diagnostic owned handle", error))
    };
    let set_creation = |file: &File, value: u64| -> Result<()> {
        let basic = BasicInformation { creation: i64::try_from(value).map_err(|_| "fixture creation overflow")?,
            access: 0, write: 0, change: 0, attributes: 0 };
        if unsafe { SetFileInformationByHandle(file.as_raw_handle(), 0, (&basic as *const BasicInformation).cast(),
            std::mem::size_of::<BasicInformation>() as u32) } == 0 {
            return Err(io("creation diagnostic set creation", std::io::Error::last_os_error()));
        }
        Ok(())
    };
    let mut old = open_mutator(&canonical)?;
    let mut staged = open_mutator(&stage)?;
    let mut control = open_mutator(&fresh_stage)?;
    let old_initial = read_checked(&mut old, &canonical)?;
    set_creation(&old, old_initial.identity.creation.checked_sub(600_000_000).ok_or("fixture creation underflow")?)?;
    let old_before = read_checked(&mut old, &canonical)?;
    let stage_before = read_checked(&mut staged, &stage)?;
    let control_before = read_checked(&mut control, &fresh_stage)?;
    if old_before.identity.creation == stage_before.identity.creation { return Err("fixture creation times not distinct".into()); }
    eprintln!("CREATION_DIAGNOSTIC_BEFORE {}", serde_json::json!({
        "oldId":object_id(&old)?,"stageId":object_id(&staged)?,"controlId":object_id(&control)?,
        "oldCreation":old_before.identity.creation,"stageCreation":stage_before.identity.creation,
        "controlCreation":control_before.identity.creation}));
    let mut old_call = None;
    let old_result = rename_user_metadata_object(&old, &directory, OsStr::new("retired.json"), &mut old_call);
    eprintln!("CREATION_DIAGNOSTIC_OLD_RENAME {}", serde_json::json!({"called":old_call,"result":old_result}));
    if old_call != Some(true) || old_result.is_err() { return Err("old rename not completely received; fixture retained".into()); }
    let mut stage_call = None;
    let stage_result = rename_user_metadata_object(&staged, &directory, OsStr::new("gate.json"), &mut stage_call);
    eprintln!("CREATION_DIAGNOSTIC_STAGE_RENAME {}", serde_json::json!({"called":stage_call,"result":stage_result}));
    if stage_call != Some(true) { return Err("stage native rename not successful; fixture retained".into()); }
    let held = read_checked(&mut staged, &canonical)?;
    let mut reopened = open_regular(&canonical, READ | WRITE | DELETE)?;
    let received = read_checked(&mut reopened, &canonical)?;
    eprintln!("CREATION_DIAGNOSTIC_STAGE_AFTER {}", serde_json::json!({"stageId":object_id(&staged)?,
        "reopenedId":object_id(&reopened)?,"heldDifference":SnapshotDifference::between(&stage_before,&held),
        "reopenedDifference":SnapshotDifference::between(&stage_before,&received),
        "heldLocatorEqualsReopen":final_path(&staged)? == final_path(&reopened)?}));
    let mut fresh_call = None;
    let fresh_result = rename_user_metadata_object(&control, &directory, OsStr::new("fresh.json"), &mut fresh_call);
    eprintln!("CREATION_DIAGNOSTIC_FRESH_RENAME {}", serde_json::json!({"called":fresh_call,"result":fresh_result}));
    if fresh_call != Some(true) { return Err("fresh-name native rename not successful; fixture retained".into()); }
    let control_after = read_checked(&mut control, &fresh_name)?;
    let mut control_reopen = open_regular(&fresh_name, READ | WRITE | DELETE)?;
    let control_received = read_checked(&mut control_reopen, &fresh_name)?;
    eprintln!("CREATION_DIAGNOSTIC_FRESH_AFTER {}", serde_json::json!({"heldId":object_id(&control)?,
        "reopenedId":object_id(&control_reopen)?,"heldDifference":SnapshotDifference::between(&control_before,&control_after),
        "reopenedDifference":SnapshotDifference::between(&control_before,&control_received)}));
    set_creation(&control, control_after.identity.creation.checked_sub(10_000_000).ok_or("fixture control underflow")?)?;
    let negative = read_checked(&mut control, &fresh_name)?;
    let unchanged_comparator_rejects = !same_snapshot(&control_after, &negative);
    eprintln!("CREATION_DIAGNOSTIC_NEGATIVE {}", serde_json::json!({"sameObject":object_id(&control)? == object_id(&control_reopen)?,
        "strictComparatorRejects":unchanged_comparator_rejects,"difference":SnapshotDifference::between(&control_after,&negative)}));
    if !unchanged_comparator_rejects { return Err("strict comparator accepted explicit creation-time change".into()); }
    Ok(())
}
pub(super) fn replace_native_file(
    target: &Path,
    staged: &Path,
    displaced: &Path,
    called: &mut Option<bool>,
) -> Result<(), String> {
    let target = NativeFsPath::from_path(target)?;
    let staged = NativeFsPath::from_path(staged)?;
    let displaced = NativeFsPath::from_path(displaced)?;
    #[cfg(test)]
    TEST_NATIVE_CALLS.with(|v| v.set(v.get() + 1));
    // Flags zero deliberately: IGNORE_MERGE_ERRORS weakens integrity and the
    // documented WRITE_THROUGH flag is unsupported. Stage/backup were flushed.
    *called = Some(false);
    if unsafe {
        ReplaceFileW(
            target.as_ptr(),
            staged.as_ptr(),
            displaced.as_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        Err(io("ReplaceFileW", std::io::Error::last_os_error()))
    } else {
        *called = Some(true);
        Ok(())
    }
}

pub(super) fn restore_replacement_security(
    target: &Path,
    staged: &SourceSnapshot,
    staged_object: &ObjectId,
    source_object: &ObjectId,
    expected_displaced: &SourceSnapshot,
    displaced: &Path,
    security: &[u8],
    guard: &mut impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    let actual = read_path(target, READ | DELETE)?;
    if actual.digest != staged.digest
        || actual.bytes != staged.bytes
        || actual.identity.volume != staged.identity.volume
        || actual.identity.index != staged.identity.index
        || !same_snapshot(&read_path(displaced, READ | DELETE)?, expected_displaced)
    {
        return Err(
            "native postimage/displaced ownership mismatch before metadata restoration".into(),
        );
    }
    if object_id(&open_regular(target, READ | DELETE)?)? != *staged_object
        || object_id(&open_regular(displaced, READ | DELETE)?)? != *source_object
    {
        return Err(
            "full native postimage/displaced identity mismatch before metadata restoration".into(),
        );
    }
    guard()?;
    let file = OpenOptions::new()
        .access_mode(0x0006_0000)
        .share_mode(READ | DELETE)
        .custom_flags(OPEN_REPARSE)
        .open(NativeFsPath::from_path(target)?.as_path())
        .map_err(|e| io("owned postimage READ_CONTROL/WRITE_DAC", e))?;
    let actual_id = identity(&file)?;
    if object_id(&file)? != *staged_object
        || actual_id.volume != staged.identity.volume
        || actual_id.index != staged.identity.index
    {
        return Err("postimage handle identity changed before metadata restoration".into());
    }
    restore_received_dacl(&file, security)
}

pub(super) fn path_evidence(path: &Path) -> serde_json::Value {
    // Exact native units remain representable even when no Unicode string is.
    serde_json::json!({"path":path.to_str(), "nativePathUtf16":path.as_os_str().encode_wide().collect::<Vec<_>>()})
}
pub(super) fn snapshot_evidence(snapshot: &SourceSnapshot) -> serde_json::Value {
    serde_json::json!({"path":path_evidence(&snapshot.target), "digest":snapshot.digest, "metadata":snapshot.identity})
}
pub(super) fn observe(path: &Path) -> serde_json::Value {
    let native = match NativeFsPath::from_path(path) {
        Ok(value) => value,
        Err(error) => return serde_json::json!({"state":"unavailable","error":error}),
    };
    match fs::symlink_metadata(native.as_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::json!({"state":"missing"}),
        Err(error) => serde_json::json!({"state":"unavailable","error":io("background observation",error)}),
        Ok(_) => match read_path(path, READ | DELETE).and_then(|snapshot| {
            let id = object_id(&open_regular(path, READ | DELETE)?)?;
            Ok(serde_json::json!({"state":"present","nativeId":id,"snapshot":snapshot_evidence(&snapshot)}))
        }) { Ok(value) => value, Err(error) => serde_json::json!({"state":"unavailable","error":error}) }
    }
}
