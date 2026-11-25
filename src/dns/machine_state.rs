//! Windows machine custody for the NRPT journal and its writer lease.

use std::ffi::c_void;
use std::io;
use std::ptr::{null, null_mut};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, HANDLE,
    WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT, CloseHandle, LocalFree};
use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, GetAce, GetKernelObjectSecurity,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    SE_DACL_PROTECTED, WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinLocalSystemSid,
    Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW};
use windows_sys::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE,
    KEY_WOW64_64KEY, REG_OPTION_NON_VOLATILE, RegCreateKeyExW, RegFlushKey, RegGetKeySecurity,
    RegOpenKeyExW};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use winreg::{RegKey, RegValue, enums::REG_BINARY};

const KEY: &str = r"SOFTWARE\AGUnlocker-NrptV1";
const HOSTS_KEY: &str = r"SOFTWARE\AGUnlocker-NrptHostsV1";
const LEASE: &str = r"Global\AGUnlocker_NrptWriterV1";
const VALUE: &str = "Journal";
const PREFIX: &str = "Ipv4Prefix";
const HOSTS_CLEANUP: &str = "HostsCleanup";
const KEY_DESCRIPTOR: &str = "O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";
const HOSTS_DESCRIPTOR: &str = "O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)";
const LEASE_DESCRIPTOR: &str = "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)";
const OWNER_AND_DACL: u32 = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn new(sddl: &str) -> Result<Self, String> {
        let mut raw = null_mut();
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), 1, &mut raw, null_mut()) } == 0 {
            return Err(format!("NRPT security descriptor: {}", io::Error::last_os_error()));
        }
        Ok(Self(raw))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0, bInheritHandle: 0 }
    }
}
impl Drop for Descriptor { fn drop(&mut self) { unsafe { LocalFree(self.0); } } }

fn administrator(sid: *mut c_void) -> bool {
    !sid.is_null() && unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 || IsWellKnownSid(sid, WinLocalSystemSid) != 0 }
}

fn machine_access(descriptor: PSECURITY_DESCRIPTOR, user_read: bool) -> Result<(), String> {
    let mut control = 0;
    let mut revision = 0;
    let mut owner = null_mut();
    let mut defaulted = 0;
    let mut present = 0;
    let mut acl: *mut ACL = null_mut();
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0
        || !administrator(owner)
        || unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
        || unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) } == 0
        || present == 0 || acl.is_null() {
        return Err("NRPT machine custody owner or protected DACL is invalid".into());
    }
    for index in 0..u32::from(unsafe { (*acl).AceCount }) {
        let mut ace = null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
            return Err("NRPT machine custody ACE unavailable".into());
        }
        let raw = ace.cast::<u8>();
        let size = unsafe { raw.add(2).cast::<u16>().read_unaligned() };
        // An ordinary ACCESS_ALLOWED_ACE has a four-byte header, a DWORD
        // access mask, and its SID. Reject conditional or inherited ACE forms.
        if size < 12 || unsafe { *raw != 0 || *raw.add(1) != 0 } {
            return Err("NRPT machine custody unsupported ACE".into());
        }
        let sid = unsafe { raw.add(8) }.cast();
        let mask = unsafe { raw.add(4).cast::<u32>().read_unaligned() };
        if !administrator(sid) && !(user_read && mask & !KEY_READ == 0
                && unsafe { IsWellKnownSid(sid, WinBuiltinUsersSid) } != 0) {
            return Err("NRPT machine custody grants access to an unrelated principal".into());
        }
    }
    Ok(())
}

fn validate_key(key: &RegKey, user_read: bool) -> Result<(), String> {
    let mut size = 0;
    let first = unsafe { RegGetKeySecurity(key.raw_handle(), OWNER_AND_DACL, null_mut(), &mut size) };
    if first != ERROR_INSUFFICIENT_BUFFER || size == 0 { return Err(win_error("NRPT registry ACL size", first)); }
    let mut descriptor = vec![0u8; size as usize];
    let status = unsafe { RegGetKeySecurity(key.raw_handle(), OWNER_AND_DACL, descriptor.as_mut_ptr().cast(), &mut size) };
    if status != 0 { return Err(win_error("NRPT registry ACL", status)); }
    machine_access(descriptor.as_mut_ptr().cast(), user_read)
}

fn win_error(operation: &str, status: u32) -> String {
    format!("{operation}: {}", io::Error::from_raw_os_error(status as i32))
}

fn key_read(path: &str, user_read: bool) -> Result<Option<RegKey>, String> {
    let mut raw: HKEY = null_mut();
    let result = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide(path).as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut raw) };
    if result == ERROR_FILE_NOT_FOUND { return Ok(None); }
    if result != 0 { return Err(win_error("read NRPT machine state", result)); }
    let key = RegKey::predef(raw);
    validate_key(&key, user_read)?;
    Ok(Some(key))
}

fn key_write(path: &str, sddl: &str, user_read: bool) -> Result<RegKey, String> {
    let mut raw: HKEY = null_mut();
    let descriptor = Descriptor::new(sddl)?;
    let result = unsafe { RegCreateKeyExW(HKEY_LOCAL_MACHINE, wide(path).as_ptr(), 0, null(),
        REG_OPTION_NON_VOLATILE, KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY, &descriptor.attributes(), &mut raw, null_mut()) };
    if result != 0 { return Err(win_error("open protected NRPT machine state", result)); }
    let key = RegKey::predef(raw);
    validate_key(&key, user_read)?;
    Ok(key)
}

fn read_value(key: &RegKey, name: &str, user_read: bool) -> Result<Option<Vec<u8>>, String> {
    validate_key(key, user_read)?;
    match key.get_raw_value(name) {
        Ok(value) if value.vtype == REG_BINARY => Ok(Some(value.bytes.into_owned())),
        Ok(_) => Err("NRPT journal registry value has the wrong type".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read NRPT journal: {error}")),
    }
}

pub(super) fn read() -> Result<Option<Vec<u8>>, String> {
    key_read(KEY, true)?.as_ref().map(|key| read_value(key, VALUE, true)).transpose().map(Option::flatten)
}

pub(super) fn has_auxiliary_cleanup() -> Result<bool, String> {
    let Some(key) = key_read(KEY, true)? else { return Ok(false); };
    let prefix = read_value(&key, PREFIX, true)?;
    let hosts = read_value(&key, HOSTS_CLEANUP, true)?;
    let hosts = match hosts.as_deref() {
        None | Some(b"0") => false,
        Some(b"1") => true,
        _ => return Err("invalid protected hosts cleanup indicator".into()),
    };
    Ok(hosts || prefix.is_some_and(|value| value != b"null"))
}

struct MutexHandle { raw: HANDLE, held: bool }
impl Drop for MutexHandle {
    fn drop(&mut self) {
        unsafe { if self.held { ReleaseMutex(self.raw); } CloseHandle(self.raw); }
    }
}

impl MutexHandle {
    fn acquire() -> Result<Self, String> {
        let descriptor = Descriptor::new(LEASE_DESCRIPTOR)?;
        let raw = unsafe { CreateMutexW(&descriptor.attributes(), 0, wide(LEASE).as_ptr()) };
        if raw.is_null() { return Err(format!("open NRPT writer lease: {}", io::Error::last_os_error())); }
        let mut lock = MutexHandle { raw, held: false };
        let mut size = 0;
        unsafe { GetKernelObjectSecurity(raw, OWNER_AND_DACL, null_mut(), 0, &mut size); }
        if size == 0 { return Err("NRPT writer lease security descriptor unavailable".into()); }
        let mut actual = vec![0u8; size as usize];
        if unsafe { GetKernelObjectSecurity(raw, OWNER_AND_DACL, actual.as_mut_ptr().cast(), size, &mut size) } == 0 {
            return Err(format!("read NRPT writer lease security: {}", io::Error::last_os_error()));
        }
        machine_access(actual.as_mut_ptr().cast(), false)?;
        match unsafe { WaitForSingleObject(raw, 0) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => lock.held = true,
            WAIT_TIMEOUT => return Err("another product DNS writer is active".into()),
            _ => return Err(format!("acquire NRPT writer lease: {}", io::Error::last_os_error())),
        }
        Ok(lock)
    }
}

/// Win32 mutex ownership is thread-affine. This scoped worker retains no state
/// other than the held mutex until the last transaction/child receipt releases it.
struct LeaseWorker {
    release: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}
impl LeaseWorker {
    fn acquire() -> Result<Self, String> {
        let (ready, received) = mpsc::sync_channel(0);
        let (release, finish) = mpsc::channel();
        let thread = thread::Builder::new().name("nrpt-machine-lease".into()).spawn(move || {
            match MutexHandle::acquire() {
                Ok(_held) => { if ready.send(Ok(())).is_ok() { let _ = finish.recv(); } }
                Err(error) => { let _ = ready.send(Err(error)); }
            }
        }).map_err(|e| format!("start NRPT mutex owner: {e}"))?;
        let worker = Self { release: Some(release), thread: Some(thread) };
        received.recv().map_err(|_| "NRPT mutex owner ended without acquiring lease")??;
        Ok(worker)
    }
}
impl Drop for LeaseWorker {
    fn drop(&mut self) {
        drop(self.release.take());
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

pub(crate) struct Writer { lease: Arc<LeaseWorker>, key: RegKey }
impl Writer {
    pub(super) fn acquire() -> Result<Self, String> {
        let lease = Arc::new(LeaseWorker::acquire()?);
        Ok(Self { lease, key: key_write(KEY, KEY_DESCRIPTOR, true)? })
    }

    pub(super) fn bind_effect(&self, owner: &mut crate::utils::CommandOutcome) {
        owner.retain_mutation_lease(self.lease.clone());
    }

    pub(super) fn read(&self) -> Result<Option<Vec<u8>>, String> { read_value(&self.key, VALUE, true) }

    pub(super) fn read_prefix(&self) -> Result<Option<Vec<u8>>, String> { read_value(&self.key, PREFIX, true) }

    pub(super) fn store_prefix(&self, bytes: &[u8]) -> Result<(), String> { store_value(&self.key, PREFIX, bytes, true) }

    pub(super) fn store(&self, bytes: &[u8]) -> Result<(), String> { store_value(&self.key, VALUE, bytes, true) }

    pub(crate) fn read_hosts(&self) -> Result<Option<Vec<u8>>, String> {
        key_read(HOSTS_KEY, false)?.as_ref().map(|key| read_value(key, VALUE, false)).transpose().map(Option::flatten)
    }

    pub(crate) fn store_hosts(&self, bytes: &[u8], cleanup_required: bool) -> Result<(), String> {
        // The public flag indexes outstanding cleanup only. The private
        // receipt still supplies all authority. An interruption can leave a
        // conservative true flag but cannot hide a private effect.
        if cleanup_required { store_value(&self.key, HOSTS_CLEANUP, b"1", true)?; }
        let key = key_write(HOSTS_KEY, HOSTS_DESCRIPTOR, false)?;
        store_value(&key, VALUE, bytes, false)?;
        if !cleanup_required { store_value(&self.key, HOSTS_CLEANUP, b"0", true)?; }
        Ok(())
    }

    pub(crate) fn clear_empty_hosts_indicator(&self) -> Result<(), String> {
        if read_value(&self.key, HOSTS_CLEANUP, true)?.as_deref() == Some(b"1") {
            store_value(&self.key, HOSTS_CLEANUP, b"0", true)?;
        }
        Ok(())
    }
}

fn store_value(key: &RegKey, name: &str, bytes: &[u8], user_read: bool) -> Result<(), String> {
    validate_key(key, user_read)?;
    key.set_raw_value(name, &RegValue { vtype: REG_BINARY, bytes: bytes.into() })
        .map_err(|e| format!("write NRPT journal: {e}"))?;
    let flushed = unsafe { RegFlushKey(key.raw_handle()) };
    if flushed != 0 { return Err(win_error("synchronize NRPT journal", flushed)); }
    if read_value(key, name, user_read)?.as_deref() != Some(bytes) { return Err("NRPT journal persisted readback disagrees".into()); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_descriptor_rejects_ordinary_ownership_and_write_grants() {
        let read_only = Descriptor::new(KEY_DESCRIPTOR).unwrap();
        assert!(machine_access(read_only.0, true).is_ok());
        assert!(machine_access(read_only.0, false).is_err());
        let private = Descriptor::new(HOSTS_DESCRIPTOR).unwrap();
        assert!(machine_access(private.0, false).is_ok());
        let foreign_write = Descriptor::new("O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KW;;;BU)").unwrap();
        assert!(machine_access(foreign_write.0, true).is_err());
        let foreign_owner = Descriptor::new("O:BUD:P(A;;KA;;;SY)(A;;KA;;;BA)").unwrap();
        assert!(machine_access(foreign_owner.0, true).is_err());
    }
}
