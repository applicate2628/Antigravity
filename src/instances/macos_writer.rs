//! Anchored receiving of the persistent settings-writer lock file.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

const LEAF: &[u8] = b"settings-writer.lock\0";

#[derive(Debug)]
pub(super) enum MacWriterError { Conflict, Native(String) }

impl std::fmt::Display for MacWriterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Conflict => f.write_str("settings writer already holds the lock"), Self::Native(error) => f.write_str(error) }
    }
}

/// The directory borrow and locked File remain alive for the writer's entire
/// lifetime; release is by handle close, never by unlinking the lock leaf.
pub(crate) struct MacSettingsWriterLease<'a> { _lock: File, _directory: &'a File }

pub(super) fn acquire_from_admitted_directory(directory: &File) -> Result<MacSettingsWriterLease<'_>, MacWriterError> {
    use crate::user_state_location::{assess_private_access, MacPrivateAccessPurpose};
    let file = receive_lock_file(directory).map_err(MacWriterError::Native)?;
    assess_private_access(&file, MacPrivateAccessPurpose::WriterLock).map_err(MacWriterError::Native)?;
    recheck_lock_file(directory, &file).map_err(MacWriterError::Native)?;
    match file.try_lock() {
        Ok(()) => {},
        Err(std::fs::TryLockError::WouldBlock) => return Err(MacWriterError::Conflict),
        Err(std::fs::TryLockError::Error(error)) => return Err(MacWriterError::Native(format!("lock settings writer: {error}"))),
    }
    recheck_lock_file(directory, &file).map_err(MacWriterError::Native)?;
    assess_private_access(&file, MacPrivateAccessPurpose::WriterLock).map_err(MacWriterError::Native)?;
    recheck_lock_file(directory, &file).map_err(MacWriterError::Native)?;
    Ok(MacSettingsWriterLease { _lock: file, _directory: directory })
}

/// Create a new private leaf, or open an existing leaf without truncation. The
/// caller still owns native ACL admission, locking and the final recheck.
pub(super) fn receive_lock_file(directory: &File) -> Result<File, String> {
    let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), LEAF.as_ptr().cast(),
        flags | libc::O_CREAT | libc::O_EXCL, 0o600 as libc::c_uint) };
    let fd = if fd >= 0 { fd } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) { return Err(format!("create writer lock: {error}")); }
        let existing = unsafe { libc::openat(directory.as_raw_fd(), LEAF.as_ptr().cast(), flags) };
        if existing < 0 { return Err(format!("open writer lock: {}", std::io::Error::last_os_error())); }
        existing
    };
    let file = unsafe { File::from_raw_fd(fd) };
    recheck_lock_file(directory, &file)?;
    Ok(file)
}

/// Bind the still-open object to its non-followed directory entry. A changed
/// or replaced leaf is a conflict; it is never removed or repaired here.
pub(super) fn recheck_lock_file(directory: &File, file: &File) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| format!("writer lock metadata: {error}"))?;
    let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstatat(directory.as_raw_fd(), LEAF.as_ptr().cast(), entry.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(format!("writer lock entry: {}", std::io::Error::last_os_error()));
    }
    let entry = unsafe { entry.assume_init() };
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1
        || metadata.len() != 0 || metadata.mode() & 0o077 != 0
        || metadata.dev() != entry.st_dev as u64 || metadata.ino() != entry.st_ino
        || metadata.uid() != entry.st_uid || metadata.mode() != u32::from(entry.st_mode)
        || metadata.nlink() != u64::from(entry.st_nlink) || metadata.len() != entry.st_size as u64 {
        return Err("writer lock has unsafe access, contents or changed identity".into());
    }
    Ok(())
}
