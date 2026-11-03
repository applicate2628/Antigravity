//! State-file operations anchored to the retained, admitted directory.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

use super::{assess_private_access, MacPrivateAccessPurpose, MacStateDirectory};

#[derive(Clone, Copy)]
pub(crate) enum MacStateFile { Secret, Public }

fn leaf(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid state file leaf"));
    }
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "state file leaf contains NUL"))
}

fn recheck(directory: &File, name: &CString, file: &File, kind: MacStateFile) -> io::Result<()> {
    let metadata = file.metadata()?;
    let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstatat(directory.as_raw_fd(), name.as_ptr(), entry.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::NotFound { io::Error::other("opened state file entry disappeared") } else { error });
    }
    let entry = unsafe { entry.assume_init() };
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1
        || metadata.dev() != entry.st_dev as u64 || metadata.ino() != entry.st_ino
        || metadata.uid() != entry.st_uid || metadata.mode() != u32::from(entry.st_mode)
        || metadata.nlink() != u64::from(entry.st_nlink) {
        return Err(io::Error::other("state file entry changed or is not owned"));
    }
    let purpose = match kind { MacStateFile::Secret => MacPrivateAccessPurpose::WriterLock, MacStateFile::Public => MacPrivateAccessPurpose::StateFile };
    assess_private_access(file, purpose).map_err(io::Error::other)?;
    // The ACL check can take time; recheck entry identity afterwards too.
    let mut after = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstatat(directory.as_raw_fd(), name.as_ptr(), after.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::NotFound { io::Error::other("state file entry disappeared during admission") } else { error });
    }
    let after = unsafe { after.assume_init() };
    if after.st_dev != entry.st_dev || after.st_ino != entry.st_ino || after.st_uid != entry.st_uid
        || after.st_mode != entry.st_mode || after.st_nlink != entry.st_nlink {
        return Err(io::Error::other("state file entry changed during admission"));
    }
    Ok(())
}

fn open_existing(directory: &File, name: &CString, flags: libc::c_int, kind: MacStateFile) -> io::Result<File> {
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    let file = unsafe { File::from_raw_fd(fd) };
    recheck(directory, name, &file, kind)?;
    Ok(file)
}

impl MacStateDirectory {
    pub(crate) fn read_file(&self, name: &str, kind: MacStateFile) -> io::Result<Vec<u8>> {
        let name = leaf(name)?;
        let mut file = open_existing(self.directory(), &name, libc::O_RDONLY, kind)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        recheck(self.directory(), &name, &file, kind)?;
        Ok(bytes)
    }

    /// Exclusive temp creation and same-directory rename preserve the existing
    /// owner's replace behavior. The temp is removed only if it is still ours.
    pub(crate) fn replace_file(&self, name: &str, bytes: &[u8], kind: MacStateFile) -> io::Result<()> {
        let name = leaf(name)?;
        let original = match open_existing(self.directory(), &name, libc::O_RDONLY, kind) {
            Ok(file) => Some(file), Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let mut random = [0u8; 16];
        unsafe { libc::arc4random_buf(random.as_mut_ptr().cast(), random.len()) };
        let temporary = CString::new(format!(".agunlocker-{}.tmp", random.iter().map(|byte| format!("{byte:02x}")).collect::<String>()))
            .map_err(|_| io::Error::other("invalid temporary leaf"))?;
        let fd = unsafe { libc::openat(self.directory().as_raw_fd(), temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600 as libc::c_uint) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut renamed = false;
        let result = (|| {
            recheck(self.directory(), &temporary, &file, kind)?;
            file.write_all(bytes)?;
            file.flush()?;
            recheck(self.directory(), &temporary, &file, kind)?;
            match &original {
                Some(original) => recheck(self.directory(), &name, original, kind)?,
                None => match open_existing(self.directory(), &name, libc::O_RDONLY, kind) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                    Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "state file appeared during replacement")),
                    Err(error) => return Err(error),
                },
            }
            if unsafe { libc::renameat(self.directory().as_raw_fd(), temporary.as_ptr(), self.directory().as_raw_fd(), name.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            renamed = true;
            recheck(self.directory(), &name, &file, kind)
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) if renamed => Err(io::Error::other(format!("replacement completed but receiving failed: {error}"))),
            Err(first) => {
                match recheck(self.directory(), &temporary, &file, kind) {
                    Ok(()) => {
                        if unsafe { libc::unlinkat(self.directory().as_raw_fd(), temporary.as_ptr(), 0) } != 0 {
                            return Err(io::Error::other(format!("{first}; temporary {} cleanup failed: {}", temporary.to_string_lossy(), io::Error::last_os_error())));
                        }
                        Err(first)
                    }
                    Err(error) => Err(io::Error::other(format!("{first}; temporary {} ownership not revalidated: {error}", temporary.to_string_lossy()))),
                }
            }
        }
    }

    pub(crate) fn remove_file(&self, name: &str, kind: MacStateFile) -> io::Result<()> {
        let name = leaf(name)?;
        let file = match open_existing(self.directory(), &name, libc::O_RDONLY, kind) {
            Ok(file) => file, Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()), Err(error) => return Err(error),
        };
        recheck(self.directory(), &name, &file, kind)?;
        if unsafe { libc::unlinkat(self.directory().as_raw_fd(), name.as_ptr(), 0) } != 0 { return Err(io::Error::last_os_error()); }
        let mut after = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstatat(self.directory().as_raw_fd(), name.as_ptr(), after.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } == 0 {
            return Err(io::Error::other("state file reappeared after removal"));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) { Ok(()) } else { Err(error) }
    }

    pub(crate) fn append_log(&self, name: &str, bytes: &[u8], rotate_above: u64) -> io::Result<()> {
        let name = leaf(name)?;
        let kind = MacStateFile::Public;
        let existing = match open_existing(self.directory(), &name, libc::O_WRONLY | libc::O_APPEND, kind) {
            Ok(file) => Some(file), Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let existing = match existing {
            Some(file) if file.metadata()?.len() > rotate_above => {
                recheck(self.directory(), &name, &file, kind)?;
                if unsafe { libc::unlinkat(self.directory().as_raw_fd(), name.as_ptr(), 0) } != 0 { return Err(io::Error::last_os_error()); }
                None
            },
            value => value,
        };
        let mut file = if let Some(file) = existing { file } else {
            let fd = unsafe { libc::openat(self.directory().as_raw_fd(), name.as_ptr(),
                libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                0o600 as libc::c_uint) };
            if fd < 0 { return Err(io::Error::last_os_error()); }
            unsafe { File::from_raw_fd(fd) }
        };
        recheck(self.directory(), &name, &file, kind)?;
        file.write_all(bytes)?;
        recheck(self.directory(), &name, &file, kind)
    }
}
