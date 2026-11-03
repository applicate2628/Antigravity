//! Existing Windows product-state leaf; callers retain their own base policy.
pub(crate) const WINDOWS_STATE_LEAF: &str = "AGUnlocker";
pub(crate) const WINDOWS_WSL_DEPLOYMENT_DATA_LEAF: &str = "wsl-deployment-context.json";

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::{self, File};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, OnceLock, Weak};

    /// One composition-root snapshot, before any state directory is touched.
    pub(crate) struct MacStateInput {
        pub(crate) xdg_data_home: Option<OsString>,
        pub(crate) home: Option<OsString>,
    }

    /// Candidate paths are data, not proof of ownership or write authority.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct MacStateCandidate {
        pub(crate) data_home: PathBuf,
        pub(crate) state_dir: PathBuf,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum MacStateError {
        RelativeXdgDataHome,
        MissingOrRelativeHome,
        Uninitialized,
        Native(String),
    }

    impl std::fmt::Display for MacStateError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::RelativeXdgDataHome => f.write_str("XDG_DATA_HOME must be absolute"),
                Self::MissingOrRelativeHome => f.write_str("HOME must be nonempty and absolute"),
                Self::Uninitialized => f.write_str("macOS state has not been initialized"),
                Self::Native(error) => f.write_str(error),
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct MacStatePaths { data_home: PathBuf, state_dir: PathBuf }
    impl MacStatePaths {
        pub(crate) fn data_home(&self) -> &Path { &self.data_home }
        pub(crate) fn state_dir(&self) -> &Path { &self.state_dir }
    }
    /// Main retains the strong owner. Published Weak state cannot keep an open
    /// descriptor alive after the owning application lifetime ends.
    #[derive(Debug)]
    pub(crate) struct MacStateDirectory { directory: File, paths: MacStatePaths }
    impl MacStateDirectory {
        pub(crate) fn state_dir(&self) -> &Path { self.paths.state_dir() }
        pub(crate) fn data_home(&self) -> &Path { self.paths.data_home() }
        pub(crate) fn directory(&self) -> &File { &self.directory }
    }
    static STATE: OnceLock<Weak<MacStateDirectory>> = OnceLock::new();

    pub(crate) fn macos_state_paths() -> Result<Arc<MacStateDirectory>, MacStateError> {
        STATE.get().and_then(Weak::upgrade).ok_or(MacStateError::Uninitialized)
    }

    fn native_error(stage: &str, error: impl std::fmt::Display) -> MacStateError {
        MacStateError::Native(format!("{stage}: {error}"))
    }

    fn component_name(name: &OsStr) -> Result<CString, MacStateError> {
        CString::new(name.as_bytes()).map_err(|_| MacStateError::Native("state path contains NUL".into()))
    }

    fn entry_matches(parent: &File, name: &CString, child: &File) -> Result<(), MacStateError> {
        let metadata = child.metadata().map_err(|error| native_error("directory metadata", error))?;
        let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), entry.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(native_error("directory entry", std::io::Error::last_os_error()));
        }
        let entry = unsafe { entry.assume_init() };
        if !metadata.is_dir() || metadata.dev() != entry.st_dev as u64 || metadata.ino() != entry.st_ino
            || metadata.uid() != entry.st_uid || metadata.mode() != u32::from(entry.st_mode) {
            return Err(MacStateError::Native("state directory entry changed".into()));
        }
        Ok(())
    }

    fn open_child(parent: &File, name: &OsStr, create: bool) -> Result<File, MacStateError> {
        use super::macos_acl::assess_private_access;
        assess_private_access(parent, MacPrivateAccessPurpose::NamespaceAncestor).map_err(MacStateError::Native)?;
        let parent_metadata = parent.metadata().map_err(|error| native_error("ancestor metadata", error))?;
        let name = component_name(name)?;
        if create && unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700 as libc::mode_t) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) { return Err(native_error("create state directory", error)); }
        }
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
        if fd < 0 { return Err(native_error("open state directory", std::io::Error::last_os_error())); }
        let child = unsafe { File::from_raw_fd(fd) };
        entry_matches(parent, &name, &child)?;
        let child_metadata = child.metadata().map_err(|error| native_error("child metadata", error))?;
        let uid = unsafe { libc::geteuid() };
        if (parent_metadata.uid() == 0 || parent_metadata.uid() == uid) && parent_metadata.mode() & 0o1000 != 0 && parent_metadata.mode() & 0o022 != 0
            && child_metadata.uid() != 0 && child_metadata.uid() != uid {
            return Err(MacStateError::Native("foreign child under shared sticky ancestor".into()));
        }
        assess_private_access(&child, MacPrivateAccessPurpose::NamespaceAncestor).map_err(MacStateError::Native)?;
        entry_matches(parent, &name, &child)?;
        Ok(child)
    }

    /// Resolve aliases only as an initial selector, then pin and validate the
    /// actual namespace. All later state I/O must use the retained descriptor.
    pub(crate) fn initialize_macos_state(input: MacStateInput) -> Result<Arc<MacStateDirectory>, MacStateError> {
        let candidate = resolve_macos_state(input)?;
        if let Some(previous) = STATE.get() {
            return match previous.upgrade() {
                Some(state) if state.data_home() == candidate.data_home.as_path() => Ok(state),
                _ => Err(MacStateError::Native("state context already initialized".into())),
            };
        }
        let mut existing = candidate.state_dir.clone();
        let mut missing = Vec::new();
        let canonical = loop {
            match fs::canonicalize(&existing) {
                Ok(path) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let name = existing.file_name().ok_or_else(|| native_error("state path", error))?.to_os_string();
                    missing.push(name);
                    if !existing.pop() { return Err(MacStateError::Native("state path has no existing ancestor".into())); }
                }
                Err(error) => return Err(native_error("resolve state path", error)),
            }
        };
        let mut directory = File::open("/").map_err(|error| native_error("open filesystem root", error))?;
        for component in canonical.components() {
            match component {
                std::path::Component::RootDir => {},
                std::path::Component::Normal(name) => directory = open_child(&directory, name, false)?,
                _ => return Err(MacStateError::Native("unexpected canonical state component".into())),
            }
        }
        for name in missing.iter().rev() { directory = open_child(&directory, name, true)?; }
        super::macos_acl::assess_private_access(&directory, MacPrivateAccessPurpose::StateDirectory).map_err(MacStateError::Native)?;
        let actual = fs::canonicalize(&candidate.state_dir).map_err(|error| native_error("recheck state path", error))?;
        let path_metadata = fs::metadata(&actual).map_err(|error| native_error("recheck state identity", error))?;
        let handle_metadata = directory.metadata().map_err(|error| native_error("state handle identity", error))?;
        if path_metadata.dev() != handle_metadata.dev() || path_metadata.ino() != handle_metadata.ino() {
            return Err(MacStateError::Native("state path changed during admission".into()));
        }
        let state = Arc::new(MacStateDirectory { directory, paths: MacStatePaths { data_home: candidate.data_home, state_dir: actual } });
        STATE.set(Arc::downgrade(&state)).map_err(|_| MacStateError::Native("state context changed during admission".into()))?;
        Ok(state)
    }

    /// Rights and flags from the received Darwin SDK sys/acl.h. This checks a
    /// decoded entry; acquisition, identity and complete native flag receiving
    /// are separate obligations of the descriptor owner.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum MacPrivateAccessPurpose { StateDirectory, WriterLock, NamespaceAncestor, StateFile }
    const ACL_KNOWN_RIGHTS: u64 = 0x3ffe | (1 << 20);
    const ACL_FILE_FORBIDDEN: u64 = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4)
        | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 12) | (1 << 13);
    const ACL_DIR_FORBIDDEN: u64 = (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6)
        | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);
    const ACL_ENTRY_FLAGS: u32 = (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8);

    pub(crate) fn check_acl_entry(purpose: MacPrivateAccessPurpose, tag: i32, owner: bool,
        rights: u64, flags: u32) -> Result<(), MacStateError> {
        let reject = || MacStateError::Native("unsupported or unsafe ACL entry".into());
        if !matches!(tag, 1 | 2) || rights & !ACL_KNOWN_RIGHTS != 0 || flags & !ACL_ENTRY_FLAGS != 0 {
            return Err(reject());
        }
        if tag == 2 || owner { return Ok(()); }
        let file_inherit = flags & (1 << 5) != 0;
        let directory_inherit = flags & (1 << 6) != 0;
        let inherit_only = flags & (1 << 8) != 0;
        let denied = match purpose {
            MacPrivateAccessPurpose::WriterLock => rights & ACL_FILE_FORBIDDEN != 0,
            MacPrivateAccessPurpose::StateDirectory => {
                ((!inherit_only || directory_inherit) && rights & ACL_DIR_FORBIDDEN != 0)
                    || (file_inherit && rights & ACL_FILE_FORBIDDEN != 0)
            }
            MacPrivateAccessPurpose::NamespaceAncestor => (!inherit_only || directory_inherit) && rights & ACL_DIR_FORBIDDEN != 0,
            MacPrivateAccessPurpose::StateFile => !inherit_only && rights & ACL_DIR_FORBIDDEN != 0,
        };
        if denied { Err(reject()) } else { Ok(()) }
    }

    pub(crate) fn resolve_macos_state(input: MacStateInput) -> Result<MacStateCandidate, MacStateError> {
        let data_home = match input.xdg_data_home.filter(|value| !value.is_empty()) {
            Some(value) => {
                let path = PathBuf::from(value);
                if !path.is_absolute() { return Err(MacStateError::RelativeXdgDataHome); }
                path
            }
            None => {
                let home = input.home.filter(|value| !value.is_empty())
                    .map(PathBuf::from).filter(|path| path.is_absolute())
                    .ok_or(MacStateError::MissingOrRelativeHome)?;
                home.join(".local").join("share")
            }
        };
        let state_dir = data_home.join("agunlocker");
        Ok(MacStateCandidate { data_home, state_dir })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn input(xdg: Option<&str>, home: Option<&str>) -> MacStateInput {
            MacStateInput { xdg_data_home: xdg.map(Into::into), home: home.map(Into::into) }
        }

        #[test]
        fn mac_state_selection_preserves_explicit_inputs_and_rejects_invalid_ones() {
            let chosen = resolve_macos_state(input(Some("/tmp/данные space"), None)).unwrap();
            assert_eq!(chosen.data_home, PathBuf::from("/tmp/данные space"));
            assert_eq!(chosen.state_dir, PathBuf::from("/tmp/данные space/agunlocker"));
            for xdg in [None, Some("")] {
                let chosen = resolve_macos_state(input(xdg, Some("/Users/example"))).unwrap();
                assert_eq!(chosen.data_home, PathBuf::from("/Users/example/.local/share"));
                assert_eq!(chosen.state_dir, PathBuf::from("/Users/example/.local/share/agunlocker"));
            }
            assert_eq!(resolve_macos_state(input(Some("relative"), Some("/valid"))), Err(MacStateError::RelativeXdgDataHome));
            for home in [None, Some(""), Some("relative")] {
                assert_eq!(resolve_macos_state(input(None, home)), Err(MacStateError::MissingOrRelativeHome));
            }
        }

        #[test]
        fn private_acl_policy_distinguishes_direct_and_inherited_grants() {
            use MacPrivateAccessPurpose::{NamespaceAncestor as Ancestor, StateDirectory as Dir, WriterLock as Lock};
            let allow = 1; let deny = 2;
            let read = 1 << 1; let write = 1 << 2; let search = 1 << 3;
            let synchronize = 1 << 20; let file_inherit = 1 << 5; let only_inherit = 1 << 8;
            assert!(check_acl_entry(Dir, allow, false, read | search, 0).is_ok());
            assert!(check_acl_entry(Dir, allow, false, read, file_inherit | only_inherit).is_err());
            assert!(check_acl_entry(Dir, allow, false, write | synchronize, 0).is_err());
            assert!(check_acl_entry(Dir, allow, false, synchronize, file_inherit).is_ok());
            assert!(check_acl_entry(Lock, allow, false, read, 0).is_err());
            assert!(check_acl_entry(Lock, allow, true, read | write, 0).is_ok());
            assert!(check_acl_entry(Lock, deny, false, read | write, 0).is_ok());
            assert!(check_acl_entry(Lock, deny, false, 1 << 30, 0).is_err());
            assert!(check_acl_entry(Lock, allow, false, 0, 1 << 29).is_err());
            assert!(check_acl_entry(Ancestor, allow, false, write, 0).is_err());
            assert!(check_acl_entry(Ancestor, allow, false, write, only_inherit).is_ok());
            assert!(check_acl_entry(Ancestor, allow, false, write, only_inherit | (1 << 6)).is_err());
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use macos::{initialize_macos_state, macos_state_paths, MacPrivateAccessPurpose, MacStateDirectory, MacStateError, MacStateInput};

#[cfg(target_os = "macos")]
#[path = "user_state_location/macos_acl.rs"]
mod macos_acl;
#[cfg(target_os = "macos")]
pub(crate) use macos_acl::assess_private_access;
#[cfg(target_os = "macos")]
#[path = "user_state_location/macos_files.rs"]
mod macos_files;
#[cfg(target_os = "macos")]
pub(crate) use macos_files::MacStateFile;
