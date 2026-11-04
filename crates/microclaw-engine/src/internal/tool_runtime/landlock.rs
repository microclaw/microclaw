//! Landlock fallback for the local sandbox (Linux without bubblewrap).
//!
//! Landlock is an unprivileged Linux security module (kernel 5.13+). A
//! ruleset is built in the parent process; the child only calls
//! `prctl(PR_SET_NO_NEW_PRIVS)` and `landlock_restrict_self` between `fork`
//! and `exec` (both plain system calls, safe in that window).
//!
//! What it enforces: file writes (create, delete, rename, truncate, write)
//! only beneath the writable roots, and — with kernel ABI 4+ — no outgoing
//! TCP connections when network access is off. Unlike bubblewrap it cannot
//! hide credential directories from reads; the policy is documented as such.

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    const CREATE_RULESET_VERSION: u32 = 1;
    const RULE_PATH_BENEATH: u32 = 1;

    const WRITE_FILE: u64 = 1 << 1;
    const REMOVE_DIR: u64 = 1 << 4;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_CHAR: u64 = 1 << 6;
    const MAKE_DIR: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SOCK: u64 = 1 << 9;
    const MAKE_FIFO: u64 = 1 << 10;
    const MAKE_BLOCK: u64 = 1 << 11;
    const MAKE_SYM: u64 = 1 << 12;
    const REFER: u64 = 1 << 13;
    const TRUNCATE: u64 = 1 << 14;
    const NET_CONNECT_TCP: u64 = 1 << 1;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    /// The kernel's Landlock ABI version, or `None` when unsupported.
    pub fn abi() -> Option<u32> {
        // SAFETY: querying the ABI passes a null attribute with size 0.
        let version = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        };
        (version > 0).then_some(version as u32)
    }

    fn write_access(abi: u32) -> u64 {
        let mut access = WRITE_FILE
            | REMOVE_DIR
            | REMOVE_FILE
            | MAKE_CHAR
            | MAKE_DIR
            | MAKE_REG
            | MAKE_SOCK
            | MAKE_FIFO
            | MAKE_BLOCK
            | MAKE_SYM;
        if abi >= 2 {
            access |= REFER;
        }
        if abi >= 3 {
            access |= TRUNCATE;
        }
        access
    }

    /// A built Landlock ruleset, applied in the child with
    /// [`Ruleset::restrict_self`].
    #[derive(Debug)]
    pub struct Ruleset {
        fd: OwnedFd,
        /// Outgoing TCP is blocked (kernel ABI 4+ and network off).
        pub network_blocked: bool,
    }

    fn open_path(path: &Path) -> io::Result<OwnedFd> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // SAFETY: c_path is a valid NUL-terminated string.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was just returned by open and is owned here.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn add_path_rule(ruleset: &OwnedFd, path: &Path, access: u64) -> io::Result<()> {
        let parent = open_path(path)?;
        let attr = PathBeneathAttr {
            allowed_access: access,
            parent_fd: parent.as_raw_fd(),
        };
        // SAFETY: attr is a valid landlock_path_beneath_attr for this call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    impl Ruleset {
        /// Allow writes only beneath `writable` (directories) plus the usual
        /// device files; block outgoing TCP when `network` is false and the
        /// kernel supports it.
        pub fn new(writable: &[PathBuf], network: bool) -> io::Result<Self> {
            let abi = abi().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "Landlock is not available")
            })?;
            let fs_access = write_access(abi);
            let block_net = !network && abi >= 4;
            let attr = RulesetAttr {
                handled_access_fs: fs_access,
                handled_access_net: if block_net { NET_CONNECT_TCP } else { 0 },
            };
            let size = if abi >= 4 {
                std::mem::size_of::<RulesetAttr>()
            } else {
                std::mem::size_of::<u64>()
            };
            // SAFETY: attr outlives the call; size matches the kernel ABI.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    &attr as *const RulesetAttr,
                    size,
                    0u32,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the kernel returned a new file descriptor we own.
            let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            for dir in writable {
                if dir.is_dir() {
                    add_path_rule(&fd, dir, fs_access)?;
                }
            }
            let file_access = WRITE_FILE | if abi >= 3 { TRUNCATE } else { 0 };
            for device in [
                "/dev/null",
                "/dev/zero",
                "/dev/full",
                "/dev/tty",
                "/dev/ptmx",
            ] {
                let _ = add_path_rule(&fd, Path::new(device), file_access);
            }
            if Path::new("/dev/pts").is_dir() {
                let _ = add_path_rule(&fd, Path::new("/dev/pts"), file_access);
            }
            Ok(Self {
                fd,
                network_blocked: block_net,
            })
        }

        /// Restrict the calling process. Only async-signal-safe system calls:
        /// meant for `pre_exec`.
        pub fn restrict_self(&self) -> io::Result<()> {
            // SAFETY: prctl and landlock_restrict_self take plain integers.
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::syscall(libc::SYS_landlock_restrict_self, self.fd.as_raw_fd(), 0u32) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;
    use std::path::PathBuf;

    pub fn abi() -> Option<u32> {
        None
    }

    #[derive(Debug)]
    pub struct Ruleset {
        pub network_blocked: bool,
    }

    impl Ruleset {
        pub fn new(_writable: &[PathBuf], _network: bool) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Landlock is Linux-only",
            ))
        }

        pub fn restrict_self(&self) -> io::Result<()> {
            Ok(())
        }
    }
}

pub use imp::{abi, Ruleset};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn restricts_writes_to_the_allowed_roots() {
        if abi().is_none() {
            eprintln!("Landlock unavailable; skipping");
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let allowed = base.path().join("allowed");
        let denied = base.path().join("denied");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&denied).unwrap();
        let rules =
            std::sync::Arc::new(Ruleset::new(std::slice::from_ref(&allowed), false).unwrap());
        let run = |script: String| {
            let rules = rules.clone();
            let mut cmd = tokio::process::Command::new("/bin/sh");
            cmd.args(["-c", &script]);
            // SAFETY: restrict_self only issues system calls.
            unsafe {
                cmd.pre_exec(move || rules.restrict_self());
            }
            async move { cmd.output().await.unwrap() }
        };
        let ok = run(format!(
            "echo a > '{}/f' && cat '{}/f'",
            allowed.display(),
            allowed.display()
        ))
        .await;
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        let bad = run(format!("echo a > '{}/f'", denied.display())).await;
        assert!(!bad.status.success());
        assert!(!denied.join("f").exists());
        let devnull = run("echo a > /dev/null".into()).await;
        assert!(devnull.status.success());
    }
}
