//! Kernel interface layer — the single place in the crate allowed to touch raw
//! syscalls. All other modules must use the safe wrappers exported here and must
//! not call libc directly.
use crate::error::{last_err, ZResult};
use libc::{c_int, c_void};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

// ---------- process identity / host queries ----------

/// Return the current process ID without exposing libc's unsafe query to callers.
pub fn process_id() -> libc::pid_t {
    unsafe { libc::getpid() }
}

/// Return the effective UID without exposing libc's unsafe query to callers.
pub fn effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

/// Return the effective GID without exposing libc's unsafe query to callers.
pub fn effective_gid() -> libc::gid_t {
    unsafe { libc::getegid() }
}

/// Apply a per-process POSIX resource limit.
///
/// Callers reach this through the safe `rlimit` module. The syscall wrapper is
/// kept here with the other kernel-facing operations.
pub fn set_resource_limit(resource: c_int, soft: u64, hard: u64) -> ZResult<()> {
    let soft = libc::rlim_t::try_from(soft)
        .map_err(|_| crate::zerr!("soft resource limit does not fit rlim_t"))?;
    let hard = libc::rlim_t::try_from(hard)
        .map_err(|_| crate::zerr!("hard resource limit does not fit rlim_t"))?;
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    if unsafe { libc::setrlimit(resource as _, &limit) } != 0 {
        return Err(last_err("setrlimit"));
    }
    Ok(())
}

/// Probe whether a PID currently exists. EPERM still means that the process
/// exists but is not inspectable by this user.
pub fn pid_exists(pid: libc::pid_t) -> bool {
    // kill(2) treats zero and negative values as process-group selectors, not
    // individual PIDs. Lifecycle state only accepts positive PIDs, so reject
    // those values here instead of accidentally reporting a process group as
    // a container init.
    if pid <= 0 {
        return false;
    }
    (unsafe { libc::kill(pid, 0) }) == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Acquire an advisory file lock. The descriptor stays locked until close.
pub fn flock(fd: RawFd, operation: c_int) -> ZResult<()> {
    if unsafe { libc::flock(fd, operation) } != 0 {
        return Err(last_err("flock"));
    }
    Ok(())
}

/// Open a file relative to a pinned directory, without following its final symlink.
pub fn open_state_file_at(directory: &std::fs::File) -> std::io::Result<std::fs::File> {
    let name = c"state.json";
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Open one log entry relative to a pinned directory without following symlinks.
pub fn open_log_file_at(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    open_log_entry_at(directory, name, libc::O_RDONLY)
}

/// Open or create a log for writing relative to a pinned directory.
pub fn open_log_writer_at(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
    create: bool,
    append: bool,
) -> std::io::Result<std::fs::File> {
    let flags = libc::O_RDWR
        | if create { libc::O_CREAT } else { 0 }
        | if append { libc::O_APPEND } else { 0 };
    open_log_entry_at(directory, name, flags)
}

/// Pin a log entry without requiring read or write permissions.
pub fn open_log_path_at(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    open_log_entry_at(directory, name, libc::O_PATH)
}

/// Exclusively create a replacement log in a pinned directory.
pub fn create_log_file_at(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    open_log_entry_at(
        directory,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )
}

/// Rename a log entry within a pinned directory.
pub fn rename_log_file_at(
    directory: &std::fs::File,
    from: &std::ffi::OsStr,
    to: &std::ffi::OsStr,
) -> std::io::Result<()> {
    let from = log_entry_name(from)?;
    let to = log_entry_name(to)?;
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Remove a log entry from a pinned directory.
pub fn unlink_log_file_at(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    let name = log_entry_name(name)?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn log_entry_name(name: &std::ffi::OsStr) -> std::io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    CString::new(bytes).map_err(|_| std::io::ErrorKind::InvalidInput.into())
}

fn open_log_entry_at(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
) -> std::io::Result<std::fs::File> {
    let name = log_entry_name(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600 as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Create an exclusive file inside an already opened directory.
pub fn create_file_at(
    directory: &std::fs::File,
    name: &str,
    mode: u32,
) -> std::io::Result<std::fs::File> {
    let name = CString::new(name).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Atomically replace a directory entry with another entry in the same directory.
pub fn rename_file_at(directory: &std::fs::File, from: &str, to: &str) -> std::io::Result<()> {
    let from = CString::new(from).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let to = CString::new(to).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Remove a temporary file from a pinned directory.
pub fn unlink_file_at(directory: &std::fs::File, name: &str) -> std::io::Result<()> {
    let name = CString::new(name).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read the system clock tick frequency used by `/proc/<pid>/stat`.
pub fn clock_ticks_per_second() -> u64 {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 {
        hz as u64
    } else {
        100
    }
}

/// Return the running kernel release, if `uname(2)` succeeds.
pub fn kernel_release() -> Option<String> {
    kernel_uname().map(|uts| cstr_to_string(uts.release.as_ptr()))
}

/// Return the kernel machine identifier used for ARM image variants.
pub fn kernel_machine() -> Option<String> {
    kernel_uname().map(|uts| cstr_to_string(uts.machine.as_ptr()))
}

/// Return the current UTS namespace hostname, if `uname(2)` succeeds.
pub fn host_name() -> Option<String> {
    kernel_uname()
        .map(|uts| cstr_to_string(uts.nodename.as_ptr()))
        .filter(|name| !name.is_empty())
}

fn kernel_uname() -> Option<libc::utsname> {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return None;
    }
    Some(uts)
}

// ---------- mounts ----------

pub fn mount<S: AsRef<str>>(
    source: Option<&str>,
    target: S,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> ZResult<()> {
    let target = cstring(target.as_ref())?;
    let src = source.map(cstring).transpose()?;
    let fty = fstype.map(cstring).transpose()?;
    let data = data.map(cstring).transpose()?;
    let rc = unsafe {
        libc::mount(
            src.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            fty.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()) as *mut c_void,
        )
    };
    if rc != 0 {
        return Err(last_err(&format!("mount -> {}", target.to_string_lossy())));
    }
    Ok(())
}

pub fn umount2<P: AsRef<Path>>(target: P, flags: c_int) -> ZResult<()> {
    let t = cpath(target.as_ref())?;
    let rc = unsafe { libc::umount2(t.as_ptr(), flags) };
    if rc != 0 {
        return Err(last_err("umount2"));
    }
    Ok(())
}

/// pivot_root(new_root, put_old).
///
/// Standard sequence used by modern runtimes: make the mount tree private, bind the
/// new root onto itself so it is a mount point, chdir into it, call
/// pivot_root(".", "."), then detach the old root.
pub fn pivot_root<P: AsRef<Path>>(new_root: P, put_old: P) -> ZResult<()> {
    let nr = cpath(new_root.as_ref())?;
    let po = cpath(put_old.as_ref())?;
    // glibc/musl do not wrap pivot_root; go through the raw syscall.
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, nr.as_ptr(), po.as_ptr()) };
    if rc != 0 {
        return Err(last_err("pivot_root"));
    }
    Ok(())
}

pub fn chdir<P: AsRef<Path>>(p: P) -> ZResult<()> {
    let s = cpath(p.as_ref())?;
    if unsafe { libc::chdir(s.as_ptr()) } != 0 {
        return Err(last_err("chdir"));
    }
    Ok(())
}

pub fn sethostname(name: &str) -> ZResult<()> {
    if unsafe { libc::sethostname(name.as_ptr() as *const libc::c_char, name.len()) } != 0 {
        return Err(last_err("sethostname"));
    }
    Ok(())
}

/// Recursive mkdir -p (existing directory is fine). Used to create mount points
/// inside root filesystems that may be missing intermediate directories.
pub fn mkdir_p<P: AsRef<Path>>(path: P, mode: libc::mode_t) -> ZResult<()> {
    let p = path.as_ref();
    if p.exists() {
        return Ok(());
    }
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            mkdir_p(parent, mode)?;
        }
    }
    let s = cpath(p)?;
    if unsafe { libc::mkdir(s.as_ptr(), mode) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(e.into());
    }
    Ok(())
}

fn mknod_device<P: AsRef<Path>>(
    path: P,
    file_type: libc::mode_t,
    major: u32,
    minor: u32,
    mode: libc::mode_t,
) -> ZResult<()> {
    let p = cpath(path.as_ref())?;
    let dev = libc::makedev(major, minor);
    let rc = unsafe { libc::mknod(p.as_ptr(), file_type | mode, dev) };
    if rc != 0 {
        return Err(last_err("mknod"));
    }
    // mknod(2) applies the process umask. Device permissions from `--device`
    // are an explicit security boundary, so make the requested mode exact.
    if unsafe { libc::chmod(p.as_ptr(), mode) } != 0 {
        return Err(last_err("chmod device node"));
    }
    Ok(())
}

/// Create a character device node (minimal /dev set inside the container).
pub fn mknod_char<P: AsRef<Path>>(
    path: P,
    major: u32,
    minor: u32,
    mode: libc::mode_t,
) -> ZResult<()> {
    mknod_device(path, libc::S_IFCHR, major, minor, mode)
}

/// Create a block device node for an explicit `--device` request.
pub fn mknod_block<P: AsRef<Path>>(
    path: P,
    major: u32,
    minor: u32,
    mode: libc::mode_t,
) -> ZResult<()> {
    mknod_device(path, libc::S_IFBLK, major, minor, mode)
}

pub fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(target: P, link: Q) -> ZResult<()> {
    let t = cpath(target.as_ref())?;
    let l = cpath(link.as_ref())?;
    if unsafe { libc::symlink(t.as_ptr(), l.as_ptr()) } != 0 {
        return Err(last_err("symlink"));
    }
    Ok(())
}

/// Read an extended attribute from a path. Missing attributes and filesystems
/// without xattr support are returned as `None`; other kernel errors stay
/// visible to the caller.
pub fn get_xattr<P: AsRef<Path>>(path: P, name: &str) -> ZResult<Option<Vec<u8>>> {
    let path = path.as_ref();
    let path_c = cpath(path)?;
    let name = CString::new(name).map_err(|_| crate::zerr!("invalid xattr name: {name}"))?;
    let mut value = vec![0u8; 64];
    loop {
        let size = unsafe {
            libc::getxattr(
                path_c.as_ptr(),
                name.as_ptr(),
                value.as_mut_ptr() as *mut c_void,
                value.len(),
            )
        };
        if size >= 0 {
            value.truncate(size as usize);
            return Ok(Some(value));
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => return Ok(None),
            // Some kernels/user-namespace combinations hide `trusted.*`
            // attributes from an otherwise authorized caller. Treat that the
            // same as an absent namespace and let callers try the `user.*`
            // spelling instead.
            Some(libc::EACCES) | Some(libc::EPERM) => return Ok(None),
            Some(libc::ERANGE) => {
                let next = value
                    .len()
                    .checked_mul(2)
                    .ok_or_else(|| crate::zerr!("xattr value is too large"))?;
                value.resize(next, 0);
            }
            _ => {
                return Err(crate::zerr!(
                    "getxattr {}::{}: {error}",
                    path.display(),
                    name.to_string_lossy()
                ));
            }
        }
    }
}

#[cfg(test)]
pub fn set_xattr<P: AsRef<Path>>(path: P, name: &str, value: &[u8]) -> ZResult<()> {
    let path = path.as_ref();
    let path_c = cpath(path)?;
    let name = CString::new(name).map_err(|_| crate::zerr!("invalid xattr name: {name}"))?;
    let size = libc::size_t::try_from(value.len())
        .map_err(|_| crate::zerr!("xattr value is too large"))?;
    if unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const c_void,
            size,
            0,
        )
    } != 0
    {
        return Err(last_err("setxattr"));
    }
    Ok(())
}

// ---------- cgroup device policy ----------

#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
struct BpfProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
}

const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_PROG_ATTACH: libc::c_long = 8;
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
const BPF_CGROUP_DEVICE: u32 = 6;

/// Load a `BPF_PROG_TYPE_CGROUP_DEVICE` program and attach it to a cgroup v2
/// directory. The instructions are generated by `device_cgroup`; keeping the
/// raw bpf(2) calls and ABI structs here preserves the unsafe concentration
/// boundary.
pub fn attach_cgroup_device_program(cgroup: &Path, instructions: &[u64]) -> ZResult<()> {
    if instructions.is_empty() {
        return Err(crate::zerr!("refusing to load an empty device BPF program"));
    }
    let mut verifier_log = vec![0u8; 64 * 1024];
    let license = b"GPL\0";
    let load = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_CGROUP_DEVICE,
        insn_cnt: instructions
            .len()
            .try_into()
            .map_err(|_| crate::zerr!("device BPF program is too large"))?,
        insns: instructions.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: verifier_log
            .len()
            .try_into()
            .map_err(|_| crate::zerr!("device BPF verifier log is too large"))?,
        log_buf: verifier_log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        // BPF object names accept letters, digits, and underscores only.
        prog_name: *b"zerun_device\0\0\0\0",
        prog_ifindex: 0,
        expected_attach_type: BPF_CGROUP_DEVICE,
    };
    let program_fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD,
            &load as *const BpfProgLoadAttr,
            std::mem::size_of::<BpfProgLoadAttr>(),
        )
    };
    if program_fd < 0 {
        let error = std::io::Error::last_os_error();
        let log = verifier_log
            .split(|byte| *byte == 0)
            .next()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        let detail = if log.trim().is_empty() {
            String::new()
        } else {
            format!("; verifier: {}", log.trim())
        };
        return Err(crate::zerr!(
            "load cgroup device BPF program: {error}{detail}"
        ));
    }
    // SAFETY: bpf(BPF_PROG_LOAD) returned a fresh, non-negative file descriptor.
    let program_fd = unsafe { OwnedFd::from_raw_fd(program_fd as RawFd) };

    let cgroup_fd = std::fs::File::open(cgroup)
        .map_err(|error| crate::zerr!("open cgroup {}: {error}", cgroup.display()))?;
    let target_fd: u32 = cgroup_fd
        .as_raw_fd()
        .try_into()
        .map_err(|_| crate::zerr!("cgroup file descriptor does not fit bpf_attr"))?;
    let attach = BpfProgAttachAttr {
        target_fd,
        attach_bpf_fd: program_fd
            .as_raw_fd()
            .try_into()
            .map_err(|_| crate::zerr!("BPF program file descriptor does not fit bpf_attr"))?,
        attach_type: BPF_CGROUP_DEVICE,
        attach_flags: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_ATTACH,
            &attach as *const BpfProgAttachAttr,
            std::mem::size_of::<BpfProgAttachAttr>(),
        )
    };
    if rc != 0 {
        return Err(last_err(&format!(
            "attach device BPF program to {}",
            cgroup.display()
        )));
    }
    Ok(())
}

// ---------- terminals / pseudo-terminals ----------

/// Allocate a new host-side PTY pair.
///
/// The master gets CLOEXEC so a container child cannot accidentally inherit the
/// host side across `execve`. The caller must dup2 the slave onto container
/// stdio and close its own slave descriptor after the worker fork.
pub fn open_pty() -> ZResult<(RawFd, RawFd)> {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        return Err(last_err("posix_openpt"));
    }
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        let e = std::io::Error::last_os_error();
        close(master);
        return Err(e.into());
    }
    let mut name = [0 as libc::c_char; 256];
    if unsafe { libc::ptsname_r(master, name.as_mut_ptr(), name.len()) } != 0 {
        let e = std::io::Error::last_os_error();
        close(master);
        return Err(e.into());
    }
    if unsafe { libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        let e = std::io::Error::last_os_error();
        close(master);
        return Err(e.into());
    }
    let slave = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave < 0 {
        let e = std::io::Error::last_os_error();
        close(master);
        return Err(e.into());
    }
    Ok((master, slave))
}

pub fn is_terminal(fd: RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

pub fn make_terminal_raw(fd: RawFd) -> ZResult<libc::termios> {
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
        return Err(last_err("tcgetattr"));
    }
    let mut raw = saved;
    unsafe { libc::cfmakeraw(&mut raw) };
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
        return Err(last_err("tcsetattr(TCSANOW)"));
    }
    Ok(saved)
}

pub fn restore_terminal(fd: RawFd, saved: &libc::termios) {
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, saved);
    }
}

/// Disable terminal echo while preserving the rest of the line discipline.
/// Returns the caller-owned saved termios for a precise restore.
pub fn disable_terminal_echo(fd: RawFd) -> ZResult<libc::termios> {
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
        return Err(last_err("tcgetattr"));
    }
    let mut hidden = saved;
    hidden.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(last_err("tcsetattr(disable ECHO)"));
    }
    Ok(saved)
}

pub fn terminal_window_size(fd: RawFd) -> ZResult<libc::winsize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } != 0 {
        return Err(last_err("ioctl(TIOCGWINSZ)"));
    }
    Ok(ws)
}

/// Best-effort terminal resize used when attaching an interactive PTY.
pub fn copy_window_size(from: RawFd, to: RawFd) -> ZResult<()> {
    let ws = terminal_window_size(from)?;
    set_terminal_window_size(to, &ws)
}

pub fn set_terminal_window_size(fd: RawFd, ws: &libc::winsize) -> ZResult<()> {
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, ws) } != 0 {
        return Err(last_err("ioctl(TIOCSWINSZ)"));
    }
    Ok(())
}

/// Make `fd` the controlling terminal of the current (already new) session.
pub fn set_controlling_terminal(fd: RawFd) -> ZResult<()> {
    if unsafe { libc::ioctl(fd, libc::TIOCSCTTY, 0) } != 0 {
        return Err(last_err("ioctl(TIOCSCTTY)"));
    }
    Ok(())
}

pub fn new_session() -> ZResult<libc::pid_t> {
    let rc = unsafe { libc::setsid() };
    if rc < 0 {
        return Err(last_err("setsid"));
    }
    Ok(rc)
}

pub fn redirect_stdio(fd: RawFd) -> ZResult<()> {
    dup2(fd, libc::STDIN_FILENO)?;
    dup2(fd, libc::STDOUT_FILENO)?;
    dup2(fd, libc::STDERR_FILENO)
}

pub fn install_signal_handler(sig: c_int, handler: extern "C" fn(c_int)) -> ZResult<()> {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            return Err(last_err("sigaction"));
        }
    }
    Ok(())
}

/// Restore the default disposition for a signal in a forked child.
pub fn reset_signal_handler(sig: c_int) -> ZResult<()> {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            return Err(last_err("sigaction"));
        }
    }
    Ok(())
}

/// Ignore a signal in a forked supervisor process.
///
/// The namespaced-child supervisor must survive terminal/job-control signals
/// that are also delivered to the runtime parent and workload. The parent
/// forwards the configured stop signal to the workload explicitly.
pub fn ignore_signal(sig: c_int) -> ZResult<()> {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            return Err(last_err("sigaction"));
        }
    }
    Ok(())
}

/// Restore a signal disposition inherited across `fork(2)` to its default.
pub fn reset_signal_default(sig: c_int) -> ZResult<()> {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            return Err(last_err("sigaction"));
        }
    }
    Ok(())
}

/// Ask the kernel to deliver `signal` when this process's parent dies.
///
/// Health monitors are children of a detached reaper rather than part of the
/// container cgroup. Tying their lifetime to the reaper prevents an orphaned
/// monitor from continuing to write state after the owning lifecycle process
/// has crashed.
pub fn set_parent_death_signal(signal: c_int) -> ZResult<()> {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, signal, 0, 0, 0) } != 0 {
        return Err(last_err("prctl(PR_SET_PDEATHSIG)"));
    }
    Ok(())
}

pub fn poll_fds(fds: &mut [libc::pollfd], timeout: c_int) -> ZResult<usize> {
    loop {
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e.into());
        }
        return Ok(n as usize);
    }
}

pub fn write_all_fd(fd: RawFd, data: &[u8]) -> ZResult<()> {
    let mut written = 0;
    while written < data.len() {
        let n = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr() as *const c_void,
                data.len() - written,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e.into());
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "write returned zero bytes",
            )
            .into());
        }
        written += n as usize;
    }
    Ok(())
}

// ---------- seccomp / prctl / capabilities ----------

/// Install a classic-BPF seccomp filter. The filter remains owned by the
/// caller only until this syscall returns; the kernel copies it immediately.
pub fn install_seccomp_filter(filter: &[libc::sock_filter]) -> ZResult<()> {
    if filter.len() > u16::MAX as usize {
        return Err(crate::zerr!("seccomp filter is too large"));
    }
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const libc::sock_filter,
    }
    const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
    let program = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &program as *const SockFprog,
        )
    };
    if rc != 0 {
        return Err(last_err("seccomp(SECCOMP_SET_MODE_FILTER)"));
    }
    Ok(())
}

pub fn prctl_set(option: c_int, arg: libc::c_ulong) -> ZResult<()> {
    if unsafe { libc::prctl(option, arg, 0, 0, 0) } != 0 {
        return Err(last_err("prctl"));
    }
    Ok(())
}

pub fn prctl_drop_cap(cap: c_int) -> ZResult<()> {
    // PR_CAPBSET_DROP
    if unsafe { libc::prctl(24, cap as libc::c_ulong, 0, 0, 0) } != 0 {
        return Err(last_err("PR_CAPBSET_DROP"));
    }
    Ok(())
}

/// Replace the supplementary group list before changing the primary group/UID.
///
/// An empty slice clears every inherited group. Linux rejects lists larger than
/// `NGROUPS_MAX`; reject them here before allocating the C-layout copy.
pub fn set_supplementary_groups(groups: &[u32]) -> ZResult<()> {
    const NGROUPS_MAX: usize = 65_536;
    if groups.len() > NGROUPS_MAX {
        return Err(crate::zerr!(
            "too many supplementary groups ({}, maximum {NGROUPS_MAX})",
            groups.len()
        ));
    }
    let groups = groups
        .iter()
        .map(|group| {
            libc::gid_t::try_from(*group)
                .map_err(|_| crate::zerr!("supplementary group {group} does not fit gid_t"))
        })
        .collect::<ZResult<Vec<_>>>()?;
    let pointer = if groups.is_empty() {
        std::ptr::null()
    } else {
        groups.as_ptr()
    };
    if unsafe { libc::setgroups(groups.len(), pointer) } != 0 {
        return Err(last_err("setgroups"));
    }
    Ok(())
}

/// Set the effective and saved group identity for the workload.
pub fn set_gid(gid: u32) -> ZResult<()> {
    if unsafe { libc::setgid(gid as libc::gid_t) } != 0 {
        return Err(last_err("setgid"));
    }
    Ok(())
}

/// Set the effective and saved user identity for the workload.
pub fn set_uid(uid: u32) -> ZResult<()> {
    if unsafe { libc::setuid(uid as libc::uid_t) } != 0 {
        return Err(last_err("setuid"));
    }
    Ok(())
}

/// Set effective, permitted, and inheritable capabilities using the Linux
/// v3 capability ABI.
pub fn set_capabilities(low: u32, high: u32) -> ZResult<()> {
    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let header = CapUserHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let mut data = [
        CapUserData {
            effective: low,
            permitted: low,
            inheritable: low,
        },
        CapUserData {
            effective: high,
            permitted: high,
            inheritable: high,
        },
    ];
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_mut_ptr()) } != 0 {
        return Err(last_err("capset"));
    }
    Ok(())
}

pub fn cap_last_cap() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(40)
}

// ---------- processes / pipes ----------

pub fn fork_process() -> ZResult<libc::pid_t> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(last_err("fork"));
    }
    Ok(pid)
}

/// Parent PID as observed by the kernel (`getppid(2)`).
pub fn parent_process_id() -> libc::pid_t {
    unsafe { libc::getppid() }
}

/// Put this process in a new process group led by its own PID.
///
/// The captured health-probe path uses a separate group so timeout cleanup can
/// terminate the probe and any ordinary descendants it spawned.
pub fn set_process_group() -> ZResult<()> {
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(last_err("setpgid"));
    }
    Ok(())
}

/// Create new namespaces for this process without changing its PID-namespace
/// membership. A subsequent fork enters the requested PID namespace; all other
/// namespace types apply to the caller immediately and are inherited by that
/// child.
pub fn unshare_namespaces(flags: c_int) -> ZResult<()> {
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(last_err("unshare"));
    }
    Ok(())
}

/// Close every file descriptor greater than or equal to `first`.
///
/// The long-lived namespaced-child supervisor uses this after its worker fork
/// so lifecycle locks and pipes inherited from a multithreaded parent do not
/// stay open until the workload exits.
pub fn close_fds_from(first: RawFd) -> ZResult<()> {
    if first < 0 {
        return Err(crate::zerr!("invalid close_range start fd {first}"));
    }
    if unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0) } == 0 {
        return Ok(());
    }
    // Fall back for old kernels, architecture-specific syscall gaps, and
    // seccomp policies that reject close_range(2). The supervisor depends on
    // releasing inherited lifecycle locks even when that syscall is blocked.
    // close(2) ignores EBADF and is bounded by the process descriptor limit.
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max = if max > 0 { max } else { 65_536 };
    for fd in first..max as RawFd {
        unsafe {
            libc::close(fd);
        }
    }
    Ok(())
}

pub fn pipe2_cloexec() -> ZResult<(RawFd, RawFd)> {
    // Blocking pipe: the parent treats read()==EOF as "child reached execve"
    // (the write end carries O_CLOEXEC, so the kernel closes it on successful
    // exec). Error messages are far below the pipe capacity, so no deadlock.
    let mut fds = [0 as c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(last_err("pipe2"));
    }
    Ok((fds[0], fds[1]))
}

/// Owned pair of CLOEXEC pipe descriptors.
///
/// Callers that fork pass the raw descriptor numbers to the child but retain
/// this owner in the parent. Each fork gets an independent descriptor table, so
/// dropping the parent owner does not close the child's copies. Explicit
/// `close_*` methods consume an endpoint safely and avoid the double-close risk
/// of calling `close(2)` while the owner still holds the same number.
#[must_use]
pub struct Pipe {
    read: Option<OwnedFd>,
    write: Option<OwnedFd>,
}

impl Pipe {
    pub fn new() -> ZResult<Self> {
        let (read, write) = pipe2_cloexec()?;
        Ok(Self {
            read: Some(unsafe { OwnedFd::from_raw_fd(read) }),
            write: Some(unsafe { OwnedFd::from_raw_fd(write) }),
        })
    }

    pub fn read_fd(&self) -> RawFd {
        self.read.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }

    pub fn write_fd(&self) -> RawFd {
        self.write.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }

    pub fn close_read(&mut self) {
        drop(self.read.take());
    }

    pub fn close_write(&mut self) {
        drop(self.write.take());
    }

    /// Move the read descriptor into a worker owner (for example a drain
    /// thread) while leaving the write descriptor under the caller's control.
    pub fn take_read(&mut self) -> Option<OwnedFd> {
        self.read.take()
    }
}

pub fn close(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

/// Terminate the current process immediately without running Rust destructors.
/// This is required in forked children that must not unwind through inherited
/// parent state or flush buffers a second time.
pub fn exit_process(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

/// Wait for a child, retrying when the call is interrupted by a signal.
///
/// `None` is returned only for a non-blocking wait (`WNOHANG`) when no child
/// has changed state yet. The returned status is intentionally kept inside the
/// syscall layer so callers do not need to touch `waitpid(2)` directly.
pub fn wait_pid(pid: libc::pid_t, options: c_int) -> ZResult<Option<(libc::pid_t, c_int)>> {
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, options) };
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error.into());
        }
        if waited == 0 {
            return Ok(None);
        }
        return Ok(Some((waited, status)));
    }
}

/// Convert a wait status to the conventional shell exit code.
pub fn wait_status_code(status: c_int) -> Option<i32> {
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status))
    } else {
        None
    }
}

/// Enter the namespace referred to by an open namespace descriptor.
pub fn setns(fd: RawFd, flags: c_int) -> ZResult<()> {
    if unsafe { libc::setns(fd, flags) } != 0 {
        return Err(last_err("setns"));
    }
    Ok(())
}

/// Clone the mount containing `path` into a detached mount fd.
///
/// This is used for explicit host namespace sharing: the source mount can be
/// captured before pivot_root and attached later without relying on a path in
/// the old root that will be detached.
pub fn open_tree_clone<P: AsRef<Path>>(path: P) -> ZResult<OwnedFd> {
    let path = cpath(path.as_ref())?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last_err("open_tree"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Attach the detached mount referred to by `fd` at `target`.
pub fn move_mount<P: AsRef<Path>>(fd: RawFd, target: P) -> ZResult<()> {
    let target = cpath(target.as_ref())?;
    let empty = c"";
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            fd,
            empty.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if rc != 0 {
        return Err(last_err(&format!(
            "move_mount -> {}",
            target.to_string_lossy()
        )));
    }
    Ok(())
}

/// Make this process the reaper for orphaned descendants.
///
/// The runtime parent uses this to sweep container descendants after a
/// `--pid host` workload exits. mini-init is normally PID 1 and already
/// inherits that role; under host PID sharing it is an ordinary process, so it
/// opts in explicitly to preserve the same `--init` behavior.
pub fn become_child_subreaper() -> ZResult<()> {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(last_err("PR_SET_CHILD_SUBREAPER"));
    }
    Ok(())
}

/// Open a stable handle for a process. Unlike a bare PID, a pidfd continues
/// to refer to the same process even if the numeric PID is later reused.
pub fn pidfd_open(pid: libc::pid_t) -> ZResult<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(last_err("pidfd_open"));
    }
    // The kernel returned a newly-owned descriptor on success.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Open a stable process handle when the target may already have exited.
///
/// Launch cleanup runs concurrently with a short-lived worker. `ESRCH` means
/// the worker is gone and there is no process identity left to pin.
pub fn pidfd_open_if_exists(pid: libc::pid_t) -> ZResult<Option<OwnedFd>> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd >= 0 {
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd as RawFd) }));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(None);
    }
    Err(error.into())
}

/// Send a signal through a pidfd, avoiding PID-reuse races between checking
/// liveness and delivering a lifecycle signal.
pub fn pidfd_send_signal(pidfd: RawFd, signal: c_int) -> ZResult<()> {
    send_signal_to_pidfd(pidfd, signal, false)
}

/// Send a signal through a pidfd when the target may already have exited.
///
/// `ESRCH` is a successful outcome for launch and process-tree cleanup because
/// the pinned process is already gone.
pub fn pidfd_send_signal_if_exists(pidfd: RawFd, signal: c_int) -> ZResult<()> {
    send_signal_to_pidfd(pidfd, signal, true)
}

fn send_signal_to_pidfd(pidfd: RawFd, signal: c_int, ignore_esrch: bool) -> ZResult<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        if ignore_esrch && error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(error.into());
    }
    Ok(())
}

/// Send a signal by numeric PID for legacy state records that predate
/// persisted process identity metadata. New lifecycle paths use pidfds.
pub fn kill(pid: libc::pid_t, signal: c_int) -> ZResult<()> {
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(last_err("kill"));
    }
    Ok(())
}

/// Send a signal to a process that may have exited concurrently.
///
/// `ESRCH` is a successful outcome for process-tree cleanup because the target
/// is already gone. Other errors remain visible to the caller.
pub fn kill_if_exists(pid: libc::pid_t, signal: c_int) -> ZResult<()> {
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(error.into())
}

/// Signal a process group, treating an already-empty group as success.
pub fn kill_process_group_if_exists(pgid: libc::pid_t, signal: c_int) -> ZResult<()> {
    if unsafe { libc::kill(-pgid, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(error.into())
}

/// Best-effort signal delivery for an async signal handler.
///
/// The handler must not allocate or format an error, so this intentionally
/// discards the return value. Ordinary lifecycle code should use [`kill`]
/// instead so failures remain visible to the caller.
pub fn signal_process(pid: libc::pid_t, signal: c_int) {
    unsafe {
        libc::kill(pid, signal);
    }
}

/// Duplicate a file descriptor (`new` replaces it and is not CLOEXEC).
pub fn dup2(old: RawFd, new: RawFd) -> ZResult<()> {
    if unsafe { libc::dup2(old, new) } < 0 {
        return Err(last_err("dup2"));
    }
    Ok(())
}

/// Point stdin at /dev/null so a detached container has no controlling CLI.
pub fn redirect_stdin_devnull() -> ZResult<()> {
    let devnull = std::fs::File::open("/dev/null")?;
    dup2(devnull.as_raw_fd(), libc::STDIN_FILENO)
}

/// Redirect all three standard streams to `/dev/null`.
pub fn redirect_stdio_devnull() -> ZResult<()> {
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        dup2(devnull.as_raw_fd(), target)?;
    }
    Ok(())
}

pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> ZResult<isize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue; // interrupted by a signal; retry
            }
            return Err(e.into());
        }
        return Ok(n);
    }
}

/// Probe whether a non-blocking stream socket still has a connected peer.
///
/// `recv(MSG_PEEK)` observes EOF without consuming application data. A socket
/// with no queued data reports `EAGAIN`; that is a live connection, while other
/// errors (for example a reset) are treated as disconnected.
pub fn socket_peer_connected(fd: RawFd) -> bool {
    let mut byte = 0u8;
    loop {
        let n = unsafe {
            libc::recv(
                fd,
                &mut byte as *mut u8 as *mut c_void,
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if n > 0 {
            return true;
        }
        if n == 0 {
            return false;
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return true,
            _ => return false,
        }
    }
}

// ---------- bring loopback up inside a fresh netns ----------

/// libc's ioctl request type differs between Linux libc ABIs. Constants are
/// passed through this target-specific adapter so both GNU and musl builds use
/// the type expected by `libc::ioctl`.
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
#[allow(clippy::unnecessary_cast)]
fn ioctl_request(request: u64) -> libc::Ioctl {
    request as libc::Ioctl
}

#[cfg(target_arch = "arm")]
#[allow(clippy::unnecessary_cast)]
fn ioctl_request(request: u32) -> libc::Ioctl {
    request as libc::Ioctl
}

pub fn bring_loopback_up() -> ZResult<()> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(last_err("socket(AF_INET)"));
        }
        let mut req: libc::ifreq = std::mem::zeroed();
        let name = b"lo\0";
        for (i, b) in name.iter().enumerate() {
            req.ifr_name[i] = *b as libc::c_char;
        }
        if libc::ioctl(sock, ioctl_request(libc::SIOCGIFFLAGS), &mut req) != 0 {
            libc::close(sock);
            return Err(last_err("SIOCGIFFLAGS"));
        }
        let flags = req.ifr_ifru.ifru_flags;
        req.ifr_ifru.ifru_flags = flags | libc::IFF_UP as i16;
        if libc::ioctl(sock, ioctl_request(libc::SIOCSIFFLAGS), &mut req) != 0 {
            libc::close(sock);
            return Err(last_err("SIOCSIFFLAGS"));
        }
        libc::close(sock);
    }
    Ok(())
}

// ---------- small helpers ----------

fn cstring(s: &str) -> ZResult<CString> {
    CString::new(s).map_err(|_| crate::zerr!("invalid C string: {s}"))
}

fn cpath(p: &Path) -> ZResult<CString> {
    CString::new(p.to_string_lossy().as_bytes())
        .map_err(|_| crate::zerr!("invalid path: {}", p.display()))
}

#[allow(dead_code)]
pub fn cstr_to_string(p: *const libc::c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn host_query_wrappers_are_safe_and_sane() {
        let _uid = effective_uid();
        let _gid = effective_gid();
        assert!(pid_exists(std::process::id() as libc::pid_t));
        assert!(!pid_exists(0));
        assert!(!pid_exists(-1));
        assert!(!pid_exists(i32::MAX));
        assert!(clock_ticks_per_second() > 0);
        assert!(host_name().is_some_and(|name| !name.is_empty()));
        assert!(kernel_release().is_some());
        assert!(kernel_machine().is_some());
    }

    #[test]
    fn pidfd_can_open_and_probe_current_process() {
        let pid = std::process::id() as libc::pid_t;
        let pidfd = pidfd_open(pid).expect("pidfd_open should be available on supported Linux");
        pidfd_send_signal(pidfd.as_raw_fd(), 0).expect("pidfd signal 0 should probe the process");
    }

    #[test]
    fn pidfd_open_if_exists_distinguishes_missing_processes() {
        assert!(pidfd_open_if_exists(i32::MAX)
            .expect("a missing process is not a pidfd error")
            .is_none());
    }

    #[test]
    fn owned_pipe_closes_endpoints_without_double_close() {
        let mut pipe = Pipe::new().expect("pipe2 should succeed");
        let read_fd = pipe.read_fd();
        let write_fd = pipe.write_fd();
        assert!(std::path::Path::new(&format!("/proc/self/fd/{read_fd}")).exists());
        assert!(std::path::Path::new(&format!("/proc/self/fd/{write_fd}")).exists());

        pipe.close_read();
        assert_eq!(pipe.read_fd(), -1);
        assert!(!std::path::Path::new(&format!("/proc/self/fd/{read_fd}")).exists());
        assert!(std::path::Path::new(&format!("/proc/self/fd/{write_fd}")).exists());

        pipe.close_write();
        assert_eq!(pipe.write_fd(), -1);
        assert!(!std::path::Path::new(&format!("/proc/self/fd/{write_fd}")).exists());
    }

    #[test]
    fn write_all_fd_writes_the_complete_buffer() {
        let (read_fd, write_fd) = pipe2_cloexec().expect("pipe2 should succeed");
        let reader = unsafe { OwnedFd::from_raw_fd(read_fd) };
        let writer = unsafe { OwnedFd::from_raw_fd(write_fd) };
        let expected = b"zerun syscall write";

        write_all_fd(writer.as_raw_fd(), expected).expect("pipe write should succeed");
        drop(writer);

        let mut reader = std::fs::File::from(reader);
        let mut actual = Vec::new();
        reader
            .read_to_end(&mut actual)
            .expect("pipe read should succeed");
        assert_eq!(actual, expected);
    }

    #[test]
    fn wait_status_decodes_exit_and_signal_results() {
        assert_eq!(wait_status_code(23 << 8), Some(23));
        assert_eq!(wait_status_code(libc::SIGTERM), Some(128 + libc::SIGTERM));
        assert_eq!(wait_status_code((libc::SIGSTOP << 8) | 0x7f), None);
    }

    #[test]
    fn socket_peer_probe_observes_eof_without_consuming_data() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let (mut server, client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        assert!(socket_peer_connected(server.as_raw_fd()));
        (&client).write_all(b"x").unwrap();
        assert!(socket_peer_connected(server.as_raw_fd()));
        let mut byte = [0u8; 1];
        server.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");

        drop(client);
        assert!(!socket_peer_connected(server.as_raw_fd()));
    }
}
