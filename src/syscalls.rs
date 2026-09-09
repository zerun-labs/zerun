//! Kernel interface layer — the single place in the crate allowed to touch raw
//! syscalls. All other modules must use the safe wrappers exported here and must
//! not call libc directly.
use crate::error::{last_err, ZResult};
use libc::{c_int, c_void};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

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

/// Create a character device node (minimal /dev set inside the container).
pub fn mknod_char<P: AsRef<Path>>(
    path: P,
    major: u32,
    minor: u32,
    mode: libc::mode_t,
) -> ZResult<()> {
    let p = cpath(path.as_ref())?;
    let dev = libc::makedev(major, minor);
    let rc = unsafe { libc::mknod(p.as_ptr(), libc::S_IFCHR | mode, dev) };
    if rc != 0 {
        return Err(last_err("mknod"));
    }
    Ok(())
}

pub fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(target: P, link: Q) -> ZResult<()> {
    let t = cpath(target.as_ref())?;
    let l = cpath(link.as_ref())?;
    if unsafe { libc::symlink(t.as_ptr(), l.as_ptr()) } != 0 {
        return Err(last_err("symlink"));
    }
    Ok(())
}

// ---------- terminals / pseudo-terminals ----------

/// Allocate a new host-side PTY pair.
///
/// The master gets CLOEXEC so a container child cannot accidentally inherit the
/// host side across `execve`. The caller must dup2 the slave onto container
/// stdio and close its own slave descriptor after clone.
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
        written += n as usize;
    }
    Ok(())
}

// ---------- prctl / capabilities ----------

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

pub fn cap_last_cap() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(40)
}

// ---------- processes / pipes ----------

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

pub fn close(fd: RawFd) {
    unsafe {
        libc::close(fd);
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

pub fn write_fd(fd: RawFd, data: &[u8]) {
    unsafe {
        libc::write(fd, data.as_ptr() as *const c_void, data.len());
    }
}

// ---------- clone: the only entry point into new namespaces ----------

const CLONE_STACK_SIZE: usize = 8 * 1024 * 1024;
const PAGE_SIZE: usize = 4096;

/// Create a child process with the given clone flags; the child runs `child_fn`.
///
/// New PID/NET/etc. namespaces must be created by a new child process; the caller
/// never enters them itself. The child stack is an anonymous mmap (lazily
/// populated, unlike a zeroed Box array, so debug builds do not overflow the
/// parent stack) with a PROT_NONE guard page below it. The mapping is leaked until
/// process exit — acceptable because CLI processes are short-lived.
pub fn clone_into<F>(flags: c_int, child_fn: F) -> ZResult<i32>
where
    F: FnOnce() -> ZResult<()> + Send + 'static,
{
    let arg = Box::into_raw(Box::new(child_fn)) as *mut c_void;
    let total = CLONE_STACK_SIZE + PAGE_SIZE;
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        unsafe {
            drop(Box::from_raw(arg as *mut F));
        }
        return Err(last_err("mmap clone stack"));
    }
    // Guard page at the bottom of the mapping: a runaway child stack hits
    // SIGSEGV instead of silently corrupting adjacent memory.
    if unsafe { libc::mprotect(base, PAGE_SIZE, libc::PROT_NONE) } != 0 {
        unsafe {
            drop(Box::from_raw(arg as *mut F));
            libc::munmap(base, total);
        }
        return Err(last_err("mprotect clone stack guard"));
    }
    let top = (base as usize + total) as *mut c_void;

    let pid = unsafe { libc::clone(trampoline::<F>, top, flags, arg) };
    if pid < 0 {
        unsafe {
            drop(Box::from_raw(arg as *mut F));
            libc::munmap(base, total);
        }
        return Err(last_err("clone"));
    }
    Ok(pid)
}

extern "C" fn trampoline<F>(arg: *mut c_void) -> c_int
where
    F: FnOnce() -> ZResult<()> + Send,
{
    let f = unsafe { Box::from_raw(arg as *mut F) };
    match f() {
        // Success normally ends in execve and never returns here. Returning here
        // only happens when exec failed; the error has already been reported to
        // the parent over the error pipe. Exit code 1.
        Ok(()) => 0,
        Err(e) => {
            eprintln!("zerun: child failed: {e}");
            1
        }
    }
}

// ---------- bring loopback up inside a fresh netns ----------

/// libc's ioctl request type differs between Linux libc ABIs.
#[cfg(target_env = "musl")]
fn ioctl_request(request: u64) -> libc::Ioctl {
    request as libc::Ioctl
}

#[cfg(not(target_env = "musl"))]
fn ioctl_request(request: u64) -> libc::Ioctl {
    request
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
