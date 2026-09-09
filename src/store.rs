//! Filesystem state layout (daemonless: everything is on disk, no in-memory
//! cross-process state).
//!
//! Rootful (euid == 0):  data /var/lib/zerun, run  /run/zerun
//! Rootless:             data $XDG_DATA_HOME/zerun (~/.local/share/zerun),
//!                       run  $XDG_RUNTIME_DIR/zerun (/run/user/<uid>/zerun)
//!
//! Both roots can be overridden with ZERUN_DATA_ROOT / ZERUN_RUNTIME_ROOT
//! (used by tests and power users).
use crate::error::ZResult;
use crate::fsutil;
use std::path::{Path, PathBuf};

/// Runtime/data directory pair for the current invocation.
#[derive(Debug, Clone)]
pub struct Store {
    data_root: PathBuf,
    run_root: PathBuf,
}

/// Per-run writable container filesystem under <data>/overlays/<id>.
#[derive(Debug)]
pub struct ContainerFs {
    /// Lower (read-only image/rootfs) directory.
    pub lower: PathBuf,
    /// Overlay upperdir (container writes land here).
    pub upper: PathBuf,
    /// Overlay workdir (kernel-internal).
    pub work: PathBuf,
    /// Overlay mount point / final root path.
    pub merged: PathBuf,
    /// True when upper/work/merged live on a per-run tmpfs.
    pub tmpfs_upper: bool,
    dir: PathBuf,
}

impl Store {
    /// Resolve the store roots for this process (env override > uid-based default).
    pub fn detect() -> ZResult<Self> {
        let data_root = match std::env::var_os("ZERUN_DATA_ROOT") {
            Some(v) => PathBuf::from(v),
            None if unsafe { libc::geteuid() } == 0 => PathBuf::from("/var/lib/zerun"),
            None => xdg_data_home()?.join("zerun"),
        };
        let run_root = match std::env::var_os("ZERUN_RUNTIME_ROOT") {
            Some(v) => PathBuf::from(v),
            None if unsafe { libc::geteuid() } == 0 => PathBuf::from("/run/zerun"),
            None => xdg_runtime_dir()?.join("zerun"),
        };
        Ok(Store {
            data_root,
            run_root,
        })
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    pub fn run_root(&self) -> &Path {
        &self.run_root
    }

    /// Create the top-level layout.
    pub fn ensure_dirs(&self) -> ZResult<()> {
        for d in [
            self.data_root.join("overlays"),
            self.data_root.join("tmp"),
            self.run_root.join("containers"),
            self.run_root.join("net"), // file-based IPAM (M5)
        ] {
            fsutil::mkdir_p(&d)?;
        }
        Ok(())
    }

    /// Prepare a per-run writable container filesystem (overlay dirs).
    pub fn prepare_container_fs(
        &self,
        id: &str,
        lower: &Path,
        tmpfs_upper: bool,
    ) -> ZResult<ContainerFs> {
        let dir = self.data_root.join("overlays").join(id);
        let upper = dir.join("upper");
        let work = dir.join("work");
        let merged = dir.join("merged");
        for d in [&upper, &work, &merged] {
            fsutil::mkdir_p(d)?;
        }
        let lower_abs = absolute(lower)?;
        Ok(ContainerFs {
            lower: lower_abs,
            upper,
            work,
            merged,
            tmpfs_upper,
            dir,
        })
    }

    /// Remove the per-run filesystem after the container exits.
    pub fn cleanup_container_fs(&self, fs: &ContainerFs) {
        fsutil::remove_dir_all_quiet(&fs.dir);
    }
}

impl ContainerFs {
    /// Path the child should pivot into (the overlay mount point).
    pub fn root(&self) -> &Path {
        &self.merged
    }

    /// The per-run directory holding upper/work/merged (what `rm` deletes).
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

fn xdg_data_home() -> ZResult<PathBuf> {
    if let Some(v) = std::env::var_os("XDG_DATA_HOME") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let home = std::env::var_os("HOME").ok_or_else(|| crate::zerr!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".local/share"))
}

fn xdg_runtime_dir() -> ZResult<PathBuf> {
    if let Some(v) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let uid = unsafe { libc::geteuid() };
    Ok(PathBuf::from(format!("/run/user/{uid}")))
}

fn absolute(p: &Path) -> ZResult<PathBuf> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|c| c.join(p))
            .map_err(|e| crate::zerr!("current_dir: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins() {
        std::env::set_var("ZERUN_DATA_ROOT", "/tmp/zerun-test-store");
        std::env::set_var("ZERUN_RUNTIME_ROOT", "/tmp/zerun-test-run");
        let s = Store::detect().unwrap();
        assert_eq!(s.data_root(), Path::new("/tmp/zerun-test-store"));
        assert_eq!(s.run_root(), Path::new("/tmp/zerun-test-run"));
        std::env::remove_var("ZERUN_DATA_ROOT");
        std::env::remove_var("ZERUN_RUNTIME_ROOT");
    }
}
