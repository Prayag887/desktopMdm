//! Atomic state replacement and process-wide serialization for security state.
use anyhow::Context as _;
use fs2::FileExt as _;
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::Path,
};

/// Hold this file open for the entire read/verify/commit transaction.
/// # Errors
/// Returns errors creating or acquiring the lock. Never continues without it.
pub fn lock(directory: &Path, name: &str) -> anyhow::Result<File> {
    fs::create_dir_all(directory)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(name))?;
    file.lock_exclusive().context("lock security state")?;
    Ok(file)
}

/// Replace a JSON document atomically, flushing bytes before publication.
/// `private` removes inherited read access before writing any sensitive bytes.
/// # Errors
/// Returns filesystem or ACL errors without deleting the previous document.
pub fn write_json(path: &Path, value: &impl Serialize, private: bool) -> anyhow::Result<()> {
    let parent = path.parent().context("state file has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(windows)]
    if private {
        use std::os::windows::process::CommandExt as _;
        let status = std::process::Command::new("icacls.exe")
            .arg(temporary.path())
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                "*S-1-5-32-544:F",
            ])
            .creation_flags(0x0800_0000)
            .output()?
            .status;
        anyhow::ensure!(status.success(), "protect private state before writing");
    }
    #[cfg(not(windows))]
    let _ = private; // NamedTempFile is owner-only on Unix.
    temporary.write_all(&serde_json::to_vec_pretty(value)?)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .context("atomically replace state")?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_keeps_previous_document_when_commit_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_json(&path, &1, false).unwrap();
        write_json(&path, &2, false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "2");
        let blocked = dir.path().join("directory");
        fs::create_dir(&blocked).unwrap();
        assert!(write_json(&blocked, &3, false).is_err());
        assert!(blocked.is_dir());
        assert_eq!(fs::read_to_string(path).unwrap(), "2");
    }
}
