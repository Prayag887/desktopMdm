//! Size-bounded, structured service logs: five 2 MiB files per process.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::Mutex,
};
struct RotatingLog {
    path: PathBuf,
    file: File,
    length: u64,
}
impl Write for RotatingLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.length + bytes.len() as u64 > 2 * 1024 * 1024 {
            let _ = fs::remove_file(self.path.with_extension("jsonl.4"));
            for index in (1..4).rev() {
                let old = self.path.with_extension(format!("jsonl.{index}"));
                if old.exists() {
                    fs::rename(
                        old,
                        self.path.with_extension(format!("jsonl.{}", index + 1)),
                    )?;
                }
            }
            // Windows cannot rename an open file: close it first by swapping a temporary handle.
            let placeholder = tempfile::tempfile()?;
            drop(std::mem::replace(&mut self.file, placeholder));
            fs::rename(&self.path, self.path.with_extension("jsonl.1"))?;
            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            self.length = 0;
        }
        let count = self.file.write(bytes)?;
        self.length += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Initialize bounded JSON logs for a service process.
///
/// # Errors
/// Returns an error if logs cannot be opened or a subscriber is already installed.
pub fn initialize(component: &str) -> anyhow::Result<()> {
    if cfg!(windows) {
        let state = PathBuf::from(
            std::env::var_os("PROGRAMDATA")
                .ok_or_else(|| anyhow::anyhow!("ProgramData missing"))?,
        )
        .join("EmiDeviceAgent");
        let path = state.join(format!("{component}.jsonl"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let length = file.metadata()?.len();
        let writer = Mutex::new(RotatingLog { path, file, length });
        tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
            .with_writer(writer)
            .try_init()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_keeps_only_five_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("core.jsonl");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let mut log = RotatingLog {
            path: path.clone(),
            file,
            length: 0,
        };
        let event = vec![b'x'; 1024 * 1024];
        for _ in 0..16 {
            log.write_all(&event).unwrap();
        }
        log.flush().unwrap();
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 5);
        assert!(!path.with_extension("jsonl.5").exists());
        for entry in fs::read_dir(directory.path()).unwrap() {
            assert!(entry.unwrap().metadata().unwrap().len() <= 2 * 1024 * 1024);
        }
    }
}
