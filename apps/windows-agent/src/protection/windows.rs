//! Fixed Windows helpers. No shell search path, caller-supplied commands or unlimited waits.
use anyhow::{Context, bail};
use std::{
    io::{Read, Seek},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Run a fixed Windows query with a deadline and bounded output.
///
/// # Errors
/// Returns an error for non-Windows hosts, process failures or query timeouts.
pub fn powershell(script: &str, arguments: &[&std::ffi::OsStr]) -> anyhow::Result<Vec<u8>> {
    powershell_with_timeout(script, arguments, Duration::from_secs(90))
}

/// Run a trusted long operation with its own bounded deadline.
///
/// # Errors
/// Returns an error for failed Windows execution or an expired deadline.
pub fn powershell_with_timeout(
    script: &str,
    arguments: &[&std::ffi::OsStr],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    if !cfg!(windows) {
        bail!("Windows protection is unsupported on this platform");
    }
    let root = std::env::var_os("SystemRoot").context("SystemRoot missing")?;
    let executable = Path::new(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let output = tempfile::tempfile()?;
    let mut command = Command::new(executable);
    let script = format!("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); {script}");
    command
        .current_dir(Path::new(&root).join("System32"))
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("Windows protection helper failed ({status}); consult Windows event logs");
            }
            let mut output = output;
            output.rewind()?;
            let mut bytes = Vec::new();
            output.take(2 * 1024 * 1024).read_to_end(&mut bytes)?;
            return Ok(bytes);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            bail!("Windows protection helper exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[must_use]
pub fn quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
}

/// Execute a previously verified installed protection script.
///
/// # Errors
/// Returns an error when the Windows helper fails or times out.
pub fn invoke_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    powershell(
        &format!("$ErrorActionPreference='Stop'; & {}", quote(path)),
        &[],
    )
}
