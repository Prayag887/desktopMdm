fn main() -> anyhow::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 3 || arguments[0] != "repair" {
        anyhow::bail!("Usage: emi-device-updater repair <installation> <trusted-package>");
    }
    emi_device_agent::protection::logging::initialize("updater")?;
    emi_device_agent::protection::repair::run(
        std::path::Path::new(&arguments[1]),
        std::path::Path::new(&arguments[2]),
    )
}
