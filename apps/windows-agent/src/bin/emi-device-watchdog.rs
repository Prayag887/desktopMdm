fn main() -> anyhow::Result<()> {
    emi_device_agent::protection::logging::initialize("watchdog")?;
    if std::env::args().nth(1).as_deref() != Some("service") {
        anyhow::bail!("Run through Windows Service Control Manager with the service argument");
    }
    emi_device_agent::protection::watchdog::service_entry()
}
