use std::{
    env,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--health-check")) {
        return health_check();
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let state = emi_control_plane::state_from_env().await?;
    let address: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "control plane listening");
    axum::serve(listener, emi_control_plane::app(state))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn health_check() -> anyhow::Result<()> {
    let address = env::var("HEALTHCHECK_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let address: SocketAddr = address.parse()?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = [0_u8; 12];
    stream.read_exact(&mut response)?;
    anyhow::ensure!(&response == b"HTTP/1.1 200", "control plane is unhealthy");
    Ok(())
}
