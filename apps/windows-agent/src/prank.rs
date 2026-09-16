//! A reversible, memory-only simulation. No OS crash, persistence or privileged actions.
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const MAX_DURATION: Duration = Duration::from_secs(300);

pub struct PrankSession {
    address: SocketAddr,
    path: String,
    dismissed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    started: Instant,
}

impl PrankSession {
    /// Bind one explicitly chosen private/loopback interface, never all interfaces.
    /// The narrow HTTP endpoint accepts no body and handles one bounded connection at a time.
    ///
    /// # Errors
    /// Returns an error for public addresses or an unavailable interface.
    pub fn start(ip: Ipv4Addr) -> io::Result<Self> {
        if !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Choose this PC's private LAN IPv4 address",
            ));
        }
        let listener = TcpListener::bind((ip, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let path = format!("/dismiss/{}", Uuid::new_v4().simple());
        let dismissed = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let done = Arc::clone(&dismissed);
        let stopping = Arc::clone(&stop);
        let route = path.clone();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) && started.elapsed() < MAX_DURATION {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let _ = serve(socket, address, &route, &done, &stopping);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            path,
            dismissed,
            stop,
            worker: Some(worker),
            started,
        })
    }

    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}{}", self.address, self.path)
    }
    #[must_use]
    pub fn dismissed(&self) -> bool {
        self.dismissed.load(Ordering::Acquire)
    }
    #[must_use]
    pub fn expired(&self) -> bool {
        self.started.elapsed() >= MAX_DURATION
    }
}

impl Drop for PrankSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_headers(socket: &mut TcpStream, stop: &AtomicBool) -> io::Result<Option<String>> {
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut bytes = Vec::with_capacity(8192);
    let mut chunk = [0; 512];
    while !bytes.ends_with(b"\r\n\r\n") {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline || bytes.len() >= 8192 {
            return Ok(None);
        }
        let limit = chunk.len().min(8192 - bytes.len());
        match socket.read(&mut chunk[..limit]) {
            Ok(0) => return Ok(None),
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(String::from_utf8(bytes).ok())
}

fn serve(
    mut socket: TcpStream,
    address: SocketAddr,
    path: &str,
    done: &AtomicBool,
    stop: &AtomicBool,
) -> io::Result<()> {
    socket.set_write_timeout(Some(Duration::from_millis(100)))?;
    // Deliberately not a general HTTP server: ASCII headers only, 8 KiB total,
    // one-second absolute deadline, no body, no keep-alive, no worker per client.
    let Some(headers) = read_headers(&mut socket, stop)? else {
        return Ok(());
    };
    let mut lines = headers.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let expected_host = address.to_string();
    let expected_origin = format!("http://{address}");
    let mut host_count = 0;
    let mut valid = true;
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((key, value)) = line.split_once(':') else {
            valid = false;
            continue;
        };
        let value = value.trim();
        if key.eq_ignore_ascii_case("host") {
            host_count += 1;
            valid &= value == expected_host;
        }
        if key.eq_ignore_ascii_case("origin") {
            valid &= value == expected_origin;
        }
        if key.eq_ignore_ascii_case("content-length") {
            valid &= value == "0";
        }
        if key.eq_ignore_ascii_case("transfer-encoding") {
            valid = false;
        }
        if key.eq_ignore_ascii_case("sec-fetch-site") {
            valid &= value != "cross-site";
        }
    }
    let get = first == format!("GET {path} HTTP/1.1");
    let post = first == format!("POST {path} HTTP/1.1");
    let (status, body) = if !valid || host_count != 1 {
        (
            "403 Forbidden",
            page(
                "Request refused",
                "Open the original QR link on this network.",
                "",
            ),
        )
    } else if !get && !post {
        (
            "404 Not Found",
            page("Link not found", "Scan the current QR code.", ""),
        )
    } else if done.load(Ordering::Acquire) {
        (
            "410 Gone",
            page(
                "Simulation already dismissed",
                "This one-time link is no longer active.",
                "",
            ),
        )
    } else if post {
        done.store(true, Ordering::Release);
        (
            "200 OK",
            page(
                "Simulation dismissed",
                "The PC will return to its desktop app. No restart is needed.",
                "",
            ),
        )
    } else {
        (
            "200 OK",
            page(
                "It's only a simulation.",
                "Windows has not crashed. Tap below to dismiss the blue screen on the PC.",
                &format!(
                    "<form method=\"post\" action=\"{path}\"><button>Dismiss simulated blue screen</button></form>"
                ),
            ),
        )
    };
    write!(
        socket,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: same-origin\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n\r\n{body}",
        body.len()
    )
}

fn page(title: &str, description: &str, action: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>body{{margin:0;background:#081a35;color:#edf5ff;font:17px/1.6 system-ui,sans-serif;min-height:100vh;display:grid;place-items:center}}main{{width:min(440px,calc(100% - 64px));padding:32px 0}}small{{color:#8fbaff;letter-spacing:.15em}}h1{{font-size:36px;line-height:1.15}}p{{color:#c4d2e6}}button{{font:inherit;font-weight:650;border:0;border-radius:12px;background:#8fc6ff;color:#071a34;padding:16px 20px;width:100%;cursor:pointer}}button:focus-visible{{outline:3px solid white;outline-offset:5px}}footer{{margin-top:32px;font-size:14px;color:#95aac6}}</style><main><small>EMI DEVICE · PRANK MODE</small><h1>{title}</h1><p>{description}</p>{action}<footer>Temporary, one-time link. Escape on the PC or a reboot also ends the simulation.</footer></main></html>"#
    )
}
