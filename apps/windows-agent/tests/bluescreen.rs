use emi_device_agent::bluescreen::BluescreenSession;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpStream},
    time::Duration,
};

fn request(session: &BluescreenSession, method: &str, path: &str, origin: &str) -> String {
    let mut socket = TcpStream::connect(session.address()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(socket, "{method} {path} HTTP/1.1\r\nHost: {}\r\n{origin}Content-Length: 0\r\nConnection: close\r\n\r\n", session.address()).unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn qr_requires_explicit_authorized_post_and_does_not_persist() {
    let session = BluescreenSession::start(Ipv4Addr::LOCALHOST).unwrap();
    assert!(!session.dismissed());
    assert!(request(&session, "GET", session.path(), "").contains("Dismiss simulated blue screen"));
    assert!(!session.dismissed(), "scanner prefetch must not dismiss");
    assert!(request(&session, "GET", session.path(), "").contains("Referrer-Policy: same-origin"));
    assert!(request(&session, "POST", "/wrong", "").contains("404"));
    assert!(
        request(
            &session,
            "POST",
            session.path(),
            "Origin: https://example.com\r\n"
        )
        .contains("403")
    );
    assert!(!session.dismissed());
    let origin = format!(
        "Origin: http://{}\r\nSec-Fetch-Site: same-origin\r\n",
        session.address()
    );
    assert!(request(&session, "POST", session.path(), &origin).contains("Simulation dismissed"));
    assert!(session.dismissed());
    assert!(request(&session, "POST", session.path(), "").contains("410 Gone"));
    let address = session.address();
    drop(session);
    assert!(TcpStream::connect(address).is_err());
    let restarted = BluescreenSession::start(Ipv4Addr::LOCALHOST).unwrap();
    assert!(!restarted.dismissed());
}

#[test]
fn private_interface_and_slow_client_shutdown_are_bounded() {
    assert!(BluescreenSession::start(Ipv4Addr::new(8, 8, 8, 8)).is_err());
    let session = BluescreenSession::start(Ipv4Addr::LOCALHOST).unwrap();
    let mut socket = TcpStream::connect(session.address()).unwrap();
    socket.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    let start = std::time::Instant::now();
    drop(session);
    assert!(start.elapsed() < Duration::from_secs(2));
}
