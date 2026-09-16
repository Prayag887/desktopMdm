use emi_device_agent::prank::PrankSession;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpStream},
    time::Duration,
};

fn request(session: &PrankSession, method: &str, path: &str, origin: &str) -> String {
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
    let session = PrankSession::start(Ipv4Addr::LOCALHOST).unwrap();
    assert!(!session.dismissed());
    assert!(request(&session, "GET", session.path(), "").contains("Dismiss simulated blue screen"));
    assert!(!session.dismissed(), "scanner prefetch must not dismiss");
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
    assert!(request(&session, "POST", session.path(), "").contains("Simulation dismissed"));
    assert!(session.dismissed());
    let address = session.address();
    drop(session);
    assert!(TcpStream::connect(address).is_err());
    let restarted = PrankSession::start(Ipv4Addr::LOCALHOST).unwrap();
    assert!(!restarted.dismissed());
}
