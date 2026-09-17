//! Local preview of the exact phone page; no fullscreen or firmware actions.
use emi_device_agent::bluescreen::BluescreenSession;
use std::{net::Ipv4Addr, thread, time::Duration};

fn main() -> std::io::Result<()> {
    let session = BluescreenSession::start(Ipv4Addr::LOCALHOST)?;
    println!("{}", session.url());
    while !session.dismissed() && !session.expired() {
        thread::sleep(Duration::from_millis(100));
    }
    // Leave the response page available briefly for preview inspection.
    thread::sleep(Duration::from_secs(2));
    Ok(())
}
