//! A PAC file server on `127.0.0.1`, shared by the native-engine tests.
//!
//! Pulled in with `#[path = "support/pac_server.rs"] mod pac_server;` so that a test binary
//! gets this and not the watcher helpers in `support/mod.rs`.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use proxy_watch::Url;

/// Serves one fixed body on `127.0.0.1` to every request, until dropped.
pub struct PacServer {
    address: SocketAddr,
    /// Tells this server's URL apart from every other one's; see [`PacServer::url`].
    serial: u64,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl PacServer {
    /// Bind an ephemeral loopback port and start serving `body`.
    pub fn start(body: &'static str) -> Self {
        Self::spawn(Some(body))
    }

    /// Bind a port that accepts connections and then says nothing, ever.
    ///
    /// The deterministic way to make a resolution overrun its budget without depending
    /// on how the machine treats an unroutable address.
    pub fn stalling() -> Self {
        Self::spawn(None)
    }

    fn spawn(body: Option<&'static str>) -> Self {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binding a loopback port");
        let address = listener.local_addr().expect("reading the bound port");
        // Non-blocking accept is what lets the thread notice `stop` and exit.
        listener
            .set_nonblocking(true)
            .expect("switching the listener to non-blocking");

        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                // Accepted-but-unanswered sockets, held open so that the peer sees a
                // stall rather than an immediate EOF.
                let mut stalled = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => match body {
                            Some(body) => serve_one(stream, body),
                            None => stalled.push(stream),
                        },
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Self {
            address,
            serial: SERIAL.fetch_add(1, Ordering::Relaxed),
            stop,
            thread: Some(thread),
        }
    }

    /// The URL the engine should download the script from.
    ///
    /// The serial and the process id are in the path because WinHTTP caches a downloaded
    /// script under the URL it came from, and that cache belongs to the autoproxy service
    /// rather than to the session this file opens; dropping a `WinHttpPacResolver` does not
    /// clear it. Every server here binds an ephemeral port, so the OS is free to hand a
    /// later one the port a finished one released. Do not make the path a constant: the URL
    /// then repeats, WinHTTP answers out of the cache without contacting the new server,
    /// and a test reads the previous script's answer as a *wrong success* rather than a
    /// timeout.
    pub fn url(&self) -> Url {
        Url::parse(&format!(
            "http://{}/proxy-{}-{}.pac",
            self.address,
            std::process::id(),
            self.serial
        ))
        .unwrap()
    }
}

/// Source of [`PacServer::serial`]. Unique within the run; the process id in the path
/// covers the rest.
static SERIAL: AtomicU64 = AtomicU64::new(0);

impl Drop for PacServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Read the request headers (and discard them), then write the PAC file back.
fn serve_one(mut stream: TcpStream, body: &str) {
    stream
        .set_nonblocking(false)
        .expect("switching the accepted socket to blocking");
    let mut reader = BufReader::new(stream.try_clone().expect("cloning the accepted socket"));
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/x-ns-proxy-autoconfig\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}
