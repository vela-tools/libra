//! An HTTP notification callback receiver for subscription testing.
//!
//! Subscriptions configure a notification endpoint (`notification.endpoint.uri`) that the context
//! broker calls directly via HTTP POST when matching entities change. Because notifications travel
//! broker -> callback receiver without passing back through Libra, this receiver captures the raw
//! payload emitted by the broker so tests can verify whether narrowed restrictions prevented leaks.

use serde_json::Value;
use std::{
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        Condvar,
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{JoinHandle, sleep, spawn},
    time::{Duration, Instant},
};

/// How long a connection is given to deliver an HTTP request before abandoning it.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// An HTTP server listening on all interfaces that records incoming notification payloads.
pub struct NotificationSink {
    port: u16,
    running: Arc<AtomicBool>,
    state: Arc<(Mutex<Vec<Value>>, Condvar)>,
    listening: Option<JoinHandle<()>>,
}

impl NotificationSink {
    /// Starts a notification sink listening on an ephemeral port on `0.0.0.0`.
    ///
    /// Binding `0.0.0.0` allows Docker containers (such as the context broker) to reach this
    /// host process via `host.docker.internal`.
    ///
    /// # Panics
    ///
    /// Panics if binding to `0.0.0.0:0` fails.
    pub fn start() -> Self {
        let listener = TcpListener::bind("0.0.0.0:0").expect("an ephemeral port should be bindable on 0.0.0.0");
        let port = listener.local_addr().expect("bound address must be readable").port();
        listener.set_nonblocking(true).expect("listener should accept non-blocking");

        let running = Arc::new(AtomicBool::new(true));
        let state = Arc::new((Mutex::new(Vec::new()), Condvar::new()));

        let listening = spawn({
            let running = Arc::clone(&running);
            let state = Arc::clone(&state);
            move || accept_loop(&listener, &running, &state)
        });

        Self {
            port,
            running,
            state,
            listening: Some(listening),
        }
    }

    /// The notification callback URI reachable by the broker container.
    pub fn endpoint_uri(&self) -> String {
        format!("http://host.docker.internal:{}/notify", self.port)
    }

    /// Waits up to `timeout` for a notification to arrive, returning the earliest unconsumed payload.
    pub fn wait_for_notification(&self, timeout: Duration) -> Option<Value> {
        let (lock, cvar) = &*self.state;
        let mut guard = lock.lock().ok()?;
        let deadline = Instant::now() + timeout;

        while guard.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline - now;
            let (next_guard, result) = cvar.wait_timeout(guard, remaining).ok()?;
            guard = next_guard;
            if result.timed_out() && guard.is_empty() {
                return None;
            }
        }

        if guard.is_empty() { None } else { Some(guard.remove(0)) }
    }
}

impl Drop for NotificationSink {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(listening) = self.listening.take() {
            let _ = listening.join();
        }
    }
}

/// Accept loop running in the background thread until stopped.
fn accept_loop(listener: &TcpListener, running: &Arc<AtomicBool>, state: &Arc<(Mutex<Vec<Value>>, Condvar)>) {
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(payload) = handle_connection(stream)
                    && let Ok(mut guard) = state.0.lock()
                {
                    guard.push(payload);
                    state.1.notify_all();
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => sleep(Duration::from_millis(5)),
            Err(_) => return,
        }
    }
}

/// Reads one HTTP POST request, parses the JSON payload, and writes back a 200 OK.
fn handle_connection(mut stream: TcpStream) -> Option<Value> {
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).ok()?;

    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }

    let mut body_bytes = vec![0u8; content_length];
    reader.read_exact(&mut body_bytes).ok()?;

    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();

    serde_json::from_slice(&body_bytes).ok()
}
