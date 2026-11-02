//! An HTTP origin the test controls, on a port of its own.
//!
//! Three things need one. Header behaviour (what Libra injects, what it strips, what it refuses to
//! forward) can only be observed from whatever the proxy talks to, and a broker will not report
//! the headers it was sent. Term expansion needs a context document at a URL the proxy is willing
//! to fetch, without depending on the network. And the suite's issuer publishes its signing keys
//! somewhere the proxy fetches them from.
//!
//! So this is a recorder: it answers every request with the same canned response and keeps what it
//! was asked, and it is deliberately the smallest thing that can do so rather than a second server
//! framework inside the test suite.

use std::{
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{JoinHandle, sleep, spawn},
    time::Duration,
};
use url::Url;

/// A URL written in a test.
///
/// # Panics
///
/// Panics if `text` is not a URL, which is a mistake in the test.
#[must_use]
pub fn address(text: &str) -> Url {
    Url::parse(text).expect("the address written in the test should be a URL")
}

/// How long a connection is given to deliver a request before it is abandoned.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// One request this origin was sent.
pub struct Recorded {
    /// The request method, as written on the request line.
    pub method: String,
    /// The request target, path and query together.
    pub target: String,
    /// Every header, in arrival order, with lowercase names.
    pub headers: Vec<(String, String)>,
    /// The request body, as sent, decoded lossily. Empty when the request carried none. This is
    /// what proves whether Libra rewrote a forwarded body or passed it through untouched.
    pub body: String,
}

impl Recorded {
    /// The first value of `name`, if the request carried it.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();

        self.headers.iter().find(|(header, _)| *header == name).map(|(_, value)| value.as_str())
    }
}

/// The response an [`Origin`] returns to every request it is sent.
///
/// A broker stand-in exists to make the *shape* of an answer observable: a status the real broker
/// would rarely produce, a body of a media type it should not send, an encoding the filter cannot
/// walk. [`Origin::serving`] covers the ordinary success case; this covers the rest.
pub struct CannedResponse {
    /// The numeric status code written on the status line.
    pub status: u16,
    /// The `Content-Type` the body is served under.
    pub content_type: String,
    /// The `Content-Encoding` to claim, when the response should carry one. Most carry none.
    pub content_encoding: Option<String>,
    /// The body, sent verbatim.
    pub body: String,
}

impl CannedResponse {
    /// A `200 OK` under `content_type` with no encoding, which is what most tests want.
    #[must_use]
    pub fn ok(content_type: &str, body: &str) -> Self {
        Self {
            status: 200,
            content_type: content_type.to_owned(),
            content_encoding: None,
            body: body.to_owned(),
        }
    }
}

/// A running origin, stopped when the test that started it ends.
pub struct Origin {
    url: String,
    recorded: Arc<Mutex<Vec<Recorded>>>,
    running: Arc<AtomicBool>,
    response: Arc<Mutex<String>>,
    listening: Option<JoinHandle<()>>,
}

impl Origin {
    /// Starts an origin that answers everything with `body` under `content_type`, as `200 OK`.
    ///
    /// # Panics
    ///
    /// Panics if no port can be bound.
    #[must_use]
    pub fn serving(content_type: &str, body: &str) -> Self {
        Self::replying(&CannedResponse::ok(content_type, body))
    }

    /// Starts an origin that answers everything with `canned`, whatever status, media type and
    /// encoding it names.
    ///
    /// # Panics
    ///
    /// Panics if no port can be bound.
    #[must_use]
    pub fn replying(canned: &CannedResponse) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port should be bindable");
        let port = listener.local_addr().expect("the bound address should be readable").port();
        listener.set_nonblocking(true).expect("the listener should accept without blocking");

        let recorded = Arc::new(Mutex::new(Vec::new()));
        let running = Arc::new(AtomicBool::new(true));
        let response = Arc::new(Mutex::new(response(canned)));
        let listening = spawn({
            let recorded = Arc::clone(&recorded);
            let running = Arc::clone(&running);
            let response = Arc::clone(&response);
            move || accept_until_stopped(&listener, &recorded, &running, &response)
        });

        Self {
            url: format!("http://127.0.0.1:{port}"),
            recorded,
            running,
            response,
            listening: Some(listening),
        }
    }

    /// Replaces what this origin answers with, from the next request onward.
    ///
    /// A rotation test serves one key set, starts the proxy against it, then swaps in another so
    /// the proxy's next refresh picks it up. Nothing else needs a running origin to change its
    /// answer, so this exists only for that.
    ///
    /// # Panics
    ///
    /// Panics if the response lock is poisoned, which only happens if a serving thread panicked.
    pub fn set_response(&self, canned: &CannedResponse) {
        *self.response.lock().expect("the response lock should not be poisoned") = response(canned);
    }

    /// Where this origin is, as text to build further addresses from.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// An absolute path on this origin, as the proxy is configured to reach it.
    ///
    /// # Panics
    ///
    /// Panics if `path` does not make a URL, which is a mistake in the test.
    #[must_use]
    pub fn endpoint(&self, path: &str) -> Url {
        address(&format!("{}{path}", self.url))
    }

    /// Where this origin is, as the proxy is configured to reach it.
    ///
    /// # Panics
    ///
    /// Panics if the origin's address is not a URL, which it always is.
    #[must_use]
    pub fn address(&self) -> Url {
        address(&self.url)
    }

    /// The last request this origin was sent, if it was sent one.
    ///
    /// # Panics
    ///
    /// Panics if the recording thread panicked while holding the lock.
    #[must_use]
    pub fn last_request(&self) -> Option<Recorded> {
        self.recorded.lock().expect("the recording lock should not be poisoned").pop()
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(listening) = self.listening.take() {
            let _ = listening.join();
        }
    }
}

/// The canned response, rendered once.
///
/// `Connection: close` keeps the loop below to one request per connection, which is what makes a
/// single-threaded accept loop sufficient. The reason phrase is cosmetic (an HTTP client reads the
/// numeric code), so an unknown status falls back to a generic one rather than failing to render.
fn response(canned: &CannedResponse) -> String {
    let reason = reason_phrase(canned.status);
    let encoding = canned
        .content_encoding
        .as_ref()
        .map(|encoding| format!("Content-Encoding: {encoding}\r\n"))
        .unwrap_or_default();

    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{encoding}Content-Length: {length}\r\nConnection: close\r\n\r\n{body}",
        status = canned.status,
        content_type = canned.content_type,
        length = canned.body.len(),
        body = canned.body,
    )
}

/// A reason phrase for the status codes the suite produces, generic for anything else.
const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Answers requests until the [`Origin`] that owns this thread is dropped.
///
/// The response is read afresh for each request so [`Origin::set_response`] takes effect from the
/// next one, which is what a rotation test relies on.
fn accept_until_stopped(listener: &TcpListener, recorded: &Arc<Mutex<Vec<Recorded>>>, running: &Arc<AtomicBool>, response: &Arc<Mutex<String>>) {
    while running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let current = match response.lock() {
                    Ok(current) => current.clone(), // answering does I/O, so the lock is released first and set_response is never blocked on a client
                    Err(_) => return,
                };
                let Some((request, mut reader)) = read_request(stream) else {
                    continue;
                };
                // Recorded before the answer is written: once the client has its response, the test
                // asks what was sent, and a request recorded after that is one the test does not see.
                match recorded.lock() {
                    Ok(mut recorded) => recorded.push(request),
                    Err(_) => return,
                }
                // A client that has gone away cannot be answered, and the request is already
                // recorded, so a failed write leaves nothing to do.
                let _ = reader.get_mut().write_all(current.as_bytes()).and_then(|()| reader.get_mut().flush());
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => sleep(Duration::from_millis(5)),
            Err(_) => return,
        }
    }
}

/// Reads one request and reports what it was, handing back the connection to answer it on.
fn read_request(stream: TcpStream) -> Option<(Recorded, BufReader<TcpStream>)> {
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).ok()?;

    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;

    let mut fields = request_line.split_whitespace();
    let method = fields.next()?.to_owned();
    let target = fields.next()?.to_owned();

    let mut headers = Vec::new();
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_owned();
            if name == "content-length" {
                length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    // The body is read rather than skipped: leaving it unread would have the client see a reset
    // connection instead of the response. It is kept so a test can assert on what Libra forwarded.
    let mut body = String::new();
    if length > 0 {
        let mut raw = vec![0_u8; length];
        reader.read_exact(&mut raw).ok()?;
        body = String::from_utf8_lossy(&raw).into_owned();
    }

    Some((Recorded { method, target, headers, body }, reader))
}
