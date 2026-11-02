//! Accepting connections, serving them, and draining them when the process stops.
//!
//! This is the listener loop that `axum::serve` would otherwise be. It is written out because that
//! function exposes neither of the two limits a public listener needs: a bound on how long a
//! client may take to send the start of a request, and a bound on how long a stopping process
//! waits for requests that will never finish.
//!
//! Without the first, a connection that sends nothing, or sends its headers a byte at a time, is
//! held open for ever. Without the second, one such connection keeps a stopping process alive until
//! the orchestrator's grace period runs out and kills it with every other request still open.

use crate::shutdown::ShutdownRequests;
use axum::{
    Router,
    extract::{ConnectInfo, Request},
};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{
        conn::auto,
        graceful::{GracefulShutdown, Watcher},
    },
    service::TowerToHyperService,
};
use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{sleep, timeout},
};
use tower::{ServiceExt, service_fn};
use tracing::{debug, info, warn};

/// How long to back off after the listener fails for a reason that is not one client's.
///
/// Running out of file descriptors is the usual one, and retrying at once would spin on it.
const ACCEPT_BACKOFF: Duration = Duration::from_secs(1);

/// The limits on a connection and on the process stopping.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionSettings {
    /// How long a client may take to send the start of a request, from connecting or from the end
    /// of its previous response.
    pub header_read_timeout: Duration,
    /// How long a stopping process waits for in-flight requests, from the first request to stop.
    pub shutdown_grace: Duration,
}

/// Serves `router` on `listener` until `requests` asks to stop, then drains.
///
/// The first request to stop closes the listener, so nothing new is accepted, and asks every open
/// connection to finish its current request and close. The drain ends when the last connection has
/// closed, when [`ConnectionSettings::shutdown_grace`] has passed, or when `requests` asks a
/// second time, whichever comes first. Connections still open then are aborted.
pub async fn serve<R>(listener: TcpListener, router: Router, settings: ConnectionSettings, mut requests: R)
where
    R: ShutdownRequests + Send,
{
    let graceful = GracefulShutdown::new();
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    // A router is a shared handle, and every connection serves from the same one.
                    let router = router.clone();
                    // The watcher is taken here and not in the task, so that a connection accepted
                    // just before a stop is part of the drain and cannot slip past it.
                    connections.spawn(serve_connection(stream, peer, router, graceful.watcher(), settings.header_read_timeout));
                }
                Err(error) => back_off(&error).await,
            },
            Some(finished) = connections.join_next() => {
                if let Err(error) = finished {
                    warn!(error = %error, "a connection task failed");
                }
            }
            () = requests.next_request() => break,
        }
    }

    drop(listener);
    drain(graceful, connections, settings.shutdown_grace, &mut requests).await;
}

/// Waits out a listener failure that is not specific to one client.
async fn back_off(error: &io::Error) {
    // The client went away between the kernel accepting it and Libra asking for it.
    if matches!(
        error.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
    ) {
        return;
    }

    warn!(error = %error, "could not accept a connection");
    sleep(ACCEPT_BACKOFF).await;
}

/// Serves one connection.
///
/// The connection is dropped without being served if it sends nothing within the header timeout.
/// The HTTP/1 header timeout cannot do that on its own: this listener accepts HTTP/1 and HTTP/2 and
/// has to read the first bytes to know which, and that read has no timeout of its own.
async fn serve_connection(stream: TcpStream, peer: SocketAddr, router: Router, watcher: Watcher, header_read_timeout: Duration) {
    if !sends_within(&stream, header_read_timeout).await {
        debug!(%peer, "a connection sent nothing and was closed");
        return;
    }

    let service = TowerToHyperService::new(service_fn(move |mut request: Request<Incoming>| {
        // The forwarded-header rules and the audit record read the peer from here.
        request.extensions_mut().insert(ConnectInfo(peer));
        // Calling a router consumes it, and the connection serves many requests from one.
        router.clone().oneshot(request)
    }));

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new()).header_read_timeout(header_read_timeout);

    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
    if let Err(error) = watcher.watch(connection).await {
        debug!(%peer, error = %error, "a connection ended with an error");
    }
}

/// Whether the peer sends its first byte within `limit`, without consuming it.
async fn sends_within(stream: &TcpStream, limit: Duration) -> bool {
    let mut first = [0_u8; 1];

    matches!(timeout(limit, stream.peek(&mut first)).await, Ok(Ok(read)) if read > 0)
}

/// Asks every connection to finish, then waits for them within the limits.
///
/// What is left open when this returns is aborted, because `connections` is dropped with it.
async fn drain<R>(graceful: GracefulShutdown, mut connections: JoinSet<()>, grace: Duration, requests: &mut R)
where
    R: ShutdownRequests + Send,
{
    info!(grace_seconds = grace.as_secs(), "draining connections");

    tokio::select! {
        () = graceful.shutdown() => info!("every connection has finished"),
        () = sleep(grace) => {
            // Reaped first: a task that finished since the loop last looked is not open.
            while connections.try_join_next().is_some() {}
            warn!(open = connections.len(), grace_seconds = grace.as_secs(), "the drain deadline passed with connections still open");
        }
        () = requests.next_request() => {
            while connections.try_join_next().is_some() {}
            warn!(open = connections.len(), "a second request to stop ended the drain");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::future::pending;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
        task::JoinHandle,
        time::Instant,
    };

    /// Requests to stop that the test sends by hand.
    struct Requests(mpsc::UnboundedReceiver<()>);

    impl ShutdownRequests for Requests {
        async fn next_request(&mut self) {
            if self.0.recv().await.is_none() {
                pending::<()>().await;
            }
        }
    }

    /// A running listener and the handles a test drives it with.
    struct Running {
        address: SocketAddr,
        stop: mpsc::UnboundedSender<()>,
        server: JoinHandle<()>,
    }

    impl Running {
        fn request_stop(&self) {
            self.stop.send(()).expect("the server is still listening for requests to stop");
        }

        /// Waits for the server to return, failing the test if it takes longer than `within`.
        async fn finished_within(self, within: Duration) -> Duration {
            let started = Instant::now();
            timeout(within, self.server)
                .await
                .expect("the server returned in time")
                .expect("the server task did not panic");
            started.elapsed()
        }
    }

    async fn start(header_read_timeout: Duration, shutdown_grace: Duration) -> Running {
        let router = Router::new()
            .route("/ok", get(|| async { "ok" }))
            .route("/peer", get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }))
            .route("/hang", get(|| async { pending::<&'static str>().await }));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a loopback port is free");
        let address = listener.local_addr().expect("a bound listener has an address");
        let (stop, requests) = mpsc::unbounded_channel();
        let settings = ConnectionSettings {
            header_read_timeout,
            shutdown_grace,
        };
        let server = tokio::spawn(serve(listener, router, settings, Requests(requests)));

        Running { address, stop, server }
    }

    async fn connect(running: &Running) -> TcpStream {
        TcpStream::connect(running.address).await.expect("the listener accepts")
    }

    async fn send(stream: &mut TcpStream, path: &str, connection: &str) {
        let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: {connection}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.expect("the request is written");
    }

    const LONG: Duration = Duration::from_secs(30);
    const PROMPT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn a_request_is_answered_and_carries_the_address_of_its_peer() {
        let running = start(LONG, LONG).await;
        let mut client = connect(&running).await;
        let peer = client.local_addr().expect("a connected socket has an address");

        send(&mut client, "/peer", "close").await;
        let mut response = String::new();
        timeout(PROMPT, client.read_to_string(&mut response))
            .await
            .expect("the response arrived")
            .expect("the response was text");

        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response.ends_with(&peer.to_string()),
            "the handler must see the peer, not an empty address: {response}"
        );
    }

    #[tokio::test]
    async fn stopping_with_nothing_open_returns_at_once() {
        let running = start(LONG, LONG).await;

        running.request_stop();

        assert!(running.finished_within(PROMPT).await < PROMPT);
    }

    #[tokio::test]
    async fn the_drain_gives_up_at_the_deadline_on_a_request_that_never_finishes() {
        let grace = Duration::from_millis(300);
        let running = start(LONG, grace).await;
        let mut client = connect(&running).await;
        send(&mut client, "/hang", "keep-alive").await;
        sleep(Duration::from_millis(100)).await;

        running.request_stop();
        let elapsed = running.finished_within(PROMPT).await;

        assert!(elapsed >= grace, "the drain ended before the deadline: {elapsed:?}");
    }

    #[tokio::test]
    async fn an_idle_connection_does_not_hold_the_drain_for_the_whole_grace_period() {
        let running = start(LONG, LONG).await;
        let mut client = connect(&running).await;
        send(&mut client, "/ok", "keep-alive").await;
        let mut first = [0_u8; 1];
        timeout(PROMPT, client.read_exact(&mut first))
            .await
            .expect("the response started")
            .expect("the response was read");

        running.request_stop();

        assert!(running.finished_within(PROMPT).await < PROMPT);
    }

    #[tokio::test]
    async fn a_second_request_to_stop_ends_the_drain_before_the_deadline() {
        let running = start(LONG, LONG).await;
        let mut client = connect(&running).await;
        send(&mut client, "/hang", "keep-alive").await;
        sleep(Duration::from_millis(100)).await;

        running.request_stop();
        sleep(Duration::from_millis(100)).await;
        running.request_stop();

        assert!(running.finished_within(PROMPT).await < PROMPT);
    }

    #[tokio::test]
    async fn nothing_new_is_accepted_once_the_drain_has_started() {
        let running = start(LONG, LONG).await;
        let mut client = connect(&running).await;
        send(&mut client, "/hang", "keep-alive").await;
        sleep(Duration::from_millis(100)).await;
        let address = running.address;

        running.request_stop();
        sleep(Duration::from_millis(200)).await;

        assert!(
            TcpStream::connect(address).await.is_err(),
            "the listener must be closed while connections drain"
        );
    }

    #[tokio::test]
    async fn a_connection_that_sends_nothing_is_closed_when_the_header_timeout_passes() {
        let running = start(Duration::from_millis(200), LONG).await;
        let mut client = connect(&running).await;

        let mut buffer = [0_u8; 1];
        let outcome = timeout(PROMPT, client.read(&mut buffer)).await.expect("the connection was closed in time");

        assert!(matches!(outcome, Ok(0) | Err(_)), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_request_whose_headers_never_finish_is_closed_when_the_header_timeout_passes() {
        let running = start(Duration::from_millis(300), LONG).await;
        let mut client = connect(&running).await;
        client
            .write_all(b"GET /ok HTTP/1.1\r\nHost: test\r\n")
            .await
            .expect("the start of a request is written");

        let mut rest = Vec::new();
        let outcome = timeout(PROMPT, client.read_to_end(&mut rest)).await;

        assert!(outcome.is_ok(), "a half-sent request must not be held open for ever");
    }
}
