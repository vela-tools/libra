//! The proxy under test: the binary cargo just built, running as a process.
//!
//! The suite deliberately does not run a published image. `CARGO_BIN_EXE_libra` is the binary built
//! by the package whose suite is running, so the suite tests that binary and cannot drift from it.
//!
//! Each instance gets its own configuration, its own policy directory and its own port, so a test
//! states the policy it is about rather than sharing one file with every other test.

use crate::proxy_settings::{ProxySettings, preloaded_path};
use reqwest::blocking::{Client, RequestBuilder};
use std::{
    env,
    fs,
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};
use tempfile::TempDir;

/// The Libra binary under test.
///
/// Cargo sets `CARGO_BIN_EXE_libra` while it builds and while it runs the integration tests of a
/// package that builds a `libra` binary. A harness running anywhere else has nothing to start, which
/// is a mistake in how it was invoked and not something a test can recover from.
fn binary() -> PathBuf {
    PathBuf::from(env::var_os("CARGO_BIN_EXE_libra").expect("CARGO_BIN_EXE_libra is set for the integration tests of a package that builds the libra binary"))
}

/// How long a proxy is given to load its policies, fetch the signing keys and start serving.
const STARTUP_BUDGET: Duration = Duration::from_secs(30);

/// How long a proxy that is expected to refuse to start is given to say so.
const FAILURE_BUDGET: Duration = Duration::from_secs(30);

/// How many times a lost port is worth retrying before calling it a failure.
const PORT_ATTEMPTS: usize = 5;

/// A running proxy, killed when the test that started it ends.
pub struct Proxy {
    child: Child,
    base: String,
    address: String,
    client: Client,
    // Holds the configuration and policy files for the process's lifetime, and is dropped after
    // `child` because it is declared after it.
    directory: TempDir,
}

impl Proxy {
    /// Starts a proxy and waits until it is serving.
    ///
    /// # Panics
    ///
    /// Panics if the process exits or does not answer its health probe within its startup budget,
    /// reporting whatever it wrote to stderr.
    #[must_use]
    pub fn start(settings: &ProxySettings) -> Self {
        for _ in 0..PORT_ATTEMPTS {
            match Self::start_once(settings) {
                Ok(proxy) => return proxy,
                // The port is chosen by binding an ephemeral one and closing it again, so between
                // that and the proxy binding it, another test in this process can take it. Nothing
                // makes that window closable from here; retrying costs one startup and removes the
                // flake. Anything else is a real failure and is reported as one.
                Err(reported) => assert!(reported.contains("Address already in use"), "{reported}"),
            }
        }

        panic!("no free port was still free by the time libra bound it, after {PORT_ATTEMPTS} attempts");
    }

    /// One attempt, reporting what the process said rather than panicking, so [`Self::start`] can
    /// tell a lost port from a real failure.
    fn start_once(settings: &ProxySettings) -> Result<Self, String> {
        let (mut child, directory, port) = spawn(settings);
        let base = format!("http://127.0.0.1:{port}");
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("the HTTP client should build");
        let deadline = Instant::now() + STARTUP_BUDGET;

        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().expect("the child's state should be readable") {
                return Err(format!("libra exited with {status} before serving\n{}", stderr(directory.path())));
            }
            if client
                .get(format!("{base}/ngsi-ld/auth/health"))
                .send()
                .is_ok_and(|response| response.status().is_success())
            {
                return Ok(Self {
                    child,
                    base,
                    address: format!("127.0.0.1:{port}"),
                    client,
                    directory,
                });
            }
            sleep(Duration::from_millis(100));
        }

        let _ = child.kill();

        Err(format!("libra did not start within {STARTUP_BUDGET:?}\n{}", stderr(directory.path())))
    }

    /// Starts a proxy that is expected to refuse the configuration it was given, and returns what
    /// it said before exiting.
    ///
    /// # Panics
    ///
    /// Panics if the process starts successfully, because a policy the build cannot enforce
    /// reaching a serving proxy is the outcome the caller is asserting cannot happen.
    #[must_use]
    pub fn start_expecting_failure(settings: &ProxySettings) -> String {
        let (mut child, directory, _) = spawn(settings);
        let deadline = Instant::now() + FAILURE_BUDGET;

        while Instant::now() < deadline {
            match child.try_wait().expect("the child's state should be readable") {
                Some(status) if status.success() => panic!("libra exited cleanly, but it was expected to refuse to start"),
                Some(_) => return stderr(directory.path()),
                None => sleep(Duration::from_millis(100)),
            }
        }

        let _ = child.kill();
        panic!("libra kept running, but it was expected to refuse to start\n{}", stderr(directory.path()));
    }

    /// Runs the binary with `arguments` against this instance's configuration, as an operator runs
    /// `libra key` or `libra principal` beside a serving proxy.
    ///
    /// # Panics
    ///
    /// Panics if the binary cannot be run.
    #[must_use]
    pub fn command(&self, arguments: &[&str]) -> Output {
        let mut command = Command::new(binary());
        for (name, _) in env::vars() {
            if name.starts_with("LIBRA_") {
                command.env_remove(name);
            }
        }

        command
            .args(arguments)
            .env("LIBRA__CONFIG_FILE", self.directory.path().join("libra.toml"))
            .output()
            .expect("the libra binary should be runnable")
    }

    /// A `GET` against this instance.
    pub fn get(&self, path: &str) -> RequestBuilder {
        self.client.get(format!("{}{path}", self.base))
    }

    /// A `POST` against this instance.
    pub fn post(&self, path: &str) -> RequestBuilder {
        self.client.post(format!("{}{path}", self.base))
    }

    /// A request with an arbitrary method, for the routes `get` and `post` do not cover.
    pub fn request(&self, method: reqwest::Method, path: &str) -> RequestBuilder {
        self.client.request(method, format!("{}{path}", self.base))
    }

    /// Sends a literal request over a fresh connection and returns the literal response.
    ///
    /// An HTTP client is entitled to rewrite the connection-management headers, and does, which
    /// makes it the wrong tool for testing what Libra does with a header a client would never
    /// send. These tests write the bytes themselves.
    ///
    /// # Panics
    ///
    /// Panics if the proxy cannot be reached.
    #[must_use]
    pub fn raw(&self, request: &str) -> String {
        let mut stream = TcpStream::connect(&self.address).expect("the proxy should accept a connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("the read timeout should be settable");
        stream.write_all(request.as_bytes()).expect("the request should be writable");
        stream.flush().expect("the request should be sendable");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("the proxy should answer");

        String::from_utf8_lossy(&response).into_owned()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Writes the instance's files and starts the process, without waiting for it.
fn spawn(settings: &ProxySettings) -> (Child, TempDir, u16) {
    let directory = TempDir::new().expect("a temporary directory should be creatable");
    let policies_dir = directory.path().join("policies");
    fs::create_dir_all(&policies_dir).expect("the policy directory should be creatable");
    if !settings.policies.trim().is_empty() {
        fs::write(policies_dir.join("policy.toml"), &settings.policies).expect("the policy file should be writable");
    }

    for (url, document) in &settings.preloaded_contexts {
        fs::write(preloaded_path(directory.path(), url), document).expect("the preloaded context should be writable");
    }

    let port = free_port();
    let config = directory.path().join("libra.toml");
    fs::write(&config, settings.to_toml(directory.path(), port)).expect("the configuration should be writable");

    let out = fs::File::create(directory.path().join("stdout")).expect("the log file should be creatable");
    let err = fs::File::create(directory.path().join("stderr")).expect("the log file should be creatable");

    let mut command = Command::new(binary());
    // The configuration must come from the file this harness wrote. Anything the developer has
    // exported under the same prefix would otherwise be layered over it, and because unknown keys
    // are fatal, a stray variable alone would stop the process before it read a policy.
    for (name, _) in env::vars() {
        if name.starts_with("LIBRA_") {
            command.env_remove(name);
        }
    }
    let child = command
        .env("LIBRA__CONFIG_FILE", &config)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("the libra binary should be runnable");

    (child, directory, port)
}

/// A port nothing is listening on.
///
/// Racy in principle: the port is free when this returns and something else could take it before
/// the proxy binds. Nothing else in the suite binds an arbitrary port, so in practice the race is
/// with the machine rather than with the test.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port should be bindable");
    listener.local_addr().expect("the bound address should be readable").port()
}

/// Whatever the process wrote to stderr, for a failure message.
fn stderr(directory: &Path) -> String {
    match fs::read_to_string(directory.join("stderr")) {
        Ok(text) if text.trim().is_empty() => "(nothing on stderr)".to_owned(),
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => "(no stderr was captured)".to_owned(),
        Err(error) => format!("(stderr could not be read: {error})"),
    }
}
