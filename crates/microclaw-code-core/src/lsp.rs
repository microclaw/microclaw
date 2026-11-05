//! Language-server diagnostics for changed files.
//!
//! After the agent edits files, the language server of each file's language
//! (rust-analyzer, typescript-language-server, pyright, gopls — whichever is
//! installed) is asked for diagnostics. Errors come back faster and more
//! precisely than a full build, and are handed to the agent like a failed
//! check. Servers are started lazily and kept for the session.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;

/// A language server MicroClaw Code knows how to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSpec {
    pub language: &'static str,
    pub language_id: &'static str,
    pub command: &'static str,
    pub args: &'static [&'static str],
    pub extensions: &'static [&'static str],
    /// First diagnostics can take long while the server indexes.
    pub first_wait: Duration,
}

pub const SERVERS: &[ServerSpec] = &[
    ServerSpec {
        language: "rust",
        language_id: "rust",
        command: "rust-analyzer",
        args: &[],
        extensions: &["rs"],
        first_wait: Duration::from_secs(60),
    },
    ServerSpec {
        language: "typescript",
        language_id: "typescript",
        command: "typescript-language-server",
        args: &["--stdio"],
        extensions: &["ts", "tsx", "js", "jsx", "mts", "cts"],
        first_wait: Duration::from_secs(20),
    },
    ServerSpec {
        language: "python",
        language_id: "python",
        command: "pyright-langserver",
        args: &["--stdio"],
        extensions: &["py"],
        first_wait: Duration::from_secs(20),
    },
    ServerSpec {
        language: "go",
        language_id: "go",
        command: "gopls",
        args: &[],
        extensions: &["go"],
        first_wait: Duration::from_secs(30),
    },
];

pub fn spec_for(path: &Path) -> Option<&'static ServerSpec> {
    let ext = path.extension()?.to_str()?;
    SERVERS.iter().find(|s| s.extensions.contains(&ext))
}

fn on_path(command: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| {
        let candidate = dir.join(command);
        candidate.is_file() || dir.join(format!("{command}.exe")).is_file()
    })
}

/// One reported problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub path: String,
    pub line: u64,
    pub column: u64,
    pub message: String,
    pub source: Option<String>,
}

impl Diagnostic {
    pub fn render(&self) -> String {
        match &self.source {
            Some(source) => format!(
                "{}:{}:{}: error[{source}]: {}",
                self.path, self.line, self.column, self.message
            ),
            None => format!(
                "{}:{}:{}: error: {}",
                self.path, self.line, self.column, self.message
            ),
        }
    }
}

/// Frame a JSON-RPC message.
pub fn frame(message: &Value) -> Vec<u8> {
    let body = message.to_string();
    let mut out = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

async fn read_message(reader: &mut BufReader<ChildStdout>) -> Option<Value> {
    let mut length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.ok()? == 0 {
            return None;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            length = value.trim().parse::<usize>().ok();
        }
    }
    let mut body = vec![0u8; length?];
    reader.read_exact(&mut body).await.ok()?;
    serde_json::from_slice(&body).ok()
}

pub fn file_uri(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let encoded: String = text
        .chars()
        .map(|c| match c {
            ' ' => "%20".to_string(),
            '#' => "%23".to_string(),
            '?' => "%3F".to_string(),
            c => c.to_string(),
        })
        .collect();
    if encoded.starts_with('/') {
        format!("file://{encoded}")
    } else {
        format!("file:///{encoded}")
    }
}

/// Errors (severity 1) of a `publishDiagnostics` notification.
pub fn errors_from_publish(params: &Value, display_path: &str) -> Vec<Diagnostic> {
    params
        .get("diagnostics")
        .and_then(|d| d.as_array())
        .map(|items| {
            items
                .iter()
                .filter(|d| d.get("severity").and_then(|s| s.as_u64()).unwrap_or(1) == 1)
                .map(|d| Diagnostic {
                    path: display_path.to_string(),
                    line: d
                        .pointer("/range/start/line")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        + 1,
                    column: d
                        .pointer("/range/start/character")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        + 1,
                    message: d
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string(),
                    source: d.get("source").and_then(|s| s.as_str()).map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default()
}

enum Incoming {
    Publish(String, Value),
    /// A request from the server; answered with an empty result.
    Request(Value),
    Response,
}

struct Server {
    spec: &'static ServerSpec,
    _child: Child,
    stdin: ChildStdin,
    incoming: mpsc::UnboundedReceiver<Incoming>,
    versions: HashMap<String, i64>,
    warmed_up: bool,
}

impl Server {
    async fn start(spec: &'static ServerSpec, root: &Path) -> anyhow::Result<Self> {
        let mut child = Command::new(spec.command)
            .args(spec.args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("no stdout"))?;
        let (tx, incoming) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            while let Some(message) = read_message(&mut reader).await {
                let method = message.get("method").and_then(|m| m.as_str());
                let item = match (method, message.get("id").is_some()) {
                    (Some("textDocument/publishDiagnostics"), _) => {
                        let params = message.get("params").cloned().unwrap_or(Value::Null);
                        let uri = params
                            .get("uri")
                            .and_then(|u| u.as_str())
                            .unwrap_or_default()
                            .to_string();
                        Incoming::Publish(uri, params)
                    }
                    (Some(_), true) => Incoming::Request(message),
                    (None, true) => Incoming::Response,
                    _ => continue,
                };
                if tx.send(item).is_err() {
                    break;
                }
            }
        });
        let mut server = Self {
            spec,
            _child: child,
            stdin,
            incoming,
            versions: HashMap::new(),
            warmed_up: false,
        };
        let root_uri = file_uri(root);
        server
            .send(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "processId": std::process::id(),
                    "rootUri": root_uri,
                    "workspaceFolders": [{"uri": root_uri, "name": "workspace"}],
                    "capabilities": {
                        "textDocument": {"publishDiagnostics": {"relatedInformation": false}},
                        "workspace": {"configuration": true, "workspaceFolders": true}
                    }
                }
            }))
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let item = tokio::time::timeout_at(deadline, server.incoming.recv())
                .await
                .map_err(|_| anyhow::anyhow!("{} did not initialize", spec.command))?
                .ok_or_else(|| anyhow::anyhow!("{} exited", spec.command))?;
            match item {
                Incoming::Response => break,
                Incoming::Request(request) => server.answer(&request).await?,
                Incoming::Publish(..) => {}
            }
        }
        server
            .send(&json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}))
            .await?;
        // Some servers (pyright) do not analyze anything until the client
        // has sent its settings at least once.
        server
            .send(&json!({
                "jsonrpc": "2.0",
                "method": "workspace/didChangeConfiguration",
                "params": {"settings": {}}
            }))
            .await?;
        Ok(server)
    }

    async fn answer(&mut self, request: &Value) -> anyhow::Result<()> {
        // workspace/configuration expects one entry per requested item.
        let result = match request.get("method").and_then(|m| m.as_str()) {
            Some("workspace/configuration") => {
                let count = request
                    .pointer("/params/items")
                    .and_then(|i| i.as_array())
                    .map(|i| i.len())
                    .unwrap_or(0);
                Value::Array(vec![Value::Null; count])
            }
            _ => Value::Null,
        };
        self.send(&json!({"jsonrpc": "2.0", "id": request["id"].clone(), "result": result}))
            .await
    }

    async fn send(&mut self, message: &Value) -> anyhow::Result<()> {
        self.stdin.write_all(&frame(message)).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    /// Open or update `path` and wait for its diagnostics. `None`: the
    /// server published nothing for the file within the wait.
    async fn diagnose(
        &mut self,
        path: &Path,
        display: &str,
    ) -> anyhow::Result<Option<Vec<Diagnostic>>> {
        let text = tokio::fs::read_to_string(path).await?;
        let uri = file_uri(path);
        while let Ok(item) = self.incoming.try_recv() {
            if let Incoming::Request(request) = item {
                self.answer(&request).await?;
            }
        }
        let version = self.versions.entry(uri.clone()).or_insert(0);
        *version += 1;
        if *version == 1 {
            let message = json!({
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {"textDocument": {
                    "uri": uri, "languageId": self.spec.language_id,
                    "version": 1, "text": text
                }}
            });
            self.send(&message).await?;
        } else {
            let message = json!({
                "jsonrpc": "2.0",
                "method": "textDocument/didChange",
                "params": {
                    "textDocument": {"uri": uri, "version": *version},
                    "contentChanges": [{"text": text}]
                }
            });
            self.send(&message).await?;
            let saved = json!({
                "jsonrpc": "2.0",
                "method": "textDocument/didSave",
                "params": {"textDocument": {"uri": uri}}
            });
            self.send(&saved).await?;
        }
        let wait = if self.warmed_up {
            Duration::from_secs(8)
        } else {
            self.spec.first_wait
        };
        let deadline = tokio::time::Instant::now() + wait;
        let mut latest: Option<Value> = None;
        // Servers often publish an empty set first and the real one shortly
        // after; take the last publication within a short quiet period.
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let quiet = if latest.is_some() {
                Duration::from_millis(1_500).min(remaining)
            } else {
                remaining
            };
            match tokio::time::timeout(quiet, self.incoming.recv()).await {
                Ok(Some(Incoming::Publish(published_uri, params))) => {
                    if published_uri == uri {
                        latest = Some(params);
                    }
                }
                Ok(Some(Incoming::Request(request))) => self.answer(&request).await?,
                Ok(Some(Incoming::Response)) => {}
                Ok(None) => anyhow::bail!("{} exited", self.spec.command),
                Err(_) => break,
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        self.warmed_up = true;
        Ok(latest.map(|params| errors_from_publish(&params, display)))
    }
}

/// What to tell the user when `spec`'s server is on PATH but will not start
/// (for example rustup's `rust-analyzer` proxy without the component).
fn start_failure_message(spec: &ServerSpec, error: &anyhow::Error) -> String {
    let hint = match spec.language {
        "rust" => "; install it with `rustup component add rust-analyzer`",
        _ => "",
    };
    format!(
        "{} could not start ({error}); skipping {} language-server diagnostics{hint}",
        spec.command, spec.language
    )
}

/// Language servers of one workspace.
pub struct LspPool {
    root: PathBuf,
    servers: HashMap<&'static str, Server>,
    unavailable: Vec<&'static str>,
}

/// Result of [`LspPool::diagnose`].
#[derive(Debug, Clone, Default)]
pub struct LspReport {
    pub errors: Vec<Diagnostic>,
    /// Languages whose server was used.
    pub languages: Vec<&'static str>,
    /// Servers (commands) that published nothing for a file within the
    /// wait, so those files were not actually checked.
    pub silent: Vec<&'static str>,
}

impl LspPool {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            servers: HashMap::new(),
            unavailable: Vec::new(),
        }
    }

    /// Whether any changed file has an installed server.
    pub fn covers(&self, files: &[String]) -> bool {
        files.iter().any(|f| {
            spec_for(Path::new(f)).is_some_and(|spec| {
                !self.unavailable.contains(&spec.language) && on_path(spec.command)
            })
        })
    }

    /// Start the servers `files` need. Returns one message per server that
    /// could not start; that language is then skipped for the session, so
    /// each failure is reported once.
    pub async fn start_servers(&mut self, files: &[String]) -> Vec<String> {
        let mut failures = Vec::new();
        for file in files {
            let path = self.root.join(file);
            if !path.is_file() {
                continue;
            }
            let Some(spec) = spec_for(&path) else {
                continue;
            };
            if self.unavailable.contains(&spec.language) || self.servers.contains_key(spec.language)
            {
                continue;
            }
            if !on_path(spec.command) {
                self.unavailable.push(spec.language);
                continue;
            }
            match Server::start(spec, &self.root).await {
                Ok(server) => {
                    self.servers.insert(spec.language, server);
                }
                Err(error) => {
                    self.unavailable.push(spec.language);
                    failures.push(start_failure_message(spec, &error));
                }
            }
        }
        failures
    }

    /// Whether a running server covers at least one of `files`.
    pub fn ready_for(&self, files: &[String]) -> bool {
        files.iter().any(|f| {
            self.root.join(f).is_file()
                && spec_for(Path::new(f))
                    .is_some_and(|spec| self.servers.contains_key(spec.language))
        })
    }

    /// Diagnostics for `files` (paths relative to the root), errors only.
    pub async fn diagnose(&mut self, files: &[String]) -> LspReport {
        self.start_servers(files).await;
        let mut report = LspReport::default();
        for file in files {
            let path = self.root.join(file);
            if !path.is_file() {
                continue;
            }
            let Some(spec) = spec_for(&path) else {
                continue;
            };
            let Some(server) = self.servers.get_mut(spec.language) else {
                continue;
            };
            match server.diagnose(&path, file).await {
                Ok(Some(errors)) => {
                    if !report.languages.contains(&spec.language) {
                        report.languages.push(spec.language);
                    }
                    report.errors.extend(errors);
                }
                Ok(None) => {
                    if !report.silent.contains(&spec.command) {
                        report.silent.push(spec.command);
                    }
                }
                Err(_) => {
                    self.servers.remove(spec.language);
                    self.unavailable.push(spec.language);
                }
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_servers_by_extension() {
        assert_eq!(
            spec_for(Path::new("src/main.rs")).unwrap().command,
            "rust-analyzer"
        );
        assert_eq!(
            spec_for(Path::new("a/b.tsx")).unwrap().language,
            "typescript"
        );
        assert_eq!(spec_for(Path::new("x.py")).unwrap().language, "python");
        assert!(spec_for(Path::new("README.md")).is_none());
    }

    #[test]
    fn frames_messages_with_content_length() {
        let framed = frame(&json!({"a": 1}));
        let text = String::from_utf8(framed).unwrap();
        assert_eq!(text, "Content-Length: 7\r\n\r\n{\"a\":1}");
    }

    #[test]
    fn keeps_only_errors_from_publications() {
        let params = json!({
            "uri": "file:///w/src/lib.rs",
            "diagnostics": [
                {"severity": 1, "message": "mismatched types\nexpected u32", "source": "rustc",
                 "range": {"start": {"line": 4, "character": 2}, "end": {"line": 4, "character": 5}}},
                {"severity": 2, "message": "unused variable",
                 "range": {"start": {"line": 1, "character": 0}, "end": {"line": 1, "character": 1}}}
            ]
        });
        let errors = errors_from_publish(&params, "src/lib.rs");
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].render(),
            "src/lib.rs:5:3: error[rustc]: mismatched types"
        );
    }

    #[test]
    fn file_uris_are_absolute() {
        assert_eq!(file_uri(Path::new("/w/a b.rs")), "file:///w/a%20b.rs");
    }

    /// End to end against a fake server written in shell: it answers
    /// initialize and publishes one error for any opened document.
    #[cfg(unix)]
    #[cfg(unix)]
    #[tokio::test]
    async fn a_server_that_exits_at_once_is_a_start_failure_with_a_hint() {
        // Like rustup's rust-analyzer proxy when the component is missing.
        let spec: &'static ServerSpec = Box::leak(Box::new(ServerSpec {
            language: "rust",
            language_id: "rust",
            command: "false",
            args: &[],
            extensions: &["rs"],
            first_wait: Duration::from_secs(10),
        }));
        let dir = tempfile::tempdir().unwrap();
        let error = match Server::start(spec, dir.path()).await {
            Ok(_) => panic!("a server that exits must not start"),
            Err(error) => error,
        };
        let message = start_failure_message(spec, &error);
        assert!(message.starts_with("false could not start"), "{message}");
        assert!(
            message.contains("rustup component add rust-analyzer"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn pool_without_servers_is_not_ready() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "x").unwrap();
        let mut pool = LspPool::new(dir.path());
        let files = vec!["a.txt".to_string(), "gone.rs".to_string()];
        assert!(pool.start_servers(&files).await.is_empty());
        assert!(!pool.ready_for(&files));
    }
    #[tokio::test]
    async fn server_round_trip_with_a_fake_language_server() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake-ls.py");
        std::fs::write(
            &script,
            r#"import sys, json
def read():
    length = 0
    while True:
        line = sys.stdin.buffer.readline()
        if not line: sys.exit(0)
        line = line.decode().strip()
        if not line: break
        if line.lower().startswith("content-length:"): length = int(line.split(":")[1])
    return json.loads(sys.stdin.buffer.read(length))
def send(msg):
    body = json.dumps(msg).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(body) + body); sys.stdout.flush()
while True:
    msg = read()
    if msg.get("method") == "initialize": send({"jsonrpc": "2.0", "id": msg["id"], "result": {"capabilities": {}}})
    if msg.get("method") in ("textDocument/didOpen", "textDocument/didChange"):
        uri = msg["params"]["textDocument"]["uri"]
        send({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics", "params": {"uri": uri, "diagnostics": [
            {"severity": 1, "message": "boom", "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}}]}})
"#,
        )
        .unwrap();
        if std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let spec: &'static ServerSpec = Box::leak(Box::new(ServerSpec {
            language: "fake",
            language_id: "fake",
            command: "python3",
            args: Box::leak(
                vec![Box::leak(script.display().to_string().into_boxed_str()) as &str]
                    .into_boxed_slice(),
            ),
            extensions: &["fk"],
            first_wait: Duration::from_secs(10),
        }));
        let file = dir.path().join("a.fk");
        std::fs::write(&file, "x").unwrap();
        let mut server = Server::start(spec, dir.path()).await.unwrap();
        let errors = server.diagnose(&file, "a.fk").await.unwrap().unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "boom");
        std::fs::write(&file, "y").unwrap();
        let errors = server.diagnose(&file, "a.fk").await.unwrap().unwrap();
        assert_eq!(errors.len(), 1);
    }
}
