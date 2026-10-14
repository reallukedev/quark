//! A client for Quark's admin socket (docs/admin-api.md): one JSON request line per connection,
//! one JSON response line back.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Answers bigger than this are refused (a snapshot of a big server is a few MB at most).
const MAX_ANSWER: u64 = 32 << 20;
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("Quark isn't answering at {path} ({source}). Is the server running, and is this the right data folder?")]
    Unreachable { path: PathBuf, source: std::io::Error },
    #[error("Quark took too long to answer.")]
    Timeout,
    #[error("Quark sent an answer that couldn't be read ({0}).")]
    BadAnswer(String),
    /// The server refused the request; `message` is meant for people.
    #[error("{message}")]
    Refused { code: String, message: String },
}

#[derive(Debug, Clone)]
pub struct AdminClient {
    socket: PathBuf,
}

impl AdminClient {
    pub fn new(socket: impl Into<PathBuf>) -> AdminClient {
        AdminClient { socket: socket.into() }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Sends `{ "cmd": cmd, "args": args }` and returns the `value` of an `ok` answer.
    pub async fn call(&self, cmd: &str, args: Value) -> Result<Value, AdminError> {
        match tokio::time::timeout(TIMEOUT, self.exchange(cmd, args)).await {
            Ok(r) => r,
            Err(_) => Err(AdminError::Timeout),
        }
    }

    async fn exchange(&self, cmd: &str, args: Value) -> Result<Value, AdminError> {
        let unreachable = |source| AdminError::Unreachable { path: self.socket.clone(), source };
        let mut stream = UnixStream::connect(&self.socket).await.map_err(unreachable)?;
        let mut line = serde_json::to_vec(&json!({ "cmd": cmd, "args": args })).map_err(|e| AdminError::BadAnswer(e.to_string()))?;
        line.push(b'\n');
        stream.write_all(&line).await.map_err(unreachable)?;
        // One request per connection: closing our side tells a server reading to EOF we're done.
        let _ = stream.shutdown().await;
        let mut buf = Vec::new();
        (&mut stream).take(MAX_ANSWER).read_to_end(&mut buf).await.map_err(unreachable)?;
        let end = buf.iter().position(|b| *b == b'\n').unwrap_or(buf.len());
        let answer: Value = serde_json::from_slice(&buf[..end]).map_err(|e| AdminError::BadAnswer(e.to_string()))?;
        parse_answer(answer)
    }
}

/// Splits an answer envelope into its value or the refusal.
pub fn parse_answer(answer: Value) -> Result<Value, AdminError> {
    match answer.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok(answer.get("value").cloned().unwrap_or(Value::Null)),
        Some(false) => Err(AdminError::Refused {
            code: answer.get("code").and_then(Value::as_str).unwrap_or("internal").to_string(),
            message: answer.get("error").and_then(Value::as_str).unwrap_or("Quark refused the request without saying why.").to_string(),
        }),
        None => Err(AdminError::BadAnswer("no \"ok\" field".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_split_into_values_and_refusals() {
        assert_eq!(parse_answer(json!({"ok": true, "value": {"a": 1}})).unwrap(), json!({"a": 1}));
        assert_eq!(parse_answer(json!({"ok": true})).unwrap(), Value::Null);
        match parse_answer(json!({"ok": false, "code": "exists", "error": "Taken."})) {
            Err(AdminError::Refused { code, message }) => assert_eq!((code.as_str(), message.as_str()), ("exists", "Taken.")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(parse_answer(json!({"value": 1})), Err(AdminError::BadAnswer(_))));
    }

    #[tokio::test]
    async fn a_missing_socket_says_the_server_is_not_answering() {
        let c = AdminClient::new("/nonexistent/quark/admin.sock");
        let e = c.call("status", json!({})).await.unwrap_err();
        assert!(e.to_string().contains("isn't answering"), "{e}");
    }
}
