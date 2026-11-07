//! JSON-RPC 2.0 over newline-delimited stdio, as ACP uses it.
//!
//! The protocol types come from `agent-client-protocol-schema`; this module
//! only frames messages. Every outgoing message goes through one ordered
//! writer, so a response never overtakes the notifications sent before it.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use agent_client_protocol_schema::v1::Error;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

/// One message read from the client.
#[derive(Debug, PartialEq)]
pub enum Incoming {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
    Response {
        id: Value,
        result: Result<Value, Error>,
    },
}

/// Parses one line; `Err` carries the JSON-RPC error to send back (with a
/// null id).
pub fn parse(line: &str) -> Result<Incoming, Error> {
    let value: Value = serde_json::from_str(line).map_err(|_| Error::parse_error())?;
    let Value::Object(mut object) = value else {
        return Err(Error::invalid_request());
    };
    let params = object.remove("params").unwrap_or(Value::Null);
    match (object.remove("method"), object.remove("id")) {
        (Some(Value::String(method)), Some(id)) => Ok(Incoming::Request { id, method, params }),
        (Some(Value::String(method)), None) => Ok(Incoming::Notification { method, params }),
        (None, Some(id)) => {
            let result = match (object.remove("result"), object.remove("error")) {
                (_, Some(error)) => {
                    Err(serde_json::from_value(error).unwrap_or_else(|_| Error::internal_error()))
                }
                (Some(result), None) => Ok(result),
                (None, None) => Ok(Value::Null),
            };
            Ok(Incoming::Response { id, result })
        }
        _ => Err(Error::invalid_request()),
    }
}

/// The agent's side of the connection.
pub struct Connection {
    out: mpsc::UnboundedSender<String>,
    pending: RefCell<HashMap<i64, oneshot::Sender<Result<Value, Error>>>>,
    next_id: Cell<i64>,
}

impl Connection {
    /// A connection and the receiver that [`write_loop`] drains.
    pub fn new() -> (Self, mpsc::UnboundedReceiver<String>) {
        let (out, rx) = mpsc::unbounded_channel();
        (
            Self {
                out,
                pending: RefCell::new(HashMap::new()),
                next_id: Cell::new(0),
            },
            rx,
        )
    }

    fn send(&self, message: Value) {
        if let Ok(line) = serde_json::to_string(&message) {
            let _ = self.out.send(line);
        }
    }

    pub fn notify(&self, method: &str, params: impl Serialize) {
        let params = serde_json::to_value(params).unwrap_or(Value::Null);
        self.send(json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    pub fn respond(&self, id: Value, result: Result<Value, Error>) {
        match result {
            Ok(result) => self.send(json!({"jsonrpc": "2.0", "id": id, "result": result})),
            Err(error) => {
                let error = serde_json::to_value(error).unwrap_or(Value::Null);
                self.send(json!({"jsonrpc": "2.0", "id": id, "error": error}));
            }
        }
    }

    /// Sends a request to the client and waits for its answer.
    pub async fn request(&self, method: &str, params: impl Serialize) -> Result<Value, Error> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let (tx, rx) = oneshot::channel();
        self.pending.borrow_mut().insert(id, tx);
        let params = serde_json::to_value(params).unwrap_or(Value::Null);
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        rx.await.unwrap_or_else(|_| Err(Error::internal_error()))
    }

    /// Routes a response from the client to the request waiting for it.
    pub fn resolve(&self, id: &Value, result: Result<Value, Error>) {
        if let Some(id) = id.as_i64()
            && let Some(tx) = self.pending.borrow_mut().remove(&id)
        {
            let _ = tx.send(result);
        }
    }

    /// Fails every request still waiting (the client went away).
    pub fn close(&self) {
        for (_, tx) in self.pending.borrow_mut().drain() {
            let _ = tx.send(Err(Error::internal_error()));
        }
    }
}

/// Writes queued lines until every sender is gone.
pub async fn write_loop(
    mut rx: mpsc::UnboundedReceiver<String>,
    mut out: impl AsyncWrite + Unpin,
) -> std::io::Result<()> {
    while let Some(mut line) = rx.recv().await {
        line.push('\n');
        out.write_all(line.as_bytes()).await?;
        out.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests_notifications_and_responses() {
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"a":1}}"#).unwrap(),
            Incoming::Request {
                id: json!(1),
                method: "initialize".into(),
                params: json!({"a": 1})
            }
        );
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","method":"session/cancel","params":{}}"#).unwrap(),
            Incoming::Notification {
                method: "session/cancel".into(),
                params: json!({})
            }
        );
        assert!(matches!(
            parse(r#"{"jsonrpc":"2.0","id":"x","error":{"code":-32603,"message":"m"}}"#).unwrap(),
            Incoming::Response { result: Err(_), .. }
        ));
        assert!(parse("not json").is_err());
    }

    #[tokio::test]
    async fn requests_are_answered_by_matching_responses() {
        let (conn, mut rx) = Connection::new();
        let conn = std::rc::Rc::new(conn);
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let c = conn.clone();
                let waiting = tokio::task::spawn_local(async move {
                    c.request("session/request_permission", json!({})).await
                });
                let sent: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
                assert_eq!(sent["method"], "session/request_permission");
                conn.resolve(&sent["id"], Ok(json!({"ok": true})));
                assert_eq!(waiting.await.unwrap().unwrap(), json!({"ok": true}));
            })
            .await;
    }
}
