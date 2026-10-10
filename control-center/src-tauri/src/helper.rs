//! Client for sysspectogram-helper. One JSON request per connection.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde_json::{json, Value};

use crate::paths;

pub fn request(op: &str, args: Value) -> Result<Value, String> {
    let sock = paths::helper_socket();
    let mut stream = UnixStream::connect(&sock)
        .map_err(|e| format!("helper is not reachable at {}: {e}", sock.display()))?;
    // Bundle installs can take a while; everything else is fast.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let mut line = json!({"op": op, "args": args}).to_string();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("helper write: {e}"))?;

    let mut reply_line = String::new();
    BufReader::new(&stream)
        .read_line(&mut reply_line)
        .map_err(|e| format!("helper read: {e}"))?;
    let reply: Value =
        serde_json::from_str(reply_line.trim()).map_err(|e| format!("helper reply: {e}"))?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(reply.get("data").cloned().unwrap_or(Value::Null))
    } else {
        Err(reply
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("helper error")
            .to_string())
    }
}
