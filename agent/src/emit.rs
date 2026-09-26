use crate::auth;
use crate::metrics::MetricsSample;
use crate::types::AgentAlert;
use std::fs;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

/// Agent is the client: send_to(path) where guard has bound a Unix datagram socket.
pub struct Emitter {
    sock: UnixDatagram,
    sock_path: PathBuf,
    jsonl: Option<PathBuf>,
    hmac_secret: Option<String>,
}

impl Emitter {
    pub fn new(socket: &Path, jsonl: Option<&Path>, hmac_secret: Option<String>) -> io::Result<Self> {
        Ok(Self {
            sock: UnixDatagram::unbound()?,
            sock_path: socket.to_path_buf(),
            jsonl: jsonl.map(|p| p.to_path_buf()),
            hmac_secret,
        })
    }

    pub fn emit_alert(&self, alert: &AgentAlert) -> io::Result<()> {
        let mut alert = alert.clone();
        if let Some(secret) = &self.hmac_secret {
            let canon = auth::canonical(
                &alert.rule_id,
                &alert.severity,
                alert.ts,
                alert.pid,
                alert.path.as_deref().unwrap_or(""),
                &alert.message,
            );
            alert.hmac = Some(auth::sign_hex(secret, &canon));
        }
        self.emit_line(&serde_json::to_string(&alert).map_err(io::Error::other)?, true)
    }

    pub fn emit_metrics(&self, sample: &MetricsSample) -> io::Result<()> {
        self.emit_line(
            &serde_json::to_string(sample).map_err(io::Error::other)?,
            false,
        )
    }

    fn emit_line(&self, line: &str, mirror_jsonl: bool) -> io::Result<()> {
        let bytes = format!("{line}\n");
        let _ = self.sock.send_to(bytes.as_bytes(), &self.sock_path);
        if mirror_jsonl {
            if let Some(path) = &self.jsonl {
                use std::io::Write;
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let mut f = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                f.write_all(bytes.as_bytes())?;
            }
            println!("{line}");
        }
        Ok(())
    }
}
