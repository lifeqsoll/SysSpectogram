//! sysspectogram-helper: the only root process the Control Center talks to.
//!
//! Protocol: one JSON request per connection, one JSON reply line.
//!   request:  {"op": "<name>", "args": {...}}
//!   reply:    {"ok": true, "data": {...}} or {"ok": false, "message": "..."}
//!
//! Security model:
//! - the caller is identified with SO_PEERCRED, never by anything it sends;
//! - every mutating operation is checked by polkit (pkcheck) for the caller process;
//! - operations are a fixed allowlist; no shell is ever involved;
//! - bundles are copied into a root-owned staging area before any verification,
//!   so the user cannot swap files between verification and installation.

mod ops;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::time::Duration;

use serde_json::{json, Value};

const SOCKET_DEFAULT: &str = "/run/sysspectogram/helper.sock";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const PKCHECK: &str = "/usr/bin/pkcheck";

#[derive(Clone, Copy, Debug)]
pub struct Caller {
    pub uid: u32,
    pub pid: i32,
}

fn peer_creds(stream: &UnixStream) -> std::io::Result<Caller> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for writes for the duration of the call.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Caller {
        uid: cred.uid,
        pid: cred.pid,
    })
}

/// Start time of a process (field 22 of /proc/<pid>/stat). Used so polkit cannot
/// be fooled by PID reuse between the check and the request.
pub fn process_start_time(pid: i32) -> Option<u64> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = raw.rsplit_once(')')?.1;
    // Fields after ')' begin at field 3 (state), so field 22 is index 19.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Ask polkit whether the calling process may perform `action`. Root is trusted.
pub fn authorize(action: &str, caller: Caller) -> Result<(), String> {
    if caller.uid == 0 {
        return Ok(());
    }
    let start = process_start_time(caller.pid).ok_or("caller process vanished")?;
    let subject = format!("{},{}", caller.pid, start);
    let status = Command::new(PKCHECK)
        .args([
            "--action-id",
            action,
            "--process",
            subject.as_str(),
            "--allow-user-interaction",
        ])
        .status()
        .map_err(|e| format!("pkcheck failed to start: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("not authorized: {action}"))
    }
}

fn reply(mut stream: &UnixStream, value: Value) {
    let mut out = value.to_string();
    out.push('\n');
    let _ = stream.write_all(out.as_bytes());
}

fn handle(stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let caller = match peer_creds(&stream) {
        Ok(c) => c,
        Err(e) => {
            reply(
                &stream,
                json!({"ok": false, "message": format!("peer credentials: {e}")}),
            );
            return;
        }
    };

    let mut line = String::new();
    let mut reader = BufReader::new(Read::take(&stream, MAX_REQUEST_BYTES));
    if let Err(e) = reader.read_line(&mut line) {
        reply(&stream, json!({"ok": false, "message": format!("read: {e}")}));
        return;
    }
    let request: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(e) => {
            reply(
                &stream,
                json!({"ok": false, "message": format!("bad request: {e}")}),
            );
            return;
        }
    };
    let op = request.get("op").and_then(Value::as_str).unwrap_or_default();
    let args = request.get("args").cloned().unwrap_or_else(|| json!({}));
    eprintln!("sysspectogram-helper: op={op} uid={} pid={}", caller.uid, caller.pid);
    let response = ops::dispatch(op, &args, caller);
    reply(&stream, response);
}

/// Set the group of a file or directory to `group` (owner unchanged). Called once at startup.
fn chown_socket_group(path: &str, group: &str) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::io::{Error, ErrorKind};

    let cgroup = CString::new(group).map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
    let cpath = CString::new(path).map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
    // SAFETY: getgrnam returns a pointer into static storage or null; we read gr_gid only
    // while checking for null, and this runs once before any worker threads exist.
    let gr = unsafe { libc::getgrnam(cgroup.as_ptr()) };
    if gr.is_null() {
        return Err(Error::new(ErrorKind::NotFound, format!("group {group} not found")));
    }
    let gid = unsafe { (*gr).gr_gid };
    // -1 leaves the owner unchanged.
    let rc = unsafe { libc::chown(cpath.as_ptr(), (-1i32) as libc::uid_t, gid) };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn main() {
    let path = std::env::var("SYSSPECTOGRAM_HELPER_SOCKET")
        .unwrap_or_else(|_| SOCKET_DEFAULT.to_string());
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sysspectogram-helper: bind {path}: {e}");
            std::process::exit(1);
        }
    };
    // The socket inherits the process group (root), so members of `sysspectogram`
    // could not write to it. Hand the socket to that group explicitly; polkit still
    // checks every mutating operation.
    // The runtime directory must also be traversable by the group (0750 root:root blocks it).
    if let Some(dir) = std::path::Path::new(&path).parent().and_then(|d| d.to_str()) {
        if !dir.is_empty() {
            if let Err(e) = chown_socket_group(dir, "sysspectogram") {
                eprintln!("sysspectogram-helper: runtime dir group not set ({e}); only root can connect");
            }
        }
    }
    if let Err(e) = chown_socket_group(&path, "sysspectogram") {
        eprintln!("sysspectogram-helper: socket group not set ({e}); only root can connect");
    }
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));

    // Serial on purpose: installs and settings writes must not interleave.
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => handle(stream),
            Err(e) => eprintln!("sysspectogram-helper: accept: {e}"),
        }
    }
}
