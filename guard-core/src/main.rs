use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::json;
use sysspectogram_guard_core::{auth, flow, metrics, render, SCHEMA_VERSION};

#[derive(Parser, Debug)]
#[command(name = "sysspectogram-guard-core", version, about = "Guard metrics/alert control-plane")]
struct Cli {
    /// Emit one metrics JSON line and exit (same as `metrics`).
    #[arg(long)]
    once: bool,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Emit one metrics JSON line and exit.
    Metrics,
    /// Print the peer IP from a Failed/Invalid sshd line.
    AuthFailIp {
        #[arg(long, allow_hyphen_values = true)]
        line: String,
    },
    /// Decode a `/proc/net/tcp` `IP:PORT` hex field.
    TcpAddr {
        #[arg(long)]
        field: String,
    },
    /// Render metric points to a PNG.
    Render {
        /// JSON array of `[ts, value]` or a path to that JSON.
        #[arg(long)]
        points: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Serve JSONL request/response over a Unix stream socket.
    Serve {
        #[arg(long)]
        socket: PathBuf,
    },
}

#[derive(Serialize)]
struct MetricsLine {
    schema_version: &'static str,
    cpu_percent: f64,
    mem_percent: f64,
}

#[derive(Serialize)]
struct TcpAddrLine {
    ip: String,
    port: u16,
}

fn main() {
    let cli = Cli::parse();
    if cli.once {
        emit_metrics_once();
        return;
    }
    match cli.command {
        Some(Cmd::Metrics) => emit_metrics_once(),
        Some(Cmd::AuthFailIp { line }) => emit_auth_fail_ip(&line),
        Some(Cmd::TcpAddr { field }) => emit_tcp_addr(&field),
        Some(Cmd::Render { points, out }) => emit_render(&points, &out),
        Some(Cmd::Serve { socket }) => serve_socket(&socket),
        None => {
            eprintln!("use --once, metrics, auth-fail-ip, tcp-addr, render, or serve");
            std::process::exit(2);
        }
    }
}

fn serve_socket(path: &std::path::Path) {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    let listener = UnixListener::bind(path).unwrap_or_else(|err| {
        eprintln!("serve bind {}: {err}", path.display());
        std::process::exit(1);
    });
    eprintln!(
        "[sysspectogram-guard-core] serve schema_version={SCHEMA_VERSION} socket={}",
        path.display()
    );
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(err) = handle_client(stream) {
                    eprintln!("serve client: {err}");
                }
            }
            Err(err) => eprintln!("serve accept: {err}"),
        }
    }
}

fn handle_client(stream: UnixStream) -> Result<(), String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        let req: serde_json::Value =
            serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
        let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("");
        let resp = match op {
            "ping" => json!({"ok": true, "schema_version": SCHEMA_VERSION}),
            "metrics" => {
                let m = metrics::collect_cpu_mem();
                json!({
                    "ok": true,
                    "schema_version": SCHEMA_VERSION,
                    "cpu_percent": m.get("cpu_percent").copied().unwrap_or(0.0),
                    "mem_percent": m.get("mem_percent").copied().unwrap_or(0.0),
                })
            }
            "auth_fail_ip" => {
                let text = req.get("line").and_then(|v| v.as_str()).unwrap_or("");
                json!({"ok": true, "ip": auth::parse_auth_fail_ip(text)})
            }
            "tcp_addr" => {
                let field = req.get("field").and_then(|v| v.as_str()).unwrap_or("");
                match flow::parse_tcp_hex_addr(field) {
                    Some((ip, port)) => json!({"ok": true, "ip": ip, "port": port}),
                    None => json!({"ok": false, "error": "bad_field"}),
                }
            }
            _ => json!({"ok": false, "error": "unknown_op"}),
        };
        let mut out = serde_json::to_string(&resp).map_err(|e| e.to_string())?;
        out.push('\n');
        writer.write_all(out.as_bytes()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn emit_metrics_once() {
    let m = metrics::collect_cpu_mem();
    let line = MetricsLine {
        schema_version: SCHEMA_VERSION,
        cpu_percent: *m.get("cpu_percent").unwrap_or(&0.0),
        mem_percent: *m.get("mem_percent").unwrap_or(&0.0),
    };
    println!("{}", serde_json::to_string(&line).expect("metrics json"));
}

fn emit_auth_fail_ip(line: &str) {
    match auth::parse_auth_fail_ip(line) {
        Some(ip) => println!("{ip}"),
        None => std::process::exit(1),
    }
}

fn emit_tcp_addr(field: &str) {
    match flow::parse_tcp_hex_addr(field) {
        Some((ip, port)) => {
            let line = TcpAddrLine { ip, port };
            println!("{}", serde_json::to_string(&line).expect("tcp json"));
        }
        None => std::process::exit(1),
    }
}

fn emit_render(points: &str, out: &std::path::Path) {
    let pts = match load_points(points) {
        Ok(pts) => pts,
        Err(err) => {
            eprintln!("render points: {err}");
            std::process::exit(2);
        }
    };
    let png = match render::render_metric_png("metric", &pts, 320, 180) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("render: {err}");
            std::process::exit(1);
        }
    };
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    if let Err(err) = fs::write(out, png) {
        eprintln!("render out: {err}");
        std::process::exit(1);
    }
}

fn load_points(raw: &str) -> Result<Vec<(f64, f64)>, String> {
    let text = if raw.trim_start().starts_with('[') {
        raw.to_string()
    } else {
        fs::read_to_string(raw).map_err(|err| err.to_string())?
    };
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    let arr = value.as_array().ok_or_else(|| "points must be a JSON array".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        if let Some(pair) = item.as_array() {
            if pair.len() >= 2 {
                let x = pair[0].as_f64().ok_or_else(|| "point x".to_string())?;
                let y = pair[1].as_f64().ok_or_else(|| "point y".to_string())?;
                out.push((x, y));
                continue;
            }
        }
        if let Some(obj) = item.as_object() {
            let x = obj
                .get("ts")
                .or_else(|| obj.get("x"))
                .and_then(|v| v.as_f64())
                .ok_or_else(|| "point x".to_string())?;
            let y = obj
                .get("value")
                .or_else(|| obj.get("y"))
                .and_then(|v| v.as_f64())
                .ok_or_else(|| "point y".to_string())?;
            out.push((x, y));
            continue;
        }
        return Err("point must be [ts, value]".into());
    }
    Ok(out)
}
