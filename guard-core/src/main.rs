use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::Serialize;
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
        None => {
            eprintln!("use --once, metrics, auth-fail-ip, tcp-addr, or render");
            std::process::exit(2);
        }
    }
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
