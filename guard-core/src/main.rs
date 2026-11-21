use clap::Parser;
use serde::Serialize;
use sysspectogram_guard_core::{metrics, SCHEMA_VERSION};

#[derive(Parser, Debug)]
#[command(name = "sysspectogram-guard-core", version, about = "Guard metrics/alert control-plane")]
struct Cli {
    /// Emit one metrics JSON line and exit.
    #[arg(long)]
    once: bool,
}

#[derive(Serialize)]
struct MetricsLine {
    schema_version: &'static str,
    cpu_percent: f64,
    mem_percent: f64,
}

fn main() {
    let cli = Cli::parse();
    if cli.once {
        emit_metrics_once();
        return;
    }
    eprintln!("use --once to print one metrics JSON line");
    std::process::exit(2);
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