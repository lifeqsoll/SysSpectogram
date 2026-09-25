//! Lightweight host metrics from /proc (Phase 2 hot path).

use crate::types::now_unix;
use serde::Serialize;
use std::fs;
use std::io;

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSample {
    pub schema: String,
    pub kind: String,
    pub host_id: String,
    pub ts: f64,
    pub cpu_percent: f64,
    pub mem_percent: f64,
    pub net_packets_sent_per_s: f64,
    pub net_packets_recv_per_s: f64,
    pub net_bytes_sent_per_s: f64,
    pub net_bytes_recv_per_s: f64,
}

pub struct MetricsSampler {
    host_id: String,
    prev_cpu: Option<(u64, u64)>,
    prev_net: Option<(u64, u64, u64, u64, std::time::Instant)>,
}

impl MetricsSampler {
    pub fn new(host_id: String) -> Self {
        Self {
            host_id,
            prev_cpu: None,
            prev_net: None,
        }
    }

    pub fn sample(&mut self) -> io::Result<MetricsSample> {
        let cpu = cpu_percent(&mut self.prev_cpu)?;
        let mem = mem_percent()?;
        let (ps, pr, bs, br) = net_rates(&mut self.prev_net)?;
        Ok(MetricsSample {
            schema: "sysspectogram.metrics.v1".into(),
            kind: "metrics".into(),
            host_id: self.host_id.clone(),
            ts: now_unix(),
            cpu_percent: cpu,
            mem_percent: mem,
            net_packets_sent_per_s: ps,
            net_packets_recv_per_s: pr,
            net_bytes_sent_per_s: bs,
            net_bytes_recv_per_s: br,
        })
    }
}

fn cpu_percent(prev: &mut Option<(u64, u64)>) -> io::Result<f64> {
    let text = fs::read_to_string("/proc/stat")?;
    let line = text.lines().next().unwrap_or("");
    let parts: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    if parts.len() < 4 {
        return Ok(0.0);
    }
    let idle = parts[3] + parts.get(4).copied().unwrap_or(0);
    let total: u64 = parts.iter().sum();
    let pct = if let Some((pi, pt)) = *prev {
        let di = idle.saturating_sub(pi) as f64;
        let dt = total.saturating_sub(pt) as f64;
        if dt > 0.0 {
            ((dt - di) / dt * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        }
    } else {
        0.0
    };
    *prev = Some((idle, total));
    Ok(pct)
}

fn mem_percent() -> io::Result<f64> {
    let text = fs::read_to_string("/proc/meminfo")?;
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = parse_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail = parse_kb(rest);
        }
    }
    if total == 0 {
        return Ok(0.0);
    }
    Ok(((total - avail) as f64 / total as f64) * 100.0)
}

fn parse_kb(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

fn net_rates(
    prev: &mut Option<(u64, u64, u64, u64, std::time::Instant)>,
) -> io::Result<(f64, f64, f64, f64)> {
    let text = fs::read_to_string("/proc/net/dev")?;
    let mut rx_b = 0u64;
    let mut tx_b = 0u64;
    let mut rx_p = 0u64;
    let mut tx_p = 0u64;
    for line in text.lines().skip(2) {
        let line = line.trim();
        if line.starts_with("lo:") {
            continue;
        }
        let Some((_iface, rest)) = line.split_once(':') else {
            continue;
        };
        let cols: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        if cols.len() < 10 {
            continue;
        }
        rx_b = rx_b.saturating_add(cols[0]);
        rx_p = rx_p.saturating_add(cols[1]);
        tx_b = tx_b.saturating_add(cols[8]);
        tx_p = tx_p.saturating_add(cols[9]);
    }
    let now = std::time::Instant::now();
    let out = if let Some((prxb, ptxb, prxp, ptxp, t0)) = *prev {
        let dt = now.duration_since(t0).as_secs_f64().max(1e-3);
        (
            (tx_p.saturating_sub(ptxp)) as f64 / dt,
            (rx_p.saturating_sub(prxp)) as f64 / dt,
            (tx_b.saturating_sub(ptxb)) as f64 / dt,
            (rx_b.saturating_sub(prxb)) as f64 / dt,
        )
    } else {
        (0.0, 0.0, 0.0, 0.0)
    };
    *prev = Some((rx_b, tx_b, rx_p, tx_p, now));
    Ok(out)
}
