//! Best-effort host CPU / memory percentages from procfs.

use std::collections::HashMap;
use std::fs;
use std::thread;
use std::time::Duration;

/// Read `/proc/stat` and `/proc/meminfo`; missing data yields `0.0` for that field.
pub fn collect_cpu_mem() -> HashMap<String, f64> {
    let mut out = HashMap::new();
    out.insert("cpu_percent".into(), cpu_percent_best_effort());
    out.insert("mem_percent".into(), mem_percent_best_effort());
    out
}

fn cpu_percent_best_effort() -> f64 {
    let Some(a) = parse_proc_stat_cpu_line() else {
        return 0.0;
    };
    thread::sleep(Duration::from_millis(100));
    let Some(b) = parse_proc_stat_cpu_line() else {
        return 0.0;
    };
    cpu_usage_between(&a, &b).unwrap_or(0.0)
}

fn parse_proc_stat_cpu_line() -> Option<Vec<u64>> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    let first = text.lines().next()?;
    if !first.starts_with("cpu ") {
        return None;
    }
    let fields: Vec<u64> = first
        .split_whitespace()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }
    Some(fields)
}

fn cpu_usage_between(a: &[u64], b: &[u64]) -> Option<f64> {
    if a.len() != b.len() {
        return None;
    }
    let idle_a = *a.get(3)?;
    let idle_b = *b.get(3)?;
    let total_a: u64 = a.iter().sum();
    let total_b: u64 = b.iter().sum();
    let total_d = total_b.saturating_sub(total_a);
    let idle_d = idle_b.saturating_sub(idle_a);
    if total_d == 0 {
        return Some(0.0);
    }
    let used = total_d.saturating_sub(idle_d);
    Some((used as f64 / total_d as f64) * 100.0)
}

fn mem_percent_best_effort() -> f64 {
    mem_percent_from_meminfo().unwrap_or(0.0)
}

fn mem_percent_from_meminfo() -> Option<f64> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb: Option<u64> = None;
    let mut avail_kb: Option<u64> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = parse_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail_kb = parse_kb(rest);
        }
    }
    let total = total_kb?;
    if total == 0 {
        return Some(0.0);
    }
    let avail = avail_kb.unwrap_or_else(|| {
        text.lines()
            .find_map(|l| l.strip_prefix("MemFree:").and_then(parse_kb))
            .unwrap_or(0)
    });
    let used = total.saturating_sub(avail);
    Some((used as f64 / total as f64) * 100.0)
}

fn parse_kb(rest: &str) -> Option<u64> {
    rest.split_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_expected_keys() {
        let m = collect_cpu_mem();
        assert!(m.contains_key("cpu_percent"));
        assert!(m.contains_key("mem_percent"));
        for v in m.values() {
            assert!(*v >= 0.0 && *v <= 100.0 || *v == 0.0);
        }
    }
}