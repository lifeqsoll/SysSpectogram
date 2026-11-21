//! Perimeter RuleEngine (auth brute, port scan, flood, egress) — parity with Python.

use crate::Alert;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug, Clone)]
pub struct RuleEngineConfig {
    pub fail_threshold: usize,
    pub fail_window_sec: f64,
    pub scan_unique_ports: usize,
    pub scan_window_sec: f64,
    pub allowlist: HashSet<String>,
    pub known_login_ips: HashSet<String>,
    pub public_ports: HashSet<u16>,
    pub listening_ports: HashSet<u16>,
    pub flood_enabled: bool,
    pub flood_ewma_alpha: f64,
    pub flood_mult: f64,
    pub flood_min_ip_per_min: f64,
    pub flood_cooldown_sec: f64,
    pub closed_port_weight: f64,
    pub alert_new_egress: bool,
    pub unusual_egress_ports: HashSet<u16>,
    pub denylist_ips: HashSet<String>,
}

impl Default for RuleEngineConfig {
    fn default() -> Self {
        Self {
            fail_threshold: 8,
            fail_window_sec: 60.0,
            scan_unique_ports: 10,
            scan_window_sec: 60.0,
            allowlist: HashSet::new(),
            known_login_ips: HashSet::new(),
            public_ports: HashSet::from([80, 443]),
            listening_ports: HashSet::new(),
            flood_enabled: true,
            flood_ewma_alpha: 0.05,
            flood_mult: 5.0,
            flood_min_ip_per_min: 2000.0,
            flood_cooldown_sec: 900.0,
            closed_port_weight: 2.0,
            alert_new_egress: false,
            unusual_egress_ports: HashSet::from([4444, 5555, 6666, 1337, 31337]),
            denylist_ips: HashSet::new(),
        }
    }
}

#[derive(Debug)]
pub struct RuleEngine {
    cfg: RuleEngineConfig,
    fails: HashMap<String, VecDeque<f64>>,
    src_ports: HashMap<String, VecDeque<(f64, u16)>>,
    port_hits: HashMap<u16, VecDeque<(f64, String)>>,
    flood_ewma: HashMap<u16, f64>,
    flood_samples: HashMap<u16, usize>,
    seen_egress: HashSet<String>,
    cooldown: HashMap<String, f64>,
    egress_bootstrapped: bool,
}

impl RuleEngine {
    pub fn new(cfg: RuleEngineConfig) -> Self {
        Self {
            cfg,
            fails: HashMap::new(),
            src_ports: HashMap::new(),
            port_hits: HashMap::new(),
            flood_ewma: HashMap::new(),
            flood_samples: HashMap::new(),
            seen_egress: HashSet::new(),
            cooldown: HashMap::new(),
            egress_bootstrapped: false,
        }
    }

    pub fn seed_egress(&mut self, keys: &[String]) {
        for k in keys {
            self.seen_egress.insert(k.clone());
        }
        self.egress_bootstrapped = true;
    }

    pub fn set_public_ports(&mut self, ports: impl IntoIterator<Item = u16>) {
        self.cfg.public_ports = ports.into_iter().collect();
    }

    pub fn set_listening_ports(&mut self, ports: impl IntoIterator<Item = u16>) {
        self.cfg.listening_ports = ports.into_iter().collect();
    }

    pub fn set_allowlist(&mut self, ips: impl IntoIterator<Item = String>) {
        self.cfg.allowlist = ips.into_iter().collect();
    }

    pub fn set_fail_threshold(&mut self, n: usize) {
        self.cfg.fail_threshold = n.max(1);
    }

    pub fn set_scan_unique_ports(&mut self, n: usize) {
        self.cfg.scan_unique_ports = n.max(1);
    }

    fn cool(&mut self, key: &str, sec: f64) -> bool {
        let now = now_ts();
        let last = self.cooldown.get(key).copied().unwrap_or(0.0);
        if now - last < sec {
            return false;
        }
        self.cooldown.insert(key.to_string(), now);
        true
    }

    pub fn on_auth_fail(&mut self, ip: &str, user: &str) -> Option<Alert> {
        if self.cfg.allowlist.contains(ip) {
            return None;
        }
        let now = now_ts();
        let key = ip.to_string();
        let q = self.fails.entry(key.clone()).or_default();
        q.push_back(now);
        while q.front().is_some_and(|t| now - t > self.cfg.fail_window_sec) {
            q.pop_front();
        }
        let n = q.len();
        if n >= self.cfg.fail_threshold && self.cool(&format!("brute:{key}"), 60.0) {
            let mut a = Alert::new(
                "bruteforce_ssh",
                "critical",
                format!(
                    "SSH brute suspected from {key}: {n} fails / {:.0}s (last={ip})",
                    self.cfg.fail_window_sec
                ),
            );
            a.ip = Some(key.clone());
            a.ts = now;
            a.extras.insert("fails".into(), serde_json::json!(n));
            a.extras.insert("user".into(), serde_json::json!(user));
            a.extras.insert("last_ip".into(), serde_json::json!(ip));
            a.extras.insert("bucket".into(), serde_json::json!(key));
            return Some(a);
        }
        None
    }

    pub fn on_auth_accepted(&mut self, ip: &str, user: &str) -> Option<Alert> {
        if self.cfg.allowlist.contains(ip) || self.cfg.known_login_ips.contains(ip) {
            self.cfg.known_login_ips.insert(ip.to_string());
            return None;
        }
        if self.cool(&format!("newlogin:{ip}"), 300.0) {
            self.cfg.known_login_ips.insert(ip.to_string());
            let mut a = Alert::new(
                "new_login_source",
                "high",
                format!("New SSH login source {ip} user={user}"),
            );
            a.ip = Some(ip.to_string());
            a.extras.insert("user".into(), serde_json::json!(user));
            return Some(a);
        }
        None
    }

    fn weighted_unique_ports(&self, hits: &VecDeque<(f64, u16)>) -> f64 {
        let mut score = 0.0;
        let mut seen = HashSet::new();
        for (_ts, port) in hits {
            if !seen.insert(*port) {
                continue;
            }
            if !self.cfg.listening_ports.is_empty() && !self.cfg.listening_ports.contains(port) {
                score += self.cfg.closed_port_weight;
            } else if !self.cfg.public_ports.contains(port)
                && !self.cfg.listening_ports.contains(port)
            {
                score += self.cfg.closed_port_weight;
            } else {
                score += 1.0;
            }
        }
        score
    }

    fn check_flood(&mut self, ip: &str, port: u16, now: f64) -> Option<Alert> {
        if !self.cfg.flood_enabled || !self.cfg.public_ports.contains(&port) {
            return None;
        }
        let q = self.port_hits.entry(port).or_default();
        q.push_back((now, ip.to_string()));
        while q.front().is_some_and(|(t, _)| now - t > 60.0) {
            q.pop_front();
        }
        let unique: HashSet<_> = q.iter().map(|(_, i)| i.clone()).collect();
        let rate = unique.len() as f64;
        let prev = self.flood_ewma.get(&port).copied();
        let samples = *self.flood_samples.get(&port).unwrap_or(&0);
        let baseline = prev.unwrap_or(rate);
        let mut alert = None;
        if samples >= 30 {
            if let Some(p) = prev {
                let threshold = (baseline * self.cfg.flood_mult).max(self.cfg.flood_min_ip_per_min);
                if rate >= threshold && rate >= self.cfg.flood_min_ip_per_min {
                    if self.cool(&format!("flood:{port}"), self.cfg.flood_cooldown_sec) {
                        let mut a = Alert::new(
                            "inbound_flood_suspected",
                            "medium",
                            format!(
                                "Inbound flood suspected on :{port}: {rate:.0} unique IPs/min (baseline≈{baseline:.0}, ×{})",
                                self.cfg.flood_mult
                            ),
                        );
                        a.port = Some(port);
                        a.ts = now;
                        a.extras
                            .insert("unique_ips".into(), serde_json::json!(rate as i64));
                        a.extras.insert("ewma".into(), serde_json::json!(baseline));
                        a.extras
                            .insert("threshold".into(), serde_json::json!(threshold));
                        alert = Some(a);
                    }
                }
                let _ = p;
            }
        }
        let alpha = self.cfg.flood_ewma_alpha;
        match prev {
            None => {
                self.flood_ewma.insert(port, rate);
            }
            Some(p) if alert.is_some() => {
                self.flood_ewma.insert(port, p);
            }
            Some(p) => {
                let soft_cap = (p * self.cfg.flood_mult).max(self.cfg.flood_min_ip_per_min);
                if rate < soft_cap {
                    self.flood_ewma
                        .insert(port, alpha * rate + (1.0 - alpha) * p);
                }
            }
        }
        self.flood_samples.insert(port, samples + 1);
        alert
    }

    pub fn on_inbound(&mut self, ip: &str, port: u16) -> Option<Alert> {
        if self.cfg.allowlist.contains(ip) {
            return None;
        }
        let now = now_ts();
        let flood = self.check_flood(ip, port, now);
        {
            let q = self.src_ports.entry(ip.to_string()).or_default();
            q.push_back((now, port));
            while q
                .front()
                .is_some_and(|(t, _)| now - t > self.cfg.scan_window_sec)
            {
                q.pop_front();
            }
        }
        let score = {
            let q = self.src_ports.get(ip).unwrap();
            self.weighted_unique_ports(q)
        };
        let unique_ports: HashSet<u16> = self
            .src_ports
            .get(ip)
            .map(|q| q.iter().map(|(_, p)| *p).collect())
            .unwrap_or_default();
        if score >= self.cfg.scan_unique_ports as f64 && self.cool(&format!("scan:{ip}"), 60.0) {
            let mut ports: Vec<u16> = unique_ports.iter().copied().collect();
            ports.sort_unstable();
            ports.truncate(40);
            let mut a = Alert::new(
                "port_scan_suspected",
                "high",
                format!(
                    "Port scan suspected from {ip}: {} unique ports / {:.0}s (score={score:.1})",
                    unique_ports.len(),
                    self.cfg.scan_window_sec
                ),
            );
            a.ip = Some(ip.to_string());
            a.port = Some(port);
            a.ts = now;
            a.extras.insert(
                "unique_ports".into(),
                serde_json::json!(unique_ports.len()),
            );
            a.extras.insert("score".into(), serde_json::json!(score));
            a.extras.insert("ports".into(), serde_json::json!(ports));
            return Some(a);
        }
        flood
    }

    pub fn on_egress(&mut self, ip: &str, port: u16, proc: Option<&str>) -> Option<Alert> {
        if self.cfg.allowlist.contains(ip) {
            return None;
        }
        let key = format!("{ip}:{port}");
        if self.cfg.denylist_ips.contains(ip) && self.cool(&format!("egressdl:{ip}"), 60.0) {
            let msg = match proc {
                Some(p) => format!("Egress to denylisted {ip}:{port} ({p})"),
                None => format!("Egress to denylisted {ip}:{port}"),
            };
            let mut a = Alert::new("egress_denylist_hit", "critical", msg);
            a.ip = Some(ip.to_string());
            a.port = Some(port);
            if let Some(p) = proc {
                a.extras.insert("process".into(), serde_json::json!(p));
            }
            return Some(a);
        }
        if !self.egress_bootstrapped {
            self.seen_egress.insert(key);
            return None;
        }
        if !self.seen_egress.contains(&key) {
            self.seen_egress.insert(key);
            let unusual = self.cfg.unusual_egress_ports.contains(&port);
            if (self.cfg.alert_new_egress || unusual)
                && self.cool(&format!("egressnew:{ip}"), 120.0)
            {
                let msg = match proc {
                    Some(p) => format!("New external egress {ip}:{port} ({p})"),
                    None => format!("New external egress {ip}:{port}"),
                };
                let mut a = Alert::new(
                    "suspicious_egress",
                    if unusual { "high" } else { "medium" },
                    msg,
                );
                a.ip = Some(ip.to_string());
                a.port = Some(port);
                a.extras
                    .insert("unusual_port".into(), serde_json::json!(unusual));
                if let Some(p) = proc {
                    a.extras.insert("process".into(), serde_json::json!(p));
                }
                return Some(a);
            }
        }
        None
    }

    pub fn on_suspicious_dns(&mut self, name: &str) -> Option<Alert> {
        let name = name.to_ascii_lowercase();
        if self.cool(&format!("dns:{name}"), 120.0) {
            let mut a = Alert::new(
                "suspicious_dns",
                "high",
                format!("Suspicious DNS query: {name}"),
            );
            a.extras.insert("domain".into(), serde_json::json!(name));
            return Some(a);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bruteforce_fires() {
        let mut eng = RuleEngine::new(RuleEngineConfig {
            fail_threshold: 5,
            ..Default::default()
        });
        let mut last = None;
        for _ in 0..5 {
            last = eng.on_auth_fail("203.0.113.20", "root");
        }
        assert_eq!(last.as_ref().map(|a| a.rule_id.as_str()), Some("bruteforce_ssh"));
    }

    #[test]
    fn allowlist_blocks_brute() {
        let mut eng = RuleEngine::new(RuleEngineConfig {
            fail_threshold: 3,
            allowlist: HashSet::from(["203.0.113.1".into()]),
            ..Default::default()
        });
        for _ in 0..5 {
            assert!(eng.on_auth_fail("203.0.113.1", "").is_none());
        }
    }

    #[test]
    fn port_scan_per_source() {
        let mut eng = RuleEngine::new(RuleEngineConfig {
            scan_unique_ports: 4,
            public_ports: HashSet::from([80, 443]),
            flood_enabled: false,
            ..Default::default()
        });
        let mut last = None;
        for port in [22u16, 23, 25, 8080] {
            if let Some(a) = eng.on_inbound("203.0.113.50", port) {
                last = Some(a);
            }
        }
        let a = last.expect("scan");
        assert_eq!(a.rule_id, "port_scan_suspected");
        assert_eq!(a.ip.as_deref(), Some("203.0.113.50"));
    }

    #[test]
    fn many_ips_on_public_not_scan() {
        let mut eng = RuleEngine::new(RuleEngineConfig {
            scan_unique_ports: 10,
            public_ports: HashSet::from([80, 443]),
            listening_ports: HashSet::from([80, 443]),
            flood_enabled: false,
            ..Default::default()
        });
        for i in 1..=200 {
            let ip = format!("192.0.2.{i}");
            if let Some(a) = eng.on_inbound(&ip, 443) {
                assert_ne!(a.rule_id, "port_scan_suspected");
            }
        }
    }
}
