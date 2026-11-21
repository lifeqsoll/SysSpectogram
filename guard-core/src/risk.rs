//! Host/agent risk fusion — parity with `sysspectogram.risk.decide_risk`.

use serde::Serialize;

pub const DEFAULT_AGENT_HALF_LIFE_SEC: f64 = 60.0;

const CRITICAL_KIRK_RULES: &[&str] = &[
    "agent_kirk_module_hide",
    "agent_kirk_pid_hide",
    "agent_kirk_symbol_drift",
    "agent_kirk_ima_mismatch",
    "agent_kirk_agent_down",
];

pub fn decay_agent_score(score: f64, age_sec: Option<f64>, half_life_sec: f64) -> f64 {
    match age_sec {
        None => score,
        Some(_) if half_life_sec <= 0.0 => score,
        Some(age) => {
            let age = age.max(0.0);
            score * (-std::f64::consts::LN_2 * age / half_life_sec).exp()
        }
    }
}

pub fn fuse_host_agent(
    host_score: f64,
    agent_score: Option<f64>,
    host_weight: f64,
    agent_weight: f64,
) -> f64 {
    match agent_score {
        None => host_score,
        Some(agent) => {
            let total = host_weight + agent_weight;
            if total <= 0.0 {
                return host_score;
            }
            let wh = host_weight / total;
            let wa = agent_weight / total;
            wh * host_score + wa * agent
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RiskDecision {
    pub risk: f64,
    pub is_anomaly: bool,
    pub reason: String,
    pub baseline_z: Option<f64>,
    pub baseline_promoted: bool,
}

pub fn decide_risk(
    host_score: f64,
    agent_score: Option<f64>,
    agent_age_sec: Option<f64>,
    host_threshold: f64,
    risk_threshold: f64,
    host_weight: f64,
    agent_weight: f64,
    agent_half_life_sec: f64,
    baseline_z: Option<f64>,
    baseline_alert: Option<bool>,
) -> RiskDecision {
    let decayed = agent_score.map(|s| decay_agent_score(s, agent_age_sec, agent_half_life_sec));
    let risk = fuse_host_agent(host_score, decayed, host_weight, agent_weight);
    if host_score >= host_threshold {
        return RiskDecision {
            risk,
            is_anomaly: true,
            reason: "host".into(),
            baseline_z,
            baseline_promoted: false,
        };
    }
    if risk >= risk_threshold {
        return RiskDecision {
            risk,
            is_anomaly: true,
            reason: "fused".into(),
            baseline_z,
            baseline_promoted: false,
        };
    }
    let can_promote = baseline_alert == Some(true)
        && baseline_z.is_some_and(|z| z.is_finite())
        && host_score.is_finite();
    if can_promote {
        return RiskDecision {
            risk,
            is_anomaly: true,
            reason: "baseline".into(),
            baseline_z,
            baseline_promoted: true,
        };
    }
    RiskDecision {
        risk,
        is_anomaly: false,
        reason: "none".into(),
        baseline_z,
        baseline_promoted: false,
    }
}

pub fn apply_kirk_override(
    risk: f64,
    rule_id: Option<&str>,
    severity: Option<&str>,
    risk_threshold: f64,
    eps: f64,
) -> f64 {
    let rid = rule_id.unwrap_or("").trim();
    let sev = severity.unwrap_or("").trim().to_ascii_lowercase();
    let hit = CRITICAL_KIRK_RULES.contains(&rid) && (sev == "critical" || sev == "high");
    if !hit {
        return risk;
    }
    risk.max(risk_threshold + eps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_gate_fires() {
        let d = decide_risk(
            0.9, None, None, 0.7, 0.8, 0.6, 0.4, 60.0, None, None,
        );
        assert!(d.is_anomaly);
        assert_eq!(d.reason, "host");
    }

    #[test]
    fn fused_gate() {
        let d = decide_risk(
            0.5,
            Some(0.95),
            Some(0.0),
            0.9,
            0.6,
            0.5,
            0.5,
            60.0,
            None,
            None,
        );
        assert!(d.is_anomaly);
        assert_eq!(d.reason, "fused");
    }

    #[test]
    fn baseline_promotes_only() {
        let d = decide_risk(
            0.1, None, None, 0.9, 0.9, 0.6, 0.4, 60.0, Some(4.0), Some(true),
        );
        assert!(d.is_anomaly && d.baseline_promoted);
        assert_eq!(d.reason, "baseline");
    }

    #[test]
    fn kirk_override() {
        let r = apply_kirk_override(0.1, Some("agent_kirk_pid_hide"), Some("critical"), 0.7, 0.05);
        assert!(r >= 0.75);
    }
}
