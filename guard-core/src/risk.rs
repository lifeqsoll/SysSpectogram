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

/// Inputs for [`decide_risk`] (keeps the call site under clippy's arg limit).
#[derive(Debug, Clone, Copy)]
pub struct RiskInputs {
    pub host_score: f64,
    pub agent_score: Option<f64>,
    pub agent_age_sec: Option<f64>,
    pub host_threshold: f64,
    pub risk_threshold: f64,
    pub host_weight: f64,
    pub agent_weight: f64,
    pub agent_half_life_sec: f64,
    pub baseline_z: Option<f64>,
    pub baseline_alert: Option<bool>,
}

pub fn decide_risk(inputs: RiskInputs) -> RiskDecision {
    let decayed = inputs
        .agent_score
        .map(|s| decay_agent_score(s, inputs.agent_age_sec, inputs.agent_half_life_sec));
    let risk = fuse_host_agent(
        inputs.host_score,
        decayed,
        inputs.host_weight,
        inputs.agent_weight,
    );
    if inputs.host_score >= inputs.host_threshold {
        return RiskDecision {
            risk,
            is_anomaly: true,
            reason: "host".into(),
            baseline_z: inputs.baseline_z,
            baseline_promoted: false,
        };
    }
    if risk >= inputs.risk_threshold {
        return RiskDecision {
            risk,
            is_anomaly: true,
            reason: "fused".into(),
            baseline_z: inputs.baseline_z,
            baseline_promoted: false,
        };
    }
    let can_promote = inputs.baseline_alert == Some(true)
        && inputs.baseline_z.is_some_and(|z| z.is_finite())
        && inputs.host_score.is_finite();
    if can_promote {
        return RiskDecision {
            risk,
            is_anomaly: true,
            reason: "baseline".into(),
            baseline_z: inputs.baseline_z,
            baseline_promoted: true,
        };
    }
    RiskDecision {
        risk,
        is_anomaly: false,
        reason: "none".into(),
        baseline_z: inputs.baseline_z,
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
        let d = decide_risk(RiskInputs {
            host_score: 0.9,
            agent_score: None,
            agent_age_sec: None,
            host_threshold: 0.7,
            risk_threshold: 0.8,
            host_weight: 0.6,
            agent_weight: 0.4,
            agent_half_life_sec: 60.0,
            baseline_z: None,
            baseline_alert: None,
        });
        assert!(d.is_anomaly);
        assert_eq!(d.reason, "host");
    }

    #[test]
    fn fused_gate() {
        let d = decide_risk(RiskInputs {
            host_score: 0.5,
            agent_score: Some(0.95),
            agent_age_sec: Some(0.0),
            host_threshold: 0.9,
            risk_threshold: 0.6,
            host_weight: 0.5,
            agent_weight: 0.5,
            agent_half_life_sec: 60.0,
            baseline_z: None,
            baseline_alert: None,
        });
        assert!(d.is_anomaly);
        assert_eq!(d.reason, "fused");
    }

    #[test]
    fn baseline_promotes_only() {
        let d = decide_risk(RiskInputs {
            host_score: 0.1,
            agent_score: None,
            agent_age_sec: None,
            host_threshold: 0.9,
            risk_threshold: 0.9,
            host_weight: 0.6,
            agent_weight: 0.4,
            agent_half_life_sec: 60.0,
            baseline_z: Some(4.0),
            baseline_alert: Some(true),
        });
        assert!(d.is_anomaly && d.baseline_promoted);
        assert_eq!(d.reason, "baseline");
    }

    #[test]
    fn kirk_override() {
        let r = apply_kirk_override(0.1, Some("agent_kirk_pid_hide"), Some("critical"), 0.7, 0.05);
        assert!(r >= 0.75);
    }
}
