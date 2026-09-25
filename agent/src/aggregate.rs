use crate::types::{now_unix, AgentAlert, EventKind, RawEvent};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct PidSnapshot {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub execs: u32,
    pub sensitive_opens: HashSet<String>,
    pub connect_hints: u32,
}

pub struct Aggregator {
    by_pid: HashMap<u32, PidSnapshot>,
}

impl Aggregator {
    pub fn new() -> Self {
        Self {
            by_pid: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, ev: RawEvent) {
        let e = self.by_pid.entry(ev.pid).or_insert_with(|| PidSnapshot {
            pid: ev.pid,
            ppid: ev.ppid,
            comm: ev.comm.clone(),
            execs: 0,
            sensitive_opens: HashSet::new(),
            connect_hints: 0,
        });
        e.ppid = ev.ppid;
        if !ev.comm.is_empty() {
            e.comm = ev.comm;
        }
        match ev.kind {
            EventKind::Exec => e.execs = e.execs.saturating_add(1),
            EventKind::OpenSensitive => {
                if let Some(p) = ev.path {
                    e.sensitive_opens.insert(p);
                }
            }
            EventKind::ConnectBurst => e.connect_hints = e.connect_hints.saturating_add(1),
        }
    }

    pub fn flush(&mut self) -> Vec<PidSnapshot> {
        std::mem::take(&mut self.by_pid).into_values().collect()
    }
}

pub fn alert_from_snapshot(
    snap: &PidSnapshot,
    rule_id: &str,
    severity: &str,
    message: String,
    host_id: &str,
    path: Option<String>,
) -> AgentAlert {
    let mut a = AgentAlert::new(rule_id, severity, message, host_id);
    a.ts = now_unix();
    a.pid = Some(snap.pid);
    a.ppid = Some(snap.ppid);
    a.comm = Some(snap.comm.clone());
    a.path = path;
    a
}
