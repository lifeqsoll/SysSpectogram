//! Read-only access to state/timeseries.sqlite (written by the guard).

use std::path::Path;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct Point {
    pub ts: f64,
    pub avg: f64,
    pub min: f64,
    pub max: f64,
    pub n: i64,
}

#[derive(Serialize, Clone, Debug)]
pub struct Latest {
    pub metric: String,
    pub ts: f64,
    pub value: f64,
}

/// Range name -> seconds. Must match sysspectogram/timeseries/store.py RANGES.
pub const RANGES: &[(&str, f64)] = &[
    ("1h", 3600.0),
    ("6h", 6.0 * 3600.0),
    ("12h", 12.0 * 3600.0),
    ("24h", 24.0 * 3600.0),
    ("7d", 7.0 * 86400.0),
    ("30d", 30.0 * 86400.0),
];

/// Range -> table. Must match _RANGE_LEVEL in store.py. Only these static names are
/// ever interpolated into SQL.
fn table_for(range: &str) -> Option<&'static str> {
    match range {
        "1h" => Some("raw"),
        "6h" | "12h" => Some("r10s"),
        "24h" | "7d" => Some("r1m"),
        "30d" => Some("r5m"),
        _ => None,
    }
}

fn range_seconds(range: &str) -> Option<f64> {
    RANGES.iter().find(|(r, _)| *r == range).map(|(_, s)| *s)
}

fn open(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open {}: {e}", path.display()))
}

pub fn query(path: &Path, metric: &str, range: &str, now: f64) -> Result<Vec<Point>, String> {
    let table = table_for(range).ok_or_else(|| format!("unknown range {range:?}"))?;
    let secs = range_seconds(range).ok_or_else(|| format!("unknown range {range:?}"))?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn = open(path)?;
    let start = (now - secs) as i64;
    let map = |row: &rusqlite::Row<'_>| -> rusqlite::Result<Point> {
        Ok(Point {
            ts: row.get::<_, i64>(0)? as f64,
            avg: row.get(1)?,
            min: row.get(2)?,
            max: row.get(3)?,
            n: row.get(4)?,
        })
    };
    let sql = if table == "raw" {
        "SELECT ts, value, value, value, 1 FROM raw WHERE metric = ?1 AND ts >= ?2 ORDER BY ts".to_string()
    } else {
        format!("SELECT ts, avg, min, max, n FROM {table} WHERE metric = ?1 AND ts >= ?2 ORDER BY ts")
    };
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![metric, start], map)
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())
}

pub fn latest(path: &Path, metrics: &[&str]) -> Result<Vec<Latest>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn = open(path)?;
    let mut out = Vec::new();
    for metric in metrics {
        let row = conn
            .query_row(
                "SELECT ts, value FROM raw WHERE metric = ?1 ORDER BY ts DESC LIMIT 1",
                params![metric],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some((ts, value)) = row {
            out.push(Latest {
                metric: (*metric).to_string(),
                ts: ts as f64,
                value,
            });
        }
    }
    Ok(out)
}

pub fn metrics(path: &Path) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn = open(path)?;
    let mut stmt = conn
        .prepare("SELECT DISTINCT metric FROM raw ORDER BY metric")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())
}
