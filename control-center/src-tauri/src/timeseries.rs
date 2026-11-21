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

/// Default cap for a single full-width chart (~viewport width).
pub const DEFAULT_MAX_POINTS: usize = 1000;

/// Stride-downsample so series length never exceeds `max_points`.
/// Always keeps the first and last samples when truncating.
pub fn downsample(mut pts: Vec<Point>, max_points: usize) -> Vec<Point> {
    if max_points == 0 || pts.len() <= max_points {
        return pts;
    }
    let n = pts.len();
    let step = n.div_ceil(max_points).max(1);
    let mut out: Vec<Point> = pts.iter().step_by(step).cloned().collect();
    // Ensure the newest point is present (step_by may skip the last).
    if let Some(last) = pts.pop() {
        if out.last().map(|p| p.ts) != Some(last.ts) {
            if out.len() >= max_points {
                out.pop();
            }
            out.push(last);
        }
    }
    if out.len() > max_points {
        out.truncate(max_points);
    }
    out
}

pub fn query(
    path: &Path,
    metric: &str,
    range: &str,
    now: f64,
    max_points: Option<usize>,
) -> Result<Vec<Point>, String> {
    let table = table_for(range).ok_or_else(|| format!("unknown range {range:?}"))?;
    let secs = range_seconds(range).ok_or_else(|| format!("unknown range {range:?}"))?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn = open(path)?;
    let start = (now - secs) as i64;
    let pts = query_with_conn(&conn, table, metric, start)?;
    Ok(downsample(pts, max_points.unwrap_or(DEFAULT_MAX_POINTS)))
}

fn query_with_conn(
    conn: &Connection,
    table: &str,
    metric: &str,
    start: i64,
) -> Result<Vec<Point>, String> {
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
        "SELECT ts, value, value, value, 1 FROM raw WHERE metric = ?1 AND ts >= ?2 ORDER BY ts"
            .to_string()
    } else {
        format!("SELECT ts, avg, min, max, n FROM {table} WHERE metric = ?1 AND ts >= ?2 ORDER BY ts")
    };
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![metric, start], map)
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())
}

/// One SQLite open for many metrics (Charts poll path).
pub fn query_many(
    path: &Path,
    metrics: &[String],
    range: &str,
    now: f64,
    max_points: Option<usize>,
    after_ts: Option<f64>,
) -> Result<std::collections::HashMap<String, Vec<Point>>, String> {
    let table = table_for(range).ok_or_else(|| format!("unknown range {range:?}"))?;
    let secs = range_seconds(range).ok_or_else(|| format!("unknown range {range:?}"))?;
    let cap = max_points.unwrap_or(DEFAULT_MAX_POINTS);
    let mut out = std::collections::HashMap::new();
    if !path.exists() {
        for m in metrics {
            out.insert(m.clone(), Vec::new());
        }
        return Ok(out);
    }
    let conn = open(path)?;
    let range_start = (now - secs) as i64;
    let start = match after_ts {
        Some(after) => range_start.max(after.floor() as i64 + 1),
        None => range_start,
    };
    for m in metrics {
        let pts = query_with_conn(&conn, table, m, start)?;
        // Tail fetches are small — skip stride when after_ts is set.
        out.insert(
            m.clone(),
            if after_ts.is_some() {
                pts
            } else {
                downsample(pts, cap)
            },
        );
    }
    Ok(out)
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

/// Points with `ts > after_ts` within the range window (for incremental chart tail).
pub fn query_after(
    path: &Path,
    metric: &str,
    range: &str,
    now: f64,
    after_ts: f64,
    max_points: Option<usize>,
) -> Result<Vec<Point>, String> {
    let table = table_for(range).ok_or_else(|| format!("unknown range {range:?}"))?;
    let secs = range_seconds(range).ok_or_else(|| format!("unknown range {range:?}"))?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let conn = open(path)?;
    let start = (now - secs) as i64;
    let after = after_ts.floor() as i64;
    let window_start = start.max(after + 1);
    let pts = query_with_conn(&conn, table, metric, window_start)?;
    Ok(downsample(pts, max_points.unwrap_or(DEFAULT_MAX_POINTS)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(ts: f64, v: f64) -> Point {
        Point {
            ts,
            avg: v,
            min: v,
            max: v,
            n: 1,
        }
    }

    #[test]
    fn downsample_noop_when_under_cap() {
        let pts: Vec<_> = (0..10).map(|i| pt(i as f64, i as f64)).collect();
        assert_eq!(downsample(pts.clone(), 100).len(), 10);
        assert_eq!(downsample(pts, 0).len(), 10);
    }

    #[test]
    fn downsample_caps_and_keeps_last() {
        let pts: Vec<_> = (0..1000).map(|i| pt(i as f64, i as f64)).collect();
        let out = downsample(pts, 100);
        assert!(out.len() <= 100);
        assert_eq!(out.last().map(|p| p.ts), Some(999.0));
        assert_eq!(out.first().map(|p| p.ts), Some(0.0));
    }
}
