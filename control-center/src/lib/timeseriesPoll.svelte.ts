/** Shared timeseries poll helpers for Charts / Dashboards. */
import { api, type Point, type Range } from './api';

export const CHART_POLL_MS = 5000;
export const DETAIL_MAX_POINTS = 1000;
export const GRID_MAX_POINTS = 300;

export function pageVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState !== 'hidden';
}

export function lastTs(points: Point[]): number | undefined {
  if (!points.length) return undefined;
  return points[points.length - 1]?.ts;
}

/** Merge full/tail series; drop points outside the rolling window if needed. */
export function appendTail(prev: Point[], tail: Point[], maxPoints = DETAIL_MAX_POINTS): Point[] {
  if (!tail.length) return prev;
  if (!prev.length) return tail;
  const cutoff = prev[prev.length - 1]?.ts ?? 0;
  const fresh = tail.filter((p) => p.ts > cutoff);
  if (!fresh.length) return prev;
  let next = prev.concat(fresh);
  if (next.length > maxPoints * 2) {
    // Keep newest maxPoints after a long session of appends.
    next = next.slice(-maxPoints);
  }
  return next;
}

export async function fetchSeries(
  metric: string,
  range: Range,
  prev: Point[],
  opts?: { maxPoints?: number; incremental?: boolean },
): Promise<Point[]> {
  const maxPoints = opts?.maxPoints ?? DETAIL_MAX_POINTS;
  const after = opts?.incremental ? lastTs(prev) : undefined;
  if (after != null) {
    const tail = await api.timeseriesQuery(metric, range, { maxPoints, afterTs: after });
    return appendTail(prev, tail, maxPoints);
  }
  return api.timeseriesQuery(metric, range, { maxPoints });
}

export async function fetchMany(
  metrics: string[],
  range: Range,
  prev: Record<string, Point[]>,
  opts?: { maxPoints?: number; incremental?: boolean },
): Promise<Record<string, Point[]>> {
  const maxPoints = opts?.maxPoints ?? GRID_MAX_POINTS;
  // Incremental many: use min last-ts across series so we don't miss points.
  let after: number | undefined;
  if (opts?.incremental) {
    let minLast: number | undefined;
    for (const id of metrics) {
      const ts = lastTs(prev[id] ?? []);
      if (ts == null) {
        minLast = undefined;
        break;
      }
      minLast = minLast == null ? ts : Math.min(minLast, ts);
    }
    after = minLast;
  }
  if (after != null) {
    const tail = await api.timeseriesQueryMany(metrics, range, { maxPoints, afterTs: after });
    const out: Record<string, Point[]> = { ...prev };
    for (const id of metrics) {
      out[id] = appendTail(prev[id] ?? [], tail[id] ?? [], maxPoints);
    }
    return out;
  }
  return api.timeseriesQueryMany(metrics, range, { maxPoints });
}
