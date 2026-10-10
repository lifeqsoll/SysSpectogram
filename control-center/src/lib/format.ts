export function fmtTime(epochSec: number): string {
  if (!epochSec) return '-';
  const d = new Date(epochSec * 1000);
  return d.toLocaleString(undefined, { hour12: false });
}

export function fmtClock(epochSec: number): string {
  const d = new Date(epochSec * 1000);
  return d.toLocaleTimeString(undefined, { hour12: false });
}

export function fmtNum(v: number | null | undefined, digits = 3): string {
  if (v === null || v === undefined || Number.isNaN(v)) return '-';
  return Number(v).toFixed(digits);
}

export function fmtBytes(v: number): string {
  if (v < 1024) return `${v.toFixed(0)} B/s`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
  return `${(v / 1024 / 1024).toFixed(2)} MB/s`;
}

export function fmtDuration(sec: number): string {
  if (sec < 60) return `${Math.round(sec)} s`;
  if (sec < 3600) return `${Math.round(sec / 60)} min`;
  return `${(sec / 3600).toFixed(1)} h`;
}
