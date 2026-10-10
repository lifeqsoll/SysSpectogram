"""Incident reports in Markdown and self-contained HTML (no external assets)."""

from __future__ import annotations

import base64
import html
from datetime import datetime, timezone
from typing import Any, Mapping


def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_markdown(inc: Mapping[str, Any]) -> str:
    lines = [
        f"# Incident {inc.get('id')}",
        "",
        f"- Host: `{inc.get('host_id') or '-'}`",
        f"- First seen: {_fmt_ts(inc.get('first_ts'))}",
        f"- Last seen: {_fmt_ts(inc.get('last_ts'))}",
        f"- Severity: **{inc.get('severity')}**",
        f"- Max risk: {inc.get('risk_max') if inc.get('risk_max') is not None else 'n/a'}",
        f"- Events: {inc.get('event_count')}",
        f"- Why grouped: {inc.get('reason')}",
        "",
        "## ATT&CK techniques",
        "",
    ]
    attack = inc.get("attack") or []
    if attack:
        lines += [f"- {t}" for t in attack]
    else:
        lines.append("- none mapped")
    lines += ["", f"_{inc.get('attack_note', '')}_", "", "## Entities", ""]
    entities = inc.get("entities") or {}
    if entities:
        for key, values in entities.items():
            lines.append(f"- {key}: {', '.join(str(v) for v in values)}")
    else:
        lines.append("- none")
    lines += ["", "## Timeline", "", "| Time (UTC) | Rule | Severity | Message |", "| --- | --- | --- | --- |"]
    for ev in inc.get("timeline") or []:
        msg = str(ev.get("message") or "").replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {_fmt_ts(ev.get('ts'))} | `{ev.get('rule_id')}` | {ev.get('severity')} | {msg} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_html(inc: Mapping[str, Any], spectrogram_png: bytes | None = None) -> str:
    e = html.escape
    rows = []
    for ev in inc.get("timeline") or []:
        rows.append(
            "<tr>"
            f"<td>{e(_fmt_ts(ev.get('ts')))}</td>"
            f"<td><code>{e(str(ev.get('rule_id')))}</code></td>"
            f"<td>{e(str(ev.get('severity')))}</td>"
            f"<td>{e(str(ev.get('message') or ''))}</td>"
            "</tr>"
        )
    entities = inc.get("entities") or {}
    ent_html = "".join(
        f"<li><span class=k>{e(str(k))}</span> {e(', '.join(str(v) for v in vals))}</li>"
        for k, vals in entities.items()
    ) or "<li>none</li>"
    attack = inc.get("attack") or []
    attack_html = "".join(f"<li><code>{e(t)}</code></li>" for t in attack) or "<li>none mapped</li>"
    if spectrogram_png:
        b64 = base64.b64encode(spectrogram_png).decode("ascii")
        spec_html = f'<img alt="Spectrogram snapshot" src="data:image/png;base64,{b64}">'
    else:
        spec_html = "<p class=muted>No spectrogram snapshot was stored for this incident.</p>"
    risk = inc.get("risk_max")
    risk_txt = "n/a" if risk is None else f"{float(risk):.2f}"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident {e(str(inc.get('id')))}</title>
<style>
  body {{ font: 15px/1.5 system-ui, sans-serif; margin: 2rem; color: #1d1f23; background: #fff; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 1rem; }}
  h2 {{ font-size: 1.05rem; margin: 1.6rem 0 .6rem; }}
  dl {{ display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; margin: 0; }}
  dt {{ color: #5b6068; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
  th, td {{ border-bottom: 1px solid #e3e5e8; padding: .4rem .5rem; text-align: left; vertical-align: top; }}
  code {{ font: 13px ui-monospace, monospace; }}
  ul {{ margin: 0; padding-left: 1.2rem; }}
  .k {{ color: #5b6068; margin-right: .4rem; }}
  .muted {{ color: #5b6068; }}
  img {{ max-width: 100%; border: 1px solid #e3e5e8; }}
</style>
</head>
<body>
<h1>Incident <code>{e(str(inc.get('id')))}</code></h1>
<dl>
  <dt>Host</dt><dd>{e(str(inc.get('host_id') or '-'))}</dd>
  <dt>First seen</dt><dd>{e(_fmt_ts(inc.get('first_ts')))}</dd>
  <dt>Last seen</dt><dd>{e(_fmt_ts(inc.get('last_ts')))}</dd>
  <dt>Severity</dt><dd>{e(str(inc.get('severity')))}</dd>
  <dt>Max risk</dt><dd>{e(risk_txt)}</dd>
  <dt>Events</dt><dd>{e(str(inc.get('event_count')))}</dd>
  <dt>Why grouped</dt><dd>{e(str(inc.get('reason')))}</dd>
</dl>
<h2>Spectrogram snapshot</h2>
{spec_html}
<h2>ATT&amp;CK techniques</h2>
<ul>{attack_html}</ul>
<p class=muted>{e(str(inc.get('attack_note', '')))}</p>
<h2>Entities</h2>
<ul>{ent_html}</ul>
<h2>Timeline</h2>
<table>
<thead><tr><th>Time (UTC)</th><th>Rule</th><th>Severity</th><th>Message</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<p class=muted>This report correlates heuristic signals. It is not a verdict.</p>
</body>
</html>
"""
