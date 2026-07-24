"""
Professional Markdown + HTML behavior reports with Plotly charts.

Generates:
  - Timeline of events
  - Category distribution
  - Severity breakdown of correlated sessions
  - Suspicious highlights table

Falls back to static HTML if plotly is not installed.

Tool made by Osidev
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path

import behavior_config as cfg
from .correlation import CorrelationEngine
from .events import BehaviorEvent, EventBus
from .highlights import score_session


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def _plotly_figures(events: list[BehaviorEvent], scored_sessions: list[dict]) -> str:
    """Return HTML snippet with embedded Plotly charts (CDN)."""
    if not cfg.ENABLE_ADVANCED_REPORT:
        return ""
    try:
        import plotly.graph_objects as go
        import plotly.io as pio
    except ImportError:
        return "<p class='meta'>Install <code>plotly</code> for interactive charts: pip install plotly</p>"

    # Timeline
    times = [e.timestamp for e in events[-400:]]
    cats = [e.category for e in events[-400:]]
    summaries = [e.summary[:80] for e in events[-400:]]
    colors = {
        "network": "#2dd4bf", "packet": "#38bdf8", "process": "#a3e635",
        "file": "#fbbf24", "registry": "#fb923c", "dns": "#c084fc",
        "etw": "#f472b6", "frida": "#f87171", "memory": "#94a3b8", "system": "#64748b",
    }
    marker_colors = [colors.get(c, "#94a3b8") for c in cats]

    fig_timeline = go.Figure(data=[go.Scatter(
        x=list(range(len(times))),
        y=cats,
        mode="markers",
        marker=dict(size=9, color=marker_colors),
        text=[f"{t}<br>{s}" for t, s in zip(times, summaries)],
        hoverinfo="text",
    )])
    fig_timeline.update_layout(
        title="Event timeline (category sequence)",
        template="plotly_dark",
        height=360,
        margin=dict(l=40, r=20, t=50, b=40),
        paper_bgcolor="#0f1418",
        plot_bgcolor="#171e24",
        font=dict(color="#e8eef2"),
    )

    cat_counts = Counter(e.category for e in events)
    fig_cats = go.Figure(data=[go.Bar(
        x=list(cat_counts.keys()),
        y=list(cat_counts.values()),
        marker_color="#2dd4bf",
    )])
    fig_cats.update_layout(
        title="Events by category",
        template="plotly_dark",
        height=320,
        margin=dict(l=40, r=20, t=50, b=40),
        paper_bgcolor="#0f1418",
        plot_bgcolor="#171e24",
        font=dict(color="#e8eef2"),
    )

    sev_counts = Counter(s["severity"] for s in scored_sessions) or Counter({"none": 1})
    fig_sev = go.Figure(data=[go.Pie(
        labels=list(sev_counts.keys()),
        values=list(sev_counts.values()),
        hole=0.45,
        marker=dict(colors=["#f87171", "#fbbf24", "#4ade80", "#64748b"]),
    )])
    fig_sev.update_layout(
        title="Session severity",
        template="plotly_dark",
        height=320,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor="#0f1418",
        font=dict(color="#e8eef2"),
    )

    parts = [
        pio.to_html(fig_timeline, full_html=False, include_plotlyjs="cdn"),
        pio.to_html(fig_cats, full_html=False, include_plotlyjs=False),
        pio.to_html(fig_sev, full_html=False, include_plotlyjs=False),
    ]
    return "\n".join(f"<div class='chart'>{p}</div>" for p in parts)


def build_report(bus: EventBus, target: str) -> tuple[str, str]:
    events = bus.snapshot()
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    engine = CorrelationEngine()
    if cfg.ENABLE_CORRELATION_ENGINE:
        engine.rebuild(events)
        scored = engine.scored_sessions()
    else:
        # Fallback: use bus sessions
        scored = []
        for sid, evs in bus.session_map().items():
            score = score_session(evs)
            scored.append({
                "session_id": sid,
                "summary": evs[0].summary if evs else sid,
                "pid": evs[0].pid if evs else None,
                "process": evs[0].process if evs else None,
                "remote_ips": [],
                "domains": [],
                "tags": [],
                "event_count": len(evs),
                "flags": score["flags"],
                "severity": score["severity"],
                "events": evs,
            })

    interesting = [e for e in events if e.interesting]
    all_flags: list[str] = []
    for s in scored:
        all_flags.extend(s.get("flags") or [])

    md_lines = [
        f"# Behavior Analysis Report",
        "",
        f"**{cfg.TOOL_SIGNATURE}** · {cfg.TOOL_NAME} v{getattr(cfg, 'TOOL_VERSION', '2.0')}",
        "",
        f"- **Target:** `{target}`",
        f"- **Generated:** {generated}",
        f"- **Total events:** {len(events)}",
        f"- **Correlated sessions:** {len(scored)}",
        f"- **Interesting events:** {len(interesting)}",
        "",
        "## Executive highlights",
        "",
    ]
    if all_flags:
        for flag in sorted(set(all_flags)):
            md_lines.append(f"- `{flag}`")
    else:
        md_lines.append("- No high-signal heuristic flags raised.")

    md_lines += ["", "## Correlated behavior sessions", ""]
    for s in scored[:40]:
        md_lines.append(
            f"### `{s['session_id']}` — **{s['severity']}** "
            f"({s['event_count']} events)"
        )
        md_lines.append("")
        md_lines.append(f"**Seed:** {_md_escape(s.get('summary') or '')}")
        if s.get("process"):
            md_lines.append(f"**Process:** {s['process']} (PID {s.get('pid')})")
        if s.get("domains"):
            md_lines.append("**Domains:** " + ", ".join(f"`{d}`" for d in s["domains"][:12]))
        if s.get("remote_ips"):
            md_lines.append("**IPs:** " + ", ".join(f"`{ip}`" for ip in s["remote_ips"][:12]))
        if s.get("flags"):
            md_lines.append("**Flags:** " + ", ".join(f"`{f}`" for f in s["flags"]))
        md_lines.append("")
        md_lines.append("| Time | Category | Action | Summary |")
        md_lines.append("|---|---|---|---|")
        for e in s["events"][:30]:
            md_lines.append(
                f"| {e.timestamp} | {e.category} | {e.action} | {_md_escape(e.summary)} |"
            )
        md_lines.append("")
        if cfg.ENABLE_SEQUENCE_ANALYSIS and len(s["events"]) > 1:
            chain = " → ".join(e.action for e in s["events"][:16])
            md_lines.append(f"**Sequence:** {chain}")
            md_lines.append("")

    md_lines += ["## Suspicious / interesting events", ""]
    for e in interesting[-80:]:
        md_lines.append(f"- `{e.timestamp}` [{e.category}/{e.action}] {_md_escape(e.summary)}")

    md_lines += ["", "## Full timeline (latest first)", ""]
    for e in reversed(events[-300:]):
        mark = " **[!]**" if e.interesting else ""
        md_lines.append(f"- `{e.timestamp}` [{e.category}/{e.action}] {_md_escape(e.summary)}{mark}")

    packet_events = [e for e in events if e.category == "packet"]
    md_lines += ["", "## Packet capture", ""]
    md_lines.append(f"- Interesting packet events: **{len(packet_events)}**")
    md_lines.append(f"- Log: `{cfg.PACKET_LOG_FILE}`")
    md_lines.append(f"- PCAP: `{cfg.PACKET_PCAP_FILE}`")

    md = "\n".join(md_lines) + "\n"
    html_doc = _to_html(target, generated, events, scored, interesting)
    return md, html_doc


def _to_html(target, generated, events, scored_sessions, interesting) -> str:
    charts = _plotly_figures(events, scored_sessions)

    session_blocks = []
    for s in scored_sessions[:30]:
        items = "".join(
            f"<li><code>{html.escape(e.timestamp)}</code> "
            f"<span class='cat'>{html.escape(e.category)}</span> "
            f"<strong>{html.escape(e.action)}</strong> — {html.escape(e.summary)}</li>"
            for e in s["events"][:25]
        )
        flags = ", ".join(html.escape(f) for f in (s.get("flags") or [])) or "none"
        domains = ", ".join(html.escape(d) for d in (s.get("domains") or [])[:8]) or "—"
        session_blocks.append(
            f"<section class='session sev-{html.escape(s['severity'])}'>"
            f"<h3>{html.escape(s['session_id'])} "
            f"<span class='sev'>{html.escape(s['severity'])}</span></h3>"
            f"<p>{html.escape(s.get('summary') or '')}</p>"
            f"<p class='meta'>Process: {html.escape(str(s.get('process') or '—'))} · "
            f"PID {html.escape(str(s.get('pid') or '—'))} · Domains: {domains}</p>"
            f"<p>Flags: {flags}</p><ol>{items}</ol></section>"
        )

    interest_rows = "".join(
        "<tr class='interesting'><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (
            html.escape(e.timestamp),
            html.escape(e.category),
            html.escape(e.action),
            html.escape(e.summary),
        )
        for e in interesting[-100:]
    )

    timeline_rows = "".join(
        "<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (
            "interesting" if e.interesting else "",
            html.escape(e.timestamp),
            html.escape(e.category),
            html.escape(e.action),
            html.escape(str(e.pid or "")),
            html.escape(e.summary),
        )
        for e in reversed(events[-400:])
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>Osidev Behavior Report — {html.escape(target)}</title>
<meta name="generator" content="Osidev Monitoring"/>
<style>
:root {{ --bg:#0f1418; --panel:#171e24; --ink:#e8eef2; --muted:#9aabb6; --line:#2a353e; --accent:#2dd4bf; }}
body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:var(--bg);color:var(--ink)}}
.wrap{{max-width:1100px;margin:0 auto;padding:2rem 1.25rem 3rem}}
h1,h2,h3{{letter-spacing:-.02em}} h1{{font-size:1.9rem;margin:0 0 .4rem}}
.meta{{color:var(--muted)}} .brand{{color:var(--accent);font-weight:700}}
.hero{{border:1px solid var(--line);background:linear-gradient(135deg,#12312e,#171e24 55%);padding:1.25rem 1.4rem;margin-bottom:1.25rem}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem;margin:1rem 0 1.5rem}}
.kpi{{background:var(--panel);border:1px solid var(--line);padding:.9rem}}
.kpi span{{display:block;color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}}
.kpi strong{{font-size:1.4rem}}
.chart{{margin:1rem 0;border:1px solid var(--line);background:var(--panel);padding:.5rem}}
.session{{border:1px solid var(--line);padding:1rem;margin:1rem 0;background:var(--panel)}}
.sev{{font-size:.75rem;padding:.1rem .4rem;border:1px solid var(--line);margin-left:.4rem}}
.sev-high .sev{{color:#f87171}} .sev-medium .sev{{color:#fbbf24}} .sev-low .sev{{color:#4ade80}}
.cat{{display:inline-block;padding:.05rem .35rem;border:1px solid var(--line);font-size:.72rem;margin-right:.25rem;color:var(--accent)}}
table{{border-collapse:collapse;width:100%;font-size:.88rem}}
td,th{{border-bottom:1px solid var(--line);padding:.45rem .5rem;text-align:left;vertical-align:top}}
tr.interesting{{background:#2a2114}}
footer{{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--line);color:var(--muted)}}
@media(max-width:800px){{.kpis{{grid-template-columns:1fr 1fr}}}}
</style></head><body><div class="wrap">
<div class="hero">
  <div class="brand">{html.escape(cfg.TOOL_SIGNATURE)}</div>
  <h1>Behavior Analysis Report</h1>
  <p class="meta">{html.escape(cfg.TOOL_NAME)} v{html.escape(str(getattr(cfg,'TOOL_VERSION','2.0')))} · Target: <strong>{html.escape(target)}</strong> · {html.escape(generated)}</p>
</div>
<div class="kpis">
  <div class="kpi"><span>Events</span><strong>{len(events)}</strong></div>
  <div class="kpi"><span>Sessions</span><strong>{len(scored_sessions)}</strong></div>
  <div class="kpi"><span>Interesting</span><strong>{len(interesting)}</strong></div>
  <div class="kpi"><span>High severity</span><strong>{sum(1 for s in scored_sessions if s.get('severity')=='high')}</strong></div>
</div>
<h2>Analytics</h2>
{charts}
<h2>Correlated behavior sessions</h2>
{''.join(session_blocks) or '<p class="meta">No correlated sessions.</p>'}
<h2>Suspicious activity</h2>
<table><thead><tr><th>Time</th><th>Category</th><th>Action</th><th>Summary</th></tr></thead>
<tbody>{interest_rows or '<tr><td colspan="4">None</td></tr>'}</tbody></table>
<h2>Full timeline</h2>
<table><thead><tr><th>Time</th><th>Category</th><th>Action</th><th>PID</th><th>Summary</th></tr></thead>
<tbody>{timeline_rows}</tbody></table>
<footer><strong class="brand">Tool made by Osidev</strong> — authorized analysis only.</footer>
</div></body></html>
"""


def write_reports(bus: EventBus, target: str) -> tuple[Path, Path]:
    cfg.LOG_DIR.mkdir(parents=True, exist_ok=True)
    md, html_doc = build_report(bus, target)
    cfg.REPORT_MARKDOWN.write_text(md, encoding="utf-8")
    cfg.REPORT_HTML.write_text(html_doc, encoding="utf-8")
    return cfg.REPORT_MARKDOWN, cfg.REPORT_HTML
