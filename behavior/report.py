"""Generate Markdown + HTML behavior reports grouped by connection sessions."""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

import behavior_config as cfg
from .events import BehaviorEvent, EventBus
from .highlights import score_session


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def build_report(bus: EventBus, target: str) -> tuple[str, str]:
    events = bus.snapshot()
    sessions = bus.session_map()
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md_lines = [
        f"# Behavior Analysis Report",
        "",
        f"**{cfg.TOOL_SIGNATURE}**",
        "",
        f"- **Tool:** {cfg.TOOL_NAME}",
        f"- **Target:** `{target}`",
        f"- **Generated:** {generated}",
        f"- **Total events:** {len(events)}",
        f"- **Connection sessions:** {len(sessions)}",
        "",
        "## Executive highlights",
        "",
    ]

    all_flags: list[str] = []
    session_scores: list[tuple[str, dict]] = []
    for sid, evs in sessions.items():
        score = score_session(evs)
        session_scores.append((sid, score))
        all_flags.extend(score["flags"])

    if all_flags:
        for flag in sorted(set(all_flags)):
            md_lines.append(f"- `{flag}`")
    else:
        md_lines.append("- No high-signal heuristic flags raised.")

    md_lines += ["", "## Connection sessions", ""]

    for sid, score in session_scores:
        evs = sessions[sid]
        net = next((e for e in evs if e.category == "network"), None)
        title = net.summary if net else sid
        md_lines.append(f"### Session `{sid}` — severity **{score['severity']}**")
        md_lines.append("")
        md_lines.append(f"**Connection:** {_md_escape(title)}")
        if score["flags"]:
            md_lines.append("")
            md_lines.append("Flags: " + ", ".join(f"`{f}`" for f in score["flags"]))
        md_lines.append("")
        md_lines.append("| Time | Category | Action | Summary |")
        md_lines.append("|---|---|---|---|")
        for e in evs:
            md_lines.append(
                f"| {e.timestamp} | {e.category} | {e.action} | {_md_escape(e.summary)} |"
            )
        md_lines.append("")

        # Sequence narrative
        if cfg.ENABLE_SEQUENCE_ANALYSIS and len(evs) > 1:
            chain = " → ".join(f"{e.action}" for e in evs[:12])
            md_lines.append(f"**Sequence:** {chain}")
            md_lines.append("")

    md_lines += ["## Full event timeline (latest first)", ""]
    for e in reversed(events[-300:]):
        mark = " **[!]**" if e.interesting else ""
        md_lines.append(f"- `{e.timestamp}` [{e.category}/{e.action}] {_md_escape(e.summary)}{mark}")

    packet_events = [e for e in events if e.category == "packet"]
    md_lines += ["", "## Packet capture highlights", ""]
    if packet_events:
        md_lines.append(f"- Interesting packet events: **{len(packet_events)}**")
        md_lines.append(f"- Text log: `{cfg.PACKET_LOG_FILE}`")
        md_lines.append(f"- PCAP (Wireshark): `{cfg.PACKET_PCAP_FILE}`")
        md_lines.append("")
        for e in packet_events[-40:]:
            md_lines.append(f"- `{e.timestamp}` {_md_escape(e.summary)}")
    else:
        md_lines.append("- No packet highlights recorded (enable `ENABLE_PACKET_CAPTURE` + Npcap + Admin).")

    md = "\n".join(md_lines) + "\n"
    html_doc = _to_html(target, generated, events, sessions, session_scores)
    return md, html_doc


def _to_html(target, generated, events, sessions, session_scores) -> str:
    rows = []
    for e in reversed(events[-400:]):
        cls = " interesting" if e.interesting else ""
        rows.append(
            "<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (
                cls,
                html.escape(e.timestamp),
                html.escape(e.category),
                html.escape(e.action),
                html.escape(str(e.pid or "")),
                html.escape(e.summary),
            )
        )

    session_blocks = []
    for sid, score in session_scores:
        evs = sessions[sid]
        items = "".join(
            f"<li><code>{html.escape(e.timestamp)}</code> "
            f"<strong>{html.escape(e.action)}</strong> — {html.escape(e.summary)}</li>"
            for e in evs
        )
        flags = ", ".join(html.escape(f) for f in score["flags"]) or "none"
        session_blocks.append(
            f"<section class='session sev-{html.escape(score['severity'])}'>"
            f"<h3>{html.escape(sid)} "
            f"<span class='sev'>{html.escape(score['severity'])}</span></h3>"
            f"<p>Flags: {flags}</p><ol>{items}</ol></section>"
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>Behavior Report — {html.escape(target)}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:2rem;background:#0f1418;color:#e8eef2}}
h1,h2,h3{{letter-spacing:-.02em}} a{{color:#2dd4bf}}
.meta{{color:#9aabb6}} table{{border-collapse:collapse;width:100%;font-size:.9rem}}
td,th{{border-bottom:1px solid #2a353e;padding:.45rem .5rem;text-align:left;vertical-align:top}}
tr.interesting{{background:#2a2114}}
.session{{border:1px solid #2a353e;padding:1rem;margin:1rem 0;background:#171e24}}
.sev{{font-size:.75rem;padding:.1rem .4rem;border:1px solid #2a353e;margin-left:.4rem}}
.sev-high .sev{{color:#f87171}} .sev-medium .sev{{color:#fbbf24}} .sev-low .sev{{color:#4ade80}}
.brand{{margin-top:2rem;padding-top:1rem;border-top:1px solid #2a353e;color:#9aabb6;font-size:.9rem}}
.brand strong{{color:#2dd4bf}}
</style></head><body>
<h1>Behavior Analysis Report</h1>
<p class="meta"><strong>{html.escape(cfg.TOOL_SIGNATURE)}</strong> · {html.escape(cfg.TOOL_NAME)}</p>
<p class="meta">Target: <strong>{html.escape(target)}</strong> · Generated: {html.escape(generated)} · Events: {len(events)}</p>
<h2>Sessions</h2>
{''.join(session_blocks) or '<p class="meta">No connection sessions recorded.</p>'}
<h2>Timeline</h2>
<table><thead><tr><th>Time</th><th>Category</th><th>Action</th><th>PID</th><th>Summary</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p class="brand"><strong>Tool made by Osidev</strong></p>
</body></html>
"""


def write_reports(bus: EventBus, target: str) -> tuple[Path, Path]:
    cfg.LOG_DIR.mkdir(parents=True, exist_ok=True)
    md, html_doc = build_report(bus, target)
    cfg.REPORT_MARKDOWN.write_text(md, encoding="utf-8")
    cfg.REPORT_HTML.write_text(html_doc, encoding="utf-8")
    return cfg.REPORT_MARKDOWN, cfg.REPORT_HTML
