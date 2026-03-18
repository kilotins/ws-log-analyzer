"""Report rendering: Markdown, JSON, HTML, PDF."""
from __future__ import annotations

import json
from pathlib import Path

from .parser import MAX_EVENT_TEXT
from .analysis import precompute_analysis, render_histogram, compact_histogram
from .event import LogEvent

# Section keys for toggling report content
REPORT_SECTIONS = {
    "onset": "Problem Onset",
    "files": "Per-File Breakdown",
    "levels": "Severity Distribution",
    "codes": "Message Codes",
    "exceptions": "Exceptions/Errors",
    "tags": "Signal Tags",
    "causes": "Likely Causes & Fixes",
    "splunk": "Splunk Searches",
    "hung": "Hung Thread Drilldown",
    "timeline": "Timeline",
    "samples": "Sample Events",
    "ai": "AI Analysis",
}

ALL_SECTIONS = set(REPORT_SECTIONS.keys())


def _sec(sections: set[str] | None, key: str) -> bool:
    """Check if a section should be included."""
    return sections is None or key in sections


def _report_meta(a: dict) -> tuple[str, str]:
    """Build report title and subtitle from analysis data.

    Returns:
        (title, subtitle) — e.g. ("LogPilot Analysis Report",
        "server.log, access.log — 2025-03-11 10:15 – 14:32 — 1,234 events")
    """
    from .analysis import parse_ts_datetime

    file_summary = a.get("file_summary", [])
    names = [Path(f).name for f, _, _ in file_summary]
    if len(names) <= 3:
        files_str = ", ".join(names)
    else:
        files_str = f"{names[0]}, {names[1]} + {len(names) - 2} more"

    # Extract time span from first/last event timestamps
    events = a.get("events", [])
    time_str = ""
    if events:
        first_dt = last_dt = None
        for e in events:
            if e.ts:
                dt = parse_ts_datetime(e.ts)
                if dt:
                    first_dt = dt
                    break
        for e in reversed(events):
            if e.ts:
                dt = parse_ts_datetime(e.ts)
                if dt:
                    last_dt = dt
                    break
        if first_dt and last_dt:
            fmt_time = "%H:%M"
            fmt_full = "%Y-%m-%d %H:%M"
            if first_dt.date() == last_dt.date():
                time_str = f"{first_dt.strftime(fmt_full)} – {last_dt.strftime(fmt_time)}"
            else:
                time_str = f"{first_dt.strftime(fmt_full)} – {last_dt.strftime(fmt_full)}"

    total = a.get("summary", {}).get("total_events", 0)
    parts = []
    if files_str:
        parts.append(files_str)
    if time_str:
        parts.append(time_str)
    if total:
        parts.append(f"{total:,} events")

    return "LogPilot Analysis Report", " — ".join(parts)


def render_json_report(events: list[LogEvent], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None, ai_content: dict | None = None, sections: set[str] | None = None) -> str:
    """Generate a JSON triage report string from parsed events."""
    a = _analysis or precompute_analysis(events, top_n, samples_n, hist_minutes)
    from .analysis import group_into_incidents
    s = a["summary"]
    samples = a["samples"]
    hist = a["hist"]
    file_summary = a["file_summary"]
    causes = a["causes"]
    data: dict = {
        "total_events": s["total_events"],
    }
    if _sec(sections, "files"):
        data["files"] = [{"file": f, "events": t, "errors": e} for f, t, e in file_summary]
    if _sec(sections, "levels"):
        data["levels"] = dict(s["levels"])
    if _sec(sections, "codes"):
        data["codes"] = dict(s["codes"])
    if _sec(sections, "exceptions"):
        data["exceptions"] = dict(s["exceptions"])
    if _sec(sections, "tags"):
        data["tags"] = dict(s["tags"])
    if _sec(sections, "causes"):
        data["likely_causes"] = causes
        data["incident_groups"] = group_into_incidents(causes) if causes else {"groups": [], "ungrouped": []}
    if _sec(sections, "splunk"):
        data["splunk_queries"] = a["splunk"]
    if _sec(sections, "hung"):
        data["hung_thread_drilldown"] = a["hung"]
    if _sec(sections, "timeline"):
        data["timeline"] = [{"bucket": b, "total": t, "errors": e} for b, t, e in hist]
    if _sec(sections, "samples"):
        data["samples"] = [
            {
                "level": e.level,
                "thread_id": e.thread_id,
                "code": e.code,
                "exception": e.exception,
                "root_cause": e.root_cause,
                "ts": e.ts,
                "tags": e.tags,
                "text": e.text[:MAX_EVENT_TEXT],
            }
            for e in samples
        ]
    if _sec(sections, "ai") and ai_content:
        data["ai_analysis"] = ai_content
    return json.dumps(data, indent=2)


def render_markdown_report(events: list[LogEvent], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None, ai_content: dict | None = None, sections: set[str] | None = None) -> str:
    """Generate a complete markdown triage report from parsed events."""
    a = _analysis or precompute_analysis(events, top_n, samples_n, hist_minutes)
    s = a["summary"]
    samples = a["samples"]
    hist = a["hist"]
    file_summary = a["file_summary"]

    md: list[str] = []
    _title, _subtitle = _report_meta(a)
    md.append(f"# {_title}")
    if _subtitle:
        md.append(f"*{_subtitle}*")
    md.append("")
    md.append(f"- Files: {len(file_summary)}")
    md.append(f"- Parsed events: {s['total_events']}")

    # Problem onset
    if _sec(sections, "onset"):
        itl = a.get("incident_timeline")
        if itl:
            trigger = itl.get("trigger_event", {})
            trigger_dt = itl.get("trigger_dt")
            if trigger_dt:
                _t_parts = [trigger.get("level", "ERROR")]
                if trigger.get("code"):
                    _t_parts.append(trigger["code"])
                if trigger.get("exception"):
                    _t_parts.append(trigger["exception"].rsplit(".", 1)[-1])
                md.append(f"- **Problem onset: {trigger_dt.strftime('%Y-%m-%d %H:%M:%S')}** — {' '.join(_t_parts)}")

    md.append("")

    if _sec(sections, "files") and len(file_summary) > 1:
        md.append("## Per-File Breakdown")
        for fname, total, errors in file_summary:
            err_note = f" ({errors} errors)" if errors else ""
            md.append(f"- `{fname}`: {total} events{err_note}")
        md.append("")

    if _sec(sections, "levels"):
        md.append("## Top Levels")
        md += [f"- **{k}**: {v}" for k, v in s["levels"]]
        md.append("")
    if _sec(sections, "codes"):
        md.append("## Top WebSphere/Liberty Codes")
        md += [f"- `{k}`: {v}" for k, v in s["codes"]] or ["- _(none detected)_"]
        md.append("")
    if _sec(sections, "exceptions"):
        md.append("## Top Exceptions/Errors")
        md += [f"- `{k}`: {v}" for k, v in s["exceptions"]] or ["- _(none detected)_"]
        md.append("")
    if _sec(sections, "tags"):
        md.append("## Signal Tags")
        md += [f"- **{k}**: {v}" for k, v in s["tags"]] or ["- _(none detected)_"]
        md.append("")
    causes = a["causes"]
    if _sec(sections, "causes") and causes:
        from .analysis import group_into_incidents
        grouped = group_into_incidents(causes)
        md.append("## Likely Causes & Fixes")
        md.append("")
        for g in grouped["groups"]:
            md.append(f"### {g['name']} ({g['total_count']} events)")
            md.append("")
            md.append(f"*{g['narrative']}*")
            md.append("")
            for t in g["triggers"]:
                md.append(f"**{t['title']}** ({t['count']} event{'s' if t['count'] != 1 else ''})")
                md.append(f"  Likely cause: {t['cause']}")
                md.append("")
            for e in g["effects"]:
                md.append(f"- ↳ {e['title']} ({e['count']} event{'s' if e['count'] != 1 else ''})")
            md.append("")
            md.append("**Suggested fixes:**")
            for t in g["triggers"]:
                for fix in t["fixes"]:
                    md.append(f"- {fix}")
            md.append("")
        if grouped["ungrouped"]:
            md.append("### Other Findings")
            md.append("")
            for c in grouped["ungrouped"]:
                md.append(f"**{c['title']}** ({c['count']} event{'s' if c['count'] != 1 else ''})")
                md.append(f"  Likely cause: {c['cause']}")
                for fix in c["fixes"]:
                    md.append(f"- {fix}")
                md.append("")

    splunk = a.get("splunk", [])
    if _sec(sections, "splunk") and splunk:
        md.append("## Suggested Splunk Searches")
        md.append("")
        for sq in splunk:
            md.append(f"**{sq['description']}**")
            md.append("```")
            md.append(sq["query"])
            md.append("```")
            md.append("")

    hung = a["hung"]
    if _sec(sections, "hung") and hung:
        md.append("## Hung Thread Drilldown")
        md.append("")
        for t in hung:
            label = f"### {t['thread_name']} ({t['count']} occurrence{'s' if t['count'] != 1 else ''})"
            md.append(label)
            md.append("")
            ts_parts = []
            if t["first_ts"]:
                ts_parts.append(f"First: {t['first_ts']}")
            if t["last_ts"] and t["last_ts"] != t["first_ts"]:
                ts_parts.append(f"Last: {t['last_ts']}")
            if t["hex_ids"]:
                ts_parts.append(f"Thread IDs: {', '.join('0x' + h for h in t['hex_ids'])}")
            if ts_parts:
                md.append(f"- {' | '.join(ts_parts)}")
                md.append("")
            if t["stack_sample"]:
                md.append("**Stack sample:**")
                md.append("```")
                md += t["stack_sample"]
                md.append("```")
                md.append("")
            md.append("**Splunk query:**")
            md.append("```")
            md.append(t["splunk_query"])
            md.append("```")
            md.append("")

    if _sec(sections, "timeline"):
        _export_hist = compact_histogram(hist)
        _hist_label = "Timeline (events per minute)" if len(_export_hist) == len(hist) else "Timeline (compacted)"
        md.append(f"## {_hist_label}")
        md.append("")
        md.append("```")
        md += render_histogram(_export_hist)
        md.append("```")
        md.append("")

    if _sec(sections, "samples"):
        md.append("## Sample Events (sanitized)")
        md.append("")
        for idx, e in enumerate(samples, start=1):
            header = f"### {idx}. {e.level or 'UNKNOWN'}"
            if e.code: header += f" `{e.code}`"
            if e.exception: header += f" -- {e.exception}"
            if e.ts: header += f" ({e.ts})"
            md.append(header)
            parts = []
            if e.tags:
                parts.append(f"Tags: {', '.join(e.tags)}")
            if e.thread_id:
                parts.append(f"Thread: 0x{e.thread_id}")
            if e.root_cause and e.root_cause != e.exception:
                parts.append(f"Root cause: `{e.root_cause}`")
            if parts:
                md.append(f"- {' | '.join(parts)}")
            md.append("")
            md.append("```")
            md.append(e.text[:MAX_EVENT_TEXT])
            if len(e.text) > MAX_EVENT_TEXT:
                md.append("\n...[TRUNCATED]...")
            md.append("```")
            md.append("")

    if _sec(sections, "ai") and ai_content:
        incident = ai_content.get("incident")
        if incident:
            md.append("")
            _q = ai_content.get("incident_query", "")
            _q_preview = _q[:80] + "..." if len(_q) > 80 else _q
            _heading = f"## AI Analysis — {_q_preview}" if _q_preview else "## AI Analysis"
            md.append(_heading)
            model = ai_content.get("incident_model", "AI")
            md.append(f"*Model: {model}*")
            md.append("")
            md.append(incident)
            md.append("")

        ask_ai = ai_content.get("ask_ai")
        if ask_ai:
            md.append("## Previous AI Queries")
            md.append("")
            for entry in ask_ai:
                _eq = entry['query']
                _eq_preview = _eq[:80] + "..." if len(_eq) > 80 else _eq
                md.append(f"### Q: {_eq_preview}")
                provider = entry.get("provider", "AI")
                md.append(f"*{provider} — {entry.get('timestamp', '')}*")
                md.append("")
                md.append(entry["answer"])
                md.append("")

    md.append("")
    md.append("---")
    md.append("*Powered by LogPilot — [Item Consulting](https://item.no)*")

    return "\n".join(md)


_LOGPILOT_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 140 28" fill="none" style="height:22px;vertical-align:middle">'
    '<path d="M4 14 L10 6 L13 6 L7 14 L13 22 L10 22 Z" fill="#7C3AED"/>'
    '<path d="M11 14 L17 6 L20 6 L14 14 L20 22 L17 22 Z" fill="#34D399"/>'
    '<text x="26" y="19" font-family="system-ui,-apple-system,sans-serif" font-size="15" font-weight="700" fill="var(--text-heading)" letter-spacing="-0.3">Log</text>'
    '<text x="53" y="19" font-family="system-ui,-apple-system,sans-serif" font-size="15" font-weight="700" fill="#7C3AED" letter-spacing="-0.3">Pilot</text>'
    '</svg>'
)


def render_html_report(events: list[LogEvent], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None, ai_content: dict | None = None, sections: set[str] | None = None) -> str:
    """Generate a premium styled HTML triage report with sidebar, collapsible sections, and dark/light mode."""
    from html import escape

    a = _analysis or precompute_analysis(events, top_n, samples_n, hist_minutes)
    s = a["summary"]
    samples = a["samples"]
    hist = a["hist"]
    file_summary = a["file_summary"]
    causes = a["causes"]
    hung = a["hung"]
    _title, _subtitle = _report_meta(a)

    # --- Collect nav items ---
    nav_items: list[tuple[str, str]] = []  # (id, label)
    _sect_num = 0

    def _add_nav(label: str) -> str:
        nonlocal _sect_num
        _sect_num += 1
        sid = f"sect-{_sect_num}"
        nav_items.append((sid, label))
        return sid

    # Pre-scan which sections will be rendered
    level_counts = dict(s["levels"])
    error_count = sum(level_counts.get(l, 0) for l in ("ERROR", "SEVERE", "FATAL"))
    warn_count = level_counts.get("WARNING", 0) + level_counts.get("WARN", 0)

    # Section order: insights first, raw data last
    if _sec(sections, "onset") and a.get("incident_timeline", {}).get("trigger_dt"):
        _add_nav("Problem Onset")
    if _sec(sections, "ai") and ai_content and ai_content.get("incident"):
        _add_nav("AI Analysis")
    if _sec(sections, "causes") and causes:
        _add_nav("Likely Causes & Fixes")
    if _sec(sections, "levels"):
        _add_nav("Severity Distribution")
    if _sec(sections, "codes") and s["codes"]:
        _add_nav("Message Codes")
    if _sec(sections, "exceptions") and s["exceptions"]:
        _add_nav("Exceptions")
    if _sec(sections, "tags") and s["tags"]:
        _add_nav("Signal Tags")
    if _sec(sections, "splunk") and a.get("splunk"):
        _add_nav("Splunk Searches")
    if _sec(sections, "hung") and hung:
        _add_nav("Hung Thread Drilldown")
    if _sec(sections, "timeline"):
        _add_nav("Timeline")
    if _sec(sections, "files") and len(file_summary) > 1:
        _add_nav("Per-File Breakdown")
    if _sec(sections, "samples"):
        _add_nav("Sample Events")
    if _sec(sections, "ai") and ai_content and ai_content.get("ask_ai"):
        _add_nav("AI Queries")

    h: list[str] = []
    h.append('<!DOCTYPE html>')
    h.append('<html lang="en" data-theme="auto">')
    h.append('<head><meta charset="UTF-8">')
    h.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    h.append(f'<title>{escape(_title)}</title>')
    h.append('<style>')
    # CSS with light/dark theme support via CSS variables
    h.append('''
/* --- Light theme (default) --- */
:root, [data-theme="light"] {
  --bg-primary: #F8FAFC; --bg-secondary: #FFFFFF; --bg-tertiary: #F1F5F9;
  --bg-hover: #E2E8F0; --border: #E2E8F0; --border-strong: #CBD5E1;
  --text-primary: #0F172A; --text-secondary: #334155; --text-muted: #64748B;
  --text-heading: #0F172A; --accent: #7C3AED;
  --green: #059669; --green-bg: #ECFDF5; --yellow: #D97706; --yellow-bg: #FFFBEB;
  --red: #DC2626; --red-bg: #FEF2F2; --blue: #2563EB; --blue-bg: #EFF6FF;
  --purple: #7C3AED; --purple-bg: #F5F3FF;
  --code-bg: #1E293B; --code-fg: #E2E8F0;
}
/* --- Dark theme --- */
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg-primary: #0d1117; --bg-secondary: #010409; --bg-tertiary: #161b22;
  --bg-hover: #1c2128; --border: #21262d; --border-strong: #30363d;
  --text-primary: #e6edf3; --text-secondary: #c9d1d9; --text-muted: #8b949e;
  --text-heading: #f0f6fc; --accent: #a78bfa;
  --green: #6fdd8b; --green-bg: #1b4332; --yellow: #f0c74f; --yellow-bg: #3d2e00;
  --red: #f47067; --red-bg: #4a1e1e; --blue: #58a6ff; --blue-bg: #1a2332;
  --purple: #bc8cff; --purple-bg: #272145;
  --code-bg: #161b22; --code-fg: #e6edf3;
}}
[data-theme="dark"] {
  --bg-primary: #0d1117; --bg-secondary: #010409; --bg-tertiary: #161b22;
  --bg-hover: #1c2128; --border: #21262d; --border-strong: #30363d;
  --text-primary: #e6edf3; --text-secondary: #c9d1d9; --text-muted: #8b949e;
  --text-heading: #f0f6fc; --accent: #a78bfa;
  --green: #6fdd8b; --green-bg: #1b4332; --yellow: #f0c74f; --yellow-bg: #3d2e00;
  --red: #f47067; --red-bg: #4a1e1e; --blue: #58a6ff; --blue-bg: #1a2332;
  --purple: #bc8cff; --purple-bg: #272145;
  --code-bg: #161b22; --code-fg: #e6edf3;
}
*, *::before, *::after { box-sizing: border-box; }
body { margin:0;padding:0; font-family:system-ui,-apple-system,sans-serif;
  background:var(--bg-primary); color:var(--text-secondary); line-height:1.7; font-size:15px; }
a { color:var(--accent); text-decoration:none; }
a:hover { text-decoration:underline; }
.layout { display:flex; min-height:100vh; }
nav { position:sticky; top:0; height:100vh; overflow-y:auto;
  width:240px; min-width:240px; background:var(--bg-secondary);
  border-right:1px solid var(--border); padding:20px 14px; font-size:13px;
  display:flex; flex-direction:column; }
nav .nav-logo { margin-bottom:12px; }
nav .nav-subtitle { font-size:11px; color:var(--text-muted);
  margin-bottom:14px; padding-bottom:10px; border-bottom:1px solid var(--border); }
nav .nav-links { flex:1; }
nav a.nav-link { display:flex; align-items:center; gap:8px;
  padding:7px 10px; border-radius:6px; color:var(--text-muted);
  transition:all 0.15s; margin-bottom:1px; font-size:12.5px; }
nav a.nav-link:hover { background:var(--bg-tertiary); color:var(--text-secondary); text-decoration:none; }
nav a.nav-link.active { background:var(--bg-tertiary); color:var(--text-primary); font-weight:500; }
nav a.nav-link .num { display:inline-flex; align-items:center; justify-content:center;
  min-width:20px; height:20px; border-radius:4px; background:var(--bg-tertiary);
  color:var(--text-muted); font-size:11px; font-weight:600; }
nav .nav-controls { margin-top:12px; padding-top:12px;
  border-top:1px solid var(--border); display:flex; gap:6px; }
nav .nav-controls button { flex:1; padding:7px; background:var(--bg-tertiary);
  color:var(--text-muted); border:1px solid var(--border-strong);
  border-radius:6px; cursor:pointer; font-size:11px; transition:all 0.15s; }
nav .nav-controls button:hover { background:var(--border-strong); color:var(--text-secondary); }
main { flex:1; max-width:960px; padding:36px 48px 80px; }
.report-header { margin-bottom:28px; border-bottom:1px solid var(--border); padding-bottom:20px; }
.report-meta { color:var(--text-muted); font-size:13px; margin:8px 0 16px; }
h1 { color:var(--text-heading); font-size:24px; margin:0 0 4px; }
h2 { color:var(--text-heading); font-size:19px; margin:24px 0 10px; }
h3 { color:var(--text-primary); font-size:16px; margin:18px 0 8px; }
strong { color:var(--text-primary); }
.metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
  gap:10px; margin:16px 0; }
.metric { background:var(--bg-tertiary); border:1px solid var(--border);
  border-radius:8px; padding:12px; text-align:center; }
.metric .value { font-size:1.5rem; font-weight:700; color:var(--accent); }
.metric .label { font-size:0.7rem; color:var(--text-muted); text-transform:uppercase; }
.metric.error .value { color:var(--red); }
.metric.warning .value { color:var(--yellow); }
details.section { margin:10px 0; border:1px solid var(--border); border-radius:8px;
  background:var(--bg-primary); }
details.section[open] { background:var(--bg-secondary); }
details.section > summary { padding:14px 18px; cursor:pointer;
  font-weight:600; color:var(--text-heading); list-style:none;
  border-radius:8px; display:flex; align-items:center; gap:10px; user-select:none; }
details.section > summary::-webkit-details-marker { display:none; }
details.section > summary::before { content:'\\25B6'; font-size:10px; color:var(--text-muted);
  transition:transform 0.2s ease; display:inline-block; min-width:14px; }
details.section[open] > summary::before { transform:rotate(90deg); }
details.section > summary:hover { background:var(--bg-tertiary); }
.section-body { padding:4px 18px 18px; }
.table-wrap { overflow-x:auto; margin:12px 0; border-radius:8px; border:1px solid var(--border); }
table { width:100%; border-collapse:collapse; font-size:13.5px; }
thead th { background:var(--bg-tertiary); color:var(--text-primary); text-align:left;
  padding:10px 14px; font-weight:600; border-bottom:2px solid var(--border-strong); }
tbody td { padding:8px 14px; border-bottom:1px solid var(--border); }
tbody tr:hover { background:var(--bg-tertiary); }
pre { background:var(--code-bg); color:var(--code-fg); padding:14px; border-radius:8px;
  overflow-x:auto; font-size:13px; line-height:1.5; margin:10px 0;
  white-space:pre-wrap; word-break:break-word; border:1px solid var(--border);
  font-family:'SF Mono','Fira Code',Consolas,monospace; }
code.inline { background:var(--bg-hover); padding:2px 6px; border-radius:4px;
  font-size:0.88em; color:var(--text-primary); }
.tag { display:inline-block; background:var(--purple-bg); color:var(--purple);
  font-size:0.75rem; padding:3px 10px; border-radius:12px; margin:3px; font-weight:600; }
.level-error { color:var(--red); font-weight:600; }
.level-warning { color:var(--yellow); font-weight:600; }
.level-info { color:var(--accent); }
.cause { background:var(--bg-tertiary); border-left:3px solid var(--purple);
  padding:14px; margin:10px 0; border-radius:0 8px 8px 0; }
.cause h3 { margin-top:0; }
.ai-section { background:var(--purple-bg); border:1px solid var(--border);
  border-radius:8px; padding:16px; margin:12px 0; }
.ai-section h3 { color:var(--purple); margin-top:0; }
.ai-answer { white-space:pre-wrap; line-height:1.6; }
.sample { background:var(--bg-tertiary); border:1px solid var(--border);
  border-radius:8px; padding:14px; margin:10px 0; }
.sample-header { font-weight:600; margin-bottom:8px; color:var(--text-heading); }
.sample-meta { font-size:0.8rem; color:var(--text-muted); margin-bottom:8px; }
.onset-alert { background:var(--red-bg); border:1px solid var(--red);
  border-radius:8px; padding:14px; margin:12px 0; color:var(--red); }
.footer { margin-top:32px; padding-top:12px; border-top:1px solid var(--border);
  color:var(--text-muted); font-size:0.75rem; text-align:center; }
.footer a { color:var(--accent); }
.theme-toggle { background:var(--bg-tertiary); border:1px solid var(--border-strong);
  border-radius:6px; padding:6px 10px; cursor:pointer; font-size:14px;
  color:var(--text-muted); transition:all 0.15s; }
.theme-toggle:hover { background:var(--border-strong); color:var(--text-primary); }
.back-to-top { position:fixed; bottom:24px; right:24px;
  width:40px; height:40px; border-radius:50%; background:var(--bg-tertiary);
  border:1px solid var(--border-strong); color:var(--text-muted);
  cursor:pointer; font-size:18px; display:none; align-items:center;
  justify-content:center; z-index:100; }
.back-to-top:hover { background:var(--border-strong); color:var(--text-primary); }
.back-to-top.visible { display:flex; }
@media (max-width:900px) { nav { display:none; } main { padding:20px 16px; } }
@media print {
  nav, .back-to-top, .theme-toggle { display:none !important; }
  details.section { border:none; break-inside:avoid; }
  details.section > summary::before { content:''; }
  details.section .section-body { display:block !important; }
  body { background:#fff; color:#000; }
}
''')
    h.append('</style></head><body>')

    # --- Sidebar nav ---
    h.append('<div class="layout">')
    h.append('<nav>')
    h.append(f'<div class="nav-logo">{_LOGPILOT_LOGO_SVG}</div>')
    h.append(f'<div class="nav-subtitle">{escape(_subtitle)}</div>')
    h.append('<div class="nav-links">')
    for i, (sid, label) in enumerate(nav_items, 1):
        h.append(f'<a class="nav-link" href="#{sid}"><span class="num">{i}</span> {escape(label)}</a>')
    h.append('</div>')
    h.append('<div class="nav-controls">')
    h.append('<button onclick="document.querySelectorAll(\'details.section\').forEach(d=>d.open=true)">Expand all</button>')
    h.append('<button onclick="document.querySelectorAll(\'details.section\').forEach(d=>d.open=false)">Collapse all</button>')
    h.append('</div>')
    h.append('<div style="margin-top:8px;text-align:center">')
    h.append('<button class="theme-toggle" onclick="toggleTheme()" title="Toggle dark/light mode">&#9788;</button>')
    h.append('</div>')
    h.append('</nav>')

    # --- Main content ---
    h.append('<main>')
    h.append('<div class="report-header">')
    h.append(f'<h1>{escape(_title)}</h1>')
    h.append(f'<div class="report-meta">{escape(_subtitle)}</div>')
    # Metrics grid
    h.append('<div class="metrics">')
    h.append(f'<div class="metric"><div class="value">{s["total_events"]:,}</div><div class="label">Events</div></div>')
    h.append(f'<div class="metric error"><div class="value">{error_count:,}</div><div class="label">Errors</div></div>')
    h.append(f'<div class="metric warning"><div class="value">{warn_count:,}</div><div class="label">Warnings</div></div>')
    h.append(f'<div class="metric"><div class="value">{len(file_summary)}</div><div class="label">Files</div></div>')
    h.append('</div></div>')

    # --- Section helpers ---
    _nav_idx = 0

    def _open_section(open_default: bool = False) -> None:
        nonlocal _nav_idx
        sid, label = nav_items[_nav_idx]
        _open = ' open' if open_default else ''
        h.append(f'<details class="section" id="{sid}"{_open}><summary><span>{escape(label)}</span></summary><div class="section-body">')
        _nav_idx += 1

    def _close_section() -> None:
        h.append('</div></details>')

    # --- Render sections (insights first, raw data last) ---

    # 1. Problem onset
    if _sec(sections, "onset"):
        itl = a.get("incident_timeline")
        if itl and itl.get("trigger_dt"):
            _open_section(True)
            trigger = itl.get("trigger_event", {})
            trigger_dt = itl["trigger_dt"]
            _t_parts = [trigger.get("level", "ERROR")]
            if trigger.get("code"):
                _t_parts.append(escape(trigger["code"]))
            if trigger.get("exception"):
                _t_parts.append(escape(trigger["exception"].rsplit(".", 1)[-1]))
            h.append(
                f'<div class="onset-alert">'
                f'<strong>Problem onset: {escape(trigger_dt.strftime("%Y-%m-%d %H:%M:%S"))}</strong>'
                f' &mdash; {" ".join(_t_parts)}</div>')
            _close_section()

    # 2. AI analysis (primary insight)
    if _sec(sections, "ai") and ai_content:
        incident = ai_content.get("incident")
        if incident:
            _open_section(True)
            h.append('<div class="ai-section">')
            model = ai_content.get("incident_model", "AI")
            _q = ai_content.get("incident_query", "")
            if _q:
                h.append(f'<h3>Q: {escape(_q[:120])}</h3>')
            h.append(f'<div class="sample-meta">Model: {escape(model)}</div>')
            h.append(f'<div class="ai-answer">{escape(incident)}</div>')
            h.append('</div>')
            _close_section()

    # 3. Likely causes
    if _sec(sections, "causes") and causes:
        from .analysis import group_into_incidents
        grouped = group_into_incidents(causes)
        _open_section(True)
        for g in grouped["groups"]:
            h.append('<div class="cause">')
            h.append(f'<h3>{escape(g["name"])} ({g["total_count"]:,} events)</h3>')
            h.append(f'<p><em>{escape(g["narrative"])}</em></p>')
            for t in g["triggers"]:
                h.append(f'<p><strong>{escape(t["title"])}</strong> ({t["count"]} event{"s" if t["count"] != 1 else ""})')
                h.append(f'<br>Likely cause: {escape(t["cause"])}</p>')
            for e in g["effects"]:
                h.append(f'<p style="margin-left:16px">&#8627; {escape(e["title"])} ({e["count"]})</p>')
            h.append('<ul>')
            for t in g["triggers"]:
                for fix in t["fixes"]:
                    h.append(f'<li>{escape(fix)}</li>')
            h.append('</ul></div>')
        if grouped["ungrouped"]:
            h.append('<h3>Other Findings</h3>')
            for c in grouped["ungrouped"]:
                h.append('<div class="cause">')
                h.append(f'<h3>{escape(c["title"])} ({c["count"]})</h3>')
                h.append(f'<p><strong>Likely cause:</strong> {escape(c["cause"])}</p>')
                h.append('<ul>')
                for fix in c["fixes"]:
                    h.append(f'<li>{escape(fix)}</li>')
                h.append('</ul></div>')
        _close_section()

    # 4. Severity
    if _sec(sections, "levels"):
        _open_section()
        h.append('<div class="table-wrap"><table><thead><tr><th>Level</th><th>Count</th></tr></thead><tbody>')
        for k, v in s["levels"]:
            cls = "level-error" if k in ("ERROR", "SEVERE", "FATAL") else "level-warning" if k in ("WARNING", "WARN") else "level-info"
            h.append(f'<tr><td class="{cls}">{escape(k)}</td><td>{v:,}</td></tr>')
        h.append('</tbody></table></div>')
        _close_section()

    # 5. Message codes
    if _sec(sections, "codes") and s["codes"]:
        _open_section()
        h.append('<div class="table-wrap"><table><thead><tr><th>Code</th><th>Count</th></tr></thead><tbody>')
        for k, v in s["codes"]:
            h.append(f'<tr><td><code class="inline">{escape(k)}</code></td><td>{v:,}</td></tr>')
        h.append('</tbody></table></div>')
        _close_section()

    # 6. Exceptions
    if _sec(sections, "exceptions") and s["exceptions"]:
        _open_section()
        h.append('<div class="table-wrap"><table><thead><tr><th>Exception</th><th>Count</th></tr></thead><tbody>')
        for k, v in s["exceptions"]:
            h.append(f'<tr><td><code class="inline">{escape(k)}</code></td><td>{v:,}</td></tr>')
        h.append('</tbody></table></div>')
        _close_section()

    # 7. Signal tags
    if _sec(sections, "tags") and s["tags"]:
        _open_section()
        for tag, count in s["tags"]:
            h.append(f'<span class="tag">{escape(tag)}: {count:,}</span>')
        _close_section()

    # 8. Splunk searches
    splunk = a.get("splunk", [])
    if _sec(sections, "splunk") and splunk:
        _open_section()
        for sq in splunk:
            h.append(f'<h3>{escape(sq["description"])}</h3>')
            h.append(f'<pre>{escape(sq["query"])}</pre>')
        _close_section()

    # 9. Hung threads
    if _sec(sections, "hung") and hung:
        _open_section()
        for t in hung:
            h.append(f'<h3>{escape(t["thread_name"])} ({t["count"]} occurrence{"s" if t["count"] != 1 else ""})</h3>')
            if t["stack_sample"]:
                h.append(f'<pre>{escape(chr(10).join(t["stack_sample"]))}</pre>')
        _close_section()

    # 10. Timeline
    if _sec(sections, "timeline"):
        _open_section()
        _export_hist = compact_histogram(hist)
        hist_lines = render_histogram(_export_hist)
        h.append(f'<pre>{escape(chr(10).join(hist_lines))}</pre>')
        _close_section()

    # 11. Per-file breakdown
    if _sec(sections, "files") and len(file_summary) > 1:
        _open_section()
        h.append('<div class="table-wrap"><table><thead><tr><th>File</th><th>Events</th><th>Errors</th></tr></thead><tbody>')
        for fname, total, errors in file_summary:
            h.append(f'<tr><td>{escape(Path(fname).name)}</td><td>{total:,}</td><td>{errors:,}</td></tr>')
        h.append('</tbody></table></div>')
        _close_section()

    # 12. Sample events
    if _sec(sections, "samples"):
        _open_section()
        for idx, e in enumerate(samples, start=1):
            lvl = e.level or "UNKNOWN"
            cls = "level-error" if lvl in ("ERROR", "SEVERE", "FATAL") else "level-warning" if lvl in ("WARNING", "WARN") else ""
            header = f'{idx}. <span class="{cls}">{escape(lvl)}</span>'
            if e.code:
                header += f' <code class="inline">{escape(e.code)}</code>'
            if e.exception:
                header += f' &mdash; {escape(e.exception)}'
            if e.ts:
                header += f' ({escape(e.ts)})'
            h.append(f'<div class="sample"><div class="sample-header">{header}</div>')
            parts = []
            if e.tags:
                parts.append("Tags: " + ", ".join(e.tags))
            if e.thread_id:
                parts.append(f"Thread: 0x{e.thread_id}")
            if e.root_cause and e.root_cause != e.exception:
                parts.append(f"Root cause: {e.root_cause}")
            if parts:
                h.append(f'<div class="sample-meta">{escape(" | ".join(parts))}</div>')
            h.append(f'<pre>{escape(e.text[:MAX_EVENT_TEXT])}</pre>')
            h.append('</div>')
        _close_section()

    # 13. AI queries (history)
    if _sec(sections, "ai") and ai_content:
        ask_ai = ai_content.get("ask_ai")
        if ask_ai:
            _open_section()
            for entry in ask_ai:
                h.append('<div class="ai-section">')
                h.append(f'<h3>Q: {escape(entry["query"][:120])}</h3>')
                provider = entry.get("provider", "AI")
                h.append(f'<div class="sample-meta">{escape(provider)} &mdash; {escape(entry.get("timestamp", ""))}</div>')
                h.append(f'<div class="ai-answer">{escape(entry["answer"])}</div>')
                h.append('</div>')
            _close_section()

    # Footer
    h.append(f'<div class="footer">{_LOGPILOT_LOGO_SVG} Powered by LogPilot &mdash; <a href="https://item.no">Item Consulting</a></div>')
    h.append('</main></div>')

    # --- Back to top + JS ---
    h.append('<button class="back-to-top" onclick="scrollTo({top:0,behavior:\'smooth\'})" title="Back to top">&#8593;</button>')
    h.append("""<script>
window.addEventListener('scroll',()=>{
  document.querySelector('.back-to-top').classList.toggle('visible',scrollY>300);
});
function toggleTheme(){
  const html=document.documentElement;
  const current=html.getAttribute('data-theme');
  if(current==='dark') html.setAttribute('data-theme','light');
  else if(current==='light') html.setAttribute('data-theme','dark');
  else{
    const isDark=window.matchMedia('(prefers-color-scheme:dark)').matches;
    html.setAttribute('data-theme',isDark?'light':'dark');
  }
}
const sections=document.querySelectorAll('details.section');
const navLinks=document.querySelectorAll('nav a.nav-link');
const obs=new IntersectionObserver(entries=>{
  entries.forEach(e=>{
    if(e.isIntersecting){
      navLinks.forEach(l=>l.classList.remove('active'));
      const link=document.querySelector('nav a[href="#'+e.target.id+'"]');
      if(link) link.classList.add('active');
    }
  });
},{threshold:0.1,rootMargin:'-80px 0px -70% 0px'});
sections.forEach(s=>obs.observe(s));
</script>""")
    h.append('</body></html>')

    return "\n".join(h)


def render_pdf_report(events: list[LogEvent], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None, ai_content: dict | None = None, sections: set[str] | None = None) -> bytes:
    """Generate a PDF triage report and return the bytes."""
    from fpdf import FPDF

    a = _analysis or precompute_analysis(events, top_n, samples_n, hist_minutes)
    s = a["summary"]
    samples = a["samples"]
    hist = a["hist"]
    file_summary = a["file_summary"]
    causes = a["causes"]
    splunk = a.get("splunk", [])
    hung = a["hung"]

    _pdf_title, _pdf_subtitle = _report_meta(a)

    def _latin1_safe(text: str) -> str:
        return text.encode("latin-1", errors="replace").decode("latin-1")

    class _BrandedPDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "", 7)
            self.set_text_color(148, 163, 184)  # #94A3B8
            self.cell(0, 6, _latin1_safe(_pdf_title), align="L")
            self.cell(0, 6, "item.no", align="R", new_x="LMARGIN", new_y="NEXT")
            self.set_draw_color(226, 232, 240)  # #E2E8F0
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(148, 163, 184)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="L")
            self.cell(0, 10, "Powered by LogPilot - Item Consulting", align="R")

    pdf = _BrandedPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(30, 41, 59)  # #1E293B
    pdf.cell(0, 12, _latin1_safe(_pdf_title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 116, 139)  # #64748B
    pdf.cell(0, 6, _latin1_safe(_pdf_subtitle or "Log Intelligence Platform"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 41, 59)
    pdf.ln(4)

    def heading(text: str, size: int = 13) -> None:
        pdf.set_font("Helvetica", "B", size)
        pdf.cell(0, 8, _latin1_safe(text), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    def body(text: str) -> None:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _latin1_safe(text))

    def mono(text: str) -> None:
        pdf.set_font("Courier", "", 7)
        pdf.set_x(pdf.l_margin)
        safe = _latin1_safe(text[:MAX_EVENT_TEXT])
        max_chars = 110
        wrapped: list[str] = []
        for line in safe.split("\n"):
            while len(line) > max_chars:
                wrapped.append(line[:max_chars])
                line = line[max_chars:]
            wrapped.append(line)
        pdf.multi_cell(0, 3.5, "\n".join(wrapped))
        pdf.ln(2)

    body(f"Files: {len(file_summary)}  |  Parsed events: {s['total_events']}")

    # Problem onset
    if _sec(sections, "onset"):
        itl = a.get("incident_timeline")
        if itl:
            trigger = itl.get("trigger_event", {})
            trigger_dt = itl.get("trigger_dt")
            if trigger_dt:
                _t_parts = [trigger.get("level", "ERROR")]
                if trigger.get("code"):
                    _t_parts.append(trigger["code"])
                if trigger.get("exception"):
                    _t_parts.append(trigger["exception"].rsplit(".", 1)[-1])
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 6, _latin1_safe(f"Problem onset: {trigger_dt.strftime('%Y-%m-%d %H:%M:%S')} -- {' '.join(_t_parts)}"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
    pdf.ln(4)

    if _sec(sections, "files") and len(file_summary) > 1:
        heading("Per-File Breakdown")
        for fname, total, errors in file_summary:
            err_note = f" ({errors} errors)" if errors else ""
            body(f"  {Path(fname).name}: {total} events{err_note}")
        pdf.ln(2)

    if _sec(sections, "levels"):
        heading("Top Levels")
        for k, v in s["levels"]:
            body(f"  {k}: {v}")
        pdf.ln(2)

    if _sec(sections, "codes"):
        heading("Top WebSphere/Liberty Codes")
        if s["codes"]:
            for k, v in s["codes"]:
                body(f"  {k}: {v}")
        else:
            body("  (none detected)")
        pdf.ln(2)

    if _sec(sections, "exceptions"):
        heading("Top Exceptions/Errors")
        if s["exceptions"]:
            for k, v in s["exceptions"]:
                body(f"  {k}: {v}")
        else:
            body("  (none detected)")
        pdf.ln(2)

    if _sec(sections, "tags"):
        heading("Signal Tags")
        if s["tags"]:
            for k, v in s["tags"]:
                body(f"  {k}: {v}")
        else:
            body("  (none detected)")
        pdf.ln(2)

    def bold_line(text: str) -> None:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _latin1_safe(text))

    if _sec(sections, "causes") and causes:
        from .analysis import group_into_incidents
        grouped = group_into_incidents(causes)
        heading("Likely Causes & Fixes")
        for g in grouped["groups"]:
            bold_line(f"{g['name']} ({g['total_count']} events)")
            body(g["narrative"])
            for t in g["triggers"]:
                bold_line(f"  {t['title']} ({t['count']} event{'s' if t['count'] != 1 else ''})")
                body(f"  Likely cause: {t['cause']}")
            for e in g["effects"]:
                body(f"    -> {e['title']} ({e['count']} event{'s' if e['count'] != 1 else ''})")
            body("  Suggested fixes:")
            for t in g["triggers"]:
                for fix in t["fixes"]:
                    body(f"    - {fix}")
            pdf.ln(2)
        if grouped["ungrouped"]:
            bold_line("Other Findings")
            for c in grouped["ungrouped"]:
                bold_line(f"  {c['title']} ({c['count']} event{'s' if c['count'] != 1 else ''})")
                body(f"  Likely cause: {c['cause']}")
                for fix in c["fixes"]:
                    body(f"    - {fix}")
                pdf.ln(2)

    if _sec(sections, "splunk") and splunk:
        heading("Suggested Splunk Searches")
        for sq in splunk:
            bold_line(sq["description"])
            mono(sq["query"])

    if _sec(sections, "hung") and hung:
        heading("Hung Thread Drilldown")
        for t in hung:
            bold_line(f"{t['thread_name']} ({t['count']} occurrence{'s' if t['count'] != 1 else ''})")
            ts_parts = []
            if t["first_ts"]:
                ts_parts.append(f"First: {t['first_ts']}")
            if t["last_ts"] and t["last_ts"] != t["first_ts"]:
                ts_parts.append(f"Last: {t['last_ts']}")
            if ts_parts:
                body(" | ".join(ts_parts))
            if t["stack_sample"]:
                mono("\n".join(t["stack_sample"]))
            mono(t["splunk_query"])

    if _sec(sections, "timeline"):
        _export_hist = compact_histogram(hist)
        _hist_label = "Timeline (events per minute)" if len(_export_hist) == len(hist) else "Timeline (compacted)"
        heading(_hist_label)
        hist_lines = render_histogram(_export_hist)
        mono("\n".join(hist_lines))

    if _sec(sections, "samples"):
        heading("Sample Events (sanitized)")
        for idx, e in enumerate(samples, start=1):
            header = f"{idx}. {e.level or 'UNKNOWN'}"
            if e.code:
                header += f" {e.code}"
            if e.exception:
                header += f" -- {e.exception}"
            if e.ts:
                header += f" ({e.ts})"
            bold_line(header)
            parts = []
            if e.tags:
                parts.append(f"Tags: {', '.join(e.tags)}")
            if e.thread_id:
                parts.append(f"Thread: 0x{e.thread_id}")
            if e.root_cause and e.root_cause != e.exception:
                parts.append(f"Root cause: {e.root_cause}")
            if parts:
                body(" | ".join(parts))
            mono(e.text[:MAX_EVENT_TEXT])

    if _sec(sections, "ai") and ai_content:
        incident = ai_content.get("incident")
        if incident:
            pdf.add_page()
            _q = ai_content.get("incident_query", "")
            _q_preview = (_q[:80] + "...") if len(_q) > 80 else _q
            _heading = f"AI Analysis -- {_q_preview}" if _q_preview else "AI Analysis"
            heading(_heading)
            model = ai_content.get("incident_model", "AI")
            body(f"Model: {model}")
            pdf.ln(2)
            body(incident)

        ask_ai = ai_content.get("ask_ai")
        if ask_ai:
            pdf.add_page()
            heading("Previous AI Queries")
            for entry in ask_ai:
                bold_line(f"Q: {entry['query']}")
                provider = entry.get("provider", "AI")
                body(f"{provider} - {entry.get('timestamp', '')}")
                pdf.ln(2)
                body(entry["answer"])
                pdf.ln(4)

    return bytes(pdf.output())
