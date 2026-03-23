"""HTML report renderer."""
from __future__ import annotations

from pathlib import Path

from ..parser import MAX_EVENT_TEXT
from ..analysis import precompute_analysis, render_histogram, compact_histogram
from ..event import LogEvent
from .config import ReportConfig, _sec, _report_meta


_LOGPILOT_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 140 28" fill="none" style="height:22px;vertical-align:middle">'
    '<path d="M4 14 L10 6 L13 6 L7 14 L13 22 L10 22 Z" fill="#7C3AED"/>'
    '<path d="M11 14 L17 6 L20 6 L14 14 L20 22 L17 22 Z" fill="#34D399"/>'
    '<text x="26" y="19" font-family="system-ui,-apple-system,sans-serif" font-size="15" font-weight="700" fill="var(--text-heading)" letter-spacing="-0.3">Log</text>'
    '<text x="53" y="19" font-family="system-ui,-apple-system,sans-serif" font-size="15" font-weight="700" fill="#7C3AED" letter-spacing="-0.3">Pilot</text>'
    '</svg>'
)


def render_html_report(
    events: list[LogEvent] | ReportConfig | None = None,
    top_n: int = 10,
    samples_n: int = 5,
    hist_minutes: int = 1,
    _analysis: dict | None = None,
    ai_content: dict | None = None,
    sections: set[str] | None = None,
    *,
    config: ReportConfig | None = None,
) -> str:
    """Generate a premium styled HTML triage report with sidebar, collapsible sections, and dark/light mode."""
    from html import escape

    if isinstance(events, ReportConfig):
        config = events
        events = None  # type: ignore[assignment]
    if config is not None:
        events = config.events  # type: ignore[assignment]
        top_n = config.top_n
        samples_n = config.samples_n
        hist_minutes = config.hist_minutes
        _analysis = _analysis or config.analysis
        ai_content = ai_content if ai_content is not None else config.ai_content
        sections = sections if sections is not None else config.sections
    a = _analysis or precompute_analysis(events, top_n, samples_n, hist_minutes)
    s = a["summary"]
    samples = a["samples"]
    hist = a["hist"]
    file_summary = a["file_summary"]
    causes = a["causes"]
    hung = a["hung"]
    grouped = a.get("grouped")
    failure_chain = a.get("failure_chain", {})
    _title, _subtitle = _report_meta(a)

    # Determine primary confidence for smart collapse
    _primary_confidence = "Medium"
    if grouped:
        for _g in grouped.get("groups", []):
            if _g.get("is_primary"):
                _primary_confidence = _g.get("confidence", {}).get("label", "Medium")
                break

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

    # Section order: decision-driven (insights first, supporting data last)
    # 1. Incident Summary (merged onset + primary + confidence + chain + AI)
    _has_onset = _sec(sections, "onset") and a.get("incident_timeline", {}).get("trigger_dt")
    _has_ai = _sec(sections, "ai") and ai_content and ai_content.get("incident")
    _has_primary = grouped and any(g.get("is_primary") for g in grouped.get("groups", []))
    if _has_onset or _has_ai or _has_primary:
        _add_nav("Incident Summary")
    # 2. Causes Hierarchy
    if _sec(sections, "causes") and causes:
        _add_nav("Likely Causes & Fixes")
    # 3. Key Evidence (timeline + hung threads)
    _has_evidence = _sec(sections, "timeline") or (_sec(sections, "hung") and hung)
    if _has_evidence:
        _add_nav("Key Evidence")
    # 4. Supporting Data (smart collapse)
    _has_supporting = (
        _sec(sections, "levels")
        or (_sec(sections, "codes") and s["codes"])
        or (_sec(sections, "exceptions") and s["exceptions"])
        or (_sec(sections, "tags") and s["tags"])
        or (_sec(sections, "files") and len(file_summary) > 1)
        or _sec(sections, "samples")
    )
    if _has_supporting:
        _add_nav("Supporting Data")
    # 5. AI Queries (history)
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
.badge { display:inline-block; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600; margin-left:8px; }
.badge-high { background:var(--green-bg); color:var(--green); }
.badge-medium { background:var(--yellow-bg); color:var(--yellow); }
.badge-low { background:var(--red-bg); color:var(--red); }
.chain { font-size:14px; margin:10px 0; padding:10px 14px; background:var(--bg-tertiary);
  border-radius:6px; border-left:3px solid var(--accent); color:var(--text-secondary); }
.chain .arrow { color:var(--text-muted); margin:0 6px; }
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

    # --- Render sections (decision-driven: insights first, supporting data last) ---

    # Prepare grouped data (use pre-computed from precompute_analysis if available)
    if not grouped and causes:
        from ..heuristics import group_into_incidents
        grouped = group_into_incidents(causes)
    from ..heuristics import collect_group_evidence

    # 1. Incident Summary (merged: onset + primary incident + confidence + chain + AI)
    if _has_onset or _has_ai or _has_primary:
        _open_section(True)

        # Problem onset
        itl = a.get("incident_timeline")
        if _has_onset and itl and itl.get("trigger_dt"):
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

        # Primary incident with confidence badge
        if grouped:
            for g in grouped.get("groups", []):
                if g.get("is_primary"):
                    conf = g.get("confidence", {})
                    conf_label = conf.get("label", "Medium")
                    conf_score = conf.get("score", 0.5)
                    badge_cls = f"badge-{conf_label.lower()}"
                    h.append(f'<h3>Primary incident: {escape(g["name"])}'
                             f'<span class="badge {badge_cls}">{conf_label} confidence ({conf_score:.0%})</span></h3>')
                    h.append(f'<p><em>{escape(g["narrative"])}</em></p>')
                    h.append(f'<p><strong>{escape(g.get("investigate_first", ""))}</strong></p>')

                    # Affected systems
                    systems_list = g.get("affected_systems", [])
                    if systems_list:
                        h.append(f'<p>Affected systems: {escape(", ".join(systems_list))}</p>')
                    break

        # Failure chain
        chain_text = failure_chain.get("chain_text", "")
        if chain_text:
            chain_html = ' <span class="arrow">&rarr;</span> '.join(
                escape(step) for step in failure_chain.get("primary_chain", []))
            h.append(f'<div class="chain"><strong>Failure chain:</strong> {chain_html}</div>')

        # Secondary findings
        secondary = failure_chain.get("secondary_findings", [])
        if secondary:
            h.append(f'<p><em>Also detected: {escape(", ".join(secondary))}</em></p>')

        # AI analysis inline
        if _has_ai and ai_content:
            incident = ai_content.get("incident")
            if incident:
                h.append('<div class="ai-section">')
                model = ai_content.get("incident_model", "AI")
                _q = ai_content.get("incident_query", "")
                if _q:
                    h.append(f'<h3>Q: {escape(_q[:120])}</h3>')
                h.append(f'<div class="sample-meta">Model: {escape(model)}</div>')
                h.append(f'<div class="ai-answer">{escape(incident)}</div>')
                h.append('</div>')

        _close_section()

    # 2. Causes Hierarchy (with confidence badges per group)
    if _sec(sections, "causes") and causes and grouped:
        _open_section(True)
        for g in grouped.get("groups", []):
            cascade = g.get("cascade_order", "")
            rank = g.get("rank", "")
            label = "root cause" if g.get("is_primary") else cascade
            conf = g.get("confidence", {})
            conf_label = conf.get("label", "")
            conf_score = conf.get("score", 0)
            badge_cls = f"badge-{conf_label.lower()}" if conf_label else ""
            badge_html = f' <span class="badge {badge_cls}">{conf_label} {conf_score:.0%}</span>' if conf_label else ""
            h.append('<div class="cause">')
            h.append(f'<h3>Step {rank} &mdash; {escape(g["name"])} ({g["total_count"]:,} events) &mdash; {escape(label)}{badge_html}</h3>')
            h.append(f'<p><em>{escape(g["narrative"])}</em></p>')

            directive = g.get("investigate_first", "")
            if directive:
                h.append(f'<p><strong>{escape(directive)}</strong></p>')

            ev_lines = collect_group_evidence(g)
            if ev_lines:
                h.append(f'<pre style="font-size:12px;padding:8px">{escape(chr(10).join(ev_lines))}</pre>')

            for t in g["triggers"]:
                h.append(f'<p><strong>{escape(t["title"])}</strong> ({t["count"]} event{"s" if t["count"] != 1 else ""})')
                h.append(f'<br>Likely cause: {escape(t["cause"])}</p>')
            for e in g["effects"]:
                h.append(f'<p style="margin-left:16px">&#8627; {escape(e["title"])} ({e["count"]})</p>')
            h.append('<details><summary>Suggested fixes</summary><ul>')
            for t in g["triggers"]:
                for fix in t["fixes"]:
                    h.append(f'<li>{escape(fix)}</li>')
            h.append('</ul></details></div>')
        if grouped.get("ungrouped"):
            h.append('<h3>Other Findings</h3>')
            for c in grouped["ungrouped"]:
                h.append('<div class="cause">')
                h.append(f'<h3>{escape(c["title"])} ({c["count"]})</h3>')
                h.append(f'<p><strong>Likely cause:</strong> {escape(c["cause"])}</p>')
                h.append('<details><summary>Fixes</summary><ul>')
                for fix in c["fixes"]:
                    h.append(f'<li>{escape(fix)}</li>')
                h.append('</ul></details></div>')
        _close_section()

    # 3. Key Evidence (timeline + hung threads)
    _expand_supporting = _primary_confidence in ("Low", None, "")
    if _has_evidence:
        _open_section(True)
        # Timeline
        if _sec(sections, "timeline"):
            h.append('<h3>Timeline</h3>')
            _export_hist = compact_histogram(hist)
            hist_lines = render_histogram(_export_hist)
            h.append(f'<pre>{escape(chr(10).join(hist_lines))}</pre>')
        # Hung threads
        if _sec(sections, "hung") and hung:
            h.append('<h3>Hung Thread Drilldown</h3>')
            for t in hung:
                h.append(f'<h3>{escape(t["thread_name"])} ({t["count"]} occurrence{"s" if t["count"] != 1 else ""})</h3>')
                if t["stack_sample"]:
                    h.append(f'<pre>{escape(chr(10).join(t["stack_sample"]))}</pre>')
        _close_section()

    # 4. Supporting Data (smart collapse: expanded on Low confidence, collapsed on High)
    if _has_supporting:
        _open_section(_expand_supporting)

        # Severity
        if _sec(sections, "levels"):
            h.append('<h3>Severity Distribution</h3>')
            h.append('<div class="table-wrap"><table><thead><tr><th>Level</th><th>Count</th></tr></thead><tbody>')
            for k, v in s["levels"]:
                cls = "level-error" if k in ("ERROR", "SEVERE", "FATAL") else "level-warning" if k in ("WARNING", "WARN") else "level-info"
                h.append(f'<tr><td class="{cls}">{escape(k)}</td><td>{v:,}</td></tr>')
            h.append('</tbody></table></div>')

        # Message codes
        if _sec(sections, "codes") and s["codes"]:
            h.append('<h3>Message Codes</h3>')
            h.append('<div class="table-wrap"><table><thead><tr><th>Code</th><th>Count</th></tr></thead><tbody>')
            for k, v in s["codes"]:
                h.append(f'<tr><td><code class="inline">{escape(k)}</code></td><td>{v:,}</td></tr>')
            h.append('</tbody></table></div>')

        # Exceptions
        if _sec(sections, "exceptions") and s["exceptions"]:
            h.append('<h3>Exceptions</h3>')
            h.append('<div class="table-wrap"><table><thead><tr><th>Exception</th><th>Count</th></tr></thead><tbody>')
            for k, v in s["exceptions"]:
                h.append(f'<tr><td><code class="inline">{escape(k)}</code></td><td>{v:,}</td></tr>')
            h.append('</tbody></table></div>')

        # Signal tags
        if _sec(sections, "tags") and s["tags"]:
            h.append('<h3>Signal Tags</h3>')
            for tag, count in s["tags"]:
                h.append(f'<span class="tag">{escape(tag)}: {count:,}</span>')

        # Per-file breakdown
        if _sec(sections, "files") and len(file_summary) > 1:
            h.append('<h3>Per-File Breakdown</h3>')
            h.append('<div class="table-wrap"><table><thead><tr><th>File</th><th>Events</th><th>Errors</th></tr></thead><tbody>')
            for fname, total, errors in file_summary:
                h.append(f'<tr><td>{escape(Path(fname).name)}</td><td>{total:,}</td><td>{errors:,}</td></tr>')
            h.append('</tbody></table></div>')

        # Sample events
        if _sec(sections, "samples"):
            h.append('<h3>Sample Events</h3>')
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
                sample_label = getattr(e, "sample_label", None)
                if sample_label:
                    header += f' <span class="tag">{escape(sample_label)}</span>'
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

    # 5. AI queries (history)
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
