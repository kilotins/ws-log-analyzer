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


def _report_title(a: dict) -> str:
    """Build a dynamic report title from file names and time span.

    Example: "LogPilot Analysis — server.log, access.log (2025-03-11 10:15 – 14:32)"
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

    title = "LogPilot Analysis"
    if files_str:
        title += f" — {files_str}"
    if time_str:
        title += f" ({time_str})"
    return title


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
    md.append(f"# {_report_title(a)}")
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


def render_html_report(events: list[LogEvent], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None, ai_content: dict | None = None, sections: set[str] | None = None) -> str:
    """Generate a styled HTML triage report."""
    from html import escape

    a = _analysis or precompute_analysis(events, top_n, samples_n, hist_minutes)
    s = a["summary"]
    samples = a["samples"]
    hist = a["hist"]
    file_summary = a["file_summary"]
    causes = a["causes"]
    hung = a["hung"]

    h: list[str] = []
    h.append('<!DOCTYPE html>')
    h.append('<html lang="en"><head><meta charset="UTF-8">')
    h.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    _title = _report_title(a)
    from html import escape as _esc
    h.append(f'<title>{_esc(_title)}</title>')
    h.append('<style>')
    h.append('''
      :root { --purple: #7C3AED; --green: #34D399; --dark: #0F172A; --red: #DC2626;
              --amber: #F59E0B; --gray: #64748B; --light: #F8FAFC; --border: #E2E8F0; }
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body { font-family: system-ui, -apple-system, sans-serif; color: var(--dark);
             background: var(--light); line-height: 1.6; max-width: 960px;
             margin: 0 auto; padding: 24px; }
      h1 { color: var(--purple); font-size: 1.75rem; margin-bottom: 4px; }
      h2 { color: var(--dark); font-size: 1.25rem; margin: 24px 0 12px;
           border-bottom: 2px solid var(--purple); padding-bottom: 4px; }
      h3 { font-size: 1rem; margin: 16px 0 8px; }
      .subtitle { color: var(--gray); font-size: 0.875rem; margin-bottom: 16px; }
      .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                 gap: 12px; margin: 16px 0; }
      .metric { background: white; border: 1px solid var(--border); border-radius: 8px;
                padding: 12px; text-align: center; }
      .metric .value { font-size: 1.5rem; font-weight: 700; color: var(--purple); }
      .metric .label { font-size: 0.75rem; color: var(--gray); text-transform: uppercase; }
      .metric.error .value { color: var(--red); }
      .metric.warning .value { color: var(--amber); }
      table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.875rem; }
      th { background: var(--dark); color: white; padding: 8px 12px; text-align: left; }
      td { padding: 6px 12px; border-bottom: 1px solid var(--border); }
      tr:nth-child(even) { background: white; }
      pre { background: #1E293B; color: #E2E8F0; padding: 12px; border-radius: 6px;
            overflow-x: auto; font-size: 0.8rem; line-height: 1.4; margin: 8px 0; white-space: pre-wrap; }
      .tag { display: inline-block; background: var(--purple); color: white; font-size: 0.7rem;
             padding: 2px 8px; border-radius: 12px; margin: 2px; }
      .cause { background: white; border-left: 3px solid var(--purple); padding: 12px;
               margin: 8px 0; border-radius: 0 6px 6px 0; }
      .cause h3 { margin-top: 0; }
      .ai-section { background: #F5F3FF; border: 1px solid #DDD6FE; border-radius: 8px;
                    padding: 16px; margin: 12px 0; }
      .ai-section h3 { color: var(--purple); }
      .ai-answer { white-space: pre-wrap; }
      .level-error { color: var(--red); font-weight: 600; }
      .level-warning { color: var(--amber); font-weight: 600; }
      .level-info { color: var(--purple); }
      .sample { background: white; border: 1px solid var(--border); border-radius: 8px;
                padding: 12px; margin: 12px 0; }
      .sample-header { font-weight: 600; margin-bottom: 8px; }
      .footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid var(--border);
                color: var(--gray); font-size: 0.75rem; text-align: center; }
      .footer a { color: var(--purple); }
      @media print { body { max-width: 100%; } pre { white-space: pre-wrap; word-break: break-all; } }
    ''')
    h.append('</style></head><body>')

    # Header
    h.append(f'<h1>{_esc(_title)}</h1>')
    h.append('<p class="subtitle">Log Intelligence Platform &mdash; Item Consulting</p>')

    # Metrics
    level_counts = dict(s["levels"])
    error_count = sum(level_counts.get(l, 0) for l in ("ERROR", "SEVERE", "FATAL"))
    warn_count = level_counts.get("WARNING", 0) + level_counts.get("WARN", 0)
    h.append('<div class="metrics">')
    h.append(f'<div class="metric"><div class="value">{s["total_events"]}</div><div class="label">Events</div></div>')
    h.append(f'<div class="metric error"><div class="value">{error_count}</div><div class="label">Errors</div></div>')
    h.append(f'<div class="metric warning"><div class="value">{warn_count}</div><div class="label">Warnings</div></div>')
    h.append(f'<div class="metric"><div class="value">{len(file_summary)}</div><div class="label">Files</div></div>')
    h.append('</div>')

    # Problem onset
    if _sec(sections, "onset"):
        itl = a.get("incident_timeline")
        if itl:
            trigger = itl.get("trigger_event", {})
            trigger_dt = itl.get("trigger_dt")
            if trigger_dt:
                _t_parts = [trigger.get("level", "ERROR")]
                if trigger.get("code"):
                    _t_parts.append(escape(trigger["code"]))
                if trigger.get("exception"):
                    _t_parts.append(escape(trigger["exception"].rsplit(".", 1)[-1]))
                h.append(
                    f'<div style="background:#FEE2E2;border:1px solid #DC2626;border-radius:8px;'
                    f'padding:12px;margin:16px 0;color:#991B1B">'
                    f'<strong>Problem onset: {escape(trigger_dt.strftime("%Y-%m-%d %H:%M:%S"))}</strong>'
                    f' &mdash; {" ".join(_t_parts)}</div>'
                )

    # Per-file breakdown
    if _sec(sections, "files") and len(file_summary) > 1:
        h.append('<h2>Per-File Breakdown</h2>')
        h.append('<table><tr><th>File</th><th>Events</th><th>Errors</th></tr>')
        for fname, total, errors in file_summary:
            h.append(f'<tr><td>{escape(Path(fname).name)}</td><td>{total}</td><td>{errors}</td></tr>')
        h.append('</table>')

    # Levels, codes, exceptions
    if _sec(sections, "levels"):
        h.append('<h2>Severity Distribution</h2>')
        h.append('<table><tr><th>Level</th><th>Count</th></tr>')
        for k, v in s["levels"]:
            cls = "level-error" if k in ("ERROR", "SEVERE", "FATAL") else "level-warning" if k in ("WARNING", "WARN") else "level-info"
            h.append(f'<tr><td class="{cls}">{escape(k)}</td><td>{v}</td></tr>')
        h.append('</table>')

    if _sec(sections, "codes") and s["codes"]:
        h.append('<h2>Top Message Codes</h2>')
        h.append('<table><tr><th>Code</th><th>Count</th></tr>')
        for k, v in s["codes"]:
            h.append(f'<tr><td><code>{escape(k)}</code></td><td>{v}</td></tr>')
        h.append('</table>')

    if _sec(sections, "exceptions") and s["exceptions"]:
        h.append('<h2>Top Exceptions</h2>')
        h.append('<table><tr><th>Exception</th><th>Count</th></tr>')
        for k, v in s["exceptions"]:
            h.append(f'<tr><td><code>{escape(k)}</code></td><td>{v}</td></tr>')
        h.append('</table>')

    if _sec(sections, "tags") and s["tags"]:
        h.append('<h2>Signal Tags</h2>')
        for tag, count in s["tags"]:
            h.append(f'<span class="tag">{escape(tag)}: {count}</span>')

    # AI content (placed early — same as UI flow)
    if _sec(sections, "ai") and ai_content:
        incident = ai_content.get("incident")
        if incident:
            _q = ai_content.get("incident_query", "")
            _q_preview = escape((_q[:80] + "...") if len(_q) > 80 else _q)
            _heading = f"AI Analysis — {_q_preview}" if _q_preview else "AI Analysis"
            h.append(f'<h2>{_heading}</h2>')
            h.append('<div class="ai-section">')
            model = ai_content.get("incident_model", "AI")
            h.append(f'<p class="subtitle">Model: {escape(model)}</p>')
            h.append(f'<div class="ai-answer">{escape(incident)}</div>')
            h.append('</div>')

        ask_ai = ai_content.get("ask_ai")
        if ask_ai:
            h.append('<h2>Previous AI Queries</h2>')
            for entry in ask_ai:
                h.append('<div class="ai-section">')
                h.append(f'<h3>Q: {escape(entry["query"])}</h3>')
                provider = entry.get("provider", "AI")
                h.append(f'<p class="subtitle">{escape(provider)} &mdash; {escape(entry.get("timestamp", ""))}</p>')
                h.append(f'<div class="ai-answer">{escape(entry["answer"])}</div>')
                h.append('</div>')

    # Likely causes
    if _sec(sections, "causes") and causes:
        from .analysis import group_into_incidents
        grouped = group_into_incidents(causes)
        h.append('<h2>Likely Causes &amp; Fixes</h2>')
        for g in grouped["groups"]:
            h.append(f'<div class="cause" style="border-left:3px solid #7C3AED;padding-left:12px;margin-bottom:16px">')
            h.append(f'<h3>{escape(g["name"])} ({g["total_count"]} events)</h3>')
            h.append(f'<p><em>{escape(g["narrative"])}</em></p>')
            for t in g["triggers"]:
                h.append(f'<p><strong>{escape(t["title"])}</strong> ({t["count"]} event{"s" if t["count"] != 1 else ""})')
                h.append(f'<br>Likely cause: {escape(t["cause"])}</p>')
            for e in g["effects"]:
                h.append(f'<p style="margin-left:16px">↳ {escape(e["title"])} ({e["count"]} event{"s" if e["count"] != 1 else ""})</p>')
            h.append('<ul>')
            for t in g["triggers"]:
                for fix in t["fixes"]:
                    h.append(f'<li>{escape(fix)}</li>')
            h.append('</ul></div>')
        if grouped["ungrouped"]:
            h.append('<h3>Other Findings</h3>')
            for c in grouped["ungrouped"]:
                h.append('<div class="cause">')
                h.append(f'<h3>{escape(c["title"])} ({c["count"]} event{"s" if c["count"] != 1 else ""})</h3>')
                h.append(f'<p><strong>Likely cause:</strong> {escape(c["cause"])}</p>')
                h.append('<ul>')
                for fix in c["fixes"]:
                    h.append(f'<li>{escape(fix)}</li>')
                h.append('</ul></div>')

    # Hung threads
    if _sec(sections, "hung") and hung:
        h.append('<h2>Hung Thread Drilldown</h2>')
        for t in hung:
            h.append(f'<h3>{escape(t["thread_name"])} ({t["count"]} occurrence{"s" if t["count"] != 1 else ""})</h3>')
            if t["stack_sample"]:
                h.append(f'<pre>{escape(chr(10).join(t["stack_sample"]))}</pre>')

    # Timeline histogram (compact for large datasets)
    if _sec(sections, "timeline"):
        _export_hist = compact_histogram(hist)
        _hist_label = "Timeline (events per minute)" if len(_export_hist) == len(hist) else "Timeline (compacted)"
        h.append(f'<h2>{_hist_label}</h2>')
        hist_lines = render_histogram(_export_hist)
        h.append(f'<pre>{escape(chr(10).join(hist_lines))}</pre>')

    # Sample events
    if _sec(sections, "samples"):
        h.append('<h2>Sample Events</h2>')
        for idx, e in enumerate(samples, start=1):
            lvl = e.level or "UNKNOWN"
            cls = "level-error" if lvl in ("ERROR", "SEVERE", "FATAL") else "level-warning" if lvl in ("WARNING", "WARN") else ""
            header = f'{idx}. <span class="{cls}">{escape(lvl)}</span>'
            if e.code:
                header += f' <code>{escape(e.code)}</code>'
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
                h.append(f'<p style="font-size:0.8rem;color:var(--gray)">{escape(" | ".join(parts))}</p>')
            h.append(f'<pre>{escape(e.text[:MAX_EVENT_TEXT])}</pre>')
            h.append('</div>')

    # Footer
    h.append('<div class="footer">Powered by LogPilot &mdash; <a href="https://item.no">Item Consulting</a></div>')
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

    _pdf_title = _report_title(a)

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
    pdf.cell(0, 6, "Log Intelligence Platform", new_x="LMARGIN", new_y="NEXT")
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
