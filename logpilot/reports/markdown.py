"""Markdown report renderer."""
from __future__ import annotations

from ..parser import MAX_EVENT_TEXT
from ..analysis import precompute_analysis, render_histogram, compact_histogram
from ..event import LogEvent
from .config import ReportConfig, _sec, _report_meta


def render_markdown_report(
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
    """Generate a complete markdown triage report from parsed events."""
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
        from ..analysis import group_into_incidents
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
