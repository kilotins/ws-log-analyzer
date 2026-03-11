"""Report rendering: Markdown, JSON, CSV, XML, PDF."""
from __future__ import annotations

import json
from pathlib import Path

from .parser import MAX_EVENT_TEXT
from .analysis import precompute_analysis, render_histogram


def render_json_report(events: list[dict], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None) -> str:
    """Generate a JSON triage report string from parsed events."""
    a = _analysis or precompute_analysis(events, top_n, samples_n, hist_minutes)
    s = a["summary"]
    samples = a["samples"]
    hist = a["hist"]
    file_summary = a["file_summary"]
    causes = a["causes"]
    data = {
        "files": [{"file": f, "events": t, "errors": e} for f, t, e in file_summary],
        "total_events": s["total_events"],
        "levels": dict(s["levels"]),
        "codes": dict(s["codes"]),
        "exceptions": dict(s["exceptions"]),
        "tags": dict(s["tags"]),
        "likely_causes": causes,
        "splunk_queries": a["splunk"],
        "hung_thread_drilldown": a["hung"],
        "timeline": [{"bucket": b, "total": t, "errors": e} for b, t, e in hist],
        "samples": [
            {
                "level": e["level"],
                "thread_id": e["thread_id"],
                "code": e["code"],
                "exception": e["exception"],
                "root_cause": e["root_cause"],
                "ts": e["ts"],
                "tags": e["tags"],
                "text": e["text"][:MAX_EVENT_TEXT],
            }
            for e in samples
        ],
    }
    return json.dumps(data, indent=2)


def render_markdown_report(events: list[dict], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None) -> str:
    """Generate a complete markdown triage report from parsed events."""
    a = _analysis or precompute_analysis(events, top_n, samples_n, hist_minutes)
    s = a["summary"]
    samples = a["samples"]
    hist = a["hist"]
    file_summary = a["file_summary"]

    md: list[str] = []
    md.append("# LogPilot Triage Report")
    md.append("")
    md.append(f"- Files: {len(file_summary)}")
    md.append(f"- Parsed events: {s['total_events']}")
    md.append("")

    if len(file_summary) > 1:
        md.append("## Per-File Breakdown")
        for fname, total, errors in file_summary:
            err_note = f" ({errors} errors)" if errors else ""
            md.append(f"- `{fname}`: {total} events{err_note}")
        md.append("")

    md.append("## Top Levels")
    md += [f"- **{k}**: {v}" for k, v in s["levels"]]
    md.append("")
    md.append("## Top WebSphere/Liberty Codes")
    md += [f"- `{k}`: {v}" for k, v in s["codes"]] or ["- _(none detected)_"]
    md.append("")
    md.append("## Top Exceptions/Errors")
    md += [f"- `{k}`: {v}" for k, v in s["exceptions"]] or ["- _(none detected)_"]
    md.append("")
    md.append("## Signal Tags")
    md += [f"- **{k}**: {v}" for k, v in s["tags"]] or ["- _(none detected)_"]
    md.append("")
    causes = a["causes"]
    if causes:
        md.append("## Likely Causes & Fixes")
        md.append("")
        for c in causes:
            md.append(f"### {c['title']} ({c['count']} event{'s' if c['count'] != 1 else ''})")
            md.append("")
            md.append(f"**Likely cause:** {c['cause']}")
            md.append("")
            md.append("**Suggested fixes:**")
            for fix in c["fixes"]:
                md.append(f"- {fix}")
            md.append("")

    splunk = a["splunk"]
    if splunk:
        md.append("## Suggested Splunk Searches")
        md.append("")
        for sq in splunk:
            md.append(f"**{sq['description']}**")
            md.append("```")
            md.append(sq["query"])
            md.append("```")
            md.append("")

    hung = a["hung"]
    if hung:
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

    md.append("## Timeline (events per minute)")
    md.append("")
    md.append("```")
    md += render_histogram(hist)
    md.append("```")
    md.append("")
    md.append("## Sample Events (sanitized)")
    md.append("")
    for idx, e in enumerate(samples, start=1):
        header = f"### {idx}. {e['level'] or 'UNKNOWN'}"
        if e["code"]: header += f" `{e['code']}`"
        if e["exception"]: header += f" -- {e['exception']}"
        if e["ts"]: header += f" ({e['ts']})"
        md.append(header)
        parts = []
        if e["tags"]:
            parts.append(f"Tags: {', '.join(e['tags'])}")
        if e["thread_id"]:
            parts.append(f"Thread: 0x{e['thread_id']}")
        if e["root_cause"] and e["root_cause"] != e["exception"]:
            parts.append(f"Root cause: `{e['root_cause']}`")
        if parts:
            md.append(f"- {' | '.join(parts)}")
        md.append("")
        md.append("```")
        md.append(e["text"][:MAX_EVENT_TEXT])
        if len(e["text"]) > MAX_EVENT_TEXT:
            md.append("\n...[TRUNCATED]...")
        md.append("```")
        md.append("")

    return "\n".join(md)


def render_csv_report(events: list[dict], max_text: int = 500) -> str:
    """Generate a CSV export of parsed events."""
    import csv
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "level", "code", "exception", "root_cause", "tags", "thread_id", "file", "text"])
    for e in events:
        writer.writerow([
            e.get("ts", ""),
            e.get("level", ""),
            e.get("code", ""),
            e.get("exception", ""),
            e.get("root_cause", ""),
            ", ".join(e.get("tags", [])),
            e.get("thread_id", ""),
            e.get("file", ""),
            (e.get("text", "")[:max_text]).replace("\n", " "),
        ])
    return buf.getvalue()


def render_xml_report(events: list[dict], max_text: int = 500) -> str:
    """Generate an XML export of parsed events."""
    from xml.sax.saxutils import escape
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<events>']
    for e in events:
        lines.append('  <event>')
        for field in ("ts", "level", "code", "exception", "root_cause", "thread_id", "file"):
            val = e.get(field, "")
            if val:
                lines.append(f'    <{field}>{escape(str(val))}</{field}>')
        tags = e.get("tags", [])
        if tags:
            lines.append('    <tags>' + escape(", ".join(tags)) + '</tags>')
        text = (e.get("text", "")[:max_text]).replace("\n", " ")
        if text:
            lines.append(f'    <text>{escape(text)}</text>')
        lines.append('  </event>')
    lines.append('</events>')
    return "\n".join(lines)


def render_pdf_report(events: list[dict], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None) -> bytes:
    """Generate a PDF triage report and return the bytes."""
    from fpdf import FPDF

    a = _analysis or precompute_analysis(events, top_n, samples_n, hist_minutes)
    s = a["summary"]
    samples = a["samples"]
    hist = a["hist"]
    file_summary = a["file_summary"]
    causes = a["causes"]
    splunk = a["splunk"]
    hung = a["hung"]

    def _latin1_safe(text: str) -> str:
        return text.encode("latin-1", errors="replace").decode("latin-1")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "LogPilot Triage Report", new_x="LMARGIN", new_y="NEXT")
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
    pdf.ln(4)

    if len(file_summary) > 1:
        heading("Per-File Breakdown")
        for fname, total, errors in file_summary:
            err_note = f" ({errors} errors)" if errors else ""
            body(f"  {Path(fname).name}: {total} events{err_note}")
        pdf.ln(2)

    heading("Top Levels")
    for k, v in s["levels"]:
        body(f"  {k}: {v}")
    pdf.ln(2)

    heading("Top WebSphere/Liberty Codes")
    if s["codes"]:
        for k, v in s["codes"]:
            body(f"  {k}: {v}")
    else:
        body("  (none detected)")
    pdf.ln(2)

    heading("Top Exceptions/Errors")
    if s["exceptions"]:
        for k, v in s["exceptions"]:
            body(f"  {k}: {v}")
    else:
        body("  (none detected)")
    pdf.ln(2)

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

    if causes:
        heading("Likely Causes & Fixes")
        for c in causes:
            bold_line(f"{c['title']} ({c['count']} event{'s' if c['count'] != 1 else ''})")
            body(f"Likely cause: {c['cause']}")
            for fix in c["fixes"]:
                body(f"  - {fix}")
            pdf.ln(2)

    if splunk:
        heading("Suggested Splunk Searches")
        for sq in splunk:
            bold_line(sq["description"])
            mono(sq["query"])

    if hung:
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

    heading("Timeline (events per minute)")
    hist_lines = render_histogram(hist)
    mono("\n".join(hist_lines))

    heading("Sample Events (sanitized)")
    for idx, e in enumerate(samples, start=1):
        header = f"{idx}. {e['level'] or 'UNKNOWN'}"
        if e["code"]:
            header += f" {e['code']}"
        if e["exception"]:
            header += f" -- {e['exception']}"
        if e["ts"]:
            header += f" ({e['ts']})"
        bold_line(header)
        parts = []
        if e["tags"]:
            parts.append(f"Tags: {', '.join(e['tags'])}")
        if e["thread_id"]:
            parts.append(f"Thread: 0x{e['thread_id']}")
        if e["root_cause"] and e["root_cause"] != e["exception"]:
            parts.append(f"Root cause: {e['root_cause']}")
        if parts:
            body(" | ".join(parts))
        mono(e["text"][:MAX_EVENT_TEXT])

    return bytes(pdf.output())
