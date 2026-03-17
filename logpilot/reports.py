"""Report rendering: Markdown, JSON, HTML, PDF."""
from __future__ import annotations

import json
from pathlib import Path

from .parser import MAX_EVENT_TEXT
from .analysis import precompute_analysis, render_histogram


def render_json_report(events: list[dict], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None, ai_content: dict | None = None) -> str:
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
    if ai_content:
        data["ai_analysis"] = ai_content
    return json.dumps(data, indent=2)


def render_markdown_report(events: list[dict], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None, ai_content: dict | None = None) -> str:
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

    if ai_content:
        triage = ai_content.get("triage")
        if triage:
            md.append("")
            md.append("## AI Cross-System Triage")
            model = ai_content.get("triage_model", "AI")
            md.append(f"*Model: {model}*")
            md.append("")
            md.append(triage)
            md.append("")

        ask_ai = ai_content.get("ask_ai")
        if ask_ai:
            md.append("## AI Analysis")
            md.append("")
            for entry in ask_ai:
                md.append(f"### Q: {entry['query']}")
                provider = entry.get("provider", "AI")
                md.append(f"*{provider} — {entry.get('timestamp', '')}*")
                md.append("")
                md.append(entry["answer"])
                md.append("")

    md.append("")
    md.append("---")
    md.append("*Powered by LogPilot — [Item Consulting](https://item.no)*")

    return "\n".join(md)


def render_html_report(events: list[dict], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None, ai_content: dict | None = None) -> str:
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
    h.append('<title>LogPilot Triage Report</title>')
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
    h.append('<h1>LogPilot Triage Report</h1>')
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

    # Per-file breakdown
    if len(file_summary) > 1:
        h.append('<h2>Per-File Breakdown</h2>')
        h.append('<table><tr><th>File</th><th>Events</th><th>Errors</th></tr>')
        for fname, total, errors in file_summary:
            h.append(f'<tr><td>{escape(Path(fname).name)}</td><td>{total}</td><td>{errors}</td></tr>')
        h.append('</table>')

    # Levels, codes, exceptions
    h.append('<h2>Severity Distribution</h2>')
    h.append('<table><tr><th>Level</th><th>Count</th></tr>')
    for k, v in s["levels"]:
        cls = "level-error" if k in ("ERROR", "SEVERE", "FATAL") else "level-warning" if k in ("WARNING", "WARN") else "level-info"
        h.append(f'<tr><td class="{cls}">{escape(k)}</td><td>{v}</td></tr>')
    h.append('</table>')

    if s["codes"]:
        h.append('<h2>Top Message Codes</h2>')
        h.append('<table><tr><th>Code</th><th>Count</th></tr>')
        for k, v in s["codes"]:
            h.append(f'<tr><td><code>{escape(k)}</code></td><td>{v}</td></tr>')
        h.append('</table>')

    if s["exceptions"]:
        h.append('<h2>Top Exceptions</h2>')
        h.append('<table><tr><th>Exception</th><th>Count</th></tr>')
        for k, v in s["exceptions"]:
            h.append(f'<tr><td><code>{escape(k)}</code></td><td>{v}</td></tr>')
        h.append('</table>')

    if s["tags"]:
        h.append('<h2>Signal Tags</h2>')
        for tag, count in s["tags"]:
            h.append(f'<span class="tag">{escape(tag)}: {count}</span>')

    # AI content (placed early — same as UI flow)
    if ai_content:
        triage = ai_content.get("triage")
        if triage:
            h.append('<h2>AI Cross-System Triage</h2>')
            h.append('<div class="ai-section">')
            model = ai_content.get("triage_model", "AI")
            h.append(f'<p class="subtitle">Model: {escape(model)}</p>')
            h.append(f'<div class="ai-answer">{escape(triage)}</div>')
            h.append('</div>')

        ask_ai = ai_content.get("ask_ai")
        if ask_ai:
            h.append('<h2>AI Analysis</h2>')
            for entry in ask_ai:
                h.append('<div class="ai-section">')
                h.append(f'<h3>Q: {escape(entry["query"])}</h3>')
                provider = entry.get("provider", "AI")
                h.append(f'<p class="subtitle">{escape(provider)} &mdash; {escape(entry.get("timestamp", ""))}</p>')
                h.append(f'<div class="ai-answer">{escape(entry["answer"])}</div>')
                h.append('</div>')

    # Likely causes
    if causes:
        h.append('<h2>Likely Causes &amp; Fixes</h2>')
        for c in causes:
            h.append('<div class="cause">')
            h.append(f'<h3>{escape(c["title"])} ({c["count"]} event{"s" if c["count"] != 1 else ""})</h3>')
            h.append(f'<p><strong>Likely cause:</strong> {escape(c["cause"])}</p>')
            h.append('<ul>')
            for fix in c["fixes"]:
                h.append(f'<li>{escape(fix)}</li>')
            h.append('</ul></div>')

    # Hung threads
    if hung:
        h.append('<h2>Hung Thread Drilldown</h2>')
        for t in hung:
            h.append(f'<h3>{escape(t["thread_name"])} ({t["count"]} occurrence{"s" if t["count"] != 1 else ""})</h3>')
            if t["stack_sample"]:
                h.append(f'<pre>{escape(chr(10).join(t["stack_sample"]))}</pre>')

    # Timeline histogram
    h.append('<h2>Timeline (events per minute)</h2>')
    hist_lines = render_histogram(hist)
    h.append(f'<pre>{escape(chr(10).join(hist_lines))}</pre>')

    # Sample events
    h.append('<h2>Sample Events</h2>')
    for idx, e in enumerate(samples, start=1):
        lvl = e["level"] or "UNKNOWN"
        cls = "level-error" if lvl in ("ERROR", "SEVERE", "FATAL") else "level-warning" if lvl in ("WARNING", "WARN") else ""
        header = f'{idx}. <span class="{cls}">{escape(lvl)}</span>'
        if e["code"]:
            header += f' <code>{escape(e["code"])}</code>'
        if e["exception"]:
            header += f' &mdash; {escape(e["exception"])}'
        if e["ts"]:
            header += f' ({escape(e["ts"])})'
        h.append(f'<div class="sample"><div class="sample-header">{header}</div>')
        parts = []
        if e["tags"]:
            parts.append("Tags: " + ", ".join(e["tags"]))
        if e["thread_id"]:
            parts.append(f"Thread: 0x{e['thread_id']}")
        if e["root_cause"] and e["root_cause"] != e["exception"]:
            parts.append(f"Root cause: {e['root_cause']}")
        if parts:
            h.append(f'<p style="font-size:0.8rem;color:var(--gray)">{escape(" | ".join(parts))}</p>')
        h.append(f'<pre>{escape(e["text"][:MAX_EVENT_TEXT])}</pre>')
        h.append('</div>')

    # Footer
    h.append('<div class="footer">Powered by LogPilot &mdash; <a href="https://item.no">Item Consulting</a></div>')
    h.append('</body></html>')

    return "\n".join(h)


def render_pdf_report(events: list[dict], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, _analysis: dict | None = None, ai_content: dict | None = None) -> bytes:
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

    class _BrandedPDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "", 7)
            self.set_text_color(148, 163, 184)  # #94A3B8
            self.cell(0, 6, "LogPilot Triage Report", align="L")
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
    pdf.cell(0, 12, "LogPilot Triage Report", new_x="LMARGIN", new_y="NEXT")
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

    if ai_content:
        triage = ai_content.get("triage")
        if triage:
            pdf.add_page()
            heading("AI Cross-System Triage")
            model = ai_content.get("triage_model", "AI")
            body(f"Model: {model}")
            pdf.ln(2)
            body(triage)

        ask_ai = ai_content.get("ask_ai")
        if ask_ai:
            pdf.add_page()
            heading("AI Analysis")
            for entry in ask_ai:
                bold_line(f"Q: {entry['query']}")
                provider = entry.get("provider", "AI")
                body(f"{provider} - {entry.get('timestamp', '')}")
                pdf.ln(2)
                body(entry["answer"])
                pdf.ln(4)

    return bytes(pdf.output())
