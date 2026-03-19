"""PDF report renderer."""
from __future__ import annotations

from pathlib import Path

from ..parser import MAX_EVENT_TEXT
from ..analysis import precompute_analysis, render_histogram, compact_histogram
from ..event import LogEvent
from .config import ReportConfig, _sec, _report_meta


def render_pdf_report(
    events: list[LogEvent] | ReportConfig | None = None,
    top_n: int = 10,
    samples_n: int = 5,
    hist_minutes: int = 1,
    _analysis: dict | None = None,
    ai_content: dict | None = None,
    sections: set[str] | None = None,
    *,
    config: ReportConfig | None = None,
) -> bytes:
    """Generate a PDF triage report and return the bytes."""
    from fpdf import FPDF

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
        heading("Top Message Codes")
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
        from ..analysis import group_into_incidents
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
