"""Premium PDF report renderer for Technical Report.

Produces a branded, professional-quality PDF matching the Leadership Brief style:
- Item Consulting branding (purple #7C3AED, green #34D399)
- Clean typography with proper heading hierarchy
- Numbered section badges and colored dividers
- Footer with page numbers and branding
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..parser import MAX_EVENT_TEXT
from ..analysis import precompute_analysis, render_histogram, compact_histogram
from ..event import LogEvent
from .config import ReportConfig, _sec, _report_meta


# --- Brand colors ---
PURPLE = (124, 58, 237)      # #7C3AED
GREEN = (52, 211, 153)       # #34D399
DARK = (15, 23, 42)          # #0F172A
SLATE_700 = (51, 65, 85)     # #334155
SLATE_500 = (100, 116, 139)  # #64748B
SLATE_300 = (203, 213, 225)  # #CBD5E1
SLATE_100 = (241, 245, 249)  # #F1F5F9
WHITE = (255, 255, 255)
RED_600 = (220, 38, 38)      # #DC2626 — for error highlights
AMBER_600 = (217, 119, 6)    # #D97706 — for warning highlights


def _latin1_safe(text: str) -> str:
    """Replace common Unicode chars with ASCII equivalents, then encode to latin-1."""
    _UNICODE_MAP = {
        "\u2192": "->",   # →
        "\u2190": "<-",   # ←
        "\u2014": "--",   # —
        "\u2013": "-",    # –
        "\u2011": "-",    # non-breaking hyphen
        "\u2018": "'",    # '
        "\u2019": "'",    # '
        "\u201c": '"',    # "
        "\u201d": '"',    # "
        "\u2026": "...",  # …
        "\u2022": "-",    # •
        "\u2212": "-",    # −
        "\u00a0": " ",    # non-breaking space
        "\u200b": "",     # zero-width space
        "\u2502": "|",    # │ box drawing
        "\u2500": "-",    # ─ box drawing
        "\u251c": "|",    # ├
        "\u2514": "`",    # └
    }
    for char, repl in _UNICODE_MAP.items():
        text = text.replace(char, repl)
    return text.encode("latin-1", errors="replace").decode("latin-1")


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
    """Generate a premium branded PDF triage report and return the bytes."""
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

    # --- Section counter for numbered badges ---
    _section_num = [0]

    class _BrandedPDF(FPDF):
        def header(self):
            if self.page_no() == 1:
                return  # Custom title page
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*SLATE_500)
            self.cell(0, 6, _latin1_safe(_pdf_title), align="L")
            self.cell(0, 6, "item.no", align="R", new_x="LMARGIN", new_y="NEXT")
            self.set_draw_color(*SLATE_300)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(6)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*SLATE_500)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="L")
            self.cell(0, 10, "Powered by LogPilot - Item Consulting", align="R")

    pdf = _BrandedPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # === Title page ===

    # Purple accent bar at top
    pdf.set_fill_color(*PURPLE)
    pdf.rect(0, 0, 210, 4, "F")

    # Logo area
    pdf.set_y(16)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*PURPLE)
    pdf.cell(10, 8, "<", align="R")
    pdf.cell(2)
    pdf.set_text_color(*GREEN)
    pdf.cell(10, 8, "<", align="L")
    pdf.set_text_color(*DARK)
    pdf.cell(0, 8, "  LogPilot", new_x="LMARGIN", new_y="NEXT")

    # Divider
    pdf.ln(2)
    pdf.set_draw_color(*SLATE_300)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(8)

    # Title
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*DARK)
    pdf.multi_cell(0, 11, _latin1_safe(_pdf_title))
    pdf.ln(2)

    # Subtitle / metadata
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*SLATE_500)
    if _pdf_subtitle:
        pdf.cell(0, 6, _latin1_safe(_pdf_subtitle), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, _latin1_safe(f"Generated {now}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Green accent line
    pdf.set_draw_color(*GREEN)
    pdf.set_line_width(0.8)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + 50, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(6)

    # Quick stats row
    total_events = s["total_events"]
    error_count = sum(v for k, v in s["levels"] if k in ("ERROR", "SEVERE", "FATAL", "CRITICAL"))
    warn_count = sum(v for k, v in s["levels"] if k in ("WARN", "WARNING"))
    exc_count = sum(v for _, v in s["exceptions"])

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*SLATE_500)
    stats = [
        f"Files: {len(file_summary)}",
        f"Events: {total_events:,}",
        f"Errors: {error_count:,}",
        f"Warnings: {warn_count:,}",
        f"Exceptions: {exc_count:,}",
    ]
    pdf.cell(0, 5, _latin1_safe("  |  ".join(stats)), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # --- Helpers ---

    def _ensure_space(min_mm: int = 40) -> None:
        if pdf.get_y() > 297 - 20 - min_mm:
            pdf.add_page()

    def heading(text: str) -> None:
        _ensure_space(35)
        _section_num[0] += 1

        # Numbered badge
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*WHITE)
        pdf.set_fill_color(*PURPLE)
        badge_text = f" {_section_num[0]} "
        badge_w = pdf.get_string_width(badge_text) + 6
        pdf.cell(badge_w, 6, badge_text, fill=True, new_x="END")
        pdf.cell(4)

        # Heading text
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 6, _latin1_safe(text), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    def section_end() -> None:
        pdf.ln(2)
        pdf.set_draw_color(*SLATE_100)
        pdf.set_line_width(0.3)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.set_line_width(0.2)
        pdf.ln(5)

    def body(text: str) -> None:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*SLATE_700)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _latin1_safe(text))

    def body_row(label: str, value: str) -> None:
        """Render a label: value pair with bold label."""
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*DARK)
        pdf.set_x(pdf.l_margin + 4)
        label_w = pdf.get_string_width(label + "  ") + 2
        usable = pdf.w - pdf.r_margin - pdf.l_margin - 4
        if label_w > usable * 0.6:
            # Long label — put value on next line
            pdf.multi_cell(0, 5, _latin1_safe(label))
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*SLATE_700)
            pdf.set_x(pdf.l_margin + 8)
            pdf.multi_cell(0, 5, _latin1_safe(value))
        else:
            pdf.cell(label_w, 5, _latin1_safe(label))
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*SLATE_700)
            pdf.multi_cell(0, 5, _latin1_safe(value))

    def mono(text: str) -> None:
        pdf.set_font("Courier", "", 7)
        pdf.set_fill_color(*SLATE_100)
        pdf.set_text_color(*SLATE_700)
        pdf.set_x(pdf.l_margin + 2)
        safe = _latin1_safe(text[:MAX_EVENT_TEXT])
        max_chars = 105
        wrapped: list[str] = []
        for line in safe.split("\n"):
            while len(line) > max_chars:
                wrapped.append(line[:max_chars])
                line = line[max_chars:]
            wrapped.append(line)
        block = "\n".join(wrapped)
        x_start = pdf.get_x()
        y_start = pdf.get_y()
        # Background fill for code block
        line_h = 3.5
        block_h = line_h * (block.count("\n") + 1) + 4
        remaining = 297 - 20 - y_start
        if block_h > remaining:
            pdf.add_page()
            y_start = pdf.get_y()
        pdf.set_fill_color(*SLATE_100)
        pdf.rect(pdf.l_margin, y_start, pdf.w - pdf.l_margin - pdf.r_margin, min(block_h, 200), "F")
        pdf.set_xy(pdf.l_margin + 2, y_start + 2)
        pdf.multi_cell(0, line_h, block)
        pdf.ln(3)

    def bold_line(text: str) -> None:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*DARK)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _latin1_safe(text))

    def bullet(text: str) -> None:
        pdf.set_x(pdf.l_margin + 6)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*SLATE_700)
        pdf.cell(4, 5, "-")
        pdf.multi_cell(0, 5, _latin1_safe(text))

    # === Problem onset ===
    if _sec(sections, "onset"):
        itl = a.get("incident_timeline")
        if itl:
            trigger = itl.get("trigger_event", {})
            trigger_dt = itl.get("trigger_dt")
            if trigger_dt:
                heading("Problem Onset")
                _t_parts = [trigger.get("level", "ERROR")]
                if trigger.get("code"):
                    _t_parts.append(trigger["code"])
                if trigger.get("exception"):
                    _t_parts.append(trigger["exception"].rsplit(".", 1)[-1])

                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(*RED_600)
                pdf.cell(0, 7, _latin1_safe(trigger_dt.strftime("%Y-%m-%d %H:%M:%S")), new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*SLATE_700)
                pdf.cell(0, 5, _latin1_safe(" ".join(_t_parts)), new_x="LMARGIN", new_y="NEXT")
                section_end()

    # === Per-File Breakdown ===
    if _sec(sections, "files") and len(file_summary) > 1:
        heading("Per-File Breakdown")
        for fname, total, errors in file_summary:
            err_note = f"  ({errors} errors)" if errors else ""
            body_row(Path(fname).name + ":", f"{total} events{err_note}")
        section_end()

    # === Severity Distribution ===
    if _sec(sections, "levels"):
        heading("Severity Distribution")
        for k, v in s["levels"]:
            if k in ("ERROR", "SEVERE", "FATAL", "CRITICAL"):
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*RED_600)
            elif k in ("WARN", "WARNING"):
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*AMBER_600)
            else:
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*SLATE_700)
            pdf.set_x(pdf.l_margin + 4)
            pdf.cell(30, 5, _latin1_safe(k))
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*SLATE_700)
            # Simple bar
            bar_max = 80
            max_val = s["levels"][0][1] if s["levels"] else 1
            bar_w = max(1, int(bar_max * v / max_val))
            y = pdf.get_y()
            pdf.set_fill_color(*PURPLE if k in ("ERROR", "SEVERE", "FATAL", "CRITICAL") else (*SLATE_300,))
            pdf.rect(pdf.l_margin + 36, y + 1, bar_w, 3, "F")
            pdf.cell(0, 5, _latin1_safe(f"  {v:,}"), new_x="LMARGIN", new_y="NEXT")
        section_end()

    # === Message Codes ===
    if _sec(sections, "codes"):
        heading("Top Message Codes")
        if s["codes"]:
            for k, v in s["codes"]:
                body_row(k + ":", f"{v:,}")
        else:
            body("  (none detected)")
        section_end()

    # === Exceptions ===
    if _sec(sections, "exceptions"):
        heading("Top Exceptions / Errors")
        if s["exceptions"]:
            for k, v in s["exceptions"]:
                body_row(k + ":", f"{v:,}")
        else:
            body("  (none detected)")
        section_end()

    # === Signal Tags ===
    if _sec(sections, "tags"):
        heading("Signal Tags")
        if s["tags"]:
            for k, v in s["tags"]:
                body_row(k + ":", f"{v:,}")
        else:
            body("  (none detected)")
        section_end()

    # === Likely Causes & Fixes ===
    if _sec(sections, "causes") and causes:
        from ..analysis import group_into_incidents
        grouped = group_into_incidents(causes)
        heading("Likely Causes & Fixes")
        for g in grouped["groups"]:
            _ensure_space(30)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*DARK)
            pdf.cell(0, 6, _latin1_safe(f"{g['name']} ({g['total_count']} events)"), new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(*SLATE_500)
            pdf.multi_cell(0, 5, _latin1_safe(g["narrative"]))
            pdf.ln(2)

            for t in g["triggers"]:
                bold_line(f"  {t['title']} ({t['count']} event{'s' if t['count'] != 1 else ''})")
                body(f"    Likely cause: {t['cause']}")
            for e in g["effects"]:
                body(f"    -> {e['title']} ({e['count']} event{'s' if e['count'] != 1 else ''})")

            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*GREEN)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 5, _latin1_safe("  Suggested fixes:"))
            for t in g["triggers"]:
                for fix in t["fixes"]:
                    bullet(fix)
            pdf.ln(3)

        if grouped["ungrouped"]:
            _ensure_space(25)
            bold_line("Other Findings")
            pdf.ln(2)
            for c in grouped["ungrouped"]:
                bold_line(f"  {c['title']} ({c['count']} event{'s' if c['count'] != 1 else ''})")
                body(f"    Likely cause: {c['cause']}")
                for fix in c["fixes"]:
                    bullet(fix)
                pdf.ln(2)
        section_end()

    # === Hung Thread Drilldown ===
    if _sec(sections, "hung") and hung:
        heading("Hung Thread Drilldown")
        for t in hung:
            _ensure_space(25)
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
        section_end()

    # === Timeline ===
    if _sec(sections, "timeline"):
        _export_hist = compact_histogram(hist)
        _hist_label = "Timeline (events per minute)" if len(_export_hist) == len(hist) else "Timeline (compacted)"
        heading(_hist_label)
        hist_lines = render_histogram(_export_hist)
        mono("\n".join(hist_lines))
        section_end()

    # === Sample Events ===
    if _sec(sections, "samples"):
        heading("Sample Events (sanitized)")
        for idx, e in enumerate(samples, start=1):
            _ensure_space(30)
            header = f"{idx}. {e.level or 'UNKNOWN'}"
            if e.code:
                header += f"  {e.code}"
            if e.exception:
                header += f"  --  {e.exception}"
            if e.ts:
                header += f"  ({e.ts})"

            # Sample header with colored level
            pdf.set_font("Helvetica", "B", 9)
            if e.level in ("ERROR", "SEVERE", "FATAL", "CRITICAL"):
                pdf.set_text_color(*RED_600)
            elif e.level in ("WARN", "WARNING"):
                pdf.set_text_color(*AMBER_600)
            else:
                pdf.set_text_color(*DARK)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 5, _latin1_safe(header))

            # Metadata line
            parts = []
            if e.tags:
                parts.append(f"Tags: {', '.join(e.tags)}")
            if e.thread_id:
                parts.append(f"Thread: 0x{e.thread_id}")
            if e.root_cause and e.root_cause != e.exception:
                parts.append(f"Root cause: {e.root_cause}")
            if parts:
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(*SLATE_500)
                pdf.set_x(pdf.l_margin + 4)
                pdf.multi_cell(0, 4, _latin1_safe(" | ".join(parts)))
            mono(e.text[:MAX_EVENT_TEXT])

    # === AI Analysis ===
    if _sec(sections, "ai") and ai_content:
        incident = ai_content.get("incident")
        if incident:
            pdf.add_page()
            heading("AI Analysis")
            _q = ai_content.get("incident_query", "")
            if _q:
                _q_preview = (_q[:100] + "...") if len(_q) > 100 else _q
                pdf.set_font("Helvetica", "I", 9)
                pdf.set_text_color(*SLATE_500)
                pdf.multi_cell(0, 5, _latin1_safe(f"Query: {_q_preview}"))
                pdf.ln(1)

            model = ai_content.get("incident_model", "AI")
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*SLATE_500)
            pdf.cell(0, 5, _latin1_safe(f"Model: {model}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

            # Render AI response with basic markdown support
            _render_ai_text(pdf, incident)

        ask_ai = ai_content.get("ask_ai")
        if ask_ai:
            pdf.add_page()
            heading("Previous AI Queries")
            for entry in ask_ai:
                _ensure_space(25)
                bold_line(f"Q: {entry['query']}")
                provider = entry.get("provider", "AI")
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(*SLATE_500)
                pdf.cell(0, 4, _latin1_safe(f"{provider} - {entry.get('timestamp', '')}"), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)
                _render_ai_text(pdf, entry["answer"])
                pdf.ln(4)

    # --- Footer accent on last page ---
    pdf.set_y(-25)
    pdf.set_draw_color(*GREEN)
    pdf.set_line_width(0.5)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + 30, pdf.get_y())
    pdf.set_line_width(0.2)

    return bytes(pdf.output())


def _render_ai_text(pdf, text: str) -> None:
    """Render AI response text with markdown support (headings, bullets, code blocks, tables, bold)."""
    import re

    lines = text.split("\n")
    i = 0
    in_code_block = False
    code_lines: list[str] = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Code block toggle
        if stripped.startswith("```"):
            if in_code_block:
                # End code block — render collected lines
                if code_lines:
                    pdf.set_font("Courier", "", 7)
                    pdf.set_fill_color(*SLATE_100)
                    pdf.set_text_color(*SLATE_700)
                    block = _latin1_safe("\n".join(code_lines))
                    y_start = pdf.get_y()
                    line_h = 3.5
                    block_h = line_h * (len(code_lines)) + 4
                    if pdf.get_y() + block_h > 277:
                        pdf.add_page()
                        y_start = pdf.get_y()
                    pdf.set_fill_color(*SLATE_100)
                    pdf.rect(pdf.l_margin, y_start, pdf.w - pdf.l_margin - pdf.r_margin, min(block_h, 200), "F")
                    pdf.set_xy(pdf.l_margin + 2, y_start + 2)
                    pdf.multi_cell(0, line_h, block)
                    pdf.ln(3)
                code_lines = []
                in_code_block = False
            else:
                in_code_block = True
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        # Empty line
        if not stripped:
            pdf.ln(2)
            i += 1
            continue

        # Horizontal rule
        if stripped in ("---", "***", "___"):
            pdf.set_draw_color(*SLATE_300)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(4)
            i += 1
            continue

        # Markdown headings
        m = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if m:
            level = len(m.group(1))
            size = {1: 13, 2: 11, 3: 10, 4: 9}.get(level, 9)
            pdf.set_font("Helvetica", "B", size)
            pdf.set_text_color(*DARK)
            pdf.set_x(pdf.l_margin)
            clean = re.sub(r'\*\*([^*]+)\*\*', r'\1', m.group(2))
            pdf.multi_cell(0, 6, _latin1_safe(clean))
            pdf.ln(2)
            i += 1
            continue

        # Markdown table — render as monospace
        if stripped.startswith("|") and "|" in stripped[1:]:
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                tl = lines[i].strip()
                # Skip separator rows (|---|---|)
                if not re.match(r"^\|[-:\s|]+\|$", tl):
                    table_lines.append(tl)
                i += 1
            if table_lines:
                pdf.set_font("Courier", "", 7)
                pdf.set_text_color(*SLATE_700)
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 3.5, _latin1_safe("\n".join(table_lines)))
                pdf.ln(3)
            continue

        # Numbered list items (1. 2. etc.)
        nm = re.match(r"^(\d+)\.\s+(.+)$", stripped)
        if nm:
            pdf.set_x(pdf.l_margin + 4)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*DARK)
            pdf.cell(8, 5, _latin1_safe(f"{nm.group(1)}."))
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*SLATE_700)
            clean = re.sub(r'\*\*([^*]+)\*\*', r'\1', nm.group(2))
            clean = re.sub(r'`([^`]+)`', r'\1', clean)
            pdf.multi_cell(0, 5, _latin1_safe(clean))
            i += 1
            continue

        # Bullet points
        if stripped.startswith("- ") or stripped.startswith("* "):
            pdf.set_x(pdf.l_margin + 6)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*SLATE_700)
            pdf.cell(4, 5, "-")
            clean = re.sub(r'\*\*([^*]+)\*\*', r'\1', stripped[2:])
            clean = re.sub(r'`([^`]+)`', r'\1', clean)
            pdf.multi_cell(0, 5, _latin1_safe(clean))
            i += 1
            continue

        # Regular text — strip bold and inline code markers
        clean = re.sub(r'\*\*([^*]+)\*\*', r'\1', stripped)
        clean = re.sub(r'`([^`]+)`', r'\1', clean)
        clean = re.sub(r'\*([^*]+)\*', r'\1', clean)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*SLATE_700)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _latin1_safe(clean))
        i += 1
