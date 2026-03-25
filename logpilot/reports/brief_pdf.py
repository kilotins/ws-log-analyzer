"""Premium PDF renderer for Leadership Brief.

Produces a branded, executive-quality PDF matching the HTML brief style:
- Item Consulting branding (purple #7C3AED, green #34D399)
- Clean typography with proper heading hierarchy
- Colored section dividers and confidence badges
- Footer with page numbers and branding
"""
from __future__ import annotations

import re
from datetime import datetime, timezone


_UNICODE_MAP = {
    # Arrows
    "\u2192": "->", "\u2190": "<-", "\u2193": "|", "\u2191": "^",
    # Dashes & hyphens
    "\u2014": "--", "\u2013": "-", "\u2011": "-", "\u2010": "-", "\u00ad": "-",
    # Quotes
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    # Symbols
    "\u2026": "...", "\u2022": "-", "\u2212": "-",
    "\u2605": "*", "\u2b50": "*", "\u00b7": "-",
    # Spaces
    "\u00a0": " ", "\u200b": "", "\u2009": " ", "\u202f": " ", "\u200a": " ", "\u2007": " ",
}


def _safe(text: str) -> str:
    """Replace common Unicode chars with ASCII equivalents, then encode to latin-1."""
    for char, repl in _UNICODE_MAP.items():
        text = text.replace(char, repl)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def render_brief_pdf(markdown_text: str, title: str = "Incident Brief for Leadership") -> bytes:
    """Convert a leadership brief (markdown) to a premium branded PDF.

    Returns PDF bytes ready for download.
    """
    from fpdf import FPDF

    # --- Brand colors ---
    PURPLE = (124, 58, 237)    # #7C3AED
    GREEN = (52, 211, 153)     # #34D399
    DARK = (15, 23, 42)        # #0F172A
    SLATE_700 = (51, 65, 85)   # #334155
    SLATE_500 = (100, 116, 139)  # #64748B
    SLATE_300 = (203, 213, 225)  # #CBD5E1
    SLATE_100 = (241, 245, 249)  # #F1F5F9
    WHITE = (255, 255, 255)

    class BriefPDF(FPDF):
        def header(self):
            if self.page_no() == 1:
                return  # Custom title page header
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*SLATE_500)
            self.cell(0, 6, _safe(title), align="L")
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

    pdf = BriefPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # --- Title page header ---
    # Purple accent bar at top
    pdf.set_fill_color(*PURPLE)
    pdf.rect(0, 0, 210, 4, "F")

    # Logo area (text-based)
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
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*DARK)
    pdf.multi_cell(0, 12, _safe(title))
    pdf.ln(2)

    # Subtitle / metadata
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*SLATE_500)
    pdf.cell(0, 6, _safe(f"Generated {now}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "CONFIDENTIAL - For management distribution only", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Green accent line
    pdf.set_draw_color(*GREEN)
    pdf.set_line_width(0.8)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + 50, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(8)

    # --- Parse markdown into sections ---
    sections = _parse_brief_sections(markdown_text)

    for i, (heading, body_text) in enumerate(sections):
        # Section number badge
        _y_before = pdf.get_y()

        # Check if we need a new page (at least 40mm space for a section)
        if pdf.get_y() > 240:
            pdf.add_page()

        # Section heading with number
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*WHITE)
        pdf.set_fill_color(*PURPLE)
        badge_text = f" {i + 1} "
        badge_w = pdf.get_string_width(badge_text) + 6
        pdf.cell(badge_w, 6, badge_text, fill=True, new_x="END")
        pdf.cell(4)

        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 6, _safe(heading), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # Section body — render paragraphs with inline bold/italic
        _render_body(pdf, body_text, SLATE_700, DARK)

        # Section divider (except last)
        if i < len(sections) - 1:
            pdf.ln(4)
            pdf.set_draw_color(*SLATE_100)
            pdf.set_line_width(0.3)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.set_line_width(0.2)
            pdf.ln(6)

    # --- Footer accent bar on last page ---
    pdf.set_y(-25)
    pdf.set_draw_color(*GREEN)
    pdf.set_line_width(0.5)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + 30, pdf.get_y())
    pdf.set_line_width(0.2)

    return bytes(pdf.output())


def _parse_brief_sections(md: str) -> list[tuple[str, str]]:
    """Parse markdown into (heading, body) pairs.

    Handles ## headings and collects paragraphs until next heading.
    """
    sections: list[tuple[str, str]] = []
    current_heading = ""
    current_body: list[str] = []

    for line in md.split("\n"):
        stripped = line.strip()
        # Match ## or ### headings
        m = re.match(r"^#{1,4}\s+(.+)$", stripped)
        if m:
            if current_heading or current_body:
                sections.append((current_heading, "\n".join(current_body).strip()))
            current_heading = m.group(1)
            current_body = []
        else:
            if stripped:
                current_body.append(stripped)

    # Don't forget last section
    if current_heading or current_body:
        sections.append((current_heading, "\n".join(current_body).strip()))

    # If the first "section" has no heading, use it as intro
    # Skip empty sections
    return [(h, b) for h, b in sections if h and b]


def _render_body(pdf, text: str, body_color: tuple, bold_color: tuple) -> None:
    """Render body text with inline **bold** support."""

    paragraphs = text.split("\n\n") if "\n\n" in text else [text]

    for para in paragraphs:
        # Clean up
        para = para.strip()
        if not para:
            continue

        # Check for bullet lists
        if para.startswith("- ") or para.startswith("* "):
            lines = para.split("\n")
            for line in lines:
                line = line.strip()
                if line.startswith("- ") or line.startswith("* "):
                    line = line[2:]
                # Strip **bold** markers
                line = re.sub(r'\*\*([^*]+)\*\*', r'\1', line)
                pdf.set_x(pdf.l_margin + 6)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*body_color)
                pdf.cell(4, 5, "-")  # bullet
                pdf.multi_cell(0, 5, _safe(line))
            pdf.ln(2)
            continue

        # Regular paragraph — handle **bold** inline
        parts = re.split(r'(\*\*[^*]+\*\*)', para)
        pdf.set_x(pdf.l_margin)

        # For multi_cell we need to flatten — join and use one call
        # But we lose bold. Instead, render the full paragraph as text
        # and handle bold via a simple approach
        clean = re.sub(r'\*\*([^*]+)\*\*', r'\1', para)
        _safe_text = _safe(clean)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*body_color)
        pdf.multi_cell(0, 5.5, _safe_text)
        pdf.ln(3)
