"""Tests for the premium Leadership Brief PDF renderer."""
from __future__ import annotations

import pytest

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

pytestmark = pytest.mark.skipif(not HAS_FPDF, reason="fpdf2 not installed")


SAMPLE_BRIEF = """\
# Incident Brief for Leadership

## What Happened

On the morning of March 23, 2026, the online claim submission service went fully
offline for customers. The outage began at approximately 11:04 AM and was caused
by two separate failures from third-party providers.

## Business Impact

All new insurance claim submissions were blocked. At minimum three confirmed
claims failed to reach our systems. **Revenue impact** is still being quantified.

## Root Cause

Two external providers failed simultaneously:
- A government identity service replaced its security credentials overnight
- Our electronic signature provider had its certificate cancelled

## Our Confidence

We are **highly confident** in this assessment. Both failures are confirmed by
detailed system logs.

## Status and Next Steps

The immediate priority is restoring service by updating credentials and obtaining
replacement certificates. Longer term, we are implementing automated alerts.
"""


class TestRenderBriefPdf:
    def test_returns_valid_pdf(self):
        from logpilot.reports.brief_pdf import render_brief_pdf
        pdf_bytes = render_brief_pdf(SAMPLE_BRIEF)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes[:4] == b"%PDF"
        assert len(pdf_bytes) > 500

    def test_custom_title(self):
        from logpilot.reports.brief_pdf import render_brief_pdf
        pdf_bytes = render_brief_pdf(SAMPLE_BRIEF, title="Custom Title")
        assert pdf_bytes[:4] == b"%PDF"

    def test_empty_brief(self):
        from logpilot.reports.brief_pdf import render_brief_pdf
        pdf_bytes = render_brief_pdf("")
        assert pdf_bytes[:4] == b"%PDF"

    def test_brief_with_bullets(self):
        from logpilot.reports.brief_pdf import render_brief_pdf
        md = "## Section\n\n- Item one\n- Item two\n- Item three\n"
        pdf_bytes = render_brief_pdf(md)
        assert pdf_bytes[:4] == b"%PDF"

    def test_brief_with_bold(self):
        from logpilot.reports.brief_pdf import render_brief_pdf
        md = "## Section\n\nThis has **bold text** in a paragraph.\n"
        pdf_bytes = render_brief_pdf(md)
        assert pdf_bytes[:4] == b"%PDF"

    def test_all_sections_present(self):
        from logpilot.reports.brief_pdf import _parse_brief_sections
        sections = _parse_brief_sections(SAMPLE_BRIEF)
        headings = [h for h, _ in sections]
        assert "What Happened" in headings
        assert "Business Impact" in headings
        assert "Root Cause" in headings
        assert "Our Confidence" in headings
        assert "Status and Next Steps" in headings

    def test_unicode_handling(self):
        from logpilot.reports.brief_pdf import render_brief_pdf
        md = "## Ärende\n\nNordic Försäkring — tjänsten gick ner kl 11:04."
        pdf_bytes = render_brief_pdf(md)
        assert pdf_bytes[:4] == b"%PDF"

    def test_long_brief(self):
        from logpilot.reports.brief_pdf import render_brief_pdf
        # Generate a long brief that forces multiple pages
        sections = []
        for i in range(10):
            sections.append(f"## Section {i + 1}\n\n{'Lorem ipsum dolor sit amet. ' * 50}\n")
        md = "\n".join(sections)
        pdf_bytes = render_brief_pdf(md)
        assert pdf_bytes[:4] == b"%PDF"
        assert len(pdf_bytes) > 2000
