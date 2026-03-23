"""Report rendering package: Markdown, JSON, HTML, PDF.

Re-exports all public symbols for backwards compatibility.
Usage: ``from logpilot.reports import render_html_report, ReportConfig``
"""
from .config import ReportConfig, REPORT_SECTIONS, ALL_SECTIONS, _sec, _report_meta
from .json_report import render_json_report
from .markdown import render_markdown_report
from .html import render_html_report, _LOGPILOT_LOGO_SVG
from .pdf import render_pdf_report
from .executive_summary import render_executive_summary, render_executive_summary_html

__all__ = [
    "ReportConfig",
    "REPORT_SECTIONS",
    "ALL_SECTIONS",
    "_sec",
    "_report_meta",
    "render_json_report",
    "render_markdown_report",
    "render_html_report",
    "render_pdf_report",
    "render_executive_summary",
    "render_executive_summary_html",
    "_LOGPILOT_LOGO_SVG",
]
