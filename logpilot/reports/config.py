"""Shared configuration, section helpers, and report metadata for all report formats."""
from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Optional


@dataclasses.dataclass
class ReportConfig:
    """Configuration bundle for report rendering functions.

    Pass as the first positional argument to any render_*_report function to
    avoid repeating the same parameters across multiple calls.  All render
    functions also continue to accept the individual keyword arguments for
    backwards compatibility.
    """

    events: list
    top_n: int = 10
    samples_n: int = 5
    hist_minutes: int = 1
    analysis: Optional[dict] = None
    ai_content: Optional[dict] = None
    sections: Optional[set] = None


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


def _report_meta(a: dict) -> tuple[str, str]:
    """Build report title and subtitle from analysis data.

    Returns:
        (title, subtitle) — e.g. ("LogPilot Analysis Report",
        "server.log, access.log — 2025-03-11 10:15 – 14:32 — 1,234 events")
    """
    from ..analysis import parse_ts_datetime

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

    total = a.get("summary", {}).get("total_events", 0)
    parts = []
    if files_str:
        parts.append(files_str)
    if time_str:
        parts.append(time_str)
    if total:
        parts.append(f"{total:,} events")

    return "LogPilot Analysis Report", " — ".join(parts)
