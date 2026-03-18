"""JSON report renderer."""
from __future__ import annotations

import json

from ..parser import MAX_EVENT_TEXT
from ..analysis import precompute_analysis
from ..event import LogEvent
from .config import ReportConfig, _sec


def render_json_report(
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
    """Generate a JSON triage report string from parsed events."""
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
    from ..analysis import group_into_incidents
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
