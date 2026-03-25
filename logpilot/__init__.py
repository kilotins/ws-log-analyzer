"""LogPilot — Log parsing and triage.

This package re-exports all public symbols for backwards compatibility.
Usage: ``from logpilot import parse_file, render_markdown_report``
"""
from __future__ import annotations

__version__ = "1.1.1"

# --- event ---
from .event import LogEvent

# --- parser ---
from .parser import (
    MAX_EVENT_TEXT,
    TS_PATTERNS, LEVEL_RE, WAS_LEVEL_RE, WAS_LEVEL_MAP, WAS_THREAD_RE,
    WAS_CODE_RE, EXC_HEAD_RE, STACK_LINE_RE, CAUSED_BY_RE,
    OOM_RE, HUNG_THREAD_RE, HUNG_THREAD_NAME_RE,
    DB_POOL_RE, SSL_RE, HTTP_RE,
    TRACE_ID_PATTERNS,
    SECRET_REPLACERS,
    TZ_OFFSET_RE, TZ_ABBREV_RE,
    open_text, redact, extract_ts, extract_tz, bucket_tags, classify_event,
    extract_trace_ids,
    parse_file_iter, parse_file, parse_file_cached,
)

# --- analysis ---
from .analysis import (
    parse_ts_datetime,
    normalize_ts_utc, sort_events_chronologically,
    summarize, incident_timeline,
    time_histogram, render_histogram,
    pick_samples, per_file_summary, per_source_summary,
    group_into_incidents, likely_causes,
    compute_confidence, build_failure_chain,
    hung_thread_drilldown,
    detect_cross_system_cascades,
    correlate_by_trace_id, find_cross_system_chains,
    precompute_analysis,
    compare_periods,
    compute_noise_scores, filter_noise,
)

# --- trace to code ---
from .trace_to_code import CodeLocation, extract_code_locations  # noqa: F401
from .code_search import CodeMatch, search_codebase  # noqa: F401

# --- jira ---
from .jira_tickets import generate_all_tickets, generate_ticket_text, suggest_team  # noqa: F401

# --- reports ---
from .reports import (
    ReportConfig,
    render_json_report, render_markdown_report,
    render_html_report, render_pdf_report,
    REPORT_SECTIONS, ALL_SECTIONS,
)

# --- ai ---
from .ai import (
    match_user_query,
    CLAUDE_SYSTEM_PROMPT, build_system_prompt,
    select_skills, load_skill_content,
    build_claude_prompt, build_cross_system_prompt,
    build_incident_system_prompt, build_incident_user_prompt, incident_cache_key,
    TOKEN_LIMITS,
    estimate_tokens, claude_cache_key, triage_cache_key, ask_gemini,
    MAX_SKILLS,
)

# --- discovery ---
from .discovery import discover_log_files, DiscoveredFile, DiscoveryResult, RejectedFile

# --- cli ---
from .cli import main

__all__ = [
    # parser
    "MAX_EVENT_TEXT", "TS_PATTERNS", "LEVEL_RE", "WAS_LEVEL_RE", "WAS_LEVEL_MAP",
    "WAS_THREAD_RE", "WAS_CODE_RE", "EXC_HEAD_RE", "STACK_LINE_RE", "CAUSED_BY_RE",
    "OOM_RE", "HUNG_THREAD_RE", "HUNG_THREAD_NAME_RE",
    "DB_POOL_RE", "SSL_RE", "HTTP_RE", "TRACE_ID_PATTERNS", "SECRET_REPLACERS",
    "TZ_OFFSET_RE", "TZ_ABBREV_RE",
    "open_text", "redact", "extract_ts", "extract_tz", "bucket_tags", "classify_event",
    "extract_trace_ids",
    "parse_file_iter", "parse_file", "parse_file_cached",
    # analysis
    "parse_ts_datetime", "normalize_ts_utc", "sort_events_chronologically",
    "summarize", "incident_timeline",
    "time_histogram", "render_histogram", "pick_samples", "per_file_summary", "per_source_summary",
    "group_into_incidents", "compute_confidence", "build_failure_chain",
    "likely_causes", "hung_thread_drilldown",
    "detect_cross_system_cascades",
    "correlate_by_trace_id", "find_cross_system_chains",
    "precompute_analysis",
    "compare_periods",
    "compute_noise_scores", "filter_noise",
    # reports
    "ReportConfig",
    "render_json_report", "render_markdown_report",
    "render_html_report", "render_pdf_report",
    # ai
    "match_user_query", "CLAUDE_SYSTEM_PROMPT", "build_system_prompt",
    "select_skills", "load_skill_content", "build_claude_prompt", "build_cross_system_prompt",
    "build_incident_system_prompt", "build_incident_user_prompt", "incident_cache_key",
    "TOKEN_LIMITS", "estimate_tokens", "claude_cache_key", "ask_gemini",
    "MAX_SKILLS",
    # trace to code
    "CodeLocation", "extract_code_locations", "CodeMatch", "search_codebase",
    # jira
    "generate_all_tickets", "generate_ticket_text", "suggest_team",
    # discovery
    "discover_log_files", "DiscoveredFile", "DiscoveryResult", "RejectedFile",
    # event
    "LogEvent",
    # cli
    "main",
]
