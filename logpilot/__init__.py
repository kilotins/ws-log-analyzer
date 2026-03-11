"""LogPilot — WebSphere/Java log parsing and triage.

This package re-exports all public symbols for backwards compatibility.
Usage: ``from logpilot import parse_file, render_markdown_report``
"""
from __future__ import annotations

# --- parser ---
from .parser import (
    MAX_EVENT_TEXT,
    TS_PATTERNS, LEVEL_RE, WAS_LEVEL_RE, WAS_LEVEL_MAP, WAS_THREAD_RE,
    WAS_CODE_RE, EXC_HEAD_RE, STACK_LINE_RE, CAUSED_BY_RE,
    OOM_RE, HUNG_THREAD_RE, HUNG_THREAD_NAME_RE,
    DB_POOL_RE, SSL_RE, HTTP_RE,
    SECRET_REPLACERS, _REDACT_FAST_CHECK,
    open_text, redact, extract_ts, bucket_tags, classify_event,
    parse_file_iter, parse_file,
)

# --- analysis ---
from .analysis import (
    parse_ts_datetime, _parse_ts_parts,
    summarize, incident_timeline,
    time_histogram, render_histogram,
    pick_samples, per_file_summary,
    _load_heuristics_from_yaml, _HEURISTICS_INLINE, _HEURISTICS,
    _heuristic_keywords, likely_causes,
    _SPLUNK_PREFIX,
    _extract_hung_thread_name, _extract_stack_sample,
    hung_thread_drilldown, suggested_splunk_queries,
    precompute_analysis,
)

# --- reports ---
from .reports import (
    render_json_report, render_markdown_report,
    render_csv_report, render_xml_report, render_pdf_report,
)

# --- ai ---
from .ai import (
    match_user_query, _truncate_event_text, _sanitize_prompt_input,
    CLAUDE_SYSTEM_PROMPT,
    _SKILLS_DIR, _SKILL_TAG_MAP, _SKILL_CODE_PREFIX_MAP,
    _SKILL_EXCEPTION_MAP, _SKILL_QUERY_KEYWORDS,
    _discover_skills, select_skills, load_skill_content,
    build_claude_prompt, TOKEN_LIMITS, _TOKEN_CHARS_PER_TOKEN,
    estimate_tokens, claude_cache_key, ask_gemini,
    MAX_SKILLS,
)

# --- cli ---
from .cli import main

__all__ = [
    # parser
    "MAX_EVENT_TEXT", "TS_PATTERNS", "LEVEL_RE", "WAS_LEVEL_RE", "WAS_LEVEL_MAP",
    "WAS_THREAD_RE", "WAS_CODE_RE", "EXC_HEAD_RE", "STACK_LINE_RE", "CAUSED_BY_RE",
    "OOM_RE", "HUNG_THREAD_RE", "HUNG_THREAD_NAME_RE",
    "DB_POOL_RE", "SSL_RE", "HTTP_RE", "SECRET_REPLACERS",
    "open_text", "redact", "extract_ts", "bucket_tags", "classify_event",
    "parse_file_iter", "parse_file",
    # analysis
    "parse_ts_datetime", "summarize", "incident_timeline",
    "time_histogram", "render_histogram", "pick_samples", "per_file_summary",
    "likely_causes", "hung_thread_drilldown", "suggested_splunk_queries",
    "precompute_analysis",
    # reports
    "render_json_report", "render_markdown_report",
    "render_csv_report", "render_xml_report", "render_pdf_report",
    # ai
    "match_user_query", "CLAUDE_SYSTEM_PROMPT",
    "select_skills", "load_skill_content", "build_claude_prompt",
    "TOKEN_LIMITS", "estimate_tokens", "claude_cache_key", "ask_gemini",
    "MAX_SKILLS",
    # cli
    "main",
]
