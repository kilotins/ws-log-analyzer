"""JSON structured log format plugin (Docker, structlog, Bunyan, zap, Winston)."""
from __future__ import annotations

import json
import re
from typing import Any

from .base import (
    EXC_HEAD_RE, LEVEL_RE, OOM_RE,
    extract_exception, extract_root_cause, is_stack_or_caused_by,
)

# --- Field name sets ---
_TS_FIELDS = ("timestamp", "time", "ts", "@timestamp", "datetime", "date", "t")
_LEVEL_FIELDS = ("level", "severity", "lvl", "loglevel", "log_level", "priority")
_MSG_FIELDS = ("msg", "message", "short_message", "text")
_EXC_FIELDS = ("err", "error", "exception", "stack_trace", "stacktrace", "stack", "exc_info")
_THREAD_FIELDS = ("thread", "thread_name", "thread_id", "threadName")

# Bunyan numeric levels
_BUNYAN_LEVELS = {10: "TRACE", 20: "DEBUG", 30: "INFO", 40: "WARN", 50: "ERROR", 60: "FATAL"}

# Syslog priority (0=emerg ... 7=debug)
_SYSLOG_LEVELS = {0: "FATAL", 1: "FATAL", 2: "CRITICAL", 3: "ERROR", 4: "WARN", 5: "INFO", 6: "INFO", 7: "DEBUG"}

# Level string normalization
_LEVEL_NORMALIZE = {
    "warning": "WARN", "warn": "WARN",
    "err": "ERROR", "error": "ERROR",
    "info": "INFO", "information": "INFO",
    "debug": "DEBUG", "trace": "TRACE",
    "fatal": "FATAL", "critical": "CRITICAL",
    "severe": "ERROR", "notice": "INFO",
    "emergency": "FATAL", "emerg": "FATAL", "alert": "FATAL",
    "panic": "FATAL",
}

# Signal tag patterns
_SSL_RE = re.compile(
    r'SSLHandshakeException|handshake_failure|PKIX path building failed'
    r'|unable to find valid certification path|certificate.*(expired|invalid|unknown)',
    re.IGNORECASE,
)
_CONN_RE = re.compile(
    r'connection pool|pool.*exhaust|connection refused|connection timed? ?out'
    r'|ECONNREFUSED|ECONNRESET|ETIMEDOUT|J2CA|Timeout waiting for idle object',
    re.IGNORECASE,
)
_HTTP_RE = re.compile(r'\b[45]\d{2}\b', re.IGNORECASE)


def _safe_parse(line: str) -> dict | None:
    """Try to parse a line as JSON, return dict or None."""
    stripped = line.strip()
    if not stripped or stripped[0] != '{':
        return None
    try:
        obj = json.loads(stripped)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _unwrap_docker(obj: dict) -> dict:
    """Unwrap Docker JSON log wrapper: {"log":"...", "stream":"...", "time":"..."}."""
    if "log" in obj and "stream" in obj and "time" in obj:
        inner_line = obj["log"].rstrip("\n")
        inner = _safe_parse(inner_line)
        if inner is not None:
            # Inner is also JSON — use it, but keep docker time if no ts
            if not any(k in inner for k in _TS_FIELDS):
                inner["time"] = obj["time"]
            # Preserve k8s metadata if present
            if "kubernetes" in obj:
                inner["_kubernetes"] = obj["kubernetes"]
            return inner
        # Inner is plain text — synthesize a JSON-like dict
        result: dict[str, Any] = {"message": inner_line, "time": obj["time"], "stream": obj["stream"]}
        if "kubernetes" in obj:
            result["_kubernetes"] = obj["kubernetes"]
        return result
    return obj


def _get_field(obj: dict, field_names: tuple[str, ...]) -> Any:
    """Get the first matching field value from obj."""
    for name in field_names:
        if name in obj:
            return obj[name]
    return None


def _normalize_level(raw: Any) -> str | None:
    """Normalize a level value (string or numeric) to standard level string."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        num = int(raw)
        # Try Bunyan first
        if num in _BUNYAN_LEVELS:
            return _BUNYAN_LEVELS[num]
        # Try syslog priority (0-7)
        if 0 <= num <= 7:
            return _SYSLOG_LEVELS[num]
        return None
    if isinstance(raw, str):
        key = raw.strip().lower()
        if key in _LEVEL_NORMALIZE:
            return _LEVEL_NORMALIZE[key]
        # Already standard?
        upper = raw.strip().upper()
        if upper in ("INFO", "DEBUG", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL", "TRACE"):
            return upper
        return None
    return None


def _get_message(obj: dict) -> str:
    """Get message text from known message fields."""
    val = _get_field(obj, _MSG_FIELDS)
    return str(val) if val is not None else ""


def _get_error_text(obj: dict) -> str:
    """Get error/exception text from known error fields."""
    parts = []
    for field in _EXC_FIELDS:
        if field in obj:
            val = obj[field]
            if isinstance(val, dict):
                # e.g. {"message": "...", "stack": "..."}
                parts.append(json.dumps(val))
            elif val is not None:
                parts.append(str(val))
    return "\n".join(parts)


class JSONFormat:
    """JSON structured log format (Docker, structlog, Bunyan, zap, Winston)."""

    name = "json"
    description = "JSON structured logs (Docker, structlog, Bunyan, zap, Winston)"

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 based on how many lines parse as JSON with log-like fields."""
        if not lines:
            return 0.0
        json_count = 0
        has_log_fields = 0
        for line in lines:
            obj = _safe_parse(line)
            if obj is None:
                continue
            json_count += 1
            obj = _unwrap_docker(obj)
            # Check for log-like fields
            has_ts = any(k in obj for k in _TS_FIELDS)
            has_level = any(k in obj for k in _LEVEL_FIELDS)
            has_msg = any(k in obj for k in _MSG_FIELDS)
            if has_ts or has_level or has_msg:
                has_log_fields += 1

        if json_count == 0:
            return 0.0

        # Base: fraction of lines that are valid JSON
        json_ratio = json_count / len(lines)
        # Boost if they have log-like fields
        field_ratio = has_log_fields / json_count if json_count else 0
        score = json_ratio * 0.5 + field_ratio * 0.5
        return min(score, 1.0)

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp from a JSON log line."""
        obj = _safe_parse(line)
        if obj is None:
            return None
        obj = _unwrap_docker(obj)
        ts = _get_field(obj, _TS_FIELDS)
        if ts is not None:
            return str(ts)
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity level from a JSON log line."""
        obj = _safe_parse(line)
        if obj is None:
            # Fall back to text-based level detection for non-JSON lines
            m = LEVEL_RE.search(line)
            return m.group(1).upper() if m else None
        obj = _unwrap_docker(obj)
        raw = _get_field(obj, _LEVEL_FIELDS)
        level = _normalize_level(raw)
        if level:
            return level
        # Fall back to scanning message text
        msg = _get_message(obj)
        m = LEVEL_RE.search(msg)
        return m.group(1).upper() if m else None

    def is_continuation(self, line: str) -> bool:
        """JSON logs are one-event-per-line; non-JSON lines may be continuations."""
        if _safe_parse(line) is not None:
            return False
        return is_stack_or_caused_by(line)

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a JSON log event and return metadata dict."""
        # Try to parse the first line (or only line) as JSON
        first_line = text.split("\n", 1)[0]
        obj = _safe_parse(first_line)

        if obj is None:
            # Not JSON — fall back to text-based classification
            return self._classify_text(text)

        obj = _unwrap_docker(obj)

        # Level
        raw_level = _get_field(obj, _LEVEL_FIELDS)
        level = _normalize_level(raw_level)

        # Thread
        thread_id = _get_field(obj, _THREAD_FIELDS)
        if thread_id is not None:
            thread_id = str(thread_id)

        # Message and error text
        msg = _get_message(obj)
        err_text = _get_error_text(obj)
        full_text = "\n".join(filter(None, [msg, err_text, text]))

        # Exception
        exc = extract_exception(full_text)

        # Root cause
        root_cause = extract_root_cause(full_text)

        # If no level from fields, try to get from message text
        if not level:
            m = LEVEL_RE.search(msg)
            if m:
                level = m.group(1).upper()

        # Code (WAS-style)
        code = None
        was_code_match = re.search(r'\b([A-Z]{4,5}\d{4}[A-Z])\b', full_text)
        if was_code_match:
            code = was_code_match.group(1)

        tags = self.bucket_tags(full_text)

        # Extract trace/correlation IDs from structured fields
        trace_ids = []
        for key in ("trace_id", "traceId", "request_id", "requestId",
                     "correlation_id", "correlationId", "x-request-id",
                     "span_id", "spanId"):
            val = obj.get(key)
            if val and isinstance(val, str):
                trace_ids.append(val.lower())

        result = {
            "level": level,
            "thread_id": thread_id,
            "code": code,
            "exception": exc,
            "root_cause": root_cause,
            "tags": sorted(tags),
        }
        if trace_ids:
            result["trace_ids"] = trace_ids
        return result

    def _classify_text(self, text: str) -> dict[str, Any]:
        """Fallback text-based classification for non-JSON content."""
        level = None
        m = LEVEL_RE.search(text)
        if m:
            level = m.group(1).upper()
        exc = extract_exception(text)
        root_cause = extract_root_cause(text)
        tags = self.bucket_tags(text)
        return {
            "level": level,
            "thread_id": None,
            "code": None,
            "exception": exc,
            "root_cause": root_cause,
            "tags": sorted(tags),
        }

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags from event text."""
        tags: set[str] = set()
        if OOM_RE.search(text):
            tags.add("OOM/GC")
        if _SSL_RE.search(text):
            tags.add("SSL/TLS")
        if _CONN_RE.search(text):
            tags.add("DB/Pool")
        if _HTTP_RE.search(text):
            tags.add("HTTP")
        return tags
