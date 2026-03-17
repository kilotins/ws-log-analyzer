"""WebSphere / Liberty log format plugin."""
from __future__ import annotations

import re
from typing import Any

from .base import (
    CAUSED_BY_RE, EXC_HEAD_RE, LEVEL_RE, OOM_RE, STACK_LINE_RE,
    extract_exception, extract_root_cause, is_stack_or_caused_by,
)

# --- WAS-specific patterns ---

TS_PATTERNS = [
    # WebSphere classic: [10/12/15 21:22:04:257 CEST]
    re.compile(r'\[(?P<ts>\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}:\d{2}:\d{3})\s+\w+\]'),
    # ISO / WebSphere common: 2025-03-05 12:34:56:789 or 2025-03-05T12:34:56.789
    re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,:.]\d{3,6})?)'),
]

# Single-letter severity after thread ID: [ts] threadid Component X
WAS_LEVEL_RE = re.compile(r'\]\s+[0-9a-f]+\s+\S+\s+([IAWEOFRDN])\s')
WAS_LEVEL_MAP = {
    'I': 'INFO', 'A': 'AUDIT', 'W': 'WARNING', 'E': 'ERROR',
    'O': 'STDOUT', 'F': 'FATAL', 'R': 'REPORT', 'D': 'DEBUG',
    'N': 'NOTICE',
}

WAS_THREAD_RE = re.compile(r'\]\s+([0-9a-f]{8})\s+')
WAS_CODE_RE = re.compile(r'\b([A-Z]{4,5}\d{4}[A-Z])\b')

HUNG_THREAD_RE = re.compile(r'hung thread|ThreadMonitor|WSVR0605|stuck thread|CWWKE0701E', re.IGNORECASE)
HUNG_THREAD_NAME_RE = re.compile(
    r'(?:[Tt]hread\s+["\']([^"\']+)["\'])'
    r'|(?:[Tt]hread\s+(WebContainer\s*:\s*\d+))'
    r'|(?:the\s+(Default Executor-thread-\d+))'
    r'|(?:[Tt]hread\s+(Default Executor-thread-\d+))',
    re.IGNORECASE,
)
DB_POOL_RE = re.compile(r'connection pool|J2CA|pool.*exhaust|Timeout waiting for idle object', re.IGNORECASE)
SSL_RE = re.compile(r'SSLHandshakeException|handshake_failure|PKIX path building failed|unable to find valid certification path', re.IGNORECASE)
HTTP_RE = re.compile(r'\b(4\d\d|5\d\d)\b.*\b(HTTP|SRVE)\b|\b(HTTP|SRVE)\b.*\b(4\d\d|5\d\d)\b', re.IGNORECASE)


class WASFormat:
    """WebSphere Application Server / Liberty log format."""

    name = "was"
    description = "WebSphere / Liberty (SystemOut.log)"

    def detect(self, lines: list[str]) -> float:
        """Score based on WAS-specific patterns in first N lines."""
        if not lines:
            return 0.0
        score = 0
        for line in lines:
            # WAS classic bracket timestamp
            if TS_PATTERNS[0].search(line):
                score += 3
            # WAS single-letter severity
            if WAS_LEVEL_RE.search(line):
                score += 3
            # WAS message codes
            if WAS_CODE_RE.search(line):
                score += 2
            # WAS thread ID (hex)
            if WAS_THREAD_RE.search(line):
                score += 1
        # Normalize: max possible per line ~9, we want 0-1
        return min(score / (len(lines) * 3), 1.0)

    def extract_ts(self, line: str) -> str | None:
        for rx in TS_PATTERNS:
            m = rx.search(line)
            if m:
                return m.group("ts")
        return None

    def extract_level(self, line: str) -> str | None:
        wm = WAS_LEVEL_RE.search(line)
        if wm:
            return WAS_LEVEL_MAP.get(wm.group(1), wm.group(1))
        m = LEVEL_RE.search(line)
        if m:
            return m.group(1).upper()
        return None

    def is_continuation(self, line: str) -> bool:
        return is_stack_or_caused_by(line)

    def classify_event(self, text: str) -> dict[str, Any]:
        # Level — prefer WAS single-letter over keyword
        lvl = None
        wm = WAS_LEVEL_RE.search(text)
        if wm:
            lvl = WAS_LEVEL_MAP.get(wm.group(1), wm.group(1))
        else:
            m = LEVEL_RE.search(text)
            if m:
                lvl = m.group(1).upper()

        # Thread ID
        thread_id = None
        tm = WAS_THREAD_RE.search(text)
        if tm:
            thread_id = tm.group(1)

        # WAS message code
        code = None
        cm = WAS_CODE_RE.search(text)
        if cm:
            code = cm.group(1)

        exc = extract_exception(text)
        root_cause = extract_root_cause(text)
        tags = self.bucket_tags(text)

        return {
            "level": lvl,
            "thread_id": thread_id,
            "code": code,
            "exception": exc,
            "root_cause": root_cause,
            "tags": sorted(tags),
        }

    def bucket_tags(self, text: str) -> set[str]:
        tags: set[str] = set()
        if OOM_RE.search(text):
            tags.add("OOM/GC")
        if HUNG_THREAD_RE.search(text):
            tags.add("HungThreads")
        if DB_POOL_RE.search(text):
            tags.add("DB/Pool")
        if SSL_RE.search(text):
            tags.add("SSL/TLS")
        if HTTP_RE.search(text):
            tags.add("HTTP")
        return tags
