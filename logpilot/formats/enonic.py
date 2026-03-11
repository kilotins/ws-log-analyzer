"""Enonic XP log format plugin (server.log + Jetty request log)."""
from __future__ import annotations

import re
from typing import Any

from .base import (
    LEVEL_RE,
    OOM_RE,
    extract_exception,
    extract_root_cause,
    is_stack_or_caused_by,
)

# --- Logback-style timestamp (Enonic uses Logback internally) ---

# Full ISO: 2025-03-11 10:15:33.123 or 2025-03-11T10:15:33.123 or comma-millis
_TS_FULL_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]\d{3})'
)

# Time-only Logback short: 10:15:33.123
_TS_TIME_ONLY_RE = re.compile(
    r'^(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3})\s'
)

# NCSA / Jetty request log bracket timestamp:
# 192.168.1.1 - - [11/Mar/2025:10:15:33 +0100] "GET /site/default/draft ..."
_NCSA_TS_RE = re.compile(
    r'\[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]'
)

# --- Level patterns ---

_LOGBACK_LEVEL_RE = re.compile(
    r'\b(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\b'
)

# --- Logback line start: timestamp + level ---
_LOGBACK_LINE_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]\d{3}\s+'
    r'(?:FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\b'
)

_LOGBACK_SHORT_RE = re.compile(
    r'^\d{2}:\d{2}:\d{2}\.\d{3}\s+(?:FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\b'
)

# --- NCSA / Jetty request log line ---
_NCSA_LINE_RE = re.compile(
    r'^\S+\s+\S+\s+\S+\s+\[[\d/\w: +\-]+\]\s+"[A-Z]+\s+'
)

# HTTP status code from NCSA line
_NCSA_STATUS_RE = re.compile(
    r'"\s+(?P<status>\d{3})\s'
)

# --- Enonic-specific markers ---

# Abbreviated Enonic loggers: c.e.x. or c.e.xp.
_ENONIC_ABBREV_RE = re.compile(r'\bc\.e\.x(?:p)?\.', re.IGNORECASE)

# Full Enonic package: com.enonic.xp.
_ENONIC_FULL_RE = re.compile(r'\bcom\.enonic\.xp\.', re.IGNORECASE)

# Enonic domain keywords
_ENONIC_KEYWORDS_RE = re.compile(
    r'\b(?:blobStore|blobStores|repository|repositoryService'
    r'|elasticsearch|cluster\.health|cluster\.state'
    r'|node\.(?:started|stopped|connected|disconnected)'
    r'|reindex|snapshot|dump|load|vacuum'
    r'|content\.(?:create|update|delete|publish|unpublish)'
    r'|enonic\.(?:xp|app))\b',
    re.IGNORECASE,
)

# --- Thread name in square brackets ---
_THREAD_RE = re.compile(r'\[([^\[\]]+)\]')

# --- Logger name: dotted package ---
_LOGGER_RE = re.compile(
    r'(?:^|\s)([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*){2,})(?:\s|$|:|\s*[-:])'
)

# --- Signal tag patterns ---

_SSL_RE = re.compile(
    r'SSLHandshakeException|handshake_failure|PKIX path building failed'
    r'|unable to find valid certification path|certificate.*(expired|invalid|unknown)',
    re.IGNORECASE,
)

_CLUSTER_RE = re.compile(
    r'cluster\.health|ClusterHealth|MasterNotDiscoveredException'
    r'|NoNodeAvailableException|NodeDisconnectedException'
    r'|cluster\.state|node\.(started|stopped|connected|disconnected)'
    r'|elasticsearch.*(?:red|yellow)',
    re.IGNORECASE,
)

_REPO_RE = re.compile(
    r'repository|blobStore|RepositoryNotFoundException'
    r'|NodeAlreadyExistException|BranchAlreadyExistException'
    r'|NodeNotFoundException|snapshot|dump|vacuum|reindex'
    r'|IndexException|IndexServiceException',
    re.IGNORECASE,
)

_INDEX_RE = re.compile(
    r'IndexException|IndexServiceException|reindex'
    r'|mapping.*failed|elasticsearch.*index'
    r'|SearchException|AggregationException',
    re.IGNORECASE,
)

_CONTENT_RE = re.compile(
    r'content\.(?:create|update|delete|publish|unpublish)'
    r'|ContentNotFoundException|ContentAlreadyExistsException'
    r'|PublishContentException|ContentDataValidationException'
    r'|ContentAccessException',
    re.IGNORECASE,
)

_HTTP_STATUS_RE = re.compile(r'\b[45]\d{2}\b')

_JETTY_RE = re.compile(
    r'org\.eclipse\.jetty|jetty\.server|jetty\.servlet'
    r'|org\.eclipse\.jetty\.io\.EofException',
    re.IGNORECASE,
)


def _has_timestamp(line: str) -> bool:
    """Return True if line starts with a recognized timestamp."""
    return bool(
        _LOGBACK_LINE_RE.match(line)
        or _LOGBACK_SHORT_RE.match(line)
        or _NCSA_LINE_RE.match(line)
    )


class EnonicFormat:
    """Enonic XP log format (server.log + Jetty request log)."""

    name = "enonic"
    description = "Enonic XP (server.log, Jetty request log)"

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 how likely these lines match Enonic XP format.

        Uses Logback patterns as a baseline and adds bonuses for Enonic-specific
        markers. Must score HIGHER than plain Log4j for Enonic content.
        """
        if not lines:
            return 0.0

        score = 0
        enonic_markers = 0

        for line in lines:
            # Logback baseline scoring (same as Log4j plugin)
            if _LOGBACK_LINE_RE.match(line):
                score += 3
            elif _LOGBACK_SHORT_RE.match(line):
                score += 3
            elif _NCSA_LINE_RE.match(line):
                score += 2
            elif _LOGGER_RE.search(line):
                score += 1

            # Enonic-specific bonuses
            if _ENONIC_ABBREV_RE.search(line):
                enonic_markers += 1
                score += 3
            if _ENONIC_FULL_RE.search(line):
                enonic_markers += 1
                score += 3
            if _ENONIC_KEYWORDS_RE.search(line):
                enonic_markers += 1
                score += 2
            if _JETTY_RE.search(line):
                enonic_markers += 1
                score += 1

        # If no Enonic-specific markers found, don't compete with log4j
        if enonic_markers == 0:
            return 0.0

        # Base score normalized like Log4j, plus a small bonus per
        # Enonic marker so Enonic always beats plain Log4j.
        base = min(score / (len(lines) * 3), 1.0)
        bonus = min(enonic_markers * 0.01, 0.05)
        return min(base + bonus, 1.0) if base < 1.0 else 1.0 + bonus

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp from a log line (Logback or NCSA)."""
        m = _TS_FULL_RE.search(line)
        if m:
            return m.group("ts")
        m = _TS_TIME_ONLY_RE.match(line)
        if m:
            return m.group("ts")
        m = _NCSA_TS_RE.search(line)
        if m:
            return m.group("ts")
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity level from a log line.

        For NCSA request lines, derives level from HTTP status code.
        """
        # Check for standard Logback level first
        m = _LOGBACK_LEVEL_RE.search(line)
        if m:
            return m.group(1)

        # NCSA request log: derive level from HTTP status code
        sm = _NCSA_STATUS_RE.search(line)
        if sm:
            status = int(sm.group("status"))
            if status >= 500:
                return "ERROR"
            elif status >= 400:
                return "WARN"
            else:
                return "INFO"

        return None

    def is_continuation(self, line: str) -> bool:
        """Return True if line is a continuation of the previous event."""
        if is_stack_or_caused_by(line):
            return True
        if not _has_timestamp(line):
            return True
        return False

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify an Enonic XP log event."""
        first_line = text.split("\n", 1)[0]

        # Level
        level = None
        m = _LOGBACK_LEVEL_RE.search(first_line)
        if m:
            level = m.group(1)
        else:
            # Try NCSA status derivation
            sm = _NCSA_STATUS_RE.search(first_line)
            if sm:
                status = int(sm.group("status"))
                if status >= 500:
                    level = "ERROR"
                elif status >= 400:
                    level = "WARN"
                else:
                    level = "INFO"
            elif _LOGBACK_LEVEL_RE.search(text):
                level = _LOGBACK_LEVEL_RE.search(text).group(1)

        # Thread name
        thread_id = None
        tm = _THREAD_RE.search(first_line)
        if tm:
            # Skip NCSA timestamp brackets
            candidate = tm.group(1).strip()
            # NCSA bracket timestamps contain '/' and ':' like 11/Mar/2025:10:15:33
            if '/' not in candidate or ':' not in candidate:
                thread_id = candidate

        # Logger name
        logger = None
        lm = _LOGGER_RE.search(first_line)
        if lm:
            logger = lm.group(1)

        exc = extract_exception(text)
        root_cause = extract_root_cause(text)
        tags = self.bucket_tags(text)

        result: dict[str, Any] = {
            "level": level,
            "thread_id": thread_id,
            "code": None,
            "exception": exc,
            "root_cause": root_cause,
            "tags": sorted(tags),
        }
        if logger:
            result["logger"] = logger
        return result

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags from event text."""
        tags: set[str] = set()

        if OOM_RE.search(text):
            tags.add("OOM/GC")
        if _SSL_RE.search(text):
            tags.add("SSL/TLS")
        if _CLUSTER_RE.search(text):
            tags.add("Enonic/Cluster")
        if _REPO_RE.search(text):
            tags.add("Enonic/Repo")
        if _INDEX_RE.search(text):
            tags.add("Enonic/Index")
        if _CONTENT_RE.search(text):
            tags.add("Enonic/Content")
        if _JETTY_RE.search(text):
            tags.add("Enonic/HTTP")
        # NCSA request lines with error statuses
        if _NCSA_LINE_RE.match(text.split("\n", 1)[0]):
            sm = _NCSA_STATUS_RE.search(text)
            if sm and int(sm.group("status")) >= 400:
                tags.add("Enonic/HTTP")

        return tags
