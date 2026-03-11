"""Log4j / Logback / Spring Boot log format plugin."""
from __future__ import annotations

import re
from typing import Any

from .base import (
    LEVEL_RE, OOM_RE,
    extract_exception, extract_root_cause, is_stack_or_caused_by,
)

# --- Log4j / Logback timestamp patterns ---

# Full ISO: 2025-03-11 10:15:33.123 or 2025-03-11 10:15:33,123 or 2025-03-11T10:15:33.123
_TS_FULL_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]\d{3})'
)

# Time-only (Logback short): 10:15:33.123
_TS_TIME_ONLY_RE = re.compile(
    r'^(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3})\s'
)

# --- Level extraction ---
# Standard Log4j/Logback levels as standalone words
_LOG4J_LEVEL_RE = re.compile(
    r'\b(FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\b'
)

# --- Logger name: dotted package pattern like com.example.MyClass or c.e.MyClass ---
_LOGGER_RE = re.compile(
    r'(?:^|\s)([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*){2,})(?:\s|$|:|\s*[-:])'
)

# --- Thread name in square brackets ---
_THREAD_RE = re.compile(r'\[([^\[\]]+)\]')

# --- Spring Boot marker: PID --- [thread] ---
_SPRING_BOOT_RE = re.compile(
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]\d{3}\s+'
    r'(?:FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\s+\d+\s+---\s+\['
)

# --- Log4j standard line pattern (timestamp + level) ---
_LOG4J_LINE_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]\d{3}\s+'
    r'(?:FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\b'
)

# --- Logback short pattern (time-only + level) ---
_LOGBACK_SHORT_RE = re.compile(
    r'^\d{2}:\d{2}:\d{2}\.\d{3}\s+(?:FATAL|ERROR|WARN|INFO|DEBUG|TRACE)\b'
)

# --- Signal tag patterns ---
_SSL_RE = re.compile(
    r'SSLHandshakeException|handshake_failure|PKIX path building failed'
    r'|unable to find valid certification path|certificate.*(expired|invalid|unknown)',
    re.IGNORECASE,
)
_DB_POOL_RE = re.compile(
    r'HikariPool|connection pool|pool.*exhaust|DataSource'
    r'|connection not available|JDBC.*connection|CannotCreateTransactionException'
    r'|JDBCConnectionException|Timeout waiting for idle object',
    re.IGNORECASE,
)
_SPRING_RE = re.compile(
    r'APPLICATION FAILED TO START|BeanCreationException'
    r'|UnsatisfiedDependencyException|CircularDependency'
    r'|NoSuchBeanDefinitionException|AutoConfiguration'
    r'|PortInUseException|DataSourceBeanCreationException',
    re.IGNORECASE,
)
_KAFKA_RE = re.compile(
    r'Rebalancing|CommitFailedException|kafka\.controller'
    r'|RecordTooLargeException|NotLeaderOrFollowerException'
    r'|OutOfOrderSequenceException',
    re.IGNORECASE,
)
_HTTP_RE = re.compile(r'\b[45]\d{2}\b')


def _has_timestamp(line: str) -> bool:
    """Return True if line starts with a recognized timestamp."""
    return bool(_LOG4J_LINE_RE.match(line) or _LOGBACK_SHORT_RE.match(line))


class Log4jFormat:
    """Log4j / Logback (Spring Boot, Kafka, Elasticsearch) log format."""

    name = "log4j"
    description = "Log4j / Logback (Spring Boot, Kafka, Elasticsearch)"

    def detect(self, lines: list[str]) -> float:
        """Score based on Log4j/Logback patterns in sample lines."""
        if not lines:
            return 0.0
        score = 0
        for line in lines:
            # Spring Boot format (highest confidence)
            if _SPRING_BOOT_RE.search(line):
                score += 4
                continue
            # Standard Log4j/Logback line with full timestamp + level
            if _LOG4J_LINE_RE.match(line):
                score += 3
                continue
            # Logback short format (time-only)
            if _LOGBACK_SHORT_RE.match(line):
                score += 3
                continue
            # Logger name pattern (dotted package) as secondary signal
            if _LOGGER_RE.search(line):
                score += 1
        # Normalize: max ~4 per line, want 0-1
        return min(score / (len(lines) * 3), 1.0)

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp from a log line."""
        m = _TS_FULL_RE.search(line)
        if m:
            return m.group("ts")
        m = _TS_TIME_ONLY_RE.match(line)
        if m:
            return m.group("ts")
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity level from a log line."""
        m = _LOG4J_LEVEL_RE.search(line)
        return m.group(1) if m else None

    def is_continuation(self, line: str) -> bool:
        """Return True if line is a continuation of the previous event."""
        # Stacktrace or Caused by lines
        if is_stack_or_caused_by(line):
            return True
        # Lines without a leading timestamp are continuations
        if not _has_timestamp(line):
            return True
        return False

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a Log4j/Logback log event."""
        first_line = text.split("\n", 1)[0]

        # Level
        level = None
        m = _LOG4J_LEVEL_RE.search(first_line)
        if m:
            level = m.group(1)
        elif _LOG4J_LEVEL_RE.search(text):
            level = _LOG4J_LEVEL_RE.search(text).group(1)

        # Thread name — find brackets, skip timestamp-related brackets
        thread_id = None
        tm = _THREAD_RE.search(first_line)
        if tm:
            thread_id = tm.group(1).strip()

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
        if _DB_POOL_RE.search(text):
            tags.add("DB/Pool")
        if _SPRING_RE.search(text):
            tags.add("Spring")
        if _KAFKA_RE.search(text):
            tags.add("Kafka")
        if _HTTP_RE.search(text):
            tags.add("HTTP")
        return tags
