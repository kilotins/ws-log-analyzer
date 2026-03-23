"""PostgreSQL log format plugin."""
from __future__ import annotations

import re
from typing import Any

from .base import OOM_RE, is_stack_or_caused_by

# --- PostgreSQL log format ---
# 2025-03-11 10:15:33.123 UTC [1234] LOG:  message
# 2025-03-11 10:15:33.123 UTC [1234] appuser@mydb ERROR:  message
PG_LINE_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+'
    r'(?P<tz>\S+)\s+'
    r'\[(?P<pid>\d+)\]\s+'
    r'(?:(?P<user>\S+)@(?P<db>\S+)\s+)?'
    r'(?P<level>LOG|ERROR|FATAL|PANIC|WARNING|INFO|NOTICE|DEBUG[1-5]|DETAIL|HINT|STATEMENT|CONTEXT):\s+'
    r'(?P<message>.*)',
)

# Continuation lines: DETAIL, HINT, STATEMENT, CONTEXT
PG_CONTINUATION_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\S+\s+\[\d+\]\s+'
    r'(?:DETAIL|HINT|STATEMENT|CONTEXT):\s+',
)

# Timestamp-only check
PG_TS_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\S+\s+\[\d+\]\s+'
)

# --- Level mapping ---
PG_LEVELS = {
    'PANIC': 'FATAL',
    'FATAL': 'ERROR',
    'ERROR': 'ERROR',
    'WARNING': 'WARNING',
    'LOG': 'INFO',
    'INFO': 'INFO',
    'NOTICE': 'INFO',
    'DEBUG1': 'DEBUG', 'DEBUG2': 'DEBUG', 'DEBUG3': 'DEBUG',
    'DEBUG4': 'DEBUG', 'DEBUG5': 'DEBUG',
}

# Continuation levels (not mapped — they belong to the previous event)
PG_CONTINUATION_LEVELS = {'DETAIL', 'HINT', 'STATEMENT', 'CONTEXT'}

# --- Signal tag patterns ---

PG_CONN_RE = re.compile(
    r'too many connections|sorry, too many clients|max_connections'
    r'|remaining connection slots|connection limit',
    re.IGNORECASE,
)

PG_LOCK_RE = re.compile(
    r'deadlock detected|lock timeout|waiting for.*Lock'
    r'|still waiting for.*lock after',
    re.IGNORECASE,
)

PG_REPLICATION_RE = re.compile(
    r'replication.*fail|WAL.*fail|streaming replication'
    r'|recovery mode|redo.*start|invalid record length',
    re.IGNORECASE,
)

PG_DISK_RE = re.compile(
    r'no space left|disk full|temp_file_limit|temporary file size'
    r'|could not write|checkpoint.*fail',
    re.IGNORECASE,
)

PG_AUTH_RE = re.compile(
    r'password authentication failed|no pg_hba.conf entry'
    r'|authentication failed|SCRAM authentication',
    re.IGNORECASE,
)

PG_VACUUM_RE = re.compile(
    r'autovacuum.*cancel|wraparound|oldest.*xmin|dead tuples'
    r'|VACUUM.*running for',
    re.IGNORECASE,
)

PG_QUERY_RE = re.compile(
    r'canceling statement due to|statement timeout|duration:\s+\d{4,}'
    r'|slow query|idle in transaction',
    re.IGNORECASE,
)

PG_SHUTDOWN_RE = re.compile(
    r'shutting down|shutdown request|database system is shut down'
    r'|recovery in progress|not properly shut down',
    re.IGNORECASE,
)


class PostgreSQLFormat:
    """PostgreSQL log format."""

    name = "postgresql"
    description = "PostgreSQL database server"

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 based on PostgreSQL log patterns."""
        if not lines:
            return 0.0
        score = 0
        for line in lines:
            m = PG_LINE_RE.match(line)
            if m:
                level = m.group("level")
                if level in PG_CONTINUATION_LEVELS:
                    score += 4  # Very strong PostgreSQL signal
                elif level in ('LOG', 'PANIC', 'NOTICE'):
                    score += 4  # Unique PG levels
                elif level in ('FATAL', 'ERROR', 'WARNING', 'INFO'):
                    score += 2  # Could be PG or other
                else:
                    score += 2  # DEBUG1-5
        return min(score / (len(lines) * 3), 1.0)

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp from PostgreSQL log line."""
        m = PG_LINE_RE.match(line)
        if m:
            return m.group("ts")
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity level."""
        m = PG_LINE_RE.match(line)
        if m:
            level = m.group("level")
            if level in PG_CONTINUATION_LEVELS:
                return None  # Continuations don't have their own level
            return PG_LEVELS.get(level)
        return None

    def is_continuation(self, line: str) -> bool:
        """Check if line is a continuation (DETAIL/HINT/STATEMENT/CONTEXT or stacktrace)."""
        if not line or not line.strip():
            return False
        # DETAIL/HINT/STATEMENT/CONTEXT are continuations of the previous event
        if PG_CONTINUATION_RE.match(line):
            return True
        # Tab-indented lines (e.g. deadlock detail)
        if line.startswith('\t'):
            return True
        # Stacktrace
        if is_stack_or_caused_by(line):
            return True
        # No PG timestamp prefix → continuation
        if not PG_TS_RE.match(line):
            return True
        return False

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a PostgreSQL event block and return metadata."""
        first_line = text.split("\n", 1)[0]
        m = PG_LINE_RE.match(first_line)

        level = None
        code = None
        pid = None

        if m:
            raw_level = m.group("level")
            if raw_level not in PG_CONTINUATION_LEVELS:
                level = PG_LEVELS.get(raw_level)
            pid = m.group("pid")
            # Extract SQLSTATE if present (e.g. "ERROR:  duplicate key value violates unique constraint")
            sqlstate_m = re.search(r'SQLSTATE\[(\w+)\]|(?:error code|sqlstate)[:=]\s*(\w{5})', text, re.IGNORECASE)
            if sqlstate_m:
                code = sqlstate_m.group(1) or sqlstate_m.group(2)

        tags = self.bucket_tags(text)

        # Extract exception-like patterns from PG errors
        exception = None
        root_cause = None
        pg_error_m = re.search(r'(?:ERROR|FATAL|PANIC):\s+(.+?)(?:\n|$)', text)
        if pg_error_m:
            exception = pg_error_m.group(1).strip()[:120]

        return {
            "level": level,
            "thread_id": pid,
            "code": code,
            "exception": exception,
            "root_cause": root_cause,
            "tags": sorted(tags),
        }

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags for PostgreSQL patterns."""
        tags: set[str] = set()

        if PG_CONN_RE.search(text):
            tags.add("PG/Conn")

        if PG_LOCK_RE.search(text):
            tags.add("PG/Lock")

        if PG_REPLICATION_RE.search(text):
            tags.add("PG/Replication")

        if PG_DISK_RE.search(text):
            tags.add("PG/Disk")

        if PG_AUTH_RE.search(text):
            tags.add("PG/Auth")

        if PG_VACUUM_RE.search(text):
            tags.add("PG/Vacuum")

        if PG_QUERY_RE.search(text):
            tags.add("PG/SlowQuery")

        if PG_SHUTDOWN_RE.search(text):
            tags.add("PG/Shutdown")

        if OOM_RE.search(text):
            tags.add("OOM/GC")

        return tags
