"""Python logging format plugin (stdlib, Django, Flask, FastAPI, gunicorn, uvicorn)."""
from __future__ import annotations

import re
from typing import Any

from .base import (
    EXC_HEAD_RE, LEVEL_RE, OOM_RE,
    extract_exception, extract_root_cause, is_stack_or_caused_by,
)

# --- Python stdlib logging ---
# 2025-03-11 10:15:33,123 - myapp.module - ERROR - Something failed
_STDLIB_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d{3})\s+-\s+\S+\s+-\s+'
    r'(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+-\s+'
)

# --- Django development server ---
# [11/Mar/2025 10:15:33] "GET /path HTTP/1.1" 200 1234
_DJANGO_RE = re.compile(
    r'^\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}\s+\d{2}:\d{2}:\d{2})\]\s+"'
    r'(?P<method>[A-Z]+)\s+\S+\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\s+'
)

# --- Flask / uvicorn access log ---
# INFO:     127.0.0.1:54321 - "GET / HTTP/1.1" 200
# Also: INFO:module.name:message
_UVICORN_ACCESS_RE = re.compile(
    r'^(?P<level>[A-Z]+):\s+.*"(?P<method>[A-Z]+)\s+\S+\s+HTTP/[\d.]+"\s+(?P<status>\d{3})'
)
_UVICORN_RE = re.compile(
    r'^(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL|TRACE):\s+'
)

# --- gunicorn ---
# [2025-03-11 10:15:33 +0000] [1234] [INFO] message
_GUNICORN_RE = re.compile(
    r'^\[(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+[^\]]*\]\s+'
    r'\[\d+\]\s+\[(?P<level>[A-Z]+)\]\s+'
)

# --- Timestamp extraction patterns (ordered by specificity) ---
_TS_STDLIB_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d{3})'
)
_TS_DJANGO_RE = re.compile(
    r'\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}\s+\d{2}:\d{2}:\d{2})\]'
)
_TS_GUNICORN_RE = re.compile(
    r'^\[(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+[^\]]*\]'
)

# --- Python traceback patterns ---
_TRACEBACK_HEAD_RE = re.compile(r'^\s*Traceback \(most recent call last\):\s*$')
_TRACEBACK_FILE_RE = re.compile(r'^\s+File\s+"[^"]+",\s+line\s+\d+')
_TRACEBACK_CARET_RE = re.compile(r'^\s+[\^~]+\s*$')
# Python exception line: "ValueError: something" or "module.exc.SomeError: msg"
_PY_EXC_RE = re.compile(
    r'^(?P<exc>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:Error|Exception|Warning|Exit))'
    r'(?::\s*(?P<msg>.*))?$'
)
# "During handling of the above exception, another exception occurred:"
_CHAINED_EXC_RE = re.compile(
    r'^\s*(?:During handling of the above exception|'
    r'The above exception was the direct cause of the following exception).*:$'
)

# --- Level patterns for lines without explicit level ---
_LEVEL_KEYWORDS = re.compile(
    r'\b(CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG)\b', re.IGNORECASE,
)

# --- Signal tag patterns ---
_IMPORT_RE = re.compile(r'ImportError|ModuleNotFoundError', re.IGNORECASE)
_DB_RE = re.compile(
    r'DatabaseError|OperationalError|IntegrityError|ProgrammingError'
    r'|DataError|django\.db|psycopg2|mysql|sqlite3\..*Error'
    r'|sqlalchemy\.exc',
    re.IGNORECASE,
)
_TEMPLATE_RE = re.compile(
    r'TemplateSyntaxError|TemplateDoesNotExist|jinja2'
    r'|UndefinedError|TemplateNotFound|TemplateAssertionError',
    re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r'CSRF|Forbidden|PermissionDenied|AuthenticationFailed'
    r'|NotAuthenticated|InvalidToken|csrf_token',
    re.IGNORECASE,
)
_HTTP_STATUS_RE = re.compile(r'\b[45]\d{2}\b')
_CELERY_RE = re.compile(
    r'\bcelery\b|\btask\b.*\b(?:failed|error|retry|rejected)\b'
    r'|\bworker\b.*\b(?:lost|shutdown|error)\b'
    r'|WorkerLostError|SoftTimeLimitExceeded|TimeLimitExceeded',
    re.IGNORECASE,
)
_OOM_PY_RE = re.compile(r'MemoryError|Killed|killed\s+process', re.IGNORECASE)


_TS_GENERIC_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d{3}\s+'
    r'(?:DEBUG|INFO|WARNING|ERROR|CRITICAL)\b'
)


def _has_timestamp(line: str) -> bool:
    """Return True if line starts with a recognized Python log timestamp."""
    return bool(
        _STDLIB_RE.match(line)
        or _TS_GENERIC_RE.match(line)
        or _DJANGO_RE.match(line)
        or _GUNICORN_RE.match(line)
        or _UVICORN_RE.match(line)
    )


def _level_from_status(status: str) -> str:
    """Derive severity level from HTTP status code."""
    code = int(status)
    if code >= 500:
        return "ERROR"
    if code >= 400:
        return "WARNING"
    return "INFO"


def _extract_py_exception(text: str) -> str | None:
    """Extract Python exception class from text.

    Falls back to the Java-style EXC_HEAD_RE for cross-language support.
    """
    for line in text.splitlines():
        stripped = line.strip()
        m = _PY_EXC_RE.match(stripped)
        if m:
            return m.group("exc")
    return extract_exception(text)


def _extract_py_root_cause(text: str) -> str | None:
    """Extract the deepest chained exception from Python traceback.

    Looks for exception lines that follow 'During handling...' sections.
    Also falls back to Java-style 'Caused by:'.
    """
    # Collect all exception lines; the last one is the deepest root cause
    exceptions: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        m = _PY_EXC_RE.match(stripped)
        if m:
            exceptions.append(m.group("exc"))

    # If there are chained exceptions (multiple), root cause is the last
    if len(exceptions) >= 2:
        return exceptions[-1]

    # Fall back to Java-style Caused by
    return extract_root_cause(text)


class PythonFormat:
    """Python logging format (stdlib, Django, Flask, FastAPI, gunicorn, uvicorn)."""

    name = "python"
    description = "Python logging (stdlib, Django, Flask, FastAPI)"

    # Python ecosystem identifiers that distinguish from Java/Logback
    _PYTHON_IDENTIFIERS_RE = re.compile(
        r'\b(?:django|celery|flask|gunicorn|uvicorn|fastapi'
        r'|werkzeug|requests\.|urllib3|pip|setuptools'
        r'|Traceback \(most recent call last\)'
        r'|\.py:\d+|\.py", line \d+)\b'
    )

    def detect(self, lines: list[str]) -> float:
        """Score based on Python logging patterns in sample lines."""
        if not lines:
            return 0.0
        score = 0
        python_markers = 0
        for line in lines:
            # stdlib format: timestamp - name - LEVEL - message
            if _STDLIB_RE.match(line):
                score += 4
            # Django dev server: [date] "METHOD path HTTP/x.x" status
            elif _DJANGO_RE.match(line):
                score += 4
            # gunicorn: [timestamp +tz] [pid] [LEVEL] message
            elif _GUNICORN_RE.match(line):
                score += 4
            # uvicorn access log: LEVEL: ip - "METHOD path" status
            elif _UVICORN_ACCESS_RE.match(line):
                score += 3
            # uvicorn/general: LEVEL:module:message or LEVEL: message
            elif _UVICORN_RE.match(line):
                score += 2
            # Python traceback lines
            elif _TRACEBACK_HEAD_RE.match(line):
                score += 2
            elif _TRACEBACK_FILE_RE.match(line):
                score += 1
            elif _PY_EXC_RE.match(line.strip()):
                score += 1

            # Python ecosystem bonus (helps beat log4j for Python logs)
            if self._PYTHON_IDENTIFIERS_RE.search(line):
                python_markers += 1
                score += 2

        # Normalize: max ~4 per line, want 0-1
        return min(score / (len(lines) * 3), 1.0)

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp from a Python log line."""
        # stdlib: 2025-03-11 10:15:33,123
        m = _STDLIB_RE.match(line)
        if m:
            return m.group("ts")
        # Django: [11/Mar/2025 10:15:33]
        m = _TS_DJANGO_RE.search(line)
        if m:
            return m.group("ts")
        # gunicorn: [2025-03-11 10:15:33 +0000]
        m = _TS_GUNICORN_RE.match(line)
        if m:
            return m.group("ts")
        # Generic fallback: any YYYY-MM-DD HH:MM:SS,mmm pattern
        m = _TS_STDLIB_RE.search(line)
        if m:
            return m.group("ts")
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity level from a Python log line."""
        # stdlib: ... - LEVEL - ...
        m = _STDLIB_RE.match(line)
        if m:
            return m.group("level")
        # gunicorn: [timestamp] [pid] [LEVEL]
        m = _GUNICORN_RE.match(line)
        if m:
            return m.group("level")
        # uvicorn access log with HTTP status
        m = _UVICORN_ACCESS_RE.match(line)
        if m:
            return _level_from_status(m.group("status"))
        # uvicorn/general: LEVEL: message
        m = _UVICORN_RE.match(line)
        if m:
            return m.group("level")
        # Django dev server: derive from HTTP status
        m = _DJANGO_RE.match(line)
        if m:
            return _level_from_status(m.group("status"))
        # Generic fallback
        m = _LEVEL_KEYWORDS.search(line)
        if m:
            return m.group(1).upper()
        return None

    def is_continuation(self, line: str) -> bool:
        """Return True if line is a continuation of the previous event."""
        # Python traceback lines
        if _TRACEBACK_HEAD_RE.match(line):
            return True
        if _TRACEBACK_FILE_RE.match(line):
            return True
        if _TRACEBACK_CARET_RE.match(line):
            return True
        if _CHAINED_EXC_RE.match(line):
            return True
        # Java-style stack traces / Caused by (for cross-language tracebacks)
        if is_stack_or_caused_by(line):
            return True
        # Indented lines (continuation of a multiline message)
        if line.startswith("    ") or line.startswith("\t"):
            return True
        # Exception lines (e.g., "ValueError: something")
        if _PY_EXC_RE.match(line.strip()) and not _has_timestamp(line):
            return True
        # Lines without a timestamp are continuations
        if not _has_timestamp(line):
            return True
        return False

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a Python log event."""
        first_line = text.split("\n", 1)[0]

        # Level from first line
        level = self.extract_level(first_line)
        if level is None:
            # Try the full text
            m = _LEVEL_KEYWORDS.search(text)
            if m:
                level = m.group(1).upper()

        # Normalize WARNING/WARN
        if level == "WARN":
            level = "WARNING"

        # Exception
        exc = _extract_py_exception(text)

        # Root cause (deepest chained exception)
        root_cause = _extract_py_root_cause(text)

        # Tags
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

        if _IMPORT_RE.search(text):
            tags.add("Import")
        if _DB_RE.search(text):
            tags.add("DB")
        if _TEMPLATE_RE.search(text):
            tags.add("Template")
        if _AUTH_RE.search(text):
            tags.add("Auth")
        if _HTTP_STATUS_RE.search(text):
            tags.add("HTTP")
        if _CELERY_RE.search(text):
            tags.add("Celery")
        if _OOM_PY_RE.search(text):
            tags.add("OOM")
        if OOM_RE.search(text):
            tags.add("OOM")

        return tags
