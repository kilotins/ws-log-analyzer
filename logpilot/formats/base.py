"""Base protocol and shared helpers for log format plugins."""
from __future__ import annotations

import re
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class LogFormat(Protocol):
    """Interface that every log format plugin must implement."""

    name: str
    description: str

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 how likely these lines match this format.

        Called with the first 50 non-empty lines of a file.
        """
        ...

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp string from a log line."""
        ...

    def extract_level(self, line: str) -> str | None:
        """Extract severity level (ERROR, WARN, INFO, DEBUG, etc.)."""
        ...

    def is_continuation(self, line: str) -> bool:
        """Return True if this line is a continuation of the previous event.

        Stacktraces, multiline messages, 'Caused by:' lines, etc.
        """
        ...

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a block of log text and return metadata dict.

        Must return at minimum: level, thread_id, code, exception, root_cause, tags.
        """
        ...

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags (OOM, HungThreads, etc.) from event text."""
        ...


# --- Shared regex patterns usable by any format ---

# Java exceptions / errors
EXC_HEAD_RE = re.compile(r'\b([a-zA-Z_$]+(?:\.[a-zA-Z_$]+)+(?:Exception|Error))\b')
STACK_LINE_RE = re.compile(r'^\s+at\s+[\w.$]+\(.*\)$')
CAUSED_BY_RE = re.compile(r'^\s*Caused by:\s+(?P<cause>.+)$')

# Common severity keywords
LEVEL_RE = re.compile(r'\b(SEVERE|ERROR|WARN|WARNING|INFO|DEBUG|FINE|FINER|FINEST|TRACE|FATAL|CRITICAL)\b', re.IGNORECASE)

# OOM / resource patterns (shared across formats)
OOM_RE = re.compile(r'OutOfMemoryError|Java heap space|GC overhead limit exceeded', re.IGNORECASE)


def extract_root_cause(text: str) -> str | None:
    """Extract deepest 'Caused by:' exception from a block of text."""
    root_cause = None
    for line in text.splitlines():
        cb = CAUSED_BY_RE.match(line)
        if cb:
            cause_text = cb.group("cause")
            ce = EXC_HEAD_RE.search(cause_text)
            if ce:
                root_cause = ce.group(1)
    return root_cause


def extract_exception(text: str) -> str | None:
    """Extract first Java-style exception class name from text."""
    m = EXC_HEAD_RE.search(text)
    return m.group(1) if m else None


def is_stack_or_caused_by(line: str) -> bool:
    """Return True if line is a Java stacktrace line or 'Caused by:'."""
    return bool(STACK_LINE_RE.match(line) or CAUSED_BY_RE.match(line))
