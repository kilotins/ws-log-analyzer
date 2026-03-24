"""Extract code locations (file, line, method) from stacktraces in log events.

Supports Java and Python stacktrace formats. Returns deduplicated CodeLocation
objects for use by the code search module.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .event import LogEvent

# ── Java stack frame ──────────────────────────────────────────────────
# at com.ibm.ws.checkout.dao.OrderDAO.saveOrder(OrderDAO.java:67)
_JAVA_FRAME_RE = re.compile(
    r'^\s+at\s+'
    r'(?P<fqcn>[\w.$]+)\.'      # fully qualified class + method
    r'(?P<method>[\w$<>]+)'     # method name (including <init>)
    r'\((?P<file>[^:)]+?)'      # source file
    r'(?::(?P<line>\d+))?\)',   # optional line number
)

# Caused by: com.ibm.ws.checkout.CheckoutException: ...
_JAVA_CAUSED_RE = re.compile(
    r'^\s*Caused by:\s+(?P<exception>[\w.$]+)',
)

# ── Python traceback frame ────────────────────────────────────────────
# File "/app/orders/tasks.py", line 45, in process_order
_PYTHON_FRAME_RE = re.compile(
    r'^\s+File\s+"(?P<path>[^"]+)",\s+line\s+(?P<line>\d+)'
    r'(?:,\s+in\s+(?P<func>[\w<>]+))?',
)

# ── Framework packages to skip (not user code) ───────────────────────
_JAVA_SKIP_PREFIXES = (
    "sun.", "java.", "javax.", "jdk.",
    "org.apache.commons.", "org.apache.catalina.", "org.apache.coyote.",
    "org.apache.tomcat.", "org.apache.jasper.",
    "com.ibm.ws.", "com.ibm.io.", "com.ibm.ejs.",
    "org.eclipse.jetty.", "io.netty.",
    "org.springframework.cglib.", "org.springframework.aop.",
    "com.sun.", "org.jboss.",
)

_PYTHON_SKIP_PATTERNS = (
    "/site-packages/", "/lib/python", "/usr/lib/",
    "/dist-packages/", "importlib/", "<frozen",
)


@dataclass
class CodeLocation:
    """A single code location extracted from a stacktrace."""
    file_hint: str                  # "OrderDAO.java" or "tasks.py"
    line: int | None = None         # line number, or None
    class_name: str | None = None   # "com.ibm.ws.checkout.dao.OrderDAO" (Java)
    method: str | None = None       # "saveOrder" or "process_order"
    language: str = "java"          # "java" or "python"
    source_line: str = ""           # Original stacktrace line for context

    def key(self) -> tuple:
        """Dedup key."""
        return (self.file_hint, self.line, self.method)

    def search_terms(self) -> list[str]:
        """Return search terms for grep-based fallback."""
        terms: list[str] = []
        if self.method and self.method not in ("<init>", "<module>", "__init__"):
            terms.append(self.method)
        if self.class_name:
            # Short class name (last part)
            short = self.class_name.rsplit(".", 1)[-1]
            if short and len(short) > 2:
                terms.append(short)
        return terms


def _is_framework_java(fqcn: str) -> bool:
    return any(fqcn.startswith(p) for p in _JAVA_SKIP_PREFIXES)


def _is_framework_python(path: str) -> bool:
    return any(p in path for p in _PYTHON_SKIP_PATTERNS)


def extract_code_locations(events: list[LogEvent], max_locations: int = 100) -> list[CodeLocation]:
    """Extract code locations from stacktraces across all events.

    Returns deduplicated locations in chronological order, limited to max_locations.
    Framework/library frames are filtered out.
    """
    seen: set[tuple] = set()
    locations: list[CodeLocation] = []

    for event in events:
        if not event.text:
            continue
        for line in event.text.split("\n"):
            loc = _parse_line(line)
            if loc and loc.key() not in seen:
                seen.add(loc.key())
                locations.append(loc)
                if len(locations) >= max_locations:
                    return locations

    return locations


def _parse_line(line: str) -> CodeLocation | None:
    """Try to parse a single line as a stack frame."""
    # Java frame
    m = _JAVA_FRAME_RE.match(line)
    if m:
        fqcn = m.group("fqcn")
        if _is_framework_java(fqcn):
            return None
        return CodeLocation(
            file_hint=m.group("file"),
            line=int(m.group("line")) if m.group("line") else None,
            class_name=fqcn,
            method=m.group("method"),
            language="java",
            source_line=line.strip(),
        )

    # Python frame
    m = _PYTHON_FRAME_RE.match(line)
    if m:
        path = m.group("path")
        if _is_framework_python(path):
            return None
        # Extract just the filename from the path
        from pathlib import PurePosixPath
        file_hint = PurePosixPath(path).name
        return CodeLocation(
            file_hint=file_hint,
            line=int(m.group("line")),
            class_name=None,
            method=m.group("func"),
            language="python",
            source_line=line.strip(),
        )

    return None
