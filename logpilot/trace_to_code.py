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

# ── Node.js/V8 stack frame ────────────────────────────────────────────
# at async requestHandler (/app/server.js:42:5)
# at /app/routes/index.js:15:21
_NODE_FRAME_RE = re.compile(
    r'^\s+at\s+'
    r'(?:(?P<func>[\w.<> ]+?)\s+)?'
    r'\(?(?P<path>.*?):(?P<line>\d+):(?P<col>\d+)\)?'
)

# ── Framework packages to skip (not user code) ───────────────────────
_JAVA_SKIP_PREFIXES = (
    # JDK / JVM
    "sun.", "java.", "javax.", "jdk.", "com.sun.",
    # IBM WebSphere / Liberty
    "com.ibm.ws.", "com.ibm.io.", "com.ibm.ejs.", "com.ibm.wsspi.",
    "com.ibm.websphere.", "com.ibm.tx.", "com.ibm.oti.",
    # IBM DataPower
    "com.ibm.datapower.", "com.ibm.dp.",
    # Apache commons / HTTP
    "org.apache.commons.", "org.apache.http.", "org.apache.hc.",
    # Apache Tomcat / Catalina
    "org.apache.catalina.", "org.apache.coyote.",
    "org.apache.tomcat.", "org.apache.jasper.", "org.apache.juli.",
    # Jetty / JBoss / Undertow
    "org.eclipse.jetty.", "org.jboss.", "io.undertow.", "org.wildfly.",
    # Enonic XP framework
    "com.enonic.xp.", "com.enonic.app.booster.", "com.enonic.app.rewrite.",
    # Spring framework
    "org.springframework.",
    # Networking / IO / reactive
    "io.netty.", "reactor.", "rx.", "io.grpc.",
    # Logging frameworks
    "org.slf4j.", "org.apache.logging.", "ch.qos.logback.",
    "org.apache.log4j.", "org.jboss.logging.",
    # ORM / persistence / JDBC
    "org.hibernate.", "org.eclipse.persistence.", "com.zaxxer.hikari.",
    "org.postgresql.", "com.mysql.", "oracle.jdbc.",
    # Kafka / messaging
    "org.apache.kafka.", "org.apache.activemq.", "com.rabbitmq.",
    # Build / bytecode / proxy
    "org.gradle.", "org.codehaus.", "net.bytebuddy.",
    "com.google.common.", "com.google.gson.", "com.google.protobuf.",
    # OSGi
    "org.osgi.", "org.ops4j.",
    # Scripting engines
    "jdk.nashorn.", "org.mozilla.javascript.",
    # Template engines (internals)
    "freemarker.core.", "freemarker.template.",
    "org.thymeleaf.", "org.apache.velocity.",
    # Kubernetes / container runtime (Java clients)
    "io.kubernetes.", "io.fabric8.",
    # Jackson / serialization
    "com.fasterxml.jackson.",
    # Test frameworks (should not appear in prod, but filter anyway)
    "org.junit.", "org.mockito.", "org.testng.",
)

_PYTHON_SKIP_PATTERNS = (
    "/site-packages/", "/lib/python", "/usr/lib/",
    "/dist-packages/", "importlib/", "<frozen",
    # Django framework
    "/django/", "/rest_framework/",
    # Flask / Werkzeug / Gunicorn
    "/flask/", "/werkzeug/", "/gunicorn/",
    # FastAPI / Starlette / Uvicorn
    "/fastapi/", "/starlette/", "/uvicorn/",
    # Celery
    "/celery/", "/kombu/", "/billiard/",
    # SQLAlchemy / DB
    "/sqlalchemy/", "/psycopg2/",
)

_NODE_SKIP_PATTERNS = (
    "node:internal/", "node_modules/", " (node:",
    # Common Node.js frameworks
    "/express/", "/koa/", "/fastify/", "/hapi/",
    "/next/dist/", "/nuxt/",
    "/pino/", "/winston/", "/bunyan/",
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

    # Generic method names that match too many things in grep
    _GENERIC_METHODS = frozenset({
        "<init>", "<module>", "__init__", "run", "call", "invoke", "execute",
        "apply", "accept", "handle", "process", "doFilter", "service",
        "get", "set", "put", "create", "build", "render", "init", "start",
        "stop", "close", "open", "read", "write", "parse", "map", "filter",
        "doGet", "doPost", "doPut", "doDelete", "lambda$",
    })

    def search_terms(self) -> list[str]:
        """Return search terms for grep-based fallback.

        Skips generic method names (create, build, render, etc.) that produce
        too many false positives across any codebase.
        """
        terms: list[str] = []
        if self.method and self.method not in self._GENERIC_METHODS:
            # Also skip lambda methods like lambda$run$0
            if not self.method.startswith("lambda$"):
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


def _is_framework_node(path: str) -> bool:
    return any(p in path for p in _NODE_SKIP_PATTERNS)


def extract_code_locations(events: list[LogEvent], max_locations: int = 100) -> list[CodeLocation]:
    """Extract code locations from stacktraces across all events.

    Returns deduplicated locations prioritized by relevance:
    1. Frames from application code (most frequent non-framework package)
    2. Frames from less common packages
    3. Limited to max_locations

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

    # Prioritize application code: rank by package frequency
    # The most common non-framework package is likely the app's own code
    if locations:
        locations = _prioritize_app_code(locations)

    return locations[:max_locations]


def _prioritize_app_code(locations: list[CodeLocation]) -> list[CodeLocation]:
    """Sort locations so application code comes first.

    Detects the app's package by finding the most frequent top-level package
    among extracted frames. Frames from that package are ranked higher.
    """
    from collections import Counter

    # Count top-level packages (e.g., "no.ukom" from "no.ukom.pdf.PdfExporter")
    pkg_counter: Counter[str] = Counter()
    for loc in locations:
        if loc.class_name and loc.language == "java":
            parts = loc.class_name.split(".")
            if len(parts) >= 2:
                # Use first 2 segments as package identifier
                pkg = ".".join(parts[:2])
                pkg_counter[pkg] += 1
        elif loc.language in ("python", "javascript"):
            # For Python/Node, use file_hint directory
            pkg_counter[loc.file_hint] += 1

    if not pkg_counter:
        return locations

    # The most frequent package is likely the app's code
    app_packages = {pkg for pkg, _ in pkg_counter.most_common(3)}

    def _sort_key(loc: CodeLocation) -> tuple:
        # Priority: 0 = app code with line number, 1 = app code, 2 = other with line, 3 = other
        is_app = False
        if loc.class_name and loc.language == "java":
            parts = loc.class_name.split(".")
            if len(parts) >= 2:
                pkg = ".".join(parts[:2])
                is_app = pkg in app_packages
        has_line = loc.line is not None
        has_specific_method = loc.method and loc.method not in CodeLocation._GENERIC_METHODS

        if is_app and has_line:
            return (0, not has_specific_method)
        if is_app:
            return (1, not has_specific_method)
        if has_line:
            return (2, not has_specific_method)
        return (3, not has_specific_method)

    return sorted(locations, key=_sort_key)


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

    # Node.js/V8 frame
    m = _NODE_FRAME_RE.match(line)
    if m:
        path = m.group("path")
        if _is_framework_node(path):
            return None
        from pathlib import PurePosixPath
        file_hint = PurePosixPath(path).name
        return CodeLocation(
            file_hint=file_hint,
            line=int(m.group("line")),
            class_name=None,
            method=m.group("func"),
            language="javascript",
            source_line=line.strip(),
        )

    return None
