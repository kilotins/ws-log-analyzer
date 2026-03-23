"""Apache Tomcat / Catalina (java.util.logging) log format plugin."""
from __future__ import annotations

import re
from typing import Any

from .base import (
    OOM_RE,
    extract_exception, extract_root_cause, is_stack_or_caused_by,
)

# --- Tomcat JUL timestamp format ---
# 11-Mar-2025 10:15:33.123 SEVERE [http-nio-8080-exec-1] org.apache.catalina.connector message
TOMCAT_RE = re.compile(
    r'^(?P<ts>\d{1,2}-[A-Z][a-z]{2}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+'
    r'(?P<level>SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST)\s+'
    r'\[(?P<thread>[^\]]+)\]\s+'
    r'(?P<logger>\S+)\s+'
    r'(?P<message>.*)',
)

# Timestamp-only check for continuation detection
TOMCAT_TS_RE = re.compile(r'^\d{1,2}-[A-Z][a-z]{2}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+')

# --- Level mapping (JUL → LogPilot) ---
TOMCAT_LEVELS = {
    'SEVERE': 'ERROR',
    'WARNING': 'WARNING',
    'INFO': 'INFO',
    'CONFIG': 'INFO',
    'FINE': 'DEBUG',
    'FINER': 'DEBUG',
    'FINEST': 'DEBUG',
}

# --- Signal tag patterns ---

TOMCAT_DEPLOY_RE = re.compile(
    r'Deploying web application|deployment.*fail|LifecycleException'
    r'|Context \[.*\] startup failed|Unable to deploy',
    re.IGNORECASE,
)

TOMCAT_CONNECTOR_RE = re.compile(
    r'Connector.*start|Protocol handler.*failed|BindException'
    r'|Address already in use|Acceptor thread|max threads',
    re.IGNORECASE,
)

TOMCAT_SESSION_RE = re.compile(
    r'Session.*expir|session.*persist|saving Session|IllegalStateException.*session'
    r'|setAttribute.*serializ|NotSerializableException',
    re.IGNORECASE,
)

TOMCAT_JDBC_RE = re.compile(
    r'DataSource|connection pool|pool.*exhaust|getConnection.*timeout'
    r'|abandoned connection|DBCP|Tomcat JDBC',
    re.IGNORECASE,
)

TOMCAT_SSL_RE = re.compile(
    r'SSLHandshakeException|certificate.*expired|PKIX|keystore'
    r'|TLS.*handshake|CertificateException',
    re.IGNORECASE,
)

TOMCAT_VALVE_RE = re.compile(
    r'valve.*error|AccessLogValve|RemoteAddrValve|stuck thread'
    r'|StuckThreadDetectionValve',
    re.IGNORECASE,
)


class TomcatFormat:
    """Apache Tomcat / Catalina (java.util.logging) log format."""

    name = "tomcat"
    description = "Apache Tomcat / Catalina (JUL)"

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 based on Tomcat JUL patterns."""
        if not lines:
            return 0.0
        score = 0
        for line in lines:
            m = TOMCAT_RE.match(line)
            if m:
                score += 3
                # Bonus for Tomcat-specific loggers
                logger = m.group("logger")
                if "catalina" in logger or "coyote" in logger or "tomcat" in logger:
                    score += 1
        return min(score / (len(lines) * 3), 1.0)

    def extract_ts(self, line: str) -> str | None:
        """Extract DD-MMM-YYYY HH:MM:SS.sss timestamp."""
        m = TOMCAT_RE.match(line)
        if m:
            return m.group("ts")
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity level from JUL level field."""
        m = TOMCAT_RE.match(line)
        if m:
            return TOMCAT_LEVELS.get(m.group("level"))
        return None

    def is_continuation(self, line: str) -> bool:
        """Check if line is a continuation (no JUL timestamp or stacktrace)."""
        if not line or not line.strip():
            return False
        if TOMCAT_TS_RE.match(line):
            return False
        if is_stack_or_caused_by(line):
            return True
        return True

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a Tomcat event block and return metadata."""
        first_line = text.split("\n", 1)[0]
        m = TOMCAT_RE.match(first_line)

        level = None
        thread_id = None
        code = None

        if m:
            level = TOMCAT_LEVELS.get(m.group("level"))
            thread_id = m.group("thread")

        exc = extract_exception(text)
        root_cause = extract_root_cause(text)
        tags = self.bucket_tags(text)

        return {
            "level": level,
            "thread_id": thread_id,
            "code": code,
            "exception": exc,
            "root_cause": root_cause,
            "tags": sorted(tags),
        }

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags for Tomcat patterns."""
        tags: set[str] = set()

        if TOMCAT_DEPLOY_RE.search(text):
            tags.add("Deploy")

        if TOMCAT_CONNECTOR_RE.search(text):
            tags.add("Connector")

        if TOMCAT_SESSION_RE.search(text):
            tags.add("Session")

        if TOMCAT_JDBC_RE.search(text):
            tags.add("DB/Pool")

        if TOMCAT_SSL_RE.search(text):
            tags.add("SSL/TLS")

        if TOMCAT_VALVE_RE.search(text):
            tags.add("Valve")

        if OOM_RE.search(text):
            tags.add("OOM/GC")

        return tags
