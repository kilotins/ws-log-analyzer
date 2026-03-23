"""IBM DataPower Gateway log format plugin."""
from __future__ import annotations

import re
from typing import Any

from .base import (
    EXC_HEAD_RE, OOM_RE,
    extract_exception, extract_root_cause, is_stack_or_caused_by,
)

# --- DataPower log format ---
# 20260320T141542.123Z [default][error][0x80e00001] Connection refused to backend
DP_FULL_RE = re.compile(
    r'^(?P<ts>\d{8}T\d{6}\.\d{3}Z)\s+'
    r'\[(?P<domain>[^\]]+)\]'
    r'\[(?P<level>[^\]]+)\]'
    r'\[(?P<code>0x[0-9a-fA-F]+)\]\s*'
    r'(?P<message>.*)',
)

# Timestamp-only check for continuation detection
DP_TS_RE = re.compile(r'^\d{8}T\d{6}\.\d{3}Z\s+\[')

# --- Level mapping ---
DP_LEVELS = {
    'emergency': 'FATAL',
    'alert': 'FATAL',
    'critical': 'ERROR',
    'error': 'ERROR',
    'warn': 'WARNING',
    'warning': 'WARNING',
    'notice': 'INFO',
    'info': 'INFO',
    'debug': 'DEBUG',
}

# --- Signal tag patterns ---

# SSL/TLS: domain=ssl, code prefix 0x80e1, or keywords
DP_SSL_RE = re.compile(
    r'ssl.*handshake|handshake.*fail|certificate.*expired|certificate.*not trusted'
    r'|cert.*revoked|CRL.*fail|PKIX|SSLHandshakeException|0x80e1',
    re.IGNORECASE,
)

# Network: domain=network, code prefix 0x80e0, or keywords
DP_NETWORK_RE = re.compile(
    r'connection refused|connection timeout|dns.*resol|no route to host'
    r'|connection reset|ECONNREFUSED|ECONNRESET|0x80e0',
    re.IGNORECASE,
)

# Auth/AAA: domain=aaa, code prefix 0x80d0, or keywords
DP_AUTH_RE = re.compile(
    r'authentication fail|authorization denied|token expired|ldap.*fail'
    r'|ldap.*unreachable|token.*invalid|0x80d0',
    re.IGNORECASE,
)

# DB/Pool: backend timeout, connection pool
DP_DB_RE = re.compile(
    r'connection pool|backend.*timeout|pool.*exhaust|0x80e00002',
    re.IGNORECASE,
)

# HTTP: 4xx/5xx status codes, rate limit
DP_HTTP_RE = re.compile(
    r'\b[45]\d{2}\b.*(?:error|fail|reject|denied|timeout|limit)'
    r'|rate.limit|HTTP/\d\.\d"\s+[45]\d{2}',
    re.IGNORECASE,
)

# XML processing: code prefix 0x80c0
DP_XML_RE = re.compile(
    r'XML.*pars|schema.*valid|XSLT.*fail|XPath.*fail|not well-formed|0x80c0',
    re.IGNORECASE,
)

# API Connect: code prefix 0x80b0
DP_APIC_RE = re.compile(
    r'rate limit|plan exceeded|catalog.*error|subscription|0x80b0',
    re.IGNORECASE,
)

# Crypto: code prefix 0x80a0
DP_CRYPTO_RE = re.compile(
    r'key.*generat|algorithm.*not supported|decrypt.*fail|encrypt.*fail|0x80a0',
    re.IGNORECASE,
)


class DataPowerFormat:
    """IBM DataPower Gateway log format."""

    name = "datapower"
    description = "IBM DataPower Gateway"

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 based on DataPower log patterns."""
        if not lines:
            return 0.0
        score = 0
        for line in lines:
            if DP_FULL_RE.match(line):
                score += 3
        return min(score / (len(lines) * 3), 1.0)

    def extract_ts(self, line: str) -> str | None:
        """Extract ISO 8601 compact timestamp."""
        m = DP_FULL_RE.match(line)
        if m:
            return m.group("ts")
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity level from DataPower level field."""
        m = DP_FULL_RE.match(line)
        if m:
            raw = m.group("level").lower().strip()
            return DP_LEVELS.get(raw)
        return None

    def is_continuation(self, line: str) -> bool:
        """Check if line is a continuation (no timestamp prefix or stacktrace)."""
        if not line or not line.strip():
            return False
        # Has a DataPower timestamp prefix → new event
        if DP_TS_RE.match(line):
            return False
        # Java stacktrace or Caused by
        if is_stack_or_caused_by(line):
            return True
        # Continuation: indented or non-timestamp line
        return True

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a DataPower event block and return metadata."""
        first_line = text.split("\n", 1)[0]
        m = DP_FULL_RE.match(first_line)

        level = None
        code = None
        domain = None

        if m:
            raw_level = m.group("level").lower().strip()
            level = DP_LEVELS.get(raw_level)
            code = m.group("code")
            domain = m.group("domain")

        exc = extract_exception(text)
        root_cause = extract_root_cause(text)
        tags = self.bucket_tags(text)

        result: dict[str, Any] = {
            "level": level,
            "thread_id": None,  # DataPower has no thread concept
            "code": code,
            "exception": exc,
            "root_cause": root_cause,
            "tags": sorted(tags),
        }

        if domain:
            result["domain"] = domain

        return result

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags for DataPower patterns."""
        tags: set[str] = set()

        if DP_SSL_RE.search(text):
            tags.add("SSL/TLS")

        if DP_NETWORK_RE.search(text):
            tags.add("Network")

        if DP_AUTH_RE.search(text):
            tags.add("Auth")

        if DP_DB_RE.search(text):
            tags.add("DB/Pool")

        if DP_HTTP_RE.search(text):
            tags.add("HTTP")

        if DP_XML_RE.search(text):
            tags.add("XML")

        if DP_APIC_RE.search(text):
            tags.add("APIC")

        if DP_CRYPTO_RE.search(text):
            tags.add("Crypto")

        if OOM_RE.search(text):
            tags.add("OOM/GC")

        return tags
