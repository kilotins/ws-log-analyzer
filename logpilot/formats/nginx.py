"""nginx / Apache access & error log format plugin."""
from __future__ import annotations

import re
from typing import Any

from .base import LEVEL_RE

# --- Access log patterns (Combined Log Format) ---

# Combined Log Format:
# 192.168.1.1 - frank [11/Mar/2025:10:15:33 +0100] "GET /api/users HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0..."
CLF_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s*(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Timestamp inside CLF brackets: [10/Mar/2025:12:34:56 +0100]
CLF_TS_RE = re.compile(r'\[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]')

# --- nginx error log pattern ---
# 2025/03/11 10:15:33 [error] 1234#5678: *99 message...
NGINX_ERR_RE = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#(?P<tid>\d+):\s+'
    r'(?:\*(?P<cid>\d+)\s+)?'
    r'(?P<message>.*)'
)

# --- Apache ErrorLog pattern ---
# [Mon Mar 11 10:15:33.123456 2025] [module:level] [pid N] message
APACHE_ERR_RE = re.compile(
    r'^\[(?P<ts>\w{3}\s+\w{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\d{4})\]\s+'
    r'\[(?:(?P<module>\w+):)?(?P<level>\w+)\]\s+'
    r'(?:\[pid\s+(?P<pid>\d+)\]\s+)?'
    r'(?P<message>.*)'
)

# --- Timestamp extraction patterns ---
NGINX_ERR_TS_RE = re.compile(r'^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})')
APACHE_ERR_TS_RE = re.compile(r'^\[(?P<ts>\w{3}\s+\w{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\d{4})\]')

# --- HTTP status code in a line ---
HTTP_STATUS_RE = re.compile(r'"\s*(?P<status>\d{3})\s')

# --- Signal tag patterns ---
UPSTREAM_RE = re.compile(
    r'upstream|connect\(\) failed|no live upstreams|'
    r'upstream timed out|upstream prematurely closed',
    re.IGNORECASE,
)
SSL_RE = re.compile(
    r'SSL_do_handshake|ssl_certificate|handshake.?failure|'
    r'SSL:\s*error|certificate.*(expired|invalid|unknown|verify failed)',
    re.IGNORECASE,
)
RATE_LIMIT_RE = re.compile(
    r'limiting requests|limit_req|limit_conn|\b429\b',
    re.IGNORECASE,
)
TIMEOUT_RE = re.compile(
    r'timed?\s*out|\b408\b|\b504\b|\b499\b',
    re.IGNORECASE,
)
DISK_RE = re.compile(r'No space left on device|ENOSPC', re.IGNORECASE)
PERMISSION_RE = re.compile(r'Permission denied|\(13:', re.IGNORECASE)

# Level mapping for nginx/Apache error levels
_NGINX_LEVEL_MAP: dict[str, str] = {
    "emerg": "FATAL",
    "alert": "FATAL",
    "crit": "CRITICAL",
    "error": "ERROR",
    "warn": "WARNING",
    "notice": "INFO",
    "info": "INFO",
    "debug": "DEBUG",
}


def _status_to_level(status: int) -> str:
    """Map HTTP status code to severity level."""
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    return "INFO"


def _extract_status(line: str) -> int | None:
    """Extract HTTP status code from an access log line."""
    m = CLF_RE.match(line)
    if m:
        try:
            return int(m.group("status"))
        except (ValueError, TypeError):
            return None
    return None


class NginxFormat:
    """nginx / Apache access & error log format."""

    name = "nginx"
    description = "nginx / Apache access & error logs"

    def detect(self, lines: list[str]) -> float:
        """Score based on nginx/Apache log patterns in first N lines."""
        if not lines:
            return 0.0
        matches = 0
        for line in lines:
            if CLF_RE.match(line):
                matches += 1
            elif NGINX_ERR_RE.match(line):
                matches += 1
            elif APACHE_ERR_RE.match(line):
                matches += 1
        ratio = matches / len(lines)
        # Scale: >60% match → 0.9+
        if ratio > 0.6:
            return min(0.9 + (ratio - 0.6) * 0.25, 1.0)
        return ratio * 1.5  # boost partial matches

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp from access or error log line."""
        # CLF access log
        m = CLF_TS_RE.search(line)
        if m:
            return m.group("ts")
        # nginx error log
        m = NGINX_ERR_TS_RE.match(line)
        if m:
            return m.group("ts")
        # Apache error log
        m = APACHE_ERR_TS_RE.match(line)
        if m:
            return m.group("ts")
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity from status code or error level bracket."""
        # nginx error log
        m = NGINX_ERR_RE.match(line)
        if m:
            raw_level = m.group("level").lower()
            return _NGINX_LEVEL_MAP.get(raw_level, raw_level.upper())
        # Apache error log
        m = APACHE_ERR_RE.match(line)
        if m:
            raw_level = m.group("level").lower()
            return _NGINX_LEVEL_MAP.get(raw_level, raw_level.upper())
        # Access log — derive from HTTP status code
        status = _extract_status(line)
        if status is not None:
            return _status_to_level(status)
        # Fallback to keyword matching
        m = LEVEL_RE.search(line)
        return m.group(1).upper() if m else None

    def is_continuation(self, line: str) -> bool:
        """Access logs are single-line; error log multiline is rare."""
        return False

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a nginx/Apache log event."""
        first_line = text.split("\n", 1)[0]

        # Try access log first
        clf_m = CLF_RE.match(first_line)
        if clf_m:
            return self._classify_access(clf_m, text)

        # Try nginx error log
        err_m = NGINX_ERR_RE.match(first_line)
        if err_m:
            return self._classify_error(err_m, text)

        # Try Apache error log
        apache_m = APACHE_ERR_RE.match(first_line)
        if apache_m:
            return self._classify_apache_error(apache_m, text)

        # Fallback
        tags = self.bucket_tags(text)
        level_m = LEVEL_RE.search(text)
        return {
            "level": level_m.group(1).upper() if level_m else None,
            "thread_id": None,
            "code": None,
            "exception": None,
            "root_cause": None,
            "tags": sorted(tags),
        }

    def _classify_access(self, m: re.Match, text: str) -> dict[str, Any]:
        """Classify a Combined Log Format access log line."""
        status = int(m.group("status"))
        level = _status_to_level(status)
        code = f"HTTP_{status}"

        tags = self.bucket_tags(text)

        return {
            "level": level,
            "thread_id": None,
            "code": code,
            "exception": None,
            "root_cause": None,
            "tags": sorted(tags),
            "method": m.group("method"),
            "path": m.group("path"),
            "status": status,
            "size": m.group("size"),
            "referrer": m.group("referrer"),
            "user_agent": m.group("user_agent"),
        }

    def _classify_error(self, m: re.Match, text: str) -> dict[str, Any]:
        """Classify a nginx error log line."""
        raw_level = m.group("level").lower()
        level = _NGINX_LEVEL_MAP.get(raw_level, raw_level.upper())
        tags = self.bucket_tags(text)

        return {
            "level": level,
            "thread_id": None,
            "code": None,
            "exception": None,
            "root_cause": None,
            "tags": sorted(tags),
        }

    def _classify_apache_error(self, m: re.Match, text: str) -> dict[str, Any]:
        """Classify an Apache ErrorLog line."""
        raw_level = m.group("level").lower()
        level = _NGINX_LEVEL_MAP.get(raw_level, raw_level.upper())
        tags = self.bucket_tags(text)

        return {
            "level": level,
            "thread_id": None,
            "code": None,
            "exception": None,
            "root_cause": None,
            "tags": sorted(tags),
        }

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags from event text."""
        tags: set[str] = set()

        # Check for HTTP status codes in access log lines
        for line in text.splitlines():
            status = _extract_status(line)
            if status is not None:
                if status >= 500:
                    tags.add("HTTP")
                elif status >= 400:
                    tags.add("HTTP")

        if UPSTREAM_RE.search(text):
            tags.add("Upstream")
        if SSL_RE.search(text):
            tags.add("SSL/TLS")
        if RATE_LIMIT_RE.search(text):
            tags.add("RateLimit")
        if TIMEOUT_RE.search(text):
            tags.add("Timeout")
        if DISK_RE.search(text):
            tags.add("DiskFull")
        if PERMISSION_RE.search(text):
            tags.add("Permission")

        return tags
