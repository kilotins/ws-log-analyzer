"""syslog (RFC 3164/5424) and journald log format plugin."""
from __future__ import annotations

import re
from typing import Any

from .base import LEVEL_RE

# --- RFC 3164 (BSD syslog) ---
# Mar 11 10:15:33 hostname process[pid]: message
RFC3164_RE = re.compile(
    r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<proc>[^\[:\s]+)'
    r'(?:\[(?P<pid>\d+)\])?'
    r':\s*(?P<message>.*)',
)

# --- RFC 5424 ---
# <priority>version timestamp hostname app-name procid msgid [SD] message
# <134>1 2025-03-11T10:15:33.123Z hostname app 1234 ID47 [exampleSDID@32473] msg
RFC5424_RE = re.compile(
    r'^<(?P<pri>\d{1,3})>'
    r'(?P<ver>\d+)\s+'
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>\S+)\s+'
    r'(?P<pid>\S+)\s+'
    r'(?P<msgid>\S+)\s*'
    r'(?:\[(?P<sd>[^\]]*)\]\s*)?'
    r'(?P<message>.*)',
)

# --- journald with priority prefix ---
# <6>Mar 11 10:15:33 hostname process: message
JOURNALD_PRI_RE = re.compile(
    r'^<(?P<pri>\d{1,3})>'
    r'(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<proc>[^\[:\s]+)'
    r'(?:\[(?P<pid>\d+)\])?'
    r':\s*(?P<message>.*)',
)

# --- Timestamp patterns for extract_ts ---
# RFC 3164 style: "Mar 11 10:15:33"
TS_3164_RE = re.compile(r'(?:^<\d{1,3}>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
# RFC 5424 style ISO 8601
TS_5424_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
)

# --- Priority to severity mapping (RFC 5424 Table 2) ---
# severity = priority & 0x07
_PRIORITY_LEVEL_MAP: dict[int, str] = {
    0: "FATAL",      # Emergency
    1: "FATAL",      # Alert
    2: "CRITICAL",   # Critical
    3: "ERROR",      # Error
    4: "WARNING",    # Warning
    5: "INFO",       # Notice
    6: "INFO",       # Informational
    7: "DEBUG",      # Debug
}

# --- Kernel stack trace / continuation patterns ---
KERNEL_TRACE_RE = re.compile(
    r'^\s*(?:'
    r'\[[\s\d.]+\]\s|'            # [  123.456789]
    r'Call Trace:|'
    r'\?\s+\S+\+0x|'             # ? function+0x...
    r'\S+\+0x[\da-f]+/0x[\da-f]+'  # function+0xABC/0xDEF
    r')',
)
CONTINUATION_RE = re.compile(
    r'^\s+|'                      # indented continuation
    r'^---\[|'                    # kernel trace separator
    r'^\s*\.\.\.\s*$',           # ellipsis continuation
)

# --- Signal tag patterns ---
OOM_RE = re.compile(
    r'Out of memory|oom-killer|oom_kill|invoked oom|'
    r'MemoryError|Cannot allocate memory|'
    r'memory cgroup out of memory',
    re.IGNORECASE,
)
AUTH_RE = re.compile(
    r'sshd\[.*authentication failure|Failed password|'
    r'pam_unix\(.*auth\)|Invalid user|'
    r'sudo:\s|COMMAND=|session opened for user|'
    r'Accepted (?:password|publickey)|'
    r'authentication failure|pam_authenticate',
    re.IGNORECASE,
)
DISK_RE = re.compile(
    r'No space left|filesystem full|I/O error|'
    r'EXT4-fs error|XFS error|'
    r'readonly|read-only file system|'
    r'SCSI error|medium error|'
    r'blk_update_request',
    re.IGNORECASE,
)
NETWORK_RE = re.compile(
    r'link down|link is not ready|carrier lost|'
    r'connection refused|unreachable|'
    r'firewall|iptables|nftables|'
    r'NetworkManager.*disconnected|'
    r'bond\d+.*link status',
    re.IGNORECASE,
)
SERVICE_RE = re.compile(
    r'Failed to start|entered failed state|'
    r'segfault at|general protection fault|'
    r'systemd\[.*Failed|'
    r'main process exited|'
    r'service .* failed',
    re.IGNORECASE,
)
KERNEL_RE = re.compile(
    r'kernel panic|BUG:|oops|hardware error|'
    r'Machine check|NMI received|'
    r'RIP:|Kernel BUG|hung_task_timeout',
    re.IGNORECASE,
)


def _severity_from_priority(pri: int) -> str:
    """Extract severity level from syslog priority value.

    Priority = facility * 8 + severity.
    """
    severity = pri & 0x07
    return _PRIORITY_LEVEL_MAP.get(severity, "INFO")


def _extract_process_info(line: str) -> tuple[str | None, str | None]:
    """Extract process name and PID from a syslog line."""
    for pattern in (JOURNALD_PRI_RE, RFC5424_RE):
        m = pattern.match(line)
        if m:
            proc = m.group("app") if "app" in pattern.groupindex else m.group("proc")
            pid = m.group("pid")
            if pid == "-":
                pid = None
            return proc, pid
    m = RFC3164_RE.match(line)
    if m:
        return m.group("proc"), m.group("pid")
    return None, None


class SyslogFormat:
    """syslog (RFC 3164/5424) and journald format."""

    name = "syslog"
    description = "syslog (RFC 3164/5424, journald)"

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 how likely these lines match syslog format."""
        if not lines:
            return 0.0
        matches = 0
        for line in lines:
            if RFC5424_RE.match(line):
                matches += 1
            elif JOURNALD_PRI_RE.match(line):
                matches += 1
            elif RFC3164_RE.match(line):
                matches += 1
        ratio = matches / len(lines)
        if ratio > 0.6:
            return min(0.9 + (ratio - 0.6) * 0.25, 1.0)
        return ratio * 1.5

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp from a syslog line."""
        # RFC 5424 first (more specific)
        m = RFC5424_RE.match(line)
        if m:
            return m.group("ts")
        # journald with priority prefix
        m = JOURNALD_PRI_RE.match(line)
        if m:
            return m.group("ts")
        # RFC 3164 (BSD)
        m = TS_3164_RE.match(line)
        if m:
            return m.group("ts")
        # Fallback: ISO 8601 anywhere in line
        m = TS_5424_RE.search(line)
        if m:
            return m.group("ts")
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity from priority value or message content."""
        # RFC 5424 priority
        m = RFC5424_RE.match(line)
        if m:
            try:
                pri = int(m.group("pri"))
                return _severity_from_priority(pri)
            except (ValueError, TypeError):
                pass
        # journald priority prefix
        m = JOURNALD_PRI_RE.match(line)
        if m:
            try:
                pri = int(m.group("pri"))
                return _severity_from_priority(pri)
            except (ValueError, TypeError):
                pass
        # Fallback: keyword matching in message
        m = LEVEL_RE.search(line)
        if m:
            return m.group(1).upper()
        # Heuristic: kernel messages with common severity indicators
        if re.search(r'kernel panic|BUG:|oops', line, re.IGNORECASE):
            return "FATAL"
        if re.search(r'error|fail|segfault', line, re.IGNORECASE):
            return "ERROR"
        if re.search(r'warn', line, re.IGNORECASE):
            return "WARNING"
        return None

    def is_continuation(self, line: str) -> bool:
        """Detect kernel stack traces and multiline messages."""
        if not line:
            return False
        # Kernel stack traces
        if KERNEL_TRACE_RE.match(line):
            return True
        # Lines starting with whitespace (but not a new syslog entry)
        if line[0] in (' ', '\t') and not RFC3164_RE.match(line.lstrip()):
            return True
        return False

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a syslog event and return metadata."""
        first_line = text.split("\n", 1)[0]
        tags = self.bucket_tags(text)
        level = self.extract_level(first_line)
        proc, pid = _extract_process_info(first_line)

        # Try to get structured data from RFC 5424
        code = None
        m = RFC5424_RE.match(first_line)
        if m:
            msgid = m.group("msgid")
            if msgid and msgid != "-":
                code = msgid

        return {
            "level": level,
            "thread_id": None,
            "code": code,
            "exception": None,
            "root_cause": None,
            "tags": sorted(tags),
            "process": proc,
            "pid": pid,
        }

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags from syslog event text."""
        tags: set[str] = set()

        if OOM_RE.search(text):
            tags.add("OOM")
        if AUTH_RE.search(text):
            tags.add("Auth")
        if DISK_RE.search(text):
            tags.add("Disk")
        if NETWORK_RE.search(text):
            tags.add("Network")
        if SERVICE_RE.search(text):
            tags.add("Service")
        if KERNEL_RE.search(text):
            tags.add("Kernel")

        return tags
