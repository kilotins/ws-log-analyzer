"""OpenShift / Kubernetes (CRI-O, klog) log format plugin."""
from __future__ import annotations

import json
import re
from typing import Any

from .base import (
    EXC_HEAD_RE, LEVEL_RE, OOM_RE,
    extract_exception, extract_root_cause, is_stack_or_caused_by,
)

# --- CRI-O container log format ---
# 2025-03-11T10:15:33.123456789+01:00 stderr F Error message
CRIO_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(?:Z|[+-]\d{2}:\d{2}))'
    r'\s+(?P<stream>stdout|stderr)'
    r'\s+(?P<flag>[FP])'
    r'\s(?P<msg>.*)$'
)

# --- klog format (Kubernetes operators, controller-runtime) ---
# I0311 10:15:33.123456  1 controller.go:123] message
KLOG_RE = re.compile(
    r'^(?P<level>[IWEF])(?P<mmdd>\d{4})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'(?P<pid>\d+)\s+'
    r'(?P<file>[^]]+)\]\s+'
    r'(?P<msg>.*)$'
)

KLOG_LEVEL_MAP = {
    'I': 'INFO',
    'W': 'WARNING',
    'E': 'ERROR',
    'F': 'FATAL',
}

# --- K8s metadata JSON envelope ---
# {"@timestamp":"...","message":"...","kubernetes":{"namespace_name":"...","pod_name":"..."}}
K8S_JSON_KEYS = ("kubernetes", "openshift")

# --- Pod lifecycle error patterns ---
POD_LIFECYCLE_RE = re.compile(
    r'CrashLoopBackOff|OOMKilled|ImagePullBackOff|ImagePull|FailedScheduling'
    r'|Evicted|CreateContainerConfigError|ErrImagePull',
    re.IGNORECASE,
)

# --- Network patterns ---
K8S_NETWORK_RE = re.compile(
    r'connection refused|no route to host|no such host'
    r'|i/o timeout|dial tcp.*timeout|ECONNREFUSED|ECONNRESET'
    r'|TLS handshake error',
    re.IGNORECASE,
)

# --- Storage patterns ---
K8S_STORAGE_RE = re.compile(
    r'FailedMount|ProvisioningFailed|VolumeInUse|NodeUnschedulable',
    re.IGNORECASE,
)

# --- Auth patterns ---
K8S_AUTH_RE = re.compile(
    r'\bUnauthorized\b|\bForbidden\b|certificate.*expired'
    r'|certificate has expired|oauth.*fail',
    re.IGNORECASE,
)

# --- OpenShift route / HAProxy patterns ---
OPENSHIFT_ROUTE_RE = re.compile(
    r'HAProxy|503.*no server|no server available|route not admitted',
    re.IGNORECASE,
)


def _safe_parse_json(line: str) -> dict | None:
    """Try to parse a line as JSON, return dict or None."""
    stripped = line.strip()
    if not stripped or stripped[0] != '{':
        return None
    try:
        obj = json.loads(stripped)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def _is_k8s_json(obj: dict) -> bool:
    """Check if a JSON object looks like a K8s metadata envelope."""
    return any(k in obj for k in K8S_JSON_KEYS)


def _extract_crio_message(line: str) -> str | None:
    """Extract the message portion from a CRI-O log line."""
    m = CRIO_RE.match(line)
    if m:
        return m.group("msg")
    return None


class CRIOFormat:
    """OpenShift / Kubernetes (CRI-O, klog) log format."""

    name = "crio"
    description = "OpenShift / Kubernetes (CRI-O, klog)"

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 based on CRI-O, klog, and K8s JSON patterns."""
        if not lines:
            return 0.0
        score = 0
        for line in lines:
            if CRIO_RE.match(line):
                score += 3
            elif KLOG_RE.match(line):
                score += 3
            else:
                obj = _safe_parse_json(line)
                if obj and _is_k8s_json(obj):
                    score += 3
                elif obj:
                    # JSON but not K8s-specific -- don't claim it
                    pass
        return min(score / (len(lines) * 3), 1.0)

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp from CRI-O, klog, or K8s JSON line."""
        # CRI-O
        m = CRIO_RE.match(line)
        if m:
            return m.group("ts")

        # klog
        km = KLOG_RE.match(line)
        if km:
            mmdd = km.group("mmdd")
            time_part = km.group("time")
            # Return as MMDD HH:MM:SS.ffffff for downstream parsing
            return f"{mmdd} {time_part}"

        # K8s JSON envelope
        obj = _safe_parse_json(line)
        if obj:
            for field in ("@timestamp", "timestamp", "time", "ts"):
                if field in obj:
                    return str(obj[field])

        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity level from CRI-O stream, klog prefix, or message content."""
        # klog -- most specific
        km = KLOG_RE.match(line)
        if km:
            return KLOG_LEVEL_MAP.get(km.group("level"))

        # CRI-O
        cm = CRIO_RE.match(line)
        if cm:
            msg = cm.group("msg")
            # Check message content for level keywords first
            lm = LEVEL_RE.search(msg)
            if lm:
                raw = lm.group(1).upper()
                if raw == "WARNING":
                    return "WARNING"
                return raw
            # Fall back to stream: stderr=WARNING, stdout=INFO
            stream = cm.group("stream")
            return "WARNING" if stream == "stderr" else "INFO"

        # K8s JSON
        obj = _safe_parse_json(line)
        if obj:
            for field in ("level", "severity", "loglevel"):
                if field in obj:
                    raw = str(obj[field]).upper()
                    if raw in ("INFO", "DEBUG", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL", "TRACE"):
                        return raw
                    if raw in ("SEVERE", "ERR"):
                        return "ERROR"
                    break

        # Generic level keyword search
        lm = LEVEL_RE.search(line)
        if lm:
            return lm.group(1).upper()

        return None

    def is_continuation(self, line: str) -> bool:
        """Check if line is a continuation (CRI-O partial or stacktrace)."""
        # CRI-O partial line (P flag)
        cm = CRIO_RE.match(line)
        if cm:
            return cm.group("flag") == "P"

        # Java stacktrace / Caused by in the message
        if is_stack_or_caused_by(line):
            return True

        # Check inside CRI-O message portion for stacktrace
        # (already handled above for raw lines; this catches the message payload)
        return False

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a CRI-O/klog event block and return metadata."""
        level = None
        thread_id = None
        code = None
        namespace = None
        pod_name = None

        first_line = text.split("\n", 1)[0]

        # Try klog
        km = KLOG_RE.match(first_line)
        if km:
            level = KLOG_LEVEL_MAP.get(km.group("level"))

        # Try CRI-O
        if not level:
            cm = CRIO_RE.match(first_line)
            if cm:
                msg = cm.group("msg")
                lm = LEVEL_RE.search(msg)
                if lm:
                    level = lm.group(1).upper()
                else:
                    stream = cm.group("stream")
                    level = "WARNING" if stream == "stderr" else "INFO"

        # Try K8s JSON envelope
        obj = _safe_parse_json(first_line)
        if obj:
            if _is_k8s_json(obj):
                k8s = obj.get("kubernetes", {})
                namespace = k8s.get("namespace_name")
                pod_name = k8s.get("pod_name")
            for field in ("level", "severity", "loglevel"):
                if field in obj and not level:
                    raw = str(obj[field]).upper()
                    if raw in ("INFO", "DEBUG", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"):
                        level = raw
                        break

        # Fall back to generic level keyword
        if not level:
            lm = LEVEL_RE.search(text)
            if lm:
                level = lm.group(1).upper()

        # Pod lifecycle error codes
        plm = POD_LIFECYCLE_RE.search(text)
        if plm:
            code = plm.group(0)
            # Normalize casing for well-known codes
            code_map = {
                "crashloopbackoff": "CrashLoopBackOff",
                "oomkilled": "OOMKilled",
                "imagepullbackoff": "ImagePullBackOff",
                "imagepull": "ImagePull",
                "failedscheduling": "FailedScheduling",
                "evicted": "Evicted",
                "createcontainerconfigerror": "CreateContainerConfigError",
                "errimagepull": "ErrImagePull",
            }
            code = code_map.get(code.lower(), code)

        exc = extract_exception(text)
        root_cause = extract_root_cause(text)
        tags = self.bucket_tags(text)

        result: dict[str, Any] = {
            "level": level,
            "thread_id": thread_id,
            "code": code,
            "exception": exc,
            "root_cause": root_cause,
            "tags": sorted(tags),
        }

        # Add K8s metadata if found
        if namespace:
            result["namespace"] = namespace
        if pod_name:
            result["pod_name"] = pod_name

        return result

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags for K8s/OpenShift patterns."""
        tags: set[str] = set()

        if POD_LIFECYCLE_RE.search(text):
            tags.add("K8s/Pod")

        if K8S_NETWORK_RE.search(text):
            tags.add("K8s/Network")

        if K8S_STORAGE_RE.search(text):
            tags.add("K8s/Storage")

        if K8S_AUTH_RE.search(text):
            tags.add("K8s/Auth")

        if OOM_RE.search(text):
            tags.add("OOM/GC")
        # Also catch OOMKilled specifically
        if re.search(r'OOMKilled', text, re.IGNORECASE):
            tags.add("OOM/GC")

        if OPENSHIFT_ROUTE_RE.search(text):
            tags.add("OpenShift/Route")

        return tags
