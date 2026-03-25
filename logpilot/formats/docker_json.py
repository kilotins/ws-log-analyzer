"""Docker JSON log driver format plugin."""
from __future__ import annotations

import json
import re
from typing import Any

from .base import (
    LEVEL_RE, OOM_RE,
    extract_exception, extract_root_cause, is_stack_or_caused_by,
)

# --- Docker JSON log format ---
# {"log":"2026-03-23 10:30:00 ERROR Something failed\n","stream":"stderr","time":"2026-03-23T10:30:00.123456789Z"}
# {"log":"  at com.example.Foo.bar(Foo.java:42)\n","stream":"stderr","time":"2026-03-23T10:30:00.123456790Z"}

# Container name may appear in attrs
# {"log":"message\n","stream":"stderr","time":"...","attrs":{"tag":"myapp"}}

DOCKER_JSON_REQUIRED_KEYS = {"log", "time"}  # stream is optional (some drivers omit it)

# Level patterns in the embedded log message
DOCKER_LEVEL_RE = re.compile(
    r'\b(FATAL|SEVERE|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE|CRITICAL)\b',
    re.IGNORECASE,
)

# K8s pod annotation pattern in Docker JSON
# Often the log line starts with a timestamp from the app itself
APP_TS_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})',
)


def _parse_docker_json(line: str) -> dict | None:
    """Try to parse a line as Docker JSON log entry."""
    stripped = line.strip()
    if not stripped or stripped[0] != '{':
        return None
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict) and DOCKER_JSON_REQUIRED_KEYS.issubset(obj.keys()):
            return obj
        return None
    except (json.JSONDecodeError, ValueError):
        return None


class DockerJSONFormat:
    """Docker JSON log driver format."""

    name = "docker_json"
    description = "Docker JSON log driver"

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 based on Docker JSON log patterns."""
        if not lines:
            return 0.0
        score = 0
        for line in lines:
            obj = _parse_docker_json(line)
            if obj:
                score += 4  # Higher than generic JSON (which scores 3)
                # Bonus for Docker-specific fields
                if "attrs" in obj or obj.get("stream") in ("stdout", "stderr"):
                    score += 1
        return min(score / (len(lines) * 3), 1.0)

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp from Docker JSON 'time' field."""
        obj = _parse_docker_json(line)
        if obj:
            return obj.get("time")
        return None

    def extract_level(self, line: str) -> str | None:
        """Extract severity from embedded log message or stream."""
        obj = _parse_docker_json(line)
        if not obj:
            return None

        log_msg = obj.get("log", "")

        # Check for level keyword in the log message
        m = DOCKER_LEVEL_RE.search(log_msg)
        if m:
            raw = m.group(1).upper()
            if raw == "SEVERE":
                return "ERROR"
            if raw == "WARN":
                return "WARNING"
            return raw

        # Fall back to stream: stderr = WARNING, stdout = INFO
        stream = obj.get("stream", "")
        if stream == "stderr":
            return "WARNING"
        return "INFO"

    def is_continuation(self, line: str) -> bool:
        """Check if line is a continuation (stacktrace in Docker JSON wrapper)."""
        if not line or not line.strip():
            return False

        obj = _parse_docker_json(line)
        if not obj:
            # Not JSON at all — raw continuation
            return True

        log_msg = obj.get("log", "")
        # Stacktrace or Caused by inside the log field
        if is_stack_or_caused_by(log_msg):
            return True
        # Indented continuation inside Docker JSON
        if log_msg.startswith((" ", "\t")) and not APP_TS_RE.match(log_msg):
            return True

        return False

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a Docker JSON event block and return metadata."""
        # Extract all log messages from potentially multiple JSON lines
        full_log = []
        container = None
        for line in text.split("\n"):
            obj = _parse_docker_json(line)
            if obj:
                full_log.append(obj.get("log", "").rstrip("\n"))
                if not container:
                    attrs = obj.get("attrs", {})
                    container = attrs.get("tag") or attrs.get("container_name")
            else:
                full_log.append(line)

        combined = "\n".join(full_log)

        # Level from first line
        level = None
        m = DOCKER_LEVEL_RE.search(combined.split("\n", 1)[0])
        if m:
            raw = m.group(1).upper()
            if raw == "SEVERE":
                level = "ERROR"
            elif raw == "WARN":
                level = "WARNING"
            else:
                level = raw

        if not level:
            # Check stream from first JSON line
            first_obj = _parse_docker_json(text.split("\n", 1)[0])
            if first_obj and first_obj.get("stream") == "stderr":
                level = "WARNING"

        exc = extract_exception(combined)
        root_cause = extract_root_cause(combined)
        tags = self.bucket_tags(combined)

        result: dict[str, Any] = {
            "level": level,
            "thread_id": None,
            "code": None,
            "exception": exc,
            "root_cause": root_cause,
            "tags": sorted(tags),
        }

        if container:
            result["container"] = container

        return result

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags from Docker JSON log content."""
        tags: set[str] = set()

        if OOM_RE.search(text):
            tags.add("OOM/GC")

        if re.search(r'OOMKilled|oom-kill|cgroup.*oom', text, re.IGNORECASE):
            tags.add("K8s/Pod")

        if re.search(r'connection refused|ECONNREFUSED|connection reset', text, re.IGNORECASE):
            tags.add("Network")

        if re.search(r'SSLHandshakeException|certificate.*expired|PKIX', text, re.IGNORECASE):
            tags.add("SSL/TLS")

        if re.search(r'pool.*exhaust|connection.*timeout|HikariPool', text, re.IGNORECASE):
            tags.add("DB/Pool")

        if re.search(r'\b[45]\d{2}\b.*(?:error|fail)', text, re.IGNORECASE):
            tags.add("HTTP")

        return tags
