# Log Format Plugin System

## Architecture

Log format parsers live under `logpilot/formats/`. Each format is a class implementing the `LogFormat` protocol.

```
logpilot/formats/
    __init__.py      # Registry, auto-detect, format listing
    base.py          # LogFormat protocol + shared helpers
    was.py           # WebSphere/Liberty (original parser)
    json_log.py      # JSON structured logs (Docker, structlog, Bunyan, zap)
    nginx.py         # nginx access + error logs
    log4j.py         # Log4j/Logback (Spring Boot, Kafka)
    python_log.py    # Python logging (Django, Flask, tracebacks)
    syslog.py        # syslog RFC 3164/5424, journald
    enonic.py        # Enonic XP server.log + Jetty request logs
    crio.py          # CRI-O / Kubernetes container runtime logs
```

## LogFormat Protocol

Every format must implement this interface:

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class LogFormat(Protocol):
    name: str           # e.g. "nginx", "json", "log4j"
    description: str    # Human-readable, shown in UI

    def detect(self, lines: list[str]) -> float:
        """Score 0.0-1.0 how likely these lines match this format.
        Called with first 50 lines of a file."""
        ...

    def extract_ts(self, line: str) -> str | None:
        """Extract timestamp string from a log line."""
        ...

    def extract_level(self, line: str) -> str | None:
        """Extract severity level (ERROR, WARN, INFO, DEBUG, etc.)."""
        ...

    def is_continuation(self, line: str) -> bool:
        """Is this line a continuation of the previous event?
        (stacktrace, multiline message, etc.)"""
        ...

    def classify_event(self, text: str) -> dict[str, Any]:
        """Classify a block of log text. Return dict with:
        level, thread_id, code, exception, root_cause, tags"""
        ...

    def bucket_tags(self, text: str) -> set[str]:
        """Extract signal tags from event text."""
        ...
```

## Auto-Detection Algorithm

```python
def detect_format(path: Path) -> LogFormat:
    """Read first 50 lines, score each registered format, return best match."""
    lines = _read_head(path, 50)
    best_score = 0.0
    best_format = GenericJavaFormat()  # fallback

    for fmt in _REGISTRY:
        score = fmt.detect(lines)
        if score > best_score:
            best_score = score
            best_format = fmt

    return best_format
```

Detection scoring guidelines:
- **1.0** — Definitive match (e.g., JSON with known library fields, WAS `[timestamp CEST]` pattern)
- **0.7-0.9** — Strong match (format-specific patterns present)
- **0.3-0.6** — Partial match (some indicators but ambiguous)
- **0.0** — No match

## Creating a New Format

### Step 1: Create the format file

```python
# logpilot/formats/myformat.py
"""MyFormat log parser."""
from __future__ import annotations
import re
from typing import Any

class MyFormat:
    name = "myformat"
    description = "My Custom Log Format"

    # Compiled regexes at class level
    _TS_RE = re.compile(r'...')
    _LEVEL_RE = re.compile(r'...')

    def detect(self, lines: list[str]) -> float:
        matches = sum(1 for l in lines if self._TS_RE.search(l))
        return min(matches / max(len(lines), 1), 1.0)

    def extract_ts(self, line: str) -> str | None:
        m = self._TS_RE.search(line)
        return m.group("ts") if m else None

    def extract_level(self, line: str) -> str | None:
        m = self._LEVEL_RE.search(line)
        return m.group(1).upper() if m else None

    def is_continuation(self, line: str) -> bool:
        return bool(STACK_LINE_RE.match(line) or CAUSED_BY_RE.match(line))

    def classify_event(self, text: str) -> dict[str, Any]:
        # Use shared helpers from base.py for exceptions, root cause, etc.
        ...

    def bucket_tags(self, text: str) -> set[str]:
        tags: set[str] = set()
        # Add format-specific tags
        return tags
```

### Step 2: Register it

```python
# logpilot/formats/__init__.py
from .myformat import MyFormat
_REGISTRY.append(MyFormat())
```

### Step 3: Add tests

```python
# tests/test_format_myformat.py
from logpilot.formats.myformat import MyFormat

SAMPLE = """\
2025-03-11 10:15:33 ERROR Something went wrong
    at com.example.Foo.bar(Foo.java:42)
"""

def test_detect():
    fmt = MyFormat()
    assert fmt.detect(SAMPLE.splitlines()) > 0.7

def test_extract_ts():
    fmt = MyFormat()
    assert fmt.extract_ts("2025-03-11 10:15:33 ERROR msg") == "2025-03-11 10:15:33"

def test_classify_event():
    fmt = MyFormat()
    result = fmt.classify_event(SAMPLE)
    assert result["level"] == "ERROR"
```

### Step 4: Add heuristics (optional)

Add format-specific entries to `heuristics.yaml`:

```yaml
- id: myformat_timeout
  match: "connection timed out|read timeout"
  title: "Connection Timeout"
  cause: "Remote service not responding within configured timeout"
  fixes:
    - "Check remote service health"
    - "Increase timeout configuration"
  formats: [myformat]  # only applies to this format
```

## Shared Helpers (base.py)

Reusable across all formats — don't duplicate:

| Helper | Purpose |
|--------|---------|
| `STACK_LINE_RE` | Java stacktrace `at ...` lines |
| `CAUSED_BY_RE` | Java `Caused by:` chains |
| `EXC_HEAD_RE` | Java exception class names |
| `extract_root_cause(text)` | Deepest `Caused by:` exception |
| `extract_exception(text)` | First exception match |
| `common_bucket_tags(text)` | OOM, SSL, HTTP — shared across formats |
| `redact(text)` | Secret redaction (always runs) |

## Event Dict Schema

All formats must produce events with this schema:

```python
{
    "file": str,           # Source file path
    "ts": str | None,      # Timestamp string (format-native)
    "ts_utc": str | None,  # ISO 8601 UTC timestamp (added by analysis pipeline)
    "level": str | None,   # Normalized: ERROR, WARN, INFO, DEBUG
    "thread_id": str | None,
    "code": str | None,    # Format-specific code (WAS code, HTTP status, etc.)
    "exception": str | None,
    "root_cause": str | None,
    "tags": list[str],     # Signal tags: OOM/GC, HungThreads, SSL/TLS, etc.
    "text": str,           # Full event text (redacted)
    "format": str,         # Which format parsed this: "was", "nginx", "json", etc.
    "system_label": str,   # Source label for cross-system analysis (e.g., "spring-backend")
    "trace_ids": dict,     # Extracted trace IDs: {"trace_id": "abc", "span_id": "def", ...}
}
```

## CLI Integration

```bash
# Auto-detect (default)
logpilot server.log

# Explicit format
logpilot --format nginx access.log error.log

# List available formats
logpilot --list-formats
```

## Testing Conventions

- Each format gets its own test file: `tests/test_format_{name}.py`
- Use inline string constants as fixtures, not real log files
- Test `detect()` with both matching and non-matching input
- Test that non-matching formats score low (no false positives)
- Test mixed-format files (auto-detect picks the right one)
- All existing tests must keep passing (WAS format unchanged)

## Gotchas

- **Level normalization**: All formats must normalize to uppercase `ERROR`, `WARN`, `INFO`, `DEBUG`. Map format-specific levels (e.g., nginx `emerg` → `ERROR`, Python `CRITICAL` → `ERROR`)
- **Timestamp preservation**: Store the raw timestamp string in `ts`, not a parsed datetime. `parse_ts_datetime()` in analysis.py handles conversion
- **Multiline events**: `is_continuation()` must correctly identify lines that belong to the current event, not just stacktraces (e.g., JSON multiline, nginx error details)
- **Redaction**: Always runs via `redact()` in the parsing pipeline — formats don't need to call it themselves
- **Performance**: `detect()` is called per file. Keep it fast — check first 50 lines, don't parse the whole file
