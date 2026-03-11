"""Parsing, classification, and redaction of WebSphere/Java log files."""
from __future__ import annotations

import gzip
import logging
import re
from pathlib import Path
from typing import IO, Any

_log = logging.getLogger("wslog")

# --- Constants ---
MAX_EVENT_TEXT = 4000  # Max characters of event text in reports

# --- Common patterns (WebSphere / Java-ish) ---
TS_PATTERNS = [
    # WebSphere classic: [10/12/15 21:22:04:257 CEST]
    re.compile(r'\[(?P<ts>\d{1,2}/\d{1,2}/\d{2,4}\s+\d{2}:\d{2}:\d{2}:\d{3})\s+\w+\]'),
    # ISO / WebSphere common: 2025-03-05 12:34:56:789 or 2025-03-05T12:34:56.789
    re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,:.]\d{3,6})?)'),
]

LEVEL_RE = re.compile(r'\b(SEVERE|ERROR|WARN|WARNING|INFO|DEBUG|FINE|FINER|FINEST)\b', re.IGNORECASE)

# WebSphere uses single-letter severity after thread ID: [ts] threadid Component X
# I=Info, A=Audit, W=Warning, E=Error, O=SystemOut/SystemErr, F=Fatal, R=Report, D=Detail
WAS_LEVEL_RE = re.compile(r'\]\s+[0-9a-f]+\s+\S+\s+([IAWEOFRD])\s')
WAS_LEVEL_MAP = {
    'I': 'INFO', 'A': 'AUDIT', 'W': 'WARNING', 'E': 'ERROR',
    'O': 'STDOUT', 'F': 'FATAL', 'R': 'REPORT', 'D': 'DEBUG',
}

# Thread ID: hex digits between ] and component name
WAS_THREAD_RE = re.compile(r'\]\s+([0-9a-f]{8})\s+')

# WebSphere / Liberty message codes (general pattern: 4-5 uppercase letters + 4 digits + severity letter)
WAS_CODE_RE = re.compile(r'\b([A-Z]{4,5}\d{4}[A-Z])\b')

# Java exceptions / errors
EXC_HEAD_RE = re.compile(r'\b([a-zA-Z_$]+(?:\.[a-zA-Z_$]+)+(?:Exception|Error))\b')
STACK_LINE_RE = re.compile(r'^\s+at\s+[\w.$]+\(.*\)$')
CAUSED_BY_RE = re.compile(r'^\s*Caused by:\s+(?P<cause>.+)$')

OOM_RE = re.compile(r'OutOfMemoryError|Java heap space|GC overhead limit exceeded', re.IGNORECASE)
HUNG_THREAD_RE = re.compile(r'hung thread|ThreadMonitor|WSVR0605|stuck thread|CWWKE0701E', re.IGNORECASE)

# Hung thread drilldown: extract thread name from WAS ThreadMonitor messages
HUNG_THREAD_NAME_RE = re.compile(
    r'(?:[Tt]hread\s+["\']([^"\']+)["\'])'          # Thread "ThreadName" or thread 'ThreadName'
    r'|(?:[Tt]hread\s+(WebContainer\s*:\s*\d+))'    # thread WebContainer : 5
    r'|(?:the\s+(Default Executor-thread-\d+))'     # Liberty: submitted to the Default Executor-thread-42
    r'|(?:[Tt]hread\s+(Default Executor-thread-\d+))',  # Liberty alt: thread Default Executor-thread-42
    re.IGNORECASE,
)
DB_POOL_RE = re.compile(r'connection pool|J2CA|pool.*exhaust|Timeout waiting for idle object', re.IGNORECASE)
SSL_RE = re.compile(r'SSLHandshakeException|handshake_failure|PKIX path building failed|unable to find valid certification path', re.IGNORECASE)
HTTP_RE = re.compile(r'\b(4\d\d|5\d\d)\b.*\b(HTTP|SRVE)\b|\b(HTTP|SRVE)\b.*\b(4\d\d|5\d\d)\b', re.IGNORECASE)

# Secret redaction patterns
SECRET_REPLACERS = [
    (re.compile(r'(?i)\b(authorization:\s*bearer)\s+[A-Za-z0-9._\-/+=]+'), r'\1 [REDACTED]'),
    (re.compile(r'(?i)\b(api[_-]?key|token|secret|password|passwd|credential)\b\s*[:=]\s*([^\n,;]+)'), r'\1=[REDACTED]'),
    (re.compile(r'(?i)("(?:api[_-]?key|token|secret|password|passwd|credential)")\s*:\s*"[^"]*"'), r'\1: "[REDACTED]"'),
    (re.compile(r'(?i)(password|pwd)\s*=\s*[^;,\s]+'), r'\1=[REDACTED]'),
    (re.compile(r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), '[REDACTED_JWT]'),
    (re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), '***AWS_KEY***'),
    (re.compile(r'(?i)(authorization:\s*basic\s+)[A-Za-z0-9+/=]+'), r'\1***REDACTED***'),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----'), '***PEM_KEY_REDACTED***'),
    (re.compile(r'(?i)(sig=)[A-Za-z0-9%+/=]+'), r'\1***REDACTED***'),
    (re.compile(r'(?i)(authorization:\s*digest\s+)[^\n]+'), r'\1***REDACTED***'),
]

_REDACT_FAST_CHECK = re.compile(
    r'(?i)(bearer|api[_-]?key|token|secret|password|passwd|credential|pwd|eyJ|AKIA|basic\s+[A-Za-z0-9]|BEGIN.*PRIVATE|sig=|digest\s)',
)


def open_text(path: Path) -> IO[str]:
    """Open a log file for reading, handling .gz transparently."""
    if path.suffix.lower() == ".gz":
        try:
            f = gzip.open(path, "rt", errors="ignore")
            f.read(1)  # probe for valid gzip
            f.seek(0)
            return f
        except (OSError, EOFError):
            _log.warning("open_text: %s has .gz suffix but is not valid gzip, falling back to plain text", path.name)
            return path.open("r", errors="ignore")
    return path.open("r", errors="ignore")


def redact(s: str) -> str:
    """Remove secrets (bearer tokens, API keys, passwords, etc.) from text."""
    if not _REDACT_FAST_CHECK.search(s):
        return s
    for rx, repl in SECRET_REPLACERS:
        s = rx.sub(repl, s)
    return s


def extract_ts(line: str) -> str | None:
    """Extract a timestamp string from a log line."""
    for rx in TS_PATTERNS:
        m = rx.search(line)
        if m:
            return m.group("ts")
    return None


def bucket_tags(text: str) -> set[str]:
    """Extract signal tags (OOM, HungThreads, etc.) from event text."""
    tags: set[str] = set()
    if OOM_RE.search(text): tags.add("OOM/GC")
    if HUNG_THREAD_RE.search(text): tags.add("HungThreads")
    if DB_POOL_RE.search(text): tags.add("DB/Pool")
    if SSL_RE.search(text): tags.add("SSL/TLS")
    if HTTP_RE.search(text): tags.add("HTTP")
    return tags


def classify_event(text: str) -> dict[str, Any]:
    """Classify a block of log text and return a dict of metadata (no file/ts)."""
    # Level — prefer WAS single-letter (authoritative) over keyword match
    lvl = None
    wm = WAS_LEVEL_RE.search(text)
    if wm:
        lvl = WAS_LEVEL_MAP.get(wm.group(1), wm.group(1))
    else:
        m = LEVEL_RE.search(text)
        if m:
            lvl = m.group(1).upper()

    # Thread ID
    thread_id = None
    tm = WAS_THREAD_RE.search(text)
    if tm:
        thread_id = tm.group(1)

    # WAS message code
    code = None
    cm = WAS_CODE_RE.search(text)
    if cm:
        code = cm.group(1)

    # Exception (first match)
    exc = None
    em = EXC_HEAD_RE.search(text)
    if em:
        exc = em.group(1)

    # Root cause — deepest "Caused by:" exception
    root_cause = None
    for line in text.splitlines():
        cb = CAUSED_BY_RE.match(line)
        if cb:
            cause_text = cb.group("cause")
            ce = EXC_HEAD_RE.search(cause_text)
            if ce:
                root_cause = ce.group(1)

    tags = bucket_tags(text)

    return {
        "level": lvl,
        "thread_id": thread_id,
        "code": code,
        "exception": exc,
        "root_cause": root_cause,
        "tags": sorted(tags),
    }


def parse_file_iter(path: Path, max_lines: int | None = None):  # type: ignore[no-untyped-def]
    """Generator-based parser that yields event dicts one at a time.

    Uses the same logic as parse_file() (flush, classify_event, stacktrace
    handling) but yields instead of accumulating, so arbitrarily large files
    can be processed without holding all events in memory.
    """
    current: list[str] = []
    current_meta: dict[str, Any] = {"file": str(path), "first_ts": None}
    has_stacktrace = False
    seen_first_ts = False

    def _build_event() -> dict[str, Any]:
        text = "\n".join(current)
        text = redact(text)
        meta = classify_event(text)
        meta["file"] = current_meta["file"]
        meta["ts"] = current_meta["first_ts"]
        meta["text"] = text
        return meta

    with open_text(path) as f:
        for i, line in enumerate(f, start=1):
            if max_lines is not None and i > max_lines:
                break
            line = line.rstrip("\n")
            ts = extract_ts(line)

            if ts and current and not STACK_LINE_RE.match(line) and not CAUSED_BY_RE.match(line):
                if seen_first_ts:
                    yield _build_event()
                current = []
                current_meta = {"file": str(path), "first_ts": None}
                has_stacktrace = False

            if ts and current_meta["first_ts"] is None:
                current_meta["first_ts"] = ts
            if ts and not seen_first_ts:
                seen_first_ts = True

            if not line.strip() and current and has_stacktrace:
                if seen_first_ts:
                    yield _build_event()
                current = []
                current_meta = {"file": str(path), "first_ts": None}
                has_stacktrace = False
                continue

            current.append(line)

            if STACK_LINE_RE.match(line) or CAUSED_BY_RE.match(line):
                has_stacktrace = True

    if current and seen_first_ts:
        yield _build_event()


def parse_file(path: Path, max_lines: int | None = None) -> list[dict[str, Any]]:
    """Parse a log file and return a list of event dicts.

    Delegates to parse_file_iter() internally.
    """
    return list(parse_file_iter(path, max_lines=max_lines))
