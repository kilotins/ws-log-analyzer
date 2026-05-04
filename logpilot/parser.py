"""Parsing, classification, and redaction of WebSphere/Java log files."""
from __future__ import annotations

import gzip
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import IO, Any, Generator

from .event import LogEvent

_log = logging.getLogger(__name__)

# --- Constants ---
MAX_EVENT_TEXT = 4000  # Max characters of event text in reports

# --- Common patterns (WebSphere / Java-ish) ---
TS_PATTERNS = [
    # WebSphere classic: [10/12/15 21:22:04:257 CEST]
    re.compile(r'\[(?P<ts>\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}:\d{2}:\d{3})\s+\w+\]'),
    # ISO / WebSphere common: 2025-03-05 12:34:56:789 or 2025-03-05T12:34:56.789
    re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,:.]\d{3,6})?)'),
]

LEVEL_RE = re.compile(r'\b(SEVERE|ERROR|WARN|WARNING|INFO|DEBUG|FINE|FINER|FINEST|TRACE|FATAL|CRITICAL)\b', re.IGNORECASE)

# WebSphere uses single-letter severity after thread ID: [ts] threadid Component X
# I=Info, A=Audit, W=Warning, E=Error, O=SystemOut/SystemErr, F=Fatal, R=Report, D=Detail
WAS_LEVEL_RE = re.compile(r'\]\s+[0-9a-f]+\s+\S+\s+([IAWEOFRDN])\s')
WAS_LEVEL_MAP = {
    'I': 'INFO', 'A': 'AUDIT', 'W': 'WARNING', 'E': 'ERROR',
    'O': 'STDOUT', 'F': 'FATAL', 'R': 'REPORT', 'D': 'DEBUG',
    'N': 'NOTICE',
}

# Thread ID: hex digits between ] and component name
WAS_THREAD_RE = re.compile(r'\]\s+([0-9a-f]{8})\s+')

# WebSphere / Liberty message codes (general pattern: 4-5 uppercase letters + 4 digits + severity letter)
WAS_CODE_RE = re.compile(r'\b([A-Z]{4,5}\d{4}[A-Z])\b')

# Java exceptions / errors — canonical definitions in formats.base
from .formats.base import EXC_HEAD_RE, STACK_LINE_RE, CAUSED_BY_RE, OOM_RE
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
HTTP_RE = re.compile(r'(?<![:/.])(?<!\d)\b(4\d\d|5\d\d)\b.*\b(HTTP|SRVE)\b|\b(HTTP|SRVE)\b.*(?<![:/.])(?<!\d)\b(4\d\d|5\d\d)\b', re.IGNORECASE)

# Trace/correlation ID patterns
TRACE_ID_PATTERNS = [
    # UUID format: 8-4-4-4-12 hex
    re.compile(r'(?:correlation[_-]?id|request[_-]?id|trace[_-]?id|x-request-id|x-correlation-id)["\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.IGNORECASE),
    # OpenTelemetry 32-char hex trace ID
    re.compile(r'(?:trace[_-]?id)["\s:=]+([0-9a-f]{32})', re.IGNORECASE),
    # Generic UUID in text (less specific, used as fallback)
    re.compile(r'\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b', re.IGNORECASE),
]


def extract_trace_ids(text: str) -> list[str]:
    """Extract trace/correlation IDs from event text. Returns deduplicated list."""
    ids: list[str] = []
    seen: set[str] = set()
    for rx in TRACE_ID_PATTERNS:
        for m in rx.finditer(text):
            tid = m.group(1).lower()
            if tid not in seen:
                seen.add(tid)
                ids.append(tid)
    return ids


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

# --- PII redaction patterns (M59: GDPR compliance) ---

# Norwegian personnummer: 11 digits (DDMMYY + 5 individual digits)
# Day 01-31, month 01-12, then 2-digit year + 5 individual digits
_PERSONNR_RE = re.compile(r'\b((?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2})\d{5}\b')

# Norwegian organisasjonsnummer: 9 digits starting with 8 or 9
_ORGNR_RE = re.compile(r'\b([89]\d{2})\d{6}\b')

# Email addresses
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# IPv4 — keep subnet, mask host
_IPV4_PRIVATE_RE = re.compile(
    r'\b(10\.\d{1,3}\.\d{1,3})\.\d{1,3}\b'
    r'|\b(172\.(?:1[6-9]|2\d|3[01])\.\d{1,3})\.\d{1,3}\b'
    r'|\b(192\.168\.\d{1,3})\.\d{1,3}\b'
)
_IPV4_PUBLIC_RE = re.compile(
    r'\b(?!10\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!192\.168\.)(?!127\.)'
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
)

# IPv6 — require at least 3 colon-separated hex groups OR :: with hex groups
# Avoids matching timestamps like 10:30:00 by requiring hex chars (a-f) somewhere
_IPV6_RE = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b'
    r'|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b'
)

# Credit card — common prefixes: Visa (4), MC (51-55/2221-2720), Amex (34/37), Discover (6011/65)
_CREDIT_CARD_RE = re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))\d{8,15}\b')

# IBAN — 2-letter country + 2 check digits + 11-30 BBAN digits (min 15 chars total)
_IBAN_RE = re.compile(r'\b[A-Z]{2}\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{3,22}\b')

# Phone numbers (Norwegian: +47/0047 + 8 digits)
_PHONE_NO_RE = re.compile(r'(?:\+47|0047)\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\b')

# Usernames in paths or log fields
_USERNAME_PATH_RE = re.compile(r'(/home/|/Users/|user[=: ]+)([A-Za-z][A-Za-z0-9._-]{2,20})')


def _redact_ipv4_private(m: re.Match) -> str:
    """Keep subnet, mask host for private IPs."""
    subnet = m.group(1) or m.group(2) or m.group(3)
    return f"{subnet}.[x]"


PII_REPLACERS = [
    (_PERSONNR_RE, r'\1*****'),
    (_ORGNR_RE, r'\1******'),
    (_EMAIL_RE, '[EMAIL]'),
    (_PHONE_NO_RE, '[PHONE]'),
    (_CREDIT_CARD_RE, '[CARD]'),
    (_IBAN_RE, '[IBAN]'),
    (_IPV6_RE, '[IPv6]'),
]

INFRA_REPLACERS = [
    (_IPV4_PUBLIC_RE, '[EXT_IP]'),
    (_USERNAME_PATH_RE, r'\1[USER]'),
]

_PII_FAST_CHECK = re.compile(
    r'\d{11}|\b[89]\d{8}\b|@.*\.\w{2,}|\+47|0047|\b[3-6]\d{12}'
    r'|\b[A-Z]{2}\d{2}\d{4}|(?:[0-9a-fA-F]{1,4}:){3}',
)

# --- Redaction levels ---
REDACTION_LEVELS = {
    "none": [],
    "secrets": SECRET_REPLACERS,
    "standard": SECRET_REPLACERS + PII_REPLACERS,
    "strict": SECRET_REPLACERS + PII_REPLACERS + INFRA_REPLACERS,
}

# Timezone extraction patterns
TZ_OFFSET_RE = re.compile(r'([+-]\d{2}:?\d{2})\s*$|[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?([+-]\d{2}:?\d{2}|Z)\b')
TZ_ABBREV_RE = re.compile(r'\b(UTC|GMT|[A-Z]{2,4}T|CEST|CET|BST|IST|JST|KST|AEST)\b')


def open_text(path: Path) -> IO[str]:
    """Open a log file for reading, handling .gz transparently."""
    if path.suffix.lower() == ".gz":
        f = None
        try:
            f = gzip.open(path, "rt", errors="ignore")
            f.read(1)  # probe for valid gzip
            f.seek(0)
            return f
        except (OSError, EOFError):
            if f is not None:
                f.close()
            _log.warning("open_text: %s has .gz suffix but is not valid gzip, falling back to plain text", path.name)
            return path.open("r", errors="ignore")
    return path.open("r", errors="ignore")


def redact(s: str, level: str = "secrets") -> str:
    """Remove sensitive data from text at the specified redaction level.

    Levels:
        none: No redaction
        secrets: Bearer tokens, API keys, passwords, JWTs (default — backward compatible)
        standard: Secrets + PII (personnummer, email, phone, cards, IBAN, IPv6)
        strict: Standard + infrastructure (public IPs, usernames in paths)
    """
    if level == "none":
        return s

    # Fast-check for secrets
    if _REDACT_FAST_CHECK.search(s):
        for rx, repl in SECRET_REPLACERS:
            s = rx.sub(repl, s)

    if level == "secrets":
        return s

    # PII redaction (standard + strict)
    if _PII_FAST_CHECK.search(s):
        for rx, repl in PII_REPLACERS:
            s = rx.sub(repl, s)

    # Private IP subnet masking (standard + strict)
    s = _IPV4_PRIVATE_RE.sub(_redact_ipv4_private, s)

    if level == "strict":
        for rx, repl in INFRA_REPLACERS:
            s = rx.sub(repl, s)

    return s


def extract_ts(line: str) -> str | None:
    """Extract a timestamp string from a log line."""
    for rx in TS_PATTERNS:
        m = rx.search(line)
        if m:
            return m.group("ts")
    return None


def extract_tz(line: str) -> str | None:
    """Extract timezone indicator from a log line."""
    m = TZ_OFFSET_RE.search(line)
    if m:
        return m.group(1) or m.group(2)
    m = TZ_ABBREV_RE.search(line)
    if m:
        return m.group(1)
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
        lvl = sys.intern(lvl)
    else:
        m = LEVEL_RE.search(text)
        if m:
            lvl = m.group(1).upper()
            lvl = sys.intern(lvl)

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
        code = sys.intern(code)

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


def _should_emit(ev: LogEvent, sample_info: int, counter: int) -> bool:
    """Check if an event should be emitted (respecting INFO sampling)."""
    if sample_info <= 0:
        return True
    if ev.level != "INFO" or ev.exception or ev.tags or ev.code:
        return True
    return counter % sample_info == 0


def parse_file_iter(path: Path, max_lines: int | None = None, format_name: str | None = None, sample_info: int = 0, redaction_level: str | None = None) -> Generator[LogEvent, None, None]:
    """Generator-based parser that yields event dicts one at a time.

    Args:
        path: Path to the log file.
        max_lines: Limit lines read (speed/safety).
        format_name: Explicit format name (e.g. "was", "json"). If None, auto-detects.
        sample_info: When > 0, keep only every Nth plain INFO event (no exception/tags/code).
            Deterministic: based on line counter modulo. 0 means no sampling (default).
        redaction_level: Redaction level ("none", "secrets", "standard", "strict").
            When None (default), falls back to LOGPILOT_REDACTION_LEVEL env var, then "secrets".
            Pass explicitly to avoid per-event env reads and to support per-request policies.

    Uses format plugins for timestamp extraction, level detection, and
    continuation line detection. Falls back to WAS format if no format
    scores above threshold.
    """
    if max_lines is not None and max_lines < 0:
        raise ValueError(f"max_lines must be non-negative, got {max_lines}")

    # Resolve redaction level once at function entry — NOT inside the hot loop.
    # This avoids repeated os.environ reads and allows per-request policies (FastAPI 2.0).
    if redaction_level is None:
        redaction_level = os.environ.get("LOGPILOT_REDACTION_LEVEL", "secrets")

    from .formats import detect_format, get_format

    # Resolve format
    if format_name:
        fmt = get_format(format_name)
    else:
        fmt = detect_format(path)

    MAX_EVENT_LINES = 500  # Safety valve: force new event boundary if exceeded

    current: list[str] = []
    current_meta: dict[str, Any] = {"file": str(path), "first_ts": None, "format": fmt.name, "tz_hint": None}
    has_stacktrace = False
    seen_first_ts = False
    _event_counter = 0  # counts every emitted event for deterministic INFO sampling

    def _build_event() -> LogEvent:
        text = "\n".join(current)
        text = redact(text, level=redaction_level)
        meta = fmt.classify_event(text)
        return LogEvent(
            text=text,
            ts=current_meta["first_ts"],
            level=meta.get("level"),
            thread_id=meta.get("thread_id"),
            code=meta.get("code"),
            exception=meta.get("exception"),
            root_cause=meta.get("root_cause"),
            tags=meta.get("tags") or [],
            file=current_meta["file"],
            format=sys.intern(current_meta["format"]),
            tz_hint=current_meta.get("tz_hint"),
            trace_ids=extract_trace_ids(text),
        )

    with open_text(path) as f:
        for i, line in enumerate(f, start=1):
            if max_lines is not None and i > max_lines:
                break
            line = line.rstrip("\n")
            ts = fmt.extract_ts(line)

            if ts and current and not fmt.is_continuation(line):
                if seen_first_ts:
                    _ev = _build_event()
                    _event_counter += 1
                    if _should_emit(_ev, sample_info, _event_counter):
                        yield _ev
                current = []
                current_meta = {"file": str(path), "first_ts": None, "format": fmt.name, "tz_hint": None}
                has_stacktrace = False

            if ts and current_meta["first_ts"] is None:
                current_meta["first_ts"] = ts
                if current_meta["tz_hint"] is None:
                    current_meta["tz_hint"] = extract_tz(line)
            if ts and not seen_first_ts:
                seen_first_ts = True

            if not line.strip() and current and has_stacktrace:
                if seen_first_ts:
                    _ev = _build_event()
                    _event_counter += 1
                    if _should_emit(_ev, sample_info, _event_counter):
                        yield _ev
                current = []
                current_meta = {"file": str(path), "first_ts": None, "format": fmt.name, "tz_hint": None}
                has_stacktrace = False
                continue

            # Safety valve: force a new event boundary if current event is too large.
            # Protects against format misdetection collapsing entire files into one event.
            if len(current) >= MAX_EVENT_LINES and seen_first_ts:
                _ev = _build_event()
                _event_counter += 1
                if _should_emit(_ev, sample_info, _event_counter):
                    yield _ev
                current = []
                current_meta = {"file": str(path), "first_ts": None, "format": fmt.name, "tz_hint": None}
                has_stacktrace = False

            current.append(line)

            if STACK_LINE_RE.match(line) or CAUSED_BY_RE.match(line):
                has_stacktrace = True

    if current and seen_first_ts:
        _ev = _build_event()
        _event_counter += 1
        if _should_emit(_ev, sample_info, _event_counter):
            yield _ev


def parse_file(path: Path, max_lines: int | None = None, format_name: str | None = None, sample_info: int = 0, redaction_level: str | None = None) -> list[LogEvent]:
    """Parse a log file and return a list of event dicts.

    Args:
        path: Path to the log file.
        max_lines: Limit lines read (speed/safety).
        format_name: Explicit format name (e.g. "was", "json"). If None, auto-detects.
        sample_info: When > 0, keep only every Nth plain INFO event (no exception/tags/code).
            Deterministic: based on event counter modulo. 0 means no sampling (default).
        redaction_level: Redaction level ("none", "secrets", "standard", "strict").
            When None (default), falls back to LOGPILOT_REDACTION_LEVEL env var, then "secrets".
    """
    return list(parse_file_iter(path, max_lines=max_lines, format_name=format_name, sample_info=sample_info, redaction_level=redaction_level))


# ---------------------------------------------------------------------------
# File-level parse cache
# ---------------------------------------------------------------------------

def _event_to_cache_dict(e: LogEvent) -> dict:
    """Minimal dict for cache storage."""
    d: dict = {}
    if e.text: d["t"] = e.text
    if e.ts: d["ts"] = e.ts
    if e.level: d["l"] = e.level
    if e.thread_id: d["th"] = e.thread_id
    if e.code: d["c"] = e.code
    if e.exception: d["ex"] = e.exception
    if e.root_cause: d["rc"] = e.root_cause
    if e.tags: d["tg"] = e.tags
    if e.file: d["f"] = e.file
    if e.line_num: d["ln"] = e.line_num
    if e.format: d["fmt"] = e.format
    if e.tz_hint: d["tz"] = e.tz_hint
    if e.trace_ids: d["tr"] = e.trace_ids
    if e.source: d["src"] = e.source
    return d


def _cache_dict_to_event(d: dict) -> LogEvent:
    """Reconstruct LogEvent from cache dict."""
    return LogEvent(
        text=d.get("t", ""),
        ts=d.get("ts"),
        level=d.get("l"),
        thread_id=d.get("th"),
        code=d.get("c"),
        exception=d.get("ex"),
        root_cause=d.get("rc"),
        tags=d.get("tg", []),
        file=d.get("f", ""),
        line_num=d.get("ln", 0),
        format=d.get("fmt"),
        tz_hint=d.get("tz"),
        trace_ids=d.get("tr", []),
        source=d.get("src"),
    )


def parse_file_cached(path: Path, content_hash: str, cache_dir: Path | None = None,
                      max_lines: int = 0, format_name: str | None = None,
                      sample_info: int = 0,
                      redaction_level: str | None = None) -> list[LogEvent]:
    """Parse with file-level caching. Falls back to parse_file on cache miss.

    ``redaction_level`` is included in the cache key so that runs with different
    redaction settings never share cached event text.  When *None* (the default)
    the value is read from the ``LOGPILOT_REDACTION_LEVEL`` environment variable
    (defaulting to ``"secrets"``), preserving existing behaviour for all callers
    that do not pass the parameter explicitly.
    """
    if redaction_level is None:
        redaction_level = os.environ.get("LOGPILOT_REDACTION_LEVEL", "secrets")
    cache_path = None
    if cache_dir:
        cache_key = f"parsed_{content_hash}_{format_name or 'auto'}_{max_lines}_{sample_info}_{redaction_level}"
        cache_path = cache_dir / f"{cache_key}.json.gz"
        if cache_path.exists():
            try:
                with gzip.open(cache_path, "rt", encoding="utf-8") as f:
                    data = json.loads(f.read())
                _log.info("Cache hit for %s (%d events)", path.name, len(data))
                events = [_cache_dict_to_event(d) for d in data]
                for event in events:
                    event.file = str(path)
                return events
            except (OSError, json.JSONDecodeError, KeyError, TypeError):
                _log.warning("Cache read failed for %s, re-parsing", path.name)

    events = parse_file(path, max_lines=max_lines or None, format_name=format_name, sample_info=sample_info, redaction_level=redaction_level)

    if cache_path:
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            data = [_event_to_cache_dict(e) for e in events]
            with gzip.open(cache_path, "wt", encoding="utf-8") as f:
                f.write(json.dumps(data, separators=(",", ":")))
            _log.info("Cached %d events for %s", len(events), path.name)
            # Evict oldest cache files if more than 50
            _evict_parse_cache(cache_dir, max_files=50)
        except Exception as ex:
            _log.warning("Cache write failed: %s", ex)

    return events


def _evict_parse_cache(cache_dir: Path, max_files: int = 50) -> None:
    """Remove oldest parse cache files if count exceeds max_files."""
    try:
        cache_files = sorted(cache_dir.glob("parsed_*.json.gz"),
                             key=lambda f: f.stat().st_mtime)
        if len(cache_files) > max_files:
            for old in cache_files[:len(cache_files) - max_files]:
                old.unlink(missing_ok=True)
                _log.debug("Evicted parse cache: %s", old.name)
    except OSError:
        pass
