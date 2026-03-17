"""Analysis functions: summarize, timeline, heuristics, splunk, hung threads."""
from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .parser import (
    CAUSED_BY_RE, HUNG_THREAD_NAME_RE, HUNG_THREAD_RE, STACK_LINE_RE,
    WAS_CODE_RE,
)

_log = logging.getLogger(__name__)

ERROR_LEVELS = ("ERROR", "SEVERE", "FATAL")


def parse_ts_datetime(ts: str | None) -> datetime | None:
    """Parse a timestamp string into a datetime object. Returns None on failure."""
    if not ts:
        return None
    try:
        for fmt in ("%m/%d/%y %H:%M:%S:%f", "%m/%d/%Y %H:%M:%S:%f"):
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        normalized = ts.replace("T", " ").replace(",", ".")
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue
    except (ValueError, TypeError, AttributeError):
        pass
    _log.debug("parse_ts_datetime: could not parse timestamp %r", ts)
    return None


# Mapping of common timezone abbreviations to UTC offset in hours
_TZ_ABBREV_OFFSETS: dict[str, float] = {
    "UTC": 0, "GMT": 0, "Z": 0,
    "BST": +1, "CET": +1,
    "CEST": +2,
    "EST": -5, "EDT": -4,
    "CST": -6, "CDT": -5,
    "MST": -7, "MDT": -6,
    "PST": -8, "PDT": -7,
    "IST": +5.5,
    "JST": +9, "KST": +9,
    "AEST": +10,
}

# Regex to detect ISO offset embedded in a timestamp string
_TS_EMBED_OFFSET_RE = re.compile(
    r'(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+-]\d{2}:?\d{2}|Z)\s*$'
)
_TS_EMBED_Z_RE = re.compile(r'Z\s*$')


def normalize_ts_utc(ts: str | None, tz_hint: str | None = None) -> datetime | None:
    """Parse timestamp and normalize to UTC. Returns None on failure.

    Args:
        ts: Raw timestamp string from log event
        tz_hint: Timezone hint (e.g. "CEST", "+02:00", "Europe/Stockholm").
                 If None, assumes UTC.
    """
    if not ts:
        return None

    # Strip trailing timezone indicators before calling parse_ts_datetime
    # so we can parse the bare datetime, then reattach the tz.
    ts_bare = ts.strip()
    embedded_offset: str | None = None

    # Check for embedded offset in the timestamp string itself
    m = _TS_EMBED_OFFSET_RE.search(ts_bare)
    if m:
        embedded_offset = m.group(1)
        ts_bare = ts_bare[:m.start(1)].strip()
    elif _TS_EMBED_Z_RE.search(ts_bare):
        embedded_offset = "Z"
        ts_bare = ts_bare[:-1].strip()

    dt = parse_ts_datetime(ts_bare) or parse_ts_datetime(ts)
    if dt is None:
        return None

    # Determine the tzinfo to attach
    tz_source = tz_hint or embedded_offset
    tz_info: datetime.tzinfo | None = None

    if tz_source:
        tz_src = tz_source.strip()

        if tz_src in ("Z", "UTC", "GMT"):
            tz_info = timezone.utc

        elif tz_src in _TZ_ABBREV_OFFSETS:
            offset_hours = _TZ_ABBREV_OFFSETS[tz_src]
            tz_info = timezone(timedelta(hours=offset_hours))

        elif re.match(r'^[+-]\d{2}:?\d{2}$', tz_src):
            # ISO offset: +02:00 or +0200
            sign = 1 if tz_src[0] == '+' else -1
            tz_clean = tz_src[1:].replace(":", "")
            hours = int(tz_clean[:2])
            minutes = int(tz_clean[2:])
            tz_info = timezone(sign * timedelta(hours=hours, minutes=minutes))

        else:
            # Try IANA name via zoneinfo (Python 3.9+)
            try:
                from zoneinfo import ZoneInfo
                tz_info = ZoneInfo(tz_src)
            except Exception:
                _log.debug("normalize_ts_utc: unrecognized tz_hint %r, assuming UTC", tz_src)
                tz_info = timezone.utc

    if tz_info is None:
        tz_info = timezone.utc

    # Attach timezone to naive datetime, then convert to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz_info)
    return dt.astimezone(timezone.utc)


def sort_events_chronologically(events: list[dict], tz_hint: str | None = None) -> None:
    """Sort events in-place by UTC-normalized timestamp. Events without timestamps go last."""
    for e in events:
        if "ts_utc" not in e:
            dt = normalize_ts_utc(e.get("ts"), tz_hint=e.get("tz_hint", tz_hint))
            e["ts_utc"] = dt.isoformat() if dt else None

    events.sort(key=lambda e: (e.get("ts_utc") is None, e.get("ts_utc") or ""))


def summarize(events: list[dict], top_n: int) -> dict[str, Any]:
    """Count top codes, exceptions, levels, tags; return summary dict."""
    by_level = Counter(e["level"] or "UNKNOWN" for e in events)
    by_code = Counter(e["code"] for e in events if e["code"])
    by_exc = Counter(e["exception"] for e in events if e["exception"])
    by_tag = Counter(tag for e in events for tag in e["tags"])

    def top(counter: Counter) -> list[tuple[str, int]]:
        return counter.most_common(top_n)

    return {
        "total_events": len(events),
        "levels": top(by_level),
        "codes": top(by_code),
        "exceptions": top(by_exc),
        "tags": top(by_tag),
    }


def incident_timeline(events: list[dict], window_seconds: int = 30) -> dict[str, Any] | None:
    """Build an incident timeline around the first error.

    Returns dict with:
      - trigger_event: the first error event
      - trigger_dt: datetime of the trigger
      - window_events: list of {event, dt, offset_seconds} within +/- window
      - window_seconds: the window used
    Returns None if no error events with timestamps exist.
    """
    ts_cache: dict[str, Any] = {}
    for e in events:
        ts = e.get("ts")
        if ts and ts not in ts_cache:
            ts_cache[ts] = parse_ts_datetime(ts)

    trigger = None
    trigger_dt = None
    for e in events:
        if e.get("level") in ERROR_LEVELS:
            dt = ts_cache.get(e.get("ts", ""))
            if dt:
                trigger = e
                trigger_dt = dt
                break

    if not trigger:
        return None

    window_events = []
    for e in events:
        dt = ts_cache.get(e.get("ts", ""))
        if not dt:
            continue
        offset = (dt - trigger_dt).total_seconds()
        if -window_seconds <= offset <= window_seconds:
            window_events.append({
                "event": e,
                "dt": dt,
                "offset_seconds": offset,
            })

    window_events.sort(key=lambda w: w["dt"])

    return {
        "trigger_event": trigger,
        "trigger_dt": trigger_dt,
        "window_events": window_events,
        "window_seconds": window_seconds,
    }


def _parse_ts_parts(ts: str) -> tuple[str | None, int, int] | None:
    """Extract (date_str, hour, minute) from a timestamp string. Returns None on failure."""
    dt = parse_ts_datetime(ts)
    if dt:
        return (dt.strftime("%Y-%m-%d"), dt.hour, dt.minute)
    # Fallback for formats parse_ts_datetime doesn't cover
    try:
        parts = ts.split()
        if len(parts) > 1:
            date_part = parts[0]
            time_part = parts[-1]
        else:
            time_part = parts[0]
            date_part = None
            if "T" in time_part:
                iso_parts = time_part.split("T", 1)
                date_part = iso_parts[0]
                time_part = iso_parts[1] if len(iso_parts) > 1 else time_part
        hms = re.split(r'[:.]', time_part)
        if len(hms) < 2:
            return None
        h, m = int(hms[0]), int(hms[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            return None
        return (date_part, h, m)
    except (ValueError, IndexError):
        return None


def time_histogram(events: list[dict], bucket_minutes: int = 1) -> list[tuple[str, int, int]]:
    """Group events by time bucket and return list of (bucket_label, total, error_count)."""
    buckets: dict[str, dict[str, int]] = {}
    dates_seen: set[str] = set()
    for e in events:
        ts = e.get("ts")
        if not ts:
            continue
        parsed = _parse_ts_parts(ts)
        if not parsed:
            continue
        date_part, h, m = parsed
        date_key = date_part or "_"
        dates_seen.add(date_key)
        total_minutes = h * 60 + m
        floored = (total_minutes // bucket_minutes) * bucket_minutes
        bh, bm = divmod(floored, 60)
        key = f"{date_key} {bh:02d}:{bm:02d}"
        if key not in buckets:
            buckets[key] = {"total": 0, "errors": 0}
        buckets[key]["total"] += 1
        if e.get("level") in ERROR_LEVELS:
            buckets[key]["errors"] += 1

    if not buckets:
        return []

    real_dates = dates_seen - {"_"}
    if real_dates and "_" in dates_seen:
        buckets = {k: v for k, v in buckets.items() if not k.startswith("_ ")}

    if len(dates_seen - {"_"}) <= 1:
        buckets = {k.split(" ", 1)[1]: v for k, v in buckets.items()}

    return [(k, buckets[k]["total"], buckets[k]["errors"]) for k in sorted(buckets)]


def render_histogram(hist: list[tuple[str, int, int]], bar_width: int = 40) -> list[str]:
    """Render ASCII bar chart lines from histogram data."""
    if not hist:
        return ["- _(no timestamped events)_"]
    max_total = max(t for _, t, _ in hist)
    lines = []
    for label, total, errors in hist:
        bar_len = int((total / max_total) * bar_width) if max_total else 0
        bar = "#" * bar_len
        err_suffix = f"  ({errors} err)" if errors else ""
        lines.append(f"  {label} | {bar} {total}{err_suffix}")
    return lines


def pick_samples(events: list[dict], n: int) -> list[dict]:
    """Select diverse sample events (by code/exception/tag)."""
    seen: set[tuple] = set()
    unique = []
    for e in events:
        key = (e["level"], e["code"], e["exception"])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    def score(e: dict) -> int:
        s = 0
        if e["level"] in ("FATAL",): s += 4
        if e["level"] in ("ERROR", "SEVERE"): s += 3
        if e["level"] in ("WARNING", "WARN"): s += 1
        if e["exception"]: s += 2
        if e["code"]: s += 1
        if e["tags"]: s += 1
        return -s
    return sorted(unique, key=score)[:n]


def per_file_summary(events: list[dict]) -> list[tuple[str, int, int]]:
    """Return list of (filename, total, error_count) for each source file."""
    files: dict[str, dict[str, int]] = {}
    for e in events:
        f = e["file"]
        if f not in files:
            files[f] = {"total": 0, "errors": 0}
        files[f]["total"] += 1
        if e.get("level") in ERROR_LEVELS:
            files[f]["errors"] += 1
    return [(f, files[f]["total"], files[f]["errors"]) for f in sorted(files)]


def _load_heuristics_from_yaml() -> list[dict] | None:
    """Try to load heuristics from YAML file. Returns None if unavailable."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return None
    yaml_path = Path(__file__).parent.parent / "heuristics.yaml"
    if not yaml_path.is_file():
        return None
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            entries = yaml.safe_load(f)
        if not isinstance(entries, list):
            return None
        heuristics = []
        for entry in entries:
            heuristics.append({
                "id": entry["id"],
                "title": entry["title"],
                "match": re.compile(entry["pattern"], re.IGNORECASE),
                "cause": entry["cause"],
                "fixes": entry["fixes"],
            })
        return heuristics
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError):
        return None


_HEURISTICS_INLINE = [
    {
        "id": "ssl-trust",
        "title": "SSL / TLS Trust Failure",
        "match": re.compile(
            r'CertPathBuilderException|SSLHandshakeException|PKIX path building failed'
            r'|CWPKI0022E|CWPKI0033E',
            re.IGNORECASE,
        ),
        "cause": "The JVM does not trust the remote certificate (self-signed, expired, or missing intermediate CA).",
        "fixes": [
            "Import the remote certificate into the WAS truststore (retrieveSigners / wsadmin).",
            "Check certificate expiry with: keytool -list -v -keystore trust.p12.",
            "If a recent cert renewal happened, the old CA chain may still be cached — restart the server.",
        ],
    },
    {
        "id": "db-pool",
        "title": "JDBC / Connection-Pool Exhaustion",
        "match": re.compile(
            r'J2CA0045E|J2CA0079E|pool.*exhaust|Timeout waiting for idle object'
            r'|ConnectionWaitTimeout|connection pool',
            re.IGNORECASE,
        ),
        "cause": "All connections in the JDBC pool are in use; new requests block until timeout.",
        "fixes": [
            "Check for long-running queries or uncommitted transactions holding connections.",
            "Increase maxConnections / connectionTimeout in the data-source config if load is legitimate.",
            "Look for connection leaks: code paths that obtain a connection but skip close() on exception.",
        ],
    },
    {
        "id": "hung-threads",
        "title": "Hung / Stuck Threads",
        "match": re.compile(
            r'WSVR0605W|WSVR0606W|ThreadMonitor|hung.thread|stuck.thread'
            r'|CWWKE0701E|CWWKE0700W',
            re.IGNORECASE,
        ),
        "cause": "One or more threads have been active longer than the configured threshold (default 600 s).",
        "fixes": [
            "Capture a thread dump (kill -3 or wsadmin) to identify what the thread is waiting on.",
            "Common culprits: slow external service calls, database locks, infinite loops.",
            "If the threshold is too aggressive for batch workloads, increase com.ibm.websphere.threadmonitor.threshold.",
        ],
    },
    {
        "id": "oom-gc",
        "title": "OutOfMemoryError / GC Pressure",
        "match": re.compile(
            r'OutOfMemoryError|Java heap space|GC overhead limit exceeded'
            r'|allocation failure|Metaspace',
            re.IGNORECASE,
        ),
        "cause": "The JVM heap (or metaspace) is exhausted — objects cannot be allocated.",
        "fixes": [
            "Collect a heap dump (-XX:+HeapDumpOnOutOfMemoryError) and analyze with Eclipse MAT.",
            "Check for memory leaks: growing collections, unclosed streams, or class-loader leaks after redeploys.",
            "Increase -Xmx / -XX:MaxMetaspaceSize only after ruling out leaks.",
        ],
    },
    {
        "id": "session-error",
        "title": "HTTP Session Failure",
        "match": re.compile(
            r'SESN0066E|SESN0008E|SESN0306E|Session.*invalid'
            r'|NotSerializableException.*[Ss]ession',
            re.IGNORECASE,
        ),
        "cause": "HTTP sessions are being invalidated, failing to replicate, or contain non-serializable objects.",
        "fixes": [
            "Ensure all objects stored in the session implement java.io.Serializable.",
            "Check session timeout settings — short timeouts cause unexpected invalidation under load.",
            "For replication failures, verify the DRS transport is healthy across cluster members.",
        ],
    },
    {
        "id": "classloader",
        "title": "ClassLoader / Linking Error",
        "match": re.compile(
            r'ClassNotFoundException|NoClassDefFoundError|LinkageError'
            r'|ClassCastException.*proxy|CWWKL0007W',
            re.IGNORECASE,
        ),
        "cause": "A required class cannot be found or loaded — typically a missing JAR, classloader policy mismatch, or stale deploy.",
        "fixes": [
            "Verify the missing class is in the app's WEB-INF/lib or a shared library.",
            "Check classloader policy (PARENT_FIRST vs PARENT_LAST) — mixing can cause LinkageError.",
            "After redeploys, restart the server to clear stale classloader references.",
        ],
    },
    {
        "id": "datasource-down",
        "title": "DataSource / Database Unreachable",
        "match": re.compile(
            r'DSRA0010E|DSRA0080E|DSRA8040I|Cannot get a connection'
            r'|SocketTimeoutException.*jcc|Communication link failure',
            re.IGNORECASE,
        ),
        "cause": "The database is unreachable or rejecting connections — network issue, DB down, or credentials expired.",
        "fixes": [
            "Test connectivity to the DB host/port from the WAS server (telnet / nc).",
            "Check DB listener status and max_connections on the database side.",
            "Review recent password rotations — update the J2C authentication alias if credentials changed.",
        ],
    },
    {
        "id": "servlet-error",
        "title": "Servlet Runtime Error",
        "match": re.compile(
            r'SRVE0293E|SRVE0315E|SRVE0777E|StackOverflowError'
            r'|Connection reset.*SocketException',
            re.IGNORECASE,
        ),
        "cause": "A servlet threw an unhandled exception or the client disconnected mid-response.",
        "fixes": [
            "Check the root exception in the stack trace — NullPointerException and StackOverflowError are the most common.",
            "For StackOverflowError, look for recursive calls and increase -Xss if the recursion is intentional.",
            "Connection reset errors are usually harmless client disconnects — suppress with response.isCommitted() checks.",
        ],
    },
    {
        "id": "deploy-fail",
        "title": "Application Deployment Failure",
        "match": re.compile(
            r'CWWKZ0002E|CWWKZ0013E|CWWKZ0060E|ADMA0004E'
            r'|failed to start|Initialization failed',
            re.IGNORECASE,
        ),
        "cause": "An application failed to start or deploy — missing dependencies, config errors, or port conflicts.",
        "fixes": [
            "Check for NameNotFoundException — a required JNDI resource (DataSource, JMS queue) may not be configured.",
            "Review the full startup exception chain for the root cause.",
            "Verify the application's deployment descriptor (web.xml / server.xml) is valid.",
        ],
    },
    {
        "id": "transaction-timeout",
        "title": "Transaction Timeout or Rollback",
        "match": re.compile(
            r'WTRN0006W|WTRN0074W|WTRN0062E|StaleConnectionException'
            r'|totalTranLifetime|transaction.*timed?\s*out',
            re.IGNORECASE,
        ),
        "cause": "A transaction exceeded the configured timeout or a connection was invalidated mid-transaction.",
        "fixes": [
            "Review the transaction timeout setting (totalTranLifetimeTimeout in tWAS or transactionTimeout in Liberty).",
            "Identify the slow query or service call holding the transaction open — add query logging or APM.",
            "For legitimate batch operations, increase the timeout; otherwise fix the underlying bottleneck.",
        ],
    },
    {
        "id": "authz-denied",
        "title": "Authorization / Access Denied",
        "match": re.compile(
            r'CWWKS9104A|CWWKS1100A.*[Ll]ocked|[Aa]uthorization.*denied'
            r'|not\s+authorized|403.*[Ff]orbidden',
            re.IGNORECASE,
        ),
        "cause": "A user authenticated successfully but lacks the required role or permissions to access the resource.",
        "fixes": [
            "Verify role mappings in application-bnd.xml (tWAS) or server.xml (Liberty) match declared roles.",
            "Check if the user's LDAP/registry group membership has changed.",
            "Review security constraints in web.xml — ensure the required role name is correct.",
        ],
    },
    {
        "id": "jndi-lookup-fail",
        "title": "JNDI Lookup Failed",
        "match": re.compile(
            r'CWNEN1001E|NameNotFoundException|JNDI.*not found'
            r'|InitialContext.*failed',
            re.IGNORECASE,
        ),
        "cause": "A JNDI lookup for a resource (DataSource, JMS queue, EJB) failed — the resource is not configured or has a mismatched name.",
        "fixes": [
            "Verify the resource is declared in server.xml (Liberty) or the admin console (tWAS) with the exact JNDI name.",
            "Check that the application's web.xml resource-ref matches the configured resource name.",
            "For EJB lookups, confirm the JNDI name follows the correct format (ejb/ModuleName/BeanName).",
        ],
    },
    {
        "id": "port-bind-fail",
        "title": "TCP Port Binding Failure",
        "match": re.compile(
            r'TCPC0003E|CHFW0019I|[Pp]ort.*in use|[Bb]ind.*failed'
            r'|Address already in use',
            re.IGNORECASE,
        ),
        "cause": "The configured port is already bound by another process, preventing the server from starting.",
        "fixes": [
            "Identify the conflicting process: lsof -i :PORT (Unix) or netstat -ano | findstr :PORT (Windows).",
            "Update httpPort / httpsPort in server.xml if a port change is needed.",
            "Ensure the WAS user has permission to bind to ports below 1024 (requires root on Unix).",
        ],
    },
    {
        "id": "ldap-connection-fail",
        "title": "LDAP / User Registry Connection Failed",
        "match": re.compile(
            r'CWWKS3005E|LDAP.*connection.*failed|[Dd]irectory.*service.*unavailable'
            r'|bindDN.*failed',
            re.IGNORECASE,
        ),
        "cause": "Cannot connect to the LDAP/AD server for authentication or user lookup.",
        "fixes": [
            "Verify LDAP server is reachable (telnet to LDAP port, usually 389 or 636).",
            "Check LDAP configuration in server.xml — verify host, port, bindDN, and password.",
            "Review firewall rules between WAS and the LDAP server.",
        ],
    },
    {
        "id": "cert-expiry",
        "title": "SSL Certificate Expired or Expiring",
        "match": re.compile(
            r'CWPKI0033E|CWPKI0823E|[Cc]ertificate.*expired'
            r'|[Cc]ert.*expir',
            re.IGNORECASE,
        ),
        "cause": "An SSL certificate in the keystore or truststore has expired, blocking HTTPS connections.",
        "fixes": [
            "Renew the certificate and import it into the keystore (keytool -import).",
            "Verify the entire certificate chain is present (root + intermediates).",
            "Restart the server after renewal to clear cached certificate references.",
        ],
    },
    {
        "id": "config-error",
        "title": "Configuration File Error",
        "match": re.compile(
            r'CWWKG0028A|CWWKC0001E|[Cc]onfig.*error.*xml'
            r'|web\.xml.*invalid|server\.xml.*error',
            re.IGNORECASE,
        ),
        "cause": "A configuration file (server.xml, web.xml) has syntax errors or failed schema validation.",
        "fixes": [
            "Check XML syntax — common issues: unclosed tags, mismatched quotes, invalid characters.",
            "Validate the file against the schema using an IDE or XML validator.",
            "Review the server log for the exact line number causing the error.",
        ],
    },
    {
        "id": "context-root-conflict",
        "title": "Context Root Conflict / Duplicate Deployment",
        "match": re.compile(
            r'CWWKZ0014W|already.*exists.*context.root'
            r'|[Dd]uplicate.*application|context.root.*conflict',
            re.IGNORECASE,
        ),
        "cause": "Two applications are configured with the same context root, or an app was not fully undeployed before redeployment.",
        "fixes": [
            "Verify only one application uses each context root — list deployments via wsadmin or Liberty app manager.",
            "Ensure the old version is fully undeployed before redeploying.",
            "Check application.xml for correct context-root values.",
        ],
    },
    # ── nginx / Apache ─────────────────────────────────────────────────
    {
        "id": "nginx-502",
        "title": "Bad Gateway / Upstream Failure (nginx)",
        "match": re.compile(
            r'502 Bad Gateway|upstream timed out|upstream prematurely closed'
            r'|connect\(\) failed.*upstream|no live upstreams',
            re.IGNORECASE,
        ),
        "cause": "The backend server (upstream) is down, too slow, or rejecting connections.",
        "fixes": [
            "Check that the upstream service is running and listening on the configured port.",
            "Increase proxy_read_timeout / proxy_connect_timeout in nginx.conf if the backend is slow.",
            "Review upstream health checks — configure max_fails and fail_timeout.",
        ],
    },
    {
        "id": "nginx-rate-limit",
        "title": "Rate Limiting / 429 Too Many Requests",
        "match": re.compile(
            r'429 Too Many Requests|limiting requests.*zone|rate limit exceeded',
            re.IGNORECASE,
        ),
        "cause": "Clients are exceeding the configured request rate limit.",
        "fixes": [
            "Review limit_req_zone settings — increase burst or rate if traffic is legitimate.",
            "Check if a single IP is generating excessive traffic (potential bot/attack).",
            "Add limit_req_status 429 and a custom error page for user-friendly responses.",
        ],
    },
    {
        "id": "nginx-ssl-error",
        "title": "SSL/TLS Handshake Error (nginx)",
        "match": re.compile(
            r'SSL_do_handshake\(\) failed|SSL routines.*alert'
            r'|upstream SSL certificate verify error|no suitable key share',
            re.IGNORECASE,
        ),
        "cause": "TLS handshake with client or upstream failed — protocol mismatch, expired cert, or untrusted CA.",
        "fixes": [
            "Check certificate expiry: openssl x509 -enddate -noout -in /path/to/cert.pem.",
            "Verify ssl_protocols includes TLSv1.2 and TLSv1.3 — disable obsolete SSLv3/TLSv1.0.",
            "For upstream verify errors, add the CA chain to proxy_ssl_trusted_certificate.",
        ],
    },
    {
        "id": "nginx-permission",
        "title": "Permission Denied / Disk Full (nginx)",
        "match": re.compile(
            r'Permission denied|No space left on device|failed.*open\(\).*Permission'
            r'|writev\(\) failed.*No space',
            re.IGNORECASE,
        ),
        "cause": "nginx cannot read files or write to disk — permission issue or disk full.",
        "fixes": [
            "Check disk space: df -h. Clear old logs or cache files if full.",
            "Verify nginx worker user has read permission on web root and write permission on temp/cache dirs.",
            "Review SELinux/AppArmor policies if permissions look correct but access is denied.",
        ],
    },
    # ── Log4j / Spring Boot ──────────────────────────────────────────
    {
        "id": "spring-startup-fail",
        "title": "Spring Boot Application Startup Failure",
        "match": re.compile(
            r'APPLICATION FAILED TO START|Failed to start bean'
            r'|BeanCreationException|UnsatisfiedDependencyException'
            r'|ApplicationContextException',
            re.IGNORECASE,
        ),
        "cause": "Spring context failed to initialize — missing bean, circular dependency, or misconfiguration.",
        "fixes": [
            "Check the Caused-by chain for the root exception (often a missing @Component or @Bean).",
            "For circular dependencies, use @Lazy on one of the injection points or restructure the code.",
            "Review application.yml for typos in property names — Spring Boot fails silently on many misconfigs.",
        ],
    },
    {
        "id": "hikari-pool",
        "title": "HikariCP Connection Pool Exhaustion",
        "match": re.compile(
            r'HikariPool.*Connection is not available'
            r'|HikariPool.*connection timeout|HikariPool.*pool.*shutdown'
            r'|ActiveConnections.*exceeds',
            re.IGNORECASE,
        ),
        "cause": "All database connections in the HikariCP pool are in use — new requests are waiting or timing out.",
        "fixes": [
            "Check for long-running transactions or queries holding connections (enable slow query log).",
            "Increase spring.datasource.hikari.maximum-pool-size (default 10) if load is legitimate.",
            "Set spring.datasource.hikari.leak-detection-threshold to detect connection leaks.",
        ],
    },
    {
        "id": "kafka-error",
        "title": "Kafka Broker / Consumer Error",
        "match": re.compile(
            r'kafka.*Broker.*not available|kafka.*Rebalancing'
            r'|kafka.*CommitFailedException|kafka.*TimeoutException'
            r'|Failed to send.*ProducerRecord',
            re.IGNORECASE,
        ),
        "cause": "Kafka broker is unreachable, consumer group is rebalancing, or message production failed.",
        "fixes": [
            "Verify Kafka broker connectivity: kafka-broker-api-versions --bootstrap-server HOST:9092.",
            "For consumer rebalances, check max.poll.interval.ms and processing time — slow consumers trigger rebalance.",
            "Review producer retries and acks configuration for send failures.",
        ],
    },
    {
        "id": "hibernate-error",
        "title": "Hibernate / JPA Persistence Error",
        "match": re.compile(
            r'LazyInitializationException|StaleObjectStateException'
            r'|ConstraintViolationException|OptimisticLockException'
            r'|could not execute statement.*hibernate',
            re.IGNORECASE,
        ),
        "cause": "JPA/Hibernate failed to persist or load data — lazy loading outside session, stale data, or constraint violation.",
        "fixes": [
            "LazyInitializationException: use @Transactional or fetch eagerly (JOIN FETCH in JPQL).",
            "OptimisticLockException: implement retry logic or check for concurrent modifications.",
            "ConstraintViolationException: check unique constraints and foreign keys in the database schema.",
        ],
    },
    # ── Python / Django / Flask ──────────────────────────────────────
    {
        "id": "python-import",
        "title": "Python Import / Module Error",
        "match": re.compile(
            r'ImportError|ModuleNotFoundError|No module named',
            re.IGNORECASE,
        ),
        "cause": "A required Python module is not installed or not on the Python path.",
        "fixes": [
            "Install the missing module: pip install <module-name>.",
            "Check that the virtual environment is activated and the correct Python is in use.",
            "For relative imports, verify the package structure (__init__.py files) is correct.",
        ],
    },
    {
        "id": "django-db",
        "title": "Django Database / ORM Error",
        "match": re.compile(
            r'OperationalError.*database|IntegrityError|ProgrammingError.*relation'
            r'|django\.db.*Error|psycopg2\..*Error',
            re.IGNORECASE,
        ),
        "cause": "Django cannot reach the database, or a query/migration failed.",
        "fixes": [
            "Check DATABASE settings in settings.py — verify host, port, name, and credentials.",
            "Run pending migrations: python manage.py migrate.",
            "For IntegrityError, check unique constraints and missing NOT NULL values.",
        ],
    },
    {
        "id": "django-template",
        "title": "Template Rendering Error",
        "match": re.compile(
            r'TemplateSyntaxError|TemplateDoesNotExist|UndefinedError'
            r'|jinja2.*Error',
            re.IGNORECASE,
        ),
        "cause": "A template has a syntax error, is missing, or references an undefined variable.",
        "fixes": [
            "Check TEMPLATES DIRS and APP_DIRS settings in Django, or the template_folder in Flask.",
            "For TemplateSyntaxError, look at the line number in the traceback.",
            "For UndefinedError (Jinja2), ensure all variables are passed in the template context.",
        ],
    },
    {
        "id": "python-csrf",
        "title": "CSRF / Authentication Failure",
        "match": re.compile(
            r'CSRF verification failed|Forbidden.*CSRF'
            r'|PermissionDenied|AuthenticationFailed|401 Unauthorized',
            re.IGNORECASE,
        ),
        "cause": "CSRF token validation failed, or a request lacks proper authentication credentials.",
        "fixes": [
            "Ensure {% csrf_token %} is in all POST forms (Django) or CSRF middleware is configured.",
            "For API endpoints, use @csrf_exempt (Django) or exclude from CSRF if using token-based auth.",
            "Check session/cookie settings: CSRF_COOKIE_SECURE, SESSION_COOKIE_SAMESITE.",
        ],
    },
    {
        "id": "celery-task-fail",
        "title": "Celery Task Failure",
        "match": re.compile(
            r'celery.*Task.*raised|celery.*MaxRetriesExceededError'
            r'|WorkerLostError|SoftTimeLimitExceeded|celery.*[Rr]ejected',
            re.IGNORECASE,
        ),
        "cause": "A Celery background task failed, exceeded retries, or was killed due to time limit.",
        "fixes": [
            "Check the task traceback in the Celery worker log for the root exception.",
            "For SoftTimeLimitExceeded, optimize the task or increase soft_time_limit.",
            "For WorkerLostError, the worker process was killed (OOM?) — check system memory.",
        ],
    },
    # ── syslog / Linux ───────────────────────────────────────────────
    {
        "id": "oom-killer",
        "title": "Linux OOM Killer Invoked",
        "match": re.compile(
            r'oom-killer|oom_kill|Out of memory.*Killed process'
            r'|invoked oom-killer|Killed process.*total-vm',
            re.IGNORECASE,
        ),
        "cause": "The system ran out of memory and the kernel OOM killer terminated a process.",
        "fixes": [
            "Check which process was killed and its memory usage at time of kill.",
            "Increase system RAM or configure swap if not present.",
            "Set appropriate memory limits per process (cgroups/systemd MemoryMax) to protect critical services.",
        ],
    },
    {
        "id": "ssh-brute-force",
        "title": "SSH Brute Force / Auth Failure",
        "match": re.compile(
            r'Failed password.*ssh|Invalid user.*sshd|maximum authentication attempts'
            r'|pam_unix.*authentication failure|repeated.*failed.*login',
            re.IGNORECASE,
        ),
        "cause": "Multiple failed SSH login attempts — potential brute-force attack or misconfigured credentials.",
        "fixes": [
            "Install and configure fail2ban to auto-block offending IPs.",
            "Disable password authentication in sshd_config; use SSH keys only (PasswordAuthentication no).",
            "Restrict SSH access by IP using AllowUsers/AllowGroups or firewall rules.",
        ],
    },
    {
        "id": "disk-full",
        "title": "Disk Full / I/O Error",
        "match": re.compile(
            r'No space left on device|filesystem full|I/O error.*dev'
            r'|EXT4-fs error|XFS.*error|read-only file system',
            re.IGNORECASE,
        ),
        "cause": "A filesystem is full or experiencing I/O errors — writes are failing.",
        "fixes": [
            "Check disk usage: df -h and du -sh /var/log/* to find large files.",
            "Clear old logs, temp files, or journal: journalctl --vacuum-size=100M.",
            "For I/O errors, check dmesg for hardware failures and run filesystem checks.",
        ],
    },
    {
        "id": "systemd-service-fail",
        "title": "systemd Service Failed to Start",
        "match": re.compile(
            r'Failed to start|entered failed state|service.*failed'
            r'|Main process exited.*code=exited.*status=',
            re.IGNORECASE,
        ),
        "cause": "A systemd service failed to start or crashed during runtime.",
        "fixes": [
            "Check service status and logs: systemctl status <service> && journalctl -u <service> -n 50.",
            "Review ExecStart path and permissions — the binary must be executable.",
            "Check for missing dependencies, port conflicts, or incorrect config files.",
        ],
    },
    {
        "id": "kernel-panic",
        "title": "Kernel Panic / Hardware Error",
        "match": re.compile(
            r'Kernel panic|BUG:.*kernel|Hardware Error|Machine check'
            r'|general protection fault',
            re.IGNORECASE,
        ),
        "cause": "A kernel bug, hardware fault, or driver issue caused a critical system failure.",
        "fixes": [
            "Check if the kernel is up to date — many panics are fixed in newer versions.",
            "Review dmesg for hardware errors (MCE, ECC memory errors, disk failures).",
            "If reproducible, capture a kernel crash dump (kdump) for analysis.",
        ],
    },
    # ── Kubernetes / OpenShift ───────────────────────────────────────
    {
        "id": "k8s-crashloop",
        "title": "CrashLoopBackOff",
        "match": re.compile(
            r'CrashLoopBackOff|Back-off restarting failed container',
            re.IGNORECASE,
        ),
        "cause": "A container keeps crashing and Kubernetes is backing off restarts.",
        "fixes": [
            "Check container logs: kubectl logs <pod> --previous to see the crash reason.",
            "Common causes: missing config/secrets, wrong entrypoint, or app error on startup.",
            "Verify liveness/readiness probes are not too aggressive (initialDelaySeconds).",
        ],
    },
    {
        "id": "k8s-oomkilled",
        "title": "OOMKilled (Kubernetes)",
        "match": re.compile(
            r'OOMKilled|memory.*limit.*exceeded|cgroup.*oom',
            re.IGNORECASE,
        ),
        "cause": "A container exceeded its memory limit and was killed by the kernel/cgroup OOM handler.",
        "fixes": [
            "Increase resources.limits.memory in the pod spec if the app genuinely needs more memory.",
            "Profile the application to find memory leaks (heap dumps, memory profiler).",
            "Set resources.requests.memory close to limits to ensure proper scheduling.",
        ],
    },
    {
        "id": "k8s-imagepull",
        "title": "ImagePullBackOff / ErrImagePull",
        "match": re.compile(
            r'ImagePullBackOff|ErrImagePull|Failed to pull image'
            r'|manifest.*not found|unauthorized.*registry',
            re.IGNORECASE,
        ),
        "cause": "Kubernetes cannot pull the container image — wrong tag, missing image, or auth failure.",
        "fixes": [
            "Verify the image name and tag exist in the registry: docker pull <image>.",
            "Check imagePullSecrets in the pod spec — the registry may require authentication.",
            "For private registries, create a Secret: kubectl create secret docker-registry ...",
        ],
    },
    {
        "id": "k8s-scheduling",
        "title": "Pod Scheduling Failure",
        "match": re.compile(
            r'FailedScheduling|Insufficient cpu|Insufficient memory'
            r'|didn.t match Pod.s node.*selector|node.*taint.*not tolerated',
            re.IGNORECASE,
        ),
        "cause": "No node has enough resources or matches the pod's scheduling constraints.",
        "fixes": [
            "Check node capacity: kubectl describe nodes | grep -A5 Allocated.",
            "Reduce resource requests or add nodes to the cluster.",
            "For taint/affinity issues, add tolerations or adjust nodeSelector.",
        ],
    },
    {
        "id": "k8s-mount-fail",
        "title": "Volume Mount Failure (Kubernetes)",
        "match": re.compile(
            r'FailedMount|ProvisioningFailed|VolumeInUse'
            r'|Unable to.*mount.*volume|MountVolume.*failed',
            re.IGNORECASE,
        ),
        "cause": "A persistent volume could not be mounted — the PV/PVC is unavailable, in use, or misconfigured.",
        "fixes": [
            "Check PVC status: kubectl get pvc — ensure it is Bound.",
            "For 'VolumeInUse', the previous pod may not have released the volume (ReadWriteOnce).",
            "Verify the storage class exists and the provisioner is healthy.",
        ],
    },
    {
        "id": "openshift-route",
        "title": "OpenShift Route / HAProxy Error",
        "match": re.compile(
            r'route not admitted|HAProxy.*no server available'
            r'|503.*no server|[Rr]outer.*error',
            re.IGNORECASE,
        ),
        "cause": "The OpenShift route cannot reach the backend service — pods are down or the route is misconfigured.",
        "fixes": [
            "Verify the target service and port exist: oc get svc <service>.",
            "Check that pods backing the service are Ready: oc get pods -l app=<app>.",
            "For TLS routes, verify the certificate matches the hostname.",
        ],
    },
    # ── Enonic XP ────────────────────────────────────────────────────
    {
        "id": "enonic-cluster",
        "title": "Enonic XP Cluster Health Issue",
        "match": re.compile(
            r'cluster\.health.*(?:RED|YELLOW)|ClusterHealth.*RED'
            r'|MasterNotDiscoveredException|NoNodeAvailableException'
            r'|NodeDisconnectedException',
            re.IGNORECASE,
        ),
        "cause": "The Enonic XP / Elasticsearch cluster is unhealthy — nodes are missing or shards are unassigned.",
        "fixes": [
            "Check cluster health: curl localhost:2609/_cluster/health (or admin console).",
            "For RED status, check for unassigned shards: _cluster/allocation/explain.",
            "Verify all cluster nodes can reach each other on the discovery port (typically 9300).",
        ],
    },
    {
        "id": "enonic-repo",
        "title": "Enonic XP Repository / Blob Error",
        "match": re.compile(
            r'RepositoryNotFoundException|NodeNotFoundException'
            r'|BlobStoreException|BranchAlreadyExistException'
            r'|blobStore.*error|snapshot.*failed',
            re.IGNORECASE,
        ),
        "cause": "The Enonic XP repository or blob store is corrupted or inaccessible.",
        "fixes": [
            "Run a repository reindex from the Enonic admin console (or REST API).",
            "Check disk space and permissions on the blob store directory ($XP_HOME/repo/blob).",
            "If a snapshot failed, ensure sufficient disk space and try again.",
        ],
    },
    {
        "id": "enonic-content",
        "title": "Enonic XP Content Error",
        "match": re.compile(
            r'ContentNotFoundException|ContentAlreadyExistsException'
            r'|PublishContentException|ContentDataValidationException'
            r'|ContentAccessException',
            re.IGNORECASE,
        ),
        "cause": "A content operation failed — content not found, duplicate, or validation error.",
        "fixes": [
            "Check that the content path/ID exists in the expected branch (draft vs master).",
            "For validation errors, review the content type schema and the submitted data.",
            "For publish errors, check that the content and all references are valid.",
        ],
    },
    # ── JSON / Structured Logs ────────────────────────────────────────
    {
        "id": "json-fatal-error",
        "title": "Fatal Error in Structured Logs",
        "match": re.compile(
            r'"level"\s*:\s*"(?:fatal|emergency|critical)"'
            r'|"severity"\s*:\s*"(?:CRITICAL|EMERGENCY|ALERT)"',
            re.IGNORECASE,
        ),
        "cause": "A fatal/critical error was logged in structured (JSON) logs — the application may be crashing.",
        "fixes": [
            "Check the 'error', 'message', or 'stack' field in the JSON entry for the root cause.",
            "Review recent deployments or config changes that may have triggered the failure.",
            "Check application health endpoints and restart if necessary.",
        ],
    },
    {
        "id": "json-unhandled-rejection",
        "title": "Unhandled Promise Rejection / Exception",
        "match": re.compile(
            r'unhandledRejection|uncaughtException|unhandled.*promise'
            r'|ECONNREFUSED|ENOTFOUND|ETIMEDOUT',
            re.IGNORECASE,
        ),
        "cause": "An unhandled exception or promise rejection crashed or destabilized the Node.js process.",
        "fixes": [
            "Add global error handlers: process.on('unhandledRejection') and process.on('uncaughtException').",
            "For ECONNREFUSED/ENOTFOUND, check that the target service is running and DNS resolves correctly.",
            "Use a process manager (PM2, nodemon) to auto-restart on crashes.",
        ],
    },
    # ── Generic / Cross-Format Patterns ───────────────────────────────
    {
        "id": "connection-refused",
        "title": "Connection Refused",
        "match": re.compile(
            r'Connection refused|ECONNREFUSED|connect\(\) failed'
            r'|Failed to connect|could not connect',
            re.IGNORECASE,
        ),
        "cause": "A connection to a remote service was actively refused — the service is down or not listening.",
        "fixes": [
            "Verify the target service is running and listening on the expected host:port.",
            "Check firewall rules and security groups between the source and target.",
            "Review service health checks and restart the target service if needed.",
        ],
    },
    {
        "id": "dns-resolution-fail",
        "title": "DNS Resolution Failure",
        "match": re.compile(
            r'Name or service not known|NXDOMAIN|DNS.*resolution.*fail'
            r'|getaddrinfo.*failed|ENOTFOUND|UnknownHostException'
            r'|could not resolve.*host',
            re.IGNORECASE,
        ),
        "cause": "DNS lookup failed — the hostname cannot be resolved to an IP address.",
        "fixes": [
            "Check /etc/resolv.conf and DNS server configuration.",
            "Verify the hostname is correct and exists in DNS (dig/nslookup).",
            "For Kubernetes, check CoreDNS pods and service DNS (svc.cluster.local).",
        ],
    },
    {
        "id": "timeout-generic",
        "title": "Connection or Request Timeout",
        "match": re.compile(
            r'timed?\s*out|timeout.*exceeded|read timeout|connect timeout'
            r'|deadline exceeded|context deadline|RequestTimeout'
            r'|SocketTimeoutException|TimeoutError',
            re.IGNORECASE,
        ),
        "cause": "A connection or request timed out — the remote service is too slow or unreachable.",
        "fixes": [
            "Check the target service's health and response times.",
            "Increase timeout values if the service is expected to be slow (batch jobs, large queries).",
            "Add circuit breaker logic to fail fast instead of waiting for timeout.",
        ],
    },
    {
        "id": "http-5xx-generic",
        "title": "HTTP 5xx Server Errors",
        "match": re.compile(
            r'\b50[0-9]\b.*(?:Internal Server Error|Bad Gateway|Service Unavailable|Gateway Timeout)'
            r'|HTTP/\d[\d.]*"\s+5\d\d\b'
            r'|\bstatus[=: ]+5\d\d\b',
            re.IGNORECASE,
        ),
        "cause": "The server returned 5xx errors — indicates server-side failures.",
        "fixes": [
            "Check application logs for exceptions at the time of the 5xx responses.",
            "For 502/503, verify upstream services and load balancer health checks.",
            "For 504, increase upstream timeout settings or investigate slow backend.",
        ],
    },
    {
        "id": "http-4xx-spike",
        "title": "HTTP 4xx Client Errors",
        "match": re.compile(
            r'\b40[0-9]\b.*(?:Not Found|Unauthorized|Forbidden|Method Not Allowed|Too Many Requests)'
            r'|HTTP/\d[\d.]*"\s+4\d\d\b'
            r'|\bstatus[=: ]+4\d\d\b',
            re.IGNORECASE,
        ),
        "cause": "Multiple client errors detected — may indicate broken links, auth issues, or API changes.",
        "fixes": [
            "For 401/403, check authentication/authorization configuration.",
            "For 404, verify URLs and routing configuration — a recent deployment may have changed paths.",
            "For 429, review rate limiting settings or identify the excessive client.",
        ],
    },
    {
        "id": "repeated-exception",
        "title": "Recurring Exception Pattern",
        "match": re.compile(
            r'(?:Exception|Error|Traceback|panic:).*(?:Exception|Error|Traceback|panic:)',
            re.IGNORECASE,
        ),
        "cause": "The same exception type is repeating — likely an unresolved bug triggered on every request/cycle.",
        "fixes": [
            "Identify the most common exception from the top exceptions list and fix the root cause.",
            "If the exception is non-critical, add proper handling to prevent log noise.",
            "Check if the exception started after a recent deployment.",
        ],
    },
    {
        "id": "network-unreachable",
        "title": "Network Unreachable / Host Down",
        "match": re.compile(
            r'Network is unreachable|No route to host|Host is down'
            r'|ENETUNREACH|EHOSTUNREACH|connection reset by peer'
            r'|Broken pipe|EPIPE|ECONNRESET',
            re.IGNORECASE,
        ),
        "cause": "Network connectivity failed — the remote host or network is unreachable.",
        "fixes": [
            "Check network connectivity: ping, traceroute, or curl to the target host.",
            "Review firewall rules, security groups, and network ACLs.",
            "For 'connection reset by peer', the remote service may be crashing or overloaded.",
        ],
    },
    {
        "id": "auth-failure-generic",
        "title": "Authentication Failure",
        "match": re.compile(
            r'authentication fail|login fail|invalid credentials|bad password'
            r'|access denied|unauthorized|auth.*error|invalid.*token',
            re.IGNORECASE,
        ),
        "cause": "Authentication failed — credentials may be incorrect, expired, or the auth service is down.",
        "fixes": [
            "Check if credentials or API tokens have expired and need rotation.",
            "Verify the authentication service is healthy and reachable.",
            "For repeated failures from the same source, investigate potential brute-force attempts.",
        ],
    },
    {
        "id": "resource-exhaustion",
        "title": "Resource Exhaustion (File Descriptors / Processes)",
        "match": re.compile(
            r'Too many open files|EMFILE|ENFILE|cannot fork'
            r'|resource temporarily unavailable|EAGAIN'
            r'|max.*open.*files|ulimit',
            re.IGNORECASE,
        ),
        "cause": "The system or process has exhausted a resource limit (file descriptors, processes, etc.).",
        "fixes": [
            "Check current limits: ulimit -n (files), ulimit -u (processes).",
            "Increase limits in /etc/security/limits.conf or the systemd unit (LimitNOFILE).",
            "Look for resource leaks: unclosed file handles, socket connections, or spawned processes.",
        ],
    },
]

# Try YAML first; fall back to inline list if PyYAML is missing or file is absent
def _merge_heuristics() -> list[dict]:
    """Merge YAML and inline heuristics. YAML entries override inline by id."""
    yaml_h = _load_heuristics_from_yaml()
    if not yaml_h:
        return _HEURISTICS_INLINE
    yaml_ids = {h["id"] for h in yaml_h}
    # YAML overrides inline for matching IDs; inline-only heuristics are kept
    return yaml_h + [h for h in _HEURISTICS_INLINE if h["id"] not in yaml_ids]

_HEURISTICS = _merge_heuristics()


def _heuristic_keywords(h: dict) -> list[str]:
    """Extract quick-check keywords from a heuristic's regex pattern."""
    pattern = h["match"].pattern
    parts = re.split(r'[|()\\.\[\]*+?{}^$]', pattern)
    keywords = [p.strip().lower() for p in parts if len(p.strip()) >= 4 and p.strip().isalnum()]
    parts2 = re.split(r'[|()\\*+?{}^$\[\]]', pattern)
    for p in parts2:
        p = p.strip().lower()
        if len(p) >= 4 and all(c.isalnum() or c in ' .-_' for c in p):
            if p not in keywords:
                keywords.append(p)
    return keywords


# --- Correlation rules ---
# Each rule fires when ALL required cause IDs are present.
_CORRELATIONS: list[dict[str, Any]] = [
    {
        "id": "corr-oom-pool",
        "requires": ["oom-gc", "db-pool"],
        "title": "Memory Exhaustion Cascading to Connection Pool",
        "cause": "OutOfMemoryError is preventing proper connection cleanup, exhausting the DB pool.",
        "fixes": [
            "Fix the memory issue first — the pool exhaustion is a symptom, not the root cause.",
            "Capture a heap dump to find the leak, then increase pool timeout as a short-term mitigation.",
        ],
    },
    {
        "id": "corr-oom-pool-hikari",
        "requires": ["oom-gc", "hikari-pool"],
        "title": "Memory Exhaustion Cascading to HikariCP Pool",
        "cause": "OutOfMemoryError is preventing proper connection cleanup, exhausting the HikariCP pool.",
        "fixes": [
            "Fix the memory issue first — the pool exhaustion is a symptom, not the root cause.",
            "Capture a heap dump to find the leak, then increase HikariCP connection timeout as a short-term mitigation.",
        ],
    },
    {
        "id": "corr-k8s-oom-crash",
        "requires": ["k8s-oomkilled", "k8s-crashloop"],
        "title": "OOMKilled Causing CrashLoopBackOff",
        "cause": "The container is repeatedly killed for exceeding its memory limit, causing CrashLoopBackOff.",
        "fixes": [
            "Increase resources.limits.memory in the pod spec.",
            "Profile the app to find memory leaks — the limit may be correct but the app leaks.",
            "Check if the JVM -Xmx is set close to the container limit (leave ~25% headroom for non-heap).",
        ],
    },
    {
        "id": "corr-k8s-image-crash",
        "requires": ["k8s-imagepull", "k8s-crashloop"],
        "title": "Image Pull Failure Preventing Pod Start",
        "cause": "Pods cannot start because the container image cannot be pulled.",
        "fixes": [
            "Fix the image pull issue first — CrashLoopBackOff will resolve once the correct image is available.",
            "Check image name/tag and registry credentials (imagePullSecrets).",
        ],
    },
    {
        "id": "corr-ssl-deploy",
        "requires": ["ssl-trust", "deploy-fail"],
        "title": "SSL Trust Failure Blocking Deployment",
        "cause": "Application deployment fails because it cannot establish trusted SSL connections to dependencies.",
        "fixes": [
            "Import the required certificates into the truststore before deploying.",
            "Check if the app connects to external services during startup that require SSL trust.",
        ],
    },
    {
        "id": "corr-db-deploy",
        "requires": ["datasource-down", "deploy-fail"],
        "title": "Database Unavailability Blocking Deployment",
        "cause": "Application startup fails because the database is unreachable during initialization.",
        "fixes": [
            "Ensure the database is up and accepting connections before deploying the application.",
            "Consider adding retry/backoff logic in the application's DataSource initialization.",
        ],
    },
    {
        "id": "corr-spring-db",
        "requires": ["spring-startup-fail", "hikari-pool"],
        "title": "Spring Boot Fails Due to Database Connection",
        "cause": "Spring Boot cannot start because HikariCP failed to establish a database connection.",
        "fixes": [
            "Check spring.datasource.url, username, and password in application.yml.",
            "Verify the database is running and accepts connections from this host.",
            "Set spring.datasource.hikari.initialization-fail-timeout to -1 for lazy init during development.",
        ],
    },
    {
        "id": "corr-spring-kafka",
        "requires": ["spring-startup-fail", "kafka-error"],
        "title": "Spring Boot Fails Due to Kafka Unavailability",
        "cause": "Spring Boot startup fails because it cannot connect to the Kafka broker.",
        "fixes": [
            "Verify spring.kafka.bootstrap-servers points to a reachable Kafka broker.",
            "If Kafka is optional, set spring.autoconfigure.exclude to disable KafkaAutoConfiguration.",
        ],
    },
    {
        "id": "corr-nginx-disk",
        "requires": ["nginx-permission", "nginx-502"],
        "title": "Disk/Permission Issue Causing Bad Gateway",
        "cause": "nginx cannot proxy requests because temp/cache directories are full or inaccessible.",
        "fixes": [
            "Check disk space on the nginx server: df -h.",
            "Verify proxy_temp_path and client_body_temp_path directories are writable.",
            "Clear stale cache: rm -rf /var/cache/nginx/*.",
        ],
    },
    {
        "id": "corr-oom-kill-service",
        "requires": ["oom-killer", "systemd-service-fail"],
        "title": "OOM Killer Took Down a Service",
        "cause": "The Linux OOM killer terminated a process, causing its systemd service to fail.",
        "fixes": [
            "Check which process was killed: dmesg | grep -i 'killed process'.",
            "Increase system RAM or set MemoryMax= in the service's systemd unit to protect it.",
            "Identify the actual memory hog — it may be a different process consuming all memory.",
        ],
    },
    {
        "id": "corr-disk-service",
        "requires": ["disk-full", "systemd-service-fail"],
        "title": "Disk Full Causing Service Failure",
        "cause": "A service failed because the disk is full — it cannot write logs, data, or temp files.",
        "fixes": [
            "Free disk space immediately: journalctl --vacuum-size=100M; find /tmp -mtime +7 -delete.",
            "Identify the largest consumers: du -sh /* | sort -rh | head.",
            "Add log rotation and disk monitoring alerts to prevent recurrence.",
        ],
    },
    {
        "id": "corr-enonic-cluster-repo",
        "requires": ["enonic-cluster", "enonic-repo"],
        "title": "Enonic XP Cluster Issue Causing Repository Errors",
        "cause": "Repository operations are failing because the cluster is unhealthy — nodes cannot agree on data.",
        "fixes": [
            "Fix cluster health first — repository errors are a downstream symptom.",
            "Check network connectivity between all cluster nodes.",
            "If a node was replaced, it may need to rejoin the cluster and resync data.",
        ],
    },
    {
        "id": "corr-timeout-5xx",
        "requires": ["timeout-generic", "http-5xx-generic"],
        "title": "Timeouts Causing HTTP 5xx Errors",
        "cause": "Backend timeouts are resulting in 5xx errors returned to clients.",
        "fixes": [
            "Identify which backend service is timing out and fix the bottleneck.",
            "Increase timeout thresholds as a short-term mitigation.",
            "Add circuit breakers to prevent cascading timeout failures.",
        ],
    },
    {
        "id": "corr-dns-timeout",
        "requires": ["dns-resolution-fail", "timeout-generic"],
        "title": "DNS Failures Causing Timeouts",
        "cause": "DNS resolution failures are causing connection timeouts to downstream services.",
        "fixes": [
            "Fix DNS resolution first — timeouts are a downstream symptom.",
            "Check DNS server health and /etc/resolv.conf configuration.",
            "For Kubernetes, verify CoreDNS pods are healthy: kubectl get pods -n kube-system.",
        ],
    },
    {
        "id": "corr-connrefused-5xx",
        "requires": ["connection-refused", "http-5xx-generic"],
        "title": "Connection Refused Causing HTTP 5xx",
        "cause": "A backend service is refusing connections, resulting in 5xx errors to clients.",
        "fixes": [
            "Restart or fix the refusing backend service.",
            "Check if the service crashed or is still starting up.",
            "Verify port configuration matches between proxy and backend.",
        ],
    },
    {
        "id": "corr-auth-4xx",
        "requires": ["auth-failure-generic", "http-4xx-spike"],
        "title": "Authentication Failures Driving 4xx Errors",
        "cause": "Authentication failures are causing a spike in 401/403 client errors.",
        "fixes": [
            "Check if credentials, tokens, or certificates were recently rotated.",
            "Verify the authentication/identity provider is healthy.",
            "Review access control configuration for recent changes.",
        ],
    },
    {
        "id": "corr-resource-timeout",
        "requires": ["resource-exhaustion", "timeout-generic"],
        "title": "Resource Exhaustion Causing Timeouts",
        "cause": "Exhausted system resources (file descriptors, processes) are causing connections to time out.",
        "fixes": [
            "Fix the resource leak or increase limits as immediate mitigation.",
            "Check for connection/file handle leaks in the application code.",
            "Increase ulimits and monitor resource usage trends.",
        ],
    },
]


# --- Incident group definitions ---
_INCIDENT_GROUPS: list[dict[str, Any]] = [
    {
        "id": "incident-oom-cascade",
        "name": "Memory Exhaustion Cascade",
        "trigger_ids": {"oom-gc", "oom-killer", "k8s-oomkilled"},
        "effect_ids": {"hung-threads", "db-pool", "hikari-pool", "servlet-error",
                       "transaction-timeout", "http-5xx-generic", "k8s-crashloop"},
        "narrative": "Memory exhaustion triggered a cascade of failures: {effects}. "
                     "Fix the memory issue first — other errors are symptoms.",
    },
    {
        "id": "incident-auth-failure",
        "name": "Authentication / Security Failure",
        "trigger_ids": {"authz-denied", "auth-failure-generic", "ssh-brute-force",
                        "ldap-connection-fail", "python-csrf"},
        "effect_ids": {"http-4xx-spike", "cert-expiry", "ssl-trust", "nginx-ssl-error"},
        "narrative": "Authentication or security failures detected: {effects}. "
                     "Check credential validity, certificate expiry, and auth service health.",
    },
    {
        "id": "incident-timeout-cascade",
        "name": "Timeout / Connectivity Cascade",
        "trigger_ids": {"timeout-generic", "connection-refused", "dns-resolution-fail",
                        "network-unreachable", "datasource-down"},
        "effect_ids": {"hung-threads", "db-pool", "hikari-pool", "http-5xx-generic",
                       "nginx-502", "transaction-timeout", "servlet-error"},
        "narrative": "Connectivity problems caused downstream timeouts and failures: {effects}. "
                     "Identify the unreachable service and restore connectivity.",
    },
    {
        "id": "incident-deploy-failure",
        "name": "Deployment / Startup Failure",
        "trigger_ids": {"deploy-fail", "spring-startup-fail", "config-error",
                        "port-bind-fail", "context-root-conflict", "k8s-imagepull",
                        "systemd-service-fail"},
        "effect_ids": {"classloader", "jndi-lookup-fail", "http-5xx-generic",
                       "k8s-crashloop", "k8s-scheduling"},
        "narrative": "A deployment or startup failure triggered related errors: {effects}. "
                     "Review the deployment configuration and fix the root startup issue.",
    },
    {
        "id": "incident-network",
        "name": "Network / Connectivity Failure",
        "trigger_ids": {"connection-refused", "dns-resolution-fail", "network-unreachable"},
        "effect_ids": {"timeout-generic", "http-5xx-generic", "nginx-502",
                       "datasource-down", "ldap-connection-fail", "kafka-error"},
        "narrative": "Network connectivity failures caused service disruptions: {effects}. "
                     "Check network infrastructure, DNS, and firewall rules.",
    },
    {
        "id": "incident-database",
        "name": "Database / Persistence Failure",
        "trigger_ids": {"datasource-down", "db-pool", "hikari-pool", "django-db",
                        "hibernate-error"},
        "effect_ids": {"transaction-timeout", "hung-threads", "http-5xx-generic",
                       "servlet-error", "spring-startup-fail"},
        "narrative": "Database connectivity or persistence issues caused application failures: {effects}. "
                     "Check database health, connection pool settings, and query performance.",
    },
]


def group_into_incidents(causes: list[dict[str, Any]]) -> dict[str, Any]:
    """Group related likely causes into incident groups.

    Returns dict with:
      - groups: list of incident dicts with trigger, effects, narrative
      - ungrouped: list of causes that don't fit any incident group
    """
    if not causes:
        return {"groups": [], "ungrouped": []}

    cause_ids = {c["id"] for c in causes}
    cause_by_id = {c["id"]: c for c in causes}
    used_ids: set[str] = set()
    groups: list[dict[str, Any]] = []

    for ig in _INCIDENT_GROUPS:
        trigger_matches = ig["trigger_ids"] & cause_ids
        effect_matches = ig["effect_ids"] & cause_ids
        if not trigger_matches:
            continue

        # Build trigger and effects lists
        triggers = [cause_by_id[cid] for cid in trigger_matches]
        effects = [cause_by_id[cid] for cid in effect_matches]
        all_ids = trigger_matches | effect_matches

        # Skip if this group would duplicate a group that already covers these
        if all_ids <= used_ids:
            continue

        # Build narrative
        effect_names = [cause_by_id[cid]["title"] for cid in effect_matches] if effect_matches else []
        narrative = ig["narrative"].format(
            effects=", ".join(effect_names) if effect_names else "no downstream effects detected"
        )

        total_count = sum(c["count"] for c in triggers) + sum(c["count"] for c in effects)

        groups.append({
            "id": ig["id"],
            "name": ig["name"],
            "narrative": narrative,
            "triggers": triggers,
            "effects": effects,
            "total_count": total_count,
        })
        used_ids |= all_ids

    # Sort groups by total event count (most impactful first)
    groups.sort(key=lambda g: -g["total_count"])

    # Ungrouped causes (skip correlation entries — they're explained by their parent causes)
    ungrouped = [c for c in causes if c["id"] not in used_ids
                 and not c.get("correlated_from")]

    return {"groups": groups, "ungrouped": ungrouped}


def _detect_burst(events: list[dict], window_seconds: float = 120.0, threshold: int = 50) -> list[dict[str, Any]]:
    """Detect error bursts — many errors in a short time window."""
    error_events = [e for e in events if e.get("level") in ERROR_LEVELS]
    if len(error_events) < threshold:
        return []

    # Parse timestamps and find bursts
    timed: list[tuple[float, dict]] = []
    for e in error_events:
        dt = parse_ts_datetime(e.get("ts"))
        if dt is None:
            continue
        timed.append((dt.timestamp(), e))

    if len(timed) < threshold:
        return []

    timed.sort(key=lambda x: x[0])
    results: list[dict[str, Any]] = []

    # Sliding window
    i = 0
    for j in range(len(timed)):
        while timed[j][0] - timed[i][0] > window_seconds:
            i += 1
        window_count = j - i + 1
        if window_count >= threshold:
            # Count unique error types in burst
            burst_types: dict[str, int] = {}
            for k in range(i, j + 1):
                exc = timed[k][1].get("exception") or timed[k][1].get("code") or "unknown"
                burst_types[exc] = burst_types.get(exc, 0) + 1
            top_type = max(burst_types, key=burst_types.get)  # type: ignore[arg-type]

            results.append({
                "id": "burst-detected",
                "title": f"Error Storm Detected ({window_count} errors in {window_seconds/60:.0f} min)",
                "count": window_count,
                "cause": f"A burst of {window_count} errors occurred in a {window_seconds/60:.0f}-minute window. "
                         f"Top error: {top_type} ({burst_types[top_type]} occurrences). "
                         f"This suggests a cascading failure, deployment issue, or sudden load spike.",
                "fixes": [
                    "Check if a deployment or config change happened just before the burst started.",
                    f"Investigate the primary error type ({top_type}) — fixing it may resolve the cascade.",
                    "Check for upstream dependency failures (database, external API, DNS) that triggered the storm.",
                    "Review auto-scaling and circuit breaker settings to prevent future cascades.",
                ],
                "severity": "critical",
            })
            break  # Report the worst burst only

    return results


def _severity_score(events: list[dict], match_re: re.Pattern) -> int:  # type: ignore[type-arg]
    """Score a heuristic higher if it matches FATAL/SEVERE events."""
    score = 0
    for e in events:
        if match_re.search(e.get("text", "")):
            level = e.get("level", "")
            if level in ("FATAL", "SEVERE"):
                score += 10
            elif level == "ERROR":
                score += 3
            else:
                score += 1
    return score


def likely_causes(events: list[dict]) -> list[dict[str, Any]]:
    """Return list of {id, title, count, cause, fixes} for detected heuristic patterns.

    Includes single-pattern heuristics, multi-signal correlations,
    burst detection, and severity-weighted ranking.
    """
    h_keywords = []
    for h in _HEURISTICS:
        h_keywords.append(_heuristic_keywords(h))

    candidates: set[int] = {idx for idx, kws in enumerate(h_keywords) if not kws}
    for e in events:
        text_lower = e.get("text", "").lower()
        for idx, kws in enumerate(h_keywords):
            if idx in candidates:
                continue
            for kw in kws:
                if kw in text_lower:
                    candidates.add(idx)
                    break
        if len(candidates) == len(_HEURISTICS):
            break

    # --- Single-pattern heuristics ---
    results = []
    matched_ids: set[str] = set()
    for idx in candidates:
        h = _HEURISTICS[idx]
        count = sum(1 for e in events if h["match"].search(e.get("text", "")))  # type: ignore[union-attr,misc]
        if count:
            sev = _severity_score(events, h["match"])
            results.append({
                "id": h["id"],
                "title": h["title"],
                "count": count,
                "cause": h["cause"],
                "fixes": list(h["fixes"]),  # type: ignore[arg-type]
                "_sev": sev,
            })
            matched_ids.add(h["id"])

    # --- Correlation rules (multi-signal) ---
    for corr in _CORRELATIONS:
        if all(rid in matched_ids for rid in corr["requires"]):
            # Sum counts of contributing causes
            contributing = [r for r in results if r["id"] in corr["requires"]]
            total_count = sum(r["count"] for r in contributing)
            max_sev = max((r["_sev"] for r in contributing), default=0)
            results.append({
                "id": corr["id"],
                "title": corr["title"],
                "count": total_count,
                "cause": corr["cause"],
                "fixes": list(corr["fixes"]),
                "_sev": max_sev + 5,  # Boost correlations above individual causes
                "correlated_from": list(corr["requires"]),
            })

    # --- Burst detection ---
    bursts = _detect_burst(events)
    for b in bursts:
        b["_sev"] = b["count"] * 2  # Bursts rank very high
        results.append(b)

    # --- Sort by severity score (descending), then by count ---
    results.sort(key=lambda r: (-r.get("_sev", 0), -r["count"]))

    # Clean up internal scoring field
    for r in results:
        r.pop("_sev", None)

    return results


_SPLUNK_PREFIX = 'index=APP sourcetype=WAS'


def _extract_hung_thread_name(text: str) -> str | None:
    """Extract thread name from a hung-thread event."""
    m = HUNG_THREAD_NAME_RE.search(text)
    if m:
        return next((g for g in m.groups() if g is not None), None)
    return None


def _extract_stack_sample(text: str, max_lines: int = 5) -> list[str]:
    """Extract up to max_lines of stack trace from event text."""
    lines: list[str] = []
    for line in text.splitlines():
        if STACK_LINE_RE.match(line) or CAUSED_BY_RE.match(line):
            lines.append(line.strip())
            if len(lines) >= max_lines:
                break
    return lines


# --- Cross-system cascade patterns ---
_CASCADE_PATTERNS: list[dict[str, Any]] = [
    {"upstream_tags": {"DB/Pool"}, "downstream_tags": {"HTTP"}, "max_delay_s": 30,
     "label": "Database failure → HTTP errors"},
    {"upstream_tags": {"SSL/TLS"}, "downstream_tags": {"HTTP"}, "max_delay_s": 10,
     "label": "SSL failure → connection errors"},
    {"upstream_tags": {"OOM/GC"}, "downstream_tags": {"HungThreads"}, "max_delay_s": 60,
     "label": "Memory pressure → thread starvation"},
    {"upstream_tags": {"OOM/GC"}, "downstream_tags": {"HTTP"}, "max_delay_s": 60,
     "label": "Memory pressure → HTTP errors"},
    {"upstream_tags": {"DB/Pool"}, "downstream_tags": {"HungThreads"}, "max_delay_s": 30,
     "label": "Database exhaustion → hung threads"},
    {"upstream_tags": {"HungThreads"}, "downstream_tags": {"HTTP"}, "max_delay_s": 15,
     "label": "Hung threads → HTTP timeouts"},
]


def detect_cross_system_cascades(events: list[dict], max_delay_s: int = 60) -> list[dict[str, Any]]:
    """Detect error cascades across different system sources.

    Looks for temporal patterns where errors in one system are followed by
    errors in another system within a time window, matching known cascade patterns.

    Returns list of cascade dicts:
        {pattern, upstream_event, downstream_events, delay_seconds, confidence}
    """
    # Need events sorted by ts_utc with at least 2 sources
    error_events = [e for e in events if e.get("level") in ERROR_LEVELS and e.get("ts_utc")]
    if len(error_events) < 2:
        return []

    sources = set(e.get("system_label", "") for e in error_events)
    if len(sources) < 2:
        return []

    # Parse ts_utc to float for fast comparison
    timed_errors: list[tuple[float, dict]] = []
    for e in error_events:
        try:
            dt = datetime.fromisoformat(e["ts_utc"])
            timed_errors.append((dt.timestamp(), e))
        except (ValueError, TypeError):
            continue

    timed_errors.sort(key=lambda x: x[0])
    cascades: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str, str]] = set()  # (pattern_label, upstream_source, downstream_source)

    for i, (t_up, e_up) in enumerate(timed_errors):
        up_tags = set(e_up.get("tags", []))
        up_source = e_up.get("system_label", "")
        if not up_tags:
            continue

        for pattern in _CASCADE_PATTERNS:
            if not pattern["upstream_tags"] & up_tags:
                continue

            # Look for downstream events in other sources within the delay window
            downstream = []
            for j in range(i + 1, len(timed_errors)):
                t_down, e_down = timed_errors[j]
                delay = t_down - t_up
                if delay > pattern["max_delay_s"]:
                    break
                if delay < 0:
                    continue

                down_source = e_down.get("system_label", "")
                if down_source == up_source:
                    continue  # Same source, not a cross-system cascade

                down_tags = set(e_down.get("tags", []))
                if pattern["downstream_tags"] & down_tags:
                    downstream.append({"event": e_down, "delay_s": round(delay, 1)})

            if downstream:
                pair_key = (pattern["label"], up_source, downstream[0]["event"].get("system_label", ""))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                confidence = min(0.9, 0.5 + 0.1 * len(downstream))
                cascades.append({
                    "pattern": pattern["label"],
                    "upstream_event": e_up,
                    "upstream_source": up_source,
                    "downstream_events": downstream[:5],  # Limit to 5
                    "downstream_source": downstream[0]["event"].get("system_label", ""),
                    "delay_seconds": downstream[0]["delay_s"],
                    "confidence": confidence,
                })

    # Sort by confidence descending
    cascades.sort(key=lambda c: -c["confidence"])
    return cascades[:10]  # Top 10 cascades


def hung_thread_drilldown(events: list[dict]) -> list[dict[str, Any]]:
    """Analyze hung/stuck thread events. Returns list of thread info dicts sorted by count."""
    threads: dict[str, dict] = {}

    for e in events:
        text = e.get("text", "")
        if not HUNG_THREAD_RE.search(text):
            continue

        thread_name = _extract_hung_thread_name(text)
        if not thread_name:
            thread_name = f"0x{e['thread_id']}" if e.get("thread_id") else "unknown"

        ts = e.get("ts")

        if thread_name not in threads:
            threads[thread_name] = {
                "thread_name": thread_name,
                "count": 0,
                "first_ts": ts,
                "last_ts": ts,
                "hex_ids": set(),
                "stack_sample": [],
            }

        info = threads[thread_name]
        info["count"] += 1
        if ts:
            if not info["first_ts"]:
                info["first_ts"] = ts
            info["last_ts"] = ts
        if e.get("thread_id"):
            info["hex_ids"].add(e["thread_id"])
        if not info["stack_sample"]:
            info["stack_sample"] = _extract_stack_sample(text)

    results = []
    for info in threads.values():
        results.append({
            "thread_name": info["thread_name"],
            "count": info["count"],
            "first_ts": info["first_ts"],
            "last_ts": info["last_ts"],
            "hex_ids": sorted(info["hex_ids"]),
            "stack_sample": info["stack_sample"],
            "splunk_query": f'{_SPLUNK_PREFIX} "{info["thread_name"]}"',
        })
    results.sort(key=lambda r: -r["count"])
    return results


def suggested_splunk_queries(summary: dict, causes: list[dict], hist: list[tuple]) -> list[dict[str, str]]:
    """Generate Splunk query strings based on detected issues."""
    queries: list[dict[str, str]] = []

    queries.append({
        "description": "All errors and severe events",
        "query": f'{_SPLUNK_PREFIX} (ERROR OR SEVERE OR FATAL)',
    })

    for exc_name, count in summary.get("exceptions", [])[:3]:
        short = exc_name.rsplit(".", 1)[-1]
        queries.append({
            "description": f"Events matching {short} ({count} seen)",
            "query": f'{_SPLUNK_PREFIX} "{short}"',
        })

    seen_prefixes: set[str] = set()
    for code, count in summary.get("codes", [])[:5]:
        prefix = re.match(r'[A-Z]+', code)
        if prefix:
            p = prefix.group()
            if p not in seen_prefixes and len(seen_prefixes) < 3:
                seen_prefixes.add(p)
                queries.append({
                    "description": f"All {p}* message codes",
                    "query": f'{_SPLUNK_PREFIX} "{p}*"',
                })

    tag_queries = {
        "SSL/TLS": {
            "description": "SSL/TLS handshake failures",
            "query": f'{_SPLUNK_PREFIX} (SSLHandshakeException OR "PKIX path building failed" OR CWPKI*)',
        },
        "OOM/GC": {
            "description": "OutOfMemory and GC pressure events",
            "query": f'{_SPLUNK_PREFIX} (OutOfMemoryError OR "GC overhead limit exceeded" OR "Java heap space")',
        },
        "DB/Pool": {
            "description": "Connection pool exhaustion",
            "query": f'{_SPLUNK_PREFIX} (J2CA* OR "pool exhausted" OR "ConnectionWaitTimeout")',
        },
        "HungThreads": {
            "description": "Hung/stuck thread detections",
            "query": f'{_SPLUNK_PREFIX} (WSVR0605W OR WSVR0606W OR ThreadMonitor OR CWWKE0701E)',
        },
    }
    for tag, _ in summary.get("tags", []):
        if tag in tag_queries and tag_queries[tag] not in queries:
            queries.append(tag_queries[tag])

    if hist:
        queries.append({
            "description": "Error spike timeline (adjust span to match your bucket size)",
            "query": f'{_SPLUNK_PREFIX} (ERROR OR SEVERE OR FATAL) | timechart span=1m count by sourcetype',
        })

    return queries[:8]


def per_source_summary(events: list[dict]) -> list[dict[str, Any]]:
    """Return summary per system_label: label, format, total, errors, top codes, top exceptions."""
    sources: dict[str, dict] = {}
    for e in events:
        label = e.get("system_label", "unknown")
        if label not in sources:
            sources[label] = {"label": label, "format": e.get("format", "unknown"),
                              "total": 0, "errors": 0, "codes": Counter(), "exceptions": Counter()}
        sources[label]["total"] += 1
        if e.get("level") in ERROR_LEVELS:
            sources[label]["errors"] += 1
        if e.get("code"):
            sources[label]["codes"][e["code"]] += 1
        if e.get("exception"):
            sources[label]["exceptions"][e["exception"]] += 1

    result = []
    for s in sorted(sources.values(), key=lambda x: x["errors"], reverse=True):
        result.append({
            "label": s["label"],
            "format": s["format"],
            "total": s["total"],
            "errors": s["errors"],
            "top_codes": s["codes"].most_common(3),
            "top_exceptions": s["exceptions"].most_common(3),
        })
    return result


def correlate_by_trace_id(events: list[dict]) -> dict[str, list[dict]]:
    """Group events by shared trace/correlation IDs across sources.

    Returns dict mapping trace_id -> list of events, only including
    IDs that appear in events from 2+ different system_labels.
    """
    # Build trace_id -> events mapping
    id_events: dict[str, list[dict]] = {}
    for e in events:
        for tid in e.get("trace_ids", []):
            if tid not in id_events:
                id_events[tid] = []
            id_events[tid].append(e)

    # Keep only cross-system correlations
    cross_system: dict[str, list[dict]] = {}
    for tid, evts in id_events.items():
        sources = set(e.get("system_label", "") for e in evts)
        if len(sources) >= 2:
            # Sort by timestamp
            cross_system[tid] = sorted(evts, key=lambda e: e.get("ts_utc") or "")

    return cross_system


def find_cross_system_chains(events: list[dict], max_chains: int = 10) -> list[dict]:
    """Find request flows that span multiple systems via trace IDs.

    Returns list of chain dicts:
        {trace_id, systems, event_count, has_errors, events}
    """
    correlations = correlate_by_trace_id(events)

    chains = []
    for tid, evts in correlations.items():
        systems = list(dict.fromkeys(e.get("system_label", "unknown") for e in evts))
        has_errors = any(e.get("level") in ERROR_LEVELS for e in evts)
        chains.append({
            "trace_id": tid,
            "systems": systems,
            "event_count": len(evts),
            "has_errors": has_errors,
            "events": evts,
        })

    # Sort: errors first, then by event count
    chains.sort(key=lambda c: (not c["has_errors"], -c["event_count"]))
    return chains[:max_chains]


def precompute_analysis(events: list[dict], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1) -> dict[str, Any]:
    """Compute all shared analysis data once. Returns a dict."""
    s = summarize(events, top_n)
    samples = pick_samples(events, samples_n)
    hist = time_histogram(events, bucket_minutes=hist_minutes)
    file_summary = per_file_summary(events)
    causes = likely_causes(events)
    splunk = suggested_splunk_queries(s, causes, hist)
    hung = hung_thread_drilldown(events)
    cascades = detect_cross_system_cascades(events)
    return {
        "summary": s,
        "samples": samples,
        "hist": hist,
        "file_summary": file_summary,
        "causes": causes,
        "splunk": splunk,
        "hung": hung,
        "cascades": cascades,
    }
