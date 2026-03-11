"""Analysis functions: summarize, timeline, heuristics, splunk, hung threads."""
from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .parser import (
    CAUSED_BY_RE, HUNG_THREAD_NAME_RE, HUNG_THREAD_RE, STACK_LINE_RE,
    WAS_CODE_RE,
)

_log = logging.getLogger("logpilot")


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
        if e.get("level") in ("ERROR", "SEVERE", "FATAL"):
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
        if e.get("level") in ("ERROR", "SEVERE", "FATAL"):
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
        if e.get("level") in ("ERROR", "SEVERE", "FATAL"):
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
]

# Try YAML first; fall back to inline list if PyYAML is missing or file is absent
_HEURISTICS = _load_heuristics_from_yaml() or _HEURISTICS_INLINE


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


def likely_causes(events: list[dict]) -> list[dict[str, Any]]:
    """Return list of {id, title, count, cause, fixes} for detected heuristic patterns."""
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

    results = []
    for idx in candidates:
        h = _HEURISTICS[idx]
        count = sum(1 for e in events if h["match"].search(e.get("text", "")))  # type: ignore[union-attr,misc]
        if count:
            results.append({
                "id": h["id"],
                "title": h["title"],
                "count": count,
                "cause": h["cause"],
                "fixes": list(h["fixes"]),  # type: ignore[arg-type]
            })
    results.sort(key=lambda r: -r["count"])  # type: ignore[operator]
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


def precompute_analysis(events: list[dict], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1) -> dict[str, Any]:
    """Compute all shared analysis data once. Returns a dict."""
    s = summarize(events, top_n)
    samples = pick_samples(events, samples_n)
    hist = time_histogram(events, bucket_minutes=hist_minutes)
    file_summary = per_file_summary(events)
    causes = likely_causes(events)
    splunk = suggested_splunk_queries(s, causes, hist)
    hung = hung_thread_drilldown(events)
    return {
        "summary": s,
        "samples": samples,
        "hist": hist,
        "file_summary": file_summary,
        "causes": causes,
        "splunk": splunk,
        "hung": hung,
    }
