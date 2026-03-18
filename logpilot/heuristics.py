"""Heuristic pattern matching, correlations, incident grouping, and burst detection."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from .event import LogEvent

_log = logging.getLogger(__name__)

ERROR_LEVELS = ("ERROR", "SEVERE", "FATAL")


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


def _detect_burst(events: list[LogEvent], window_seconds: float = 120.0, threshold: int = 50) -> list[dict[str, Any]]:
    """Detect error bursts — many errors in a short time window."""
    from .analysis import parse_ts_datetime

    error_events = [e for e in events if e.level in ERROR_LEVELS]
    if len(error_events) < threshold:
        return []

    # Parse timestamps and find bursts
    timed: list[tuple[float, LogEvent]] = []
    for e in error_events:
        dt = parse_ts_datetime(e.ts)
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
                exc = timed[k][1].exception or timed[k][1].code or "unknown"
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


def _severity_score(events: list[LogEvent], match_re: re.Pattern) -> int:  # type: ignore[type-arg]
    """Score a heuristic higher if it matches FATAL/SEVERE events."""
    score = 0
    for e in events:
        if match_re.search(e.text or ""):
            level = e.level or ""
            if level in ("FATAL", "SEVERE"):
                score += 10
            elif level == "ERROR":
                score += 3
            else:
                score += 1
    return score


def likely_causes(events: list[LogEvent]) -> list[dict[str, Any]]:
    """Return list of {id, title, count, cause, fixes} for detected heuristic patterns.

    Includes single-pattern heuristics, multi-signal correlations,
    burst detection, and severity-weighted ranking.
    """
    h_keywords = []
    for h in _HEURISTICS:
        h_keywords.append(_heuristic_keywords(h))

    candidates: set[int] = {idx for idx, kws in enumerate(h_keywords) if not kws}
    texts_lower = [(e.text or "").lower() for e in events]
    for text_lower in texts_lower:
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
        count = 0
        sev = 0
        match_re = h["match"]
        for e in events:
            if match_re.search(e.text or ""):  # type: ignore[union-attr,misc]
                count += 1
                if count <= 1000:  # Cap severity sampling
                    level = e.level or ""
                    if level in ("FATAL", "SEVERE"):
                        sev += 10
                    elif level == "ERROR":
                        sev += 3
                    else:
                        sev += 1
        if count:
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


def incident_fingerprint(causes: list[dict]) -> str:
    """Create a stable fingerprint from heuristic findings.

    Combines sorted heuristic IDs and top exception names into a
    deterministic string key for comparing incidents.

    Args:
        causes: List of cause dicts from likely_causes(), each with 'id' and optionally 'title'.

    Returns:
        A stable fingerprint string (hash).
    """
    import hashlib
    # Extract heuristic IDs
    ids = sorted(set(c.get("id", c.get("title", "")) for c in causes))
    # Extract top exception names from cause descriptions
    exceptions = sorted(set(
        c.get("title", "")
        for c in causes
        if any(kw in c.get("title", "").lower() for kw in ("exception", "error", "failure", "oom", "timeout"))
    ))
    fingerprint_data = "|".join(ids) + "||" + "|".join(exceptions)
    return hashlib.sha256(fingerprint_data.encode("utf-8")).hexdigest()[:16]


def match_similar_incidents(current_causes: list[dict],
                            history: list[dict]) -> list[dict]:
    """Compare current incident against a history of past analyses.

    Uses Jaccard similarity on heuristic ID sets.

    Args:
        current_causes: Current cause dicts from likely_causes().
        history: List of past incident dicts, each with 'fingerprint', 'ids', 'timestamp'.

    Returns:
        List of matching incidents with similarity >= 0.5, each containing:
        {fingerprint, timestamp, similarity}.
    """
    if not current_causes or not history:
        return []

    current_ids = set(c.get("id", c.get("title", "")) for c in current_causes)
    if not current_ids:
        return []

    matches = []
    for past in history:
        past_ids = set(past.get("ids", []))
        if not past_ids:
            continue

        # Jaccard similarity
        intersection = len(current_ids & past_ids)
        union = len(current_ids | past_ids)
        if union == 0:
            continue
        similarity = intersection / union

        if similarity >= 0.5:
            matches.append({
                "fingerprint": past.get("fingerprint", ""),
                "timestamp": past.get("timestamp", ""),
                "similarity": round(similarity, 2),
            })

    # Sort by similarity descending
    matches.sort(key=lambda m: -m["similarity"])
    return matches
