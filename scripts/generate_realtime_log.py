#!/usr/bin/env python3
"""Generate realistic WebSphere Liberty SystemOut.log data for testing realtime monitoring.

Usage:
    python scripts/generate_realtime_log.py [--output /tmp/SystemOut.log] [--rate 2.0] [--duration 300]

The script appends log lines at a configurable rate to simulate a live Liberty server.
Press Ctrl+C to stop.
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# --- Templates ---

THREAD_NAMES = [
    "Default Executor-thread-5", "Default Executor-thread-12",
    "Default Executor-thread-23", "Default Executor-thread-41",
    "WebContainer : 0", "WebContainer : 1", "WebContainer : 3",
    "LargeThreadPool-thread-7", "ConnectorTimer-thread-1",
    "SchedulerThread-2", "Timer-1", "WMQJMSConnection-thread-8",
]

LOGGER_NAMES = [
    "com.ibm.ws.webcontainer.servlet",
    "com.ibm.ws.session.SessionContext",
    "com.ibm.ws.kernel.feature.internal.FeatureManager",
    "com.ibm.ws.security.authentication.AuthenticationService",
    "com.ibm.ws.jndi.iiop",
    "com.ibm.ws.jdbc.DataSourceService",
    "com.ibm.ws.http.channel.internal",
    "com.ibm.ws.app.manager.AppMessageHelper",
    "com.ibm.ws.ssl.config.SSLConfigManager",
    "org.apache.myfaces.webapp.StartupServletContextListener",
    "com.ibm.ws.transaction.services.TransactionManagerService",
    "com.ibm.ws.container.service.metadata",
    "com.ibm.ejs.container.BeanMetaData",
]

SERVLETS = [
    "CustomerServlet", "OrderProcessingServlet", "LoginServlet",
    "HealthCheckServlet", "PaymentGatewayServlet", "ReportServlet",
    "APIDispatcher", "NotificationServlet",
]

DB_TABLES = ["CUSTOMERS", "ORDERS", "INVENTORY", "SESSIONS", "AUDIT_LOG", "PAYMENTS"]

WAS_CODES_INFO = [
    ("CWWKZ0001I", "Application {app} started in {ms} seconds."),
    ("CWWKF0012I", "The server installed the following features: [{features}]."),
    ("CWWKT0016I", "Web application available: http://localhost:9080/{app}/"),
    ("CWWKE0036I", "The server {server} is ready to run a smarter planet."),
    ("CWWKS4105I", "LTPA configuration is ready after {ms} seconds."),
    ("SRVE0242I", "Servlet {servlet} initialized successfully."),
    ("CWWKZ0003I", "The application {app} updated in {ms} seconds."),
    ("SESN0176I", "A new session context will be created for application key {app}."),
]

WAS_CODES_WARNING = [
    ("CWWKS3005W", "A LTPA configuration error was detected. Session timeout set to {ms} seconds."),
    ("SRVE0190W", "Servlet {servlet}: response already committed, cannot forward."),
    ("CWWKE0039W", "Unexpected thread quiesce during shutdown of server {server}."),
    ("CWWKZ0014W", "The application {app} could not be started as it could not be found at location {path}."),
    ("DSRA0302W", "Connection pool {pool} reached max capacity ({max} connections)."),
    ("TRAS0017W", "The trace string has been changed. The new trace state is *=info."),
]

WAS_CODES_ERROR = [
    ("CWWKS1106E", "Authentication did not succeed for user {user}. An invalid user ID or password was specified."),
    ("SRVE0777E", "Exception thrown by application class 'com.app.{servlet}.doGet': {exc}"),
    ("DSRA0010E", "SQL State = 08S01, Error Code = 0. Connection is closed."),
    ("CWWKE1102E", "Bundle com.ibm.ws.jaxrs id=147 has not been started."),
    ("CWWKZ0002E", "An exception occurred while starting the application {app}. The exception is: {exc}"),
    ("TRAS0014E", "Trace could not be written to the output file. Error: Disk full."),
]

EXCEPTIONS = [
    ("java.sql.SQLTransientConnectionException", "Connection is not available, request timed out after 30000ms."),
    ("java.lang.NullPointerException", None),
    ("javax.naming.NameNotFoundException", "Name comp/env/jdbc/AppDS not found in context."),
    ("java.io.IOException", "Broken pipe"),
    ("java.lang.OutOfMemoryError", "Java heap space"),
    ("javax.net.ssl.SSLHandshakeException", "Remote host terminated the handshake"),
    ("java.util.concurrent.TimeoutException", "Hung thread detected: Default Executor-thread-23 has been active for 612000ms"),
    ("com.ibm.websphere.ce.cm.ConnectionWaitTimeoutException", "Wait timeout of 180000ms exceeded for pool AppDataSource."),
    ("java.lang.ClassNotFoundException", "com.app.legacy.OldServiceAdapter"),
]

STACK_FRAMES = [
    "at com.app.service.CustomerService.findById(CustomerService.java:{line})",
    "at com.app.dao.JDBCCustomerDAO.query(JDBCCustomerDAO.java:{line})",
    "at com.app.web.{servlet}.doGet({servlet}.java:{line})",
    "at javax.servlet.http.HttpServlet.service(HttpServlet.java:687)",
    "at com.ibm.ws.webcontainer.servlet.ServletWrapper.service(ServletWrapper.java:{line})",
    "at com.ibm.ws.webcontainer.filter.WebAppFilterChain.doFilter(WebAppFilterChain.java:{line})",
    "at com.ibm.ws.webcontainer.servlet.CacheServletWrapper.handleRequest(CacheServletWrapper.java:{line})",
    "at com.ibm.ws.webcontainer.WebContainer.handleRequest(WebContainer.java:{line})",
    "at com.ibm.ws.http.HttpConnection.readAndHandleRequest(HttpConnection.java:{line})",
    "at java.base/java.lang.Thread.run(Thread.java:834)",
]

APPS = ["CustomerPortal", "OrderService", "PaymentGateway", "AdminConsole", "ReportEngine"]
SERVERS = ["appServer01", "appServer02", "liberty01"]
USERS = ["admin", "jsmith", "svc_account", "api_user", "unknown"]


def _ts(dt: datetime) -> str:
    """Format a Liberty-style timestamp."""
    return dt.strftime("[%m/%d/%y %H:%M:%S:%f")[:-3] + " CET]"


def _random_line(line_no: int) -> str:
    return str(random.randint(30, 900))


def _gen_stacktrace(exc_class: str, message: str | None, servlet: str) -> list[str]:
    """Generate a realistic Java stacktrace."""
    msg = f"{exc_class}: {message}" if message else exc_class
    lines = [msg]
    depth = random.randint(4, 8)
    frames = random.sample(STACK_FRAMES, min(depth, len(STACK_FRAMES)))
    for frame in frames:
        lines.append("\t" + frame.format(servlet=servlet, line=_random_line(0)))
    if random.random() < 0.3:
        caused_exc = random.choice(EXCEPTIONS)
        caused_msg = f"Caused by: {caused_exc[0]}" + (f": {caused_exc[1]}" if caused_exc[1] else "")
        lines.append(caused_msg)
        for frame in random.sample(STACK_FRAMES, 3):
            lines.append("\t" + frame.format(servlet=servlet, line=_random_line(0)))
    return lines


def generate_event(dt: datetime) -> list[str]:
    """Generate one log event (possibly multi-line with stacktrace). Returns list of lines."""
    ts = _ts(dt)
    thread = random.choice(THREAD_NAMES)
    roll = random.random()

    # 60% INFO
    if roll < 0.60:
        code, template = random.choice(WAS_CODES_INFO)
        msg = template.format(
            app=random.choice(APPS),
            servlet=random.choice(SERVLETS),
            server=random.choice(SERVERS),
            features="servlet-4.0, jsp-2.3, jndi-1.0, jdbc-4.2",
            ms=f"{random.uniform(0.2, 15.0):.3f}",
            path="/opt/ibm/wlp/usr/servers/apps/",
        )
        return [f"{ts} {thread:>40s} I {random.choice(LOGGER_NAMES)} {code}: {msg}"]

    # 10% audit/detail
    if roll < 0.70:
        detail_msgs = [
            f"SECJ0305I: The identity of the caller is {random.choice(USERS)} at realm defaultRealm.",
            f"JDBC connection allocated from pool AppDataSource. Total active: {random.randint(1, 50)}.",
            f"HTTP request completed: GET /{random.choice(APPS)}/api/v1/health -> 200 in {random.randint(1, 200)}ms",
            f"Session {random.randbytes(8).hex()} created for user {random.choice(USERS)}.",
            f"GC cycle completed: nursery={random.randint(50, 300)}MB tenure={random.randint(200, 1200)}MB pause={random.randint(5, 80)}ms",
        ]
        return [f"{ts} {thread:>40s} A {random.choice(LOGGER_NAMES)} {random.choice(detail_msgs)}"]

    # 18% WARNING
    if roll < 0.88:
        code, template = random.choice(WAS_CODES_WARNING)
        msg = template.format(
            app=random.choice(APPS),
            servlet=random.choice(SERVLETS),
            server=random.choice(SERVERS),
            pool="AppDataSource",
            max=random.choice([20, 50, 100]),
            ms=str(random.randint(60, 1800)),
            path="/opt/ibm/wlp/usr/servers/apps/",
        )
        lines = [f"{ts} {thread:>40s} W {random.choice(LOGGER_NAMES)} {code}: {msg}"]
        if random.random() < 0.2:
            exc = random.choice(EXCEPTIONS)
            lines.extend(_gen_stacktrace(exc[0], exc[1], random.choice(SERVLETS)))
        return lines

    # 10% ERROR
    if roll < 0.98:
        code, template = random.choice(WAS_CODES_ERROR)
        servlet = random.choice(SERVLETS)
        exc = random.choice(EXCEPTIONS)
        msg = template.format(
            app=random.choice(APPS),
            servlet=servlet,
            server=random.choice(SERVERS),
            user=random.choice(USERS),
            exc=f"{exc[0]}: {exc[1]}" if exc[1] else exc[0],
        )
        lines = [f"{ts} {thread:>40s} E {random.choice(LOGGER_NAMES)} {code}: {msg}"]
        if random.random() < 0.7:
            lines.extend(_gen_stacktrace(exc[0], exc[1], servlet))
        return lines

    # 2% FATAL / OOM
    lines = []
    if random.random() < 0.5:
        lines.append(f"{ts} {thread:>40s} E com.ibm.ws.kernel.launch CWWKE0036I: java.lang.OutOfMemoryError: Java heap space")
        lines.extend(_gen_stacktrace("java.lang.OutOfMemoryError", "Java heap space", random.choice(SERVLETS)))
    else:
        hung_thread = random.choice(THREAD_NAMES)
        duration = random.randint(600, 1200)
        lines.append(f"{ts} {thread:>40s} W com.ibm.ws.threading.internal WSVR0605W: Thread {hung_thread} has been active for {duration}000 milliseconds and may be hung.")
        lines.append(f"\tStack trace for thread {hung_thread}:")
        servlet = random.choice(SERVLETS)
        for frame in random.sample(STACK_FRAMES, 5):
            lines.append("\t" + frame.format(servlet=servlet, line=_random_line(0)))
    return lines


def main():
    parser = argparse.ArgumentParser(description="Generate realtime WebSphere Liberty SystemOut.log data")
    parser.add_argument("--output", "-o", default="/tmp/SystemOut.log", help="Output log file path (default: /tmp/SystemOut.log)")
    parser.add_argument("--rate", "-r", type=float, default=2.0, help="Average events per second (default: 2.0)")
    parser.add_argument("--duration", "-d", type=int, default=0, help="Duration in seconds, 0=infinite (default: 0)")
    parser.add_argument("--burst", action="store_true", help="Occasionally generate bursts of errors")
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    dt = datetime.now()
    avg_delay = 1.0 / args.rate
    start = time.monotonic()
    count = 0

    print(f"Writing Liberty SystemOut.log to: {output}")
    print(f"Rate: ~{args.rate} events/sec | Duration: {'infinite' if args.duration == 0 else f'{args.duration}s'} | Burst: {args.burst}")
    print("Press Ctrl+C to stop.\n")

    try:
        with output.open("a") as f:
            while True:
                if args.duration > 0 and (time.monotonic() - start) >= args.duration:
                    break

                # Burst mode: occasional spike of errors
                if args.burst and random.random() < 0.03:
                    burst_count = random.randint(5, 15)
                    print(f"  [BURST] Generating {burst_count} rapid error events...")
                    for _ in range(burst_count):
                        dt += timedelta(milliseconds=random.randint(10, 200))
                        # Force error/fatal events during burst
                        old_roll = random.random
                        random.random = lambda: 0.95  # force ERROR range
                        lines = generate_event(dt)
                        random.random = old_roll
                        for line in lines:
                            f.write(line + "\n")
                        count += 1
                    f.flush()
                    continue

                dt += timedelta(milliseconds=int(avg_delay * 1000 * random.uniform(0.3, 2.5)))
                lines = generate_event(dt)
                for line in lines:
                    f.write(line + "\n")
                f.flush()
                count += 1

                if count % 20 == 0:
                    print(f"  {count} events written, latest: {dt.strftime('%H:%M:%S')}")

                time.sleep(avg_delay * random.uniform(0.3, 2.5))

    except KeyboardInterrupt:
        pass

    print(f"\nDone. {count} events written to {output}")


if __name__ == "__main__":
    main()
