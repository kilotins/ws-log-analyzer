# Tomcat / Catalina Log Analysis

## Log Format

Tomcat uses **java.util.logging** (JUL) by default, NOT Log4j. The timestamp format is different from standard Log4j/Logback.

### catalina.out (Default Format)
```
11-Mar-2025 10:15:33.123 INFO [main] org.apache.catalina.startup.Catalina.start Server startup in [1234] milliseconds
11-Mar-2025 10:15:34.456 SEVERE [http-nio-8080-exec-1] org.apache.catalina.connector.CoyoteAdapter.service Exception processing request
```

**Pattern**: `DD-MMM-YYYY HH:MM:SS.sss LEVEL [thread] logger.method message`

### Key Differences from Log4j
| Aspect | Tomcat (JUL) | Log4j/Logback |
|--------|-------------|---------------|
| Date format | `11-Mar-2025` (DD-MMM-YYYY) | `2025-03-11` (YYYY-MM-DD) |
| Severity names | `SEVERE`, `WARNING`, `FINE`, `FINER`, `FINEST` | `ERROR`, `WARN`, `DEBUG`, `TRACE` |
| Thread format | `[thread-name]` before logger | After timestamp or at end |
| Logger | `package.Class.method` (includes method) | `package.Class` (no method) |

### Level Mapping
| JUL Level | LogPilot Level |
|-----------|---------------|
| SEVERE | ERROR |
| WARNING | WARNING |
| INFO | INFO |
| CONFIG | INFO |
| FINE | DEBUG |
| FINER | DEBUG |
| FINEST | DEBUG |

### Detection Regex
```python
# Tomcat JUL timestamp: DD-MMM-YYYY HH:MM:SS.sss
TOMCAT_TS_RE = re.compile(
    r'^(?P<ts>\d{1,2}-[A-Z][a-z]{2}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+'
    r'(?P<level>SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST)\s+'
    r'\[(?P<thread>[^\]]+)\]\s+'
    r'(?P<logger>\S+)\s+'
    r'(?P<message>.*)'
)
```

## Tomcat-Specific Log Files

| File | Content | Format |
|------|---------|--------|
| `catalina.out` | Main server log, stdout/stderr | JUL or Log4j (depends on config) |
| `catalina.YYYY-MM-DD.log` | Rotated server log | Same as catalina.out |
| `localhost.YYYY-MM-DD.log` | Web application logs | JUL |
| `localhost_access_log.YYYY-MM-DD.txt` | HTTP access log | Apache CLF (handled by nginx plugin) |
| `manager.YYYY-MM-DD.log` | Manager app logs | JUL |
| `host-manager.YYYY-MM-DD.log` | Host manager logs | JUL |

## High-Impact Error Patterns

### Startup Failures
```
SEVERE [main] org.apache.catalina.core.StandardContext.startInternal One or more Filters failed to start
SEVERE [main] org.apache.catalina.core.StandardContext.startInternal Context [/myapp] startup failed
SEVERE [main] org.apache.catalina.startup.HostConfig.deployWAR Error deploying web application archive
```

### Connection Pool (DBCP/Tomcat Pool)
```
WARNING [http-nio-8080-exec-5] org.apache.tomcat.dbcp.dbcp2.BasicDataSource.getConnection Cannot get a connection, pool error
SEVERE [http-nio-8080-exec-5] org.apache.tomcat.dbcp.dbcp2.BasicDataSource.getConnection Cannot get a connection, pool exhausted
```

### Thread Pool Exhaustion
```
WARNING [main] org.apache.catalina.connector.Connector.pause Thread pool [http-nio-8080] not stopping in time
SEVERE [http-nio-8080-exec-200] org.apache.coyote.http11.Http11Processor.service Error processing request: maximum threads (200) reached
```

### Memory / OOM
```
SEVERE [http-nio-8080-exec-1] org.apache.catalina.connector.CoyoteAdapter.service Exception processing request
java.lang.OutOfMemoryError: Java heap space
```

### Session Errors
```
WARNING [ContainerBackgroundProcessor] org.apache.catalina.session.StandardManager.expire Session [ABC123] is invalid
SEVERE [main] org.apache.catalina.session.PersistentManagerBase.processExpires Exception processing session persistence
```

### SSL/TLS
```
SEVERE [main] org.apache.tomcat.util.net.NioEndpoint.bind Failed to initialize connector [Connector[HTTP/1.1-8443]]
Caused by: java.io.FileNotFoundException: /opt/tomcat/conf/keystore.jks (No such file or directory)
```

## Signal Tags

| Tag | Trigger patterns |
|-----|-----------------|
| `OOM/GC` | `OutOfMemoryError`, `heap space`, GC overhead |
| `DB/Pool` | `pool error`, `pool exhausted`, `Cannot get a connection`, DBCP |
| `SSL/TLS` | `SSLHandshakeException`, `keystore`, `certificate`, NioEndpoint bind failure |
| `HTTP` | HTTP status 4xx/5xx in access log |
| `Deploy` | `deployment failed`, `startup failed`, `failed to start` |
| `Thread` | `maximum threads reached`, `thread pool not stopping` |

## Common Incident Patterns

### Deployment Cascade
```
SEVERE [main] org.apache.catalina.core.StandardContext.startInternal Context [/myapp] startup failed
WARNING [main] org.apache.catalina.loader.WebappClassLoaderBase.clearReferencesThreads Thread [pool-1-thread-1] started by web app but not stopped
SEVERE [main] org.apache.catalina.startup.HostConfig.deployWAR Error deploying: /opt/tomcat/webapps/myapp.war
```
**Pattern**: App fails to start → threads leak → subsequent deploys also fail.

### Connection Pool Death Spiral
```
WARNING [http-nio-8080-exec-50] BasicDataSource.getConnection Cannot get connection, pool error: Timeout
WARNING [http-nio-8080-exec-51] BasicDataSource.getConnection Cannot get connection, pool error: Timeout
SEVERE  [http-nio-8080-exec-52] CoyoteAdapter.service Exception: java.sql.SQLException
```
**Pattern**: Pool timeout → requests queue → more timeouts → all threads blocked.

## Related Skills
- `skills/log4j-analysis.md` — If Tomcat is configured with Log4j instead of JUL
- `skills/servlet-errors.md` — Servlet lifecycle, filter issues
- `skills/stacktrace-analysis.md` — Java stacktrace reading
- `skills/database-errors.md` — Database error codes in connection pool failures
