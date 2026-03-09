# Servlet Error Analysis

## Servlet Lifecycle

```
init() -> service() [doGet/doPost/...] -> destroy()
```

Errors can occur at any phase. The SRVE message code tells you where.

## Common Servlet Errors

### SRVE0255E — Uncaught Exception
**Most common servlet error.** An unhandled exception escaped the servlet.

Triage:
1. Read the full stacktrace — the `Caused by:` chain reveals the real issue
2. Common root causes:
   - `NullPointerException` — application bug
   - `SQLException` — database issue
   - `IOException` — downstream service failure
   - `ClassCastException` — session deserialization after redeploy

### SRVE0293E — Servlet Not Found (404)
Request URL doesn't match any servlet mapping.

Check:
- Is the application deployed and started?
- Does `web.xml` or `@WebServlet` annotation match the URL?
- Case sensitivity in URL mapping
- Context root mismatch (`/app` vs `/App`)

### SRVE0207E — Initialization Failed
Servlet `init()` threw an exception.

Check:
- Missing init-param in `web.xml`
- Dependency injection failure (CDI, Spring)
- Datasource JNDI lookup failed during init
- After fix, the servlet must be reloaded (redeploy or server restart)

### SRVE0068E — Destroy Failed
Servlet `destroy()` threw an exception. Usually a resource cleanup issue.

Check:
- Unclosed database connections
- Thread not interrupted cleanly
- Timer/scheduler not cancelled
- Typically non-critical but indicates resource leak

### SRVE0190E — Request/Response Error
I/O error during request processing.

Common causes:
- Client disconnected mid-request (broken pipe)
- Response buffer overflow
- Timeout during large response write

### SRVE0319E — Request Too Large
Request body exceeds configured max size.

Check: `maxRequestSize` in server config, file upload limits.

## Error Correlation

### Multiple Servlets Failing Simultaneously
If many different servlets fail at once:
- Shared resource down (database, external service)
- Thread pool exhausted
- Memory pressure (OOM approaching)

### Single Servlet Failing Repeatedly
If one servlet fails while others work:
- Application bug in that servlet
- Specific resource dependency for that servlet
- URL-specific input causing failure

## HTTP Status Code Mapping

| SRVE Code | HTTP Status | Meaning |
|-----------|------------|---------|
| SRVE0293E | 404 | Servlet not found |
| SRVE0255E | 500 | Uncaught exception |
| SRVE0207E | 503 | Servlet unavailable (init failed) |
| SRVE0319E | 413 | Request too large |
| SRVE0190E | varies | I/O error, often client-side |

## Filter and Interceptor Errors

Modern apps use servlet filters heavily (authentication, logging, CORS). Filter errors may not produce SRVE codes directly:

### Filter Chain Failure
```
SRVE0255E: A Servlet Exception occurred
Caused by: java.lang.RuntimeException: Filter execution failed
    at com.example.filter.AuthFilter.doFilter(AuthFilter.java:45)
```
The stacktrace shows the filter class, not the servlet. Look for `doFilter` in the trace.

### Common Filter Issues
| Pattern | Cause |
|---------|-------|
| `AuthFilter` + `NullPointerException` | Missing security context or session |
| `CorsFilter` + `IllegalStateException` | Response already committed before CORS headers |
| `LoggingFilter` + `OutOfMemoryError` | Filter buffering entire request/response body |
| `CompressionFilter` + `IOException` | Client disconnected during compressed response |

## Async Servlet Errors

Async servlets (`AsyncContext`) introduce new failure modes:

### Async Timeout
```
SRVE0255E: ... AsyncContext timeout
```
The async operation didn't call `complete()` within the timeout (default 30s).
Fix: Increase `asyncTimeout` or fix the slow async operation.

### Async Error After Response
```
IllegalStateException: Response already committed
    at javax.servlet.AsyncContext.dispatch(AsyncContext.java:...)
```
The async handler tried to write after the response was already sent.
Fix: Check `response.isCommitted()` before writing.

## Servlet Timeout Configuration

WAS servlet timeouts manifest differently than HTTP client timeouts:

| Config | Default | Log Pattern |
|--------|---------|-------------|
| `asyncTimeout` | 30s | SRVE0255E with AsyncContext |
| `connectionTimeout` | 60s | SRVE0190E, connection closed |
| `readTimeout` | 60s | SRVE0190E, read timed out |
| `writeTimeout` | 60s | SRVE0315E, write failed |

### Slow Servlet Load (SRVE0242I)
If the time between SRVE0169I (loading module) and SRVE0242I (servlet loaded) is > 10 seconds:
- Servlet `init()` is doing heavy work (DB connections, cache warmup)
- Consider lazy initialization or async init for expensive setup

## Incident Response Playbook

### Scenario: 500 Errors Spiking
1. Check if one servlet or many → single = app bug, many = shared resource down
2. Extract the root exception from SRVE0255E stacktraces
3. If `SQLException` → check DB health (DSRA codes)
4. If `ConnectException` → downstream service is down
5. If `NullPointerException` → application bug, check the exact line number
6. If errors started after deploy → rollback candidate
