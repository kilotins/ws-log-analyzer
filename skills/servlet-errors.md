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
