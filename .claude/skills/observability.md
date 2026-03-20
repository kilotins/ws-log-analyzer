# Observability

LogPilot must have excellent logging and monitoring — a log analysis tool with bad observability is a credibility disaster.

## Structured Logging (structlog)

All logging uses `structlog` with JSON output. No `print()` statements — ever.

### Setup (once at startup)

```python
import structlog

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)
```

### Usage

```python
import structlog
logger = structlog.get_logger()

# In request handler
logger.info("analysis_complete",
    session_id=session.id,
    files_parsed=5,
    events_found=12847,
    incidents_detected=2,
    duration_ms=3420,
)

# Warning for slow operations
if duration_ms > 5000:
    logger.warning("slow_request",
        path=request.url.path,
        method=request.method,
        duration_ms=duration_ms,
    )

# Error with full context
logger.error("parse_failed",
    session_id=session.id,
    filename=upload.filename,
    error=str(exc),
    exc_info=True,
)
```

### Example Output

```json
{
  "timestamp": "2026-03-20T14:15:42.123Z",
  "level": "info",
  "event": "analysis_complete",
  "request_id": "req_a3f2b8c1",
  "workspace_id": "ws_devops_klp",
  "user_id": "usr_erik",
  "session_id": "ses_f47ac10b",
  "files_parsed": 5,
  "events_found": 12847,
  "incidents_detected": 2,
  "duration_ms": 3420
}
```

## Request Tracing

### Middleware

```python
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request_id = f"req_{uuid.uuid4().hex[:8]}"

        # Bind to structlog context (available in all downstream logging)
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        # Set response header
        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id

        # Log request completion
        logger.info("request_complete",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=elapsed_ms,
        )
        return response
```

### Propagation

Request ID must flow through:
- API request → service layer → database calls
- API request → background job (pass as job parameter)
- API request → AI provider call (log with same request_id)

```python
# When enqueuing a background job
await queue.enqueue("parse_file", {
    "session_id": session.id,
    "request_id": structlog.contextvars.get_contextvars()["request_id"],
})

# In the worker
async def handle_parse_file(payload):
    structlog.contextvars.bind_contextvars(
        request_id=payload["request_id"],
        job_id=job.id,
    )
    logger.info("parse_started", session_id=payload["session_id"])
```

## Log Levels

| Level | When | Example |
|-------|------|---------|
| `DEBUG` | Development only. Verbose internal state. | SQL queries, cache hits/misses, event counts per batch |
| `INFO` | Normal operations. One per significant action. | `request_complete`, `analysis_complete`, `ai_call_complete` |
| `WARNING` | Something unusual but recoverable. | Slow request (>5s), approaching rate limit, retry succeeded |
| `ERROR` | Something failed. Needs attention. | Parse failed, AI provider error, DB connection lost |

**Rule**: INFO logs should tell the story of a request. A developer reading only INFO logs should understand what happened.

## Health Endpoints

```python
@router.get("/health")
async def health():
    """Process alive. Always returns 200."""
    return {"status": "ok"}

@router.get("/ready")
async def ready(db: Database = Depends(get_database)):
    """Dependencies connected. Returns 503 if not."""
    checks = {}
    try:
        await db.execute("SELECT 1")
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"

    # Redis check (if configured)
    if cache := get_cache():
        try:
            await cache.ping()
            checks["cache"] = "ok"
        except Exception:
            checks["cache"] = "error"

    healthy = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ready" if healthy else "not_ready", "checks": checks},
    )
```

Used by:
- Docker: `HEALTHCHECK CMD curl -f http://localhost:8000/health`
- Kubernetes: `livenessProbe` → `/health`, `readinessProbe` → `/ready`

## Performance Metrics

Key timings to log per request:

| Metric | Where | Threshold |
|--------|-------|-----------|
| `parse_duration_ms` | Per file in parse pipeline | WARN if > 30s |
| `analysis_duration_ms` | Full analysis run | WARN if > 10s |
| `ai_call_duration_ms` | Per AI provider call | WARN if > 30s |
| `request_duration_ms` | Total API request time | WARN if > 5s |
| `db_query_ms` | Per database query | WARN if > 1s |

```python
# Simple timing context manager
from contextlib import asynccontextmanager
import time

@asynccontextmanager
async def timed(metric_name: str):
    start = time.monotonic()
    yield
    duration_ms = int((time.monotonic() - start) * 1000)
    logger.info(f"{metric_name}_complete", duration_ms=duration_ms)
    if duration_ms > 5000:
        logger.warning(f"{metric_name}_slow", duration_ms=duration_ms)

# Usage
async with timed("parse"):
    events = parse_file(upload.path, format=detected_format)
```

## Error Tracking

### SaaS: Sentry

```python
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration

if settings.sentry_dsn:
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        integrations=[FastApiIntegration()],
        traces_sample_rate=0.1,
    )
```

### Self-service: Structured ERROR logs

Same information, just in log output instead of Sentry:

```python
logger.error("unhandled_exception",
    path=request.url.path,
    method=request.method,
    workspace_id=ws_ctx.workspace.id if ws_ctx else None,
    exc_info=True,  # includes full stack trace
)
```

## AI Call Logging

Every AI provider call is logged with:

```python
logger.info("ai_call_complete",
    provider="claude",
    model="claude-sonnet-4-20250514",
    input_tokens=2450,
    output_tokens=890,
    cost_usd=0.0123,
    duration_ms=4200,
    cache_hit=False,
    session_id=session.id,
)
```

Also stored in `ai_conversations` table for:
- Audit trail (who asked what, when)
- Cost tracking (per workspace, per user)
- Cache hit analysis (are we wasting money on duplicate queries?)

## Background Job Logging

```python
# Job lifecycle
logger.info("job_started", job_id=job.id, type="parse_file", session_id=sid)
logger.info("job_progress", job_id=job.id, percent=45, files_done=3, files_total=7)
logger.info("job_complete", job_id=job.id, duration_ms=12000)

# On failure
logger.error("job_failed", job_id=job.id, error=str(exc), exc_info=True)
```

## Audit Trail

The `audit_log` table records significant actions:

| Action | Resource | When |
|--------|----------|------|
| `session.create` | session | User creates analysis session |
| `session.delete` | session | User deletes session |
| `ai.explain` | session | AI explanation requested |
| `export.pdf` | session | Report exported |
| `workspace.create` | workspace | New workspace created |
| `member.invite` | workspace | Member added to workspace |
| `api_key.create` | workspace | API key generated |
| `api_key.revoke` | workspace | API key deleted |

```python
async def audit(db: Database, ws_ctx: WorkspaceContext, action: str, resource_type: str, resource_id: str, metadata: dict = None):
    await db.insert_audit_log(
        workspace_id=ws_ctx.workspace.id,
        user_id=ws_ctx.user.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata=metadata or {},
    )
```

## Eat Your Own Dog Food

LogPilot's own logs must be parseable by LogPilot:
- Use JSON structured format → matches our `json_log` format plugin
- Include all fields that our parser looks for (timestamp, level, event/message)
- If we can't analyze our own production incidents with our own tool, we have work to do
- Powerful demo: "Here's LogPilot analyzing its own logs"

## Gotchas

- **structlog processors are configured once at startup** — don't reconfigure mid-request
- **Never log sensitive data** — no API keys, passwords, tokens, even at DEBUG level
- **Request ID must be generated BEFORE any logging** — first thing in middleware
- **Background jobs need their own bound logger** — not the request's contextvars (different process/thread)
- **Don't log full request/response bodies** — too verbose, may contain secrets. Log metadata only.
- **Log rotation**: stdout in Docker (let Docker/K8s handle rotation). Don't write to files in containers.
