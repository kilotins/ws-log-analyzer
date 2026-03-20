# FastAPI Patterns

## Project Structure

```
backend/
├── api/              # Route modules
│   ├── auth.py       # Login, callback, logout
│   ├── sessions.py   # Session CRUD, upload, analyze
│   ├── workspaces.py # Workspace + member management
│   ├── orgs.py       # Organization management
│   ├── ingest.py     # API ingestion endpoint
│   └── ai.py         # AI explain (SSE streaming)
├── adapters/         # Infrastructure abstractions
│   ├── storage/      # ObjectStore: LocalStore, S3Store
│   ├── database/     # Database: SQLiteDB, PostgresDB
│   ├── queue/        # JobQueue: InlineQueue, RedisQueue
│   ├── cache/        # Cache: MemoryCache, RedisCache
│   └── auth/         # AuthProvider: NoAuth, Local, OIDC
├── services/         # Business logic
│   ├── analysis.py   # Orchestrates parse → analyze pipeline
│   ├── ai_service.py # AI provider routing, redaction, cost tracking
│   └── reports.py    # Report generation
├── workers/          # Background job handlers
│   ├── parse_job.py
│   └── analyze_job.py
├── settings.py       # Pydantic BaseSettings
└── main.py           # App factory, middleware, lifespan
```

## Settings

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database
    database_url: str = "sqlite:///~/.logpilot/db.sqlite"

    # Storage
    storage_backend: str = "filesystem"  # "filesystem" | "s3"
    storage_path: str = "~/.logpilot/data"
    s3_bucket: str = ""
    s3_endpoint: str = ""

    # Queue
    queue_backend: str = "inline"  # "inline" | "redis"
    redis_url: str = "redis://localhost:6379"

    # Auth
    auth_backend: str = "none"  # "none" | "local" | "oidc"
    secret_key: str = "change-me-in-production"
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""

    # AI
    ai_external_enabled: bool = True

    # Billing (SaaS only)
    billing_enabled: bool = False

    # Observability
    sentry_dsn: str = ""
    log_level: str = "INFO"

    model_config = {"env_prefix": "LOGPILOT_"}

settings = Settings()
```

Zero env vars = laptop mode. Add vars to scale up.

## App Factory + Lifespan

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await get_database().connect()
    if settings.auth_backend == "none":
        await ensure_local_setup(get_database())
    yield
    # Shutdown
    await get_database().disconnect()

def create_app() -> FastAPI:
    app = FastAPI(title="LogPilot", lifespan=lifespan)

    # Middleware (order matters — last added runs first)
    app.add_middleware(CORSMiddleware,
        allow_origins=["http://localhost:5173"] if settings.debug else [settings.frontend_url],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestIdMiddleware)

    # Routes
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(sessions_router, prefix="/api/v1/sessions", tags=["sessions"])
    app.include_router(workspaces_router, prefix="/api/v1/workspaces", tags=["workspaces"])
    app.include_router(orgs_router, prefix="/api/v1/orgs", tags=["orgs"])
    app.include_router(ingest_router, prefix="/api/v1/ingest", tags=["ingest"])

    return app

app = create_app()
```

## Dependency Injection

### Infrastructure Dependencies (singleton, resolved at startup)

```python
from functools import lru_cache

@lru_cache
def get_database() -> Database:
    if settings.database_url.startswith("postgres"):
        return PostgresDB(settings.database_url)
    return SQLiteDB(settings.database_url)

@lru_cache
def get_storage() -> ObjectStore:
    if settings.storage_backend == "s3":
        return S3Store(settings.s3_bucket, settings.s3_endpoint)
    return LocalStore(settings.storage_path)

@lru_cache
def get_queue() -> JobQueue:
    if settings.queue_backend == "redis":
        return RedisQueue(settings.redis_url)
    return InlineQueue()

@lru_cache
def get_auth_provider() -> AuthProvider:
    if settings.auth_backend == "oidc":
        return OIDCProvider(settings.oidc_issuer, settings.oidc_client_id, settings.oidc_client_secret)
    elif settings.auth_backend == "local":
        return LocalAuthProvider(settings.secret_key)
    return NoAuthProvider()
```

### Request-scoped Dependencies

```python
# Type aliases for cleaner route signatures
DbDep = Annotated[Database, Depends(get_database)]
StorageDep = Annotated[ObjectStore, Depends(get_storage)]
QueueDep = Annotated[JobQueue, Depends(get_queue)]

async def get_current_user(
    request: Request,
    auth: AuthProvider = Depends(get_auth_provider),
    db: Database = Depends(get_database),
) -> AuthUser:
    # API key path
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer lp_"):
        return await authenticate_api_key(auth_header[7:], db)
    # Session path
    return await auth.authenticate(request)

UserDep = Annotated[AuthUser, Depends(get_current_user)]

async def get_workspace_context(
    user: UserDep,
    org_slug: str = Path(...),
    workspace_slug: str = Path(...),
    db: DbDep = ...,
) -> WorkspaceContext:
    org = await db.get_org_by_slug(org_slug)
    if not org:
        raise NotFound("Organization not found")
    ws = await db.get_workspace_by_slug(org.id, workspace_slug)
    if not ws:
        raise NotFound("Workspace not found")
    # Verify membership
    membership = await db.get_ws_membership(ws.id, user.id)
    org_membership = await db.get_org_membership(org.id, user.id)
    if not membership and (not org_membership or org_membership.role != "org_admin"):
        raise Forbidden("Not a member of this workspace")
    # Set RLS context
    await db.set_workspace_context(ws.id)
    return WorkspaceContext(org=org, workspace=ws, user=user, settings=resolve_settings(org, ws))

WsDep = Annotated[WorkspaceContext, Depends(get_workspace_context)]
```

### Using in Routes

```python
@router.post("/sessions")
async def create_session(
    body: CreateSessionRequest,
    ws: WsDep,
    db: DbDep,
    storage: StorageDep,
):
    session = await db.create_session(ws.workspace.id, body.name, ws.user.id)
    return SessionResponse.model_validate(session)
```

Routes never import adapters directly. They receive typed dependencies.

## Pydantic Models

```python
from pydantic import BaseModel, Field
from datetime import datetime

class CreateSessionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, examples=["prod-incident-2026-03-20"])

class SessionResponse(BaseModel):
    id: str
    name: str
    status: str  # created | parsing | analyzing | ready | error
    file_count: int = 0
    event_count: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}

class IncidentGroup(BaseModel):
    id: str
    name: str
    severity: str
    triggers: list[str]
    effects: list[str]
    evidence: EvidenceBlock
    narrative: str

class AnalysisResults(BaseModel):
    session_id: str
    summary: dict
    incidents: list[IncidentGroup]
    timeline: list[dict]
    cascades: list[dict]
```

## SSE Streaming (AI Responses)

```python
from fastapi.responses import StreamingResponse
from typing import AsyncGenerator

@router.post("/sessions/{session_id}/explain")
async def explain_incident(
    session_id: str,
    body: ExplainRequest,
    ws: WsDep,
    db: DbDep,
):
    # Build context from analysis (not raw events)
    analysis = await db.get_analysis(session_id)
    context = build_incident_context(analysis, body.prompt)

    # Redact before sending to AI
    redacted = redaction_gate.redact(context, ws.settings)

    async def stream() -> AsyncGenerator[str, None]:
        async for chunk in ai_service.stream(redacted, ws.settings):
            yield f"data: {chunk}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")
```

## Background Jobs

```python
# Small jobs (< 5s): use FastAPI BackgroundTasks
@router.post("/sessions/{session_id}/analyze")
async def trigger_analysis(
    session_id: str,
    background_tasks: BackgroundTasks,
    ws: WsDep,
    db: DbDep,
    queue: QueueDep,
):
    session = await db.get_session(session_id)
    total_size = sum(u.size_bytes for u in session.uploads)

    if total_size < 50_000_000:  # < 50MB: run inline
        background_tasks.add_task(run_analysis, session_id, db)
    else:  # Large: queue for worker
        await queue.enqueue("analyze", {"session_id": session_id})

    await db.update_session_status(session_id, "analyzing")
    return {"status": "analyzing"}
```

## WebSocket Notifications

```python
from fastapi import WebSocket
from collections import defaultdict

# Simple in-memory pub/sub (replace with Redis pub/sub in production)
ws_connections: dict[str, list[WebSocket]] = defaultdict(list)

@router.websocket("/ws/{workspace_slug}")
async def websocket_endpoint(websocket: WebSocket, workspace_slug: str):
    await websocket.accept()
    ws_connections[workspace_slug].append(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keep alive
    except WebSocketDisconnect:
        ws_connections[workspace_slug].remove(websocket)

# Called from analysis pipeline when done
async def notify_workspace(workspace_slug: str, event: dict):
    for ws in ws_connections.get(workspace_slug, []):
        await ws.send_json(event)
```

## Middleware

### Request ID

```python
import uuid
import structlog
from starlette.middleware.base import BaseHTTPMiddleware

class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request_id = f"req_{uuid.uuid4().hex[:8]}"
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        return response
```

## Error Handling

```python
from fastapi import HTTPException

class NotFound(HTTPException):
    def __init__(self, detail: str = "Not found"):
        super().__init__(status_code=404, detail=detail)

class Forbidden(HTTPException):
    def __init__(self, detail: str = "Forbidden"):
        super().__init__(status_code=403, detail=detail)

class RateLimited(HTTPException):
    def __init__(self):
        super().__init__(status_code=429, detail="Rate limit exceeded")

# Global handler for consistent JSON format
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "request_id": structlog.contextvars.get_contextvars().get("request_id")},
    )

# Catch unhandled exceptions
@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    logger.error("unhandled_exception", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "request_id": structlog.contextvars.get_contextvars().get("request_id")},
    )
```

Never expose stack traces in production responses.

## Testing

```python
import pytest
from httpx import AsyncClient, ASGITransport
from main import create_app

@pytest.fixture
async def client():
    app = create_app()
    # Override dependencies for testing
    app.dependency_overrides[get_database] = lambda: SQLiteDB(":memory:")
    app.dependency_overrides[get_auth_provider] = lambda: NoAuthProvider()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

async def test_create_session(client):
    r = await client.post("/api/v1/sessions", json={"name": "test-incident"})
    assert r.status_code == 200
    assert r.json()["name"] == "test-incident"
    assert r.json()["status"] == "created"

async def test_workspace_isolation(client):
    # Create session in workspace A
    # Try to access from workspace B → 403
    ...
```

## Gotchas

- **lifespan replaces on_startup/on_shutdown** — the old decorators are deprecated in FastAPI 0.100+
- **Depends() only works in route functions** — cannot be used in utility functions. Pass dependencies explicitly.
- **async def vs def routes**: `async def` for I/O-bound (DB, AI calls). `def` for CPU-bound (runs in threadpool automatically).
- **StreamingResponse must yield strings for SSE**, not bytes. Use `media_type="text/event-stream"`.
- **CORS must set allow_credentials=True** for cookie auth to work cross-origin.
- **Path parameters with slashes** need `path` converter: `{file_path:path}`.
- **Pydantic V2**: use `model_validate()` not `from_orm()`, `model_config` not `class Config`.
- **Background tasks run after response is sent** — don't use them for operations that need to report status.
- **WebSocket connections don't go through middleware** — auth must be handled in the WebSocket handler itself.
