# Database Adapter Pattern

## Overview

LogPilot uses a Protocol-based adapter pattern for database access:
- **Protocol** defines the interface (what operations exist)
- **SQLiteDB** implements it for local/laptop mode
- **PostgresDB** implements it for team/SaaS mode
- Routes and services only use the Protocol — they never know which backend is active

Selection happens at startup based on `LOGPILOT_DATABASE_URL`:
- `sqlite:///...` → SQLiteDB
- `postgres://...` → PostgresDB

## Protocol Interface

```python
from typing import Protocol

class Database(Protocol):
    # Connection lifecycle
    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...
    async def execute(self, query: str, *args) -> None: ...

    # Organizations
    async def create_org(self, name: str, slug: str) -> Organization: ...
    async def get_org_by_slug(self, slug: str) -> Organization | None: ...
    async def get_org(self, org_id: str) -> Organization | None: ...

    # Workspaces
    async def create_workspace(self, org_id: str, name: str, slug: str) -> Workspace: ...
    async def get_workspace_by_slug(self, org_id: str, slug: str) -> Workspace | None: ...
    async def get_workspace(self, ws_id: str) -> Workspace | None: ...
    async def set_workspace_context(self, ws_id: str) -> None: ...

    # Users
    async def create_user(self, email: str, name: str, **kwargs) -> User: ...
    async def get_user_by_email(self, email: str) -> User | None: ...

    # Memberships
    async def add_org_member(self, org_id: str, user_id: str, role: str) -> None: ...
    async def add_ws_member(self, ws_id: str, user_id: str, role: str) -> None: ...
    async def get_org_membership(self, org_id: str, user_id: str) -> OrgMembership | None: ...
    async def get_ws_membership(self, ws_id: str, user_id: str) -> WsMembership | None: ...

    # Sessions
    async def create_session(self, ws_id: str, name: str, user_id: str) -> Session: ...
    async def get_session(self, session_id: str) -> Session | None: ...
    async def list_sessions(self, ws_id: str) -> list[Session]: ...
    async def delete_session(self, session_id: str) -> None: ...
    async def update_session_status(self, session_id: str, status: str) -> None: ...

    # Analysis
    async def save_analysis(self, session_id: str, results: dict) -> None: ...
    async def get_analysis(self, session_id: str) -> dict | None: ...

    # AI Conversations
    async def save_ai_conversation(self, **kwargs) -> None: ...
    async def get_ai_conversations(self, session_id: str) -> list[dict]: ...

    # API Keys
    async def create_api_key(self, ws_id: str, name: str, key_hash: str, prefix: str, scopes: list[str], user_id: str) -> APIKey: ...
    async def get_api_key_by_prefix(self, prefix: str) -> APIKey | None: ...

    # Audit
    async def insert_audit_log(self, **kwargs) -> None: ...

    # Utility
    async def has_any_org(self) -> bool: ...
```

## Factory

```python
from functools import lru_cache

@lru_cache
def get_database() -> Database:
    url = settings.database_url
    if url.startswith("postgres"):
        return PostgresDB(url)
    return SQLiteDB(url)
```

## SQLite vs Postgres: Key Differences

| Concern | SQLite | Postgres |
|---------|--------|----------|
| UUID type | `TEXT` | `uuid` (native) |
| UUID generation | Python `uuid4()` | Python `uuid4()` (not `gen_random_uuid()` for consistency) |
| Array type | `JSON` (stored as text) | `text[]` (native array) |
| JSON queries | `json_extract(col, '$.key')` | `col->>'key'` or `col @> '...'` |
| Timestamps | `TEXT` (ISO 8601 string) | `timestamptz` (native) |
| Row-Level Security | Not available — use WHERE clauses | `CREATE POLICY ... USING (...)` |
| Concurrency | WAL mode, single writer | Full MVCC, concurrent writers |
| Connection | `aiosqlite`, single connection | `asyncpg`, connection pool (2-10) |
| GIN indexes | Not available | `CREATE INDEX ... USING GIN (jsonb_col)` |

### Critical Rule

**Always generate UUIDs in Python**, not in the database. This ensures both backends produce identical IDs:

```python
import uuid

async def create_session(self, ws_id: str, name: str, user_id: str) -> Session:
    session_id = str(uuid.uuid4())
    await self.execute(
        "INSERT INTO sessions (id, workspace_id, name, created_by) VALUES (?, ?, ?, ?)",
        session_id, ws_id, name, user_id,
    )
    return Session(id=session_id, workspace_id=ws_id, name=name, ...)
```

## SQLite Implementation

```python
import aiosqlite

class SQLiteDB:
    def __init__(self, url: str):
        self.path = url.replace("sqlite:///", "")
        self.db: aiosqlite.Connection | None = None

    async def connect(self):
        self.db = await aiosqlite.connect(self.path)
        self.db.row_factory = aiosqlite.Row
        await self.db.execute("PRAGMA journal_mode=WAL")
        await self.db.execute("PRAGMA foreign_keys=ON")

    async def disconnect(self):
        if self.db:
            await self.db.close()

    async def set_workspace_context(self, ws_id: str):
        # SQLite has no RLS — store context for manual WHERE clauses
        self._current_workspace_id = ws_id

    async def list_sessions(self, ws_id: str) -> list[Session]:
        # Manual workspace filtering (no RLS)
        cursor = await self.db.execute(
            "SELECT * FROM sessions WHERE workspace_id = ? ORDER BY created_at DESC",
            (ws_id,),
        )
        rows = await cursor.fetchall()
        return [Session(**dict(row)) for row in rows]
```

## Postgres Implementation

```python
import asyncpg

class PostgresDB:
    def __init__(self, url: str):
        self.url = url
        self.pool: asyncpg.Pool | None = None

    async def connect(self):
        self.pool = await asyncpg.create_pool(self.url, min_size=2, max_size=10)

    async def disconnect(self):
        if self.pool:
            await self.pool.close()

    async def set_workspace_context(self, ws_id: str):
        # RLS enforcement — sets context for all queries in this connection
        conn = self._current_connection
        await conn.execute(f"SET LOCAL app.current_workspace_id = '{ws_id}'")

    async def list_sessions(self, ws_id: str) -> list[Session]:
        # RLS handles filtering — no WHERE needed (but we add it for safety)
        rows = await self.pool.fetch(
            "SELECT * FROM sessions WHERE workspace_id = $1 ORDER BY created_at DESC",
            ws_id,
        )
        return [Session(**dict(row)) for row in rows]
```

## Alembic Migrations

Single migration chain that works for both backends:

```python
# migrations/versions/001_initial_schema.py
from alembic import op
import sqlalchemy as sa

def upgrade():
    # Tables use TEXT for UUIDs (works on both SQLite and Postgres)
    op.create_table("organizations",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("slug", sa.Text, unique=True, nullable=False),
        sa.Column("plan", sa.Text, server_default="free"),
        sa.Column("settings", sa.JSON, server_default="{}"),
        sa.Column("created_at", sa.Text, nullable=False),  # ISO string for both
    )

    # Postgres-specific: RLS
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE sessions ENABLE ROW LEVEL SECURITY")
        op.execute("""
            CREATE POLICY workspace_isolation ON sessions
            USING (workspace_id = current_setting('app.current_workspace_id'))
        """)

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS workspace_isolation ON sessions")
    op.drop_table("organizations")
```

### Migration Rules

- **Naming**: `001_initial_schema.py`, `002_add_api_keys.py`, `003_add_audit_log.py`
- **Use TEXT for UUIDs** — works on both backends
- **Use sa.JSON for JSONB** — Alembic maps it correctly per dialect
- **Dialect checks**: `if op.get_bind().dialect.name == "postgresql"` for Postgres-only features
- **Always test both backends**: CI runs migrations against SQLite AND Postgres

## Row-Level Security (Postgres)

```sql
-- Applied to ALL workspace-scoped tables
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Same policy pattern for each
CREATE POLICY workspace_isolation ON sessions
    USING (workspace_id = current_setting('app.current_workspace_id')::text);
```

**Setting context per request:**
```python
# In get_workspace_context() dependency
await db.set_workspace_context(workspace.id)
# Now all queries on RLS-enabled tables are automatically filtered
```

**SQLite equivalent:** Every query includes `WHERE workspace_id = ?` explicitly. The adapter handles this — routes don't know.

## JSONB Query Patterns

Analysis results are stored as JSONB. Query patterns differ:

```python
# Postgres: native JSONB operators
"SELECT * FROM analyses WHERE results->'summary'->>'total_errors' > '100'"
"SELECT * FROM analyses WHERE incidents @> '[{\"severity\": \"critical\"}]'"

# SQLite: json_extract
"SELECT * FROM analyses WHERE CAST(json_extract(results, '$.summary.total_errors') AS INTEGER) > 100"
# For complex queries: fetch + Python-side filtering
```

### Index (Postgres only)

```sql
CREATE INDEX idx_analyses_incidents ON analyses USING GIN (incidents);
```

## Testing Strategy

### Parametrized Fixtures (same test, both backends)

```python
import pytest

@pytest.fixture(params=["sqlite", "postgres"])
async def db(request, tmp_path):
    if request.param == "sqlite":
        database = SQLiteDB(f"sqlite:///{tmp_path}/test.db")
    else:
        database = PostgresDB("postgres://localhost:5432/logpilot_test")
    await database.connect()
    await run_migrations(database)
    yield database
    await database.disconnect()

async def test_create_and_get_session(db):
    org = await db.create_org("Test Org", "test")
    ws = await db.create_workspace(org.id, "DevOps", "devops")
    user = await db.create_user("test@example.com", "Test User")

    session = await db.create_session(ws.id, "incident-1", user.id)
    retrieved = await db.get_session(session.id)

    assert retrieved is not None
    assert retrieved.name == "incident-1"
    assert retrieved.workspace_id == ws.id

async def test_workspace_isolation(db):
    # Setup: two workspaces
    org = await db.create_org("Test", "test")
    ws_a = await db.create_workspace(org.id, "A", "a")
    ws_b = await db.create_workspace(org.id, "B", "b")
    user = await db.create_user("test@example.com", "Test")

    # Create session in workspace A
    await db.create_session(ws_a.id, "session-a", user.id)

    # Query from workspace B context
    await db.set_workspace_context(ws_b.id)
    sessions = await db.list_sessions(ws_b.id)

    # Must not see workspace A's session
    assert len(sessions) == 0
```

### CI: Docker Postgres

```yaml
# .github/workflows/test.yml
services:
  postgres:
    image: postgres:16
    env:
      POSTGRES_DB: logpilot_test
      POSTGRES_PASSWORD: test
    ports:
      - 5432:5432
```

## Checklist: Adding a New Table

1. Add methods to `Database` Protocol
2. Implement in `SQLiteDB` (with manual WHERE for workspace scope)
3. Implement in `PostgresDB` (with RLS policy if workspace-scoped)
4. Create Alembic migration (with dialect check for RLS)
5. Add parametrized tests (both backends)
6. Run `pytest --db=sqlite` and `pytest --db=postgres` locally
7. Verify CI passes on both

## Gotchas

- **SQLite WAL mode** must be enabled explicitly (`PRAGMA journal_mode=WAL`). Without it, concurrent reads during writes will fail.
- **SQLite foreign keys** are off by default. Always run `PRAGMA foreign_keys=ON` after connecting.
- **asyncpg uses $1, $2 placeholders**, not `?`. The adapter must handle this difference internally or use a query builder.
- **Postgres RLS applies to the connection, not the query.** If you forget `SET LOCAL`, queries return all rows.
- **SET LOCAL only lasts for the current transaction.** Use it inside a transaction block, or set per-query.
- **Alembic autogenerate** doesn't detect RLS policies or GIN indexes. Add them manually.
- **Don't use ORM (SQLAlchemy models)** — raw SQL with the async driver is simpler and faster for our adapter pattern. The Protocol interface is our abstraction.
- **Test cascade deletes** — verify that deleting a workspace removes all child sessions, analyses, and AI conversations.
