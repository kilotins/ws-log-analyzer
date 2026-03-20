# Workspace Model

## Three-Layer Hierarchy

```
Organization (the customer)
├── Workspace (data isolation boundary)
│   ├── Member (user + role)
│   ├── Sessions (log analyses)
│   ├── AI conversations
│   └── Audit log
└── Workspace
    ├── Member
    └── ...
```

## Organization

- The paying customer (KLP, Acme, etc.)
- Owns: billing, OIDC/IdP configuration, org-level default settings
- Roles: `org_admin` (manages everything), `member` (uses workspaces)
- In SaaS: one org per customer. Self-hosted: typically one org per installation.
- Laptop mode: one auto-created org ("Local")

## Workspace

- **The data isolation boundary.** All data belongs to exactly one workspace.
- Has own settings (AI provider keys, retention policy) — overrides org defaults
- Contains: sessions, uploads, analyses, AI conversations, audit log entries
- Data never leaks between workspaces — enforced by RLS (Postgres) or WHERE clause (SQLite)
- URL: `/:orgSlug/:wsSlug/...`

## Members

- A user + role in a specific workspace
- Roles: `admin` (manage workspace settings, members), `member` (full analysis access), `viewer` (read-only)
- Same user can be in multiple workspaces with different roles
- Example: Erik is admin in DevOps, viewer in SecOps

## Settings Inheritance

Organization settings are defaults. Workspace settings override them:

```python
def resolve_settings(org: Organization, ws: Workspace) -> EffectiveSettings:
    base = org.settings.copy()
    base.update(ws.settings)  # workspace wins
    return EffectiveSettings(**base)

# Example:
# org.settings  = {"ai_provider": "claude", "ai_key": "sk-org-..."}
# ws.settings   = {"ai_key": "sk-secops-..."}
# effective     = {"ai_provider": "claude", "ai_key": "sk-secops-..."}
```

Merge is **shallow** (one level). Nested dicts are replaced entirely, not deep-merged.

## Auto-Setup (Laptop / NoAuth Mode)

At first start, if no org exists, create everything automatically:

```python
async def ensure_local_setup(db: Database):
    """Called at startup when auth_backend == 'none'.
    User goes straight to work — no setup screens."""
    if await db.has_any_org():
        return
    org = await db.create_org(name="Local", slug="local")
    ws = await db.create_workspace(org.id, name="Personal", slug="personal")
    user = await db.create_user(email="local@logpilot", name="Local User")
    await db.add_org_member(org.id, user.id, role="org_admin")
    await db.add_ws_member(ws.id, user.id, role="admin")
```

The user sees: app starts → already logged in → already in "Personal" workspace → upload logs. Zero friction.

## Workspace Context in API

Every workspace-scoped request goes through `get_workspace_context()`:

```python
async def get_workspace_context(
    user: AuthUser = Depends(get_current_user),
    org_slug: str = Path(...),
    workspace_slug: str = Path(...),
    db: Database = Depends(get_database),
) -> WorkspaceContext:
    # 1. Resolve org
    org = await db.get_org_by_slug(org_slug)
    if not org:
        raise HTTPException(404, "Organization not found")

    # 2. Verify org membership
    org_member = await db.get_org_membership(org.id, user.id)
    if not org_member:
        raise HTTPException(403, "Not a member of this organization")

    # 3. Resolve workspace
    ws = await db.get_workspace_by_slug(org.id, workspace_slug)
    if not ws:
        raise HTTPException(404, "Workspace not found")

    # 4. Verify workspace membership (or org_admin bypass)
    ws_member = await db.get_ws_membership(ws.id, user.id)
    if not ws_member and org_member.role != "org_admin":
        raise HTTPException(403, "Not a member of this workspace")

    # 5. Set RLS context (Postgres)
    await db.set_workspace_context(ws.id)

    # 6. Resolve effective settings
    settings = resolve_settings(org, ws)

    return WorkspaceContext(org=org, workspace=ws, user=user, role=ws_member.role if ws_member else "org_admin", settings=settings)
```

## API Key Context

API keys are scoped to a workspace — no org/workspace resolution needed:

```python
async def get_workspace_from_api_key(api_key: APIKey, db: Database) -> WorkspaceContext:
    ws = await db.get_workspace(api_key.workspace_id)
    org = await db.get_org(ws.org_id)
    await db.set_workspace_context(ws.id)
    return WorkspaceContext(org=org, workspace=ws, user=api_key.created_by, role="api_key", settings=resolve_settings(org, ws))
```

## Data Lifecycle

- **Delete workspace** → cascading delete of all sessions, uploads, analyses, AI conversations, audit log entries, API keys
- **Delete org** → cascading delete of all workspaces (and all their data)
- **Remove user from workspace** → their sessions remain (owned by workspace, not user)
- **Delete user** → remove from all memberships. Sessions remain (workspace-owned).

## RLS Enforcement

### Postgres
```sql
-- Every workspace-scoped table has this policy
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON sessions
    USING (workspace_id = current_setting('app.current_workspace_id')::uuid);
```

### SQLite (no RLS — adapter handles it)
```python
class SQLiteDB:
    async def get_sessions(self, workspace_id: str) -> list[Session]:
        # WHERE clause added explicitly — not RLS
        return await self.fetchall(
            "SELECT * FROM sessions WHERE workspace_id = ? ORDER BY created_at DESC",
            (workspace_id,)
        )
```

## Gotchas

- **Workspace slug is unique per org**, not globally. Two orgs can both have a "devops" workspace.
- **org_admin bypasses workspace membership** — they can access all workspaces in their org without explicit membership.
- **Local mode auto-setup runs once** — if the DB already has an org, it's skipped. Delete the DB to reset.
- **Settings merge is shallow** — `{"ai": {"key": "x", "model": "y"}}` in org, `{"ai": {"key": "z"}}` in workspace → effective: `{"ai": {"key": "z"}}` (model lost). Keep settings flat.
- **Cascade deletes are irreversible** — add confirmation UI and soft-delete grace period before hard delete.
