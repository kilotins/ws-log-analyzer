# Auth Implementation

## Three Auth Modes

LogPilot supports three auth modes, selected by `LOGPILOT_AUTH_BACKEND` setting:

| Mode | When | How it works |
|------|------|-------------|
| `none` (default) | Laptop, single user | Auto-returns default local user. No login screen. |
| `local` | Team server | Email + bcrypt password. JWT in httpOnly cookie. |
| `oidc` | Enterprise / SaaS | Azure AD / Google / Okta via authorization code + PKCE. |

## AuthProvider Protocol

```python
from typing import Protocol
from fastapi import Request

class AuthProvider(Protocol):
    async def authenticate(self, request: Request) -> AuthUser: ...
    async def get_login_url(self, redirect: str) -> str: ...
    async def handle_callback(self, request: Request) -> AuthUser: ...
```

### NoAuthProvider

```python
class NoAuthProvider:
    """Laptop mode. No login, no friction."""

    async def authenticate(self, request: Request) -> AuthUser:
        return AuthUser(id=LOCAL_USER_ID, email="local@logpilot", name="Local User")

    async def get_login_url(self, redirect: str) -> str:
        return redirect  # no login needed

    async def handle_callback(self, request: Request) -> AuthUser:
        return await self.authenticate(request)
```

### LocalAuthProvider

```python
class LocalAuthProvider:
    """Email + password auth with bcrypt."""

    async def authenticate(self, request: Request) -> AuthUser:
        token = request.cookies.get("logpilot_session")
        if not token:
            raise HTTPException(401, "Not authenticated")
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        return AuthUser(id=payload["sub"], email=payload["email"], name=payload["name"])

    async def login(self, email: str, password: str, db: Database) -> tuple[str, str]:
        user = await db.get_user_by_email(email)
        if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            raise HTTPException(401, "Invalid credentials")
        access_token = create_jwt(user, expires_in=timedelta(minutes=15))
        refresh_token = create_jwt(user, expires_in=timedelta(days=7))
        return access_token, refresh_token
```

### OIDCProvider

```python
class OIDCProvider:
    """OpenID Connect for Azure AD, Google, Okta."""

    def __init__(self, issuer: str, client_id: str, client_secret: str):
        self.issuer = issuer
        self.client_id = client_id
        # Discover endpoints from .well-known/openid-configuration
        self.discovery_url = f"{issuer}/.well-known/openid-configuration"

    async def get_login_url(self, redirect: str) -> str:
        # Authorization code + PKCE flow
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64url(sha256(code_verifier))
        return f"{self.authorize_endpoint}?response_type=code&client_id={self.client_id}&redirect_uri={redirect}&code_challenge={code_challenge}&code_challenge_method=S256&scope=openid email profile"

    async def handle_callback(self, request: Request) -> AuthUser:
        code = request.query_params["code"]
        # Exchange code for tokens
        tokens = await self._exchange_code(code)
        # Validate ID token
        id_token = jwt.decode(tokens["id_token"], ...)
        # Provision user if first login
        user = await db.get_or_create_user(
            email=id_token["email"],
            name=id_token["name"],
            auth_provider="oidc",
            auth_subject=id_token["sub"],
        )
        return user
```

## API Key Auth

API keys are a separate auth path from user sessions:

```python
async def get_current_user(request: Request) -> AuthUser:
    # 1. Check for API key
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer lp_"):
        return await authenticate_api_key(auth_header[7:])

    # 2. Fall back to session auth (cookie)
    return await auth_provider.authenticate(request)

async def authenticate_api_key(key: str) -> AuthUser:
    prefix = key[:12]  # "lp_live_a3f2"
    api_key = await db.get_api_key_by_prefix(prefix)
    if not api_key or not bcrypt.checkpw(key.encode(), api_key.key_hash.encode()):
        raise HTTPException(401, "Invalid API key")
    if api_key.expires_at and api_key.expires_at < utcnow():
        raise HTTPException(401, "API key expired")
    await db.update_api_key_last_used(api_key.id)
    return AuthUser(id=api_key.created_by, workspace_id=api_key.workspace_id, scopes=api_key.scopes)
```

### Key Format
- Prefix: `lp_live_` (production) or `lp_test_` (staging)
- Full key: `lp_live_a3f2b8c1d9e0f7...` (32+ chars)
- Only shown once at creation — stored as bcrypt hash
- Scopes: `ingest`, `read`, `analyze`, `admin`

## Session Management

- **Access token**: JWT, 15 min expiry, in httpOnly secure cookie
- **Refresh token**: JWT, 7 day expiry, separate httpOnly cookie
- **CSRF**: SameSite=Lax (blocks cross-origin POST)
- **Rotation**: refresh token rotated on each use (old one invalidated)

```python
def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    response.set_cookie("logpilot_session", access_token, httponly=True, secure=True, samesite="lax", max_age=900)
    response.set_cookie("logpilot_refresh", refresh_token, httponly=True, secure=True, samesite="lax", max_age=604800)
```

## OIDC Provider Specifics

### Azure AD
```
issuer: https://login.microsoftonline.com/{tenant_id}/v2.0
client_id: from Azure App Registration
scopes: openid email profile
```

### Google
```
issuer: https://accounts.google.com
client_id: from Google Cloud Console
scopes: openid email profile
```

## Testing

```python
# Test all three auth modes
@pytest.fixture(params=["none", "local", "oidc"])
def auth_provider(request):
    if request.param == "none":
        return NoAuthProvider()
    elif request.param == "local":
        return LocalAuthProvider(secret_key="test")
    else:
        return MockOIDCProvider()

# Test API key scopes
async def test_api_key_ingest_only(client, api_key_ingest):
    # Can upload
    r = await client.post("/api/v1/ingest", headers={"Authorization": f"Bearer {api_key_ingest}"}, files={"file": b"log data"})
    assert r.status_code == 200
    # Cannot delete
    r = await client.delete("/api/v1/sessions/abc", headers={"Authorization": f"Bearer {api_key_ingest}"})
    assert r.status_code == 403
```

## Gotchas

- PKCE is **required** for public clients (SPA) — no client secret in browser
- Refresh token rotation prevents token theft but requires DB tracking
- API keys and user sessions are **separate auth paths** — never mix them
- NoAuth mode still creates user/workspace records (for data model consistency)
- JWT secret key must be set via env var in production — never hardcode
- OIDC discovery document should be cached (TTL: 1 hour)
