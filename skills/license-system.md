# License System Skill

## Purpose
Offline trial license system for LogPilot. Gates AI features (Claude, Gemini, OpenAI) behind a signed token. Local AI models are always free. All parsing, reports, and export work without a license.

## Token Format

```
LP-1-<base64-payload>.<hmac-signature>
```

- **LP**: LogPilot prefix
- **1**: Token version (for future format changes)
- **base64-payload**: URL-safe base64-encoded JSON
- **hmac-signature**: HMAC-SHA256 hex digest of the payload bytes

### Payload Schema

```json
{
  "name": "Customer Name",
  "exp": 1753488000,
  "feat": ["ai"],
  "tier": "trial"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Customer/organization name |
| `exp` | int | Expiry as Unix timestamp (UTC) |
| `feat` | list[str] | Licensed features: `"ai"` gates all cloud AI providers |
| `tier` | string | `"trial"` (90 days) or `"pro"` (annual) |

## Architecture

### Core: `logpilot/license.py`
Stdlib only (`hmac`, `hashlib`, `base64`, `json`, `time`).

```python
# Key functions
generate_token(name, days, features, tier, secret) -> str
validate_token(token, secret) -> LicenseInfo | None
is_feature_licensed(token, feature, secret) -> bool
days_remaining(token, secret) -> int | None
```

`LicenseInfo` is a dataclass with fields: `name`, `expires`, `features`, `tier`, `valid`, `days_left`.

### Validation Rules
1. Token must start with `LP-1-`
2. Split on `.` → payload + signature
3. Recompute HMAC-SHA256 of payload with secret → compare (constant-time via `hmac.compare_digest`)
4. Decode payload JSON
5. Check `exp` > current UTC time
6. Check requested feature in `feat` list

Return `None` on any validation failure (malformed, tampered, expired). Never raise exceptions — callers check `if result:`.

### Secret Management
- Env var: `LOGPILOT_LICENSE_SECRET`
- Fallback: hardcoded development secret (only for local dev/testing)
- The secret is the same for generation and validation (symmetric HMAC)
- Never log or display the secret

## Generator Script: `scripts/generate_license.py`

```bash
# Generate 90-day trial
python scripts/generate_license.py --name "Acme AB" --days 90

# Generate 365-day pro license with custom secret
LOGPILOT_LICENSE_SECRET=mysecret python scripts/generate_license.py \
  --name "BigCorp" --days 365 --tier pro
```

Output: the token string, ready to copy-paste.

## GUI Integration

### Sidebar (app.py)
- Text input: "License key" (stored in session state + local file)
- Status badge below the input:
  - **Valid**: green badge with customer name + days remaining
  - **Expiring soon** (≤30 days): yellow badge with warning
  - **Expired**: red badge with expiry date
  - **Missing**: gray "No license — AI features disabled"
- License key persisted to `cache/.license_key` (same pattern as API keys)

### AI Gate (app_ai.py)
- Check `is_feature_licensed(token, "ai", secret)` before `call_ai_provider()`
- If not licensed: return early with a message "AI analysis requires a valid license"
- **Bypass for local provider**: `provider == "local"` skips license check
- Gate applies to: incident analysis, cross-system triage, leadership brief

### Expiry Banner (app.py)
- When ≤30 days remaining: `st.warning()` banner at top of page
- Text: "Your trial expires in X days. Contact info@item.no for a full license."
- When expired: `st.error()` banner replacing the warning
- Banner only shown once per session (session state flag)

## CLI Integration (future)
- `logpilot/cli.py` checks license before `--ai` flag processing
- Same `is_feature_licensed()` call
- Token read from env var `LOGPILOT_LICENSE_KEY` or `--license` flag

## Testing

### Unit tests: `tests/test_license.py`
- Generate and validate a valid token
- Expired token returns invalid
- Tampered payload rejected
- Tampered signature rejected
- Malformed token (missing prefix, missing dot, bad base64) returns None
- Feature check: licensed feature returns True, unlicensed returns False
- Days remaining calculation
- Empty/None token returns None
- Wrong secret rejects valid token

### GUI tests: in existing test files
- AI gate blocks when no license
- AI gate allows when valid license
- Local provider bypasses license check
- Expiry banner appears at ≤30 days

## Security Considerations
- HMAC-SHA256 prevents token forgery without the secret
- Constant-time comparison prevents timing attacks
- No network calls — fully offline, no phone-home
- Secret never appears in logs, UI, or error messages
- Token is not encrypted — customer name is visible in base64. This is intentional (transparency)
- For production: rotate secret per major version if needed

## What This System Does NOT Do
- No user accounts or login
- No usage tracking or telemetry
- No feature-level granularity beyond "ai" (kept simple for V1)
- No revocation (token is valid until expiry)
- No network validation or license server
