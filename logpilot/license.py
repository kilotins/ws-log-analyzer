"""Offline trial license system for LogPilot.

Gates cloud AI features behind a signed HMAC-SHA256 token.
Local AI models are always free. All parsing, reports, and export
work without a license.

Token format: LP-1-<base64-payload>.<hmac-hex-signature>
Payload JSON: {"name": "...", "exp": <unix-ts>, "feat": ["ai"], "tier": "trial"|"pro"}

Activation: set LOGPILOT_REQUIRE_LICENSE=true to enable license checks.
Without that env var, all features are unlocked (developer mode).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass

# ── Constants ────────────────────────────────────────────────────────

TOKEN_PREFIX = "LP-1-"
_ENV_SECRET = "LOGPILOT_LICENSE_SECRET"
_ENV_REQUIRE = "LOGPILOT_REQUIRE_LICENSE"
_DEV_SECRET = "logpilot-dev-secret-change-me"


# ── Data ─────────────────────────────────────────────────────────────

@dataclass
class LicenseInfo:
    """Validated license information."""
    name: str
    expires: float
    features: list[str]
    tier: str
    valid: bool
    days_left: int


# ── Secret ───────────────────────────────────────────────────────────

def _get_secret() -> str:
    """Read the signing secret from env var, fall back to dev secret."""
    return os.environ.get(_ENV_SECRET, _DEV_SECRET)


def require_license() -> bool:
    """Return True if license checks are active."""
    return os.environ.get(_ENV_REQUIRE, "").lower() == "true"


# ── Generate ─────────────────────────────────────────────────────────

def generate_token(
    name: str,
    days: int = 90,
    features: list[str] | None = None,
    tier: str = "trial",
    secret: str | None = None,
) -> str:
    """Generate a signed license token.

    Args:
        name: Customer/organization name.
        days: Number of days until expiry.
        features: Licensed features (default: ["ai"]).
        tier: License tier ("trial" or "pro").
        secret: Signing secret (default: from env var).

    Returns:
        Token string in format LP-1-<payload>.<signature>.
    """
    if not name or not name.strip():
        raise ValueError("License name must not be empty")
    if days < 1:
        raise ValueError("License must be valid for at least 1 day")

    secret = secret or _get_secret()
    payload = {
        "name": name.strip(),
        "exp": int(time.time()) + (days * 86400),
        "feat": features or ["ai"],
        "tier": tier,
    }
    payload_bytes = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    signature = hmac.new(
        secret.encode(), payload_bytes, hashlib.sha256
    ).hexdigest()
    return f"{TOKEN_PREFIX}{payload_bytes.decode()}.{signature}"


# ── Validate ─────────────────────────────────────────────────────────

def validate_token(token: str | None, secret: str | None = None) -> LicenseInfo | None:
    """Validate a license token and return info, or None if invalid.

    Never raises exceptions — returns None on any failure.
    """
    if not token or not isinstance(token, str):
        return None

    token = token.strip()
    if not token.startswith(TOKEN_PREFIX):
        return None

    body = token[len(TOKEN_PREFIX):]
    if "." not in body:
        return None

    payload_b64, provided_sig = body.rsplit(".", 1)

    # Verify signature (constant-time comparison)
    secret = secret or _get_secret()
    expected_sig = hmac.new(
        secret.encode(), payload_b64.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_sig, provided_sig):
        return None

    # Decode payload
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return None

    # Validate required fields
    name = payload.get("name")
    exp = payload.get("exp")
    if not name or not isinstance(exp, (int, float)):
        return None

    features = payload.get("feat", [])
    tier = payload.get("tier", "trial")
    now = time.time()
    days_left = max(0, int((exp - now) / 86400))
    valid = exp > now

    return LicenseInfo(
        name=str(name),
        expires=float(exp),
        features=list(features),
        tier=str(tier),
        valid=valid,
        days_left=days_left,
    )


def is_feature_licensed(token: str | None, feature: str = "ai",
                        secret: str | None = None) -> bool:
    """Check if a specific feature is licensed. Returns False on any error."""
    if not require_license():
        return True  # License checks disabled — all features unlocked
    info = validate_token(token, secret)
    if not info or not info.valid:
        return False
    return feature in info.features


def days_remaining(token: str | None, secret: str | None = None) -> int | None:
    """Return days remaining on a license, or None if invalid."""
    info = validate_token(token, secret)
    if not info:
        return None
    return info.days_left


# ── Secret Generation ────────────────────────────────────────────────

def generate_secret() -> str:
    """Generate a cryptographically secure secret for license signing."""
    import secrets
    return secrets.token_urlsafe(32)
