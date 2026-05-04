"""Offline trial license system for LogPilot.

Gates cloud AI features behind a signed HMAC-SHA256 token.
Local AI models are always free. All parsing, reports, and export
work without a license.

Token format: LP-1-<base64-payload>.<hmac-hex-signature>
Payload JSON: {"name": "...", "exp": <unix-ts>, "feat": ["ai"], "tier": "trial"|"pro",
               "providers": [...], "models": [...]}

Activation: set LOGPILOT_REQUIRE_LICENSE=true to enable license checks.
Without that env var, all features are unlocked (developer mode).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass

_log = logging.getLogger(__name__)
_logged_secret_error = False  # module-level: log the misconfiguration only once per process

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
    providers: list[str]  # ["claude"] for trial, ["claude", "gemini", "openai"] for pro
    models: list[str]     # ["haiku"] for trial, ["all"] for pro


# ── Secret ───────────────────────────────────────────────────────────

def _get_secret() -> str:
    """Read the signing secret from env var, fall back to dev secret."""
    secret = os.environ.get(_ENV_SECRET, "").strip()
    if secret:
        return secret
    if require_license():
        raise RuntimeError(
            f"{_ENV_SECRET} must be set when {_ENV_REQUIRE}=true"
        )
    return _DEV_SECRET


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
    providers: list[str] | None = None,
    models: list[str] | None = None,
) -> str:
    """Generate a signed license token.

    Args:
        name: Customer/organization name.
        days: Number of days until expiry.
        features: Licensed features (default: ["ai"]).
        tier: License tier ("trial" or "pro").
        secret: Signing secret (default: from env var).
        providers: Allowed AI providers (default: ["claude"] for trial, ["claude","gemini","openai"] for pro).
        models: Allowed models (default: ["haiku"] for trial, ["all"] for pro).

    Returns:
        Token string in format LP-1-<payload>.<signature>.
    """
    if not name or not name.strip():
        raise ValueError("License name must not be empty")
    if days < 1:
        raise ValueError("License must be valid for at least 1 day")

    # Apply tier-based defaults when not explicitly provided
    if providers is None:
        providers = ["claude", "gemini", "openai"] if tier == "pro" else ["claude"]
    if models is None:
        models = ["all"] if tier == "pro" else ["haiku"]

    secret = secret or _get_secret()
    payload = {
        "name": name.strip(),
        "exp": int(time.time()) + (days * 86400),
        "feat": features or ["ai"],
        "tier": tier,
        "providers": providers,
        "models": models,
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
    global _logged_secret_error

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
    try:
        secret = secret or _get_secret()
    except RuntimeError as ex:
        if not _logged_secret_error:
            _log.error("License check failed (env misconfigured): %s", ex)
            _logged_secret_error = True
        return None
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
    # Backwards compat: old tokens without providers/models default to trial restrictions
    providers = payload.get("providers", ["claude"])
    models = payload.get("models", ["haiku"])
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
        providers=list(providers),
        models=list(models),
    )


def is_feature_licensed(token: str | None, feature: str = "ai",
                        secret: str | None = None) -> bool:
    """Check if a specific feature is licensed. Returns False on any error."""
    global _logged_secret_error

    if not require_license():
        return True  # License checks disabled — all features unlocked
    try:
        info = validate_token(token, secret)
    except RuntimeError as ex:
        if not _logged_secret_error:
            _log.error("License check failed (env misconfigured): %s", ex)
            _logged_secret_error = True
        return False
    if not info or not info.valid:
        return False
    return feature in info.features


def days_remaining(token: str | None, secret: str | None = None) -> int | None:
    """Return days remaining on a license, or None if invalid."""
    info = validate_token(token, secret)
    if not info:
        return None
    return info.days_left


def allowed_providers(token: str | None, secret: str | None = None) -> list[str]:
    """Return list of allowed provider names. Returns all if license not required.

    Local AI is always free and always included in the result.
    """
    if not require_license():
        return ["claude", "gemini", "openai", "local"]
    info = validate_token(token, secret)
    if not info or not info.valid:
        return ["local"]  # local always free
    return info.providers + ["local"]  # local always included


def is_model_allowed(token: str | None, model: str, secret: str | None = None) -> bool:
    """Check if a specific model is allowed by the license."""
    if not require_license():
        return True
    info = validate_token(token, secret)
    if not info or not info.valid:
        return False
    if "all" in info.models:
        return True
    # Check if model name contains any allowed model substring
    model_lower = model.lower()
    return any(m.lower() in model_lower for m in info.models)


# ── Secret Generation ────────────────────────────────────────────────

def generate_secret() -> str:
    """Generate a cryptographically secure secret for license signing."""
    import secrets
    return secrets.token_urlsafe(32)


# ── Pure AI License Check (Framework-agnostic) ───────────────────────

_LICENSE_MSG = (
    "AI analysis requires a valid license key. "
    "Enter one in the sidebar or contact eric@item.no."
)


def _check_ai_license(
    token: str | None,
    provider: str = "",
    model: str = "",
) -> tuple[bool, str | None]:
    """Pure license check for AI features — no Streamlit dependency.

    Suitable for use in FastAPI handlers (pass token from Authorization header)
    or any context where ``st.session_state`` is not available.

    Args:
        token: License token string (or None / empty string when absent).
        provider: AI provider name (e.g. ``"claude"``, ``"gemini"``).
                  Pass ``""`` to skip provider check.
        model: Model identifier (e.g. ``"claude-sonnet-4-6"``).
               Pass ``""`` to skip model check.

    Returns:
        ``(True, None)`` when the action is permitted.
        ``(False, error_message)`` when it is blocked.
    """
    if not token:
        return (False, "No license key provided")

    if not is_feature_licensed(token):
        return (False, _LICENSE_MSG)

    if provider and provider != "local":
        providers = allowed_providers(token)
        if provider not in providers:
            return (
                False,
                f"Provider '{provider}' requires a Pro license. "
                "Contact eric@item.no to upgrade.",
            )

    if model and not is_model_allowed(token, model):
        return (
            False,
            f"Model '{model}' requires a Pro license. "
            "Contact eric@item.no to upgrade.",
        )

    return (True, None)
