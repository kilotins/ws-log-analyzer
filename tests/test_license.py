"""Unit tests for the license system (logpilot/license.py)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from logpilot.license import (
    LicenseInfo,
    generate_token,
    validate_token,
    is_feature_licensed,
    days_remaining,
    generate_secret,
    require_license,
    allowed_providers,
    is_model_allowed,
    TOKEN_PREFIX,
)

_TEST_SECRET = "test-secret-for-unit-tests"


# ── Generation ───────────────────────────────────────────────────────

class TestGenerateToken:
    def test_generates_valid_token(self):
        token = generate_token("Acme AB", days=90, secret=_TEST_SECRET)
        assert token.startswith(TOKEN_PREFIX)
        assert "." in token[len(TOKEN_PREFIX):]

    def test_generated_token_validates(self):
        token = generate_token("Acme AB", days=90, secret=_TEST_SECRET)
        info = validate_token(token, secret=_TEST_SECRET)
        assert info is not None
        assert info.valid is True
        assert info.name == "Acme AB"
        assert info.tier == "trial"
        assert "ai" in info.features
        assert 89 <= info.days_left <= 90

    def test_custom_tier(self):
        token = generate_token("BigCorp", days=365, tier="pro", secret=_TEST_SECRET)
        info = validate_token(token, secret=_TEST_SECRET)
        assert info.tier == "pro"
        assert 364 <= info.days_left <= 365

    def test_custom_features(self):
        token = generate_token("Test", days=30, features=["ai", "export"],
                               secret=_TEST_SECRET)
        info = validate_token(token, secret=_TEST_SECRET)
        assert info.features == ["ai", "export"]

    def test_empty_name_raises(self):
        with pytest.raises(ValueError, match="empty"):
            generate_token("", secret=_TEST_SECRET)

    def test_whitespace_name_raises(self):
        with pytest.raises(ValueError, match="empty"):
            generate_token("   ", secret=_TEST_SECRET)

    def test_zero_days_raises(self):
        with pytest.raises(ValueError, match="at least 1"):
            generate_token("Test", days=0, secret=_TEST_SECRET)

    def test_name_is_stripped(self):
        token = generate_token("  Acme AB  ", days=30, secret=_TEST_SECRET)
        info = validate_token(token, secret=_TEST_SECRET)
        assert info.name == "Acme AB"


# ── Validation ───────────────────────────────────────────────────────

class TestValidateToken:
    def test_none_returns_none(self):
        assert validate_token(None, secret=_TEST_SECRET) is None

    def test_empty_string_returns_none(self):
        assert validate_token("", secret=_TEST_SECRET) is None

    def test_non_string_returns_none(self):
        assert validate_token(12345, secret=_TEST_SECRET) is None

    def test_wrong_prefix_returns_none(self):
        assert validate_token("XX-1-abc.def", secret=_TEST_SECRET) is None

    def test_no_dot_returns_none(self):
        assert validate_token("LP-1-nodothere", secret=_TEST_SECRET) is None

    def test_bad_base64_returns_none(self):
        assert validate_token("LP-1-!!!invalid!!!.abcdef", secret=_TEST_SECRET) is None

    def test_tampered_payload_rejected(self):
        token = generate_token("Acme AB", days=90, secret=_TEST_SECRET)
        body = token[len(TOKEN_PREFIX):]
        payload_b64, sig = body.rsplit(".", 1)
        # Decode, tamper, re-encode
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        payload["name"] = "Evil Corp"
        tampered_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).decode()
        tampered_token = f"{TOKEN_PREFIX}{tampered_b64}.{sig}"
        assert validate_token(tampered_token, secret=_TEST_SECRET) is None

    def test_tampered_signature_rejected(self):
        token = generate_token("Acme AB", days=90, secret=_TEST_SECRET)
        # Flip last char of signature
        tampered = token[:-1] + ("a" if token[-1] != "a" else "b")
        assert validate_token(tampered, secret=_TEST_SECRET) is None

    def test_wrong_secret_rejected(self):
        token = generate_token("Acme AB", days=90, secret=_TEST_SECRET)
        assert validate_token(token, secret="wrong-secret") is None

    def test_expired_token_is_invalid(self):
        # Create a token that expired 1 day ago
        secret = _TEST_SECRET
        payload = {
            "name": "Expired Corp",
            "exp": int(time.time()) - 86400,
            "feat": ["ai"],
            "tier": "trial",
        }
        payload_bytes = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
        token = f"{TOKEN_PREFIX}{payload_bytes.decode()}.{sig}"

        info = validate_token(token, secret=secret)
        assert info is not None
        assert info.valid is False
        assert info.days_left == 0
        assert info.name == "Expired Corp"

    def test_whitespace_around_token_is_stripped(self):
        token = generate_token("Acme AB", days=90, secret=_TEST_SECRET)
        info = validate_token(f"  {token}  ", secret=_TEST_SECRET)
        assert info is not None
        assert info.valid is True


# ── Feature Check ────────────────────────────────────────────────────

class TestIsFeatureLicensed:
    def test_licensed_feature_returns_true(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("Test", days=90, features=["ai"], secret=_TEST_SECRET)
        assert is_feature_licensed(token, "ai", secret=_TEST_SECRET) is True

    def test_unlicensed_feature_returns_false(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("Test", days=90, features=["ai"], secret=_TEST_SECRET)
        assert is_feature_licensed(token, "export", secret=_TEST_SECRET) is False

    def test_expired_token_returns_false(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        secret = _TEST_SECRET
        payload = {
            "name": "Expired",
            "exp": int(time.time()) - 86400,
            "feat": ["ai"],
            "tier": "trial",
        }
        payload_bytes = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
        token = f"{TOKEN_PREFIX}{payload_bytes.decode()}.{sig}"
        assert is_feature_licensed(token, "ai", secret=secret) is False

    def test_none_token_returns_false(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        assert is_feature_licensed(None, "ai", secret=_TEST_SECRET) is False

    def test_require_disabled_always_returns_true(self, monkeypatch):
        monkeypatch.delenv("LOGPILOT_REQUIRE_LICENSE", raising=False)
        assert is_feature_licensed(None, "ai", secret=_TEST_SECRET) is True
        assert is_feature_licensed("garbage", "ai", secret=_TEST_SECRET) is True


# ── Days Remaining ───────────────────────────────────────────────────

class TestDaysRemaining:
    def test_valid_token_returns_days(self):
        token = generate_token("Test", days=45, secret=_TEST_SECRET)
        remaining = days_remaining(token, secret=_TEST_SECRET)
        assert 44 <= remaining <= 45

    def test_invalid_token_returns_none(self):
        assert days_remaining("garbage", secret=_TEST_SECRET) is None

    def test_none_token_returns_none(self):
        assert days_remaining(None, secret=_TEST_SECRET) is None


# ── Require License Toggle ───────────────────────────────────────────

class TestRequireLicense:
    def test_false_by_default(self, monkeypatch):
        monkeypatch.delenv("LOGPILOT_REQUIRE_LICENSE", raising=False)
        assert require_license() is False

    def test_true_when_set(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        assert require_license() is True

    def test_true_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "TRUE")
        assert require_license() is True

    def test_false_for_other_values(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "yes")
        assert require_license() is False


# ── Secret Generation ────────────────────────────────────────────────

class TestGenerateSecret:
    def test_generates_string(self):
        secret = generate_secret()
        assert isinstance(secret, str)
        assert len(secret) >= 32

    def test_unique_each_time(self):
        s1 = generate_secret()
        s2 = generate_secret()
        assert s1 != s2


# ── Provider Access ───────────────────────────────────────────────────

class TestProviderAccess:
    def test_trial_allows_claude_and_local(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("Test", days=90, tier="trial", secret=_TEST_SECRET)
        providers = allowed_providers(token, secret=_TEST_SECRET)
        assert "claude" in providers
        assert "local" in providers

    def test_trial_blocks_gemini(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("Test", days=90, tier="trial", secret=_TEST_SECRET)
        providers = allowed_providers(token, secret=_TEST_SECRET)
        assert "gemini" not in providers

    def test_trial_blocks_openai(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("Test", days=90, tier="trial", secret=_TEST_SECRET)
        providers = allowed_providers(token, secret=_TEST_SECRET)
        assert "openai" not in providers

    def test_pro_allows_all_providers(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("BigCorp", days=365, tier="pro", secret=_TEST_SECRET)
        providers = allowed_providers(token, secret=_TEST_SECRET)
        assert "claude" in providers
        assert "gemini" in providers
        assert "openai" in providers
        assert "local" in providers

    def test_no_license_allows_only_local(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        providers = allowed_providers(None, secret=_TEST_SECRET)
        assert providers == ["local"]

    def test_require_disabled_allows_all(self, monkeypatch):
        monkeypatch.delenv("LOGPILOT_REQUIRE_LICENSE", raising=False)
        providers = allowed_providers(None, secret=_TEST_SECRET)
        assert "claude" in providers
        assert "gemini" in providers
        assert "openai" in providers
        assert "local" in providers

    def test_expired_allows_only_local(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        payload = {
            "name": "Expired Corp",
            "exp": int(time.time()) - 86400,
            "feat": ["ai"],
            "tier": "pro",
            "providers": ["claude", "gemini", "openai"],
            "models": ["all"],
        }
        payload_bytes = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        sig = hmac.new(_TEST_SECRET.encode(), payload_bytes, hashlib.sha256).hexdigest()
        token = f"{TOKEN_PREFIX}{payload_bytes.decode()}.{sig}"
        providers = allowed_providers(token, secret=_TEST_SECRET)
        assert providers == ["local"]


# ── Model Access ──────────────────────────────────────────────────────

class TestModelAccess:
    def test_trial_allows_haiku(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("Test", days=90, tier="trial", secret=_TEST_SECRET)
        assert is_model_allowed(token, "claude-3-haiku-20240307", secret=_TEST_SECRET) is True

    def test_trial_blocks_sonnet(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("Test", days=90, tier="trial", secret=_TEST_SECRET)
        assert is_model_allowed(token, "claude-3-5-sonnet-20241022", secret=_TEST_SECRET) is False

    def test_trial_blocks_opus(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("Test", days=90, tier="trial", secret=_TEST_SECRET)
        assert is_model_allowed(token, "claude-3-opus-20240229", secret=_TEST_SECRET) is False

    def test_pro_allows_all_models(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("BigCorp", days=365, tier="pro", secret=_TEST_SECRET)
        assert is_model_allowed(token, "claude-3-haiku-20240307", secret=_TEST_SECRET) is True
        assert is_model_allowed(token, "claude-3-5-sonnet-20241022", secret=_TEST_SECRET) is True
        assert is_model_allowed(token, "claude-3-opus-20240229", secret=_TEST_SECRET) is True
        assert is_model_allowed(token, "gemini-1.5-pro", secret=_TEST_SECRET) is True
        assert is_model_allowed(token, "gpt-4o", secret=_TEST_SECRET) is True

    def test_model_match_is_substring(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        token = generate_token("Test", days=90, tier="trial", secret=_TEST_SECRET)
        # "haiku" substring matches "claude-3-haiku-20240307"
        assert is_model_allowed(token, "claude-3-haiku-20240307", secret=_TEST_SECRET) is True
        # "haiku" does NOT match "claude-3-sonnet-20240229"
        assert is_model_allowed(token, "claude-3-sonnet-20240229", secret=_TEST_SECRET) is False

    def test_no_license_blocks_all(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        assert is_model_allowed(None, "claude-3-haiku-20240307", secret=_TEST_SECRET) is False

    def test_require_disabled_allows_all(self, monkeypatch):
        monkeypatch.delenv("LOGPILOT_REQUIRE_LICENSE", raising=False)
        assert is_model_allowed(None, "claude-3-opus-20240229", secret=_TEST_SECRET) is True
        assert is_model_allowed(None, "gpt-4o", secret=_TEST_SECRET) is True


# ── Missing Secret (P0-2 regression) ─────────────────────────────────

class TestMissingSecret:
    def test_validate_token_returns_none_on_missing_secret(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        monkeypatch.delenv("LOGPILOT_LICENSE_SECRET", raising=False)
        import importlib
        import logpilot.license as lic_mod
        importlib.reload(lic_mod)
        result = lic_mod.validate_token("fake-token")
        assert result is None  # Must not crash

    def test_is_feature_licensed_returns_false_on_missing_secret(self, monkeypatch):
        monkeypatch.setenv("LOGPILOT_REQUIRE_LICENSE", "true")
        monkeypatch.delenv("LOGPILOT_LICENSE_SECRET", raising=False)
        import importlib
        import logpilot.license as lic_mod
        importlib.reload(lic_mod)
        assert lic_mod.is_feature_licensed("fake-token", "ai_analysis") is False


# ── Backwards Compatibility ───────────────────────────────────────────

class TestBackwardsCompat:
    def _make_old_token(self, payload: dict) -> str:
        """Build a token from a raw payload dict (simulates old token format)."""
        payload_bytes = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        sig = hmac.new(_TEST_SECRET.encode(), payload_bytes, hashlib.sha256).hexdigest()
        return f"{TOKEN_PREFIX}{payload_bytes.decode()}.{sig}"

    def test_old_token_without_providers_defaults_to_claude(self):
        # Old token has no "providers" key — should default to ["claude"]
        token = self._make_old_token({
            "name": "OldCustomer",
            "exp": int(time.time()) + 86400,
            "feat": ["ai"],
            "tier": "trial",
        })
        info = validate_token(token, secret=_TEST_SECRET)
        assert info is not None
        assert info.valid is True
        assert info.providers == ["claude"]

    def test_old_token_without_models_defaults_to_haiku(self):
        # Old token has no "models" key — should default to ["haiku"]
        token = self._make_old_token({
            "name": "OldCustomer",
            "exp": int(time.time()) + 86400,
            "feat": ["ai"],
            "tier": "trial",
        })
        info = validate_token(token, secret=_TEST_SECRET)
        assert info is not None
        assert info.valid is True
        assert info.models == ["haiku"]
