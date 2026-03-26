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
