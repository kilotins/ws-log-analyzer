"""Tests for M59: PII redaction at multiple levels."""
from __future__ import annotations

import pytest

from logpilot.parser import redact


class TestSecretsLevel:
    """Existing secret redaction (backward compatible)."""

    def test_bearer_token(self):
        text = "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        result = redact(text, level="secrets")
        assert "eyJ" not in result
        assert "REDACTED" in result

    def test_api_key(self):
        text = "api_key=sk-abc123def456"
        result = redact(text, level="secrets")
        assert "sk-abc123" not in result

    def test_password(self):
        text = "password=SuperSecret123!"
        result = redact(text, level="secrets")
        assert "SuperSecret" not in result

    def test_no_redaction_at_none(self):
        text = "password=SuperSecret123!"
        result = redact(text, level="none")
        assert "SuperSecret" in result

    def test_default_level_is_secrets(self):
        text = "password=SuperSecret123!"
        result = redact(text)
        assert "SuperSecret" not in result


class TestPIIStandard:
    """PII redaction at 'standard' level."""

    def test_personnummer(self):
        text = "Bruker 15038812345 har logget inn"
        result = redact(text, level="standard")
        assert "12345" not in result
        assert "150388" in result  # Keep DDMMYY prefix

    def test_orgnummer(self):
        text = "Organisasjon 912345678 registrert"
        result = redact(text, level="standard")
        assert "912345678" not in result
        assert "912" in result  # Keep first 3

    def test_email(self):
        text = "Sendt til test.user@example.com"
        result = redact(text, level="standard")
        assert "test.user@example.com" not in result
        assert "[EMAIL]" in result

    def test_phone_norwegian(self):
        text = "Kontakt: +4791234567"
        result = redact(text, level="standard")
        assert "91234567" not in result
        assert "[PHONE]" in result

    def test_phone_with_spaces(self):
        text = "Ring +47 91 23 45 67"
        result = redact(text, level="standard")
        assert "[PHONE]" in result

    def test_credit_card(self):
        text = "Kort: 4532015112830366"
        result = redact(text, level="standard")
        assert "4532015112830366" not in result
        assert "[CARD]" in result

    def test_iban(self):
        text = "Konto: NO9386011117947"
        result = redact(text, level="standard")
        assert "NO9386011117947" not in result
        assert "[IBAN]" in result

    def test_ipv6(self):
        text = "Connected from 2001:db8:85a3::8a2e:370:7334"
        result = redact(text, level="standard")
        assert "2001:db8" not in result
        assert "[IPv6]" in result

    def test_private_ip_keeps_subnet(self):
        text = "Connected from 10.0.1.50 to 10.0.2.100"
        result = redact(text, level="standard")
        assert "10.0.1.[x]" in result
        assert "10.0.2.[x]" in result
        assert "10.0.1.50" not in result

    def test_192_168_keeps_subnet(self):
        text = "Host: 192.168.1.100"
        result = redact(text, level="standard")
        assert "192.168.1.[x]" in result
        assert "192.168.1.100" not in result

    def test_secrets_also_redacted(self):
        """Standard level includes secret redaction."""
        text = "password=MySecret api_key=abc123 user 15038812345"
        result = redact(text, level="standard")
        assert "MySecret" not in result
        assert "12345" not in result

    def test_normal_text_untouched(self):
        text = "2026-03-23 10:30:00 INFO Application started successfully"
        result = redact(text, level="standard")
        assert result == text

    def test_log_with_mixed_pii(self):
        text = (
            "User 15038812345 (test@example.com) logged in from 10.0.1.50, "
            "card 4532015112830366, phone +4791234567"
        )
        result = redact(text, level="standard")
        assert "12345" not in result
        assert "[EMAIL]" in result
        assert "10.0.1.[x]" in result
        assert "[CARD]" in result
        assert "[PHONE]" in result


class TestStrictLevel:
    """Strict redaction: standard + infrastructure."""

    def test_public_ip_fully_redacted(self):
        text = "Upstream: 159.171.100.25:443"
        result = redact(text, level="strict")
        assert "159.171.100.25" not in result
        assert "[EXT_IP]" in result

    def test_private_ip_keeps_subnet_in_strict(self):
        """Private IPs keep subnet even in strict mode."""
        text = "Backend: 10.0.2.50:8080"
        result = redact(text, level="strict")
        assert "10.0.2.[x]" in result

    def test_username_in_path(self):
        text = "File: /home/test.user/logs/app.log"
        result = redact(text, level="strict")
        assert "test.user" not in result
        assert "[USER]" in result

    def test_user_field(self):
        text = "user=test.user authenticated"
        result = redact(text, level="strict")
        assert "test.user" not in result

    def test_strict_includes_all_lower_levels(self):
        text = (
            "password=Secret123 user 15038812345 from 159.171.100.25 "
            "path /home/admin/logs"
        )
        result = redact(text, level="strict")
        assert "Secret123" not in result  # secrets
        assert "12345" not in result       # PII
        assert "159.171.100.25" not in result  # infra
        assert "admin" not in result       # username


class TestEdgeCases:
    def test_empty_string(self):
        assert redact("", level="strict") == ""

    def test_no_pii_at_standard(self):
        text = "ERROR: Connection refused to backend service"
        assert redact(text, level="standard") == text

    def test_uuid_not_redacted(self):
        """UUIDs should NOT be redacted — needed for trace correlation."""
        text = "trace=a1b2c3d4-1234-5678-9abc-def012345678"
        result = redact(text, level="strict")
        assert "a1b2c3d4-1234-5678-9abc-def012345678" in result

    def test_timestamp_not_redacted(self):
        text = "2026-03-23 10:30:00.123 UTC [1234] LOG: ready"
        result = redact(text, level="strict")
        assert "2026-03-23 10:30:00.123" in result

    def test_port_numbers_not_redacted(self):
        """Port numbers in host:port should not be confused with PII."""
        text = "listening on port 8080"
        result = redact(text, level="standard")
        assert "8080" in result

    def test_localhost_not_redacted(self):
        text = "Connected to 127.0.0.1:5432"
        result = redact(text, level="strict")
        assert "127.0.0.1" in result
