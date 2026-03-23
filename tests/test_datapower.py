"""Tests for IBM DataPower Gateway format plugin."""
from __future__ import annotations

from pathlib import Path

import pytest

from logpilot.formats.datapower import DataPowerFormat, DP_FULL_RE
from logpilot.parser import parse_file
from logpilot.formats import detect_format

FIXTURE = Path(__file__).parent / "fixtures" / "datapower-sample.log"
FMT = DataPowerFormat()


class TestDetection:
    def test_detect_datapower_log(self):
        lines = FIXTURE.read_text().splitlines()[:50]
        score = FMT.detect(lines)
        assert score > 0.5

    def test_detect_not_other_formats(self):
        """DataPower should not score on non-DataPower logs."""
        nginx_lines = [
            '10.0.0.1 - - [15/Mar/2025:14:30:18 +0000] "GET / HTTP/1.1" 200 612',
            '10.0.0.2 - - [15/Mar/2025:14:30:19 +0000] "POST /api HTTP/1.1" 502 0',
        ]
        assert FMT.detect(nginx_lines) == 0.0

    def test_auto_detect_fixture(self):
        fmt = detect_format(FIXTURE)
        assert fmt.name == "datapower"

    def test_detect_empty(self):
        assert FMT.detect([]) == 0.0


class TestTimestamp:
    def test_extract_ts(self):
        line = "20260320T141542.123Z [default][error][0x80e00001] Connection refused"
        assert FMT.extract_ts(line) == "20260320T141542.123Z"

    def test_extract_ts_none_for_continuation(self):
        assert FMT.extract_ts("  Transform error in stylesheet") is None

    def test_extract_ts_info(self):
        line = "20260320T141500.000Z [default][info][0x00000000] Gateway started"
        assert FMT.extract_ts(line) == "20260320T141500.000Z"


class TestLevel:
    @pytest.mark.parametrize("level_str,expected", [
        ("info", "INFO"),
        ("error", "ERROR"),
        ("warn", "WARNING"),
        ("debug", "DEBUG"),
        ("critical", "ERROR"),
        ("emergency", "FATAL"),
        ("alert", "FATAL"),
        ("notice", "INFO"),
    ])
    def test_level_mapping(self, level_str, expected):
        line = f"20260320T141500.000Z [default][{level_str}][0x00000000] Test message"
        assert FMT.extract_level(line) == expected

    def test_level_none_for_continuation(self):
        assert FMT.extract_level("  continuation line") is None


class TestContinuation:
    def test_new_event_not_continuation(self):
        line = "20260320T141542.123Z [default][error][0x80e00001] Connection refused"
        assert FMT.is_continuation(line) is False

    def test_indented_line_is_continuation(self):
        assert FMT.is_continuation("  Transform error in stylesheet") is True

    def test_stacktrace_is_continuation(self):
        assert FMT.is_continuation("	at java.net.Socket.connect(Socket.java:589)") is True

    def test_caused_by_is_continuation(self):
        assert FMT.is_continuation("Caused by: java.io.IOException: Connection timed out") is True

    def test_empty_line_not_continuation(self):
        assert FMT.is_continuation("") is False
        assert FMT.is_continuation("   ") is False


class TestClassify:
    def test_classify_error(self):
        text = "20260320T141542.123Z [default][error][0x80e00001] Connection refused to backend"
        result = FMT.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["code"] == "0x80e00001"
        assert result["domain"] == "default"
        assert "Network" in result["tags"]

    def test_classify_ssl(self):
        text = "20260320T141546.345Z [ssl][error][0x80e10001] SSL handshake failed: peer certificate expired"
        result = FMT.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["code"] == "0x80e10001"
        assert result["domain"] == "ssl"
        assert "SSL/TLS" in result["tags"]

    def test_classify_auth(self):
        text = "20260320T141548.000Z [aaa][error][0x80d00001] Authentication failed for user 'svc-checkout'"
        result = FMT.classify_event(text)
        assert result["code"] == "0x80d00001"
        assert "Auth" in result["tags"]

    def test_classify_xml(self):
        text = "20260320T141545.012Z [xmlparse][error][0x80c00001] XML parsing failed: not well-formed"
        result = FMT.classify_event(text)
        assert result["code"] == "0x80c00001"
        assert "XML" in result["tags"]

    def test_classify_with_stacktrace(self):
        text = (
            "20260320T141550.000Z [default][error][0x80e00002] Connection timeout to backend\n"
            "  java.net.SocketTimeoutException: connect timed out\n"
            "\tat java.net.Socket.connect(Socket.java:589)\n"
            "Caused by: java.io.IOException: Connection timed out\n"
            "\tat sun.nio.ch.SocketChannelImpl.connect(SocketChannelImpl.java:734)"
        )
        result = FMT.classify_event(text)
        assert result["exception"] == "java.net.SocketTimeoutException"
        assert result["root_cause"] == "java.io.IOException"

    def test_classify_crypto(self):
        text = "20260320T141552.000Z [crypto][error][0x80a00001] Key generation failed: algorithm not supported"
        result = FMT.classify_event(text)
        assert "Crypto" in result["tags"]

    def test_classify_apic(self):
        text = "20260320T141553.000Z [apiconnect][error][0x80b00001] API subscription not found"
        result = FMT.classify_event(text)
        assert "APIC" in result["tags"]

    def test_classify_critical_as_error(self):
        text = "20260320T141554.000Z [default][critical][0x80e00010] No route to host"
        result = FMT.classify_event(text)
        assert result["level"] == "ERROR"

    def test_no_thread_id(self):
        text = "20260320T141500.000Z [default][info][0x00000000] Gateway started"
        result = FMT.classify_event(text)
        assert result["thread_id"] is None


class TestSignalTags:
    def test_ssl_tag(self):
        tags = FMT.bucket_tags("SSL handshake failed: certificate expired")
        assert "SSL/TLS" in tags

    def test_network_tag(self):
        tags = FMT.bucket_tags("connection refused to backend 10.0.1.5")
        assert "Network" in tags

    def test_auth_tag(self):
        tags = FMT.bucket_tags("authentication failed for user 'admin'")
        assert "Auth" in tags

    def test_db_pool_tag(self):
        tags = FMT.bucket_tags("backend timeout after 30000ms, connection pool exhausted")
        assert "DB/Pool" in tags

    def test_xml_tag_by_code(self):
        tags = FMT.bucket_tags("0x80c00001 parse error")
        assert "XML" in tags

    def test_multiple_tags(self):
        tags = FMT.bucket_tags("SSL handshake failed: connection refused")
        assert "SSL/TLS" in tags
        assert "Network" in tags

    def test_no_tags(self):
        tags = FMT.bucket_tags("Transaction completed: 200 OK (12ms)")
        assert len(tags) == 0


class TestParsing:
    def test_parse_fixture(self):
        events = parse_file(FIXTURE)
        assert len(events) > 0

    def test_event_count(self):
        events = parse_file(FIXTURE)
        # 22 timestamped lines in fixture, some with continuations
        assert len(events) >= 18

    def test_error_events(self):
        events = parse_file(FIXTURE)
        errors = [e for e in events if e.level == "ERROR"]
        assert len(errors) >= 8

    def test_multiline_event(self):
        """Events with continuations should be merged."""
        events = parse_file(FIXTURE)
        # The connection timeout event has a Java stacktrace
        timeout_events = [e for e in events if "SocketTimeoutException" in (e.text or "")]
        assert len(timeout_events) >= 1
        evt = timeout_events[0]
        assert "Caused by" in evt.text
        assert evt.exception == "java.net.SocketTimeoutException"
        assert evt.root_cause == "java.io.IOException"

    def test_signal_tags_present(self):
        events = parse_file(FIXTURE)
        all_tags = set()
        for e in events:
            all_tags.update(e.tags or [])
        assert "SSL/TLS" in all_tags
        assert "Network" in all_tags
        assert "Auth" in all_tags
        assert "XML" in all_tags

    def test_codes_extracted(self):
        events = parse_file(FIXTURE)
        codes = {e.code for e in events if e.code}
        assert "0x80e00001" in codes
        assert "0x80e10001" in codes
        assert "0x80c00001" in codes
        assert "0x80d00001" in codes

    def test_domains_detected(self):
        """DataPower domain should be accessible (stored in classify extras)."""
        events = parse_file(FIXTURE)
        # Domains are in the raw text, verify parsing worked
        ssl_events = [e for e in events if "[ssl]" in (e.text or "")]
        assert len(ssl_events) >= 2

    def test_info_events(self):
        events = parse_file(FIXTURE)
        info = [e for e in events if e.level == "INFO"]
        assert len(info) >= 4

    def test_warning_events(self):
        events = parse_file(FIXTURE)
        warns = [e for e in events if e.level == "WARNING"]
        assert len(warns) >= 2
