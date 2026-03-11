"""Tests for the log format plugin system (M27)."""
from __future__ import annotations

import sys
import os
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from logpilot.formats import detect_format, get_format, list_formats, register_format
from logpilot.formats.base import LogFormat, is_stack_or_caused_by, extract_exception, extract_root_cause
from logpilot.formats.was import WASFormat
from logpilot.parser import parse_file, parse_file_iter


# --- Sample log data ---

WAS_LOG = """\
[10/12/15 21:22:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: config loaded
[10/12/15 21:22:04:291 CEST] 00000001 TCPChannel    I   TCPC0001I: TCP listening on port 9081.
[10/12/15 21:22:04:385 CEST] 00000001 JMSRequestMap W   XJMS0022W: Destination in use.
[10/12/15 21:22:13:837 CEST] 00000150 WSX509TrustMa E   CWPKI0022E: SSL HANDSHAKE FAILURE
"""

ISO_LOG = """\
2025-03-05 12:34:56.789 INFO  Starting application
2025-03-05 12:34:57.123 ERROR Connection refused to database
2025-03-05 12:34:58.456 WARN  Retrying in 5 seconds
"""


class TestLogFormatProtocol:
    """Test that WASFormat implements the LogFormat protocol."""

    def test_was_is_log_format(self):
        fmt = WASFormat()
        assert isinstance(fmt, LogFormat)

    def test_was_has_required_attributes(self):
        fmt = WASFormat()
        assert fmt.name == "was"
        assert fmt.description


class TestWASFormatDetect:
    """Test WAS format auto-detection scoring."""

    def test_high_score_for_was_logs(self):
        lines = WAS_LOG.strip().splitlines()
        fmt = WASFormat()
        score = fmt.detect(lines)
        assert score > 0.5

    def test_low_score_for_plain_text(self):
        lines = ["Hello world", "This is not a log", "Just plain text"]
        fmt = WASFormat()
        score = fmt.detect(lines)
        assert score < 0.1

    def test_zero_score_for_empty(self):
        fmt = WASFormat()
        assert fmt.detect([]) == 0.0


class TestWASFormatExtract:
    """Test WAS format field extraction."""

    def test_extract_ts_classic(self):
        fmt = WASFormat()
        ts = fmt.extract_ts("[10/12/15 21:22:04:257 CEST] 00000001 Comp I msg")
        assert ts == "10/12/15 21:22:04:257"

    def test_extract_ts_iso(self):
        fmt = WASFormat()
        ts = fmt.extract_ts("2025-03-05 12:34:56.789 INFO msg")
        assert ts == "2025-03-05 12:34:56.789"

    def test_extract_ts_no_match(self):
        fmt = WASFormat()
        assert fmt.extract_ts("no timestamp here") is None

    def test_extract_level_was_single_letter(self):
        fmt = WASFormat()
        lvl = fmt.extract_level("[ts] 00000001 Comp E   SOME0001E: error")
        # WAS_LEVEL_RE requires ] threadid Component X pattern
        # This tests the keyword fallback
        assert lvl is not None

    def test_extract_level_keyword(self):
        fmt = WASFormat()
        lvl = fmt.extract_level("2025-01-01 12:00:00 ERROR something bad")
        assert lvl == "ERROR"

    def test_is_continuation_stacktrace(self):
        fmt = WASFormat()
        assert fmt.is_continuation("\tat com.example.Foo.bar(Foo.java:42)")
        assert fmt.is_continuation("Caused by: java.io.IOException: timeout")
        assert not fmt.is_continuation("[10/12/15 21:22:04:257 CEST] normal line")


class TestWASFormatClassify:
    """Test WAS format event classification."""

    def test_classify_with_code_and_exception(self):
        fmt = WASFormat()
        text = (
            "[10/12/15 21:22:13:837 CEST] 00000150 WSX509TrustMa E   "
            "CWPKI0022E: SSL HANDSHAKE FAILURE: PKIX path building failed: "
            "java.security.cert.CertPathBuilderException: could not build path"
        )
        result = fmt.classify_event(text)
        assert result["level"] == "ERROR"
        assert result["thread_id"] == "00000150"
        assert result["code"] == "CWPKI0022E"
        assert result["exception"] == "java.security.cert.CertPathBuilderException"
        assert "SSL/TLS" in result["tags"]

    def test_classify_with_root_cause(self):
        fmt = WASFormat()
        text = (
            "com.example.AppException: something failed\n"
            "\tat com.example.App.run(App.java:10)\n"
            "Caused by: java.net.ConnectException: Connection refused\n"
            "\tat java.net.Socket.connect(Socket.java:100)"
        )
        result = fmt.classify_event(text)
        assert result["root_cause"] == "java.net.ConnectException"


class TestWASFormatBucketTags:
    """Test signal tag extraction."""

    def test_oom_tag(self):
        fmt = WASFormat()
        assert "OOM/GC" in fmt.bucket_tags("java.lang.OutOfMemoryError: Java heap space")

    def test_ssl_tag(self):
        fmt = WASFormat()
        assert "SSL/TLS" in fmt.bucket_tags("SSLHandshakeException: certificate unknown")

    def test_db_pool_tag(self):
        fmt = WASFormat()
        assert "DB/Pool" in fmt.bucket_tags("J2CA0045E: connection pool exhausted")

    def test_hung_threads_tag(self):
        fmt = WASFormat()
        assert "HungThreads" in fmt.bucket_tags("WSVR0605W: Thread stuck for 600 seconds")

    def test_no_tags(self):
        fmt = WASFormat()
        assert fmt.bucket_tags("INFO: normal operation") == set()


class TestFormatRegistry:
    """Test format registry functions."""

    def test_get_format_was(self):
        fmt = get_format("was")
        assert fmt.name == "was"

    def test_get_format_unknown_raises(self):
        with pytest.raises(KeyError):
            get_format("nonexistent_format")

    def test_list_formats_includes_was(self):
        formats = list_formats()
        names = [f["name"] for f in formats]
        assert "was" in names

    def test_list_formats_has_description(self):
        formats = list_formats()
        for f in formats:
            assert "name" in f
            assert "description" in f
            assert f["description"]  # not empty


class TestRegisterFormat:
    """Test dynamic format registration."""

    def test_register_custom_format(self):
        class DummyFormat:
            name = "dummy"
            description = "Dummy format for testing"

            def detect(self, lines):
                return 0.0

            def extract_ts(self, line):
                return None

            def extract_level(self, line):
                return None

            def is_continuation(self, line):
                return False

            def classify_event(self, text):
                return {"level": None, "thread_id": None, "code": None,
                        "exception": None, "root_cause": None, "tags": []}

            def bucket_tags(self, text):
                return set()

        register_format(DummyFormat())
        fmt = get_format("dummy")
        assert fmt.name == "dummy"

        # Cleanup
        from logpilot.formats import _FORMATS, _FORMAT_MAP
        _FORMATS[:] = [f for f in _FORMATS if f.name != "dummy"]
        del _FORMAT_MAP["dummy"]


class TestAutoDetect:
    """Test auto-detection of log formats."""

    def test_detect_was_from_lines(self):
        lines = WAS_LOG.strip().splitlines()
        fmt = detect_format(lines)
        assert fmt.name == "was"

    def test_detect_was_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(WAS_LOG)
            f.flush()
            path = Path(f.name)

        try:
            fmt = detect_format(path)
            assert fmt.name == "was"
        finally:
            path.unlink()

    def test_detect_fallback_for_empty(self):
        fmt = detect_format([])
        assert fmt.name == "was"  # default fallback

    def test_detect_fallback_for_plain_text(self):
        lines = ["just some random text", "nothing log-like here"]
        fmt = detect_format(lines)
        # Should fallback to default
        assert fmt.name == "was"


class TestParseFileWithFormat:
    """Test parse_file with explicit and auto-detected formats."""

    def test_parse_was_explicit(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(WAS_LOG)
            f.flush()
            path = Path(f.name)

        try:
            events = parse_file(path, format_name="was")
            assert len(events) >= 4
            assert all(e.get("format") == "was" for e in events)
        finally:
            path.unlink()

    def test_parse_was_autodetect(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(WAS_LOG)
            f.flush()
            path = Path(f.name)

        try:
            events = parse_file(path)
            assert len(events) >= 4
            # Should auto-detect as WAS
            assert all(e.get("format") == "was" for e in events)
        finally:
            path.unlink()

    def test_parse_file_iter_with_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(WAS_LOG)
            f.flush()
            path = Path(f.name)

        try:
            events = list(parse_file_iter(path, format_name="was"))
            assert len(events) >= 4
        finally:
            path.unlink()

    def test_parse_invalid_format_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(WAS_LOG)
            f.flush()
            path = Path(f.name)

        try:
            with pytest.raises(KeyError):
                parse_file(path, format_name="nonexistent")
        finally:
            path.unlink()

    def test_events_include_format_field(self):
        """Verify that parsed events include the 'format' metadata field."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(WAS_LOG)
            f.flush()
            path = Path(f.name)

        try:
            events = parse_file(path)
            for e in events:
                assert "format" in e
                assert e["format"] == "was"
        finally:
            path.unlink()


class TestBaseHelpers:
    """Test shared helper functions in base.py."""

    def test_is_stack_or_caused_by(self):
        assert is_stack_or_caused_by("\tat com.example.Foo.bar(Foo.java:42)")
        assert is_stack_or_caused_by("Caused by: java.io.IOException: fail")
        assert not is_stack_or_caused_by("normal log line")

    def test_extract_exception(self):
        assert extract_exception("java.lang.NullPointerException: null") == "java.lang.NullPointerException"
        assert extract_exception("no exception here") is None

    def test_extract_root_cause(self):
        text = (
            "com.example.AppException: fail\n"
            "\tat com.example.App.run(App.java:10)\n"
            "Caused by: java.io.IOException: disk full\n"
            "\tat java.io.FileOutputStream.write(FOS.java:5)"
        )
        assert extract_root_cause(text) == "java.io.IOException"

    def test_extract_root_cause_none(self):
        assert extract_root_cause("no caused by here") is None


class TestExistingTestsStillPass:
    """Verify that the format system doesn't break existing parse behavior."""

    def test_stacktrace_kept_with_parent(self):
        log = (
            "[10/12/15 21:22:13:851 CEST] 00000150 WebAuth E   SECJ0126E: Trust failed\n"
            "\tat com.ibm.ws.security.Foo.bar(Foo.java:42)\n"
            "Caused by: javax.net.ssl.SSLHandshakeException: PKIX\n"
            "\tat com.ibm.jsse2.o.a(o.java:3)\n"
            "[10/12/15 21:22:14:000 CEST] 00000001 Comp I   Normal line\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(log)
            f.flush()
            path = Path(f.name)

        try:
            events = parse_file(path)
            assert len(events) == 2
            # First event should contain the stacktrace
            assert "SSLHandshakeException" in events[0]["text"]
            assert events[0]["root_cause"] == "javax.net.ssl.SSLHandshakeException"
        finally:
            path.unlink()

    def test_redaction_still_works(self):
        log = (
            "2025-03-05 12:34:56.789 ERROR password=s3cret123 token=abc123\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(log)
            f.flush()
            path = Path(f.name)

        try:
            events = parse_file(path)
            assert len(events) == 1
            assert "s3cret123" not in events[0]["text"]
            assert "REDACTED" in events[0]["text"]
        finally:
            path.unlink()


class TestCLIListFormats:
    """Test --list-formats CLI flag."""

    def test_list_formats_cli(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "logpilot", "--list-formats"],
            capture_output=True, text=True, cwd=str(Path(__file__).parent.parent)
        )
        assert result.returncode == 0
        assert "was" in result.stdout
        assert "WebSphere" in result.stdout
