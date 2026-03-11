import json
import subprocess
from pathlib import Path

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

from wslog import (
    extract_ts, redact, parse_file, parse_file_iter, classify_event, bucket_tags,
    _parse_ts_parts, parse_ts_datetime,
    EXC_HEAD_RE, WAS_LEVEL_RE, WAS_LEVEL_MAP, WAS_CODE_RE, WAS_THREAD_RE,
    LEVEL_RE, HUNG_THREAD_RE, open_text,
)
from conftest import make_event, empty_match

# --- Shared fixtures ---

SAMPLE_LOG = """\
[10/12/15 21:22:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: config loaded
[10/12/15 21:22:04:291 CEST] 00000001 TCPChannel    I   TCPC0001I: TCP listening on port 9081.
[10/12/15 21:22:04:385 CEST] 00000001 JMSRequestMap W   XJMS0022W: Destination in use by multiple modules.
[10/12/15 21:22:13:837 CEST] 00000150 WSX509TrustMa E   CWPKI0022E: SSL HANDSHAKE FAILURE: PKIX path building failed: java.security.cert.CertPathBuilderException: could not build path
[10/12/15 21:25:01:000 CEST] 0000014c NotificationS I   CLFWY0297I: task started
"""

PREAMBLE_LOG = """\
************ Start Display Current Environment ************
WebSphere Platform 8.5.5.3
Java version = 1.6.0
************* End Display Current Environment *************
[10/12/15 21:22:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: config loaded
[10/12/15 21:22:04:291 CEST] 00000001 TCPChannel    I   TCPC0001I: TCP listening on port 9081.
"""

MULTI_DAY_LOG = """\
[10/12/15 23:59:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: before midnight
[10/13/15 00:01:04:257 CEST] 00000001 TCPChannel    I   TCPC0001I: after midnight
"""

STACKTRACE_LOG = """\
[10/12/15 21:22:13:851 CEST] 00000150 WebAuthentica E   SECJ0126E: Trust Association failed. The exception is com.ibm.websphere.security.WebTrustAssociationFailedException: CWTAI2007E
\tat com.ibm.ws.security.oidc.client.RelyingParty.handleSigninCallback(RelyingParty.java:566)
\tat com.ibm.ws.security.web.WebAuthenticator.handleTrustAssociation(WebAuthenticator.java:421)
Caused by: com.ibm.ws.security.oidc.client.RelyingPartyException: Failed to make a request to OP server
\tat com.ibm.ws.security.oidc.client.RelyingPartyUtils.invokeRequest(RelyingPartyUtils.java:312)
Caused by: javax.net.ssl.SSLHandshakeException: PKIX path building failed
\tat com.ibm.jsse2.o.a(o.java:3)

[10/12/15 21:22:14:000 CEST] 00000001 TCPChannel    I   TCPC0001I: next event
"""


@pytest.fixture
def sample_log(tmp_path):
    p = tmp_path / "test.log"
    p.write_text(SAMPLE_LOG)
    return p


@pytest.fixture
def preamble_log(tmp_path):
    p = tmp_path / "preamble.log"
    p.write_text(PREAMBLE_LOG)
    return p


@pytest.fixture
def multi_day_log(tmp_path):
    p = tmp_path / "multi.log"
    p.write_text(MULTI_DAY_LOG)
    return p


@pytest.fixture
def stacktrace_log(tmp_path):
    p = tmp_path / "stack.log"
    p.write_text(STACKTRACE_LOG)
    return p


@pytest.fixture
def sample_events(sample_log):
    return parse_file(sample_log)


# --- Timestamp extraction ---

def test_extract_ts_was_classic():
    line = "[10/12/15 21:22:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: hello"
    ts = extract_ts(line)
    assert ts == "10/12/15 21:22:04:257"


def test_extract_ts_iso():
    line = "2025-03-05 12:34:56:789 some log message"
    ts = extract_ts(line)
    assert ts == "2025-03-05 12:34:56:789"


def test_extract_ts_no_match():
    assert extract_ts("no timestamp here") is None


# --- WAS level parsing (parametrized) ---

@pytest.mark.parametrize("line,expected_level", [
    ("] 00000001 WsmmConfigFac I   ARFM5007I: hello", "INFO"),
    ("] 00000150 WSX509TrustMa E   CWPKI0022E: SSL failure", "ERROR"),
    ("] 00000001 JMSRequestMap W   XJMS0022W: Destination in use", "WARNING"),
    ("] 00000001 WSChannelFram A   CHFW0019I: chain started", "AUDIT"),
    ("] 00000150 SystemOut     O CWPKI0022E: SSL HANDSHAKE FAILURE", "STDOUT"),
])
def test_was_level(line, expected_level):
    m = WAS_LEVEL_RE.search(line)
    assert m and WAS_LEVEL_MAP[m.group(1)] == expected_level


def test_was_level_takes_priority(sample_events):
    """WAS single-letter level should be used over keyword matches in message body."""
    levels = [e["level"] for e in sample_events]
    assert levels == ["INFO", "INFO", "WARNING", "ERROR", "INFO"]


# --- Thread ID ---

def test_thread_id_extracted():
    line = "] 00000150 WSX509TrustMa E   CWPKI0022E: SSL failure"
    m = WAS_THREAD_RE.search(line)
    assert m and m.group(1) == "00000150"


def test_classify_event_thread_id():
    text = "[10/12/15 21:22:04:257 CEST] 00000150 WSX509TrustMa E   CWPKI0022E: SSL failure"
    meta = classify_event(text)
    assert meta["thread_id"] == "00000150"


# --- WAS code regex ---

def test_was_code_matches_common_prefixes():
    for code in ["ARFM5007I", "TCPC0001I", "CHFW0019I", "SCHD0077I",
                 "CWPKI0022E", "CWWIM6002I", "ODCF8010I", "XJMS0008I",
                 "CLFWY0297I", "CWLRB5873I"]:
        m = WAS_CODE_RE.search(f"some text {code}: message")
        assert m and m.group(1) == code, f"Failed to match {code}"


def test_was_code_no_false_positive():
    assert WAS_CODE_RE.search("ABC123X something") is None
    assert WAS_CODE_RE.search("normal log line") is None


# --- Exception regex ---

def test_exc_matches_qualified():
    m = EXC_HEAD_RE.search("java.security.cert.CertPathBuilderException: msg")
    assert m and m.group(1) == "java.security.cert.CertPathBuilderException"


def test_exc_matches_ssl():
    m = EXC_HEAD_RE.search("javax.net.ssl.SSLHandshakeException: msg")
    assert m and m.group(1) == "javax.net.ssl.SSLHandshakeException"


def test_exc_no_match_bare_error():
    assert EXC_HEAD_RE.search("Some Error occurred in the system") is None


def test_exc_no_match_bare_exception():
    assert EXC_HEAD_RE.search("An Exception was thrown") is None


# --- Redaction ---

def test_redact_bearer():
    s = "Authorization: Bearer eyJhbGciOi.stuff.here"
    result = redact(s)
    assert "eyJhbGciOi" not in result
    assert "[REDACTED]" in result


def test_redact_password():
    s = "password=s3cret123"
    result = redact(s)
    assert "s3cret123" not in result


def test_redact_no_secrets():
    s = "Just a normal log line"
    assert redact(s) == s


# --- Bucket tags ---

def test_bucket_tags_ssl():
    tags = bucket_tags("PKIX path building failed: something")
    assert "SSL/TLS" in tags


def test_bucket_tags_oom():
    tags = bucket_tags("java.lang.OutOfMemoryError: Java heap space")
    assert "OOM/GC" in tags


def test_bucket_tags_none():
    tags = bucket_tags("normal info log line")
    assert len(tags) == 0


def test_hung_thread_no_false_positive_wsvr0001():
    """WSVR0001I (server started) should NOT trigger HungThreads tag."""
    assert not HUNG_THREAD_RE.search("WSVR0001I: Server open for e-business")


def test_hung_thread_matches_wsvr0605():
    """WSVR0605W (ThreadMonitor) should trigger HungThreads tag."""
    assert HUNG_THREAD_RE.search("WSVR0605W: Thread stuck for 600 seconds")


def test_hung_thread_matches_threadmonitor():
    assert HUNG_THREAD_RE.search("ThreadMonitor W   WSVR0605W: Thread is hung")


# --- classify_event ---

def test_classify_event_basic():
    text = "[10/12/15 21:22:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: config loaded"
    meta = classify_event(text)
    assert meta["level"] == "INFO"
    assert meta["code"] == "ARFM5007I"
    assert meta["thread_id"] == "00000001"
    assert meta["exception"] is None
    assert meta["root_cause"] is None


def test_classify_event_with_exception():
    text = "CWPKI0022E: PKIX path building failed: java.security.cert.CertPathBuilderException: bad"
    meta = classify_event(text)
    assert meta["exception"] == "java.security.cert.CertPathBuilderException"


# --- Root cause extraction ---

def test_root_cause_extracted(stacktrace_log):
    events = parse_file(stacktrace_log)
    error_event = [e for e in events if e["level"] == "ERROR"][0]
    assert error_event["root_cause"] == "javax.net.ssl.SSLHandshakeException"
    assert "WebTrustAssociationFailedException" in error_event["exception"]


def test_root_cause_none_when_no_caused_by(sample_events):
    for e in sample_events:
        assert e["root_cause"] is None


# --- Preamble handling ---

def test_preamble_skipped(preamble_log):
    events = parse_file(preamble_log)
    assert len(events) == 2
    assert all(e["ts"] is not None for e in events)
    # No UNKNOWN preamble event
    assert all(e["level"] is not None for e in events)


# --- Full parse ---

def test_parse_splits_events(sample_events):
    assert len(sample_events) == 5


def test_parse_classifies_levels(sample_events):
    levels = [e["level"] for e in sample_events]
    assert levels.count("INFO") == 3
    assert levels.count("WARNING") == 1
    assert levels.count("ERROR") == 1


def test_parse_detects_exception(sample_events):
    exc_events = [e for e in sample_events if e["exception"]]
    assert len(exc_events) == 1
    assert "CertPathBuilderException" in exc_events[0]["exception"]


def test_parse_detects_was_codes(sample_events):
    codes = [e["code"] for e in sample_events if e["code"]]
    assert "ARFM5007I" in codes
    assert "TCPC0001I" in codes
    assert "CWPKI0022E" in codes


def test_parse_extracts_thread_ids(sample_events):
    thread_ids = [e["thread_id"] for e in sample_events]
    assert "00000001" in thread_ids
    assert "00000150" in thread_ids


# --- GZ file support ---

def test_parse_gz_file(tmp_path):
    """Parsing a .gz compressed log should produce the same events as plain text."""
    import gzip as gz_mod
    content = SAMPLE_LOG.encode("utf-8")
    gz_path = tmp_path / "test.log.gz"
    with gz_mod.open(gz_path, "wb") as f:
        f.write(content)
    events = parse_file(gz_path)
    assert len(events) == 5
    levels = [e["level"] for e in events]
    assert levels.count("ERROR") == 1


# --- Additional redaction tests ---

def test_redact_api_key():
    s = "api_key=sk-abc123def456"
    result = redact(s)
    assert "sk-abc123def456" not in result
    assert "[REDACTED]" in result


def test_redact_token():
    s = "token=eyJhbGciOi.stuff.here"
    result = redact(s)
    assert "eyJhbGciOi" not in result


def test_redact_secret():
    s = "secret=my_super_secret_value"
    result = redact(s)
    assert "my_super_secret_value" not in result


# --- Redaction false-positive tests (must NOT over-redact) ---

@pytest.mark.parametrize("text", [
    "SRVE0293E: Servlet Error - /api/v1/health returned 500",
    "CWWKZ0002E: The application myapp failed to start",
    "WebContainer : 5 has been active for 610 seconds",
    "javax.naming.NameNotFoundException: java:comp/env/jdbc/MyDS",
    "Connection pool exhausted for DataSource jdbc/AppDB",
    "SSLHandshakeException: PKIX path building failed",
    "Thread-42 performed token refresh successfully",
    "SELECT * FROM users WHERE password_hash = 'abc'",
    "Application password-reset-service started in 2.3s",
    "java.lang.OutOfMemoryError: Java heap space at com.example.Service.process",
    "authorization check passed for user admin",
    "The credential store was initialized successfully",
    "Using API endpoint https://api.example.com/v2/status",
    "secret_key_rotation completed for partition 3",
])
def test_redact_preserves_normal_log_text(text):
    """Ensure redaction doesn't destroy normal log content."""
    result = redact(text)
    # The text should be mostly preserved (some keyword matches may redact adjacent values)
    # but the core message structure must survive
    assert len(result) >= len(text) * 0.5, f"Over-redacted: {text!r} -> {result!r}"


def test_redact_preserves_was_codes():
    """WAS message codes must never be redacted."""
    codes = ["SRVE0293E", "CWWKZ0002E", "J2CA0045E", "DSRA0010E", "WSVR0605W"]
    for code in codes:
        text = f"[ERROR] {code}: Something happened"
        assert code in redact(text)


def test_redact_preserves_exception_names():
    """Java exception class names must not be redacted."""
    exceptions = [
        "javax.naming.NameNotFoundException",
        "java.lang.NullPointerException",
        "javax.net.ssl.SSLHandshakeException",
        "java.sql.SQLException",
    ]
    for exc in exceptions:
        text = f"Caused by: {exc}: detail message"
        assert exc in redact(text)


def test_redact_json_key_only_redacts_value():
    """JSON-style secrets: only the value should be redacted, not the key."""
    s = '"api_key": "sk-ant-abc123"'
    result = redact(s)
    assert "api_key" in result
    assert "sk-ant-abc123" not in result


def test_redact_jwt_preserves_surrounding():
    """JWT redaction should only remove the token, not surrounding text."""
    # "Token:" triggers the key=value redaction, which aggressively redacts
    # everything after the keyword (multi-word secret support)
    s = "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123 was expired"
    result = redact(s)
    assert "[REDACTED]" in result
    # Without a triggering keyword, JWT pattern applies directly
    s2 = "Header eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123 trail"
    r2 = redact(s2)
    assert "[REDACTED_JWT]" in r2
    assert "trail" in r2


# --- Edge cases for parse_file ---

def test_parse_empty_file(tmp_path):
    """Empty file should return no events."""
    p = tmp_path / "empty.log"
    p.write_text("")
    events = parse_file(p)
    assert events == []


def test_parse_file_with_max_lines(sample_log):
    """max_lines should limit how many lines are read."""
    events_all = parse_file(sample_log)
    events_limited = parse_file(sample_log, max_lines=2)
    assert len(events_limited) < len(events_all)


def test_parse_only_preamble(tmp_path):
    """File with only preamble (no timestamps) should return no events."""
    p = tmp_path / "preamble_only.log"
    p.write_text("Just some text\nwithout any timestamps\nat all\n")
    events = parse_file(p)
    assert events == []


# --- Stacktrace keeps parent event ---

def test_stacktrace_kept_with_parent(stacktrace_log):
    """Stacktrace lines and Caused by should be part of the parent event."""
    events = parse_file(stacktrace_log)
    error_events = [e for e in events if e["level"] == "ERROR"]
    assert len(error_events) == 1
    assert "at com.ibm.ws.security" in error_events[0]["text"]
    assert "Caused by:" in error_events[0]["text"]


# --- Signal tag combinations ---

def test_bucket_tags_db_pool():
    tags = bucket_tags("Timeout waiting for idle object in connection pool")
    assert "DB/Pool" in tags


def test_bucket_tags_http():
    tags = bucket_tags("500 Internal Server Error HTTP/1.1 SRVE0260E")
    assert "HTTP" in tags


def test_bucket_tags_multiple():
    """A single log line can have multiple signal tags."""
    text = "OutOfMemoryError during SSL handshake SSLHandshakeException"
    tags = bucket_tags(text)
    assert "OOM/GC" in tags
    assert "SSL/TLS" in tags


# --- Classify event edge cases ---

def test_classify_event_fallback_to_keyword_level():
    """When no WAS single-letter level, fall back to keyword matching."""
    text = "2025-03-05 12:00:00:000 ERROR something went wrong"
    meta = classify_event(text)
    assert meta["level"] == "ERROR"


def test_classify_event_no_level():
    """Lines with no level indicator should return None for level."""
    text = "just some random text without any level"
    meta = classify_event(text)
    assert meta["level"] is None


# --- _parse_ts_parts ---

def test_parse_ts_parts_was():
    result = _parse_ts_parts("10/12/15 21:22:04:257")
    assert result == ("10/12/15", 21, 22)


def test_parse_ts_parts_iso():
    result = _parse_ts_parts("2025-03-05T12:34:56.789")
    assert result == ("2025-03-05", 12, 34)


def test_parse_ts_parts_invalid():
    assert _parse_ts_parts("garbage") is None


# --- parse_ts_datetime tests ---

def test_parse_ts_datetime_was_classic():
    dt = parse_ts_datetime("10/12/15 21:22:04:257")
    assert dt is not None
    assert dt.hour == 21
    assert dt.minute == 22
    assert dt.second == 4


def test_parse_ts_datetime_iso():
    dt = parse_ts_datetime("2025-03-05T12:34:56.789")
    assert dt is not None
    assert dt.year == 2025
    assert dt.hour == 12
    assert dt.minute == 34


def test_parse_ts_datetime_iso_no_millis():
    dt = parse_ts_datetime("2025-03-05 12:34:56")
    assert dt is not None
    assert dt.second == 56


def test_parse_ts_datetime_invalid():
    assert parse_ts_datetime(None) is None
    assert parse_ts_datetime("") is None
    assert parse_ts_datetime("not a timestamp") is None


# --- Error scenario tests ---

def test_parse_file_permission_error(tmp_path, monkeypatch):
    """parse_file should raise or propagate PermissionError when file can't be opened."""
    from unittest.mock import patch

    p = tmp_path / "noperm.log"
    p.write_text("[10/12/15 21:22:04:257 CEST] 00000001 Comp I   CODE0001I: ok\n")

    with patch("wslog.open_text", side_effect=PermissionError("Permission denied")):
        with pytest.raises(PermissionError):
            parse_file(p)


def test_parse_file_non_utf8_content(tmp_path):
    """parse_file should handle files with non-UTF8 (latin-1) encoded content without crashing."""
    p = tmp_path / "latin1.log"
    # Write latin-1 encoded content with characters outside ASCII
    content = "[10/12/15 21:22:04:257 CEST] 00000001 Comp I   CODE0001I: caf\xe9 r\xe9sum\xe9\n"
    p.write_bytes(content.encode("latin-1"))
    events = parse_file(p)
    assert len(events) == 1
    assert events[0]["code"] == "CODE0001I"


def test_open_text_with_null_bytes(tmp_path):
    """open_text should handle files containing null bytes without crashing."""
    p = tmp_path / "nullbytes.log"
    content = "[10/12/15 21:22:04:257 CEST] 00000001 Comp I   CODE0001I: before\x00after\n"
    p.write_bytes(content.encode("utf-8"))
    with open_text(p) as fh:
        text = fh.read()
    assert "before" in text
    assert "after" in text


# --- 10.1 open_text() with invalid gzip data ---

def test_open_text_invalid_gz_falls_back_to_plain(tmp_path):
    """A .gz file that is actually plain text should fall back to plain text reading."""
    p = tmp_path / "fake.log.gz"
    p.write_text("This is plain text, not gzip compressed\nSecond line\n")
    with open_text(p) as fh:
        content = fh.read()
    assert "This is plain text" in content
    assert "Second line" in content


# --- 10.3 Negative tests for WAS_THREAD_RE ---

class TestWasThreadReNegative:
    def test_plain_text_no_match(self):
        assert WAS_THREAD_RE.search("just some plain text") is None

    def test_non_hex_chars_no_match(self):
        """String with non-hex characters (g-z) should not match."""
        assert WAS_THREAD_RE.search("] 0000ghij Component") is None

    def test_short_hex_no_match(self):
        """Hex string shorter than 8 chars should not match."""
        assert WAS_THREAD_RE.search("] 0000abc Component") is None

    def test_no_bracket_prefix_no_match(self):
        """Thread regex requires ] before the hex ID."""
        assert WAS_THREAD_RE.search("00000001 Component I") is None

    def test_uppercase_hex_no_match(self):
        """WAS thread IDs use lowercase hex; uppercase should not match."""
        assert WAS_THREAD_RE.search("] 0000ABCD Component") is None

    def test_empty_string_no_match(self):
        assert WAS_THREAD_RE.search("") is None

    def test_numbers_without_bracket(self):
        assert WAS_THREAD_RE.search("thread 00000001 running") is None


# --- 17.1 Streaming parser parse_file_iter ---

class TestParseFileIter:
    """Tests for the streaming generator-based parser."""

    def test_parse_file_iter_yields_same_as_parse_file(self, tmp_path):
        """parse_file_iter should yield the exact same events as parse_file."""
        content = SAMPLE_LOG
        p = tmp_path / "sample.log"
        p.write_text(content)
        expected = parse_file(p)
        from_iter = list(parse_file_iter(p))
        assert len(from_iter) == len(expected)
        for a, b in zip(from_iter, expected):
            assert a == b

    def test_parse_file_iter_with_stacktrace(self, tmp_path):
        """parse_file_iter should handle stacktraces identically to parse_file."""
        p = tmp_path / "stack.log"
        p.write_text(STACKTRACE_LOG)
        expected = parse_file(p)
        from_iter = list(parse_file_iter(p))
        assert len(from_iter) == len(expected)
        for a, b in zip(from_iter, expected):
            assert a == b

    def test_parse_file_iter_with_preamble(self, tmp_path):
        """parse_file_iter should skip preamble lines like parse_file."""
        p = tmp_path / "preamble.log"
        p.write_text(PREAMBLE_LOG)
        expected = parse_file(p)
        from_iter = list(parse_file_iter(p))
        assert len(from_iter) == len(expected)
        for a, b in zip(from_iter, expected):
            assert a == b

    def test_parse_file_iter_with_max_lines(self, tmp_path):
        """parse_file_iter should respect max_lines parameter."""
        p = tmp_path / "sample.log"
        p.write_text(SAMPLE_LOG)
        expected = parse_file(p, max_lines=3)
        from_iter = list(parse_file_iter(p, max_lines=3))
        assert len(from_iter) == len(expected)
        for a, b in zip(from_iter, expected):
            assert a == b

    def test_parse_file_iter_empty_file(self, tmp_path):
        """parse_file_iter should yield nothing for an empty file."""
        p = tmp_path / "empty.log"
        p.write_text("")
        assert list(parse_file_iter(p)) == []

    def test_parse_file_iter_is_generator(self, tmp_path):
        """parse_file_iter should return a generator, not a list."""
        import types
        p = tmp_path / "sample.log"
        p.write_text(SAMPLE_LOG)
        result = parse_file_iter(p)
        assert isinstance(result, types.GeneratorType)


# --- 10.4 parse_file with blank lines after timestamp ---

def test_parse_file_blank_lines_after_timestamp(tmp_path):
    """Timestamp line followed by blank lines should parse gracefully."""
    content = (
        "[10/12/15 21:22:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: config loaded\n"
        "\n"
        "\n"
        "\n"
        "[10/12/15 21:22:05:000 CEST] 00000001 TCPChannel    I   TCPC0001I: TCP listening\n"
    )
    p = tmp_path / "blanks.log"
    p.write_text(content)
    events = parse_file(p)
    assert len(events) == 2
    # First event should include the blank lines as part of its text
    assert events[0]["ts"] is not None
    assert events[1]["ts"] is not None


# --- 17.2 MAX_UPLOAD_MB constant ---

def test_max_upload_mb_constant_exists():
    """MAX_UPLOAD_MB should be defined in app_constants."""
    from app_constants import MAX_UPLOAD_MB
    assert isinstance(MAX_UPLOAD_MB, int)
    assert MAX_UPLOAD_MB == 200


# ── 11.1: Multi-word secret redaction ─────────────────────────────────

def test_redact_multiword_password():
    """password = very secret with spaces should be fully redacted."""
    text = "password = very secret with spaces"
    result = redact(text)
    assert "very secret" not in result
    assert "spaces" not in result
    assert "[REDACTED]" in result


def test_redact_multiword_api_key():
    """api_key = my long key value should be fully redacted."""
    text = "api_key = my long key value"
    result = redact(text)
    assert "my long key" not in result
    assert "[REDACTED]" in result


def test_redact_multiword_stops_at_comma():
    """Multi-word redaction stops at comma delimiter."""
    text = "password = secret stuff, other_field=safe"
    result = redact(text)
    assert "secret stuff" not in result
    assert "safe" in result


# ── 14.5: Azure SAS token and Authorization Digest redaction ─────────

def test_redact_azure_sas_token():
    """Azure SAS token signature should be redacted."""
    text = "https://myaccount.blob.core.windows.net/container/blob?sv=2021-06-08&sig=abc123DEF456%2Bxyz%3D&se=2025-01-01"
    result = redact(text)
    assert "abc123DEF456" not in result
    assert "sig=***REDACTED***" in result
    assert "sv=2021-06-08" in result  # non-secret param preserved


def test_redact_azure_sas_case_insensitive():
    """Azure SAS redaction should be case-insensitive."""
    text = "url?SIG=MySecretSignature123"
    result = redact(text)
    assert "MySecretSignature123" not in result
    assert "***REDACTED***" in result


def test_redact_authorization_digest():
    """Authorization Digest header should be redacted."""
    text = 'Authorization: Digest username="admin",realm="test",nonce="abc123",response="def456"'
    result = redact(text)
    assert "username=" not in result
    assert "Authorization: Digest ***REDACTED***" in result


def test_redact_authorization_digest_case_insensitive():
    """Authorization Digest redaction should be case-insensitive."""
    text = "authorization: digest abc123secret"
    result = redact(text)
    assert "abc123secret" not in result
    assert "***REDACTED***" in result


def test_redact_azure_sas_preserves_surrounding():
    """Azure SAS redaction should preserve surrounding text."""
    text = "Connecting to storage sig=SECRETVALUE&timeout=30"
    result = redact(text)
    assert "SECRETVALUE" not in result
    assert "Connecting to storage" in result


def test_redact_authorization_digest_preserves_surrounding():
    """Digest auth redaction should preserve surrounding log text."""
    text = "[2025-01-01 12:00:00] Request header: Authorization: Digest credentials123 -- response 401"
    result = redact(text)
    assert "credentials123" not in result
    assert "[2025-01-01 12:00:00]" in result
