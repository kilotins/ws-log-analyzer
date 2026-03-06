import json
import subprocess
from pathlib import Path

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from wslog import (
    extract_ts, redact, parse_file, summarize, bucket_tags,
    time_histogram, render_histogram, pick_samples, per_file_summary,
    classify_event, _parse_ts_parts, render_markdown_report, render_json_report,
    likely_causes,
    EXC_HEAD_RE, WAS_LEVEL_RE, WAS_LEVEL_MAP, WAS_CODE_RE, WAS_THREAD_RE,
    LEVEL_RE, HUNG_THREAD_RE,
)

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


# --- WAS level parsing ---

def test_was_level_info():
    line = "] 00000001 WsmmConfigFac I   ARFM5007I: hello"
    m = WAS_LEVEL_RE.search(line)
    assert m and WAS_LEVEL_MAP[m.group(1)] == "INFO"


def test_was_level_error():
    line = "] 00000150 WSX509TrustMa E   CWPKI0022E: SSL failure"
    m = WAS_LEVEL_RE.search(line)
    assert m and WAS_LEVEL_MAP[m.group(1)] == "ERROR"


def test_was_level_warning():
    line = "] 00000001 JMSRequestMap W   XJMS0022W: Destination in use"
    m = WAS_LEVEL_RE.search(line)
    assert m and WAS_LEVEL_MAP[m.group(1)] == "WARNING"


def test_was_level_audit():
    line = "] 00000001 WSChannelFram A   CHFW0019I: chain started"
    m = WAS_LEVEL_RE.search(line)
    assert m and WAS_LEVEL_MAP[m.group(1)] == "AUDIT"


def test_was_level_stdout():
    """SystemOut O lines should map to STDOUT, not OFF."""
    line = "] 00000150 SystemOut     O CWPKI0022E: SSL HANDSHAKE FAILURE"
    m = WAS_LEVEL_RE.search(line)
    assert m and WAS_LEVEL_MAP[m.group(1)] == "STDOUT"


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


def test_summarize(sample_events):
    s = summarize(sample_events, top_n=10)
    assert s["total_events"] == 5
    level_dict = dict(s["levels"])
    assert level_dict["INFO"] == 3


# --- Pick samples ---

def test_pick_samples_deduplicates():
    events = [
        {"level": "ERROR", "code": "CWPKI0022E", "exception": "SSLException",
         "tags": ["SSL/TLS"], "ts": "1", "text": "first",
         "thread_id": "1", "root_cause": None},
        {"level": "ERROR", "code": "CWPKI0022E", "exception": "SSLException",
         "tags": ["SSL/TLS"], "ts": "2", "text": "duplicate",
         "thread_id": "2", "root_cause": None},
        {"level": "INFO", "code": None, "exception": None,
         "tags": [], "ts": "3", "text": "info",
         "thread_id": "3", "root_cause": None},
    ]
    samples = pick_samples(events, n=5)
    assert len(samples) == 2


# --- Histogram ---

def test_time_histogram(sample_events):
    hist = time_histogram(sample_events)
    assert len(hist) >= 2
    labels = [h[0] for h in hist]
    assert "21:22" in labels
    assert "21:25" in labels


def test_time_histogram_multi_day(multi_day_log):
    events = parse_file(multi_day_log)
    hist = time_histogram(events)
    labels = [h[0] for h in hist]
    assert any("10/12/15" in l for l in labels)
    assert any("10/13/15" in l for l in labels)


def test_time_histogram_custom_bucket(sample_events):
    hist = time_histogram(sample_events, bucket_minutes=5)
    labels = [h[0] for h in hist]
    assert "21:20" in labels
    assert "21:25" in labels


def test_render_histogram_empty():
    lines = render_histogram([])
    assert len(lines) == 1
    assert "no timestamped" in lines[0]


def test_render_histogram_output():
    hist = [("21:22", 10, 2), ("21:25", 5, 0)]
    lines = render_histogram(hist)
    assert len(lines) == 2
    assert "err" in lines[0]
    assert "err" not in lines[1]


# --- Per-file summary ---

def test_per_file_summary(sample_events):
    fs = per_file_summary(sample_events)
    assert len(fs) == 1
    fname, total, errors = fs[0]
    assert total == 5
    assert errors == 1


def test_per_file_summary_multi(tmp_path):
    log1 = tmp_path / "a.log"
    log2 = tmp_path / "b.log"
    log1.write_text("[10/12/15 21:22:04:257 CEST] 00000001 Comp I   CODE0001I: ok\n")
    log2.write_text("[10/12/15 21:22:04:257 CEST] 00000150 Comp E   CODE0002E: fail\n")
    events = parse_file(log1) + parse_file(log2)
    fs = per_file_summary(events)
    assert len(fs) == 2
    by_file = {f: (t, e) for f, t, e in fs}
    assert by_file[str(log1)] == (1, 0)
    assert by_file[str(log2)] == (1, 1)


# --- JSON output ---

def test_json_output(sample_log, tmp_path):
    out = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, "wslog.py", str(sample_log), "--format", "json", "--out", str(out)],
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(__file__)),
    )
    assert result.returncode == 0
    data = json.loads(out.read_text())
    assert data["total_events"] == 5
    assert "levels" in data
    assert "timeline" in data
    assert "samples" in data
    assert "files" in data
    # New fields in samples
    sample = data["samples"][0]
    assert "thread_id" in sample
    assert "root_cause" in sample


# --- _parse_ts_parts ---

def test_parse_ts_parts_was():
    result = _parse_ts_parts("10/12/15 21:22:04:257")
    assert result == ("10/12/15", 21, 22)


def test_parse_ts_parts_iso():
    result = _parse_ts_parts("2025-03-05T12:34:56.789")
    assert result == ("2025-03-05", 12, 34)


def test_parse_ts_parts_invalid():
    assert _parse_ts_parts("garbage") is None


# --- render_markdown_report ---

def test_render_markdown_report(sample_events):
    report = render_markdown_report(sample_events, top_n=5, samples_n=3, hist_minutes=1)
    assert "# WebSphere/Java Log Triage Report" in report
    assert "Parsed events: 5" in report
    assert "## Top Levels" in report
    assert "## Top WebSphere/Liberty Codes" in report
    assert "## Sample Events (sanitized)" in report
    assert "## Timeline (events per minute)" in report


def test_render_markdown_report_includes_exceptions(sample_events):
    report = render_markdown_report(sample_events, top_n=5, samples_n=5)
    assert "CertPathBuilderException" in report


def test_render_json_report(sample_events):
    report = render_json_report(sample_events, top_n=5, samples_n=3)
    data = json.loads(report)
    assert data["total_events"] == 5
    assert "levels" in data
    assert "codes" in data
    assert "exceptions" in data
    assert "timeline" in data
    assert len(data["samples"]) <= 3
    assert "thread_id" in data["samples"][0]


# --- pick_samples scoring ---

def test_pick_samples_fatal_first():
    events = [
        {"level": "ERROR", "code": "ERR0001E", "exception": "java.lang.RuntimeException",
         "tags": [], "ts": "1", "text": "error", "thread_id": "1", "root_cause": None},
        {"level": "FATAL", "code": "FAT0001F", "exception": "java.lang.OutOfMemoryError",
         "tags": ["OOM/GC"], "ts": "2", "text": "fatal", "thread_id": "2", "root_cause": None},
        {"level": "INFO", "code": None, "exception": None,
         "tags": [], "ts": "3", "text": "info", "thread_id": "3", "root_cause": None},
    ]
    samples = pick_samples(events, n=3)
    assert samples[0]["level"] == "FATAL"


def test_pick_samples_warning_over_info():
    events = [
        {"level": "INFO", "code": None, "exception": None,
         "tags": [], "ts": "1", "text": "info", "thread_id": "1", "root_cause": None},
        {"level": "WARNING", "code": "WARN001W", "exception": None,
         "tags": [], "ts": "2", "text": "warning", "thread_id": "2", "root_cause": None},
    ]
    samples = pick_samples(events, n=2)
    assert samples[0]["level"] == "WARNING"


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


# --- Render reports with edge cases ---

def test_render_markdown_report_no_exceptions():
    """Report should handle events with no exceptions gracefully."""
    events = [{
        "level": "INFO", "code": "TEST0001I", "exception": None,
        "root_cause": None, "tags": [], "ts": "10/12/15 21:22:04:257",
        "file": "test.log", "text": "Normal info message", "thread_id": "00000001",
    }]
    report = render_markdown_report(events, top_n=5, samples_n=5)
    assert "_(none detected)_" in report
    assert "## Top Levels" in report


def test_render_json_report_sample_text_truncation():
    """Sample text longer than 4000 chars should be truncated in JSON."""
    events = [{
        "level": "ERROR", "code": "ERR0001E", "exception": "java.lang.RuntimeException",
        "root_cause": None, "tags": [], "ts": "10/12/15 21:22:04:257",
        "file": "test.log", "text": "X" * 5000, "thread_id": "00000001",
    }]
    report = render_json_report(events, top_n=5, samples_n=5)
    data = json.loads(report)
    assert len(data["samples"][0]["text"]) == 4000


# --- Likely causes heuristics ---

def _make_event(text):
    """Helper to build a minimal event dict for heuristic tests."""
    return {
        "level": "ERROR", "code": None, "exception": None,
        "root_cause": None, "tags": [], "ts": "10/12/15 21:22:04:257",
        "file": "test.log", "text": text, "thread_id": "00000001",
    }


def test_likely_causes_ssl_certpath():
    events = [_make_event("PKIX path building failed: CertPathBuilderException")]
    causes = likely_causes(events)
    assert len(causes) == 1
    assert causes[0]["id"] == "ssl-trust"
    assert causes[0]["count"] == 1


def test_likely_causes_ssl_handshake():
    events = [_make_event("javax.net.ssl.SSLHandshakeException: handshake failure")]
    causes = likely_causes(events)
    ids = [c["id"] for c in causes]
    assert "ssl-trust" in ids


def test_likely_causes_ssl_cwpki():
    events = [_make_event("CWPKI0022E: SSL HANDSHAKE FAILURE")]
    causes = likely_causes(events)
    ids = [c["id"] for c in causes]
    assert "ssl-trust" in ids


def test_likely_causes_db_pool_j2ca():
    events = [_make_event("J2CA0045E: Connection not available from pool")]
    causes = likely_causes(events)
    assert len(causes) == 1
    assert causes[0]["id"] == "db-pool"


def test_likely_causes_db_pool_timeout():
    events = [_make_event("Timeout waiting for idle object in connection pool")]
    causes = likely_causes(events)
    ids = [c["id"] for c in causes]
    assert "db-pool" in ids


def test_likely_causes_db_pool_exhausted():
    events = [_make_event("JDBC pool exhausted, no connections available")]
    causes = likely_causes(events)
    ids = [c["id"] for c in causes]
    assert "db-pool" in ids


def test_likely_causes_hung_threads_wsvr0605():
    events = [_make_event("WSVR0605W: Thread stuck for 600 seconds")]
    causes = likely_causes(events)
    assert len(causes) == 1
    assert causes[0]["id"] == "hung-threads"


def test_likely_causes_hung_threads_threadmonitor():
    events = [_make_event("ThreadMonitor W   WSVR0605W: Thread is hung")]
    causes = likely_causes(events)
    ids = [c["id"] for c in causes]
    assert "hung-threads" in ids


def test_likely_causes_hung_threads_liberty():
    events = [_make_event("CWWKE0701E: A task has been running on thread for 600 seconds")]
    causes = likely_causes(events)
    ids = [c["id"] for c in causes]
    assert "hung-threads" in ids


def test_likely_causes_oom_heap():
    events = [_make_event("java.lang.OutOfMemoryError: Java heap space")]
    causes = likely_causes(events)
    assert len(causes) == 1
    assert causes[0]["id"] == "oom-gc"


def test_likely_causes_oom_gc_overhead():
    events = [_make_event("java.lang.OutOfMemoryError: GC overhead limit exceeded")]
    causes = likely_causes(events)
    ids = [c["id"] for c in causes]
    assert "oom-gc" in ids


def test_likely_causes_oom_metaspace():
    events = [_make_event("java.lang.OutOfMemoryError: Metaspace")]
    causes = likely_causes(events)
    ids = [c["id"] for c in causes]
    assert "oom-gc" in ids


def test_likely_causes_multiple_patterns():
    """Multiple different issues should produce multiple causes, sorted by count."""
    events = [
        _make_event("PKIX path building failed"),
        _make_event("SSLHandshakeException: trust failure"),
        _make_event("OutOfMemoryError: Java heap space"),
    ]
    causes = likely_causes(events)
    assert len(causes) == 2
    assert causes[0]["id"] == "ssl-trust"  # 2 events
    assert causes[0]["count"] == 2
    assert causes[1]["id"] == "oom-gc"  # 1 event
    assert causes[1]["count"] == 1


def test_likely_causes_none_detected():
    events = [_make_event("INFO: Normal application startup complete")]
    causes = likely_causes(events)
    assert causes == []


def test_likely_causes_has_fixes():
    """Each cause should include at least one fix suggestion."""
    events = [
        _make_event("OutOfMemoryError: Java heap space"),
        _make_event("WSVR0605W: Thread hung"),
        _make_event("SSLHandshakeException"),
        _make_event("J2CA0045E: pool exhausted"),
    ]
    causes = likely_causes(events)
    assert len(causes) == 4
    for c in causes:
        assert len(c["fixes"]) >= 1
        assert c["cause"]


def test_likely_causes_in_markdown_report():
    events = [_make_event("PKIX path building failed: CertPathBuilderException")]
    report = render_markdown_report(events, top_n=5, samples_n=5)
    assert "## Likely Causes & Fixes" in report
    assert "SSL / TLS Trust Failure" in report
    assert "truststore" in report


def test_likely_causes_in_json_report():
    events = [_make_event("OutOfMemoryError: Java heap space")]
    report = render_json_report(events, top_n=5, samples_n=5)
    data = json.loads(report)
    assert "likely_causes" in data
    assert len(data["likely_causes"]) == 1
    assert data["likely_causes"][0]["id"] == "oom-gc"


def test_likely_causes_not_in_report_when_none():
    events = [_make_event("INFO: everything is fine")]
    report = render_markdown_report(events, top_n=5, samples_n=5)
    assert "## Likely Causes & Fixes" not in report
