import tempfile
from pathlib import Path

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from wslog import (
    extract_ts, redact, parse_file, summarize, bucket_tags,
    time_histogram, render_histogram,
    EXC_HEAD_RE, WAS_LEVEL_RE, WAS_LEVEL_MAP, LEVEL_RE,
)

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


# --- Exception regex ---

def test_exc_matches_qualified():
    m = EXC_HEAD_RE.search("java.security.cert.CertPathBuilderException: msg")
    assert m and m.group(1) == "java.security.cert.CertPathBuilderException"


def test_exc_matches_ssl():
    m = EXC_HEAD_RE.search("javax.net.ssl.SSLHandshakeException: msg")
    assert m and m.group(1) == "javax.net.ssl.SSLHandshakeException"


def test_exc_no_match_bare_error():
    """Bare 'Error' without package qualification should NOT match."""
    m = EXC_HEAD_RE.search("Some Error occurred in the system")
    assert m is None


def test_exc_no_match_bare_exception():
    """Bare 'Exception' without package qualification should NOT match."""
    m = EXC_HEAD_RE.search("An Exception was thrown")
    assert m is None


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


# --- Full parse ---

SAMPLE_LOG = """\
[10/12/15 21:22:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: config loaded
[10/12/15 21:22:04:291 CEST] 00000001 TCPChannel    I   TCPC0001I: TCP listening on port 9081.
[10/12/15 21:22:04:385 CEST] 00000001 JMSRequestMap W   XJMS0022W: Destination in use by multiple modules.
[10/12/15 21:22:13:837 CEST] 00000150 WSX509TrustMa E   CWPKI0022E: SSL HANDSHAKE FAILURE: PKIX path building failed: java.security.cert.CertPathBuilderException: could not build path
[10/12/15 21:25:01:000 CEST] 0000014c NotificationS I   CLFWY0297I: task started
"""


def test_parse_splits_events():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_LOG)
        f.flush()
        events = parse_file(Path(f.name), max_lines=None)
    assert len(events) == 5


def test_parse_classifies_levels():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_LOG)
        f.flush()
        events = parse_file(Path(f.name), max_lines=None)
    levels = [e["level"] for e in events]
    assert levels.count("INFO") == 3
    assert levels.count("WARNING") == 1
    assert levels.count("ERROR") == 1


def test_parse_detects_exception():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_LOG)
        f.flush()
        events = parse_file(Path(f.name), max_lines=None)
    exc_events = [e for e in events if e["exception"]]
    assert len(exc_events) == 1
    assert "CertPathBuilderException" in exc_events[0]["exception"]


def test_summarize():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_LOG)
        f.flush()
        events = parse_file(Path(f.name), max_lines=None)
    s = summarize(events, top_n=10)
    assert s["total_events"] == 5
    level_dict = dict(s["levels"])
    assert level_dict["INFO"] == 3


# --- Histogram ---

def test_time_histogram():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_LOG)
        f.flush()
        events = parse_file(Path(f.name), max_lines=None)
    hist = time_histogram(events)
    assert len(hist) >= 2  # 21:22 and 21:25
    labels = [h[0] for h in hist]
    assert "21:22" in labels
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
