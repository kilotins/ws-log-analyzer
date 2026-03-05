import json
import subprocess
from pathlib import Path

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from wslog import (
    extract_ts, redact, parse_file, summarize, bucket_tags,
    time_histogram, render_histogram, pick_samples, per_file_summary,
    _parse_ts_parts,
    EXC_HEAD_RE, WAS_LEVEL_RE, WAS_LEVEL_MAP, WAS_CODE_RE, LEVEL_RE,
)

# --- Shared fixture ---

SAMPLE_LOG = """\
[10/12/15 21:22:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: config loaded
[10/12/15 21:22:04:291 CEST] 00000001 TCPChannel    I   TCPC0001I: TCP listening on port 9081.
[10/12/15 21:22:04:385 CEST] 00000001 JMSRequestMap W   XJMS0022W: Destination in use by multiple modules.
[10/12/15 21:22:13:837 CEST] 00000150 WSX509TrustMa E   CWPKI0022E: SSL HANDSHAKE FAILURE: PKIX path building failed: java.security.cert.CertPathBuilderException: could not build path
[10/12/15 21:25:01:000 CEST] 0000014c NotificationS I   CLFWY0297I: task started
"""

MULTI_DAY_LOG = """\
[10/12/15 23:59:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: before midnight
[10/13/15 00:01:04:257 CEST] 00000001 TCPChannel    I   TCPC0001I: after midnight
"""


@pytest.fixture
def sample_log(tmp_path):
    p = tmp_path / "test.log"
    p.write_text(SAMPLE_LOG)
    return p


@pytest.fixture
def multi_day_log(tmp_path):
    p = tmp_path / "multi.log"
    p.write_text(MULTI_DAY_LOG)
    return p


@pytest.fixture
def sample_events(sample_log):
    return parse_file(sample_log, max_lines=None)


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


def test_was_level_takes_priority(sample_events):
    """WAS single-letter level should be used over keyword matches in message body."""
    # The INFO line has "ARFM5007I" which contains no LEVEL_RE keyword,
    # but the WARNING line text contains "XJMS0022W" — WAS_LEVEL_RE should classify it.
    levels = [e["level"] for e in sample_events]
    assert levels == ["INFO", "INFO", "WARNING", "ERROR", "INFO"]


# --- WAS code regex ---

def test_was_code_matches_common_prefixes():
    """Generalized pattern should match codes beyond the original 8 prefixes."""
    for code in ["ARFM5007I", "TCPC0001I", "CHFW0019I", "SCHD0077I",
                 "CWPKI0022E", "CWWIM6002I", "ODCF8010I", "XJMS0008I",
                 "CLFWY0297I", "CWLRB5873I"]:
        m = WAS_CODE_RE.search(f"some text {code}: message")
        assert m and m.group(1) == code, f"Failed to match {code}"


def test_was_code_no_false_positive():
    """Should not match random uppercase strings or short codes."""
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
    """Bare 'Error' without package qualification should NOT match."""
    assert EXC_HEAD_RE.search("Some Error occurred in the system") is None


def test_exc_no_match_bare_exception():
    """Bare 'Exception' without package qualification should NOT match."""
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


def test_summarize(sample_events):
    s = summarize(sample_events, top_n=10)
    assert s["total_events"] == 5
    level_dict = dict(s["levels"])
    assert level_dict["INFO"] == 3


# --- Pick samples ---

def test_pick_samples_deduplicates():
    """Duplicate (level, code, exception) combos should be collapsed."""
    events = [
        {"level": "ERROR", "code": "CWPKI0022E", "exception": "SSLException",
         "tags": ["SSL/TLS"], "ts": "1", "text": "first"},
        {"level": "ERROR", "code": "CWPKI0022E", "exception": "SSLException",
         "tags": ["SSL/TLS"], "ts": "2", "text": "duplicate"},
        {"level": "INFO", "code": None, "exception": None,
         "tags": [], "ts": "3", "text": "info"},
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
    events = parse_file(multi_day_log, max_lines=None)
    hist = time_histogram(events)
    labels = [h[0] for h in hist]
    # Should include date prefix when multiple dates present
    assert any("10/12/15" in l for l in labels)
    assert any("10/13/15" in l for l in labels)


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
    events = parse_file(log1, None) + parse_file(log2, None)
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


# --- _parse_ts_parts ---

def test_parse_ts_parts_was():
    result = _parse_ts_parts("10/12/15 21:22:04:257")
    assert result == ("10/12/15", 21, 22)


def test_parse_ts_parts_iso():
    result = _parse_ts_parts("2025-03-05T12:34:56.789")
    assert result == ("2025-03-05", 12, 34)


def test_parse_ts_parts_invalid():
    assert _parse_ts_parts("garbage") is None
