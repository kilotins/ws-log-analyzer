import json
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

from logpilot import (
    parse_file, summarize, pick_samples, time_histogram, render_histogram,
    per_file_summary, render_markdown_report, render_json_report,
    render_pdf_report, render_html_report,
    precompute_analysis,
)
from logpilot.event import LogEvent
from conftest import make_event, empty_match

# --- Shared fixtures ---

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
    return parse_file(sample_log)


# --- Summarize ---

def test_summarize(sample_events):
    s = summarize(sample_events, top_n=10)
    assert s["total_events"] == 5
    level_dict = dict(s["levels"])
    assert level_dict["INFO"] == 3


# --- Pick samples ---

def test_pick_samples_deduplicates():
    events = [
        LogEvent(level="ERROR", code="CWPKI0022E", exception="SSLException",
                 tags=["SSL/TLS"], ts="1", text="first",
                 thread_id="1", root_cause=None),
        LogEvent(level="ERROR", code="CWPKI0022E", exception="SSLException",
                 tags=["SSL/TLS"], ts="2", text="duplicate",
                 thread_id="2", root_cause=None),
        LogEvent(level="INFO", code=None, exception=None,
                 tags=[], ts="3", text="info",
                 thread_id="3", root_cause=None),
    ]
    samples = pick_samples(events, n=5)
    assert len(samples) == 2


def test_pick_samples_fatal_first():
    events = [
        LogEvent(level="ERROR", code="ERR0001E", exception="java.lang.RuntimeException",
                 tags=[], ts="1", text="error", thread_id="1", root_cause=None),
        LogEvent(level="FATAL", code="FAT0001F", exception="java.lang.OutOfMemoryError",
                 tags=["OOM/GC"], ts="2", text="fatal", thread_id="2", root_cause=None),
        LogEvent(level="INFO", code=None, exception=None,
                 tags=[], ts="3", text="info", thread_id="3", root_cause=None),
    ]
    samples = pick_samples(events, n=3)
    assert samples[0]["level"] == "FATAL"


def test_pick_samples_warning_over_info():
    events = [
        LogEvent(level="INFO", code=None, exception=None,
                 tags=[], ts="1", text="info", thread_id="1", root_cause=None),
        LogEvent(level="WARNING", code="WARN001W", exception=None,
                 tags=[], ts="2", text="warning", thread_id="2", root_cause=None),
    ]
    samples = pick_samples(events, n=2)
    assert samples[0]["level"] == "WARNING"


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
    assert any("2015-10-12" in l for l in labels)
    assert any("2015-10-13" in l for l in labels)


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
        [sys.executable, "-m", "logpilot", str(sample_log), "--format", "json", "--out", str(out)],
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


# --- render_markdown_report ---

def test_render_markdown_report(sample_events):
    report = render_markdown_report(sample_events, top_n=5, samples_n=3, hist_minutes=1)
    assert "# LogPilot Analysis" in report
    assert "Parsed events: 5" in report
    assert "## Top Levels" in report
    assert "## Top Message Codes" in report
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


def test_render_pdf_report(sample_events):
    pdf_bytes = render_pdf_report(sample_events, top_n=5, samples_n=3)
    assert isinstance(pdf_bytes, (bytes, bytearray))
    assert pdf_bytes[:5] == b"%PDF-"
    assert len(pdf_bytes) > 500


# --- Render reports with edge cases ---

def test_render_markdown_report_no_exceptions():
    """Report should handle events with no exceptions gracefully."""
    events = [
        LogEvent(level="INFO", code="TEST0001I", exception=None,
                 root_cause=None, tags=[], ts="10/12/15 21:22:04:257",
                 file="test.log", text="Normal info message", thread_id="00000001"),
    ]
    report = render_markdown_report(events, top_n=5, samples_n=5)
    assert "_(none detected)_" in report
    assert "## Top Levels" in report


def test_render_json_report_sample_text_truncation():
    """Sample text longer than 4000 chars should be truncated in JSON."""
    events = [
        LogEvent(level="ERROR", code="ERR0001E", exception="java.lang.RuntimeException",
                 root_cause=None, tags=[], ts="10/12/15 21:22:04:257",
                 file="test.log", text="X" * 5000, thread_id="00000001"),
    ]
    report = render_json_report(events, top_n=5, samples_n=5)
    data = json.loads(report)
    assert len(data["samples"][0]["text"]) == 4000


def test_render_pdf_report_missing_fpdf2(monkeypatch):
    """render_pdf_report should raise ImportError when fpdf2 is not installed."""
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "fpdf":
            raise ImportError("No module named 'fpdf'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    events = [make_event("ERROR: something broke")]
    with pytest.raises(ImportError, match="fpdf"):
        render_pdf_report(events)


# --- precompute_analysis ---

def test_precompute_analysis_has_all_keys():
    events = [
        LogEvent(level="ERROR", code="SRVE0255E", exception="NullPointerException",
                 root_cause="NullPointerException", thread_id="abc",
                 tags=["HTTP"], ts="2025-03-05 12:00:00", file="test.log",
                 text="SRVE0255E error"),
    ]
    pa = precompute_analysis(events)
    for key in ("summary", "samples", "hist", "file_summary", "causes", "hung"):
        assert key in pa, f"Missing key: {key}"


def test_precompute_renders_identical_output():
    events = [
        LogEvent(level="ERROR", code="SRVE0255E", exception="NullPointerException",
                 root_cause="NullPointerException", thread_id="abc",
                 tags=["HTTP"], ts="2025-03-05 12:00:00", file="test.log",
                 text="SRVE0255E error"),
    ]
    # Without precompute
    md_direct = render_markdown_report(events, top_n=5, samples_n=3, hist_minutes=1)
    js_direct = render_json_report(events, top_n=5, samples_n=3, hist_minutes=1)

    # With precompute
    pa = precompute_analysis(events, top_n=5, samples_n=3, hist_minutes=1)
    md_pre = render_markdown_report(events, _analysis=pa)
    js_pre = render_json_report(events, _analysis=pa)

    assert md_direct == md_pre
    assert js_direct == js_pre


def test_precompute_renders_identical_pdf():
    events = [
        LogEvent(level="ERROR", code="SRVE0255E", exception="NullPointerException",
                 root_cause="NullPointerException", thread_id="abc",
                 tags=["HTTP"], ts="2025-03-05 12:00:00", file="test.log",
                 text="SRVE0255E error"),
    ]
    pdf_direct = render_pdf_report(events, top_n=5, samples_n=3, hist_minutes=1)
    pa = precompute_analysis(events, top_n=5, samples_n=3, hist_minutes=1)
    pdf_pre = render_pdf_report(events, _analysis=pa)
    assert pdf_direct == pdf_pre


def test_precompute_analysis_empty_events():
    pa = precompute_analysis([], top_n=5, samples_n=3, hist_minutes=1)
    assert pa["summary"]["total_events"] == 0
    assert pa["samples"] == []
    assert pa["hist"] == []
    assert pa["causes"] == []
    assert pa["hung"] == []


def test_render_markdown_report_empty_events():
    md = render_markdown_report([], top_n=5, samples_n=3, hist_minutes=1)
    assert "Parsed events: 0" in md


def test_render_json_report_empty_events():
    js = render_json_report([], top_n=5, samples_n=3, hist_minutes=1)
    data = json.loads(js)
    assert data["total_events"] == 0


# --- HTML export tests ---

class TestRenderHtmlReport:
    def test_html_has_structure(self):
        events = [make_event(level="ERROR", text="fail")]
        html = render_html_report(events)
        assert "<!DOCTYPE html>" in html
        assert "<title>LogPilot Analysis" in html
        assert "</html>" in html

    def test_html_contains_event_data(self):
        events = [make_event(level="ERROR", code="SRVE0293E",
                             exception="NullPointerException", tags=["HTTP"], text="error text")]
        html = render_html_report(events)
        assert "ERROR" in html
        assert "SRVE0293E" in html
        assert "NullPointerException" in html
        assert "error text" in html

    def test_html_escapes_special_chars(self):
        events = [make_event(level="ERROR", text="a < b & c > d")]
        html = render_html_report(events)
        assert "&lt;" in html
        assert "&amp;" in html

    def test_html_empty_events(self):
        html = render_html_report([])
        assert "<!DOCTYPE html>" in html
        assert "LogPilot" in html

    def test_html_includes_ai_incident(self):
        events = [make_event(level="ERROR", text="fail")]
        ai = {"incident": "Root cause is DB connection timeout", "incident_model": "Claude"}
        html = render_html_report(events, ai_content=ai)
        assert "Root cause is DB connection timeout" in html
        assert "Claude" in html
        assert "Incident Summary" in html

    def test_html_no_ai_queries_section(self):
        """AI Queries history section should not appear in exports."""
        events = [make_event(level="ERROR", text="fail")]
        ai = {"ask_ai": [{"query": "What happened?", "answer": "A crash occurred",
                           "provider": "Gemini", "timestamp": "12:00:00"}]}
        html = render_html_report(events, ai_content=ai)
        assert "AI Queries" not in html
        assert "Previous AI Queries" not in html


# --- 10.5 render_pdf_report() content verification ---

def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Decompress all FlateDecode streams in a PDF and return concatenated text."""
    import re
    import zlib
    raw = bytes(pdf_bytes)
    texts = []
    for m in re.finditer(b'stream\n(.+?)\nendstream', raw, re.DOTALL):
        try:
            decompressed = zlib.decompress(m.group(1)).decode("latin-1", errors="ignore")
            texts.append(decompressed)
        except Exception:
            pass
    return "\n".join(texts)


def test_render_pdf_report_contains_summary_text():
    """Verify PDF output contains expected section headings and data."""
    try:
        import fpdf  # noqa: F401
    except ImportError:
        pytest.skip("fpdf2 not installed")

    events = [
        LogEvent(level="ERROR", code="CWPKI0022E", exception="SSLHandshakeException",
                 root_cause="javax.net.ssl.SSLException", tags=["SSL/TLS"],
                 ts="10/12/15 21:22:04:257", file="test.log",
                 text="CWPKI0022E: SSL HANDSHAKE FAILURE", thread_id="00000150"),
        LogEvent(level="INFO", code="ARFM5007I", exception=None,
                 root_cause=None, tags=[],
                 ts="10/12/15 21:22:05:000", file="test.log",
                 text="ARFM5007I: config loaded", thread_id="00000001"),
    ]
    pdf_bytes = render_pdf_report(events, top_n=5, samples_n=5)
    pdf_text = _extract_pdf_text(pdf_bytes)
    assert "Events: 2" in pdf_text
    assert "Severity Distribution" in pdf_text
    assert "ERROR" in pdf_text
    assert "INFO" in pdf_text
    assert "Sample Events" in pdf_text


def test_render_pdf_report_contains_codes_section():
    """Verify PDF includes WebSphere codes section."""
    try:
        import fpdf  # noqa: F401
    except ImportError:
        pytest.skip("fpdf2 not installed")

    events = [
        LogEvent(level="ERROR", code="CWPKI0022E", exception="SSLHandshakeException",
                 root_cause=None, tags=["SSL/TLS"],
                 ts="10/12/15 21:22:04:257", file="test.log",
                 text="CWPKI0022E: SSL failure", thread_id="00000150"),
    ]
    pdf_bytes = render_pdf_report(events, top_n=5, samples_n=5)
    pdf_text = _extract_pdf_text(pdf_bytes)
    assert "Top Message Codes" in pdf_text
    assert "CWPKI0022E" in pdf_text


# ---------------------------------------------------------------------------
# Performance tests for large log files
# ---------------------------------------------------------------------------

def test_parse_large_file_performance():
    """Parse a 100k-line WAS log file and verify it completes without error."""
    lines = []
    for i in range(100_000):
        if i % 500 == 0:
            level, code = "E", "SRVE0255E"
            text = f"SRVE0255E: Error on line {i}\njava.lang.NullPointerException: simulated\n\tat com.example.Foo.bar(Foo.java:{i})"
        elif i % 200 == 0:
            level, code = "W", "XJMS0022W"
            text = f"XJMS0022W: Warning message {i}"
        else:
            level, code = "O", ""
            text = f"Some log message {i}"
        lines.append(
            f"[03/09/26 12:00:{i % 60:02d}:000 EST] 00000001 SystemOut     {level}   {code + ': ' if code else ''}{text}"
        )
    content = "\n".join(lines) + "\n"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(content)
        tmp_path = f.name

    try:
        t0 = time.time()
        events = parse_file(Path(tmp_path))
        elapsed = time.time() - t0
        # Should return a reasonable number of events (at least a few hundred)
        assert len(events) > 100, f"Expected many events, got {len(events)}"
        # Just log timing — no assertion on speed
        print(f"Parsed 100k lines in {elapsed:.2f}s -> {len(events)} events")
    finally:
        import os as _os
        _os.unlink(tmp_path)


def test_summarize_large_event_list():
    """Summarize 50k synthetic events and verify output structure."""
    events = []
    levels = ["INFO", "WARNING", "ERROR"]
    for i in range(50_000):
        events.append(LogEvent(
            ts=f"2026-03-09 12:{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}",
            level=levels[i % 3],
            code=f"TEST{i % 100:04d}I" if i % 5 == 0 else None,
            exception="NullPointerException" if i % 1000 == 0 else None,
            tags=["DB/Pool"] if i % 2000 == 0 else [],
            text=f"Synthetic event {i}",
            thread_id=f"{i % 50:08x}",
            root_cause=None,
        ))

    s = summarize(events, top_n=10)
    assert s["total_events"] == 50_000
    assert "levels" in s
    assert "codes" in s
    assert len(s["codes"]) <= 10


def test_time_histogram_many_events():
    """Create 10k events with varied timestamps and verify histogram output."""
    events = []
    for i in range(10_000):
        hour = i % 24
        minute = (i * 7) % 60
        events.append(LogEvent(
            ts=f"2026-03-09 {hour:02d}:{minute:02d}:00",
            level="ERROR" if i % 100 == 0 else "INFO",
            code=None,
            exception=None,
            tags=[],
            text=f"Event {i}",
            thread_id="00000001",
            root_cause=None,
        ))

    hist = time_histogram(events)
    assert len(hist) > 0, "Histogram should have at least one bucket"
    # Each entry is (bucket_label, total, error_count)
    for label, total, err_count in hist:
        assert total > 0
