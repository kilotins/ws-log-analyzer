import json
import re as _re
from pathlib import Path

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

from logpilot import (
    parse_file, likely_causes, suggested_splunk_queries,
    hung_thread_drilldown,
    render_markdown_report, render_json_report,
    incident_timeline,
    per_file_summary, summarize,
)
from logpilot.splunk import _extract_hung_thread_name, _extract_stack_sample
from logpilot.heuristics import _load_heuristics_from_yaml
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

SECOND_LOG = """\
[10/13/15 08:00:01:000 CEST] 00000200 AppServer     I   WSVR0001I: Server open for e-business
[10/13/15 08:00:02:000 CEST] 00000201 DataSource    E   J2CA0045E: Connection not available from pool
[10/13/15 08:00:03:000 CEST] 00000202 WebContainer  W   SRVE0255W: request timeout
"""

HUNG_THREAD_LOG_WEBCONTAINER = """\
[10/12/15 21:22:04:257 CEST] 00000150 ThreadMonitor W   WSVR0605W: Thread "WebContainer : 5" (00000150) has been active for 612015 milliseconds and may be hung. There is/are 1 thread(s) in total in the server that may be hung.
\tat com.ibm.ws.webcontainer.servlet.ServletWrapper.handleRequest(ServletWrapper.java:776)
\tat com.ibm.ws.webcontainer.webapp.WebApp.handleRequest(WebApp.java:3941)
\tat com.ibm.ws.webcontainer.channel.WCChannelLink.ready(WCChannelLink.java:200)
[10/12/15 21:32:04:500 CEST] 00000150 ThreadMonitor W   WSVR0605W: Thread "WebContainer : 5" (00000150) has been active for 1212015 milliseconds and may be hung. There is/are 2 thread(s) in total in the server that may be hung.
\tat com.ibm.ws.webcontainer.servlet.ServletWrapper.handleRequest(ServletWrapper.java:776)
[10/12/15 21:32:05:000 CEST] 00000160 ThreadMonitor W   WSVR0605W: Thread "WebContainer : 8" (00000160) has been active for 600123 milliseconds and may be hung.
\tat com.example.service.SlowService.process(SlowService.java:42)
\tat com.example.web.ApiServlet.doGet(ApiServlet.java:118)
"""

HUNG_THREAD_LOG_LIBERTY = """\
[10/12/15 21:22:04:257 CEST] 00000170 com.ibm.ws.kernel.launch.internal.FrameworkManager E   CWWKE0701E: A task that was submitted to the Default Executor-thread-42 has been running for 601234 milliseconds. This task might be hung.
\tat com.example.batch.LongRunningJob.execute(LongRunningJob.java:55)
\tat com.ibm.ws.threading.internal.ExecutorServiceImpl$RunnableWrapper.run(ExecutorServiceImpl.java:237)
"""

HUNG_THREAD_LOG_QUOTED = """\
[10/12/15 21:22:04:257 CEST] 00000180 ThreadMonitor W   WSVR0605W: Thread "ORB.thread.pool : 3" (00000180) has been active for 700000 milliseconds and may be hung.
"""


@pytest.fixture
def sample_log(tmp_path):
    p = tmp_path / "test.log"
    p.write_text(SAMPLE_LOG)
    return p


@pytest.fixture
def second_log(tmp_path):
    p = tmp_path / "second.log"
    p.write_text(SECOND_LOG)
    return p


@pytest.fixture
def hung_webcontainer_log(tmp_path):
    p = tmp_path / "hung_wc.log"
    p.write_text(HUNG_THREAD_LOG_WEBCONTAINER)
    return p


@pytest.fixture
def hung_liberty_log(tmp_path):
    p = tmp_path / "hung_liberty.log"
    p.write_text(HUNG_THREAD_LOG_LIBERTY)
    return p


@pytest.fixture
def hung_quoted_log(tmp_path):
    p = tmp_path / "hung_quoted.log"
    p.write_text(HUNG_THREAD_LOG_QUOTED)
    return p


# --- Likely causes heuristics (parametrized) ---

@pytest.mark.parametrize("text,expected_id", [
    ("PKIX path building failed: CertPathBuilderException", "ssl-trust"),
    ("javax.net.ssl.SSLHandshakeException: handshake failure", "ssl-trust"),
    ("CWPKI0022E: SSL HANDSHAKE FAILURE", "ssl-trust"),
    ("J2CA0045E: Connection not available from pool", "db-pool"),
    ("Timeout waiting for idle object in connection pool", "db-pool"),
    ("JDBC pool exhausted, no connections available", "db-pool"),
    ("WSVR0605W: Thread stuck for 600 seconds", "hung-threads"),
    ("ThreadMonitor W   WSVR0605W: Thread is hung", "hung-threads"),
    ("CWWKE0701E: A task has been running on thread for 600 seconds", "hung-threads"),
    ("java.lang.OutOfMemoryError: Java heap space", "oom-gc"),
    ("java.lang.OutOfMemoryError: GC overhead limit exceeded", "oom-gc"),
    ("java.lang.OutOfMemoryError: Metaspace", "oom-gc"),
])
def test_likely_causes(text, expected_id):
    events = [make_event(text)]
    causes = likely_causes(events)
    ids = [c["id"] for c in causes]
    assert expected_id in ids


def test_likely_causes_ssl_certpath_count():
    events = [make_event("PKIX path building failed: CertPathBuilderException")]
    causes = likely_causes(events)
    assert len(causes) == 1
    assert causes[0]["count"] == 1


def test_likely_causes_db_pool_j2ca_count():
    events = [make_event("J2CA0045E: Connection not available from pool")]
    causes = likely_causes(events)
    assert len(causes) == 1


def test_likely_causes_hung_threads_wsvr0605_count():
    events = [make_event("WSVR0605W: Thread stuck for 600 seconds")]
    causes = likely_causes(events)
    assert len(causes) == 1


def test_likely_causes_oom_heap_count():
    events = [make_event("java.lang.OutOfMemoryError: Java heap space")]
    causes = likely_causes(events)
    assert len(causes) == 1


def test_likely_causes_multiple_patterns():
    """Multiple different issues should produce multiple causes, sorted by count."""
    events = [
        make_event("PKIX path building failed"),
        make_event("SSLHandshakeException: trust failure"),
        make_event("OutOfMemoryError: Java heap space"),
    ]
    causes = likely_causes(events)
    assert len(causes) == 2
    assert causes[0]["id"] == "ssl-trust"  # 2 events
    assert causes[0]["count"] == 2
    assert causes[1]["id"] == "oom-gc"  # 1 event
    assert causes[1]["count"] == 1


def test_likely_causes_none_detected():
    events = [make_event("INFO: Normal application startup complete")]
    causes = likely_causes(events)
    assert causes == []


def test_likely_causes_has_fixes():
    """Each cause should include at least one fix suggestion."""
    events = [
        make_event("OutOfMemoryError: Java heap space"),
        make_event("WSVR0605W: Thread hung"),
        make_event("SSLHandshakeException"),
        make_event("J2CA0045E: pool exhausted"),
    ]
    causes = likely_causes(events)
    base_causes = [c for c in causes if not c["id"].startswith("corr-")]
    assert len(base_causes) == 4
    for c in causes:
        assert len(c["fixes"]) >= 1
        assert c["cause"]


def test_likely_causes_in_markdown_report():
    events = [make_event("PKIX path building failed: CertPathBuilderException")]
    report = render_markdown_report(events, top_n=5, samples_n=5)
    assert "## Likely Causes & Fixes" in report
    assert "SSL / TLS Trust Failure" in report
    assert "truststore" in report


def test_likely_causes_in_json_report():
    events = [make_event("OutOfMemoryError: Java heap space")]
    report = render_json_report(events, top_n=5, samples_n=5)
    data = json.loads(report)
    assert "likely_causes" in data
    assert len(data["likely_causes"]) == 1
    assert data["likely_causes"][0]["id"] == "oom-gc"


def test_likely_causes_not_in_report_when_none():
    events = [make_event("INFO: everything is fine")]
    report = render_markdown_report(events, top_n=5, samples_n=5)
    assert "## Likely Causes & Fixes" not in report


# --- Multi-file combined analysis ---

def test_multi_file_combined_events(sample_log, second_log):
    """Events from multiple files should be combined."""
    events = parse_file(sample_log) + parse_file(second_log)
    assert len(events) == 8  # 5 from sample + 3 from second


def test_multi_file_per_file_summary(sample_log, second_log):
    """Per-file summary should list each file with correct counts."""
    events = parse_file(sample_log) + parse_file(second_log)
    fs = per_file_summary(events)
    assert len(fs) == 2
    by_file = {Path(f).name: (t, e) for f, t, e in fs}
    assert by_file["test.log"] == (5, 1)
    assert by_file["second.log"] == (3, 1)


def test_multi_file_combined_summarize(sample_log, second_log):
    """Summarize should aggregate across all files."""
    events = parse_file(sample_log) + parse_file(second_log)
    s = summarize(events, top_n=10)
    assert s["total_events"] == 8
    level_dict = dict(s["levels"])
    assert level_dict["INFO"] == 4  # 3 from sample + 1 from second
    assert level_dict["ERROR"] == 2  # 1 from each


def test_multi_file_markdown_report_shows_breakdown(sample_log, second_log):
    """Markdown report should include per-file breakdown when multiple files."""
    events = parse_file(sample_log) + parse_file(second_log)
    report = render_markdown_report(events, top_n=5, samples_n=3)
    assert "## Per-File Breakdown" in report
    assert "Files: 2" in report
    assert "8" in report  # total events


def test_multi_file_json_report_has_files(sample_log, second_log):
    """JSON report should list each file with event counts."""
    events = parse_file(sample_log) + parse_file(second_log)
    report = render_json_report(events, top_n=5, samples_n=3)
    data = json.loads(report)
    assert len(data["files"]) == 2
    assert data["total_events"] == 8
    file_events = {Path(f["file"]).name: f["events"] for f in data["files"]}
    assert file_events["test.log"] == 5
    assert file_events["second.log"] == 3


def test_multi_file_cli_output(sample_log, second_log, tmp_path):
    """CLI should report per-file counts and combined total."""
    import subprocess
    out = tmp_path / "report.md"
    result = subprocess.run(
        [sys.executable, "-m", "logpilot", str(sample_log), str(second_log), "--out", str(out)],
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(__file__)),
    )
    assert result.returncode == 0
    assert "test.log: 5 events" in result.stderr
    assert "second.log: 3 events" in result.stderr
    assert "Combined: 8 events from 2 files" in result.stderr
    report = out.read_text()
    assert "Files: 2" in report
    assert "Per-File Breakdown" in report


def test_multi_file_signals_combined(sample_log, second_log):
    """Signal tags should aggregate across files."""
    events = parse_file(sample_log) + parse_file(second_log)
    s = summarize(events, top_n=10)
    tag_dict = dict(s["tags"])
    assert "SSL/TLS" in tag_dict  # from sample_log
    assert "DB/Pool" in tag_dict  # from second_log


# --- Suggested Splunk searches ---

def test_splunk_always_has_generic_error_query():
    """Should always include a generic error query."""
    s = {"exceptions": [], "codes": [], "tags": []}
    queries = suggested_splunk_queries(s, [], [])
    assert len(queries) >= 1
    assert any("ERROR OR SEVERE OR FATAL" in q["query"] for q in queries)


def test_splunk_exception_based_query():
    """Should generate query for detected exceptions."""
    s = {
        "exceptions": [("java.security.cert.CertPathBuilderException", 3)],
        "codes": [], "tags": [],
    }
    queries = suggested_splunk_queries(s, [], [])
    assert any("CertPathBuilderException" in q["query"] for q in queries)


def test_splunk_code_based_query():
    """Should generate prefix-grouped query for WAS codes."""
    s = {
        "exceptions": [],
        "codes": [("CWPKI0022E", 5), ("CWPKI0033E", 2)],
        "tags": [],
    }
    queries = suggested_splunk_queries(s, [], [])
    assert any("CWPKI" in q["query"] for q in queries)


def test_splunk_ssl_tag_query():
    """SSL/TLS tag should produce a targeted query."""
    s = {"exceptions": [], "codes": [], "tags": [("SSL/TLS", 4)]}
    queries = suggested_splunk_queries(s, [], [])
    assert any("SSLHandshakeException" in q["query"] for q in queries)


def test_splunk_oom_tag_query():
    """OOM/GC tag should produce a targeted query."""
    s = {"exceptions": [], "codes": [], "tags": [("OOM/GC", 2)]}
    queries = suggested_splunk_queries(s, [], [])
    assert any("OutOfMemoryError" in q["query"] for q in queries)


def test_splunk_db_pool_tag_query():
    """DB/Pool tag should produce a targeted query."""
    s = {"exceptions": [], "codes": [], "tags": [("DB/Pool", 1)]}
    queries = suggested_splunk_queries(s, [], [])
    assert any("J2CA" in q["query"] for q in queries)


def test_splunk_hung_threads_tag_query():
    """HungThreads tag should produce a targeted query."""
    s = {"exceptions": [], "codes": [], "tags": [("HungThreads", 1)]}
    queries = suggested_splunk_queries(s, [], [])
    assert any("WSVR0605W" in q["query"] for q in queries)


def test_splunk_spike_query_when_timeline():
    """Should include timechart query when histogram data exists."""
    s = {"exceptions": [], "codes": [], "tags": []}
    hist = [("21:22", 10, 2)]
    queries = suggested_splunk_queries(s, [], hist)
    assert any("timechart" in q["query"] for q in queries)


def test_splunk_no_spike_query_without_timeline():
    """Should not include timechart query when no histogram data."""
    s = {"exceptions": [], "codes": [], "tags": []}
    queries = suggested_splunk_queries(s, [], [])
    assert not any("timechart" in q["query"] for q in queries)


def test_splunk_max_8_queries():
    """Should cap at 8 queries even with many detections."""
    s = {
        "exceptions": [("a.b.FooException", 5), ("c.d.BarException", 3), ("e.f.BazException", 1)],
        "codes": [("AAAA0001E", 5), ("BBBB0001E", 3), ("CCCC0001E", 1)],
        "tags": [("SSL/TLS", 4), ("OOM/GC", 2), ("DB/Pool", 1), ("HungThreads", 1)],
    }
    hist = [("21:22", 10, 2)]
    queries = suggested_splunk_queries(s, [], hist)
    assert len(queries) <= 8


def test_splunk_uses_placeholder_index():
    """All queries should use the vendor-neutral placeholder prefix."""
    s = {
        "exceptions": [("javax.net.ssl.SSLHandshakeException", 2)],
        "codes": [("CWPKI0022E", 3)],
        "tags": [("SSL/TLS", 2)],
    }
    queries = suggested_splunk_queries(s, [], [("21:22", 10, 2)])
    for q in queries:
        assert "index=APP" in q["query"]
        assert "sourcetype=WAS" in q["query"]


def test_splunk_in_markdown_report():
    events = [make_event("CWPKI0022E: PKIX path building failed: CertPathBuilderException")]
    report = render_markdown_report(events, top_n=5, samples_n=5)
    assert "## Suggested Splunk Searches" in report
    assert "index=APP" in report


def test_splunk_in_json_report():
    events = [make_event("OutOfMemoryError: Java heap space")]
    report = render_json_report(events, top_n=5, samples_n=5)
    data = json.loads(report)
    assert "splunk_queries" in data
    assert len(data["splunk_queries"]) >= 1


# --- Hung thread drilldown ---

def test_extract_hung_thread_name_webcontainer():
    text = 'WSVR0605W: Thread "WebContainer : 5" (00000150) has been active'
    assert _extract_hung_thread_name(text) == "WebContainer : 5"


def test_extract_hung_thread_name_liberty():
    text = "submitted to the Default Executor-thread-42 has been running"
    assert _extract_hung_thread_name(text) == "Default Executor-thread-42"


def test_extract_hung_thread_name_quoted():
    text = 'WSVR0605W: Thread "ORB.thread.pool : 3" (00000180) has been active'
    assert _extract_hung_thread_name(text) == "ORB.thread.pool : 3"


def test_extract_hung_thread_name_none():
    assert _extract_hung_thread_name("normal log line without thread info") is None


def test_extract_stack_sample():
    text = (
        "WSVR0605W: Thread hung\n"
        "\tat com.example.Foo.bar(Foo.java:10)\n"
        "\tat com.example.Baz.qux(Baz.java:20)\n"
        "\tat com.example.Main.run(Main.java:5)\n"
    )
    lines = _extract_stack_sample(text, max_lines=2)
    assert len(lines) == 2
    assert "com.example.Foo.bar" in lines[0]


def test_extract_stack_sample_empty():
    assert _extract_stack_sample("no stack trace here") == []


def test_hung_thread_drilldown_webcontainer(hung_webcontainer_log):
    """Should detect WebContainer threads with counts, timestamps, and stacks."""
    events = parse_file(hung_webcontainer_log)
    drilldown = hung_thread_drilldown(events)
    assert len(drilldown) == 2

    # WebContainer : 5 appears twice, should be first (sorted by count)
    wc5 = drilldown[0]
    assert wc5["thread_name"] == "WebContainer : 5"
    assert wc5["count"] == 2
    assert wc5["first_ts"] == "10/12/15 21:22:04:257"
    assert wc5["last_ts"] == "10/12/15 21:32:04:500"
    assert "00000150" in wc5["hex_ids"]
    assert len(wc5["stack_sample"]) >= 1
    assert "ServletWrapper" in wc5["stack_sample"][0]
    assert "index=APP" in wc5["splunk_query"]
    assert "WebContainer : 5" in wc5["splunk_query"]

    # WebContainer : 8 appears once
    wc8 = drilldown[1]
    assert wc8["thread_name"] == "WebContainer : 8"
    assert wc8["count"] == 1
    assert "00000160" in wc8["hex_ids"]
    assert any("SlowService" in line for line in wc8["stack_sample"])


def test_hung_thread_drilldown_liberty(hung_liberty_log):
    """Should detect Liberty Default Executor threads."""
    events = parse_file(hung_liberty_log)
    drilldown = hung_thread_drilldown(events)
    assert len(drilldown) == 1
    assert drilldown[0]["thread_name"] == "Default Executor-thread-42"
    assert drilldown[0]["count"] == 1
    assert any("LongRunningJob" in line for line in drilldown[0]["stack_sample"])


def test_hung_thread_drilldown_quoted_name(hung_quoted_log):
    """Should extract quoted thread names like ORB.thread.pool."""
    events = parse_file(hung_quoted_log)
    drilldown = hung_thread_drilldown(events)
    assert len(drilldown) == 1
    assert drilldown[0]["thread_name"] == "ORB.thread.pool : 3"


def test_hung_thread_drilldown_no_hung_threads():
    """Should return empty list when no hung threads detected."""
    events = [make_event("INFO: Normal application startup")]
    assert hung_thread_drilldown(events) == []


def test_hung_thread_drilldown_fallback_to_hex_id():
    """Should fall back to hex thread ID when no thread name is extractable."""
    events = [make_event("WSVR0605W: stuck thread detected")]
    events[0]["thread_id"] = "0000abcd"
    drilldown = hung_thread_drilldown(events)
    assert len(drilldown) == 1
    assert drilldown[0]["thread_name"] == "0x0000abcd"


def test_hung_thread_drilldown_in_markdown_report(hung_webcontainer_log):
    events = parse_file(hung_webcontainer_log)
    report = render_markdown_report(events, top_n=5, samples_n=5)
    assert "## Hung Thread Drilldown" in report
    assert "WebContainer : 5" in report
    assert "WebContainer : 8" in report
    assert "ServletWrapper" in report
    assert "index=APP" in report


def test_hung_thread_drilldown_in_json_report(hung_webcontainer_log):
    events = parse_file(hung_webcontainer_log)
    report = render_json_report(events, top_n=5, samples_n=5)
    data = json.loads(report)
    assert "hung_thread_drilldown" in data
    assert len(data["hung_thread_drilldown"]) == 2
    names = [t["thread_name"] for t in data["hung_thread_drilldown"]]
    assert "WebContainer : 5" in names
    assert "WebContainer : 8" in names


def test_hung_thread_drilldown_not_in_report_when_none():
    events = [make_event("INFO: all good")]
    report = render_markdown_report(events, top_n=5, samples_n=5)
    assert "## Hung Thread Drilldown" not in report


# --- incident_timeline tests ---

def test_incident_timeline_basic():
    events = [
        LogEvent(level="INFO", ts="10/12/15 21:22:00:000", code=None,
                 exception=None, thread_id=None, tags=[], text="startup"),
        LogEvent(level="ERROR", ts="10/12/15 21:22:04:257", code="SRVE0293E",
                 exception="java.lang.NullPointerException", thread_id="0000004e",
                 tags=[], text="error happened"),
        LogEvent(level="INFO", ts="10/12/15 21:22:10:000", code=None,
                 exception=None, thread_id=None, tags=[], text="after error"),
    ]
    itl = incident_timeline(events, window_seconds=30)
    assert itl is not None
    assert itl["trigger_event"]["code"] == "SRVE0293E"
    assert len(itl["window_events"]) == 3  # all within 30s


def test_incident_timeline_no_errors():
    events = [
        LogEvent(level="INFO", ts="10/12/15 21:22:00:000", code=None,
                 exception=None, thread_id=None, tags=[], text="ok"),
    ]
    assert incident_timeline(events) is None


def test_incident_timeline_window_filters():
    events = [
        LogEvent(level="INFO", ts="10/12/15 21:20:00:000", code=None,
                 exception=None, thread_id=None, tags=[], text="too early"),
        LogEvent(level="ERROR", ts="10/12/15 21:22:04:257", code="ERR001E",
                 exception=None, thread_id=None, tags=[], text="trigger"),
        LogEvent(level="INFO", ts="10/12/15 21:22:30:000", code=None,
                 exception=None, thread_id=None, tags=[], text="within window"),
        LogEvent(level="INFO", ts="10/12/15 21:25:00:000", code=None,
                 exception=None, thread_id=None, tags=[], text="too late"),
    ]
    itl = incident_timeline(events, window_seconds=30)
    assert itl is not None
    assert len(itl["window_events"]) == 2  # trigger + within window


# ── _load_heuristics_from_yaml() ─────────────────────────────────────

def test_load_heuristics_from_yaml_returns_list():
    """When heuristics_data.yaml exists, returns a non-empty heuristics list."""
    heuristics, correlations, incident_groups = _load_heuristics_from_yaml()
    if heuristics is None:
        pytest.skip("yaml not installed or heuristics_data.yaml missing")
    assert isinstance(heuristics, list)
    assert len(heuristics) > 0


def test_load_heuristics_from_yaml_entry_keys():
    """Each heuristic entry has required keys: match, cause, fixes."""
    heuristics, _, _ = _load_heuristics_from_yaml()
    if heuristics is None:
        pytest.skip("yaml not installed or heuristics_data.yaml missing")
    for entry in heuristics:
        assert "match" in entry, f"entry missing 'match': {entry}"
        assert "cause" in entry, f"entry missing 'cause': {entry}"
        assert "fixes" in entry, f"entry missing 'fixes': {entry}"


def test_load_heuristics_from_yaml_patterns_are_compiled():
    """The 'match' field should be a compiled regex pattern."""
    heuristics, _, _ = _load_heuristics_from_yaml()
    if heuristics is None:
        pytest.skip("yaml not installed or heuristics_data.yaml missing")
    for entry in heuristics:
        assert isinstance(entry["match"], _re.Pattern), (
            f"'match' is not a compiled regex: {type(entry['match'])}"
        )


def test_load_heuristics_from_yaml_correlations():
    """Correlations should be loaded from YAML."""
    _, correlations, _ = _load_heuristics_from_yaml()
    if correlations is None:
        pytest.skip("yaml not installed or heuristics_data.yaml missing")
    assert isinstance(correlations, list)
    assert len(correlations) > 0
    for c in correlations:
        assert "id" in c
        assert "requires" in c
        assert "cause" in c


def test_load_heuristics_from_yaml_incident_groups():
    """Incident groups should be loaded from YAML."""
    _, _, incident_groups = _load_heuristics_from_yaml()
    if incident_groups is None:
        pytest.skip("yaml not installed or heuristics_data.yaml missing")
    assert isinstance(incident_groups, list)
    assert len(incident_groups) > 0
    for ig in incident_groups:
        assert "id" in ig
        assert "trigger_ids" in ig
        assert isinstance(ig["trigger_ids"], set)


# --- 17.3 likely_causes pre-filtering regression test ---

def test_likely_causes_prefiltering_regression():
    """Verify likely_causes returns same results with pre-filtering optimization."""
    events = [
        LogEvent(text="CWPKI0022E: SSL HANDSHAKE FAILURE: PKIX path building failed: java.security.cert.CertPathBuilderException"),
        LogEvent(text="J2CA0045E: Connection pool exhausted for datasource jdbc/myDS"),
        LogEvent(text="WSVR0605W: Thread WebContainer : 5 has been active for 623,456 milliseconds"),
        LogEvent(text="OutOfMemoryError: Java heap space"),
        LogEvent(text="ARFM5007I: config loaded"),  # should not match any heuristic
    ]
    results = likely_causes(events)
    # Should detect SSL, DB pool, hung threads, OOM
    ids = {r["id"] for r in results}
    assert "ssl-trust" in ids
    assert "db-pool" in ids
    assert "hung-threads" in ids
    assert "oom-gc" in ids
    # Base heuristics each have count == 1
    base_results = [r for r in results if not r["id"].startswith("corr-")]
    for r in base_results:
        assert r["count"] == 1
    # Correlations may also fire (e.g. corr-oom-pool from oom-gc + db-pool)
    assert len(base_results) == 4


def test_likely_causes_prefiltering_no_false_negatives():
    """Every heuristic that would match must still be found after pre-filtering."""
    # Test with events that match multiple heuristics
    events = [
        LogEvent(text="SSLHandshakeException: PKIX path building failed"),
        LogEvent(text="Timeout waiting for idle object in connection pool"),
        LogEvent(text="ThreadMonitor: hung thread detected"),
        LogEvent(text="GC overhead limit exceeded"),
        LogEvent(text="SESN0066E: Session invalidated"),
        LogEvent(text="ClassNotFoundException: com.example.MyClass"),
        LogEvent(text="DSRA0010E: Cannot get a connection from data source"),
        LogEvent(text="SRVE0293E: Servlet Error"),
        LogEvent(text="CWWKZ0002E: Application failed to start"),
        LogEvent(text="WTRN0006W: Transaction timed out"),
        LogEvent(text="Authorization denied for user"),
        LogEvent(text="CWNEN1001E: JNDI lookup not found"),
        LogEvent(text="Address already in use on port 9443"),
        LogEvent(text="CWWKS3005E: LDAP connection failed"),
        LogEvent(text="CWPKI0033E: Certificate expired"),
        LogEvent(text="CWWKG0028A: Config error in xml"),
        LogEvent(text="CWWKZ0014W: context root conflict"),
    ]
    results = likely_causes(events)
    ids = {r["id"] for r in results}
    # All 17 base heuristics should match (plus any correlations)
    expected_base_ids = {
        "ssl-trust", "db-pool", "hung-threads", "oom-gc", "session-error",
        "classloader", "datasource-down", "servlet-error", "deploy-fail",
        "transaction-timeout", "authz-denied", "jndi-lookup-fail",
        "port-bind-fail", "ldap-connection-fail", "cert-expiry",
        "config-error", "context-root-conflict",
    }
    assert expected_base_ids.issubset(ids)


# --- M42: incident_fingerprint and match_similar_incidents ---

from logpilot.heuristics import incident_fingerprint, match_similar_incidents


def test_incident_fingerprint_stable():
    causes = [
        {"id": "ssl-trust", "title": "SSL / TLS Trust Failure", "count": 3},
        {"id": "oom-gc", "title": "OutOfMemory / GC Pressure", "count": 2},
    ]
    fp1 = incident_fingerprint(causes)
    fp2 = incident_fingerprint(causes)
    assert fp1 == fp2
    assert len(fp1) == 16  # 16-char hex


def test_incident_fingerprint_order_independent():
    causes_a = [
        {"id": "ssl-trust", "title": "SSL / TLS Trust Failure"},
        {"id": "oom-gc", "title": "OutOfMemory / GC Pressure"},
    ]
    causes_b = [
        {"id": "oom-gc", "title": "OutOfMemory / GC Pressure"},
        {"id": "ssl-trust", "title": "SSL / TLS Trust Failure"},
    ]
    assert incident_fingerprint(causes_a) == incident_fingerprint(causes_b)


def test_incident_fingerprint_different_causes():
    fp1 = incident_fingerprint([{"id": "ssl-trust", "title": "SSL Failure"}])
    fp2 = incident_fingerprint([{"id": "db-pool", "title": "DB Pool Exhaustion"}])
    assert fp1 != fp2


def test_match_similar_incidents_exact():
    current = [{"id": "ssl-trust", "title": "SSL"}, {"id": "oom-gc", "title": "OOM error"}]
    history = [{
        "fingerprint": "abc",
        "ids": ["ssl-trust", "oom-gc"],
        "timestamp": "2026-03-18 10:00:00",
    }]
    matches = match_similar_incidents(current, history)
    assert len(matches) == 1
    assert matches[0]["similarity"] == 1.0


def test_match_similar_incidents_partial():
    current = [{"id": "ssl-trust"}, {"id": "oom-gc"}, {"id": "db-pool"}]
    history = [{
        "fingerprint": "abc",
        "ids": ["ssl-trust", "oom-gc"],
        "timestamp": "2026-03-18 10:00:00",
    }]
    matches = match_similar_incidents(current, history)
    # Jaccard: 2 / 3 = 0.67 >= 0.5
    assert len(matches) == 1
    assert matches[0]["similarity"] >= 0.5


def test_match_similar_incidents_below_threshold():
    current = [{"id": "ssl-trust"}, {"id": "oom-gc"}, {"id": "db-pool"}, {"id": "hung-threads"}]
    history = [{
        "fingerprint": "abc",
        "ids": ["deploy-fail"],
        "timestamp": "2026-03-18 10:00:00",
    }]
    matches = match_similar_incidents(current, history)
    assert len(matches) == 0


def test_match_similar_incidents_empty_history():
    current = [{"id": "ssl-trust"}]
    assert match_similar_incidents(current, []) == []


def test_match_similar_incidents_empty_causes():
    assert match_similar_incidents([], [{"ids": ["x"], "timestamp": "t"}]) == []
