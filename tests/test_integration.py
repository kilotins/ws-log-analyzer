"""Integration tests for multi-file log analysis workflows."""
import gzip
from pathlib import Path

import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from logpilot import (
    parse_file, precompute_analysis, render_markdown_report,
    render_json_report, render_html_report,
    incident_timeline, summarize,
)

# --- Sample logs from different "servers" ---

SERVER1_LOG = """\
[10/12/15 21:22:04:257 CEST] 00000001 WsmmConfigFac I   ARFM5007I: config loaded
[10/12/15 21:22:04:291 CEST] 00000001 TCPChannel    I   TCPC0001I: TCP listening on port 9081.
[10/12/15 21:22:13:837 CEST] 00000150 WSX509TrustMa E   CWPKI0022E: SSL HANDSHAKE FAILURE: PKIX path building failed
java.security.cert.CertPathBuilderException: could not build path
\tat com.ibm.security.cert.PKIXCertPathBuilderImpl.build(PKIXCertPathBuilderImpl.java:345)
\tat sun.security.provider.certpath.SunCertPathBuilder.build(SunCertPathBuilder.java:145)
[10/12/15 21:22:14:100 CEST] 00000150 WSX509TrustMa E   CWPKI0022E: SSL HANDSHAKE FAILURE again
"""

SERVER2_LOG = """\
[10/12/15 21:22:10:000 CEST] 00000042 ConnectionMgr W   J2CA0045W: Connection pool exhausted for resource jdbc/AppDS
[10/12/15 21:22:11:500 CEST] 00000042 ConnectionMgr E   J2CA0056E: Connection allocation failure for jdbc/AppDS
java.sql.SQLException: Cannot get a connection, pool error Timeout waiting for idle object
\tat org.apache.commons.dbcp.PoolingDataSource.getConnection(PoolingDataSource.java:114)
[10/12/15 21:22:15:000 CEST] 00000043 SystemOut     O   Normal operation resumed
"""

SERVER3_LOG = """\
[10/12/15 21:23:00:000 CEST] 00000099 ThreadMonitor W   WSVR0605W: Thread "WebContainer : 5" has been active for 612123 milliseconds
[10/12/15 21:23:01:000 CEST] 00000099 ThreadMonitor W   WSVR0605W: Thread "WebContainer : 7" has been active for 715000 milliseconds
[10/12/15 21:24:00:000 CEST] 0000009a SystemErr     E   OutOfMemoryError in thread WebContainer-5
java.lang.OutOfMemoryError: Java heap space
\tat java.util.Arrays.copyOf(Arrays.java:3236)
"""


def _parse_all(directory):
    """Parse all log files in a directory and combine events."""
    all_events = []
    for f in sorted(directory.glob("*.log")) + sorted(directory.glob("*.gz")):
        all_events.extend(parse_file(f))
    return all_events


@pytest.fixture
def multi_file_dir(tmp_path):
    """Create a tmp dir with 3 log files from different servers."""
    (tmp_path / "server1.log").write_text(SERVER1_LOG)
    (tmp_path / "server2.log").write_text(SERVER2_LOG)
    (tmp_path / "server3.log").write_text(SERVER3_LOG)
    return tmp_path


# ── 24.1 Multi-file integration tests ───────────────────────────────

class TestMultiFileAnalysis:
    def test_parse_multiple_files_combined(self, multi_file_dir):
        """Parse 3 files and combine events for unified analysis."""
        all_events = _parse_all(multi_file_dir)

        # file field contains full path — check basenames
        basenames = {Path(e["file"]).name for e in all_events}
        assert "server1.log" in basenames
        assert "server2.log" in basenames
        assert "server3.log" in basenames

    def test_combined_analysis_covers_all_files(self, multi_file_dir):
        """precompute_analysis on combined events includes data from all files."""
        all_events = _parse_all(multi_file_dir)

        pa = precompute_analysis(all_events, top_n=10)
        s = pa["summary"]
        assert s["total_events"] >= 8
        # Count errors from all files
        error_count = sum(1 for e in all_events if e.get("level") in ("ERROR", "SEVERE"))
        assert error_count >= 3  # SSL + DB + OOM

    def test_combined_markdown_report(self, multi_file_dir):
        """Markdown report from combined events mentions codes from multiple files."""
        all_events = _parse_all(multi_file_dir)

        md = render_markdown_report(all_events)
        assert "CWPKI0022E" in md  # server1 SSL error
        assert "J2CA0056E" in md or "J2CA0045W" in md  # server2 DB error

    def test_combined_json_report_valid(self, multi_file_dir):
        """JSON report from combined events is valid JSON with expected keys."""
        import json
        all_events = _parse_all(multi_file_dir)

        report = render_json_report(all_events)
        data = json.loads(report)
        assert "total_events" in data
        assert data["total_events"] >= 8

    def test_combined_html_valid(self, multi_file_dir):
        """HTML export from combined events contains expected structure."""
        all_events = _parse_all(multi_file_dir)

        html = render_html_report(all_events)
        assert "<!DOCTYPE html>" in html
        assert "LogPilot Analysis" in html
        assert "ERROR" in html

    def test_gz_and_plain_mixed(self, tmp_path):
        """Parsing works with a mix of .gz and plain text files."""
        (tmp_path / "plain.log").write_text(SERVER1_LOG)
        with gzip.open(tmp_path / "compressed.log.gz", "wt") as f:
            f.write(SERVER2_LOG)

        all_events = _parse_all(tmp_path)
        basenames = {Path(e["file"]).name for e in all_events}
        assert "plain.log" in basenames
        assert "compressed.log.gz" in basenames


# ── 24.2 Multi-file timeline & tag aggregation ──────────────────────

class TestMultiFileTimeline:
    def test_timeline_spans_multiple_files(self, multi_file_dir):
        """incident_timeline should find the first error across all files."""
        all_events = _parse_all(multi_file_dir)

        timeline = incident_timeline(all_events, window_seconds=120)
        assert timeline is not None
        assert len(timeline["window_events"]) > 1

    def test_signal_tags_aggregated(self, multi_file_dir):
        """Signal tags from all files should be aggregated in summary."""
        all_events = _parse_all(multi_file_dir)

        s = summarize(all_events, top_n=10)
        all_tags = [tag for tag, _ in s["tags"]]
        assert "SSL/TLS" in all_tags    # server1
        assert "DB/Pool" in all_tags    # server2
        assert "OOM/GC" in all_tags     # server3

    def test_hung_threads_from_server3(self, multi_file_dir):
        """Hung thread detection should find threads from server3."""
        all_events = _parse_all(multi_file_dir)

        pa = precompute_analysis(all_events)
        hung = pa["hung"]
        assert len(hung) >= 1

    def test_file_summary_per_file(self, multi_file_dir):
        """precompute_analysis file_summary should have entries per source file."""
        all_events = _parse_all(multi_file_dir)

        pa = precompute_analysis(all_events)
        # file_summary is list of (filename, total, errors) tuples
        file_basenames = [Path(fs[0]).name for fs in pa["file_summary"]]
        assert "server1.log" in file_basenames
        assert "server2.log" in file_basenames
        assert "server3.log" in file_basenames

    def test_exceptions_from_multiple_files(self, multi_file_dir):
        """Exceptions from different files should all appear in summary."""
        all_events = _parse_all(multi_file_dir)

        s = summarize(all_events, top_n=10)
        exc_names = [name for name, _ in s["exceptions"]]
        assert any("CertPath" in e for e in exc_names)     # server1
        assert any("OutOfMemory" in e for e in exc_names)   # server3
