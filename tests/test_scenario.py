"""M43: Production Incident Simulation — E-Commerce Checkout Outage.

Tests the full analysis pipeline on 6 synthetic log files representing
a cascading database pool exhaustion across WAS, nginx, Log4j, JSON,
CRI-O, and Python services.

Scenario timeline (2025-03-15 UTC):
  14:25  Normal operations
  14:30  DB pool exhausted (WAS) → hung threads → HikariCP timeout (Log4j)
         → 502s (nginx) → ECONNREFUSED (JSON) → OOMKilled (CRI-O) → Celery failures (Python)
  14:35  OOM in WAS, session errors
  14:40  Gradual recovery
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logpilot.parser import parse_file
from logpilot.formats import detect_format
from logpilot.analysis import (
    sort_events_chronologically,
    summarize,
    precompute_analysis,
    detect_cross_system_cascades,
    correlate_by_trace_id,
    find_cross_system_chains,
    hung_thread_drilldown,
    per_source_summary,
    time_histogram,
)
from logpilot.heuristics import likely_causes, group_into_incidents

SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenario"

SCENARIO_FILES = {
    "checkout-was": "was",
    "frontend-lb": "nginx",
    "payment-api": "log4j",
    "order-service": "json",
    "payment-pod": "crio",
    "order-worker": "python",
}


# ── Module-scoped fixtures ─────────────────────────────────────────


@pytest.fixture(scope="module")
def all_events():
    """Parse all 6 scenario files, assign system_label, sort chronologically."""
    events = []
    for stem in sorted(SCENARIO_FILES):
        f = SCENARIO_DIR / f"{stem}.log"
        file_events = parse_file(f)
        for e in file_events:
            e.system_label = stem
        events.extend(file_events)
    sort_events_chronologically(events)
    return events


@pytest.fixture(scope="module")
def analysis(all_events):
    return precompute_analysis(all_events, top_n=10, samples_n=10)


@pytest.fixture(scope="module")
def causes(all_events):
    return likely_causes(all_events)


@pytest.fixture(scope="module")
def cause_ids(causes):
    return [c["id"] for c in causes]


@pytest.fixture(scope="module")
def incidents(causes):
    return group_into_incidents(causes)


# ── P2.1: Format auto-detection ────────────────────────────────────


class TestFormatDetection:
    @pytest.mark.parametrize("stem,expected_format", list(SCENARIO_FILES.items()))
    def test_format_detection(self, stem, expected_format):
        f = SCENARIO_DIR / f"{stem}.log"
        fmt = detect_format(f)
        assert fmt is not None, f"No format detected for {f.name}"
        assert fmt.name == expected_format


# ── P2.2: Event counts ─────────────────────────────────────────────


class TestEventCounts:
    def test_total_event_count(self, all_events):
        assert 70 <= len(all_events) <= 130

    def test_per_source_counts(self, all_events):
        sources = per_source_summary(all_events)
        labels = {s["label"] for s in sources}
        assert labels == set(SCENARIO_FILES.keys())
        for s in sources:
            assert s["total"] >= 5, f"{s['label']} has too few events"


# ── P2.3: Severity distribution ────────────────────────────────────


class TestSeverity:
    def test_error_events_present(self, all_events):
        errors = [e for e in all_events if e.level in ("ERROR", "FATAL")]
        assert len(errors) >= 10

    def test_summary_levels(self, all_events):
        s = summarize(all_events, top_n=10)
        # levels is a list of (level, count) tuples
        level_names = {lvl for lvl, _count in s["levels"]}
        assert "ERROR" in level_names
        assert "INFO" in level_names


# ── P2.4: Heuristic IDs ────────────────────────────────────────────


class TestHeuristics:
    """Verify that expected heuristics fire for the scenario."""

    EXPECTED_HEURISTICS = [
        "db-pool",
        "hung-threads",
        "oom-gc",
        "transaction-timeout",
        "session-error",
        "nginx-502",
        "hikari-pool",
        "timeout-generic",
        "json-unhandled-rejection",
        "connection-refused",
        "k8s-oomkilled",
        "k8s-crashloop",
        "celery-task-fail",
        "django-db",
        "http-5xx-generic",
    ]

    @pytest.mark.parametrize("heuristic_id", EXPECTED_HEURISTICS)
    def test_heuristic_fires(self, cause_ids, heuristic_id):
        assert heuristic_id in cause_ids, f"Heuristic '{heuristic_id}' did not fire"


# ── P2.5: Correlation IDs ──────────────────────────────────────────


class TestCorrelations:
    EXPECTED_CORRELATIONS = [
        "corr-oom-pool",
        "corr-oom-pool-hikari",
        "corr-k8s-oom-crash",
        "corr-timeout-5xx",
        "corr-connrefused-5xx",
    ]

    @pytest.mark.parametrize("corr_id", EXPECTED_CORRELATIONS)
    def test_correlation_fires(self, cause_ids, corr_id):
        assert corr_id in cause_ids, f"Correlation '{corr_id}' did not fire"


# ── P2.6: Incident groups ──────────────────────────────────────────


class TestIncidentGroups:
    EXPECTED_GROUPS = [
        "incident-oom-cascade",
        "incident-timeout-cascade",
        "incident-database",
    ]

    def test_incident_groups_present(self, incidents):
        group_ids = [g["id"] for g in incidents.get("groups", [])]
        for gid in self.EXPECTED_GROUPS:
            assert gid in group_ids, f"Incident group '{gid}' not found"

    def test_ungrouped_causes_present(self, incidents):
        """Some causes should remain ungrouped (e.g. celery, session)."""
        ungrouped = incidents.get("ungrouped", [])
        assert len(ungrouped) >= 1


# ── P2.7: Cross-system cascades ────────────────────────────────────


class TestCascades:
    def test_cascades_detected(self, all_events):
        cascades = detect_cross_system_cascades(all_events)
        assert len(cascades) >= 1

    def test_cascade_involves_multiple_sources(self, all_events):
        cascades = detect_cross_system_cascades(all_events)
        sources = set()
        for c in cascades:
            sources.add(c["upstream_source"])
            sources.add(c["downstream_source"])
        assert len(sources) >= 2


# ── P2.8: Cross-system trace correlation ───────────────────────────


class TestTraceCorrelation:
    SHARED_TRACE_ID = "a1b2c3d4-1234-5678-9abc-def012345678"

    def test_trace_id_found(self, all_events):
        traces = correlate_by_trace_id(all_events)
        assert self.SHARED_TRACE_ID in traces

    def test_trace_spans_multiple_systems(self, all_events):
        traces = correlate_by_trace_id(all_events)
        evts = traces[self.SHARED_TRACE_ID]
        systems = {e.system_label for e in evts}
        assert len(systems) >= 2

    def test_cross_system_chains(self, all_events):
        chains = find_cross_system_chains(all_events)
        assert len(chains) >= 1
        assert chains[0]["has_errors"] is True
        assert len(chains[0]["systems"]) >= 2


# ── P2.9: Hung thread drilldown ────────────────────────────────────


class TestHungThreads:
    def test_hung_threads_detected(self, all_events):
        ht = hung_thread_drilldown(all_events)
        assert len(ht) >= 1

    def test_webcontainer_thread_found(self, all_events):
        ht = hung_thread_drilldown(all_events)
        thread_names = [t["thread_name"] for t in ht]
        assert any("WebContainer" in n for n in thread_names)


# ── P2.10: Root cause extraction ───────────────────────────────────


class TestRootCause:
    def test_root_cause_extracted(self, all_events):
        events_with_rc = [e for e in all_events if e.root_cause]
        assert len(events_with_rc) >= 1

    def test_caused_by_chain(self, all_events):
        """At least one event should have a Caused by chain."""
        has_caused_by = any("Caused by" in (e.text or "") for e in all_events)
        assert has_caused_by


# ── P2.11: Timeline histogram ──────────────────────────────────────


class TestTimeline:
    def test_histogram_has_data(self, all_events):
        hist = time_histogram(all_events, bucket_minutes=5)
        assert len(hist) >= 1

    def test_spike_at_incident_time(self, all_events):
        """The 14:30 bucket should have the most error events."""
        # time_histogram returns list of tuples: (bucket_label, total_count, error_count)
        hist = time_histogram(all_events, bucket_minutes=5)
        error_buckets = [(bucket, err_count) for bucket, _total, err_count in hist]
        error_buckets.sort(key=lambda x: x[1], reverse=True)
        # Top error bucket should be in the 14:30 window
        if error_buckets and error_buckets[0][1] > 0:
            assert "14:3" in error_buckets[0][0] or "14:2" in error_buckets[0][0]


# ── P2.12: Report generation ───────────────────────────────────────


class TestReports:
    def test_markdown_report(self, all_events, analysis):
        from logpilot.reports.markdown import render_markdown_report
        from logpilot.reports.config import ReportConfig

        config = ReportConfig(events=all_events, analysis=analysis)
        md = render_markdown_report(config)
        assert "Likely Causes" in md or "likely causes" in md.lower()
        assert len(md) > 200

    def test_json_report(self, all_events, analysis):
        from logpilot.reports.json_report import render_json_report
        from logpilot.reports.config import ReportConfig
        import json

        config = ReportConfig(events=all_events, analysis=analysis)
        raw = render_json_report(config)
        data = json.loads(raw)
        assert "total_events" in data
        assert data["total_events"] == len(all_events)

    def test_html_report(self, all_events, analysis):
        from logpilot.reports.html import render_html_report
        from logpilot.reports.config import ReportConfig

        config = ReportConfig(events=all_events, analysis=analysis)
        html = render_html_report(config)
        assert "<html" in html.lower()
        assert len(html) > 500


# ── P2.13: precompute_analysis integration ─────────────────────────


class TestPrecomputeIntegration:
    def test_analysis_keys(self, analysis):
        expected_keys = {"summary", "samples", "hist", "file_summary", "causes", "hung", "cascades"}
        assert expected_keys <= set(analysis.keys())

    def test_analysis_has_causes(self, analysis):
        assert len(analysis["causes"]) >= 10

    def test_analysis_has_cascades(self, analysis):
        assert len(analysis["cascades"]) >= 1

    def test_analysis_has_hung_threads(self, analysis):
        assert len(analysis["hung"]) >= 1
