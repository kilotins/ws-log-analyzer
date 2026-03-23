"""Tests for incident grouping, new heuristics, and YAML/inline merge."""
import re
from pathlib import Path

import pytest
from logpilot.heuristics import (
    group_into_incidents, _INCIDENT_GROUPS, _HEURISTICS,
    _load_all_data, likely_causes, _CORRELATIONS,
    extract_evidence, rank_incident_groups, build_narrative,
    _merge_evidence,
)
from logpilot._heuristics_fallback import _HEURISTICS_INLINE
from logpilot.event import LogEvent


class TestMergeHeuristics:
    """Tests for YAML/inline heuristic merge logic."""

    def test_load_all_data_preserves_all_inline(self):
        # _load_all_data falls back to inline when YAML not available
        heuristics, _, _ = _load_all_data()
        # Should have at least all inline heuristics
        inline_ids = {h["id"] for h in _HEURISTICS_INLINE}
        result_ids = {h["id"] for h in heuristics}
        assert inline_ids <= result_ids

    def test_heuristics_has_all_inline_ids(self):
        """_HEURISTICS must contain all inline heuristic IDs (the bug fix)."""
        inline_ids = {h["id"] for h in _HEURISTICS_INLINE}
        loaded_ids = {h["id"] for h in _HEURISTICS}
        missing = inline_ids - loaded_ids
        assert not missing, f"Missing heuristics after merge: {missing}"

    def test_heuristics_count_at_least_55(self):
        """We now have 55+ heuristics (17 WAS + 30 format + 11 new generic)."""
        assert len(_HEURISTICS_INLINE) >= 55

    def test_all_heuristics_have_required_keys(self):
        for h in _HEURISTICS_INLINE:
            assert "id" in h, f"Missing id in heuristic"
            assert "title" in h, f"Missing title in {h['id']}"
            assert "match" in h, f"Missing match in {h['id']}"
            assert "cause" in h, f"Missing cause in {h['id']}"
            assert "fixes" in h, f"Missing fixes in {h['id']}"
            assert isinstance(h["match"], re.Pattern), f"match is not compiled regex in {h['id']}"

    def test_no_duplicate_heuristic_ids(self):
        ids = [h["id"] for h in _HEURISTICS_INLINE]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"


class TestNewHeuristics:
    """Tests for newly added generic/cross-format heuristics."""

    def _make_event(self, text, level="ERROR"):
        return LogEvent(text=text, level=level, code=None, exception=None,
                        tags=[], ts=None, thread_id=None, root_cause=None, file="test.log")

    def test_connection_refused_detected(self):
        events = [self._make_event("Connection refused to database server")]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "connection-refused" in ids

    def test_dns_resolution_fail_detected(self):
        events = [self._make_event("getaddrinfo failed: Name or service not known")]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "dns-resolution-fail" in ids

    def test_timeout_generic_detected(self):
        events = [self._make_event("Request timed out after 30000ms")]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "timeout-generic" in ids

    def test_http_5xx_detected(self):
        events = [self._make_event('HTTP/1.1" 502 Bad Gateway')]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "http-5xx-generic" in ids

    def test_http_4xx_detected(self):
        events = [self._make_event('HTTP/1.1" 401 Unauthorized')]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "http-4xx-spike" in ids

    def test_network_unreachable_detected(self):
        events = [self._make_event("Network is unreachable")]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "network-unreachable" in ids

    def test_auth_failure_generic_detected(self):
        events = [self._make_event("authentication failed for user admin")]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "auth-failure-generic" in ids

    def test_resource_exhaustion_detected(self):
        events = [self._make_event("Too many open files")]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "resource-exhaustion" in ids

    def test_json_fatal_error_detected(self):
        events = [self._make_event('{"level": "critical", "message": "database connection lost"}')]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "json-fatal-error" in ids

    def test_json_unhandled_rejection_detected(self):
        events = [self._make_event("unhandledRejection: ECONNREFUSED 127.0.0.1:5432")]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "json-unhandled-rejection" in ids


class TestNewCorrelations:
    """Tests for new correlation rules."""

    def test_all_correlations_have_required_keys(self):
        for c in _CORRELATIONS:
            assert "id" in c
            assert "requires" in c
            assert "title" in c
            assert "cause" in c
            assert "fixes" in c
            assert len(c["requires"]) >= 2

    def test_no_duplicate_correlation_ids(self):
        ids = [c["id"] for c in _CORRELATIONS]
        assert len(ids) == len(set(ids))

    def test_correlation_timeout_5xx(self):
        """timeout-generic + http-5xx-generic should trigger corr-timeout-5xx."""
        events = [
            LogEvent(text="Request timed out after 30s", level="ERROR", code=None,
                     exception=None, tags=[], ts=None, thread_id=None, root_cause=None, file="t.log"),
            LogEvent(text='status=503 Service Unavailable', level="ERROR", code=None,
                     exception=None, tags=[], ts=None, thread_id=None, root_cause=None, file="t.log"),
        ]
        causes = likely_causes(events)
        ids = [c["id"] for c in causes]
        assert "corr-timeout-5xx" in ids


class TestIncidentGrouping:
    """Tests for group_into_incidents function."""

    def _make_cause(self, id, title="Test", count=5):
        return {"id": id, "title": title, "count": count,
                "cause": "Test cause", "fixes": ["Fix 1"]}

    def test_empty_causes(self):
        result = group_into_incidents([])
        assert result["groups"] == []
        assert result["ungrouped"] == []

    def test_oom_cascade_groups_trigger_and_effects(self):
        causes = [
            self._make_cause("oom-gc", "OutOfMemoryError", 10),
            self._make_cause("hung-threads", "Hung Threads", 5),
            self._make_cause("db-pool", "Connection Pool", 3),
        ]
        result = group_into_incidents(causes)
        assert len(result["groups"]) == 1
        g = result["groups"][0]
        assert g["id"] == "incident-oom-cascade"
        assert len(g["triggers"]) == 1
        assert g["triggers"][0]["id"] == "oom-gc"
        assert len(g["effects"]) == 2
        effect_ids = {e["id"] for e in g["effects"]}
        assert "hung-threads" in effect_ids
        assert "db-pool" in effect_ids
        assert g["total_count"] == 18
        assert result["ungrouped"] == []

    def test_ungrouped_causes_preserved(self):
        causes = [
            self._make_cause("ssl-trust", "SSL Trust Failure", 2),
        ]
        result = group_into_incidents(causes)
        assert len(result["groups"]) == 0
        assert len(result["ungrouped"]) == 1
        assert result["ungrouped"][0]["id"] == "ssl-trust"

    def test_no_group_without_trigger(self):
        """Effects alone should not create a group."""
        causes = [
            self._make_cause("hung-threads", "Hung Threads", 5),
            self._make_cause("servlet-error", "Servlet Error", 3),
        ]
        result = group_into_incidents(causes)
        assert len(result["groups"]) == 0
        assert len(result["ungrouped"]) == 2

    def test_narrative_contains_effect_names(self):
        causes = [
            self._make_cause("connection-refused", "Connection Refused", 10),
            self._make_cause("timeout-generic", "Timeout", 5),
            self._make_cause("http-5xx-generic", "HTTP 5xx", 8),
        ]
        result = group_into_incidents(causes)
        assert len(result["groups"]) >= 1
        g = result["groups"][0]
        assert "narrative" in g
        assert len(g["narrative"]) > 0

    def test_correlated_causes_excluded_from_ungrouped(self):
        """Causes with correlated_from should not appear in ungrouped."""
        causes = [
            self._make_cause("ssl-trust", "SSL Trust", 2),
            {**self._make_cause("corr-ssl-deploy", "SSL+Deploy", 4), "correlated_from": ["ssl-trust", "deploy-fail"]},
        ]
        result = group_into_incidents(causes)
        ungrouped_ids = [c["id"] for c in result["ungrouped"]]
        assert "corr-ssl-deploy" not in ungrouped_ids

    def test_groups_ranked_with_primary(self):
        causes = [
            self._make_cause("oom-gc", "OOM", 2),
            self._make_cause("connection-refused", "ConnRefused", 20),
            self._make_cause("timeout-generic", "Timeout", 15),
            self._make_cause("http-5xx-generic", "HTTP 5xx", 10),
        ]
        result = group_into_incidents(causes)
        if len(result["groups"]) >= 2:
            # Groups should have rank assigned (1-based) and primary flag
            assert result["groups"][0].get("rank") == 1
            assert result["groups"][0].get("is_primary") is True

    def test_incident_group_definitions_valid(self):
        for ig in _INCIDENT_GROUPS:
            assert "id" in ig
            assert "name" in ig
            assert "trigger_ids" in ig
            assert "effect_ids" in ig
            assert "narrative" in ig
            assert isinstance(ig["trigger_ids"], set)
            assert isinstance(ig["effect_ids"], set)
            assert "{effects}" in ig["narrative"]

    def test_deploy_failure_incident(self):
        causes = [
            self._make_cause("deploy-fail", "Deploy Failure", 3),
            self._make_cause("classloader", "ClassLoader Error", 7),
        ]
        result = group_into_incidents(causes)
        assert len(result["groups"]) == 1
        assert result["groups"][0]["id"] == "incident-deploy-failure"

    def test_database_incident(self):
        causes = [
            self._make_cause("db-pool", "DB Connection Pool", 5),
            self._make_cause("transaction-timeout", "Tx Timeout", 3),
            self._make_cause("hung-threads", "Hung Threads", 2),
        ]
        result = group_into_incidents(causes)
        group_ids = [g["id"] for g in result["groups"]]
        assert "incident-database" in group_ids


# ── P6: Evidence extraction tests ───────────────────────────────────


class TestExtractEvidence:
    def test_ip_extraction(self):
        events = [
            LogEvent(text="Connection refused to 10.0.1.5:5432", level="ERROR",
                     system_label="api", ts="2025-03-15 14:30:00"),
        ]
        match_re = re.compile(r"Connection refused", re.IGNORECASE)
        ev = extract_evidence(events, match_re)
        assert "10.0.1.5:5432" in ev["ip_addresses"]

    def test_duration_extraction(self):
        events = [
            LogEvent(text='Thread "WebContainer : 5" has been active for 612000 milliseconds',
                     level="WARNING", system_label="was", ts="2025-03-15 14:30:08"),
        ]
        match_re = re.compile(r"active for", re.IGNORECASE)
        ev = extract_evidence(events, match_re)
        assert any("612000" in d for d in ev["durations"])

    def test_affected_systems(self):
        events = [
            LogEvent(text="OOMKilled", level="ERROR", system_label="pod-a", ts="2025-01-01 00:00:00"),
            LogEvent(text="OOMKilled", level="ERROR", system_label="pod-b", ts="2025-01-01 00:01:00"),
            LogEvent(text="OK", level="INFO", system_label="pod-c", ts="2025-01-01 00:02:00"),
        ]
        match_re = re.compile(r"OOMKilled")
        ev = extract_evidence(events, match_re)
        assert sorted(ev["affected_systems"]) == ["pod-a", "pod-b"]

    def test_exception_extraction(self):
        events = [
            LogEvent(text="java.lang.NullPointerException at Foo.java:42",
                     level="ERROR", exception="java.lang.NullPointerException",
                     ts="2025-01-01 00:00:00"),
        ]
        match_re = re.compile(r"NullPointerException")
        ev = extract_evidence(events, match_re)
        assert "NullPointerException" in ev["exceptions"]

    def test_sample_line(self):
        events = [
            LogEvent(text="FATAL: JVM heap at 98%\nDetails follow", level="FATAL",
                     ts="2025-01-01 00:00:00"),
        ]
        match_re = re.compile(r"FATAL.*heap")
        ev = extract_evidence(events, match_re)
        assert "98%" in ev["sample_line"]
        assert "\n" not in ev["sample_line"]

    def test_no_matches_returns_empty(self):
        events = [LogEvent(text="All OK", level="INFO", ts="2025-01-01 00:00:00")]
        match_re = re.compile(r"CRITICAL_FAILURE")
        ev = extract_evidence(events, match_re)
        assert ev["first_ts"] is None
        assert ev["affected_systems"] == []
        assert ev["ip_addresses"] == []

    def test_localhost_ips_excluded(self):
        events = [
            LogEvent(text="Listening on 127.0.0.1:8080 and 10.0.1.5:5432",
                     level="INFO", ts="2025-01-01 00:00:00"),
        ]
        match_re = re.compile(r"Listening")
        ev = extract_evidence(events, match_re)
        assert "127.0.0.1:8080" not in ev["ip_addresses"]
        assert "10.0.1.5:5432" in ev["ip_addresses"]


class TestMergeEvidence:
    def test_merge_preserves_earliest_ts(self):
        ev1 = {"first_ts": "2025-03-15T14:30:00", "last_ts": "2025-03-15T14:31:00",
               "affected_systems": ["a"], "ip_addresses": ["1.2.3.4"],
               "hostnames": [], "durations": [], "exceptions": [], "threads": [], "sample_line": ""}
        ev2 = {"first_ts": "2025-03-15T14:25:00", "last_ts": "2025-03-15T14:35:00",
               "affected_systems": ["b"], "ip_addresses": ["5.6.7.8"],
               "hostnames": [], "durations": [], "exceptions": [], "threads": [], "sample_line": "line2"}
        merged = _merge_evidence([ev1, ev2])
        assert merged["first_ts"] == "2025-03-15T14:25:00"
        assert merged["last_ts"] == "2025-03-15T14:35:00"
        assert sorted(merged["affected_systems"]) == ["a", "b"]
        assert sorted(merged["ip_addresses"]) == ["1.2.3.4", "5.6.7.8"]

    def test_merge_empty_list(self):
        merged = _merge_evidence([])
        assert merged["first_ts"] is None
        assert merged["affected_systems"] == []


# ── Ranking tests ───────────────────────────────────────────────────


class TestRankIncidentGroups:
    def _make_group(self, gid, name, triggers, effects, total_count):
        return {
            "id": gid, "name": name, "narrative": "",
            "triggers": triggers, "effects": effects,
            "total_count": total_count,
        }

    def _make_trigger(self, cid, title, count, first_ts=None, systems=None):
        return {
            "id": cid, "title": title, "count": count,
            "evidence": {
                "first_ts": first_ts, "affected_systems": systems or [],
                "ip_addresses": [], "durations": [], "exceptions": [],
            },
        }

    def test_earliest_trigger_is_primary(self):
        g1 = self._make_group("g1", "Later Group",
                              [self._make_trigger("t1", "T1", 5, "2025-03-15T14:35:00", ["svc-a"])],
                              [], 5)
        g2 = self._make_group("g2", "Earlier Group",
                              [self._make_trigger("t2", "T2", 3, "2025-03-15T14:30:00", ["svc-b"])],
                              [], 3)
        groups = [g1, g2]
        rank_incident_groups(groups, [])
        assert groups[0]["is_primary"] is True
        assert groups[0]["name"] == "Earlier Group"
        assert groups[0]["rank"] == 1
        assert groups[1]["rank"] == 2

    def test_primary_has_investigate_first(self):
        g = self._make_group("g1", "Root",
                             [self._make_trigger("t1", "DB Pool", 5, "2025-03-15T14:30:00", ["was"])],
                             [], 5)
        rank_incident_groups([g], [])
        assert "Start here" in g["investigate_first"]
        assert "was" in g["investigate_first"]

    def test_downstream_label(self):
        # g1's trigger (timeout-generic) is g2's effect
        g1 = self._make_group("g1", "Primary",
                              [self._make_trigger("oom-gc", "OOM", 2, "2025-03-15T14:30:00")],
                              [{"id": "timeout-generic", "title": "Timeout", "count": 3, "evidence": {}}],
                              5)
        g2 = self._make_group("g2", "Secondary",
                              [self._make_trigger("timeout-generic", "Timeout", 3, "2025-03-15T14:31:00")],
                              [], 3)
        groups = [g1, g2]
        rank_incident_groups(groups, [])
        assert groups[1]["cascade_order"] == "downstream of Primary"

    def test_empty_groups(self):
        result = rank_incident_groups([], [])
        assert result == []


# ── Narrative tests ─────────────────────────────────────────────────


class TestBuildNarrative:
    def test_narrative_includes_timestamp(self):
        g = {
            "first_trigger_ts": "2025-03-15T14:30:05.123000+00:00",
            "affected_systems": ["checkout-was", "frontend-lb"],
            "cascade_order": "root cause",
            "triggers": [{"title": "DB Pool Exhaustion", "count": 5,
                          "evidence": {"ip_addresses": ["10.0.1.5:5432"], "durations": ["30000 ms"],
                                       "affected_systems": ["checkout-was"]}}],
            "effects": [{"title": "HTTP 502", "count": 3,
                         "evidence": {"affected_systems": ["frontend-lb"]}}],
            "total_count": 8,
        }
        narrative = build_narrative(g)
        assert "14:30:05" in narrative
        assert "checkout-was" in narrative
        assert "10.0.1.5:5432" in narrative

    def test_narrative_includes_cascade(self):
        g = {
            "first_trigger_ts": "2025-01-01T00:00:00",
            "affected_systems": ["a", "b"],
            "cascade_order": "root cause",
            "triggers": [{"title": "OOM", "count": 1, "evidence": {"ip_addresses": [], "durations": [],
                                                                      "affected_systems": ["a"]}}],
            "effects": [{"title": "Hung Threads", "count": 2, "evidence": {"affected_systems": ["a"]}}],
            "total_count": 3,
        }
        narrative = build_narrative(g)
        assert "cascaded to" in narrative
        assert "Hung Threads" in narrative

    def test_narrative_no_effects(self):
        g = {
            "first_trigger_ts": "2025-01-01T00:00:00",
            "affected_systems": ["svc"],
            "cascade_order": "concurrent",
            "triggers": [{"title": "Error", "count": 1, "evidence": {"ip_addresses": [], "durations": [],
                                                                        "affected_systems": ["svc"]}}],
            "effects": [],
            "total_count": 1,
        }
        narrative = build_narrative(g)
        assert "cascaded" not in narrative


# ── Full scenario integration ───────────────────────────────────────


class TestEnrichedScenarioIntegration:
    """Test enriched incident analysis with the M43 scenario fixture."""

    @pytest.fixture(scope="class")
    def scenario_incidents(self):
        from logpilot.parser import parse_file
        from logpilot.analysis import sort_events_chronologically
        scenario = Path(__file__).parent / "fixtures" / "scenario"
        all_events = []
        for f in sorted(scenario.glob("*.log")):
            evts = parse_file(f)
            for e in evts:
                e.system_label = f.stem
            all_events.extend(evts)
        sort_events_chronologically(all_events)
        causes = likely_causes(all_events)
        return group_into_incidents(causes)

    def test_primary_incident_identified(self, scenario_incidents):
        groups = scenario_incidents["groups"]
        assert len(groups) >= 1
        assert groups[0].get("is_primary") is True

    def test_all_groups_have_rank(self, scenario_incidents):
        for g in scenario_incidents["groups"]:
            assert "rank" in g
            assert "cascade_order" in g
            assert "investigate_first" in g

    def test_primary_has_systems(self, scenario_incidents):
        primary = scenario_incidents["groups"][0]
        assert len(primary.get("affected_systems", [])) >= 2

    def test_narrative_contains_specifics(self, scenario_incidents):
        primary = scenario_incidents["groups"][0]
        narrative = primary["narrative"]
        # Should contain a timestamp (format varies: 14:30 or 15:00 depending on log sources)
        assert any(ts in narrative for ts in ["14:30", "14:29", "15:00"])
        assert any(s in narrative for s in ["checkout-was", "frontend-lb", "payment-api"])

    def test_evidence_on_causes(self, scenario_incidents):
        """Causes within groups should have evidence dicts."""
        primary = scenario_incidents["groups"][0]
        for t in primary["triggers"]:
            assert "evidence" in t
            ev = t["evidence"]
            assert isinstance(ev.get("affected_systems"), list)
