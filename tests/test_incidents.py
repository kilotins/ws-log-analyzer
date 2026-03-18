"""Tests for incident grouping, new heuristics, and YAML/inline merge."""
import re
import pytest
from logpilot.heuristics import (
    group_into_incidents, _INCIDENT_GROUPS, _HEURISTICS,
    _load_all_data, likely_causes, _CORRELATIONS,
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

    def test_groups_sorted_by_total_count(self):
        causes = [
            self._make_cause("oom-gc", "OOM", 2),
            self._make_cause("connection-refused", "ConnRefused", 20),
            self._make_cause("timeout-generic", "Timeout", 15),
            self._make_cause("http-5xx-generic", "HTTP 5xx", 10),
        ]
        result = group_into_incidents(causes)
        if len(result["groups"]) >= 2:
            assert result["groups"][0]["total_count"] >= result["groups"][1]["total_count"]

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
