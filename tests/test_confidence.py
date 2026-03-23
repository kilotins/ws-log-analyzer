"""Tests for M54: confidence scoring, failure chains, and precompute integration."""
from __future__ import annotations

from pathlib import Path

from logpilot.event import LogEvent
from logpilot.heuristics import (
    compute_confidence,
    build_failure_chain,
    group_into_incidents,
    likely_causes,
)


def _make_event(text="", level="ERROR", system_label="sys1", ts="2025-03-15 14:30:00"):
    return LogEvent(text=text, level=level, system_label=system_label, ts=ts)


def _make_group(total_count=10, effects=None, systems=None, is_primary=False, triggers=None):
    return {
        "total_count": total_count,
        "effects": effects or [],
        "affected_systems": systems or ["sys1"],
        "is_primary": is_primary,
        "triggers": triggers or [{"title": "Test Trigger", "evidence": {}}],
    }


# ── compute_confidence ──────────────────────────────────────────────


class TestComputeConfidence:
    def test_no_events_returns_medium_default(self):
        group = _make_group()
        result = compute_confidence(group, events=None)
        assert result["label"] == "Medium"
        assert result["score"] == 0.50
        assert "default" in result["factors"][0]

    def test_low_confidence(self):
        group = _make_group(total_count=2, systems=["sys1"])
        events = [_make_event()]
        result = compute_confidence(group, events=events)
        assert result["label"] == "Low"
        assert result["score"] < 0.35

    def test_medium_confidence(self):
        group = _make_group(
            total_count=10,
            effects=[{"title": "E1"}],
            systems=["sys1", "sys2"],
            is_primary=False,
        )
        events = [_make_event()]
        result = compute_confidence(group, events=events)
        # base 0.10 + freq min(10/50,0.25)=0.20 + depth 0.05 + spread 0.10 = 0.45
        assert result["label"] == "Medium"
        assert 0.35 <= result["score"] < 0.65

    def test_high_confidence(self):
        group = _make_group(
            total_count=100,
            effects=[{"title": f"E{i}"} for i in range(4)],
            systems=["sys1", "sys2", "sys3"],
            is_primary=True,
            triggers=[{
                "title": "DB Pool",
                "evidence": {"ip_addresses": ["10.0.1.5"], "sample_line": "trace a1b2c3d4-1234-5678-9abc-def012345678"},
            }],
        )
        events = [
            _make_event(text="connection to 10.0.1.5 refused", system_label="sys1"),
            _make_event(text="10.0.1.5 unreachable", system_label="sys2"),
            _make_event(text="trace a1b2c3d4-1234-5678-9abc-def012345678", system_label="sys1"),
            _make_event(text="a1b2c3d4-1234-5678-9abc-def012345678 failed", system_label="sys3"),
        ]
        result = compute_confidence(group, events=events)
        assert result["label"] == "High"
        assert result["score"] >= 0.65

    def test_cross_system_corroboration(self):
        group = _make_group(
            triggers=[{"title": "T", "evidence": {"ip_addresses": ["10.0.1.5"]}}],
        )
        events = [
            _make_event(text="connect to 10.0.1.5 failed", system_label="app1"),
            _make_event(text="10.0.1.5 connection refused", system_label="app2"),
        ]
        result = compute_confidence(group, events=events)
        assert any("cross-system" in f for f in result["factors"])

    def test_trace_correlation(self):
        trace_id = "a1b2c3d4-1234-5678-9abc-def012345678"
        group = _make_group(
            triggers=[{"title": "T", "evidence": {"sample_line": f"req {trace_id} failed"}}],
        )
        events = [
            _make_event(text=f"processing {trace_id}", system_label="svc1"),
            _make_event(text=f"{trace_id} timeout", system_label="svc2"),
        ]
        result = compute_confidence(group, events=events)
        assert any("trace" in f for f in result["factors"])

    def test_score_clamped_to_1(self):
        group = _make_group(
            total_count=1000,
            effects=[{"title": f"E{i}"} for i in range(10)],
            systems=[f"sys{i}" for i in range(10)],
            is_primary=True,
            triggers=[{
                "title": "T",
                "evidence": {"ip_addresses": ["10.0.0.1"], "sample_line": "a1b2c3d4-1234-5678-9abc-def012345678"},
            }],
        )
        events = [
            _make_event(text="10.0.0.1 a1b2c3d4-1234-5678-9abc-def012345678", system_label="s1"),
            _make_event(text="10.0.0.1 a1b2c3d4-1234-5678-9abc-def012345678", system_label="s2"),
        ]
        result = compute_confidence(group, events=events)
        assert result["score"] <= 1.0


# ── build_failure_chain ─────────────────────────────────────────────


class TestBuildFailureChain:
    def test_empty_groups(self):
        result = build_failure_chain([])
        assert result["primary_chain"] == []
        assert result["chain_text"] == ""
        assert result["secondary_findings"] == []

    def test_basic_chain(self):
        groups = [{
            "is_primary": True,
            "cascade_order": "root cause",
            "triggers": [{"title": "DB Unreachable"}, {"title": "Pool Exhaustion"}],
            "effects": [{"title": "Hung Threads"}, {"title": "HTTP 502"}],
            "total_count": 50,
            "name": "Timeout Cascade",
        }]
        result = build_failure_chain(groups)
        assert result["primary_chain"] == ["DB Unreachable", "Pool Exhaustion", "Hung Threads", "HTTP 502"]
        assert "→" in result["chain_text"]
        assert result["secondary_findings"] == []

    def test_max_5_steps(self):
        groups = [{
            "is_primary": True,
            "cascade_order": "root cause",
            "triggers": [{"title": f"T{i}"} for i in range(4)],
            "effects": [{"title": f"E{i}"} for i in range(4)],
            "total_count": 80,
            "name": "Big",
        }]
        result = build_failure_chain(groups)
        assert len(result["primary_chain"]) == 5

    def test_secondary_findings(self):
        groups = [
            {
                "is_primary": True, "cascade_order": "root cause",
                "triggers": [{"title": "T1"}], "effects": [],
                "total_count": 20, "name": "Primary",
            },
            {
                "is_primary": False, "cascade_order": "concurrent",
                "triggers": [{"title": "T2"}], "effects": [],
                "total_count": 10, "name": "OOM Cascade",
            },
        ]
        result = build_failure_chain(groups)
        assert len(result["secondary_findings"]) == 1
        assert "OOM Cascade" in result["secondary_findings"][0]

    def test_with_cascades(self):
        groups = [{
            "is_primary": True, "cascade_order": "root cause",
            "triggers": [{"title": "DB Down"}], "effects": [],
            "total_count": 10, "name": "DB",
        }]
        cascades = [
            {"pattern": "DB → App timeout", "confidence": 0.8},
            {"pattern": "App timeout → User 502", "confidence": 0.7},
        ]
        result = build_failure_chain(groups, cascades)
        assert len(result["primary_chain"]) == 3
        assert "DB → App timeout" in result["primary_chain"]

    def test_deduplicates_titles(self):
        groups = [{
            "is_primary": True, "cascade_order": "root cause",
            "triggers": [{"title": "Pool Exhaustion"}],
            "effects": [{"title": "Pool Exhaustion"}, {"title": "HTTP 502"}],
            "total_count": 20, "name": "Test",
        }]
        result = build_failure_chain(groups)
        assert result["primary_chain"].count("Pool Exhaustion") == 1


# ── Integration ─────────────────────────────────────────────────────


class TestIntegration:
    def test_group_into_incidents_has_confidence(self):
        """groups from group_into_incidents should have confidence dicts."""
        scenario = Path(__file__).parent / "fixtures" / "scenario"
        from logpilot.parser import parse_file
        all_events = []
        for f in sorted(scenario.glob("*.log")):
            evts = parse_file(f)
            for e in evts:
                e.system_label = f.stem
            all_events.extend(evts)

        causes = likely_causes(all_events)
        result = group_into_incidents(causes, events=all_events)
        for g in result["groups"]:
            assert "confidence" in g
            assert g["confidence"]["label"] in ("Low", "Medium", "High")
            assert 0 <= g["confidence"]["score"] <= 1.0
            assert isinstance(g["confidence"]["factors"], list)

    def test_precompute_has_grouped_and_chain(self):
        """precompute_analysis should return grouped and failure_chain."""
        from logpilot.analysis import precompute_analysis
        from logpilot.parser import parse_file

        scenario = Path(__file__).parent / "fixtures" / "scenario"
        all_events = []
        for f in sorted(scenario.glob("*.log")):
            evts = parse_file(f)
            for e in evts:
                e.system_label = f.stem
            all_events.extend(evts)

        result = precompute_analysis(all_events)
        assert "grouped" in result
        assert "failure_chain" in result
        assert isinstance(result["grouped"]["groups"], list)
        assert isinstance(result["failure_chain"]["chain_text"], str)

    def test_scenario_primary_is_high_confidence(self):
        """The M43 scenario primary incident should have High confidence."""
        from logpilot.parser import parse_file

        scenario = Path(__file__).parent / "fixtures" / "scenario"
        all_events = []
        for f in sorted(scenario.glob("*.log")):
            evts = parse_file(f)
            for e in evts:
                e.system_label = f.stem
            all_events.extend(evts)

        causes = likely_causes(all_events)
        result = group_into_incidents(causes, events=all_events)
        primary = next(g for g in result["groups"] if g["is_primary"])
        assert primary["confidence"]["label"] == "High"

    def test_scenario_failure_chain_not_empty(self):
        """The M43 scenario should produce a non-empty failure chain."""
        from logpilot.analysis import precompute_analysis
        from logpilot.parser import parse_file

        scenario = Path(__file__).parent / "fixtures" / "scenario"
        all_events = []
        for f in sorted(scenario.glob("*.log")):
            evts = parse_file(f)
            for e in evts:
                e.system_label = f.stem
            all_events.extend(evts)

        result = precompute_analysis(all_events)
        chain = result["failure_chain"]
        assert len(chain["primary_chain"]) >= 2
        assert "→" in chain["chain_text"]
