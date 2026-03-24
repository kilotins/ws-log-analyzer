"""M65 P1: Jira ticket generation tests.

Tests the core ticket generation logic in logpilot/jira_tickets.py
using both synthetic data and real scenario fixtures.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from logpilot.jira_tickets import (
    TEAM_SUGGESTIONS,
    CONFIDENCE_TO_PRIORITY,
    suggest_team,
    generate_ticket_text,
    generate_ungrouped_ticket,
    generate_all_tickets,
    _ID_TO_TEAM,
)
from logpilot.heuristics import group_into_incidents, likely_causes
from logpilot.parser import parse_file
from logpilot.analysis import sort_events_chronologically


SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenario"
BANK_SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenario-bank-api"


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def scenario_events():
    """Parse all scenario files into a combined event list."""
    all_events = []
    for f in sorted(SCENARIO_DIR.iterdir()):
        if f.is_file() and f.suffix == ".log":
            all_events.extend(parse_file(f))
    sort_events_chronologically(all_events)
    return all_events


@pytest.fixture(scope="module")
def scenario_causes(scenario_events):
    return likely_causes(scenario_events)


@pytest.fixture(scope="module")
def scenario_groups(scenario_causes, scenario_events):
    return group_into_incidents(scenario_causes, events=scenario_events)


@pytest.fixture(scope="module")
def bank_events():
    """Parse bank-api scenario files."""
    all_events = []
    for f in sorted(BANK_SCENARIO_DIR.iterdir()):
        if f.is_file() and f.suffix == ".log":
            all_events.extend(parse_file(f))
    sort_events_chronologically(all_events)
    return all_events


@pytest.fixture(scope="module")
def bank_causes(bank_events):
    return likely_causes(bank_events)


# ── Team suggestion tests ─────────────────────────────────────────────


class TestTeamSuggestions:
    def test_id_to_team_mapping_complete(self):
        """Every ID in TEAM_SUGGESTIONS should appear in _ID_TO_TEAM."""
        for team, ids in TEAM_SUGGESTIONS.items():
            for hid in ids:
                assert _ID_TO_TEAM[hid] == team

    def test_suggest_team_dba(self):
        group = {"triggers": [{"id": "pg-deadlock"}], "effects": [{"id": "datasource-down"}]}
        assert suggest_team(group) == "DBA"

    def test_suggest_team_devops(self):
        group = {"triggers": [{"id": "k8s-oomkilled"}], "effects": []}
        assert suggest_team(group) == "DevOps"

    def test_suggest_team_security(self):
        group = {"triggers": [{"id": "ssl-trust"}], "effects": [{"id": "auth-failure-generic"}]}
        assert suggest_team(group) == "Security"

    def test_suggest_team_unknown(self):
        group = {"triggers": [{"id": "made-up-id"}], "effects": []}
        assert suggest_team(group) == "Unknown"

    def test_suggest_team_trigger_weight(self):
        """Triggers should weigh more than effects."""
        group = {
            "triggers": [{"id": "pg-deadlock"}],      # DBA (weight 2)
            "effects": [{"id": "k8s-crashloop"}, {"id": "k8s-oomkilled"}],  # DevOps (weight 1+1)
        }
        assert suggest_team(group) == "DBA"

    def test_suggest_team_empty(self):
        assert suggest_team({"triggers": [], "effects": []}) == "Unknown"


# ── Priority mapping tests ────────────────────────────────────────────


class TestPriorityMapping:
    def test_high_confidence(self):
        assert CONFIDENCE_TO_PRIORITY["High"] == "P2 Major"

    def test_low_confidence(self):
        assert CONFIDENCE_TO_PRIORITY["Low"] == "P1 Critical"

    def test_all_levels_mapped(self):
        for level in ("High", "Medium", "Low"):
            assert level in CONFIDENCE_TO_PRIORITY


# ── Ticket generation tests ───────────────────────────────────────────


class TestGenerateTicketText:
    def test_basic_ticket(self):
        group = {
            "id": "oom-cascade",
            "name": "OOM Cascade",
            "narrative": "Out of memory errors cascading across services.",
            "triggers": [
                {"id": "oom-gc", "title": "GC overhead", "count": 5,
                 "cause": "JVM heap exhausted", "fixes": ["Increase heap", "Fix leak"],
                 "evidence": {"first_ts": "2025-03-15T14:30:00", "affected_systems": ["api-server"]}},
            ],
            "effects": [
                {"id": "k8s-oomkilled", "title": "OOMKilled", "count": 3,
                 "cause": "Container killed", "fixes": ["Increase memory limit"]},
            ],
            "total_count": 8,
            "is_primary": True,
            "rank": 1,
            "cascade_order": "root cause",
            "investigate_first": "Start here: check api-server around 14:30",
            "first_trigger_ts": "2025-03-15T14:30:00",
            "affected_systems": ["api-server"],
            "confidence": {"score": 0.78, "label": "High", "factors": []},
        }
        ticket = generate_ticket_text(group, 1)

        assert "Step 1" in ticket["summary"]
        assert "OOM Cascade" in ticket["summary"]
        assert "root cause" in ticket["summary"]
        assert ticket["priority"] == "P2 Major"
        assert ticket["suggested_team"] in ("Developers", "DevOps")
        assert "api-server" in ticket["labels"]
        assert ticket["group_id"] == "oom-cascade"
        assert "### Root Cause" in ticket["description"]
        assert "### Acceptance Criteria" in ticket["description"]
        assert "Increase heap" in ticket["description"]
        assert "Investigation Directive" in ticket["description"]
        assert "Generated by LogPilot" in ticket["description"]

    def test_ticket_has_all_required_keys(self):
        group = {
            "id": "test", "name": "Test",
            "triggers": [{"id": "x", "title": "X", "count": 1, "fixes": []}],
            "effects": [],
            "confidence": {"score": 0.5, "label": "Medium"},
        }
        ticket = generate_ticket_text(group, 1)
        required = {"summary", "description", "priority", "labels", "suggested_team",
                     "confidence", "cascade_order", "group_id", "group_name"}
        assert required <= set(ticket.keys())

    def test_fixes_capped_at_5(self):
        group = {
            "id": "test", "name": "Test",
            "triggers": [{"id": "x", "title": "X", "count": 1,
                          "fixes": [f"Fix {i}" for i in range(10)]}],
            "effects": [],
            "confidence": {"score": 0.5, "label": "Medium"},
        }
        ticket = generate_ticket_text(group, 1)
        checkbox_count = ticket["description"].count("- [ ]")
        assert checkbox_count <= 5


class TestGenerateUngroupedTicket:
    def test_basic_ungrouped(self):
        cause = {
            "id": "repeated-exception",
            "title": "Repeated NullPointerException",
            "count": 42,
            "cause": "Frequent NPE in UserService",
            "fixes": ["Add null check", "Validate input"],
        }
        ticket = generate_ungrouped_ticket(cause, 3)
        assert "Finding:" in ticket["summary"]
        assert "42 occurrences" in ticket["summary"]
        assert ticket["priority"] == "P3 Minor"
        assert ticket["suggested_team"] == "Developers"
        assert "### Cause" in ticket["description"]
        assert "### Acceptance Criteria" in ticket["description"]


# ── Full pipeline tests (with real scenario data) ─────────────────────


class TestGenerateAllTickets:
    def test_scenario_generates_tickets(self, scenario_causes, scenario_events):
        tickets = generate_all_tickets(scenario_causes, events=scenario_events)
        assert len(tickets) > 0
        # All tickets have required keys
        for t in tickets:
            assert t["summary"]
            assert t["description"]
            assert t["priority"]
            assert isinstance(t["labels"], list)

    def test_first_ticket_is_root_cause(self, scenario_causes, scenario_events):
        tickets = generate_all_tickets(scenario_causes, events=scenario_events)
        if tickets and tickets[0]["cascade_order"]:
            assert "root" in tickets[0]["cascade_order"].lower()

    def test_bank_scenario_tickets(self, bank_causes, bank_events):
        tickets = generate_all_tickets(bank_causes, events=bank_events)
        assert len(tickets) > 0
        # Should detect meaningful incidents with team suggestions
        all_teams = {t["suggested_team"] for t in tickets}
        assert len(all_teams) >= 1  # At least one team identified
        # First ticket should be root cause
        assert tickets[0]["cascade_order"] in ("root cause", "")

    def test_redaction_applied(self, scenario_causes, scenario_events):
        """Generated tickets should have PII redacted."""
        tickets = generate_all_tickets(scenario_causes, events=scenario_events,
                                        redaction_level="standard")
        # No raw bearer tokens or API keys should appear
        for t in tickets:
            assert "bearer " not in t["description"].lower() or "REDACTED" in t["description"]

    def test_no_redaction(self, scenario_causes, scenario_events):
        tickets = generate_all_tickets(scenario_causes, events=scenario_events,
                                        redaction_level="none")
        assert len(tickets) > 0

    def test_empty_causes(self):
        tickets = generate_all_tickets([])
        assert tickets == []

    def test_tickets_ordered_by_rank(self, scenario_causes, scenario_events):
        tickets = generate_all_tickets(scenario_causes, events=scenario_events)
        # Grouped tickets come first (with Step N numbering)
        step_tickets = [t for t in tickets if t["summary"].startswith("Step")]
        for i, t in enumerate(step_tickets):
            assert t["summary"].startswith(f"Step {i + 1}")


class TestTicketContentQuality:
    """Test that tickets contain meaningful, actionable content."""

    def test_description_has_structure(self, scenario_causes, scenario_events):
        tickets = generate_all_tickets(scenario_causes, events=scenario_events)
        for t in tickets:
            # Every ticket should have at least a heading
            assert "##" in t["description"]
            # Every ticket should have the LogPilot footer
            assert "Generated by LogPilot" in t["description"]

    def test_grouped_tickets_have_narrative(self, scenario_causes, scenario_events):
        tickets = generate_all_tickets(scenario_causes, events=scenario_events)
        step_tickets = [t for t in tickets if t["summary"].startswith("Step")]
        for t in step_tickets:
            # Grouped tickets should have root cause or failure chain
            has_root = "### Root Cause" in t["description"]
            has_chain = "### Failure Chain" in t["description"]
            assert has_root or has_chain, f"Ticket '{t['summary']}' lacks root cause/chain"
