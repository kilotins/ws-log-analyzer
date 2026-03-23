"""Tests for M61: Executive Summary report."""
from __future__ import annotations

from pathlib import Path

from logpilot.parser import parse_file
from logpilot.analysis import precompute_analysis
from logpilot.reports.executive_summary import render_executive_summary, render_executive_summary_html


def _load_scenario(name: str = "scenario"):
    """Load a test scenario and return events + analysis."""
    scenario = Path(__file__).parent / "fixtures" / name
    all_events = []
    for f in sorted(scenario.glob("*.log")):
        evts = parse_file(f)
        for e in evts:
            e.system_label = f.stem
        all_events.extend(evts)
    analysis = precompute_analysis(all_events)
    return all_events, analysis


class TestExecutiveSummaryMarkdown:
    def test_generates_markdown(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        assert "# Incident Executive Summary" in md

    def test_contains_root_cause(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        assert "## Root Cause" in md

    def test_contains_confidence(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        assert "## Confidence Assessment" in md
        assert "confidence" in md.lower()

    def test_contains_impact(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        assert "## Impact" in md
        assert "errors" in md

    def test_contains_actions(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        assert "## Recommended Actions" in md

    def test_contains_failure_chain(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        # Should have either chain section or chain text
        assert "→" in md or "Chain" in md or "chain" in md

    def test_contains_metrics_table(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        assert "Events" in md
        assert "Errors" in md

    def test_contains_affected_systems(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        assert "Affected systems" in md

    def test_footer(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        assert "LogPilot" in md
        assert "Item Consulting" in md

    def test_with_ai_content(self):
        events, analysis = _load_scenario()
        ai = {"incident": "## Executive Summary\nThe root cause was a database crash."}
        md = render_executive_summary(events, _analysis=analysis, ai_content=ai)
        assert "## AI Analysis" in md
        assert "database crash" in md

    def test_suggested_team(self):
        events, analysis = _load_scenario()
        md = render_executive_summary(events, _analysis=analysis)
        assert "Suggested team" in md

    def test_bank_scenario(self):
        events, analysis = _load_scenario("scenario-bank")
        md = render_executive_summary(events, _analysis=analysis)
        assert "# Incident Executive Summary" in md
        assert "## Root Cause" in md

    def test_insurance_scenario(self):
        events, analysis = _load_scenario("scenario-insurance")
        md = render_executive_summary(events, _analysis=analysis)
        assert len(md) > 200


class TestExecutiveSummaryHTML:
    def test_generates_html(self):
        events, analysis = _load_scenario()
        html = render_executive_summary_html(events, _analysis=analysis)
        assert "<!DOCTYPE html>" in html
        assert "Incident Executive Summary" in html

    def test_has_styled_table(self):
        events, analysis = _load_scenario()
        html = render_executive_summary_html(events, _analysis=analysis)
        assert "<table>" in html
        assert "<th>" in html

    def test_has_blockquote(self):
        events, analysis = _load_scenario()
        html = render_executive_summary_html(events, _analysis=analysis)
        assert "<blockquote>" in html

    def test_has_brand_color(self):
        events, analysis = _load_scenario()
        html = render_executive_summary_html(events, _analysis=analysis)
        assert "#7C3AED" in html
