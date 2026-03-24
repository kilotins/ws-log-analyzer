"""Comprehensive Playwright E2E test for LogPilot.

Tests the full user flow: upload → analyze → verify sections → export → Jira tickets.

Requires:
    pip install pytest-playwright && playwright install chromium
    Streamlit app running: streamlit run app.py

Run:
    pytest tests/test_e2e_full.py -v --headed   (visible browser)
    pytest tests/test_e2e_full.py -v             (headless)
"""
from __future__ import annotations

import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenario"
SCENARIO_FILES = sorted(str(f) for f in SCENARIO_DIR.glob("*.log"))
FIXTURE_LOG = Path(__file__).parent / "fixtures" / "sample.log"

APP_URL = "http://localhost:8501"
APP_PY = Path(__file__).parent.parent / "app.py"
T = 60_000  # default timeout ms

pytestmark = pytest.mark.slow


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def _ensure_server():
    """Ensure Streamlit is running — reuse existing or start new."""
    try:
        urllib.request.urlopen(APP_URL, timeout=2)
        yield None
        return
    except Exception:
        pass

    proc = subprocess.Popen(
        ["streamlit", "run", str(APP_PY),
         "--server.port", "8501",
         "--server.headless", "true",
         "--browser.gatherUsageStats", "false"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    for _ in range(30):
        try:
            urllib.request.urlopen(APP_URL, timeout=1)
            break
        except Exception:
            time.sleep(1)
    else:
        proc.terminate()
        pytest.fail("Streamlit server did not start in time")
    yield proc
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture()
def app(page: Page, _ensure_server) -> Page:
    """Navigate to the app and wait for Streamlit to fully render."""
    page.goto(APP_URL)
    # Wait for Streamlit to render (no h1 — check for known text)
    page.wait_for_selector("text=Upload log file", timeout=T)
    return page


# ── Helpers ───────────────────────────────────────────────────────────

def _upload_scenario(page: Page):
    page.goto(APP_URL)
    page.wait_for_selector("text=Upload log file", timeout=T)
    page.locator('input[type="file"]').first.set_input_files(SCENARIO_FILES)
    page.wait_for_timeout(3000)  # Wait for Streamlit to process upload


def _upload_sample(page: Page):
    page.goto(APP_URL)
    page.wait_for_selector("text=Upload log file", timeout=T)
    page.locator('input[type="file"]').first.set_input_files(str(FIXTURE_LOG))
    page.wait_for_selector("text=sample.log", timeout=T)


def _analyze(page: Page):
    page.get_by_role("button", name="Analyze", exact=True).click()
    page.wait_for_selector("text=Parsed", timeout=T)
    page.wait_for_timeout(2000)


# ── 1. App loads correctly ────────────────────────────────────────────

class TestAppLoads:
    def test_title(self, app):
        assert app.title() == "LogPilot"

    def test_logpilot_text(self, app):
        expect(app.locator("text=LogPilot").first).to_be_visible()

    def test_file_uploader_visible(self, app):
        expect(app.get_by_text("Upload log file")).to_be_visible()

    def test_tabs_present(self, app):
        for tab_name in ["Analyze", "Realtime Console", "Audit Report", "Cloud Spend"]:
            expect(app.get_by_role("tab", name=tab_name)).to_be_visible()

    def test_sidebar_has_api_keys(self, app):
        sidebar = app.locator('[data-testid="stSidebar"]')
        expect(sidebar.get_by_text("API Keys", exact=False).first).to_be_visible()

    def test_sidebar_has_integrations(self, app):
        sidebar = app.locator('[data-testid="stSidebar"]')
        expect(sidebar.get_by_text("Integrations", exact=False).first).to_be_visible()

    def test_no_crash_on_load(self, app):
        body = app.text_content("body")
        assert "Traceback" not in body
        assert "KeyError" not in body


# ── 2. Single file analysis ──────────────────────────────────────────

class TestSingleFileAnalysis:
    def test_upload_and_analyze(self, app):
        _upload_sample(app)
        _analyze(app)
        expect(app.get_by_text("Total Events").first).to_be_visible()

    def test_summary_metrics(self, app):
        _upload_sample(app)
        _analyze(app)
        expect(app.locator('[data-testid="stMetric"]').filter(has_text="Errors").first).to_be_visible()

    def test_top_codes_visible(self, app):
        _upload_sample(app)
        _analyze(app)
        expect(app.get_by_text("Top Message Codes", exact=True).first).to_be_visible()

    def test_top_exceptions_visible(self, app):
        _upload_sample(app)
        _analyze(app)
        expect(app.get_by_text("Top Exceptions", exact=True).first).to_be_visible()

    def test_likely_causes_visible(self, app):
        _upload_sample(app)
        _analyze(app)
        expect(app.get_by_text("Likely Causes", exact=False).first).to_be_visible()

    def test_event_samples_visible(self, app):
        _upload_sample(app)
        _analyze(app)
        expect(app.get_by_text("Event Samples", exact=False).first).to_be_visible()


# ── 3. Multi-file scenario analysis ──────────────────────────────────

class TestScenarioAnalysis:
    def test_scenario_upload_analyze_and_verify(self, app):
        """Upload 6 scenario files, analyze, verify key sections."""
        _upload_scenario(app)
        _analyze(app)
        body = app.text_content("body")

        # Summary visible
        assert "Total Events" in body

        # Multiple sources detected
        found = sum(1 for name in ["checkout-was", "frontend-lb", "payment-api",
                                    "order-service", "payment-pod", "order-worker"]
                    if name in body)
        assert found >= 3

        # Causes detected
        assert any(term in body for term in [
            "Connection Pool", "pool", "OOM", "OutOfMemory", "Timeout", "Cascade",
        ])

        # No Streamlit crash (tracebacks in log samples are expected)
        assert "st.exception" not in body
        assert "StreamlitAPIException" not in body


# ── 4. Export section ─────────────────────────────────────────────────

class TestExport:
    def test_export_section_visible(self, app):
        _upload_sample(app)
        _analyze(app)
        heading = app.get_by_text("Generate Technical Report", exact=False).first
        heading.scroll_into_view_if_needed()
        expect(heading).to_be_visible()

    def test_export_button_exists(self, app):
        _upload_sample(app)
        _analyze(app)
        app.get_by_text("Generate Technical Report", exact=False).first.scroll_into_view_if_needed()
        export_btn = app.get_by_role("button", name="Export Technical Report", exact=False).first
        expect(export_btn).to_be_visible()

    def test_no_executive_summary_in_page(self, app):
        """M66: Executive Summary removed from export dropdown."""
        _upload_sample(app)
        _analyze(app)
        app.get_by_text("Generate Technical Report", exact=False).first.scroll_into_view_if_needed()
        assert app.locator('text="Executive Summary"').count() == 0


# ── 5. Jira Tickets section (M65) ────────────────────────────────────

class TestJiraTickets:
    def test_jira_section_and_tickets(self, app):
        """Upload sample, analyze, verify Jira section with tickets."""
        _upload_sample(app)
        _analyze(app)
        body = app.text_content("body")

        # Jira section should be visible if causes exist
        if "Likely Causes" in body:
            jira = app.get_by_text("Jira Tickets", exact=False).first
            jira.scroll_into_view_if_needed()
            expect(jira).to_be_visible()
            app.wait_for_timeout(500)
            body = app.text_content("body")
            assert "ticket" in body.lower() or "finding" in body.lower()

    def test_jira_create_disabled_without_config(self, app):
        _upload_sample(app)
        _analyze(app)
        body = app.text_content("body")
        if "Jira Tickets" in body:
            jira = app.get_by_text("Jira Tickets", exact=False).first
            jira.scroll_into_view_if_needed()
            app.wait_for_timeout(500)
            disabled_btn = app.locator('button:has-text("configure in sidebar")').first
            if disabled_btn.count() > 0:
                assert disabled_btn.is_disabled()


# ── 6. AI section ────────────────────────────────────────────────────

class TestAISection:
    def test_ai_section_visible_no_crash(self, app):
        _upload_sample(app)
        _analyze(app)
        expect(app.get_by_text("Incident AI Assistant", exact=False).first).to_be_visible()
        body = app.text_content("body")
        assert "Traceback" not in body


# ── 7. Sidebar integrations (M65) ────────────────────────────────────

class TestSidebarIntegrations:
    def test_integrations_expander(self, app):
        sidebar = app.locator('[data-testid="stSidebar"]')
        expect(sidebar.get_by_text("Integrations", exact=False).first).to_be_visible()

    def test_jira_fields(self, app):
        sidebar = app.locator('[data-testid="stSidebar"]')
        sidebar.get_by_text("Integrations", exact=False).first.click()
        app.wait_for_timeout(500)
        expect(sidebar.get_by_placeholder("https://mycompany.atlassian.net").first).to_be_visible()

    def test_confluence_field(self, app):
        sidebar = app.locator('[data-testid="stSidebar"]')
        sidebar.get_by_text("Integrations", exact=False).first.click()
        app.wait_for_timeout(500)
        expect(sidebar.get_by_text("Confluence", exact=False).first).to_be_visible()


# ── 8. Error handling ─────────────────────────────────────────────────

class TestErrorHandling:
    def test_empty_file_graceful(self, app):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w") as f:
            f.write("")
            empty_path = f.name
        try:
            app.locator('input[type="file"]').first.set_input_files(empty_path)
            app.wait_for_timeout(1000)
            btn = app.get_by_role("button", name="Analyze", exact=True)
            if btn.is_visible() and btn.is_enabled():
                btn.click()
                app.wait_for_timeout(3000)
            assert "LogPilot" in app.text_content("body")
        finally:
            Path(empty_path).unlink(missing_ok=True)

    def test_tab_switching(self, app):
        for tab_name in ["Realtime Console", "Audit Report", "Cloud Spend", "Analyze"]:
            app.get_by_role("tab", name=tab_name).click()
            app.wait_for_timeout(500)
        body = app.text_content("body")
        assert "Traceback" not in body
        assert "LogPilot" in body
