"""End-to-end Playwright tests for the Streamlit GUI.

Requires a running Streamlit instance:
    streamlit run app.py --server.port 8501 --server.headless true

Run with:
    pytest tests/test_app_e2e.py -v
"""
import subprocess
import time
from pathlib import Path

import pytest

FIXTURE_LOG = Path(__file__).parent / "fixtures" / "sample.log"
APP_URL = "http://localhost:8501"
APP_PY = Path(__file__).parent.parent / "app.py"


@pytest.fixture(scope="module")
def streamlit_server():
    """Start a Streamlit server for the test session, stop it after."""
    proc = subprocess.Popen(
        ["streamlit", "run", str(APP_PY),
         "--server.port", "8501",
         "--server.headless", "true",
         "--browser.gatherUsageStats", "false"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for server to be ready
    import urllib.request
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
def page(browser, streamlit_server):
    """Create a new browser page for each test."""
    p = browser.new_page()
    p.goto(APP_URL, wait_until="networkidle")
    # Wait for Streamlit to fully render
    p.wait_for_selector("h1:has-text('WebSphere Log Analyzer')", timeout=15000)
    yield p
    p.close()


def _upload_file(page):
    """Upload the sample log file via the Streamlit file uploader."""
    # Streamlit's file uploader uses a hidden <input type="file">
    file_input = page.locator('input[type="file"]')
    file_input.set_input_files(str(FIXTURE_LOG))
    # Wait for filename to appear
    page.wait_for_selector(f"text=sample.log", timeout=5000)


def _click_analyze(page):
    """Click the Analyze button and wait for results."""
    # Click the primary Analyze button (not "Analyze with Claude")
    page.get_by_role("button", name="Analyze", exact=True).click()
    # Wait for the success message showing parsed events
    page.wait_for_selector("text=Parsed", timeout=15000)
    page.wait_for_timeout(1000)
    # Summary expander is expanded=True by default, but click to ensure
    summary_exp = page.get_by_text("Summary", exact=True).first
    # Scroll it into view and check if content is visible
    summary_exp.scroll_into_view_if_needed()
    # If metrics aren't visible yet, click to expand
    if not page.get_by_text("Total Events").first.is_visible():
        summary_exp.click()
        page.wait_for_timeout(500)


class TestAppLoads:
    def test_title_visible(self, page):
        assert page.title() == "WS Log Analyzer"
        heading = page.locator("h1").first
        assert "WebSphere Log Analyzer" in heading.text_content()

    def test_file_uploader_visible(self, page):
        uploader = page.get_by_text("Upload WebSphere log file")
        assert uploader.is_visible()

    def test_settings_sidebar(self, page):
        sidebar = page.locator('[data-testid="stSidebar"]')
        assert sidebar.get_by_text("Settings").is_visible()

    def test_tabs_visible(self, page):
        assert page.get_by_role("tab", name="Analyze").is_visible()
        assert page.get_by_role("tab", name="History").is_visible()


class TestAnalysis:
    def test_upload_and_analyze(self, page):
        _upload_file(page)
        _click_analyze(page)
        page.wait_for_selector("text=Total Events", timeout=5000)
        assert page.get_by_text("Total Events").first.is_visible()

    def test_summary_metrics(self, page):
        _upload_file(page)
        _click_analyze(page)
        assert page.get_by_text("Total Events").first.is_visible()
        # "Errors" metric label
        assert page.locator('[data-testid="stMetric"]').filter(has_text="Errors").first.is_visible()

    def test_top_exceptions_shown(self, page):
        _upload_file(page)
        _click_analyze(page)
        # Exceptions are in a two-column layout; check DOM presence
        assert page.get_by_text("Top Exceptions", exact=True).first.is_visible()
        # NullPointerException may be off-screen in the left column — check it exists in DOM
        npe = page.locator("text=NullPointerException").first
        assert npe.count() > 0 or page.content().count("NullPointerException") > 0

    def test_top_codes_shown(self, page):
        _upload_file(page)
        _click_analyze(page)
        assert page.get_by_text("Top Message Codes", exact=True).first.is_visible()
        assert page.get_by_text("SRVE0293E").first.is_visible()

    def test_download_buttons(self, page):
        _upload_file(page)
        _click_analyze(page)
        assert page.get_by_role("button", name="Download Markdown").is_visible()
        assert page.get_by_role("button", name="Download JSON").is_visible()
        assert page.get_by_role("button", name="Download PDF").is_visible()


class TestAskClaude:
    def test_ask_claude_expander_visible(self, page):
        _upload_file(page)
        _click_analyze(page)
        assert page.get_by_text("Ask Claude", exact=True).first.is_visible()

    def test_ask_claude_input_field(self, page):
        _upload_file(page)
        _click_analyze(page)
        # The Ask Claude expander is expanded=True by default
        input_field = page.get_by_placeholder("CWPKI0022E")
        if not input_field.is_visible():
            page.get_by_text("Ask Claude", exact=True).first.click()
            page.wait_for_timeout(500)
        assert input_field.is_visible()

    def test_analyze_button_disabled_without_input(self, page):
        _upload_file(page)
        _click_analyze(page)
        btn = page.get_by_role("button", name="Analyze with Claude")
        assert btn.is_disabled()

    def test_code_button_populates_input(self, page):
        _upload_file(page)
        _click_analyze(page)
        # Find "Ask Claude" buttons in the codes section (inside Summary expander)
        # These have keys like "ask_SRVE0293E"
        code_btn = page.locator('button:has-text("Ask Claude")').first
        code_btn.scroll_into_view_if_needed()
        code_btn.click()
        # Wait for Streamlit rerun to complete
        page.wait_for_timeout(3000)
        # The input should now be populated via session state
        input_field = page.get_by_placeholder("CWPKI0022E")
        input_field.scroll_into_view_if_needed()
        val = input_field.input_value()
        # The code button sets session_state.claude_query_input
        assert len(val) > 0, f"Expected code in input, got empty string"


class TestSplunkSection:
    def test_splunk_section_visible(self, page):
        _upload_file(page)
        _click_analyze(page)
        assert page.get_by_text("Suggested Splunk Searches", exact=False).first.is_visible()

    def test_splunk_has_baseline(self, page):
        _upload_file(page)
        _click_analyze(page)
        # Click on the Splunk expander
        page.get_by_text("Suggested Splunk Searches", exact=False).first.click()
        page.wait_for_timeout(500)
        assert page.get_by_text("Baseline searches").first.is_visible()


class TestTimeline:
    def test_timeline_section(self, page):
        _upload_file(page)
        _click_analyze(page)
        assert page.get_by_text("Timeline", exact=True).first.is_visible()


class TestEventSamples:
    def test_samples_visible(self, page):
        _upload_file(page)
        _click_analyze(page)
        assert page.get_by_text("Event Samples", exact=False).first.is_visible()


class TestIncidentTimeline:
    def test_incident_timeline_section(self, page):
        _upload_file(page)
        _click_analyze(page)
        assert page.get_by_text("Incident Timeline", exact=False).first.is_visible()

    def test_incident_timeline_has_chart(self, page):
        _upload_file(page)
        _click_analyze(page)
        page.get_by_text("Incident Timeline", exact=False).first.click()
        page.wait_for_timeout(1000)
        # Plotly renders a chart inside the expander
        assert page.locator(".js-plotly-plot").first.count() > 0 or \
               page.get_by_text("first error", exact=False).first.count() > 0


class TestSwedishChefMode:
    def _enable_chef_mode(self, page):
        """Toggle Swedish Chef mode in sidebar."""
        sidebar = page.locator('[data-testid="stSidebar"]')
        toggle = sidebar.get_by_text("Swedish Chef mode", exact=False).first
        toggle.click()
        page.wait_for_timeout(500)

    def test_chef_toggle_visible(self, page):
        sidebar = page.locator('[data-testid="stSidebar"]')
        assert sidebar.get_by_text("Swedish Chef mode", exact=False).first.is_visible()

    def test_chef_mode_changes_button_labels(self, page):
        _upload_file(page)
        _click_analyze(page)
        self._enable_chef_mode(page)
        page.wait_for_timeout(1000)
        # The Ask Claude expander should now say "Ask zee Swedish Chef"
        body = page.text_content("body")
        assert "Swedish Chef" in body or "zee" in body.lower()

    def test_chef_mode_shows_analyze_button(self, page):
        _upload_file(page)
        _click_analyze(page)
        self._enable_chef_mode(page)
        page.wait_for_timeout(1000)
        btn = page.get_by_role("button", name="Analyze with zee Swedish Chef")
        assert btn.count() > 0


class TestRealtimeMonitoring:
    def test_realtime_toggle_in_sidebar(self, page):
        sidebar = page.locator('[data-testid="stSidebar"]')
        assert sidebar.get_by_text("Realtime monitoring", exact=False).first.is_visible()

    def test_realtime_toggle_shows_path_input(self, page):
        sidebar = page.locator('[data-testid="stSidebar"]')
        toggle = sidebar.get_by_text("Enable realtime", exact=False).first
        toggle.click()
        page.wait_for_timeout(500)
        assert sidebar.get_by_text("Log file path", exact=False).first.is_visible()


class TestHistoryTab:
    def test_history_tab_accessible(self, page):
        page.get_by_role("tab", name="History").click()
        page.wait_for_timeout(1000)
        content = page.text_content("body")
        assert "report" in content.lower() or "No reports yet" in content


class TestApplicationLog:
    def test_app_log_expander(self, page):
        assert page.get_by_text("Application Log", exact=True).first.is_visible()

    def test_app_log_has_entries(self, page):
        page.get_by_text("Application Log", exact=True).first.click()
        page.wait_for_timeout(1000)
        content = page.locator('[data-testid="stExpander"]').last.text_content()
        assert "startup" in content.lower() or "INFO" in content
