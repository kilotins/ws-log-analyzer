"""M43: Playwright E2E test for the checkout outage scenario.

Uploads all 6 scenario log files, runs analysis, and verifies
key sections appear in the GUI.

Requires Playwright: pip install playwright && playwright install

Run with:
    pytest tests/test_scenario_e2e.py -v --headed  (visible browser)
    pytest tests/test_scenario_e2e.py -v            (headless)
"""

import subprocess
import time
from pathlib import Path

import pytest
from playwright.sync_api import expect

SCENARIO_DIR = Path(__file__).parent / "fixtures" / "scenario"
SCENARIO_FILES = sorted(str(f) for f in SCENARIO_DIR.glob("*.log"))
APP_URL = "http://localhost:8501"
APP_PY = Path(__file__).parent.parent / "app.py"
DEFAULT_TIMEOUT = 60000

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def streamlit_server():
    """Start a Streamlit server for the test session."""
    proc = subprocess.Popen(
        ["streamlit", "run", str(APP_PY),
         "--server.port", "8501",
         "--server.headless", "true",
         "--browser.gatherUsageStats", "false"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
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
    p.wait_for_selector("h1:has-text('LogPilot')", timeout=DEFAULT_TIMEOUT)
    yield p
    p.close()


def _upload_scenario_files(page):
    """Upload all 6 scenario log files."""
    file_input = page.locator('input[type="file"]')
    file_input.set_input_files(SCENARIO_FILES)
    # Wait for all filenames to appear
    for f in SCENARIO_FILES:
        name = Path(f).name
        page.wait_for_selector(f"text={name}", timeout=DEFAULT_TIMEOUT)


def _click_analyze(page):
    """Click Analyze and wait for results."""
    page.get_by_role("button", name="Analyze", exact=True).click()
    page.wait_for_selector("text=Parsed", timeout=DEFAULT_TIMEOUT)
    page.wait_for_timeout(1000)


class TestScenarioE2E:
    def test_upload_all_scenario_files(self, page):
        """Upload 6 scenario log files."""
        _upload_scenario_files(page)
        for f in SCENARIO_FILES:
            name = Path(f).name
            assert page.get_by_text(name).first.is_visible()

    def test_analyze_shows_summary(self, page):
        """After Analyze, Summary section shows total events."""
        _upload_scenario_files(page)
        _click_analyze(page)
        page.wait_for_selector("text=Total Events", timeout=DEFAULT_TIMEOUT)
        assert page.get_by_text("Total Events").first.is_visible()

    def test_likely_causes_visible(self, page):
        """Likely Causes section shows DB pool and OOM causes."""
        _upload_scenario_files(page)
        _click_analyze(page)
        page.wait_for_selector("text=Likely Causes", timeout=DEFAULT_TIMEOUT)
        body = page.text_content("body")
        assert "Likely Causes" in body
        # At least one of the key causes should be mentioned
        assert any(term in body for term in [
            "Connection Pool", "pool", "OOM", "OutOfMemory", "Timeout",
        ])

    def test_hung_thread_section_visible(self, page):
        """Hung Thread Drilldown shows WebContainer threads."""
        _upload_scenario_files(page)
        _click_analyze(page)
        page.wait_for_selector("text=Hung Thread", timeout=DEFAULT_TIMEOUT)
        body = page.text_content("body")
        assert "WebContainer" in body

    def test_multi_source_detected(self, page):
        """Per-file breakdown shows multiple sources."""
        _upload_scenario_files(page)
        _click_analyze(page)
        body = page.text_content("body")
        # At least a few source filenames should appear
        found = sum(1 for name in ["checkout-was", "frontend-lb", "payment-api",
                                    "order-service", "payment-pod", "order-worker"]
                    if name in body)
        assert found >= 3, f"Expected at least 3 source names in body, found {found}"

    def test_no_crash(self, page):
        """The page should not show any unhandled exception."""
        _upload_scenario_files(page)
        _click_analyze(page)
        page.wait_for_timeout(2000)
        body = page.text_content("body")
        assert "Traceback" not in body
        assert "KeyError" not in body
        assert "LogPilot" in body
