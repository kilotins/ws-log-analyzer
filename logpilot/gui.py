"""GUI entry point — launches the Streamlit app via `logpilot-gui` command."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run_streamlit(app_py: Path, *, headless: bool = False) -> None:
    """Launch Streamlit and propagate any non-zero exit code."""
    cmd = [sys.executable, "-m", "streamlit", "run", str(app_py)]
    if headless:
        cmd.append("--server.headless=true")
    cmd.append("--browser.gatherUsageStats=false")
    try:
        result = subprocess.run(cmd)
    except FileNotFoundError:
        print("Streamlit not installed. Run: pip install logpilot[gui]", file=sys.stderr)
        sys.exit(1)
    if result.returncode:
        sys.exit(result.returncode)


def main() -> None:
    """Launch the Streamlit GUI."""
    app_py = Path(__file__).parent.parent / "app.py"
    if not app_py.exists():
        print("Starting LogPilot GUI...", file=sys.stderr)
        _run_streamlit(app_py, headless=True)
    else:
        print("Starting LogPilot GUI...", file=sys.stderr)
        _run_streamlit(app_py)
