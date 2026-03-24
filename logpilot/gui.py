"""GUI entry point — launches the Streamlit app via `logpilot-gui` command."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    """Launch the Streamlit GUI."""
    app_py = Path(__file__).parent.parent / "app.py"
    if not app_py.exists():
        # Installed via pip — try to find app.py relative to site-packages
        import importlib.resources
        print("Starting LogPilot GUI...", file=sys.stderr)
        try:
            subprocess.run(
                [sys.executable, "-m", "streamlit", "run", str(app_py),
                 "--server.headless=true",
                 "--browser.gatherUsageStats=false"],
            )
        except FileNotFoundError:
            print("Streamlit not installed. Run: pip install logpilot[gui]", file=sys.stderr)
            sys.exit(1)
    else:
        print("Starting LogPilot GUI...", file=sys.stderr)
        try:
            subprocess.run(
                [sys.executable, "-m", "streamlit", "run", str(app_py),
                 "--browser.gatherUsageStats=false"],
            )
        except FileNotFoundError:
            print("Streamlit not installed. Run: pip install logpilot[gui]", file=sys.stderr)
            sys.exit(1)
