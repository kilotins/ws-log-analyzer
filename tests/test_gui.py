"""Tests for logpilot.gui entry point."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from logpilot import gui


class TestRunStreamlit:
    def test_run_streamlit_exits_with_child_return_code(self):
        with patch.object(gui.subprocess, "run", return_value=MagicMock(returncode=7)):
            with pytest.raises(SystemExit) as exc_info:
                gui._run_streamlit(Path("/tmp/app.py"))
        assert exc_info.value.code == 7

    def test_run_streamlit_exits_when_streamlit_missing(self, capsys):
        with patch.object(gui.subprocess, "run", side_effect=FileNotFoundError):
            with pytest.raises(SystemExit) as exc_info:
                gui._run_streamlit(Path("/tmp/app.py"))
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Streamlit not installed" in captured.err

    def test_run_streamlit_adds_headless_flag_when_requested(self):
        with patch.object(gui.subprocess, "run", return_value=MagicMock(returncode=0)) as mock_run:
            gui._run_streamlit(Path("/tmp/app.py"), headless=True)
        cmd = mock_run.call_args.args[0]
        assert "--server.headless=true" in cmd


class TestMain:
    def test_main_uses_existing_app_without_headless(self, tmp_path, capsys):
        app_py = tmp_path / "app.py"
        app_py.write_text("print('app')")

        with patch.object(gui, "_run_streamlit") as mock_run:
            with patch.object(gui, "__file__", str(tmp_path / "logpilot" / "gui.py")):
                gui.main()

        mock_run.assert_called_once_with(app_py)
        captured = capsys.readouterr()
        assert "Starting LogPilot GUI..." in captured.err

    def test_main_uses_headless_mode_when_app_missing(self, tmp_path):
        with patch.object(gui, "_run_streamlit") as mock_run:
            with patch.object(gui, "__file__", str(tmp_path / "logpilot" / "gui.py")):
                gui.main()

        mock_run.assert_called_once_with(tmp_path / "app.py", headless=True)
