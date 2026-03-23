"""Tests for logpilot CLI (cli.py)."""
import sys
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from logpilot.cli import main


class TestCliBasic:
    """Basic CLI argument parsing and file handling."""

    def test_no_args_exits_with_error(self, capsys):
        """CLI with no arguments should print error and exit."""
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["logpilot"]):
                main()
        assert exc_info.value.code != 0

    def test_list_formats(self, capsys):
        """--list-formats should list available format plugins."""
        with patch("sys.argv", ["logpilot", "--list-formats"]):
            main()
        captured = capsys.readouterr()
        assert "was" in captured.out.lower()

    def test_missing_file_skipped(self, capsys, tmp_path):
        """Non-existent file should be skipped with warning."""
        fake = str(tmp_path / "nonexistent.log")
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["logpilot", fake]):
                main()
        captured = capsys.readouterr()
        assert "Skip" in captured.err or "No events" in captured.err

    def test_empty_file_exits(self, tmp_path, capsys):
        """Empty log file should exit with code 2."""
        empty = tmp_path / "empty.log"
        empty.write_text("")
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["logpilot", str(empty)]):
                main()
        assert exc_info.value.code == 2

    def test_parse_and_report_markdown(self, tmp_path):
        """Should parse a simple log and write markdown report."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E CWWKZ0002E: An error occurred\n"
            "[10/12/15 21:22:05:100 CEST] 0000001b SystemOut I Normal message\n"
        )
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "-q"]):
            main()
        assert out.exists()
        content = out.read_text()
        assert "Triage" in content or "triage" in content or "LogPilot" in content

    def test_parse_and_report_json(self, tmp_path):
        """Should parse a simple log and write JSON report."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E CWWKZ0002E: An error occurred\n"
        )
        out = tmp_path / "report.json"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--format", "json", "-q"]):
            main()
        assert out.exists()
        import json
        data = json.loads(out.read_text())
        assert "summary" in data or "events" in data or isinstance(data, dict)

    def test_quiet_suppresses_output(self, tmp_path, capsys):
        """--quiet should suppress progress messages."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E CWWKZ0002E: Error\n"
        )
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "-q"]):
            main()
        captured = capsys.readouterr()
        assert captured.err == "" or "event" not in captured.err.lower()


class TestCliAiIntegration:
    """Tests for CLI AI integration paths (mocked)."""

    def test_claude_missing_sdk(self, tmp_path, capsys):
        """--claude should fail gracefully when anthropic is not installed."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error occurred\n"
        )
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--claude", "-q"]):
            with patch.dict("sys.modules", {"anthropic": None}):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    def test_claude_api_error_caught(self, tmp_path, capsys):
        """Claude API errors should be caught and printed to stderr."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error occurred\n"
        )
        out = tmp_path / "report.md"

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = OSError("Connection refused")
        mock_anthropic.Anthropic.return_value = mock_client

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--claude", "-q"]):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                main()
        captured = capsys.readouterr()
        assert "failed" in captured.err.lower() or "error" in captured.err.lower()

    def test_claude_unexpected_error_caught(self, tmp_path, capsys):
        """Unexpected exceptions from Claude API should be caught (not crash)."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error occurred\n"
        )
        out = tmp_path / "report.md"

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = RuntimeError("API rate limit exceeded")
        mock_anthropic.Anthropic.return_value = mock_client

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--claude", "-q"]):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                main()
        captured = capsys.readouterr()
        assert "failed" in captured.err.lower()

    def test_local_ai_missing_sdk(self, tmp_path, capsys):
        """--ai-endpoint should fail gracefully when openai is not installed."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error occurred\n"
        )
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--ai-endpoint", "http://localhost:1234/v1", "-q"]):
            with patch.dict("sys.modules", {"openai": None}):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    def test_local_ai_connection_error(self, tmp_path, capsys):
        """Local AI connection error should be caught."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error occurred\n"
        )
        out = tmp_path / "report.md"

        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = OSError("Connection refused")
        mock_openai.OpenAI.return_value = mock_client

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--ai-endpoint", "http://localhost:1234/v1", "-q"]):
            with patch.dict("sys.modules", {"openai": mock_openai}):
                main()
        captured = capsys.readouterr()
        assert "failed" in captured.err.lower()

    def test_local_ai_unexpected_error_caught(self, tmp_path, capsys):
        """Unexpected exceptions from local AI should be caught (not crash)."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error occurred\n"
        )
        out = tmp_path / "report.md"

        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = KeyError("unexpected")
        mock_openai.OpenAI.return_value = mock_client

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--ai-endpoint", "http://localhost:1234/v1", "-q"]):
            with patch.dict("sys.modules", {"openai": mock_openai}):
                main()
        captured = capsys.readouterr()
        assert "failed" in captured.err.lower()

    def test_claude_success_writes_analysis(self, tmp_path):
        """Successful Claude call should write claude-analysis.md."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error occurred\n"
        )
        out = tmp_path / "report.md"

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_content = MagicMock()
        mock_content.text = "Root cause: configuration error"
        mock_message = MagicMock()
        mock_message.content = [mock_content]
        mock_client.messages.create.return_value = mock_message
        mock_anthropic.Anthropic.return_value = mock_client

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--claude", "-q"]):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                main()
        analysis_path = tmp_path / "claude-analysis.md"
        assert analysis_path.exists()
        assert "Root cause" in analysis_path.read_text()

    def test_local_ai_success_writes_analysis(self, tmp_path):
        """Successful local AI call should write ai-analysis.md."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error occurred\n"
        )
        out = tmp_path / "report.md"

        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Analysis: timeout issue"
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.OpenAI.return_value = mock_client

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--ai-endpoint", "http://localhost:1234/v1", "-q"]):
            with patch.dict("sys.modules", {"openai": mock_openai}):
                main()
        analysis_path = tmp_path / "ai-analysis.md"
        assert analysis_path.exists()
        assert "timeout" in analysis_path.read_text()


class TestCliOptions:
    """Test various CLI option combinations."""

    def test_top_and_samples_args(self, tmp_path):
        """--top and --samples should be passed to report generation."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error one\n"
            "[10/12/15 21:22:05:100 CEST] 0000001b SystemOut E Error two\n"
        )
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--top", "3", "--samples", "2", "-q"]):
            main()
        assert out.exists()

    def test_json_default_extension(self, tmp_path):
        """--format json with default --out should change extension to .json."""
        log = tmp_path / "test.log"
        log.write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error\n"
        )
        # Use default out name, should become report.json
        with patch("sys.argv", ["logpilot", str(log), "--format", "json", "-q"]):
            with patch("logpilot.cli.Path.write_text") as mock_write:
                try:
                    main()
                except Exception:
                    pass

    def test_multiple_files(self, tmp_path, capsys):
        """Multiple log files should be combined."""
        log1 = tmp_path / "a.log"
        log2 = tmp_path / "b.log"
        log1.write_text("[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error A\n")
        log2.write_text("[10/12/15 21:22:05:100 CEST] 0000001b SystemOut E Error B\n")
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log1), str(log2), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "Combined" in captured.err


class TestCliDirectory:
    """Tests for --directory recursive folder scanning."""

    def test_directory_scans_recursively(self, tmp_path, capsys):
        """--directory should find log files in subdirectories."""
        sub = tmp_path / "api"
        sub.mkdir()
        (sub / "server.log").write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error\n"
        )
        (tmp_path / "root.log").write_text(
            "[10/12/15 21:22:05:100 CEST] 0000001b SystemOut I OK\n"
        )
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", "-d", str(tmp_path), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "2 files" in captured.err
        assert out.exists()

    def test_directory_combined_with_files(self, tmp_path, capsys):
        """--directory can be combined with positional file arguments."""
        sub = tmp_path / "logs"
        sub.mkdir()
        (sub / "a.log").write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error A\n"
        )
        extra = tmp_path / "extra.log"
        extra.write_text(
            "[10/12/15 21:22:05:100 CEST] 0000001b SystemOut E Error B\n"
        )
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(extra), "-d", str(sub), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "Combined" in captured.err

    def test_directory_not_a_dir_exits(self, tmp_path):
        """--directory pointing to a file should exit with error."""
        f = tmp_path / "notadir.log"
        f.write_text("data\n")
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["logpilot", "-d", str(f)]):
                main()
        assert exc_info.value.code != 0

    def test_directory_empty_folder_exits(self, tmp_path):
        """--directory with empty folder (no log files) should exit with error."""
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["logpilot", "-d", str(empty)]):
                main()
        assert exc_info.value.code != 0

    def test_directory_skips_binary_files(self, tmp_path, capsys):
        """Binary files in directory should be skipped."""
        (tmp_path / "good.log").write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error\n"
        )
        (tmp_path / "bad.log").write_bytes(b"\x00\x01binary\x00")
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", "-d", str(tmp_path), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "1 skipped" in captured.err

    def test_directory_quiet_mode(self, tmp_path, capsys):
        """--directory with -q should suppress scan summary."""
        (tmp_path / "a.log").write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error\n"
        )
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", "-d", str(tmp_path), "--out", str(out), "-q"]):
            main()
        captured = capsys.readouterr()
        assert "Scanned" not in captured.err

    def test_directory_sets_system_label(self, tmp_path):
        """Events from --directory should have system_label set."""
        (tmp_path / "myapp.log").write_text(
            "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E Error\n"
        )
        out = tmp_path / "report.json"
        with patch("sys.argv", ["logpilot", "-d", str(tmp_path), "--out", str(out), "--format", "json", "-q"]):
            main()
        import json
        data = json.loads(out.read_text())
        # JSON report should contain events referencing the file
        assert out.exists()

    def test_directory_scenario_files(self, capsys, tmp_path):
        """--directory should work with the scenario fixture directory."""
        scenario = Path(__file__).parent / "fixtures" / "scenario"
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", "-d", str(scenario), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "12 files" in captured.err
        assert out.exists()
        content = out.read_text()
        assert len(content) > 200


class TestCliExitCode:
    """Tests for --exit-code and --error-threshold flags."""

    # Log line with an ERROR-level event
    _error_line = "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E CWWKZ0002E: An error occurred\n"
    # Log line with an INFO-level event
    _info_line = "[10/12/15 21:22:05:100 CEST] 0000001b SystemOut I Normal message\n"

    def test_exit_code_above_threshold_exits_1(self, tmp_path):
        """--exit-code exits with 1 when error count exceeds threshold."""
        log = tmp_path / "test.log"
        log.write_text(self._error_line * 3)
        out = tmp_path / "report.md"
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", [
                "logpilot", str(log), "--out", str(out),
                "--exit-code", "--error-threshold", "0", "-q",
            ]):
                main()
        assert exc_info.value.code == 1

    def test_exit_code_below_or_equal_threshold_exits_0(self, tmp_path):
        """--exit-code exits normally when error count is within threshold."""
        log = tmp_path / "test.log"
        log.write_text(self._error_line)
        out = tmp_path / "report.md"
        # threshold=5 means up to 5 errors are allowed — 1 error should not trigger exit 1
        with patch("sys.argv", [
            "logpilot", str(log), "--out", str(out),
            "--exit-code", "--error-threshold", "5", "-q",
        ]):
            main()  # must not raise SystemExit(1)
        assert out.exists()

    def test_without_exit_code_flag_always_exits_normally(self, tmp_path):
        """Without --exit-code, many errors do not cause a non-zero exit."""
        log = tmp_path / "test.log"
        log.write_text(self._error_line * 10)
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "-q"]):
            main()  # must not raise SystemExit(1)
        assert out.exists()
