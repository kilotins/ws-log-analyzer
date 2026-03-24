"""Tests for logpilot CLI (cli.py)."""
import sys
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from logpilot.cli import main, _resolve_ai_provider, _detect_formats


# Helper: a simple WAS log line
_ERROR_LINE = "[10/12/15 21:22:04:257 CEST] 0000001a SystemOut E CWWKZ0002E: An error occurred\n"
_INFO_LINE = "[10/12/15 21:22:05:100 CEST] 0000001b SystemOut I Normal message\n"


def _make_log(tmp_path, content=_ERROR_LINE):
    log = tmp_path / "test.log"
    log.write_text(content)
    return log


class TestCliBasic:
    """Basic CLI argument parsing and file handling."""

    def test_no_args_exits_with_error(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["logpilot"]):
                main()
        assert exc_info.value.code != 0

    def test_list_formats(self, capsys):
        with patch("sys.argv", ["logpilot", "--list-formats"]):
            main()
        captured = capsys.readouterr()
        assert "was" in captured.out.lower()

    def test_missing_file_skipped(self, capsys, tmp_path):
        fake = str(tmp_path / "nonexistent.log")
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["logpilot", fake]):
                main()

    def test_empty_file_exits(self, tmp_path):
        empty = tmp_path / "empty.log"
        empty.write_text("")
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["logpilot", str(empty)]):
                main()
        assert exc_info.value.code == 2

    def test_parse_and_report_markdown(self, tmp_path):
        log = _make_log(tmp_path, _ERROR_LINE + _INFO_LINE)
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "-q"]):
            main()
        assert out.exists()
        content = out.read_text()
        assert "LogPilot" in content or "Triage" in content

    def test_parse_and_report_json(self, tmp_path):
        log = _make_log(tmp_path)
        out = tmp_path / "report.json"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--format", "json", "-q"]):
            main()
        assert out.exists()
        import json
        data = json.loads(out.read_text())
        assert isinstance(data, dict)

    def test_parse_and_report_html(self, tmp_path):
        log = _make_log(tmp_path)
        out = tmp_path / "report.html"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--format", "html", "-q"]):
            main()
        assert out.exists()
        assert "<html" in out.read_text().lower()

    def test_quiet_suppresses_output(self, tmp_path, capsys):
        log = _make_log(tmp_path)
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "-q"]):
            main()
        captured = capsys.readouterr()
        assert captured.err == "" or "event" not in captured.err.lower()


class TestCliAiFlag:
    """Tests for the unified --ai flag."""

    def test_ai_flag_choices(self):
        """--ai accepts claude, gemini, openai, local."""
        for provider in ["claude", "gemini", "openai", "local"]:
            args = MagicMock(ai=provider, claude=False, ai_endpoint=None, ai_model=None, model=None)
            p, m, e = _resolve_ai_provider(args)
            assert p == provider

    def test_claude_backwards_compat(self):
        """--claude flag should resolve to claude provider."""
        args = MagicMock(ai=None, claude=True, ai_endpoint=None, ai_model=None, model=None)
        p, m, e = _resolve_ai_provider(args)
        assert p == "claude"
        assert "claude" in m or "sonnet" in m

    def test_ai_endpoint_backwards_compat(self):
        """--ai-endpoint should resolve to local provider."""
        args = MagicMock(ai=None, claude=False, ai_endpoint="http://localhost:1234/v1",
                         ai_model=None, model=None)
        p, m, e = _resolve_ai_provider(args)
        assert p == "local"
        assert e == "http://localhost:1234/v1"

    def test_no_ai_flag(self):
        """No AI flags should return empty provider."""
        args = MagicMock(ai=None, claude=False, ai_endpoint=None, ai_model=None, model=None)
        p, m, e = _resolve_ai_provider(args)
        assert p == ""

    def test_custom_model(self):
        """--model should override default model."""
        args = MagicMock(ai="claude", claude=False, ai_endpoint=None, ai_model=None,
                         model="claude-opus-4-6")
        p, m, e = _resolve_ai_provider(args)
        assert m == "claude-opus-4-6"

    def test_gemini_default_model(self):
        args = MagicMock(ai="gemini", claude=False, ai_endpoint=None, ai_model=None, model=None)
        _, m, _ = _resolve_ai_provider(args)
        assert "gemini" in m

    def test_openai_default_model(self):
        args = MagicMock(ai="openai", claude=False, ai_endpoint=None, ai_model=None, model=None)
        _, m, _ = _resolve_ai_provider(args)
        assert "gpt" in m


class TestDetectFormats:
    """Tests for _detect_formats helper."""

    def test_single_format(self):
        from logpilot.event import LogEvent
        events = [LogEvent(text="x", format="was"), LogEvent(text="y", format="was")]
        dominant, sources, multi = _detect_formats(events)
        assert dominant == "was"
        assert not multi

    def test_multi_format(self):
        from logpilot.event import LogEvent
        events = [LogEvent(text="x", format="was"), LogEvent(text="y", format="nginx")]
        dominant, sources, multi = _detect_formats(events)
        assert multi
        assert len(sources) == 2

    def test_empty_events(self):
        dominant, sources, multi = _detect_formats([])
        assert dominant == ""
        assert not multi


class TestCliAiIntegration:
    """Tests for CLI AI integration paths (mocked)."""

    def _mock_streaming_claude(self):
        """Create a mock Anthropic client with streaming support."""
        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        # Mock streaming context manager
        mock_stream = MagicMock()
        mock_stream.__enter__ = MagicMock(return_value=mock_stream)
        mock_stream.__exit__ = MagicMock(return_value=False)
        mock_stream.text_stream = iter(["Root cause: ", "configuration error"])
        mock_client.messages.stream.return_value = mock_stream

        return mock_anthropic

    def _mock_streaming_openai(self, text="Analysis: timeout issue"):
        """Create a mock OpenAI client with streaming support."""
        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        # Mock streaming response
        chunks = []
        for word in text.split(" "):
            chunk = MagicMock()
            chunk.choices = [MagicMock()]
            chunk.choices[0].delta.content = word + " "
            chunks.append(chunk)
        mock_client.chat.completions.create.return_value = iter(chunks)

        return mock_openai

    def test_claude_missing_sdk(self, tmp_path):
        log = _make_log(tmp_path)
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--ai", "claude", "-q"]):
            with patch.dict("sys.modules", {"anthropic": None}):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    def test_claude_api_error_caught(self, tmp_path, capsys):
        log = _make_log(tmp_path)
        out = tmp_path / "report.md"

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_client.messages.stream.side_effect = OSError("Connection refused")
        mock_anthropic.Anthropic.return_value = mock_client

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--ai", "claude", "-q"]):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                main()
        captured = capsys.readouterr()
        assert "failed" in captured.err.lower()
        assert out.exists()  # Report still written

    def test_claude_success_inline(self, tmp_path):
        """Successful Claude call should include AI analysis inline in report."""
        log = _make_log(tmp_path)
        out = tmp_path / "report.md"

        mock_anthropic = self._mock_streaming_claude()

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--ai", "claude", "-q"]):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                main()
        content = out.read_text()
        assert "Root cause" in content or "configuration error" in content

    def test_claude_backwards_compat(self, tmp_path):
        """--claude flag should still work."""
        log = _make_log(tmp_path)
        out = tmp_path / "report.md"

        mock_anthropic = self._mock_streaming_claude()

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--claude", "-q"]):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                main()
        assert out.exists()

    def test_local_ai_missing_sdk(self, tmp_path):
        log = _make_log(tmp_path)
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--ai", "local", "--ai-endpoint", "http://localhost:1234/v1", "-q"]):
            with patch.dict("sys.modules", {"openai": None}):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    def test_local_ai_connection_error(self, tmp_path, capsys):
        log = _make_log(tmp_path)
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

    def test_local_ai_success_inline(self, tmp_path):
        """Successful local AI call should include analysis inline in report."""
        log = _make_log(tmp_path)
        out = tmp_path / "report.md"

        mock_openai = self._mock_streaming_openai()

        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--ai-endpoint", "http://localhost:1234/v1", "-q"]):
            with patch.dict("sys.modules", {"openai": mock_openai}):
                main()
        content = out.read_text()
        assert "timeout" in content.lower() or "Analysis" in content

    def test_report_without_ai_has_no_ai_section(self, tmp_path):
        """Report generated without --ai should not have AI section."""
        log = _make_log(tmp_path)
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "-q"]):
            main()
        content = out.read_text()
        assert "AI Analysis" not in content


class TestCliOptions:
    """Test various CLI option combinations."""

    def test_top_and_samples_args(self, tmp_path):
        log = _make_log(tmp_path, _ERROR_LINE * 2)
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "--top", "3", "--samples", "2", "-q"]):
            main()
        assert out.exists()

    def test_multiple_files(self, tmp_path, capsys):
        log1 = tmp_path / "a.log"
        log2 = tmp_path / "b.log"
        log1.write_text(_ERROR_LINE)
        log2.write_text("[10/12/15 21:22:05:100 CEST] 0000001b SystemOut E Error B\n")
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log1), str(log2), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "Combined" in captured.err


class TestCliDirectory:
    """Tests for --directory recursive folder scanning."""

    def test_directory_scans_recursively(self, tmp_path, capsys):
        sub = tmp_path / "api"
        sub.mkdir()
        (sub / "server.log").write_text(_ERROR_LINE)
        (tmp_path / "root.log").write_text(_INFO_LINE)
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", "-d", str(tmp_path), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "2 files" in captured.err
        assert out.exists()

    def test_directory_combined_with_files(self, tmp_path, capsys):
        sub = tmp_path / "logs"
        sub.mkdir()
        (sub / "a.log").write_text(_ERROR_LINE)
        extra = tmp_path / "extra.log"
        extra.write_text("[10/12/15 21:22:05:100 CEST] 0000001b SystemOut E Error B\n")
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(extra), "-d", str(sub), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "Combined" in captured.err

    def test_directory_not_a_dir_exits(self, tmp_path):
        f = tmp_path / "notadir.log"
        f.write_text("data\n")
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["logpilot", "-d", str(f)]):
                main()

    def test_directory_empty_folder_exits(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["logpilot", "-d", str(empty)]):
                main()

    def test_directory_skips_binary_files(self, tmp_path, capsys):
        (tmp_path / "good.log").write_text(_ERROR_LINE)
        (tmp_path / "bad.log").write_bytes(b"\x00\x01binary\x00")
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", "-d", str(tmp_path), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "1 skipped" in captured.err

    def test_directory_scenario_files(self, capsys, tmp_path):
        scenario = Path(__file__).parent / "fixtures" / "scenario"
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", "-d", str(scenario), "--out", str(out)]):
            main()
        captured = capsys.readouterr()
        assert "12 files" in captured.err
        assert out.exists()


class TestCliExitCode:
    """Tests for --exit-code and --error-threshold flags."""

    def test_exit_code_above_threshold_exits_1(self, tmp_path):
        log = _make_log(tmp_path, _ERROR_LINE * 3)
        out = tmp_path / "report.md"
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", [
                "logpilot", str(log), "--out", str(out),
                "--exit-code", "--error-threshold", "0", "-q",
            ]):
                main()
        assert exc_info.value.code == 1

    def test_exit_code_below_threshold_exits_0(self, tmp_path):
        log = _make_log(tmp_path)
        out = tmp_path / "report.md"
        with patch("sys.argv", [
            "logpilot", str(log), "--out", str(out),
            "--exit-code", "--error-threshold", "5", "-q",
        ]):
            main()
        assert out.exists()

    def test_without_exit_code_flag_always_exits_normally(self, tmp_path):
        log = _make_log(tmp_path, _ERROR_LINE * 10)
        out = tmp_path / "report.md"
        with patch("sys.argv", ["logpilot", str(log), "--out", str(out), "-q"]):
            main()
        assert out.exists()
