"""Tests for logpilot.discovery — recursive log file discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from logpilot.discovery import (
    DiscoveredFile,
    DiscoveryResult,
    RejectedFile,
    discover_log_files,
    guess_group,
    _is_binary,
    _fmt_size,
    INCLUDE_EXTENSIONS,
    EXCLUDE_DIRS,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_TOTAL_SIZE,
    DEFAULT_MAX_FILE_SIZE,
)


# ── guess_group ─────────────────────────────────────────────────────


class TestGuessGroup:
    def test_root_level_file(self):
        assert guess_group("server.log") == ""

    def test_single_parent(self):
        assert guess_group("api/server.log") == "api"

    def test_nested_path(self):
        assert guess_group("logs/worker/out.log") == "logs/worker"

    def test_deep_nesting(self):
        assert guess_group("a/b/c/d/deep.log") == "a/b/c/d"


# ── _is_binary ──────────────────────────────────────────────────────


class TestIsBinary:
    def test_text_file(self, tmp_path):
        f = tmp_path / "text.log"
        f.write_text("Hello world\nLine 2\n")
        assert _is_binary(f) is False

    def test_binary_file(self, tmp_path):
        f = tmp_path / "binary.dat"
        f.write_bytes(b"\x00\x01\x02\x03\x04")
        assert _is_binary(f) is True

    def test_nonexistent_file(self, tmp_path):
        f = tmp_path / "nope.log"
        assert _is_binary(f) is True  # returns True on error

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.log"
        f.write_bytes(b"")
        assert _is_binary(f) is False  # no null bytes in empty content


# ── _fmt_size ───────────────────────────────────────────────────────


class TestFmtSize:
    def test_bytes(self):
        assert _fmt_size(500) == "500 B"

    def test_kilobytes(self):
        assert _fmt_size(2048) == "2.0 KB"

    def test_megabytes(self):
        assert _fmt_size(5 * 1024 * 1024) == "5.0 MB"

    def test_gigabytes(self):
        assert _fmt_size(2 * 1024 * 1024 * 1024) == "2.0 GB"

    def test_zero(self):
        assert _fmt_size(0) == "0 B"


# ── discover_log_files — basic scenarios ────────────────────────────


class TestDiscoverBasic:
    def test_empty_directory(self, tmp_path):
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 0
        assert len(result.rejected) == 0

    def test_single_log_file(self, tmp_path):
        (tmp_path / "app.log").write_text("2025-01-01 INFO started\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 1
        assert result.accepted[0].relative_path == "app.log"
        assert result.accepted[0].group == ""

    def test_multiple_extensions(self, tmp_path):
        (tmp_path / "a.log").write_text("log line\n")
        (tmp_path / "b.txt").write_text("text line\n")
        (tmp_path / "c.out").write_text("output line\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 3

    def test_unsupported_extension_rejected(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b"fake png content no nulls")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 0
        assert len(result.rejected) == 1
        assert "extension" in result.rejected[0].reason

    def test_not_a_directory(self, tmp_path):
        f = tmp_path / "file.log"
        f.write_text("data\n")
        result = discover_log_files(f)  # pass a file, not a dir
        assert len(result.accepted) == 0


# ── discover_log_files — recursive traversal ────────────────────────


class TestDiscoverRecursive:
    def test_nested_directories(self, tmp_path):
        (tmp_path / "api").mkdir()
        (tmp_path / "api" / "server.log").write_text("log\n")
        (tmp_path / "worker").mkdir()
        (tmp_path / "worker" / "out.log").write_text("log\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 2
        groups = {f.group for f in result.accepted}
        assert groups == {"api", "worker"}

    def test_deep_nesting(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "deep.log").write_text("log\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 1
        assert result.accepted[0].group == "a/b/c"

    def test_mixed_files_at_different_levels(self, tmp_path):
        (tmp_path / "root.log").write_text("root\n")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "child.log").write_text("child\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 2
        rels = {f.relative_path for f in result.accepted}
        assert "root.log" in rels
        assert "sub/child.log" in rels


# ── discover_log_files — exclusions ─────────────────────────────────


class TestDiscoverExclusions:
    def test_exclude_hidden_files(self, tmp_path):
        (tmp_path / ".hidden.log").write_text("hidden\n")
        (tmp_path / "visible.log").write_text("visible\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 1
        assert result.accepted[0].relative_path == "visible.log"

    def test_include_hidden_files_when_requested(self, tmp_path):
        (tmp_path / ".hidden.log").write_text("hidden\n")
        (tmp_path / "visible.log").write_text("visible\n")
        result = discover_log_files(tmp_path, include_hidden=True)
        assert len(result.accepted) == 2

    def test_exclude_git_directory(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "log.log").write_text("git log\n")
        (tmp_path / "app.log").write_text("app\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 1
        assert result.accepted[0].relative_path == "app.log"

    def test_exclude_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "debug.log").write_text("debug\n")
        (tmp_path / "app.log").write_text("app\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 1

    def test_exclude_pycache(self, tmp_path):
        pc = tmp_path / "__pycache__"
        pc.mkdir()
        (pc / "cache.log").write_text("cache\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 0

    def test_binary_file_rejected(self, tmp_path):
        (tmp_path / "binary.log").write_bytes(b"text\x00binary\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 0
        assert len(result.rejected) == 1
        assert "binary" in result.rejected[0].reason

    def test_empty_file_rejected(self, tmp_path):
        (tmp_path / "empty.log").write_text("")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 0
        assert len(result.rejected) == 1
        assert "empty" in result.rejected[0].reason


# ── discover_log_files — limits ─────────────────────────────────────


class TestDiscoverLimits:
    def test_max_files_limit(self, tmp_path):
        for i in range(10):
            (tmp_path / f"file{i:02d}.log").write_text(f"line {i}\n")
        result = discover_log_files(tmp_path, max_files=5)
        assert len(result.accepted) == 5
        assert result.truncated is True
        assert "max files" in result.truncation_reason

    def test_max_file_size_limit(self, tmp_path):
        (tmp_path / "big.log").write_text("x" * 2000)
        (tmp_path / "small.log").write_text("ok\n")
        result = discover_log_files(tmp_path, max_file_size=1000)
        assert len(result.accepted) == 1
        assert result.accepted[0].relative_path == "small.log"
        assert len(result.rejected) == 1
        assert "max file size" in result.rejected[0].reason

    def test_max_total_size_limit(self, tmp_path):
        for i in range(5):
            (tmp_path / f"f{i}.log").write_text("x" * 100)
        # Total is 500 bytes, limit to 250
        result = discover_log_files(tmp_path, max_total_size=250)
        assert len(result.accepted) < 5
        assert result.truncated is True
        assert "max total size" in result.truncation_reason

    def test_no_truncation_within_limits(self, tmp_path):
        for i in range(3):
            (tmp_path / f"f{i}.log").write_text("ok\n")
        result = discover_log_files(tmp_path, max_files=10)
        assert result.truncated is False
        assert result.truncation_reason == ""


# ── discover_log_files — .gz handling ───────────────────────────────


class TestDiscoverGzip:
    def test_gz_log_accepted(self, tmp_path):
        import gzip
        f = tmp_path / "app.log.gz"
        with gzip.open(f, "wt") as fh:
            fh.write("2025-01-01 INFO started\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 1
        assert result.accepted[0].relative_path == "app.log.gz"

    def test_gz_non_log_extension_rejected(self, tmp_path):
        import gzip
        f = tmp_path / "data.csv.gz"
        with gzip.open(f, "wt") as fh:
            fh.write("a,b,c\n1,2,3\n")
        result = discover_log_files(tmp_path)
        assert len(result.accepted) == 0
        assert len(result.rejected) == 1

    def test_plain_gz_accepted(self, tmp_path):
        """A .gz file without double extension is accepted (could be a log)."""
        import gzip
        f = tmp_path / "archive.gz"
        with gzip.open(f, "wt") as fh:
            fh.write("log data\n")
        result = discover_log_files(tmp_path)
        # .gz with no inner extension — stem has no suffix, so stem_suffix is ""
        # Empty stem_suffix means no restriction, so it should be accepted
        assert len(result.accepted) == 1


# ── discover_log_files — deterministic ordering ─────────────────────


class TestDiscoverOrdering:
    def test_files_sorted_by_relative_path(self, tmp_path):
        (tmp_path / "z.log").write_text("z\n")
        (tmp_path / "a.log").write_text("a\n")
        sub = tmp_path / "m"
        sub.mkdir()
        (sub / "mid.log").write_text("m\n")
        result = discover_log_files(tmp_path)
        rels = [f.relative_path for f in result.accepted]
        assert rels == sorted(rels)


# ── DiscoveryResult metadata ────────────────────────────────────────


class TestDiscoveryResult:
    def test_total_size_calculated(self, tmp_path):
        (tmp_path / "a.log").write_text("hello\n")  # 6 bytes
        (tmp_path / "b.log").write_text("world\n")  # 6 bytes
        result = discover_log_files(tmp_path)
        assert result.total_size == sum(f.size for f in result.accepted)
        assert result.total_size > 0


# ── Constants ───────────────────────────────────────────────────────


class TestConstants:
    def test_include_extensions_has_log(self):
        assert ".log" in INCLUDE_EXTENSIONS
        assert ".gz" in INCLUDE_EXTENSIONS
        assert ".txt" in INCLUDE_EXTENSIONS

    def test_exclude_dirs_has_git(self):
        assert ".git" in EXCLUDE_DIRS
        assert "node_modules" in EXCLUDE_DIRS
        assert "__pycache__" in EXCLUDE_DIRS

    def test_defaults_are_reasonable(self):
        assert DEFAULT_MAX_FILES == 100
        assert DEFAULT_MAX_TOTAL_SIZE == 500 * 1024 * 1024
        assert DEFAULT_MAX_FILE_SIZE == 100 * 1024 * 1024


# ── P4: Integration with parser pipeline ────────────────────────────


class TestPipelineIntegration:
    """Test that discovered files parse correctly and retain metadata."""

    def test_scenario_files_discoverable(self):
        """The scenario fixture directory should discover all 12 log files."""
        scenario = Path(__file__).parent / "fixtures" / "scenario"
        result = discover_log_files(scenario)
        assert len(result.accepted) == 12

    def test_discovered_files_parseable(self):
        """All discovered scenario files should parse without error."""
        from logpilot.parser import parse_file

        scenario = Path(__file__).parent / "fixtures" / "scenario"
        result = discover_log_files(scenario)
        total = 0
        for df in result.accepted:
            events = parse_file(df.path)
            assert len(events) > 0, f"{df.relative_path} produced no events"
            total += len(events)
        assert total >= 290  # varies slightly by format plugin parsing (PG merges DETAIL/HINT)

    def test_group_labels_in_nested_structure(self, tmp_path):
        """Files in subdirs get group labels from path."""
        import shutil
        scenario = Path(__file__).parent / "fixtures" / "scenario"
        # Create nested structure
        (tmp_path / "frontend").mkdir()
        (tmp_path / "backend").mkdir()
        shutil.copy(scenario / "frontend-lb.log", tmp_path / "frontend" / "access.log")
        shutil.copy(scenario / "checkout-was.log", tmp_path / "backend" / "app.log")

        result = discover_log_files(tmp_path)
        groups = {df.group for df in result.accepted}
        assert "frontend" in groups
        assert "backend" in groups

    def test_system_label_from_group(self, tmp_path):
        """system_label should include group prefix when files are nested."""
        import shutil
        from logpilot.parser import parse_file
        from logpilot.analysis import per_source_summary

        scenario = Path(__file__).parent / "fixtures" / "scenario"
        (tmp_path / "api").mkdir()
        shutil.copy(scenario / "checkout-was.log", tmp_path / "api" / "server.log")
        shutil.copy(scenario / "frontend-lb.log", tmp_path / "access.log")

        result = discover_log_files(tmp_path)
        all_events = []
        for df in result.accepted:
            evts = parse_file(df.path)
            stem = df.path.stem
            label = f"{df.group}/{stem}" if df.group else stem
            for e in evts:
                e.system_label = label
            all_events.extend(evts)

        sources = per_source_summary(all_events)
        labels = {s["label"] for s in sources}
        assert "api/server" in labels
        assert "access" in labels

    def test_many_sources_handled(self, tmp_path):
        """per_source_summary handles 12+ sources gracefully."""
        from logpilot.parser import parse_file
        from logpilot.analysis import per_source_summary

        # Create 12 files with simple content
        for i in range(12):
            (tmp_path / f"svc{i:02d}.log").write_text(
                f"[10/12/15 21:22:04:257 CEST] 0000001a Comp E CODE{i:02d}E: Error in service {i}\n"
            )

        result = discover_log_files(tmp_path)
        all_events = []
        for df in result.accepted:
            evts = parse_file(df.path)
            for e in evts:
                e.system_label = df.path.stem
            all_events.extend(evts)

        sources = per_source_summary(all_events)
        assert len(sources) == 12

    def test_public_api_exports(self):
        """Discovery classes should be importable from logpilot."""
        from logpilot import discover_log_files, DiscoveredFile, DiscoveryResult, RejectedFile
        assert callable(discover_log_files)
        assert DiscoveredFile is not None
        assert DiscoveryResult is not None
        assert RejectedFile is not None
