"""M50 P1: Tests for logpilot/code_search.py

Tests CodeMatch dataclass, _iter_files(), _read_snippet(), and search_codebase()
covering exact matches, file-only matches, grep fallback, skip dirs, dedup,
read-only guarantees, and language extension filtering.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

import pytest

from logpilot.trace_to_code import CodeLocation
from logpilot.code_search import (
    CodeMatch,
    search_codebase,
    _read_snippet,
    _iter_files,
)


# ── Repo builder helpers ──────────────────────────────────────────────


def _make_java_repo(tmp_path: Path) -> Path:
    src = tmp_path / "src" / "com" / "myapp"
    src.mkdir(parents=True)
    (src / "OrderDAO.java").write_text(
        "package com.myapp;\n"
        "public class OrderDAO {\n"
        "    public void save(Order order) {\n"
        "        // save logic\n"
        "        db.execute(order);\n"
        "    }\n"
        "}\n"
    )
    (src / "PaymentService.java").write_text(
        "package com.myapp;\n"
        "public class PaymentService {\n"
        "    public void processCharge(String id) {\n"
        "        gateway.charge(id);\n"
        "    }\n"
        "}\n"
    )
    return tmp_path


def _make_python_repo(tmp_path: Path) -> Path:
    app = tmp_path / "app"
    app.mkdir(parents=True)
    (app / "tasks.py").write_text(
        "from celery import shared_task\n"
        "\n"
        "@shared_task\n"
        "def process_order(order_id):\n"
        "    db.save(order_id)\n"
        "    return True\n"
    )
    (app / "models.py").write_text(
        "class Order:\n"
        "    def __init__(self, order_id):\n"
        "        self.order_id = order_id\n"
    )
    return tmp_path


def _java_location(file_hint: str, line: int | None, method: str, class_name: str = "com.myapp.OrderDAO") -> CodeLocation:
    return CodeLocation(
        file_hint=file_hint,
        line=line,
        class_name=class_name,
        method=method,
        language="java",
    )


def _python_location(file_hint: str, line: int | None, method: str | None = None) -> CodeLocation:
    return CodeLocation(
        file_hint=file_hint,
        line=line,
        method=method,
        language="python",
    )


# ── _iter_files ───────────────────────────────────────────────────────


class TestIterFiles:
    def test_finds_java_files(self, tmp_path):
        _make_java_repo(tmp_path)
        files = _iter_files(tmp_path, extensions={".java"})
        names = {f.name for f in files}
        assert "OrderDAO.java" in names
        assert "PaymentService.java" in names

    def test_finds_python_files(self, tmp_path):
        _make_python_repo(tmp_path)
        files = _iter_files(tmp_path, extensions={".py"})
        names = {f.name for f in files}
        assert "tasks.py" in names
        assert "models.py" in names

    def test_skips_git_dir(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
        (tmp_path / "Main.java").write_text("public class Main {}")
        files = _iter_files(tmp_path, extensions={".java"})
        paths = [str(f) for f in files]
        assert not any(".git" in p for p in paths)

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "somelib"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("module.exports = {};")
        (tmp_path / "App.java").write_text("public class App {}")
        files = _iter_files(tmp_path, extensions={".java"})
        # No file returned should live inside the node_modules subtree
        nm_prefix = str(nm.parent)
        assert not any(str(f).startswith(nm_prefix) for f in files)

    def test_skips_pycache(self, tmp_path):
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "tasks.cpython-311.pyc").write_bytes(b"\x00" * 100)
        (tmp_path / "tasks.py").write_text("print('hello')")
        files = _iter_files(tmp_path, extensions={".py"})
        paths = [str(f) for f in files]
        assert not any("__pycache__" in p for p in paths)

    def test_skips_large_files(self, tmp_path):
        big = tmp_path / "Big.java"
        big.write_bytes(b"x" * (1_048_576 + 1))  # 1 MB + 1 byte
        files = _iter_files(tmp_path, extensions={".java"})
        assert big not in files

    def test_no_extension_filter_returns_all(self, tmp_path):
        (tmp_path / "a.java").write_text("class A {}")
        (tmp_path / "b.py").write_text("pass")
        (tmp_path / "c.txt").write_text("text")
        files = _iter_files(tmp_path, extensions=None)
        names = {f.name for f in files}
        assert {"a.java", "b.py", "c.txt"} <= names

    def test_empty_dir_returns_empty(self, tmp_path):
        assert _iter_files(tmp_path) == []

    def test_skips_symlinked_directories_outside_repo(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "Main.java").write_text("public class Main {}")
        with tempfile.TemporaryDirectory() as td:
            external = Path(td)
            (external / "Leaked.java").write_text("public class Leaked {}")

            (tmp_path / "link-out").symlink_to(external, target_is_directory=True)

            files = _iter_files(tmp_path, extensions={".java"})
            names = {f.name for f in files}

            assert "Main.java" in names
            assert "Leaked.java" not in names

    def test_skips_symlinked_files(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        target = tmp_path / "Target.java"
        target.write_text("public class Target {}")
        (src / "TargetLink.java").symlink_to(target)

        files = _iter_files(tmp_path, extensions={".java"})
        names = {f.name for f in files}

        assert "TargetLink.java" not in names


# ── _read_snippet ─────────────────────────────────────────────────────


class TestReadSnippet:
    def _write_numbered(self, path: Path, n: int = 20) -> Path:
        path.write_text("\n".join(f"line {i}" for i in range(1, n + 1)))
        return path

    def test_marks_target_line_with_arrow(self, tmp_path):
        f = self._write_numbered(tmp_path / "code.java")
        snippet = _read_snippet(f, line_num=5, context=2)
        target = [s for s in snippet if s.startswith(">")]
        assert len(target) == 1
        assert "5" in target[0]
        assert "line 5" in target[0]

    def test_non_target_lines_have_space_prefix(self, tmp_path):
        f = self._write_numbered(tmp_path / "code.java")
        snippet = _read_snippet(f, line_num=5, context=2)
        non_targets = [s for s in snippet if not s.startswith(">")]
        assert all(s.startswith(" ") for s in non_targets)

    def test_context_lines_count(self, tmp_path):
        f = self._write_numbered(tmp_path / "code.java", n=20)
        snippet = _read_snippet(f, line_num=10, context=5)
        # Lines 5–15 inclusive = 11 lines
        assert len(snippet) == 11

    def test_context_clipped_at_start_of_file(self, tmp_path):
        f = self._write_numbered(tmp_path / "code.java")
        snippet = _read_snippet(f, line_num=2, context=5)
        # Can't go before line 1
        line_nums = [int(s.split("|")[0].strip().lstrip(">").strip()) for s in snippet]
        assert min(line_nums) == 1

    def test_context_clipped_at_end_of_file(self, tmp_path):
        f = self._write_numbered(tmp_path / "code.java", n=10)
        snippet = _read_snippet(f, line_num=9, context=5)
        line_nums = [int(s.split("|")[0].strip().lstrip(">").strip()) for s in snippet]
        assert max(line_nums) == 10

    def test_nonexistent_file_returns_empty(self, tmp_path):
        assert _read_snippet(tmp_path / "missing.java", 1) == []

    def test_line_num_1_works(self, tmp_path):
        f = self._write_numbered(tmp_path / "code.java")
        snippet = _read_snippet(f, line_num=1, context=3)
        target = [s for s in snippet if s.startswith(">")]
        assert len(target) == 1
        assert "1" in target[0]


# ── search_codebase: exact match ──────────────────────────────────────


class TestSearchCodebaseExact:
    def test_exact_match_java(self, tmp_path):
        _make_java_repo(tmp_path)
        loc = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path, [loc])
        assert len(matches) == 1
        assert matches[0].confidence == "exact"
        assert matches[0].line_num == 3
        assert "OrderDAO.java" in matches[0].abs_path

    def test_exact_match_python(self, tmp_path):
        _make_python_repo(tmp_path)
        loc = _python_location("tasks.py", line=4, method="process_order")
        matches = search_codebase(tmp_path, [loc])
        assert len(matches) == 1
        assert matches[0].confidence == "exact"
        assert matches[0].line_num == 4

    def test_exact_match_rel_path_is_relative(self, tmp_path):
        _make_java_repo(tmp_path)
        loc = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path, [loc])
        assert len(matches) == 1
        rel = matches[0].rel_path
        assert not Path(rel).is_absolute()
        assert "OrderDAO.java" in rel

    def test_exact_match_snippet_contains_target(self, tmp_path):
        _make_java_repo(tmp_path)
        loc = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path, [loc])
        assert matches
        snippet_text = "\n".join(matches[0].snippet)
        assert ">" in snippet_text  # target line is marked

    def test_exact_match_location_backref(self, tmp_path):
        _make_java_repo(tmp_path)
        loc = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path, [loc])
        assert matches[0].location is loc


# ── search_codebase: file-only match ─────────────────────────────────


class TestSearchCodebaseFileOnly:
    def test_file_match_no_line(self, tmp_path):
        _make_java_repo(tmp_path)
        loc = _java_location("OrderDAO.java", line=None, method="save")
        matches = search_codebase(tmp_path, [loc])
        assert len(matches) == 1
        assert matches[0].confidence == "file"
        assert matches[0].line_num == 1  # top of file

    def test_file_match_python_no_line(self, tmp_path):
        _make_python_repo(tmp_path)
        loc = _python_location("tasks.py", line=None)
        matches = search_codebase(tmp_path, [loc])
        assert len(matches) == 1
        assert matches[0].confidence == "file"


# ── search_codebase: grep fallback ───────────────────────────────────


class TestSearchCodebaseGrep:
    def test_grep_fallback_method_found(self, tmp_path):
        _make_java_repo(tmp_path)
        # File hint doesn't match, but method "processCharge" is in PaymentService.java
        loc = CodeLocation(
            file_hint="NonExistent.java",
            line=None,
            class_name="com.myapp.PaymentService",
            method="processCharge",
            language="java",
        )
        matches = search_codebase(tmp_path, [loc])
        assert len(matches) >= 1
        assert matches[0].confidence == "grep"
        assert "PaymentService.java" in matches[0].abs_path

    def test_grep_fallback_python_function(self, tmp_path):
        _make_python_repo(tmp_path)
        loc = CodeLocation(
            file_hint="missing.py",
            line=None,
            method="process_order",
            language="python",
        )
        matches = search_codebase(tmp_path, [loc])
        assert len(matches) >= 1
        assert matches[0].confidence == "grep"
        assert "tasks.py" in matches[0].abs_path

    def test_no_match_returns_empty(self, tmp_path):
        _make_java_repo(tmp_path)
        loc = _java_location("Ghost.java", line=99, method="phantomMethod", class_name="com.ghost.Ghost")
        matches = search_codebase(tmp_path, [loc])
        assert matches == []


# ── search_codebase: edge cases ───────────────────────────────────────


class TestSearchCodebaseEdgeCases:
    def test_empty_repo_returns_empty(self, tmp_path):
        loc = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path, [loc])
        assert matches == []

    def test_nonexistent_repo_returns_empty(self, tmp_path):
        loc = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path / "does_not_exist", [loc])
        assert matches == []

    def test_empty_locations_returns_empty(self, tmp_path):
        _make_java_repo(tmp_path)
        assert search_codebase(tmp_path, []) == []

    def test_max_results_respected(self, tmp_path):
        # Create many unique Java files
        src = tmp_path / "src"
        src.mkdir()
        for i in range(20):
            (src / f"Service{i}.java").write_text(
                f"public class Service{i} {{\n"
                f"    public void handle{i}() {{}}\n"
                f"}}\n"
            )
        locations = [
            _java_location(f"Service{i}.java", line=2, method=f"handle{i}",
                           class_name=f"com.myapp.Service{i}")
            for i in range(20)
        ]
        matches = search_codebase(tmp_path, locations, max_results=5)
        assert len(matches) <= 5

    def test_deduplication_same_file_and_line(self, tmp_path):
        _make_java_repo(tmp_path)
        loc1 = _java_location("OrderDAO.java", line=3, method="save")
        loc2 = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path, [loc1, loc2])
        # Same rel_path + line should not appear twice
        seen = set()
        for m in matches:
            key = (m.rel_path, m.line_num)
            assert key not in seen, f"Duplicate match: {key}"
            seen.add(key)

    def test_read_only_no_files_created(self, tmp_path):
        _make_java_repo(tmp_path)
        before = set(tmp_path.rglob("*"))
        loc = _java_location("OrderDAO.java", line=3, method="save")
        search_codebase(tmp_path, [loc])
        after = set(tmp_path.rglob("*"))
        assert before == after, "search_codebase created or deleted files — must be read-only"

    def test_multiple_locations_some_found_some_not(self, tmp_path):
        _make_java_repo(tmp_path)
        locations = [
            _java_location("OrderDAO.java", line=3, method="save"),        # found
            _java_location("Phantom.java", line=99, method="phantomOp",    # not found
                           class_name="com.ghost.Phantom"),
        ]
        matches = search_codebase(tmp_path, locations)
        assert len(matches) == 1
        assert matches[0].confidence == "exact"

    def test_results_sorted_by_confidence(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        # Exact match file
        (src / "Alpha.java").write_text(
            "public class Alpha {\n"
            "    public void doAlpha() {}\n"
            "}\n"
        )
        # File that only contains method via grep
        (src / "Beta.java").write_text(
            "public class Beta {\n"
            "    public void doGrepTarget() {}\n"
            "}\n"
        )
        locations = [
            # grep match: wrong file hint but method found in Beta.java
            CodeLocation(file_hint="Missing.java", line=None,
                         class_name="com.myapp.Beta", method="doGrepTarget", language="java"),
            # exact match
            _java_location("Alpha.java", line=2, method="doAlpha", class_name="com.myapp.Alpha"),
        ]
        matches = search_codebase(tmp_path, locations)
        confidences = [m.confidence for m in matches]
        priority = {"exact": 0, "file": 1, "grep": 2}
        for i in range(len(confidences) - 1):
            assert priority[confidences[i]] <= priority[confidences[i + 1]]

    def test_search_codebase_does_not_return_matches_from_symlinked_directories(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "OrderDAO.java").write_text(
            "public class OrderDAO {\n"
            "    public void save() {}\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            external = Path(td)
            (external / "LeakedService.java").write_text(
                "public class LeakedService {\n"
                "    public void processCharge() {}\n"
                "}\n"
            )
            (tmp_path / "vendor-link").symlink_to(external, target_is_directory=True)

            loc = CodeLocation(
                file_hint="Missing.java",
                line=None,
                class_name="com.myapp.LeakedService",
                method="processCharge",
                language="java",
            )
            matches = search_codebase(tmp_path, [loc])
            assert matches == []


# ── CodeMatch.to_dict ─────────────────────────────────────────────────


class TestCodeMatchToDict:
    def test_to_dict_has_required_keys(self, tmp_path):
        _make_java_repo(tmp_path)
        loc = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path, [loc])
        assert matches
        d = matches[0].to_dict()
        required = {"abs_path", "rel_path", "line_num", "snippet", "confidence",
                    "language", "method", "file_hint"}
        assert required <= set(d.keys())

    def test_to_dict_snippet_is_string(self, tmp_path):
        _make_java_repo(tmp_path)
        loc = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path, [loc])
        assert matches
        d = matches[0].to_dict()
        assert isinstance(d["snippet"], str)

    def test_to_dict_language_matches_location(self, tmp_path):
        _make_java_repo(tmp_path)
        loc = _java_location("OrderDAO.java", line=3, method="save")
        matches = search_codebase(tmp_path, [loc])
        assert matches[0].to_dict()["language"] == "java"

    def test_to_dict_python_language(self, tmp_path):
        _make_python_repo(tmp_path)
        loc = _python_location("tasks.py", line=4, method="process_order")
        matches = search_codebase(tmp_path, [loc])
        assert matches
        assert matches[0].to_dict()["language"] == "python"


# ── Language extension filtering ─────────────────────────────────────


class TestLanguageExtensionFiltering:
    def test_java_location_only_searches_java_files(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        # Java file with the method
        (src / "OrderDAO.java").write_text(
            "public class OrderDAO {\n"
            "    public void save() {}\n"
            "}\n"
        )
        # Python file also has "save" — should NOT match for a java location
        (src / "service.py").write_text(
            "def save():\n"
            "    pass\n"
        )
        loc = CodeLocation(
            file_hint="NotFound.java",
            line=None,
            class_name="com.myapp.OrderDAO",
            method="save",
            language="java",
        )
        matches = search_codebase(tmp_path, [loc])
        for m in matches:
            assert m.abs_path.endswith(".java") or m.abs_path.endswith(".kt") \
                   or m.abs_path.endswith(".scala") or m.abs_path.endswith(".groovy")

    def test_python_location_only_searches_py_files(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "tasks.py").write_text("def process_order():\n    pass\n")
        (src / "Tasks.java").write_text("public class Tasks {\n    void processOrder() {}\n}\n")
        loc = CodeLocation(
            file_hint="missing.py",
            line=None,
            method="process_order",
            language="python",
        )
        matches = search_codebase(tmp_path, [loc])
        for m in matches:
            assert m.abs_path.endswith(".py")
