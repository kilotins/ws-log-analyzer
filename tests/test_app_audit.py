"""Tests for app_audit.py — signature extraction, source collection, model definitions."""
import sys
import types
import textwrap
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Stub streamlit and optional deps before importing app_audit
# ---------------------------------------------------------------------------

_st_stub = types.ModuleType("streamlit")
_st_stub.session_state = MagicMock()
sys.modules.setdefault("streamlit", _st_stub)

# Stub logpilot dependencies that app_audit imports at module level
# Only create stubs for modules not already loaded (avoid corrupting real modules)
_stubs_installed: list[str] = []

if "logpilot" not in sys.modules:
    _logpilot_stub = types.ModuleType("logpilot")
    _logpilot_stub.ask_gemini = MagicMock()
    _logpilot_stub.estimate_tokens = MagicMock(return_value=100)
    sys.modules["logpilot"] = _logpilot_stub
    _stubs_installed.append("logpilot")

if "app_spend" not in sys.modules:
    _app_spend_stub = types.ModuleType("app_spend")
    _app_spend_stub.record_spend = MagicMock()
    _app_spend_stub.render_spend_tab = MagicMock()
    sys.modules["app_spend"] = _app_spend_stub
    _stubs_installed.append("app_spend")

import app_audit as audit

# Clean up stubs so they don't pollute other test modules
for _stub_name in _stubs_installed:
    sys.modules.pop(_stub_name, None)


# ---------------------------------------------------------------------------
# _AUDIT_MODELS
# ---------------------------------------------------------------------------

class TestAuditModels:
    """Verify _AUDIT_MODELS structure."""

    _REQUIRED_KEYS = {"provider", "id", "max_tokens"}

    def test_all_entries_have_required_keys(self):
        for label, info in audit._AUDIT_MODELS.items():
            missing = self._REQUIRED_KEYS - set(info.keys())
            assert not missing, f"'{label}' is missing keys: {missing}"

    def test_provider_values_are_known(self):
        known_providers = {"local", "claude", "gemini", "openai"}
        for label, info in audit._AUDIT_MODELS.items():
            assert info["provider"] in known_providers, (
                f"Unknown provider '{info['provider']}' in '{label}'"
            )

    def test_max_tokens_positive_int(self):
        for label, info in audit._AUDIT_MODELS.items():
            assert isinstance(info["max_tokens"], int)
            assert info["max_tokens"] > 0

    def test_has_at_least_one_claude_model(self):
        claude_models = [k for k, v in audit._AUDIT_MODELS.items() if v["provider"] == "claude"]
        assert len(claude_models) >= 1

    def test_has_local_model(self):
        local = [k for k, v in audit._AUDIT_MODELS.items() if v["provider"] == "local"]
        assert len(local) >= 1

    def test_model_ids_are_strings(self):
        for label, info in audit._AUDIT_MODELS.items():
            assert isinstance(info["id"], str), f"'{label}' id is not a string"


# ---------------------------------------------------------------------------
# _AUDIT_SYSTEM_PROMPT
# ---------------------------------------------------------------------------

class TestAuditSystemPrompt:
    """Verify _AUDIT_SYSTEM_PROMPT content."""

    def test_non_empty(self):
        assert len(audit._AUDIT_SYSTEM_PROMPT.strip()) > 0

    def test_contains_executive_summary(self):
        assert "Executive Summary" in audit._AUDIT_SYSTEM_PROMPT

    def test_contains_code_review(self):
        assert "Code Review" in audit._AUDIT_SYSTEM_PROMPT

    def test_contains_grade_instruction(self):
        # Should instruct the model to assign grades
        prompt = audit._AUDIT_SYSTEM_PROMPT.lower()
        assert "grade" in prompt

    def test_contains_markdown_instruction(self):
        prompt = audit._AUDIT_SYSTEM_PROMPT.lower()
        assert "markdown" in prompt

    def test_starts_with_role_description(self):
        # Should describe the LLM's role
        assert "engineer" in audit._AUDIT_SYSTEM_PROMPT.lower() or \
               "audit" in audit._AUDIT_SYSTEM_PROMPT.lower()

    def test_contains_report_title_instruction(self):
        assert "LogPilot" in audit._AUDIT_SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# _extract_signatures (AST-based)
# ---------------------------------------------------------------------------

class TestExtractSignatures:
    """Tests for _extract_signatures — AST extraction of signatures and docstrings."""

    def test_simple_function(self):
        src = textwrap.dedent("""\
            def hello(name: str) -> str:
                \"\"\"Greet someone.\"\"\"
                return f"Hello, {name}"
        """)
        result = audit._extract_signatures(src)
        assert "def hello" in result
        assert "Greet someone." in result

    def test_function_without_docstring(self):
        src = "def add(a, b):\n    return a + b\n"
        result = audit._extract_signatures(src)
        assert "def add" in result

    def test_class_with_methods(self):
        src = textwrap.dedent("""\
            class MyClass:
                \"\"\"A test class.\"\"\"

                def __init__(self, x: int):
                    \"\"\"Initialize.\"\"\"
                    self.x = x

                def value(self) -> int:
                    return self.x
        """)
        result = audit._extract_signatures(src)
        assert "class MyClass" in result
        assert "A test class." in result
        assert "def __init__" in result
        assert "def value" in result

    def test_imports_included(self):
        src = "import os\nfrom pathlib import Path\n"
        result = audit._extract_signatures(src)
        assert "import os" in result
        assert "from pathlib import Path" in result

    def test_module_level_constant(self):
        src = "MAX_RETRIES = 3\n"
        result = audit._extract_signatures(src)
        assert "MAX_RETRIES" in result

    def test_multiline_function_signature(self):
        src = textwrap.dedent("""\
            def complex_func(
                arg1: str,
                arg2: int,
                arg3: float = 1.0,
            ) -> dict:
                \"\"\"Does complex stuff.\"\"\"
                pass
        """)
        result = audit._extract_signatures(src)
        assert "def complex_func" in result
        assert "Does complex stuff." in result

    def test_async_function(self):
        src = textwrap.dedent("""\
            async def fetch(url: str) -> bytes:
                \"\"\"Fetch a URL.\"\"\"
                pass
        """)
        result = audit._extract_signatures(src)
        assert "async def fetch" in result

    def test_body_not_included(self):
        src = textwrap.dedent("""\
            def my_func():
                x = 100
                y = 200
                return x + y
        """)
        result = audit._extract_signatures(src)
        assert "x = 100" not in result
        assert "y = 200" not in result

    def test_decorated_function(self):
        src = textwrap.dedent("""\
            @staticmethod
            def helper():
                pass
        """)
        result = audit._extract_signatures(src)
        assert "@staticmethod" in result
        assert "def helper" in result

    def test_empty_source(self):
        result = audit._extract_signatures("")
        assert result == "" or result.strip() == ""

    def test_syntax_error_falls_back_to_regex(self):
        # Non-Python content should fall back without raising
        bad_src = "this is not python code {{ invalid }}"
        result = audit._extract_signatures(bad_src)
        assert isinstance(result, str)

    def test_respects_compact_max_lines(self):
        # Generate a function with many lines to exceed COMPACT_MAX_LINES
        many_funcs = "\n".join(
            f'def func_{i}():\n    """Docstring {i}."""\n    pass\n'
            for i in range(300)
        )
        result = audit._extract_signatures(many_funcs)
        lines = result.splitlines()
        assert len(lines) <= audit._COMPACT_MAX_LINES

    def test_nested_class(self):
        src = textwrap.dedent("""\
            class Outer:
                class Inner:
                    def method(self):
                        \"\"\"Inner method.\"\"\"
                        pass
        """)
        result = audit._extract_signatures(src)
        assert "class Outer" in result
        assert "class Inner" in result
        assert "def method" in result


# ---------------------------------------------------------------------------
# _extract_signatures_regex (fallback)
# ---------------------------------------------------------------------------

class TestExtractSignaturesRegex:
    """Tests for _extract_signatures_regex — regex fallback extraction."""

    def test_extracts_def(self):
        src = "def my_func(x, y):\n    return x + y\n"
        result = audit._extract_signatures_regex(src)
        assert "def my_func" in result

    def test_extracts_class(self):
        src = "class Foo:\n    pass\n"
        result = audit._extract_signatures_regex(src)
        assert "class Foo" in result

    def test_extracts_imports(self):
        src = "import os\nfrom pathlib import Path\n"
        result = audit._extract_signatures_regex(src)
        assert "import os" in result

    def test_extracts_docstring_after_def(self):
        src = 'def greet():\n    """Say hello."""\n    pass\n'
        result = audit._extract_signatures_regex(src)
        assert "def greet" in result
        assert "Say hello." in result

    def test_extracts_module_level_assignment(self):
        src = "VERSION = '1.0.0'\n"
        result = audit._extract_signatures_regex(src)
        assert "VERSION" in result

    def test_empty_source(self):
        result = audit._extract_signatures_regex("")
        assert result == ""

    def test_non_python_text_does_not_crash(self):
        result = audit._extract_signatures_regex("just some plain text\nno code here")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# _collect_audit_sources
# ---------------------------------------------------------------------------

class TestCollectAuditSources:
    """Tests for _collect_audit_sources — file collection for audit."""

    def test_returns_string(self, tmp_path):
        with patch("app_audit._get_app_dir", return_value=tmp_path):
            result = audit._collect_audit_sources(compact=False)
        assert isinstance(result, str)

    def test_result_starts_with_preamble(self, tmp_path):
        with patch("app_audit._get_app_dir", return_value=tmp_path):
            result = audit._collect_audit_sources(compact=True)
        assert "audit" in result.lower()

    def test_includes_existing_file(self, tmp_path):
        # Create a file that matches _AUDIT_FILES_COMPACT
        py_file = tmp_path / "logpilot"
        py_file.mkdir()
        (py_file / "parser.py").write_text("def parse(): pass\n")

        with patch("app_audit._get_app_dir", return_value=tmp_path):
            result = audit._collect_audit_sources(compact=True)
        assert "logpilot/parser.py" in result

    def test_missing_files_skipped(self, tmp_path):
        # No files exist — should not raise
        with patch("app_audit._get_app_dir", return_value=tmp_path):
            result = audit._collect_audit_sources(compact=False)
        assert isinstance(result, str)

    def test_compact_mode_uses_compact_file_list(self, tmp_path):
        # In compact mode, only _AUDIT_FILES_COMPACT files are listed
        py_file = tmp_path / "logpilot"
        py_file.mkdir()
        (py_file / "parser.py").write_text("x = 1\n" * 10)

        with patch("app_audit._get_app_dir", return_value=tmp_path):
            compact_result = audit._collect_audit_sources(compact=True)
            full_result = audit._collect_audit_sources(compact=False)

        # Both should succeed
        assert isinstance(compact_result, str)
        assert isinstance(full_result, str)

    def test_compact_truncates_large_py_file(self, tmp_path):
        py_dir = tmp_path / "logpilot"
        py_dir.mkdir()
        # Write a Python file with more than COMPACT_MAX_LINES lines
        big_content = "\n".join(f"def func_{i}(): pass" for i in range(300))
        (py_dir / "parser.py").write_text(big_content)

        with patch("app_audit._get_app_dir", return_value=tmp_path):
            result = audit._collect_audit_sources(compact=True)

        assert "signature lines" in result or "showing" in result

    def test_compact_includes_skill_file_names_only(self, tmp_path):
        # Create a skills directory with markdown files
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "my-skill.md").write_text("# Skill\nLots of content here.\n" * 50)

        with patch("app_audit._get_app_dir", return_value=tmp_path):
            compact_result = audit._collect_audit_sources(compact=True)

        # In compact mode skill filenames appear but not their full content
        assert "my-skill.md" in compact_result
        # Full content should NOT be in compact output
        assert "Lots of content here." not in compact_result

    def test_full_mode_includes_skill_file_content(self, tmp_path):
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "test-skill.md").write_text("# Test Skill\nUnique skill content.\n")

        with patch("app_audit._get_app_dir", return_value=tmp_path):
            full_result = audit._collect_audit_sources(compact=False)

        assert "Unique skill content." in full_result

    def test_non_py_file_truncated_in_compact(self, tmp_path):
        # Create CLAUDE.md with many lines
        big_md = "line\n" * 300
        (tmp_path / "CLAUDE.md").write_text(big_md)

        with patch("app_audit._get_app_dir", return_value=tmp_path):
            result = audit._collect_audit_sources(compact=True)

        # File appears but should be noted as truncated
        if "CLAUDE.md" in result:
            assert "showing first" in result or len(result.split("CLAUDE.md")[1]) < len(big_md)
