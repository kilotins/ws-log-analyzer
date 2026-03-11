# Rebranding Guide: Renaming a Python Project

## Checklist for wslog → logpilot

### 1. Package directory

```bash
# Rename the package
mv wslog/ logpilot/
```

Update `logpilot/__init__.py`:
- Add `__version__ = "1.0.0"`
- Update all internal imports (`from .parser import ...` stays the same)
- Update re-exports if needed

### 2. pyproject.toml

```toml
[project]
name = "logpilot"

[tool.setuptools]
packages = ["logpilot", "logpilot.formats"]

[project.scripts]
logpilot = "logpilot.cli:main"
```

### 3. App layer imports

All `app*.py` files that import from wslog:

```python
# Before
from wslog import parse_file, summarize, build_claude_prompt
from wslog.parser import redact

# After
from logpilot import parse_file, summarize, build_claude_prompt
from logpilot.parser import redact
```

Files to update:
- `app.py`
- `app_ai.py`
- `app_render.py`
- `app_audit.py`
- `app_spend.py`
- `app_realtime.py`

### 4. Test imports

```python
# Before
from wslog.parser import parse_file, redact
import wslog

# After
from logpilot.parser import parse_file, redact
import logpilot
```

Also update mock paths:
```python
# Before
@patch("wslog.parser.open_text", ...)

# After
@patch("logpilot.parser.open_text", ...)
```

Files to update:
- All `tests/test_*.py` files
- Consider renaming `test_wslog.py` → `test_logpilot.py`

### 5. CLI references

```python
# Before
python -m wslog
sys.executable, "-m", "wslog"

# After
python -m logpilot
sys.executable, "-m", "logpilot"
```

In tests that spawn subprocesses.

### 6. UI text and titles

Search and replace in app*.py:
- `"WebSphere/Java Log"` → `"LogPilot"`
- `"WS Log Analyzer"` → `"LogPilot"`
- Page title in `st.set_page_config(page_title=...)`
- Report headers in `reports.py`

Keep WAS-specific text in:
- WAS format parser (it's a log format, not the product name)
- WAS-specific heuristics
- Skills that describe WAS patterns

### 7. Documentation

| File | What to update |
|------|----------------|
| `README.md` | Title, install commands, CLI examples |
| `CLAUDE.md` | Project name, package references, structure |
| `ARCHITECTURE.md` | Package name, module paths |
| `docs/API.md` | Import examples, package name |
| `MILESTONES.md` | References to wslog.py |

### 8. CI and config

- `.github/workflows/ci.yml` — mypy target: `mypy logpilot/`
- `.claude/skills/*.md` — references to `wslog/` and `wslog.py`
- `heuristics.yaml` — no changes needed (format-agnostic)

### 9. Git and GitHub

- Rename GitHub repo: Settings → General → Repository name
- Update `pyproject.toml` URLs
- Old `wslog` package import path stops working — this is intentional

### 10. Validation

After renaming, verify:

```bash
# Package imports
python -c "from logpilot import parse_file; print('OK')"
python -c "from logpilot.parser import redact; print('OK')"

# CLI
python -m logpilot --help

# Tests
pytest tests/ --ignore=tests/test_app_e2e.py -m "not slow" -q

# mypy
mypy logpilot/ --ignore-missing-imports

# Grep for stale references
grep -r "wslog" --include="*.py" --include="*.md" --include="*.yml" --include="*.toml" . \
    | grep -v ".git/" | grep -v ".venv/" | grep -v "__pycache__"
```

The final grep should only show:
- Historical references in MILESTONES.md (old milestone names)
- `ws_log_analyzer.egg-info/` (delete this)
- Git history (unavoidable)

## Gotchas

- **egg-info**: Delete `ws_log_analyzer.egg-info/` after rename, then `pip install -e .`
- **Import caching**: Python caches imports. Restart interpreter/test runner after rename
- **__pycache__**: Delete all `__pycache__/` dirs to avoid stale `.pyc` files: `find . -type d -name __pycache__ -exec rm -rf {} +`
- **Streamlit cache**: Clear `.streamlit/cache/` if Streamlit complains about missing modules
- **IDE**: Re-index project in VS Code/PyCharm after rename
- **Do NOT add backwards-compat shims**: No `wslog/` directory that re-imports from `logpilot/`. Clean break.
