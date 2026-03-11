# Python Packaging & Distribution

## Project Layout

```
logpilot/
    __init__.py          # Version, re-exports
    __main__.py          # python -m logpilot
    parser.py
    analysis.py
    reports.py
    ai.py
    cli.py
    formats/
        __init__.py
        base.py
        was.py
        ...
app.py                   # Streamlit GUI (not in package)
app_*.py                 # Streamlit helpers (not in package)
pyproject.toml           # Single source of truth for metadata
```

## pyproject.toml Structure

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "logpilot"
version = "1.0.0"
description = "Multi-format log analyzer with AI-powered root cause analysis"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.9"
authors = [
    {name = "Your Name", email = "you@example.com"},
]
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Environment :: Web Environment",
    "Intended Audience :: System Administrators",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: System :: Logging",
    "Topic :: System :: Systems Administration",
]
dependencies = []  # Core has zero deps

[project.optional-dependencies]
claude = ["anthropic>=0.40"]
gemini = ["google-generativeai>=0.5"]
openai = ["openai>=1.0"]
gui = ["streamlit>=1.30", "plotly>=5.0"]
pdf = ["fpdf2>=2.7"]
all-ai = ["anthropic>=0.40", "google-generativeai>=0.5", "openai>=1.0"]
all = ["logpilot[gui,all-ai,pdf]"]
test = ["pytest>=7"]
e2e = ["pytest>=7", "playwright>=1.40"]
dev = ["pytest>=7", "ruff", "mypy", "build", "twine"]

[project.scripts]
logpilot = "logpilot.cli:main"

[project.urls]
Homepage = "https://github.com/kilotins/logpilot"
Repository = "https://github.com/kilotins/logpilot"
Issues = "https://github.com/kilotins/logpilot/issues"

[tool.setuptools]
packages = ["logpilot", "logpilot.formats"]
py-modules = ["app", "app_ai", "app_render", "app_audit", "app_spend", "app_realtime", "app_constants"]
```

## Version Management

Single source of version in `logpilot/__init__.py`:

```python
__version__ = "1.0.0"
```

Access programmatically:
```python
from logpilot import __version__
```

Or from CLI: `logpilot --version`

## requirements.txt Files

For users who prefer `pip install -r`:

**requirements.txt** (core CLI only):
```
# Core has no dependencies — install the package directly
-e .
```

**requirements-gui.txt** (Streamlit app):
```
-e ".[gui,all-ai,pdf]"
```

**requirements-dev.txt** (development):
```
-e ".[gui,all-ai,pdf,test,e2e,dev]"
```

## Building

```bash
# Install build tools
pip install build twine

# Build sdist + wheel
python -m build

# Validate
twine check dist/*

# Test install in clean venv
python -m venv /tmp/test-install
/tmp/test-install/bin/pip install dist/logpilot-*.whl
/tmp/test-install/bin/logpilot --help
```

## Publishing

### TestPyPI (test first)

```bash
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ logpilot
```

### PyPI (production)

```bash
twine upload dist/*
```

### GitHub Actions (automated)

```yaml
# .github/workflows/publish.yml
name: Publish to PyPI

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Trusted publisher (no API token needed)
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Build
        run: |
          pip install build
          python -m build

      - name: Validate
        run: |
          pip install twine
          twine check dist/*

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

Use PyPI Trusted Publishers (OIDC) — no API tokens to manage.

## Entry Points

### CLI

Defined in `pyproject.toml`:
```toml
[project.scripts]
logpilot = "logpilot.cli:main"
```

After `pip install`, the `logpilot` command is available globally.

### python -m logpilot

Via `logpilot/__main__.py`:
```python
from .cli import main
main()
```

### Streamlit app

Not packaged as an entry point. Run directly:
```bash
streamlit run app.py
```

Or add a convenience entry point:
```toml
[project.scripts]
logpilot = "logpilot.cli:main"
logpilot-gui = "logpilot.gui:main"  # optional
```

## MANIFEST.in

For including non-Python files in sdist:

```
include heuristics.yaml
include LICENSE
include README.md
recursive-include skills *.md *.yaml
recursive-include assets *
```

Or in pyproject.toml:
```toml
[tool.setuptools.package-data]
logpilot = ["../heuristics.yaml", "../skills/*.md", "../skills/*.yaml"]
```

## Gotchas

- **Zero deps for core**: The `dependencies = []` is intentional. Users who only need CLI parsing shouldn't install Streamlit
- **Optional extras**: Use `pip install logpilot[gui]` for Streamlit, `logpilot[claude]` for AI
- **py-modules**: `app.py` and `app_*.py` are listed in `py-modules` for the GUI but are NOT part of the `logpilot` package
- **Data files**: `heuristics.yaml`, `skills/`, and `assets/` must be explicitly included via `package-data` or `MANIFEST.in`
- **Version bumping**: Update only `logpilot/__init__.py` — don't scatter version strings
- **Python 3.9 compat**: Don't use `X | Y` union syntax in runtime code (only in `from __future__ import annotations` context). Use `Optional[X]` or `Union[X, Y]` for runtime type checks
- **Editable installs**: `pip install -e .` is needed during development so imports resolve correctly
