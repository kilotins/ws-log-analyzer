# LogPilot — Shared Agent Instructions

This file is read by all AI coding agents (Claude Code, Codex, Gemini CLI).
For agent-specific config see: CLAUDE.md, GEMINI.md.

## Project

LogPilot is a multi-format log analyzer (Python 3.9+, stdlib-only core). Parses logs, detects incidents with 68 heuristics, generates triage reports, and provides AI-powered root cause analysis.

- **Core package:** `logpilot/` — parser, analysis, heuristics, event, formats/, reports/, ai, cli
- **GUI:** `app.py` + `app_*.py` (Streamlit) — will be replaced by React + FastAPI in 2.0
- **Tests:** `tests/` — 1922+ unit tests (pytest), Playwright e2e
- **Skills:** `skills/` — domain knowledge YAML/MD used in AI prompts
- **Distribution:** Docker Hub (`kilotin/logpilot`), TestPyPI (`logpilot`)

## Rules

1. **Core is Streamlit-free.** `logpilot/` has zero Streamlit imports. Keep it that way.
2. **No required deps.** Core runs on stdlib only. AI SDKs, Streamlit, fpdf2 are optional.
3. **Secret redaction.** All event text is redacted before output. Use `sanitize_error()` from `logpilot.ai` for error messages.
4. **Preserve behavior.** Don't change logic unless clearly buggy. All existing tests must pass.
5. **No architecture changes.** This is a V1 codebase being maintained until 2.0 platform launches.

## Key Files

| File | Purpose |
|------|---------|
| `logpilot/parser.py` | Event parsing, redaction, format auto-detection |
| `logpilot/analysis.py` | Summarize, timeline, cascades, incident grouping |
| `logpilot/heuristics.py` | 68 heuristics, 19 correlations, 7 incident groups |
| `logpilot/ai.py` | AI prompts, token estimation, `sanitize_error()` |
| `logpilot/formats/` | 14 format plugins (WAS, JSON, nginx, Log4j, etc.) |
| `logpilot/reports/` | 7 renderers (markdown, html, json, pdf, etc.) |
| `app.py` | Streamlit GUI entry point |
| `app_ai.py` | AI provider orchestration (Streamlit-coupled) |
| `app_incident.py` | Incident AI assistant with multimodal support |
| `report_renderer.py` | Markdown to branded HTML converter |

## Tools

- **Render MD as HTML:** `python3 report_renderer.py <file>.md --open`
- **Run tests:** `python3 -m pytest tests/ --ignore=tests/test_app_e2e.py --ignore=tests/test_scenario_e2e.py --ignore=tests/test_e2e_full.py -q`
- **Build Docker:** `docker build -t kilotin/logpilot:latest .`
- **Build PyPI:** `pipx run build . && pipx run twine upload --repository testpypi dist/*`

## Environment

- **Python venv:** `.venv/` uses Python 3.9. System python is 3.14. Always use `.venv` for tests.
- **Run tests in venv:** `source .venv/bin/activate && python -m pytest ...`
- **Docker Desktop** must be running for Docker builds/pushes.

## Release Process

Version is defined in 3 files — all must be updated together:
1. `pyproject.toml` → `version = "x.y.z"`
2. `logpilot/__init__.py` → `__version__ = "x.y.z"`
3. `app.py` → `base = "x.y.z"`

After version bump, publish to all channels:
1. **GitHub:** `git push`
2. **Docker Hub:** `docker build -t kilotin/logpilot:latest -t kilotin/logpilot:x.y.z . && docker push kilotin/logpilot:latest && docker push kilotin/logpilot:x.y.z`
3. **TestPyPI:** `pipx run build . && pipx run twine upload --repository testpypi dist/logpilot-x.y.z*`

## Do NOT Refactor

These files are replaced in 2.0 (React + FastAPI). Fix bugs only, don't refactor:
- `app.py`, `app_ai.py`, `app_render.py`, `app_incident.py`, `app_audit.py`
- `app_spend.py`, `app_realtime.py`, `app_jira.py`, `app_constants.py`

## Agent Roles

Your role depends on which worktree you are in:

- **In `main` worktree:** You are a **reviewer**, not a code writer.
- **In a separate worktree:** You are an **implementer** on your own branch.

**Always start by stating:**
1. Which directory you are in (`pwd`)
2. Which branch you are on (`git branch --show-current`)
3. Whether you are acting as reviewer or implementer

**Reviewer rules (main):**
- Never write code in main without explicit instruction.
- Focus on: bugs, regression risks, edge cases, missing tests, unclear logic.
- Read diffs and relevant files. List findings first.

**Implementer rules (worktree branch):**
- Work only in your worktree. Don't assume other worktrees have the same state.
- Do the full task: analyze, change code, run tests, summarize results.
- Stay on task — no opportunistic side-refactors.
- All existing tests must pass before committing.

## Worktrees (Parallel Agent Work)

Each AI agent works in its own git worktree to avoid conflicts:

```
ws-log-analyzer/          ← main branch (review)
ws-log-analyzer-claude/   ← claude-work branch (Claude)
ws-log-analyzer-codex/    ← codex-work branch (Codex)
ws-log-analyzer-gemini/   ← gemini-work branch (Gemini)
```

**If you are running in a worktree:**
- You are on your own branch. Commit freely.
- Run tests before committing: all 1922+ tests must pass.
- Do NOT merge to main — the user will merge your branch when ready.
- Do NOT push to origin unless the user asks.

**Workflow:**
1. Agent works on its branch in its worktree
2. User reviews changes
3. User merges to main: `git merge claude-work` / `git merge codex-work` / `git merge gemini-work`
4. User cleans up: `git worktree remove ../ws-log-analyzer-claude`

**Create worktrees** (run from main repo):
```bash
git worktree add ../ws-log-analyzer-claude -b claude-work
git worktree add ../ws-log-analyzer-codex -b codex-work
git worktree add ../ws-log-analyzer-gemini -b gemini-work
```

## Commits

- Commit messages in **English**
- End with the appropriate co-author trailer:
  - Claude: `Co-Authored-By: Claude <noreply@anthropic.com>`
  - Codex: `Co-Authored-By: Codex <noreply@openai.com>`
  - Gemini: `Co-Authored-By: Gemini <noreply@google.com>`
- Don't commit `.env`, `cache/`, `*.log`, `.DS_Store`

## Reporting

All AI agents (Claude, Codex, Gemini) must follow these steps when generating a report, review, or audit:
1. **Save as Markdown:** Save the output as a `.md` file in the project root.
2. **Render as Branded HTML:** Convert it using: `python3 report_renderer.py <filename>.md --open`.
3. **Notify User:** Inform the user that the HTML version is ready for viewing.

This ensures a consistent, branded experience across all system analysis outputs.
