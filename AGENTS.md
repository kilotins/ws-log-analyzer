# AGENTS.md — Shared Agent Instructions

Read by all AI coding agents (Claude Code, Codex, Gemini CLI).
For agent-specific config see CLAUDE.md, GEMINI.md.
For project details see ARCHITECTURE.md and README.md.

## Ground Rules

1. **Core is Streamlit-free.** `logpilot/` has zero Streamlit imports. Keep it that way.
2. **No required deps.** Core runs on stdlib only. AI SDKs, Streamlit, fpdf2 are optional.
3. **Secret redaction.** Use `sanitize_error()` from `logpilot.ai` for error messages.
4. **Preserve behavior.** Don't change logic unless clearly buggy. All existing tests must pass.
5. **No architecture changes.** V1 codebase maintained until 2.0 platform launches.
6. **No opportunistic refactors.** Fix what you're asked to fix, nothing more.

## Do NOT Refactor

These Streamlit files are replaced in 2.0. Fix bugs only:
`app.py`, `app_ai.py`, `app_render.py`, `app_incident.py`, `app_audit.py`,
`app_spend.py`, `app_realtime.py`, `app_jira.py`, `app_constants.py`

## Environment

- **Python:** 3.9+ (`.venv/` — always activate before running tests)
- **Run tests:** `source .venv/bin/activate && python -m pytest tests/ --ignore=tests/test_app_e2e.py --ignore=tests/test_scenario_e2e.py --ignore=tests/test_e2e_full.py -q`
- **Current version:** 1.2.0 (update in `pyproject.toml`, `logpilot/__init__.py`, `app.py`)
- **Test count:** ~1850 unit tests + 25 Playwright e2e
- **Docker:** `docker build -t kilotin/logpilot:latest .`

## Multi-Agent Workflow

Each agent works in its own clone or worktree to avoid conflicts:

```
ws-log-analyzer/          <- main (review only)
ws-log-analyzer-claude/   <- Claude worktree/clone
ws-log-analyzer-codex/    <- Codex clone
ws-log-analyzer-gemini/   <- Gemini worktree/clone
```

### Roles

- **In main:** You are a **reviewer**. Never write code without explicit instruction.
- **In your own clone/worktree:** You are an **implementer**. Sync with main before starting.

### Implementer Checklist

1. Sync: `git pull origin main` or `git merge main`
2. Do the task — analyze, code, test
3. All tests must pass before committing
4. Push and open PR when requested — never merge yourself
5. Stay on task — no side-refactors

## Commits

- Messages in **English**
- Co-author trailer:
  - `Co-Authored-By: Claude <noreply@anthropic.com>`
  - `Co-Authored-By: Codex <noreply@openai.com>`
  - `Co-Authored-By: Gemini <noreply@google.com>`
- Use `git add <specific files>` — never `git add .` or `git add -A`
- **Never commit:** `.env`, `cache/`, `uploads/`, `reports/`, `logs/`, `*.log`, `.DS_Store`, `__pycache__/`, `dist/`, `*.egg-info/`, generated HTML reports

## Reports

When generating a review, audit, or analysis report:
1. Save as `.md` in project root
2. Render: `python3 report_renderer.py <file>.md --open`
3. Notify user that HTML is ready

## Milestones

All agents share milestone numbering. Check before starting work.

**Next available: M72**

| Milestone | Agent | Status | Description |
|-----------|-------|--------|-------------|
| M71 | — | Planned | Tiered AI Access (trial=Haiku, pro=all providers) |
| M70 | Codex | Merged | Zip Upload for Docker/Remote |
| M69 | Claude | Merged | Trial License System |
| M68c | Gemini | Merged | Scenario: cross-system correlation |
| M68b | Codex | Merged | Scenario: edge cases, malformed lines |
| M68a | Claude | Merged | Scenario: Healthcare TLS cert cascade |
| M67 | Claude | Merged | Safety valve, LogEvent fixes, CRITICAL consistency |

Note: Agent worktrees auto-sync on every push from main.
