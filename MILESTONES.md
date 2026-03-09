# Milestones — WS Log Analyzer

> Generated from [AUDIT_REPORT.html](AUDIT_REPORT.html) — 2026-03-09
> Overall grade: **A-** — target: **A**

---

## Milestone 1 — Buggfixar & hygien
**Priority: P0 (immediate)**
**Estimated scope: Small — 5 targeted edits**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 1.1 | Fix OpenAI model routing — pass model ID from `_AI_MODELS` dropdown through to `run_openai_analysis()` so GPT-4o mini actually uses `gpt-4o-mini` | `app.py` | [x] |
| 1.2 | Fix Claude model routing — pass model ID so Haiku/Sonnet/Opus selection is honored (currently hardcodes `claude-sonnet-4-6`) | `app.py` | [x] |
| 1.3 | Fix Gemini model routing — pass model ID so Flash/Pro selection is honored (currently uses default `gemini-2.5-flash`) | `app.py` | [x] |
| 1.4 | Fix "Clear AI cache" button — add missing OpenAI cache/history/answer clearing | `app.py` L1252-1266 | [x] |
| 1.5 | Update stale counts in docs — test count (295), line counts (1641/1849) | `ARCHITECTURE.md`, `README.md` | [x] |

**Acceptance**: All 7 AI models in the dropdown route to their correct model ID. Cache clearing covers all 3 providers. Docs match reality. All 295 tests pass.

---

## Milestone 2 — DRY AI-funktioner
**Priority: P1 (short-term)**
**Estimated scope: Medium — refactor + tests**
**Depends on: Milestone 1**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 2.1 | Extract `_run_ai_analysis(provider, model_id, user_query, events, container)` — common orchestration for cache lookup, API call, history recording, cache storage | `app.py` | [x] |
| 2.2 | Reduce `run_claude_analysis` / `run_gemini_analysis` / `run_openai_analysis` to thin wrappers calling the common function with provider-specific API logic | `app.py` | [x] |
| 2.3 | Consolidate history helpers — single `_load_provider_history(path)` / `_save_provider_history(path, data)` replacing 6 duplicate functions | `app.py` | [x] |
| 2.4 | Extend `_AI_MODELS` dict to include `model_id` per entry (not just provider string) | `app.py` | [x] |
| 2.5 | Add unit tests for the new common orchestration function | `tests/test_app_helpers.py` | [x] |

**Acceptance**: Net reduction of ~120 lines. Same behavior. All tests pass. Adding a new AI provider in the future requires only ~15 lines.

---

## Milestone 3 — Streaming & UX
**Priority: P2 (mid-term)**
**Depends on: Milestone 2**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 3.1 | Streaming Claude responses — use `client.messages.stream()` and render tokens incrementally | `app.py` | [x] |
| 3.2 | Streaming OpenAI responses — use `stream=True` in `chat.completions.create()` | `app.py` | [x] |
| 3.3 | Cost tracking — log input/output tokens and estimated cost per API call in the UI | `app.py` | [x] |
| 3.4 | Smarter compact mode for audit — send function signatures + docstrings only (not full source) for large files | `app.py` | [x] |
| 3.5 | Audit comparison in GUI — surface `compare_audits.py` delta reports in the Audit tab | `app.py`, `scripts/` | [x] |

**Acceptance**: AI responses stream visibly. Token count + cost shown after each call. Audit tab shows delta between runs.

---

## Milestone 4 — Kvalitet & polish
**Priority: P3 (long-term)**
**Depends on: Milestone 3**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 4.1 | Split `app.py` into modules (`ai_providers.py`, `sidebar.py`, `renderers.py`) if it exceeds 2,000 lines | `app.py` → multiple | [ ] |
| 4.2 | Add false-positive tests for redaction (ensure normal log text isn't over-redacted) | `tests/test_wslog.py` | [ ] |
| 4.3 | Add mock-based tests for `run_*_analysis()` functions | `tests/test_app_helpers.py` | [ ] |
| 4.4 | Multi-file audit — allow selecting which files to include in audit scope | `app.py` | [ ] |
| 4.5 | CSV/XML export options for analysis results | `wslog.py`, `app.py` | [ ] |

**Acceptance**: Clean module boundaries. >300 tests. No known bugs. Audit grade **A**.

---

## Progress Tracker

| Milestone | Tasks | Done | Status |
|-----------|-------|------|--------|
| 1 — Buggfixar & hygien | 5 | 5 | Done |
| 2 — DRY AI-funktioner | 5 | 5 | Done |
| 3 — Streaming & UX | 5 | 5 | Done |
| 4 — Kvalitet & polish | 5 | 0 | Not started |
