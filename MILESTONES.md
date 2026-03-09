# Milestones — WS Log Analyzer (v2)

> Generated from [AUDIT_REPORT.html](AUDIT_REPORT.html) — 2026-03-09
> Overall grade: **A** — target: **A+**
>
> Previous milestones (v1) are all completed. This is the next iteration.

---

## Milestone 5 — Säkerhetsförstärkning & stabilitet
**Priority: P0 (immediate)**
**Estimated scope: Small — targeted fixes**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 5.1 | Add symlink check to `_is_safe_rt_path()` — resolve path with `p.resolve()` and reject symlinks to prevent path traversal | `app.py` | [ ] |
| 5.2 | Narrow bare `except Exception` blocks — replace with specific exceptions (`ValueError`, `OSError`, `ImportError`, `json.JSONDecodeError`) | `wslog.py` | [ ] |
| 5.3 | Tighten realtime monitor extensions — remove `.out` from allowed extensions or add explicit symlink/ownership check | `app.py` | [ ] |
| 5.4 | Add API key format validation — check that Claude keys start with `sk-ant-`, OpenAI with `sk-`, before making API calls | `app.py` | [ ] |
| 5.5 | Add tests for symlink rejection and narrowed exception handling | `tests/test_app_helpers.py`, `tests/test_wslog.py` | [ ] |

**Acceptance**: No bare `except Exception` in `wslog.py`. Symlinks rejected by path safety. API key format validated on entry. All tests pass.

---

## Milestone 6 — E2e-teststabilitet
**Priority: P1 (short-term)**
**Estimated scope: Medium — fix 6 flaky tests**
**Depends on: Milestone 5**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 6.1 | Fix `TestAskClaude` flakiness — update "Ask Claude" to "Ask AI for help", add `wait_for_selector` | `tests/test_app_e2e.py` | [x] |
| 6.2 | Fix `test_analyze_button_disabled_without_input` — update button selector to match "Analyze" | `tests/test_app_e2e.py` | [x] |
| 6.3 | Fix `test_code_button_populates_input` — add `wait_for` before scroll and click | `tests/test_app_e2e.py` | [x] |
| 6.4 | Fix `TestSwedishChefMode` (3 tests) — rewrite to use model dropdown instead of non-existent toggle | `tests/test_app_e2e.py` | [x] |
| 6.5 | Add CI-friendly timeout configuration — increase default Playwright timeout from 30s to 60s | `tests/test_app_e2e.py` | [x] |

**Acceptance**: All 18 e2e tests pass reliably on 3 consecutive runs. No timeout-based flakiness.

---

## Milestone 7 — Kodstruktur & refaktorering
**Priority: P2 (mid-term)**
**Estimated scope: Medium — refactor long functions**
**Depends on: Milestone 6**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 7.1 | Split `_rt_live_view()` into `_rt_status_panel()`, `_rt_controls()`, `_rt_render_buffer()` | `app.py` | [x] |
| 7.2 | Replace 6 thin history wrappers with `_PROVIDER_HISTORY_FILES` dict | `app.py` | [x] |
| 7.3 | Split `app.py` into modules if it exceeds 2,000 lines | `app.py` → multiple | [x] Deferred — 1,989 lines |
| 7.4 | Add type hints to 12 key `app.py` functions | `app.py` | [x] |
| 7.5 | Update tests to match new module structure (imports, mocks) | `tests/test_app_helpers.py` | [x] No changes needed |

**Acceptance**: No function over 150 lines. `app.py` under 1,500 lines (if split). Key functions typed. All 340+ tests pass.

---

## Milestone 8 — Funktioner & förbättringar
**Priority: P3 (long-term)**
**Estimated scope: Medium — new features**
**Depends on: Milestone 7**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 8.1 | Multi-file audit scope — add checkboxes in Audit tab to select which files to include (default: all Python files) | `app.py` | [ ] |
| 8.2 | API rate limiting — add simple cooldown (e.g., 2s between calls) to prevent budget exhaustion from rapid clicking | `app.py` | [ ] |
| 8.3 | XML export option — add `render_xml_report()` alongside existing CSV/JSON/Markdown/PDF | `wslog.py`, `app.py` | [ ] |
| 8.4 | Gemini streaming — investigate `generate_content(stream=True)` for incremental rendering when SDK supports it | `app.py` | [ ] |
| 8.5 | Integration test for `_run_audit()` — mock-based end-to-end audit pipeline test | `tests/test_app_helpers.py` | [ ] |

**Acceptance**: Audit scope selectable. Rate limiting prevents rapid-fire API calls. XML export available. >360 tests. Audit grade **A+**.

---

## Progress Tracker

| Milestone | Tasks | Done | Status |
|-----------|-------|------|--------|
| 1 — Buggfixar & hygien | 5 | 5 | Done |
| 2 — DRY AI-funktioner | 5 | 5 | Done |
| 3 — Streaming & UX | 5 | 5 | Done |
| 4 — Kvalitet & polish | 5 | 5 | Done |
| 5 — Säkerhetsförstärkning | 5 | 0 | Not started |
| 6 — E2e-teststabilitet | 5 | 5 | Done |
| 7 — Kodstruktur & refaktorering | 5 | 5 | Done |
| 8 — Funktioner & förbättringar | 5 | 0 | Not started |
