# Milestones — WS Log Analyzer (v3)

> Generated from [AUDIT_REPORT.html](AUDIT_REPORT.html) — 2026-03-09
> Overall grade: **A-** — target: **A+**
>
> v1 milestones (1–4) and v2 milestones (5–8) are all completed. This is v3.

---

## Milestone 5 — Säkerhetsförstärkning & stabilitet
**Priority: P0 (immediate)**
**Estimated scope: Small — targeted fixes**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 5.1 | Add symlink check to `_is_safe_rt_path()` — resolve path with `p.resolve()` and reject symlinks to prevent path traversal | `app.py` | [x] |
| 5.2 | Narrow bare `except Exception` blocks — replace with specific exceptions (`ValueError`, `OSError`, `ImportError`, `json.JSONDecodeError`) | `wslog.py` | [x] |
| 5.3 | Tighten realtime monitor extensions — remove `.out` from allowed extensions or add explicit symlink/ownership check | `app.py` | [x] |
| 5.4 | Add API key format validation — check that Claude keys start with `sk-ant-`, OpenAI with `sk-`, before making API calls | `app.py` | [x] |
| 5.5 | Add tests for symlink rejection and narrowed exception handling | `tests/test_app_helpers.py`, `tests/test_wslog.py` | [x] |

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
| 8.1 | Persistent API keys — file-based fallback for keyring, keys survive app restarts | `app.py` | [x] |
| 8.2 | API rate limiting — 2s cooldown between AI calls to prevent budget exhaustion | `app.py` | [x] |
| 8.3 | XML export option — `render_xml_report()` + download button alongside CSV/JSON/PDF | `wslog.py`, `app.py` | [x] |
| 8.4 | Audit source collection test — integration tests for `_collect_audit_sources()` | `tests/test_app_helpers.py` | [x] |
| 8.5 | Additional tests — XML export, rate limit config, provider history files, keychain fallback | `tests/` | [x] |

**Acceptance**: Audit scope selectable. Rate limiting prevents rapid-fire API calls. XML export available. >360 tests. Audit grade **A+**.

---

---

## Milestone 9 — Dokumentation & snabbfixar
**Priority: P0 (immediate)**
**Estimated scope: Small — targeted fixes**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 9.1 | Fix ARCHITECTURE.md: remove false SHA-256 claim for cache keys — actual uses pipe-delimited string | `ARCHITECTURE.md` | [ ] |
| 9.2 | Fix ARCHITECTURE.md: update line counts, test counts, add OpenAI state keys to State Management section | `ARCHITECTURE.md` | [ ] |
| 9.3 | Fix `ask_gemini()` variable shadowing — rename `model` to `gen_model` after GenerativeModel instantiation | `wslog.py` | [ ] |
| 9.4 | Add `<report>` tag to `_sanitize_prompt_input()` strip list to prevent prompt breakout in CLI mode | `wslog.py` | [ ] |
| 9.5 | Move `from datetime import datetime` to module-level import in `wslog.py` | `wslog.py` | [ ] |

**Acceptance**: ARCHITECTURE.md accurate. No variable shadowing. `<report>` tag sanitized. All tests pass.

---

## Milestone 10 — Testtäckning
**Priority: P1 (short-term)**
**Estimated scope: Small — add missing tests**
**Depends on: Milestone 9**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 10.1 | Add test for `open_text()` with invalid gzip data — verify fallback to plain text | `tests/test_wslog.py` | [ ] |
| 10.2 | Add `TestRenderCsvReport` class — header, fields, escaping, empty events | `tests/test_wslog.py` | [ ] |
| 10.3 | Add negative test for `WAS_THREAD_RE` — verify non-matching patterns rejected | `tests/test_wslog.py` | [ ] |
| 10.4 | Add test for `parse_file` with blank lines after timestamp (edge case) | `tests/test_wslog.py` | [ ] |
| 10.5 | Add test for `render_pdf_report()` content — verify sections present, not just valid bytes | `tests/test_wslog.py` | [ ] |

**Acceptance**: All new tests pass. Total test count >390. No untested critical paths.

---

## Milestone 11 — Säkerhet & integritet
**Priority: P1 (short-term)**
**Estimated scope: Small — security hardening**
**Depends on: Milestone 10**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 11.1 | Improve secret redaction regex — replace `\S+` with `[^\n,;]+` to catch multi-word secrets | `wslog.py` | [ ] |
| 11.2 | Hash cache keys — use SHA-256 digest so queries aren't readable in `ai_responses.json` | `wslog.py` | [ ] |
| 11.3 | Add aggressive XML tag stripping — strip all `<tag>` patterns from untrusted input, not just known tags | `wslog.py` | [ ] |
| 11.4 | Add cache TTL — timestamp entries, expire after 7 days on load | `app.py` | [ ] |
| 11.5 | Add tests for improved redaction, hashed cache keys, TTL expiration, and aggressive sanitization | `tests/test_wslog.py`, `tests/test_app_helpers.py` | [ ] |

**Acceptance**: Multi-word secrets redacted. Cache keys hashed. Old cache entries expired. All XML tags stripped from untrusted input. Tests pass.

---

## Milestone 12 — Kodstruktur: splitta app.py
**Priority: P2 (mid-term)**
**Estimated scope: Large — refactor into modules**
**Depends on: Milestone 11**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 12.1 | Extract AI provider logic to `app_ai.py` — `_run_ai_analysis`, `_call_*_api`, streaming, caching | `app.py` → `app_ai.py` | [ ] |
| 12.2 | Extract report rendering to `app_render.py` — `render_report_sections`, `render_summary`, download buttons | `app.py` → `app_render.py` | [ ] |
| 12.3 | Extract audit tab to `app_audit.py` — `_run_audit`, `_collect_audit_sources`, `_extract_signatures` | `app.py` → `app_audit.py` | [ ] |
| 12.4 | Extract realtime monitoring to `app_realtime.py` — `_rt_poll`, `_rt_live_view`, path validation | `app.py` → `app_realtime.py` | [ ] |
| 12.5 | Update all tests and imports — fix mocks, verify all 385+ tests pass with new module structure | `tests/` | [ ] |

**Acceptance**: `app.py` under 800 lines (layout + tab wiring only). Each module under 500 lines. All tests pass.

---

## Milestone 13 — Funktioner & förbättringar
**Priority: P3 (long-term)**
**Estimated scope: Medium — new features**
**Depends on: Milestone 12**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 13.1 | Pre-flight token estimation — estimate prompt size before API calls, warn if near context limit | `app_ai.py`, `wslog.py` | [ ] |
| 13.2 | Extract `_HEURISTICS` to YAML data file — easier to extend without touching Python | `wslog.py`, `heuristics.yaml` | [ ] |
| 13.3 | Add JMS/SIB skill file — cover `CWSID*`, `CWSJY*` message codes and SIBJMSRAThreadPool patterns | `skills/jms-messaging.md` | [ ] |
| 13.4 | Add GC/performance skill file — verbose GC log patterns, heap dump guidance, G1/ZGC tuning | `skills/gc-performance.md` | [ ] |
| 13.5 | Structured event filtering in UI — filter by level, code prefix, exception type, time range before AI analysis | `app_render.py`, `app.py` | [ ] |

**Acceptance**: Token estimation warns before expensive calls. Heuristics editable via YAML. 2 new skill files. Event filtering in UI. Audit grade **A+**.

---

## Progress Tracker

| Milestone | Tasks | Done | Status |
|-----------|-------|------|--------|
| 1 — Buggfixar & hygien | 5 | 5 | Done |
| 2 — DRY AI-funktioner | 5 | 5 | Done |
| 3 — Streaming & UX | 5 | 5 | Done |
| 4 — Kvalitet & polish | 5 | 5 | Done |
| 5 — Säkerhetsförstärkning | 5 | 5 | Done |
| 6 — E2e-teststabilitet | 5 | 5 | Done |
| 7 — Kodstruktur & refaktorering | 5 | 5 | Done |
| 8 — Funktioner & förbättringar | 5 | 5 | Done |
| 9 — Dokumentation & snabbfixar | 5 | 0 | Not started |
| 10 — Testtäckning | 5 | 0 | Not started |
| 11 — Säkerhet & integritet | 5 | 0 | Not started |
| 12 — Kodstruktur: splitta app.py | 5 | 0 | Not started |
| 13 — Funktioner & förbättringar | 5 | 0 | Not started |
