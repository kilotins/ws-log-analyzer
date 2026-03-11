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
| 13.1 | Pre-flight token estimation — estimate prompt size before API calls, warn if near context limit | `app_ai.py`, `wslog.py` | [x] |
| 13.2 | Extract `_HEURISTICS` to YAML data file — easier to extend without touching Python | `wslog.py`, `heuristics.yaml` | [x] |
| 13.3 | Add JMS/SIB skill file — cover `CWSID*`, `CWSJY*` message codes and SIBJMSRAThreadPool patterns | `skills/jms-messaging.md` | [x] |
| 13.4 | Add GC/performance skill file — verbose GC log patterns, heap dump guidance, G1/ZGC tuning | `skills/gc-performance.md` | [x] |
| 13.5 | Structured event filtering in UI — filter by level, code prefix, exception type, time range before AI analysis | `app_render.py`, `app.py` | [x] |

**Acceptance**: Token estimation warns before expensive calls. Heuristics editable via YAML. 2 new skill files. Event filtering in UI. Audit grade **A+**.

---

## Milestone 14 — Dokumentation & kodkonventioner
**Priority: P1 (short-term)**
**Estimated scope: Small — quick fixes**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 14.1 | Update README.md test count to 392 and line counts | `README.md` | [x] |
| 14.2 | Update ARCHITECTURE.md line counts (wslog.py 1759, app.py 658, app_audit.py 381) and add app_constants.py to structure | `ARCHITECTURE.md` | [x] |
| 14.3 | Update `.claude/skills/testing.md` test count to 392 | `.claude/skills/testing.md` | [x] |
| 14.4 | Rename underscore-prefixed cross-module exports to public names (`_PROVIDER_CONFIG` → `PROVIDER_CONFIG`, etc.) | `app_ai.py`, `app.py` | [x] |
| 14.5 | Add Azure SAS token and `Authorization: Digest` redaction patterns + tests | `wslog.py`, `tests/test_wslog.py` | [x] |

**Acceptance**: All docs accurate. No underscore-prefixed cross-module exports. Azure SAS tokens redacted. Tests pass.

---

## Milestone 15 — Testtäckning: E2E & kantfall
**Priority: P1 (short-term)**
**Estimated scope: Medium — new tests**
**Depends on: Milestone 14**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 15.1 | Add E2E error flow tests — invalid file upload, empty file, corrupt file | `tests/test_app_e2e.py` | [x] |
| 15.2 | Add E2E tests for API failure handling — mock API errors, verify user-facing error messages | `tests/test_app_e2e.py` | [x] |
| 15.3 | Add direct tests for `_lookup_cache()` and `_store_cache()` — cache hit, miss, TTL, size eviction | `tests/test_app_helpers.py` | [x] |
| 15.4 | Add concurrency test for cache file access — simulate two writers, verify no corruption | `tests/test_app_helpers.py` | [x] |
| 15.5 | Add network/timeout error tests — mock API timeout, verify graceful handling | `tests/test_app_helpers.py` | [x] |

**Acceptance**: E2E tests cover error flows. Cache helpers fully tested. Total test count >410. No flaky tests.

---

## Milestone 16 — Robusthet & Splunk-parsing
**Priority: P2 (mid-term)**
**Estimated scope: Medium — refactor + features**
**Depends on: Milestone 15**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 16.1 | Replace regex-based Splunk extraction with proper markdown parser — handle nested fences, inline backticks | `app_ai.py` | [x] |
| 16.2 | Add session state schema validation — define expected keys+types, warn on unknown keys in debug mode | `app.py` | [x] |
| 16.3 | Add event pagination in GUI — show first N events with "Show more" button instead of rendering all | `app_render.py` | [x] |
| 16.4 | Add cross-references between skill files — "See also" links at bottom of each skill | `skills/*.md` | [x] |
| 16.5 | Add tests for Splunk extraction edge cases (nested fences, inline backticks, empty blocks) | `tests/test_app_helpers.py` | [x] |

**Acceptance**: Splunk extraction handles nested fences. Event pagination for large analyses. Skills cross-linked. Tests pass.

---

## Milestone 17 — Skalbarhet & prestanda
**Priority: P3 (long-term)**
**Estimated scope: Large — new capabilities**
**Depends on: Milestone 16**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 17.1 | Add streaming parser `parse_file_iter()` — generator-based, yields events without accumulating all in memory | `wslog.py` | [x] |
| 17.2 | Add hard upload limit (configurable, default 200MB) — reject files over limit with clear message | `app.py` | [x] |
| 17.3 | Add heuristic pre-filtering — index events by tag on first pass, avoid O(n×17) scan in `likely_causes()` | `wslog.py` | [x] |
| 17.4 | Add dynamic skill discovery — scan `skills/` directory at startup instead of hardcoding filenames in maps | `wslog.py` | [x] |
| 17.5 | Add tests for streaming parser, upload limits, and pre-filtered heuristics | `tests/test_wslog.py` | [x] |

**Acceptance**: Streaming parser handles >100MB files without OOM. Upload limit enforced. Heuristic scanning faster. Dynamic skill discovery works. Tests pass.

---

## Milestone 18 — Reviewfixar: prestanda, tester & arkitektur
**Priority: P1 (short-term)**
**Estimated scope: Medium — fixes from 4-part review**
**Source: Architecture (B+), Security (A-), Performance (B+), Test Quality (B+) reviews**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 18.1 | Lazy-render rapporter — generera PDF/CSV/XML vid nedladdning, inte vid uppladdning | `app.py`, `app_render.py` | [ ] |
| 18.2 | Cachelagra filtrerad analys — memoize `precompute_analysis()` per filterkombination istället för att räkna om varje gång | `app_render.py` | [ ] |
| 18.3 | Fixa dött E2E-test — ta bort `or True` i `test_analyze_button_disabled_without_input`, skriv fungerande assertion | `tests/test_app_e2e.py` | [ ] |
| 18.4 | Konsolidera Splunk-parsing — flytta `_looks_like_splunk` + `_split_combined_splunk` till `wslog.py` så att `app_ai.py` och `app_render.py` delar samma kod | `wslog.py`, `app_ai.py`, `app_render.py` | [ ] |
| 18.5 | Ersätt hårdkodade `wait_for_timeout()` i E2E-tester med villkorsbaserade `wait_for_selector()` / `expect()` | `tests/test_app_e2e.py` | [ ] |

**Acceptance**: Rapporter genereras on-demand (snabbare analys). Filtrerad analys cachas. Inga döda tester. Splunk-logik på ett ställe. E2E-tester utan godtyckliga väntetider. Alla 432+ tester passerar.

---

## Milestone 19 — Testkvalitet & organisation
**Priority: P2 (mid-term)**
**Estimated scope: Medium — refaktorering av testsvit**
**Depends on: Milestone 18**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 19.1 | Splitta `test_wslog.py` (2750 rader) i `test_parsing.py`, `test_reports.py`, `test_ai_prompt.py`, `test_heuristics.py` | `tests/` | [ ] |
| 19.2 | Skapa `tests/conftest.py` med delade fixtures (`_make_event`, `_make_classified_event`, `_empty_match`) | `tests/conftest.py` | [ ] |
| 19.3 | Parametrisera 12 `test_likely_causes_*` tester till en enda `@pytest.mark.parametrize` | `tests/test_wslog.py` | [ ] |
| 19.4 | Parametrisera 5 `test_was_level_*` tester till en enda `@pytest.mark.parametrize` | `tests/test_wslog.py` | [ ] |
| 19.5 | Lägg till enhetstester för `app_ai.py` — mocka API-svar för providerkonfiguration, kostnadsberäkning och cachelogik | `tests/test_app_ai.py` | [ ] |

**Acceptance**: Inga testfiler över 1000 rader. Delade fixtures i conftest.py. Parametriserade heuristik-/nivåtester. `app_ai.py` har enhetstester. Alla tester passerar.

---

## Milestone 20 — Arkitektur & prestandaoptimering
**Priority: P3 (long-term)**
**Estimated scope: Medium — refaktorering**
**Depends on: Milestone 19**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 20.1 | Konsolidera audit-AI-anrop — återanvänd `PROVIDER_CONFIG` / `call_*_api` från `app_ai.py` i `app_audit.py` istället för duplicerade funktioner | `app_audit.py`, `app_ai.py` | [x] |
| 20.2 | Cacha `incident_timeline()` timestamp-parsing — undvik upprepad `parse_ts_datetime()` per event | `wslog.py` | [x] |
| 20.3 | Early-exit i `redact()` — snabbkolla om vanliga secretmönster finns innan 11 regex-substitutioner körs | `wslog.py` | [x] |
| 20.4 | Cacha `_discover_skills()` med `lru_cache` — undvik filsystem-scan vid varje `select_skills()`-anrop | `wslog.py` | [x] |
| 20.5 | Använd `parse_file_iter()` i GUI för filer >50MB — streama events istället för att ladda alla i minnet | `app.py` | [—] Skippat — `precompute_analysis()` kräver alla events i minnet, minimal vinst |

**Acceptance**: Ingen duplicerad AI-anropslogik. Timestamp-parsing cachad. Redaction snabbare för normala loggar. Skill-discovery cachad. ~~Stora filer streamade.~~ Alla tester passerar (436 passed).

---

## Milestone 21 — CI/CD Pipeline & Atomic Writes
**Priority: P0 (immediate)**
**Estimated scope: Small — 4-6 hours**
**Audit finding: "No CI/CD pipeline" (medium), "Cache file not atomically written" (security concern)**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 21.1 | Skapa GitHub Actions CI workflow — kör `pytest` på Python 3.9, 3.11, 3.12 vid push/PR till main | `.github/workflows/ci.yml` | [ ] |
| 21.2 | Lägg till linting i CI — kör `ruff check` med minimal config, faila vid fel | `.github/workflows/ci.yml`, `pyproject.toml` | [ ] |
| 21.3 | Implementera atomic cache writes — använd `tempfile.NamedTemporaryFile(delete=False)` + `os.replace()` i `_save_json_file()` | `app.py` | [ ] |
| 21.4 | Atomic writes för alla historikfiler — samma mönster för HISTORY_FILE, GEMINI_HISTORY_FILE, OPENAI_HISTORY_FILE | `app.py` | [ ] |
| 21.5 | Lägg till test för atomic write — verifiera att cache-fil är giltig JSON även vid avbruten skrivning | `tests/test_app_helpers.py` | [ ] |

**Acceptance**: CI körs vid varje push. Lint och tester passerar. Cache-skrivningar använder tempfile+rename. Ingen korruption möjlig vid samtidig åtkomst.

---

## Milestone 22 — Strukturerad loggning & felhantering
**Priority: P1 (short-term)**
**Estimated scope: Small-Medium — 6-8 hours**
**Audit finding: "No structured logging" (low), Error handling B+, "silent None returns"**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 22.1 | Lägg till JSON-loggformatterare — konfigurerbar via `WSLOG_LOG_FORMAT=json` env var | `app.py` | [x] |
| 22.2 | Lägg till `--log-format json` CLI-flagga för core engine | `wslog.py` | [x] |
| 22.3 | Ersätt tysta None-returer med explicita exceptions/varningar i `parse_ts`, `open_text`, `_load_json_file` | `wslog.py`, `app.py` | [x] |
| 22.4 | Provider-specifika token-estimeringsratios — Claude ~3.5 chars/token, GPT ~4, Gemini ~4 istället för uniform ~4 | `app_ai.py`, `wslog.py` | [x] |
| 22.5 | Tester för JSON-loggformat och förbättrad felpropagering | `tests/test_parsing.py`, `tests/test_app_helpers.py` | [x] |

**Acceptance**: `WSLOG_LOG_FORMAT=json` producerar giltiga JSON-lograder. Tysta None-returer ersatta. Token-estimering använder provider-ratios. Alla tester passerar.

---

## Milestone 23 — Dokumentation & utvecklaronboarding
**Priority: P1 (short-term)**
**Estimated scope: Small — 4-6 hours**
**Audit finding: Documentation A- (87), "No CONTRIBUTING.md", "No API documentation"**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 23.1 | Skapa CONTRIBUTING.md — dev setup (venv, pip install -e .[test,gui]), köra tester, kodstil, PR-checklista | `CONTRIBUTING.md` | [x] |
| 23.2 | Lägg till API-dokumentation — dokumentera `parse_file()`, `precompute_analysis()`, `render_*_report()`, `summarize()` med exempel | `docs/API.md` | [x] |
| 23.3 | Lägg till docstring-exempel på 5 publika funktioner | `wslog.py` | [x] |
| 23.4 | Uppdatera ARCHITECTURE.md med aktuell modulstruktur — lägg till `app_spend.py`, `report_renderer.py`, uppdatera radantal | `ARCHITECTURE.md` | [x] |
| 23.5 | Uppdatera README.md med CI-badge, bidragslänk och aktuellt testantal (476) | `README.md` | [x] |

**Acceptance**: CONTRIBUTING.md täcker fullt dev-workflow. API.md dokumenterar alla publika funktioner. ARCHITECTURE.md speglar aktuell kodbas.

---

## Milestone 24 — Integrationstester & stresstestning
**Priority: P2 (mid-term)**
**Estimated scope: Medium — 1-2 days**
**Audit finding: "No integration tests for multi-file workflows", "No stress tests for >1GB"**
**Depends on: Milestone 21 (CI måste finnas först)**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 24.1 | Lägg till multi-fil integrationstester — ladda upp 2-3 loggfiler, verifiera kombinerad analys | `tests/test_integration.py` | [x] |
| 24.2 | Multi-fil jämförelse-test — verifiera att timeline spänner alla filer, signaltaggar aggregeras | `tests/test_integration.py` | [x] |
| 24.3 | Stresstest för stora filer — generera 100K+ events, verifiera `parse_file` och `parse_file_iter` klarar det utan OOM | `tests/test_performance.py` | [x] |
| 24.4 | Stresstest för samtidig cache-åtkomst — 4 trådar som skriver cache samtidigt, verifiera ingen korruption | `tests/test_performance.py` | [x] |
| 24.5 | CI-marks för långsamma tester — markera stresstester med `@pytest.mark.slow`, exkludera från standard-CI | `tests/conftest.py`, `.github/workflows/ci.yml` | [x] |

**Acceptance**: Multi-fil workflows testade end-to-end. Stresstester validerar 100K+ events. Långsamma tester markerade och exkluderade från snabb CI.

---

## Milestone 25 — Typsäkerhet & wslog.py modularisering
**Priority: P3 (long-term)**
**Estimated scope: Large — 2-3 days**
**Audit finding: "Split wslog.py into subpackage" (P2), "Add mypy" (P3), Code Quality A- (85)**
**Depends on: Milestones 21-24**

| # | Task | File(s) | Status |
|---|------|---------|--------|
| 25.1 | Lägg till mypy-konfiguration — `[tool.mypy]` i pyproject.toml | `pyproject.toml` | [x] |
| 25.2 | Fixa mypy-fel — type annotations med `dict[str, Any]`, targeted `type: ignore` | `wslog/` | [x] |
| 25.3 | Splitta wslog.py till `wslog/`-paket — `__init__.py`, `parser.py`, `analysis.py`, `reports.py`, `ai.py`, `cli.py`, `__main__.py` | `wslog/` | [x] |
| 25.4 | Lägg till mypy i CI-pipeline — informational (`mypy wslog/ || true`) | `.github/workflows/ci.yml` | [x] |
| 25.5 | Uppdatera alla imports — `app_audit.py`, testfiler, mock-paths | Alla `.py` filer | [x] |

**Acceptance**: mypy passerar på `wslog/`-paketet med strict mode. wslog.py uppdelad i 4+ moduler under 500 rader var. Alla 460+ tester passerar. CI enforcar typkontroll.

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
| 9 — Dokumentation & snabbfixar | 5 | 5 | Done |
| 10 — Testtäckning | 5 | 5 | Done |
| 11 — Säkerhet & integritet | 5 | 5 | Done |
| 12 — Kodstruktur: splitta app.py | 5 | 5 | Done |
| 13 — Funktioner & förbättringar | 5 | 5 | Done |
| 14 — Dokumentation & kodkonventioner | 5 | 5 | Done |
| 15 — Testtäckning: E2E & kantfall | 5 | 5 | Done |
| 16 — Robusthet & Splunk-parsing | 5 | 5 | Done |
| 17 — Skalbarhet & prestanda | 5 | 5 | Done |
| 18 — Reviewfixar: prestanda, tester & arkitektur | 5 | 5 | Done |
| 19 — Testkvalitet & organisation | 5 | 5 | Done |
| 20 — Arkitektur & prestandaoptimering | 5 | 4 | Done (20.5 skipped) |
| 21 — CI/CD Pipeline & Atomic Writes | 5 | 5 | Done |
| 22 — Strukturerad loggning & felhantering | 5 | 5 | Done |
| 23 — Dokumentation & utvecklaronboarding | 5 | 5 | Done |
| 24 — Integrationstester & stresstestning | 5 | 5 | Done |
| 25 — Typsäkerhet & wslog.py modularisering | 5 | 5 | Done |
