# LogPilot Code Audit Report

**Date:** 2026-03-19
**Auditor:** Claude Opus 4.6
**Score:** 8/10
**Tests:** 1579 passing

## 1. Executive Summary

LogPilot is a well-structured, mature Python codebase with strong test coverage (1579 tests), clean module boundaries, and thoughtful security measures. The core parsing and analysis logic is solid. A previous audit (M53) fixed all P0 issues (dead Splunk references, Gemini safety handling) and standardized LogEvent access. The codebase is ready for the next major milestone (M50: Trace to Code).

**Key strengths:** Zero required dependencies for core, 8 format plugins with auto-detection, comprehensive heuristic system (58 patterns, 17 correlations, 7 incident groups), enriched incident analysis with evidence extraction and cascade ranking.

## 2. Architecture Review

### Strengths
- Clean separation: `logpilot/` package is pure stdlib, app layer (`app*.py`) depends on Streamlit
- Format plugin system (`logpilot/formats/`) with base class and auto-detection is well designed
- `LogEvent` dataclass with dict-protocol compatibility is a pragmatic bridge pattern
- Report rendering split into per-format modules (`reports/`) is clean
- AI prompt building is centralized in `logpilot/ai.py` with injection defense
- Discovery module (`logpilot/discovery.py`) follows same patterns as parser
- Enriched heuristics (evidence extraction, ranking, narratives) add significant diagnostic value without AI dependency

### Module Map
```
logpilot/
├── event.py          LogEvent dataclass (19 fields, __slots__ on 3.10+)
├── parser.py         Parse + redact + format detect + cache
├── analysis.py       Summarize, timeline, cascades, samples, noise
├── heuristics.py     58 heuristics, correlations, incidents, evidence, ranking
├── discovery.py      Recursive folder scan with filtering
├── ai.py             AI prompts, caching, skills, Gemini/Claude/OpenAI
├── cli.py            CLI entry point (--directory, --exit-code)
├── formats/          8 format plugins (WAS, JSON, nginx, Log4j, CRI-O, Python, syslog, Enonic)
└── reports/          Per-format renderers (markdown, html, json, pdf, config)

app.py               Streamlit main (session state, upload, folder scan)
app_render.py         Report sections, filters, export, incident overview
app_incident.py       Unified AI assistant (multi-source, screenshots, noise filter)
app_ai.py             AI provider calls, cost tracking, probe logging
```

## 3. Security

### Strengths
- **Secret redaction** (`parser.py`): JWT, AWS keys, PEM, bearer tokens, Basic auth, passwords, API keys, digest auth, signed URLs. Fast-check regex optimization.
- **Prompt injection defense** (`ai.py`): Unicode homoglyph sanitization, XML tag stripping, entity escaping.
- **Path traversal prevention** (`app.py`): `upload_path.resolve().is_relative_to(UPLOADS_DIR.resolve())`
- **API keys**: Stored in session state only, not persisted to disk (except local AI settings).
- **Codebase access**: M50 will be strictly READ-ONLY — no git write operations.

### Remaining Items
- **P2**: Local AI settings persisted to disk (`cache/.local_ai_settings.json`) — includes API key field (typically "not-needed" but not filtered).

## 4. Performance

### Strengths
- Generator-based parsing (`parse_file_iter`) for lazy evaluation
- INFO event sampling for large files (`sample_info` parameter)
- Parse cache with gzip compression and LRU eviction (50 files max)
- Keyword pre-filtering in `likely_causes()` avoids running all 58 regexes on every event
- `sys.intern()` on repeated strings, `__slots__` on Python 3.10+

### Remaining Items
- **P2**: `likely_causes()` iterates events twice per matched heuristic (count + evidence). Could be single-pass.
- **P2**: Timestamp parsing repeated across analysis functions. A cached `_parsed_dt` property on LogEvent would help.

## 5. Error Handling

### Strengths
- Graceful degradation for optional dependencies (anthropic, google-generativeai, openai, streamlit, PyYAML)
- AI retry logic with exponential backoff
- Atomic JSON writes via tempfile + os.replace
- Cache read/write failures caught and logged, never crash
- `ask_gemini()` now handles safety-blocked responses (M53 fix)

## 6. Code Quality

### Strengths
- Consistent naming conventions
- Type hints throughout (PEP 604 union syntax)
- Docstrings on all public functions
- `LogEvent` dataclass with clean defaults and dict-protocol compat
- All report renderers share `ReportConfig` dataclass
- Evidence extraction, incident ranking, and narrative building are well-separated functions

### Fixed in M53
- Dead Splunk references removed from all Python files
- Format-aware "Top Message Codes" heading
- LogEvent access standardized to attribute-style in app layer
- Redundant Counter import removed
- Audit file lists updated

### Remaining Items
- **P2**: Dict-style `.get()` on LogEvent persists in `logpilot/ai.py` and report renderers. Functionally correct but inconsistent.
- **P2**: Stale Splunk references in documentation (README.md, CONTRIBUTING.md, docs/API.md).

## 7. Test Coverage

**1579 tests across 35 test files.**

- Format plugins: 394 tests (WAS, JSON, nginx, Log4j, CRI-O, Python, syslog, Enonic)
- Heuristics/incidents: 49 tests (evidence, ranking, narratives, correlations, groups)
- Scenario simulation: 56 tests (6 log files, format detection, cascades, traces, reports, e2e)
- Discovery: 46 tests (recursion, filtering, limits, gzip, groups, pipeline integration)
- Reports: HTML, Markdown, JSON, PDF rendering tests
- App render: filter logic, AI content collection, export caching
- Performance: `__slots__`, caching, large dataset handling

## 8. Bugs Found (Post-M53)

No functional bugs found. All previous P0/P1 issues have been resolved.

## 9. P0 Issues

None. All P0 issues from previous audit have been fixed.

## 10. P1 Issues

None remaining. All P1 issues have been addressed in M53.

## 11. P2 Issues (Cosmetic/Cleanup)

| # | File | Issue |
|---|------|-------|
| 1 | `README.md` | Stale "Splunk Searches" feature claims (3 locations) |
| 2 | `CONTRIBUTING.md` | Lists deleted `splunk.py` and `reports.py` |
| 3 | `docs/API.md` | `precompute_analysis` return docs list `splunk` key |
| 4 | `logpilot/ai.py` | Dict-style `.get()` on LogEvent in core |
| 5 | `logpilot/reports/` | Same dict-style trigger access in onset section |

All P2 items are documentation/style issues scheduled for M45 (Documentation refresh).

## 12. Improvement Plan

### Completed This Session
1. ✅ M43: Production Incident Simulation (50 tests)
2. ✅ M52: Recursive Log Upload (54 tests)
3. ✅ M49: Enriched Likely Causes + AI UX (27 tests)
4. ✅ M53: Audit Fixes — dead code, Gemini safety, LogEvent consistency
5. ✅ Cache hygiene: eviction, orphan cleanup, atomic writes
6. ✅ AI history delete fix
7. ✅ Noise filter table font fix
8. ✅ Rotated log file support in discovery

### Next Steps
1. **M45**: Documentation refresh (~1-2h)
2. **M50**: Trace to Code (~12h) — read-only codebase connector
3. **M33**: Docker packaging (~30min)
4. **M34**: PyPI packaging (~45min)

### Metrics
- **Tests:** 1579 passing
- **Format plugins:** 8
- **Heuristics:** 58 patterns, 17 correlations, 7 incident groups
- **Report formats:** 4 (Markdown, HTML, JSON, PDF)
- **Report presets:** 3 (Quick Diagnosis, Incident Report, Deep Analysis)
- **AI providers:** 4 (Claude, Gemini, OpenAI, Local)
