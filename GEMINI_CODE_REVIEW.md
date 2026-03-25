# Code Review: LogPilot

**Date:** 2026-03-25
**Reviewer:** Gemini CLI
**Version:** 1.1.2

## Executive Summary

LogPilot is a well-structured, production-grade application with impressive breadth (14 formats, 68 heuristics, 4 AI providers). It follows modern Python practices (type hinting, dataclasses, modularity) and has a robust test suite.

However, there are critical concurrency issues in the AI layer, logic bugs in the report rendering, and several performance bottlenecks in the parsing/analysis pipeline. Security is generally good (redaction is ubiquitous), but API key handling needs tightening.

---

## 1. Bugs

| File | Line (Approx) | Severity | Issue | Suggested Fix |
| :--- | :--- | :--- | :--- | :--- |
| `app_ai.py` | 328 | **Critical** | **Race Condition:** `genai.configure(api_key=key)` sets global state. In a multi-user Streamlit app, concurrent requests will overwrite each other's API keys. | Use `genai.GenerativeModel(..., api_key=key)` (if supported by SDK v0.5+) or use a threading lock around the configure/generate call block. |
| `logpilot/reports/html.py` | 130 vs 260 | **Critical** | **Nav Desync:** Navigation items are added if `causes` exist, but the section is only rendered if `causes AND grouped` exist. If `grouped` is empty, the nav links point to the wrong sections (off-by-one error). | Align the `if` conditions exactly. Change line 260 to `if _sec(sections, "causes") and causes:` and handle empty `grouped` inside (show "No groups found"). |
| `logpilot/analysis.py` | 445 | **Important** | `detect_cross_system_cascades` relies on `e.ts_utc` being populated. If called before `sort_events_chronologically`, it fails silently. | Call `sort_events_chronologically` inside `detect_...` or raise `ValueError` if `ts_utc` is missing. |
| `app_spend.py` | 130 | **Important** | `_parse_google_csv` hardcodes column checks for "Cost (kr)" and converts SEK to USD. Fails for non-SEK billing exports. | Detect currency from column header (e.g. "Cost (USD)", "Cost (EUR)") or allow user to select currency. |
| `logpilot/formats/docker_json.py` | 55 | **Minor** | `_unwrap_docker` requires `stream` field. Some logging drivers (e.g. specialized splunk/fluentd wrappers) might omit it. | Change check to `if "log" in obj and "time" in obj:` (stream is optional). |
| `logpilot/heuristics.py` | 120 | **Minor** | `_IP_PORT_RE` matches `d.d.d.d`. It filters `0.` and `127.` but matches version numbers like `1.2.3.4` in text. | Require look-behind/ahead or stricter IP validation (e.g. no adjacent dots/alphanumerics). |

## 2. Security

| File | Line (Approx) | Severity | Issue | Suggested Fix |
| :--- | :--- | :--- | :--- | :--- |
| `app.py` | 330 | **Important** | `_save_keychain` stores API keys in `cache/.api_keys.json`. While `chmod 0600` is used, storing secrets in a cache folder in plaintext is risky (backups, accidentally shared). | Use system keyring ONLY, or separate `config/secrets.json` outside cache. Add `cache/` to `.gitignore` (verified: it is ignored, but still risky on shared FS). |
| `app_ai.py` | 65 | **Medium** | `_log_probe` and general logging: `log.error(..., exc)` might log raw exceptions containing API keys (e.g. in 401 response bodies). `_sanitize_error` is only used for UI. | Implement a `RedactingLogger` or sanitize exception strings before passing to `log.error`. |
| `logpilot/reports/html.py` | 45 | **Medium** | `_render_ai_markdown` manually parses markdown. Malicious AI output could theoretically inject HTML if sanitization fails upstream. | Use a battle-tested library like `bleach` on the final HTML output, or a proper markdown parser (e.g. `markdown` or `mistune`) with safe mode. |

## 3. Performance

| File | Line (Approx) | Severity | Issue | Suggested Fix |
| :--- | :--- | :--- | :--- | :--- |
| `logpilot/parser.py` | 170 | **Important** | `redact()` is called on every event text join. For 500k events, this is expensive. | Optimize `_REDACT_FAST_CHECK` further or redact only sample/display text (risk: sensitive data in analysis/memory). Better: use Rust-based regex (e.g. `polars`/`rust-regex` binding) or optimize the regex set. |
| `logpilot/formats/json_log.py` | 125 | **Medium** | `detect()` calls `json.loads` on 50 lines. Then `classify_event` calls `json.loads` again on the same lines during parsing. | Minor impact (only 50 lines), but inefficient. Pass parsed object if possible, or use lru_cache for the first 50 lines. |
| `app_audit.py` | 180 | **Medium** | `_collect_audit_sources` reads all source files into memory string. Large repos will OOM. | Stream content or limit total bytes read (e.g. max 10MB total context). |
| `app_spend.py` | 40 | **Medium** | `_load_entries` / `_save_entries` reads/writes full JSON history on every update. | Use append-only JSONL (JSON Lines) format for spend tracking. |

## 4. Inconsistencies & Maintenance

| File | Line (Approx) | Severity | Issue | Suggested Fix |
| :--- | :--- | :--- | :--- | :--- |
| `app_ai.py` | 170 | **Nice-to-have** | `TOKEN_COSTS` are hardcoded. Pricing changes frequently. | Load from an external `prices.json` or fetch dynamically (if possible), or at least move to `app_constants.py`. |
| `logpilot/parser.py` | 350 | **Nice-to-have** | `parse_file` vs `parse_file_iter`. `parse_file` just wraps list. | Standardize on iterator approach to support streaming/pagination in future. |
| `logpilot/formats/was.py` | 40 | **Nice-to-have** | `detect` scoring logic: score increases with match count, normalized by `len(lines)*3`. Can exceed 1.0. | Cap score at 1.0 (already done via `min`, but logic is loose). |

---

## Top 10 Fixes (Prioritized)

1.  **[Security/Critical]** Fix `genai.configure` race condition in `app_ai.py`. Use a lock or instance-based configuration.
2.  **[Bug/Critical]** Fix HTML report navigation desync in `logpilot/reports/html.py` (ensure `_add_nav` and `_open_section` conditions match).
3.  **[Security/Important]** Stop logging raw exceptions in `app_ai.py` / `app.py` to prevent API key leakage in logs.
4.  **[Bug/Important]** Fix `detect_cross_system_cascades` in `logpilot/analysis.py` to handle unsorted events/missing UTC timestamps gracefully.
5.  **[Bug/Important]** Generalize currency handling in `app_spend.py` (don't assume SEK).
6.  **[Performance]** Optimize `redact()` in `logpilot/parser.py` (it's the bottleneck for large files).
7.  **[Performance]** Switch spend tracking to append-only (JSONL) in `app_spend.py` to avoid O(N) reads/writes.
8.  **[Bug]** Fix `_unwrap_docker` in `logpilot/formats/json_log.py` to support drivers without `stream` field.
9.  **[Security]** Move `cache/.api_keys.json` to a more secure location or restrict to system keyring only.
10. **[Maintainability]** Move `TOKEN_COSTS` to a config file/constant module and update with latest pricing.
