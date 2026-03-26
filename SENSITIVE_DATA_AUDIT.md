# Sensitive Data Audit Report: LogPilot Repository

**Date:** 2026-03-26  
**Status:** Action Required (Critical)  
**Scope:** Public GitHub Readiness Review

## 1. Executive Summary
The repository contains several high-severity leaks of internal business strategy and personally identifiable information (PII). A recent attempt to remove these files (Commit `328ac620`) failed to actually remove them from the git index; they are still tracked. Furthermore, the git history still contains full versions of these documents.

## 2. Findings Table

| File Path | Line(s) | Finding | Severity | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| `docs/logpilot-go-to-market.html` | All | Full GTM Strategy, pricing visions, and competitor analysis. | **CRITICAL** | `git rm --cached` and purge from history using `git filter-repo`. |
| `docs/logpilot-project-plan.html` | All | Internal PRD, roadmap, and resource planning. | **CRITICAL** | `git rm --cached` and purge from history. |
| `docs/logpilot-dream-architecture.html`| All | Strategic technical vision and internal design goals. | **HIGH** | `git rm --cached` and purge from history. |
| `AUDIT_REPORT.md` / `.html` | All | Detailed vulnerability and gap analysis of the system. | **HIGH** | Move to private storage; remove from git tracking. |
| `GEMINI_CODE_REVIEW.md` | All | Internal architectural critique and security observations. | **MEDIUM** | Move to private storage; remove from git tracking. |
| `tests/test_pii_redaction.py` | 55, 116 | Real-looking PII: `erik.hansen@klpbank.no`. | **HIGH** | Replace with `user@example.com` in test cases. |
| `app_jira.py` | 203 | Placeholder `user@company.no`. | **LOW** | Replace with generic `user@example.com`. |
| `MILESTONES.md` | All | Detailed dev history including internal pivots and naming. | **MEDIUM** | Clean up or remove before public release. |
| `SKILLS_AUDIT.md` | All | Internal skill gap analysis. | **MEDIUM** | Remove from public repository. |
| `git history` (Commit `328ac620`) | - | All "deleted" files are fully recoverable from history. | **CRITICAL** | Use `git filter-repo --path docs/` to wipe history. |

## 3. Detailed Technical Observations

### 3.1 Tracking Failure
The command `git ls-files` confirms that the following files are **still in the git index**, meaning they will be included in the next push:
- `docs/logpilot-go-to-market.html`
- `docs/logpilot-project-plan.html`
- `AUDIT_REPORT.md`
- `GEMINI_CODE_REVIEW.md`

### 3.2 PII in Testing
While `tests/fixtures/` are synthetic, the actual test code in `tests/test_pii_redaction.py` contains hardcoded strings that look like real customer data from a specific Norwegian bank (`klpbank.no`). Even if synthetic, using a real domain in a public repo is a reputation risk.

### 3.3 Internal Infrastructure
The file `app_jira.py` contains logic that implies internal workflows (Jira/Confluence integration) which, while functional, uses placeholders that point to `company.no`.

## 4. Remediation Plan

1.  **Stop Tracking:** Immediately run `git rm --cached` on all files in `docs/` (except `API.md`) and the various `*_REPORT.md` files in the root.
2.  **History Purge:** Use `git filter-repo` or `BFG Repo-Cleaner` to remove the `docs/` folder's history from the repository entirely.
3.  **Sanitize Tests:** Update `tests/test_pii_redaction.py` to use `example.com` instead of `klpbank.no`.
4.  **Update .gitignore:** Ensure the `.gitignore` correctly targets these patterns to prevent accidental re-addition.

---
**Instruction for User:** Run `python3 report_renderer.py SENSITIVE_DATA_AUDIT.md --open` to view this report as a branded HTML document for your records.
