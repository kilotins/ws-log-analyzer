# Skills Audit Report — LogPilot

**Date:** 2026-03-25
**Reviewer:** Gemini CLI
**Audit Scope:** 23 skills in `skills/` directory

## Executive Summary
The skills system in LogPilot is the "brain" behind the AI's diagnostic capabilities. The overall quality is **Exceptional (Grade: A)**. The documentation for Java/WebSphere, Databases, and GC is industry-leading in its detail.

There are minor gaps in newer or less common formats (DataPower, Enonic) and some inconsistencies between the regex patterns defined in skills vs. those implemented in the Python format plugins.

---

## 1. Coverage Analysis

LogPilot supports 14 format plugins. Here is the skill coverage:

| Format Plugin | Corresponding Skill | Status | Gap/Note |
| :--- | :--- | :--- | :--- |
| `was.py` | `liberty-analysis.md` / `websphere-startup.md` | ✅ Complete | Very high detail. |
| `nginx.py` | `nginx-analysis.md` | ✅ Complete | Covers 4xx/5xx well. |
| `log4j.py` | `log4j-analysis.md` | ✅ Complete | Standard patterns. |
| `json_log.py` | `json-structured-logs.md` | ✅ Complete | Covers Bunyan/Pino. |
| `syslog.py` | `syslog-analysis.md` | ✅ Complete | RFC compliance info. |
| `postgresql.py` | `postgresql-log-analysis.md` | ✅ Complete | Good SQLSTATE coverage. |
| `tomcat.py` | `tomcat-analysis.md` | ✅ Complete | Standard Catalina logs. |
| `datapower.py` | `datapower-analysis.md` | ⚠️ Partial | Missing some newer 0x80e... codes. |
| `enonic.py` | `enonic-xp-analysis.md` | ⚠️ Partial | Could use more "Common Incidents". |
| `python_log.py` | `python-logging-analysis.md` | ✅ Complete | Traceback patterns included. |
| `docker_json.py` | — | ❌ Missing | Relies on `json-structured-logs.md`. |
| `crio.py` | `openshift-k8s-analysis.md` | ✅ Complete | Covers CRI-O/K8s wrappers. |

---

## 2. Key Findings

### 2.1 Technical Depth (Strength)
The `database-errors.md` skill is a standout. It doesn't just list codes; it explains *why* they happen in a Java context (e.g., how WAS wraps ORA-00060 in a `DSRA0010E`). This is critical for root cause analysis.

### 2.2 Regex Mismatch (Risk)
Some skills suggest regex patterns that differ slightly from the implementation in `logpilot/formats/`.
*   *Example:* `datapower-analysis.md` suggests `DP_TS_RE`, but `logpilot/formats/datapower.py` uses a slightly different capture group structure.
*   *Fix:* Harmonize regex strings between `.md` skills and `.py` code to ensure AI and Parser "see" the same thing.

### 2.3 Cross-System Logic (Strength)
The `cross-system-analysis.md` skill is vital for the "Analyze All Logs" feature. it correctly identifies "Cascade" patterns where a failure in one system (DB) causes a hang in another (WAS) and a timeout in a third (Nginx).

---

## 3. Improvement Opportunities

### High Priority
1.  **Create `docker-analysis.md`**: Specifically for Docker/Containerd logs that aren't just pure JSON, covering common container lifecycle errors (OOMKilled, Exit 137).
2.  **Expand `enonic-xp-analysis.md`**: Add specific patterns for Elasticsearch issues within Enonic XP.

### Medium Priority
1.  **Update `datapower-analysis.md`**: Add 0x80b... (API Connect) and 0x80d... (AAA) specific error breakdowns.
2.  **Add "Solution Snippets"**: Include more copy-pasteable CLI commands for fixing issues (e.g., `db2pd` commands for DB2 deadlocks).

---

## 4. Prioritized Action Plan

1.  **Audit Harmonization**: Verify all `Signal Tags` mentioned in skills are actually implemented in the `bucket_tags()` methods of the corresponding Python plugins.
2.  **Skills Metadata**: Add a `compatibility` tag to the top of each Markdown file to explicitly link it to one or more `LogFormat` plugins.
3.  **New Skill**: Draft `container-orchestration.md` to cover the gap between raw logs and K8s/Docker runtime errors.

**Overall Grade: A-**
*Robust, deep, and actionable. Minor gaps in edge-case formats.*
