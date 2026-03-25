# Skills Review For Claude

Date: 2026-03-25
Scope: `skills/*.md`, selected project docs, and the skill-selection code in `logpilot/ai.py`

## Summary

The project skill set is strong overall. Coverage is broad, the best files are deep and practical, and the material is clearly written for incident triage rather than generic documentation.

The main problems are not content quality. They are integration and consistency problems:

- A new Docker skill exists but is not actually selected for Docker logs.
- The current selection logic still favors older WAS-centric skills for generic tags.
- The test suite does not cover format-to-skill mapping well enough to catch these regressions.
- Some project documentation about skills is stale and now misleading.

## Findings

### 1. High: Docker skill exists but is unreachable for Docker format selection

The dedicated Docker skill is present at `skills/docker-analysis.md`, but `logpilot/ai.py` still maps the `docker_json` format to `json-structured-logs.md` instead of the Docker skill.

Evidence:

- `skills/docker-analysis.md` exists and is a dedicated domain skill.
- `logpilot/ai.py` maps:

```python
"docker_json": ["json-structured-logs.md"],
```

Impact:

- Docker/container-specific guidance like `OOMKilled`, `CrashLoopBackOff`, `ImagePullBackOff`, and lifecycle interpretation is skipped.
- AI responses for Docker logs will lean generic JSON instead of container/runtime diagnostics.

Recommendation:

- Change `docker_json` to select `docker-analysis.md`.
- Optionally keep `json-structured-logs.md` as a secondary skill if you want both wrapper parsing context and container triage context.

### 2. Medium: Generic tag mapping is still too WAS-centric for a multi-format product

The format coverage in `skills/` is broader than the generic tag routing in `logpilot/ai.py`.

Examples from `_SKILL_TAG_MAP`:

- `DB/Pool` routes to `message-codes.md` and `jms-messaging.md`
- `HTTP` routes to `servlet-errors.md` and `message-codes.md`
- `SSL/TLS` routes only to `security-analysis.md`

Impact:

- Tag-driven prompts for nginx, Tomcat, PostgreSQL, Docker, DataPower, and OpenShift can miss the most relevant domain skill unless format detection also succeeds.
- If the user asks a free-text question without strong format context, the AI may overfit to Java/WAS patterns.

Examples:

- `HTTP` on nginx logs should strongly favor `nginx-analysis.md`.
- `DB/Pool` on PostgreSQL or Docker-wrapped app logs could benefit from `database-errors.md`, `postgresql-log-analysis.md`, or `docker-analysis.md`.
- `SSL/TLS` on DataPower or nginx often needs domain-specific interpretation beyond the generic security skill.

Recommendation:

- Keep the generic tag map, but expand it to include modern non-WAS skills.
- Prefer combining generic skills with format-specific skills, not replacing one with the other.

### 3. Medium: Test coverage misses format-mapping regressions

The current tests in `tests/test_ai_prompt.py` cover tags, code prefixes, exceptions, fallback behavior, and query keywords. They do not appear to directly assert the expected skill selection for newer detected formats such as Docker, DataPower, PostgreSQL, Tomcat, OpenShift, or Enonic.

Impact:

- The Docker mapping regression slipped through even though the dedicated skill file now exists.
- Future additions to `_SKILL_FORMAT_MAP` can drift from the actual skill inventory with no direct failing test.

Recommendation:

- Add explicit tests for `select_skills(..., detected_format=...)` covering all registered format names.
- Add one assertion per format for the expected primary skill.
- Add a regression test specifically for `docker_json -> docker-analysis.md`.

### 4. Medium: Query-keyword routing is uneven across the newer domains

`_SKILL_QUERY_KEYWORDS` contains solid coverage for Liberty, deployment, threads, security, GC, JMS, Enonic, and cross-system analysis. It is comparatively thin for newer format families such as Docker, Tomcat, PostgreSQL, DataPower, syslog, nginx, and OpenShift/Kubernetes.

Impact:

- Users asking direct questions like "why is tomcat returning severe connector errors" or "postgres deadlock" may not get the most specific skill unless a parsed format is already available.
- This is a product fit problem rather than a parser problem.

Recommendation:

- Add a small set of domain keywords for each newer format family.
- Keep it minimal. You do not need exhaustive keyword lists, only the obvious high-signal terms.

Suggested examples:

- Docker: `oomkilled`, `crashloop`, `imagepullbackoff`, `containerd`
- Tomcat: `catalina`, `coyote`, `dbcp`, `http-nio`
- PostgreSQL: `sqlstate`, `deadlock detected`, `remaining connection slots`
- DataPower: `mpgw`, `apiconnect`, `aaa`, `0x80e`
- OpenShift/K8s: `pod`, `route`, `init container`, `readiness probe`

### 5. Low: Skill structure is good, but not standardized enough

The skills are readable and useful, but they are not normalized to a shared shape.

Examples:

- Some files include `Signal Tags`, `Triage Strategy`, `Incident Response Playbook`, and `See Also`.
- Others omit one or more of those sections entirely.
- `cross-system-analysis.md` is concise and useful, but much thinner than the rest of the collection.
- `message-codes.md` is important but structurally lighter than the strongest domain skills.

Impact:

- Human maintainers get an uneven editing experience.
- AI prompt quality may vary based on which files are selected together.

Recommendation:

- Define a lightweight skill template and gradually align the files.
- Do not over-normalize. The goal is predictable utility, not identical document length.

Suggested baseline sections:

1. Overview
2. Detection or log format notes
3. High-impact patterns
4. Signal tags
5. Triage strategy
6. Related skills or see also

### 6. Low: Claude-facing project documentation is stale

`CLAUDE.md` still describes the project as having 8 format plugins even though `README.md` describes 14. It also lists several `.claude/skills` entries that were not visible in the project tree I reviewed.

Impact:

- A Claude-based workflow can start from incorrect assumptions about the product surface.
- Skill discovery from documentation becomes less trustworthy.

Recommendation:

- Update `CLAUDE.md` to match the current plugin inventory and actual skill locations.
- Treat it as operational context, not archival documentation.

### 7. Low: Existing audit output is stale and should not be treated as authoritative

`SKILLS_AUDIT.md` still says `docker-analysis.md` is missing, but the file now exists.

Impact:

- Maintainers may use an outdated audit as planning input.

Recommendation:

- Refresh or archive the audit report.
- If audits are generated by AI, mark them with scope and freshness warnings.

## Strengths

These are the strongest qualities in the current skill set:

- `skills/database-errors.md` is unusually strong. It ties database error codes to Java/WAS wrapping behavior instead of just listing codes.
- `skills/gc-performance.md` is detailed, operational, and grounded in actual triage workflows.
- `skills/openshift-k8s-analysis.md`, `skills/syslog-analysis.md`, and `skills/enonic-xp-analysis.md` expand the product beyond the original WAS focus in a useful way.
- Several skills include practical Splunk queries and incident playbooks, which is high-value prompt material.

## Prioritized Actions

### Immediate

1. Fix `docker_json` mapping in `logpilot/ai.py`.
2. Add tests for all format-to-skill mappings.
3. Refresh `CLAUDE.md` and `SKILLS_AUDIT.md`.

### Next

1. Expand generic tag routing so it is less WAS-centric.
2. Add minimal query-keyword coverage for Docker, Tomcat, PostgreSQL, DataPower, and OpenShift/K8s.

### Later

1. Introduce a lightweight skill template.
2. Bring thinner files like `cross-system-analysis.md` and `message-codes.md` closer to the standard sections where it adds value.

## Bottom Line

The content quality is already good enough to support a strong AI-assisted triage experience. The highest leverage work now is not writing many new skills. It is tightening the routing, tests, and Claude-facing documentation so the right skill is actually selected at the right time.
