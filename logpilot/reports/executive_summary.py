"""Executive Summary report renderer — 1-page incident overview for management."""
from __future__ import annotations

from datetime import datetime

from ..analysis import precompute_analysis
from ..event import LogEvent
from .config import ReportConfig, _report_meta


def render_executive_summary(
    events: list[LogEvent] | ReportConfig | None = None,
    _analysis: dict | None = None,
    ai_content: dict | None = None,
    *,
    config: ReportConfig | None = None,
) -> str:
    """Generate a concise executive summary as Markdown.

    Designed to be converted to a 1-page PDF or shared with management.
    Contains only: incident overview, root cause, impact, failure chain,
    actions, and confidence — no raw data, no samples, no code.
    """
    if isinstance(events, ReportConfig):
        config = events
        events = None  # type: ignore[assignment]
    if config is not None:
        events = config.events  # type: ignore[assignment]
        _analysis = _analysis or config.analysis
        ai_content = ai_content if ai_content is not None else config.ai_content
    a = _analysis or precompute_analysis(events)
    s = a["summary"]
    _title, _subtitle = _report_meta(a)
    grouped = a.get("grouped")
    failure_chain = a.get("failure_chain", {})

    if not grouped:
        from ..heuristics import group_into_incidents, build_failure_chain
        grouped = group_into_incidents(a.get("causes", []), events=events)
        failure_chain = build_failure_chain(grouped.get("groups", []), a.get("cascades"))

    md: list[str] = []

    # Header
    md.append("# Incident Executive Summary")
    md.append(f"*{_subtitle}*")
    md.append(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*")
    md.append("")

    # Metrics bar
    level_counts = dict(s.get("levels", []))
    error_count = sum(level_counts.get(l, 0) for l in ("ERROR", "SEVERE", "FATAL"))
    warn_count = level_counts.get("WARNING", 0) + level_counts.get("WARN", 0)
    file_count = len(a.get("file_summary", []))
    md.append(f"| Events | Errors | Warnings | Files |")
    md.append(f"|--------|--------|----------|-------|")
    md.append(f"| {s['total_events']:,} | {error_count:,} | {warn_count:,} | {file_count} |")
    md.append("")

    # Primary incident
    groups = grouped.get("groups", [])
    primary = next((g for g in groups if g.get("is_primary")), None)

    if primary:
        conf = primary.get("confidence", {})
        conf_label = conf.get("label", "Medium")
        conf_score = conf.get("score", 0.5)

        md.append("## Root Cause")
        md.append(f"**{primary['name']}** — {conf_label} confidence ({conf_score:.0%})")
        md.append("")
        md.append(f"> {primary['narrative']}")
        md.append("")

        # Failure chain
        chain_text = failure_chain.get("chain_text", "")
        if chain_text:
            md.append("## Failure Chain")
            md.append(f"**{chain_text}**")
            md.append("")

        # Affected systems
        systems = primary.get("affected_systems", [])
        if systems:
            md.append(f"**Affected systems:** {', '.join(systems)}")
            md.append("")

        # Timeline
        ts = primary.get("first_trigger_ts")
        if ts:
            md.append(f"**Incident start:** {ts}")
            md.append("")

    # Impact summary
    md.append("## Impact")
    md.append(f"- **{error_count:,} errors** across {file_count} systems")
    if groups:
        md.append(f"- **{len(groups)} incident groups** detected")
        downstream = [g for g in groups if "downstream" in g.get("cascade_order", "")]
        concurrent = [g for g in groups if g.get("cascade_order") == "concurrent"]
        if downstream:
            md.append(f"- {len(downstream)} downstream cascade(s)")
        if concurrent:
            md.append(f"- {len(concurrent)} concurrent issue(s)")
    md.append("")

    # Secondary findings
    secondary = failure_chain.get("secondary_findings", [])
    if secondary:
        md.append("## Also Detected")
        for s_finding in secondary:
            md.append(f"- {s_finding}")
        md.append("")

    # Actions
    if primary:
        md.append("## Recommended Actions")
        action_num = 0
        for t in primary.get("triggers", []):
            for fix in t.get("fixes", [])[:2]:  # Top 2 fixes per trigger
                action_num += 1
                md.append(f"{action_num}. {fix}")
        md.append("")

        # Suggested team
        from ..heuristics import likely_causes
        _team_map = {
            "DBA": {"db-pool", "pg-deadlock", "pg-conn-limit", "pg-replication-fail",
                     "pg-temp-file", "ora-error", "db2-sqlcode", "mssql-error",
                     "mysql-error", "hikari-pool", "datasource-down"},
            "DevOps": {"k8s-crashloop", "k8s-oomkilled", "k8s-scheduling",
                       "k8s-node-pressure", "k8s-imagepull", "k8s-mount-fail",
                       "deploy-fail", "systemd-service-fail"},
            "Security": {"ssl-trust", "cert-expiry", "auth-failure-generic",
                         "authz-denied", "ssh-brute-force", "ldap-connection-fail"},
            "Network": {"connection-refused", "timeout-generic", "dns-resolution-fail",
                        "network-unreachable", "nginx-502"},
            "Developers": {"oom-gc", "repeated-exception", "session-error",
                           "servlet-error", "spring-startup-fail"},
            "Infra": {"oom-killer", "disk-full", "kernel-panic"},
        }
        trigger_ids = {t["id"] for t in primary.get("triggers", [])}
        suggested_teams = []
        for team, heuristic_ids in _team_map.items():
            if trigger_ids & heuristic_ids:
                suggested_teams.append(team)
        if suggested_teams:
            md.append(f"**Suggested team:** {', '.join(suggested_teams)}")
            md.append("")

    # Confidence table
    if groups:
        md.append("## Confidence Assessment")
        md.append("| Incident | Confidence | Role |")
        md.append("|----------|-----------|------|")
        for g in groups:
            conf = g.get("confidence", {})
            label = conf.get("label", "?")
            score = conf.get("score", 0)
            role = g.get("cascade_order", "")
            md.append(f"| {g['name']} | {label} ({score:.0%}) | {role} |")
        md.append("")

    # AI analysis (if available) — extract key sections, not just a snippet
    if ai_content and ai_content.get("incident"):
        ai_text = ai_content["incident"]
        md.append("## AI Analysis")
        md.append("")

        # Extract the most valuable sections from AI response
        _key_sections = [
            "## What Happened",
            "## Executive Summary",  # fallback for older AI responses
            "## Root Cause",
            "## Cascade Analysis",
            "## What To Do Now",
            "## Suggested Actions",  # fallback for older AI responses
            "## Missing Logs",
        ]
        _extracted = []
        for section_header in _key_sections:
            if section_header in ai_text:
                start = ai_text.index(section_header)
                end = ai_text.find("\n## ", start + len(section_header))
                section_text = ai_text[start:end].strip() if end > 0 else ai_text[start:].strip()
                # Limit each section to 1000 chars to keep it concise but meaningful
                if len(section_text) > 1000:
                    section_text = section_text[:1000].rsplit("\n", 1)[0] + "\n..."
                _extracted.append(section_text)

        if _extracted:
            md.append("\n\n".join(_extracted))
        else:
            # No structured sections found — include full AI text up to 2000 chars
            ai_excerpt = ai_text[:2000].strip()
            if len(ai_text) > 2000:
                ai_excerpt = ai_excerpt.rsplit("\n", 1)[0] + "\n..."
            md.append(ai_excerpt)
        md.append("")

    # Footer
    md.append("---")
    md.append("*Powered by LogPilot — [Item Consulting](https://item.no)*")

    return "\n".join(md)


def render_executive_summary_html(
    events: list[LogEvent] | ReportConfig | None = None,
    _analysis: dict | None = None,
    ai_content: dict | None = None,
    *,
    config: ReportConfig | None = None,
) -> str:
    """Generate executive summary as a styled HTML page."""
    from html import escape

    md_text = render_executive_summary(events, _analysis=_analysis, ai_content=ai_content, config=config)

    # Simple markdown → HTML conversion for the summary
    lines = md_text.split("\n")
    html_parts = ['<!DOCTYPE html><html><head><meta charset="UTF-8">']
    html_parts.append('<style>')
    html_parts.append('body{font-family:system-ui,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;color:#0F172A;line-height:1.6}')
    html_parts.append('h1{font-size:1.8rem;color:#7C3AED;border-bottom:3px solid #7C3AED;padding-bottom:8px}')
    html_parts.append('h2{font-size:1.2rem;color:#334155;margin-top:1.5rem}')
    html_parts.append('table{width:100%;border-collapse:collapse;margin:12px 0;font-size:0.9rem}')
    html_parts.append('th{background:#1E293B;color:white;padding:8px 12px;text-align:left}')
    html_parts.append('td{padding:6px 12px;border-bottom:1px solid #E2E8F0}')
    html_parts.append('blockquote{border-left:3px solid #7C3AED;padding:8px 16px;margin:12px 0;background:#F5F3FF;color:#334155}')
    html_parts.append('strong{color:#0F172A}')
    html_parts.append('em{color:#64748B}')
    html_parts.append('hr{border:none;border-top:1px solid #E2E8F0;margin:24px 0}')
    html_parts.append('ol,ul{padding-left:1.5rem}')
    html_parts.append('</style></head><body>')

    in_table = False
    for line in lines:
        if line.startswith("# "):
            html_parts.append(f"<h1>{escape(line[2:])}</h1>")
        elif line.startswith("## "):
            html_parts.append(f"<h2>{escape(line[3:])}</h2>")
        elif line.startswith("|") and "---" in line:
            continue  # table separator
        elif line.startswith("|"):
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if not in_table:
                html_parts.append("<table><thead><tr>")
                for c in cells:
                    html_parts.append(f"<th>{escape(c)}</th>")
                html_parts.append("</tr></thead><tbody>")
                in_table = True
            else:
                html_parts.append("<tr>")
                for c in cells:
                    # Bold markers
                    c_html = escape(c).replace("**", "")
                    html_parts.append(f"<td>{c_html}</td>")
                html_parts.append("</tr>")
        else:
            if in_table:
                html_parts.append("</tbody></table>")
                in_table = False
            if line.startswith("> "):
                html_parts.append(f"<blockquote>{escape(line[2:])}</blockquote>")
            elif line.startswith("- "):
                html_parts.append(f"<li>{escape(line[2:])}</li>")
            elif line.startswith("---"):
                html_parts.append("<hr>")
            elif line.startswith("*") and line.endswith("*"):
                html_parts.append(f"<p><em>{escape(line.strip('*'))}</em></p>")
            elif line.strip():
                # Handle **bold** in text
                safe = escape(line)
                html_parts.append(f"<p>{safe}</p>")

    if in_table:
        html_parts.append("</tbody></table>")

    html_parts.append("</body></html>")
    return "\n".join(html_parts)
