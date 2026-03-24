"""Jira ticket text generator — maps incident groups to structured ticket data.

Pure logic, no Streamlit dependency.  LogPilot fills in what it *knows*
from the analysis; the user supplies project, assignee, sprint, etc.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# ── Team suggestion mapping ───────────────────────────────────────────

TEAM_SUGGESTIONS: dict[str, list[str]] = {
    "DBA": [
        "db-pool", "pg-deadlock", "pg-conn-limit", "pg-replication-fail",
        "pg-temp-file", "ora-error", "db2-sqlcode", "mssql-error",
        "mysql-error", "hikari-pool", "datasource-down",
    ],
    "DevOps": [
        "k8s-crashloop", "k8s-oomkilled", "k8s-scheduling",
        "k8s-node-pressure", "k8s-imagepull", "k8s-mount-fail",
        "deploy-fail", "systemd-service-fail",
    ],
    "Security": [
        "ssl-trust", "cert-expiry", "auth-failure-generic",
        "authz-denied", "ssh-brute-force", "ldap-connection-fail",
    ],
    "Network": [
        "connection-refused", "timeout-generic", "dns-resolution-fail",
        "network-unreachable", "nginx-502",
    ],
    "Developers": [
        "oom-gc", "repeated-exception", "session-error",
        "servlet-error", "spring-startup-fail", "python-traceback",
        "celery-task-fail", "unhandled-rejection",
    ],
    "Infra": [
        "oom-killer", "disk-full", "kernel-panic", "syslog-service-fail",
    ],
    "Middleware": [
        "hung-threads", "transaction-timeout",
        "classloader", "jndi-lookup-fail",
    ],
    "Integration": [
        "http-5xx-generic", "http-4xx-spike",
        "nginx-rate-limit", "kafka-error",
    ],
}

# Reverse lookup: heuristic-id → team
_ID_TO_TEAM: dict[str, str] = {}
for _team, _ids in TEAM_SUGGESTIONS.items():
    for _hid in _ids:
        _ID_TO_TEAM[_hid] = _team

CONFIDENCE_TO_PRIORITY: dict[str, str] = {
    "High": "P2 Major",
    "Medium": "P2 Major",
    "Low": "P1 Critical",   # Low confidence = needs urgent investigation
}


def suggest_team(group: dict[str, Any]) -> str:
    """Return the most likely team name for an incident group."""
    team_votes: dict[str, int] = {}
    for item in group.get("triggers", []) + group.get("effects", []):
        hid = item.get("id", "")
        team = _ID_TO_TEAM.get(hid)
        if team:
            # Weight triggers higher than effects
            weight = 2 if item in group.get("triggers", []) else 1
            team_votes[team] = team_votes.get(team, 0) + weight
    if not team_votes:
        return "Unknown"
    return max(team_votes, key=team_votes.get)  # type: ignore[arg-type]


def generate_ticket_text(group: dict[str, Any], idx: int) -> dict[str, Any]:
    """Generate Jira ticket fields from one incident group.

    Args:
        group: One entry from group_into_incidents()["groups"]
        idx: 1-based step number

    Returns dict with: summary, description, priority, labels,
        suggested_team, confidence, cascade_order, group_id, group_name
    """
    from .heuristics import collect_group_evidence, build_failure_chain

    name = group.get("name", "Unknown Incident")
    confidence = group.get("confidence", {})
    conf_label = confidence.get("label", "Medium")
    conf_score = confidence.get("score", 0.5)
    cascade = group.get("cascade_order", "")
    narrative = group.get("narrative", "")
    first_ts = group.get("first_trigger_ts", "")
    systems = group.get("affected_systems", [])
    investigate = group.get("investigate_first", "")
    team = suggest_team(group)

    # Summary — short, actionable
    summary = f"Step {idx}: {name}"
    if cascade:
        summary += f" ({cascade})"

    # Failure chain — build_failure_chain expects a list of groups
    chain_text = ""
    chain = build_failure_chain([group])
    if chain.get("primary_chain"):
        chain_text = chain["chain_text"]

    # Evidence
    evidence_lines = collect_group_evidence(group)

    # Fixes from triggers
    fixes: list[str] = []
    for t in group.get("triggers", []):
        for f in t.get("fixes", []):
            if f not in fixes:
                fixes.append(f)
                if len(fixes) >= 5:
                    break
        if len(fixes) >= 5:
            break

    # Build markdown description
    parts = [
        f"## Incident: {name}",
        "",
        f"**Status**: {cascade} | **Confidence**: {conf_label} ({conf_score:.0%})",
    ]
    if first_ts:
        parts.append(f"**When**: {first_ts}")
    if systems:
        parts.append(f"**Affected systems**: {', '.join(systems)}")
    parts.append(f"**Suggested team**: {team}")
    parts.append("")

    if narrative:
        parts.append("### Root Cause")
        parts.append(narrative)
        parts.append("")

    if chain_text:
        parts.append("### Failure Chain")
        parts.append(chain_text)
        parts.append("")

    if evidence_lines:
        parts.append("### Evidence")
        for line in evidence_lines:
            parts.append(f"- {line}")
        parts.append("")

    if fixes:
        parts.append("### Acceptance Criteria")
        for f in fixes:
            parts.append(f"- [ ] {f}")
        parts.append("")

    if investigate:
        parts.append("### Investigation Directive")
        parts.append(investigate)
        parts.append("")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts.append("---")
    parts.append(f"*Generated by LogPilot — {now_str}*")

    description = "\n".join(parts)

    return {
        "summary": summary,
        "description": description,
        "priority": CONFIDENCE_TO_PRIORITY.get(conf_label, "P2 Major"),
        "labels": systems[:10],
        "suggested_team": team,
        "confidence": f"{conf_label} ({conf_score:.0%})",
        "cascade_order": cascade,
        "group_id": group.get("id", ""),
        "group_name": name,
    }


def generate_ungrouped_ticket(cause: dict[str, Any], idx: int) -> dict[str, Any]:
    """Generate a simpler ticket for an ungrouped finding."""
    title = cause.get("title", "Unknown")
    cause_text = cause.get("cause", "")
    fixes = cause.get("fixes", [])[:5]
    count = cause.get("count", 0)
    team = _ID_TO_TEAM.get(cause.get("id", ""), "Unknown")

    parts = [
        f"## Finding: {title}",
        "",
        f"**Occurrences**: {count}",
        f"**Suggested team**: {team}",
        "",
    ]
    if cause_text:
        parts.append("### Cause")
        parts.append(cause_text)
        parts.append("")
    if fixes:
        parts.append("### Acceptance Criteria")
        for f in fixes:
            parts.append(f"- [ ] {f}")
        parts.append("")

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts.append("---")
    parts.append(f"*Generated by LogPilot — {now_str}*")

    return {
        "summary": f"Finding: {title} ({count} occurrences)",
        "description": "\n".join(parts),
        "priority": "P3 Minor",
        "labels": [],
        "suggested_team": team,
        "confidence": "",
        "cascade_order": "",
        "group_id": cause.get("id", ""),
        "group_name": title,
    }


def generate_all_tickets(
    causes: list[dict[str, Any]],
    events: list | None = None,
    redaction_level: str = "standard",
) -> list[dict[str, Any]]:
    """Generate ticket dicts for all incident groups (+ ungrouped findings).

    Applies PII redaction to all text fields.
    Returns list ordered by incident rank.
    """
    from .heuristics import group_into_incidents

    grouped = group_into_incidents(causes, events=events)
    tickets: list[dict[str, Any]] = []

    for idx, g in enumerate(grouped.get("groups", []), 1):
        tickets.append(generate_ticket_text(g, idx))

    for cause in grouped.get("ungrouped", []):
        tickets.append(generate_ungrouped_ticket(cause, len(tickets) + 1))

    # Apply PII redaction to all text fields
    if redaction_level != "none":
        from .parser import redact
        for t in tickets:
            for key in ("summary", "description"):
                t[key] = redact(t[key], level=redaction_level)

    return tickets
