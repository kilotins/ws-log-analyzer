"""Jira & Confluence integration UI for the Streamlit GUI.

Renders ticket previews from incident analysis, handles clipboard copy,
and optionally creates issues via Jira REST API / publishes to Confluence.
"""
from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from base64 import b64encode
from typing import Any

import streamlit as st

_log = logging.getLogger(__name__)


# ── P1: Ticket preview & copy ─────────────────────────────────────────


def render_jira_tickets(causes: list[dict], analysis: dict) -> None:
    """Main entry point — render Jira ticket section in the report.

    Always available; Jira API features enabled only when credentials configured.
    """
    if not causes:
        return

    st.subheader("🎫 Jira Tickets")
    st.caption("Generate incident tickets with team suggestions — one per incident group")

    # Generate tickets (cached in session state)
    events = analysis.get("events")
    cache_key = f"_jira_tickets_{len(causes)}_{len(events or [])}"

    if st.session_state.get("_jira_cache_key") != cache_key:
        from logpilot.jira_tickets import generate_all_tickets
        import os
        redaction = os.environ.get("LOGPILOT_PII_LEVEL", "standard")
        tickets = generate_all_tickets(causes, events=events, redaction_level=redaction)
        st.session_state["_jira_tickets"] = tickets
        st.session_state["_jira_cache_key"] = cache_key
    else:
        tickets = st.session_state.get("_jira_tickets", [])

    if not tickets:
        st.info("No incident groups detected — ticket generation requires heuristic findings.")
        return

    # Show ticket count summary
    grouped = [t for t in tickets if t["summary"].startswith("Step")]
    ungrouped = [t for t in tickets if not t["summary"].startswith("Step")]
    summary_parts = []
    if grouped:
        summary_parts.append(f"{len(grouped)} incident tickets")
    if ungrouped:
        summary_parts.append(f"{len(ungrouped)} additional findings")
    st.write(f"**{' + '.join(summary_parts)}** generated from analysis")

    # Checkboxes + previews
    selected: list[int] = []
    for i, ticket in enumerate(tickets):
        col1, col2 = st.columns([0.05, 0.95])
        with col1:
            checked = st.checkbox("", value=True, key=f"_jira_sel_{i}", label_visibility="collapsed")
        with col2:
            team_badge = f"  `{ticket['suggested_team']}`" if ticket["suggested_team"] != "Unknown" else ""
            priority_badge = f"  {ticket['priority']}" if ticket["priority"] else ""
            st.markdown(f"**{ticket['summary']}**{team_badge}{priority_badge}")
        if checked:
            selected.append(i)

        # Editable preview (collapsed by default)
        with st.expander(f"Preview & edit ticket {i + 1}", expanded=False):
            edited_summary = st.text_input(
                "Summary", value=ticket["summary"], key=f"_jira_summary_{i}")
            edited_desc = st.text_area(
                "Description", value=ticket["description"], height=300, key=f"_jira_desc_{i}")
            edited_priority = st.selectbox(
                "Priority", ["P1 Critical", "P2 Major", "P3 Minor"],
                index=["P1 Critical", "P2 Major", "P3 Minor"].index(ticket["priority"])
                if ticket["priority"] in ["P1 Critical", "P2 Major", "P3 Minor"] else 1,
                key=f"_jira_priority_{i}")
            edited_labels = st.text_input(
                "Labels (comma-separated)",
                value=", ".join(ticket["labels"]), key=f"_jira_labels_{i}")
            # Store edits back
            tickets[i] = {
                **ticket,
                "summary": edited_summary,
                "description": edited_desc,
                "priority": edited_priority,
                "labels": [l.strip() for l in edited_labels.split(",") if l.strip()],
            }

    if not selected:
        st.info("Select at least one ticket above.")
        return

    # Action buttons
    col_copy, col_jira, col_confluence = st.columns(3)

    with col_copy:
        selected_tickets = [tickets[i] for i in selected]
        csv_data = _format_tickets_csv(selected_tickets)
        st.download_button(
            f"Export {len(selected)} ticket(s) as CSV",
            data=csv_data,
            file_name="jira_tickets.csv",
            mime="text/csv",
            use_container_width=True,
        )

    jira_configured = bool(
        st.session_state.get("_jira_url")
        and st.session_state.get("_jira_token")
        and st.session_state.get("_jira_project")
    )

    with col_jira:
        if jira_configured:
            if st.button(f"Create {len(selected)} ticket(s) in Jira",
                         type="primary", use_container_width=True):
                _create_jira_issues(selected_tickets)
        else:
            st.button("Create in Jira (configure in sidebar)", disabled=True,
                      use_container_width=True)

    confluence_configured = bool(
        st.session_state.get("_jira_url")
        and st.session_state.get("_jira_token")
        and st.session_state.get("_confluence_space")
    )

    with col_confluence:
        if confluence_configured:
            if st.button("Publish to Confluence", use_container_width=True):
                _publish_confluence_report(analysis)
        else:
            st.button("Publish to Confluence (configure in sidebar)", disabled=True,
                      use_container_width=True)


def _format_tickets_csv(tickets: list[dict]) -> str:
    """Format tickets as CSV for Jira CSV import.

    Columns match Jira's built-in CSV importer:
    Summary, Description, Priority, Labels, Issue Type, Component
    """
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Summary", "Description", "Priority", "Labels",
        "Issue Type", "Suggested Team",
    ])
    issue_type = st.session_state.get("_jira_issue_type", "Bug")
    for t in tickets:
        writer.writerow([
            t["summary"],
            t["description"],
            {"P1 Critical": "Critical", "P2 Major": "Major", "P3 Minor": "Minor"}.get(
                t["priority"], "Major"),
            " ".join(l.replace(" ", "-") for l in t["labels"]),
            issue_type,
            t["suggested_team"],
        ])
    return output.getvalue()


# ── Sidebar configuration ─────────────────────────────────────────────


def render_jira_sidebar() -> None:
    """Render the Integrations sidebar section."""
    jira_url = st.session_state.get("_jira_url", "")
    jira_token = st.session_state.get("_jira_token", "")
    _configured = bool(jira_url and jira_token)
    _label = "Integrations (Jira/Confluence)" + (" ✓" if _configured else "")

    with st.expander(_label, expanded=False):
        server_type = st.radio(
            "Jira type", ["Cloud", "Server/Data Center"],
            horizontal=True, key="_jira_type_radio",
            index=0 if st.session_state.get("_jira_server_type", "cloud") == "cloud" else 1,
        )
        st.session_state["_jira_server_type"] = "cloud" if server_type == "Cloud" else "server"

        _url = st.text_input(
            "Jira URL", value=st.session_state.get("_jira_url", ""),
            placeholder="https://mycompany.atlassian.net",
            key="_jira_url_input",
        )
        st.session_state["_jira_url"] = _url.rstrip("/")

        if server_type == "Cloud":
            _email = st.text_input(
                "Email", value=st.session_state.get("_jira_email", ""),
                placeholder="user@company.no", key="_jira_email_input",
            )
            st.session_state["_jira_email"] = _email

        _token = st.text_input(
            "API Token", value=st.session_state.get("_jira_token", ""),
            type="password", placeholder="your-api-token",
            key="_jira_token_input",
        )
        st.session_state["_jira_token"] = _token

        _project = st.text_input(
            "Default Project Key", value=st.session_state.get("_jira_project", ""),
            placeholder="OPS", key="_jira_project_input",
        )
        st.session_state["_jira_project"] = _project.upper() if _project else ""

        _issue_type = st.selectbox(
            "Issue Type", ["Bug", "Incident", "Task", "Story"],
            index=["Bug", "Incident", "Task", "Story"].index(
                st.session_state.get("_jira_issue_type", "Bug")),
            key="_jira_issue_type_input",
        )
        st.session_state["_jira_issue_type"] = _issue_type

        # Confluence section
        st.markdown("**Confluence**")
        _space = st.text_input(
            "Space Key", value=st.session_state.get("_confluence_space", ""),
            placeholder="INCIDENTS", key="_confluence_space_input",
        )
        st.session_state["_confluence_space"] = _space.upper() if _space else ""

        _parent = st.text_input(
            "Parent Page ID (optional)",
            value=st.session_state.get("_confluence_parent", ""),
            placeholder="12345678", key="_confluence_parent_input",
        )
        st.session_state["_confluence_parent"] = _parent

        # Test connection
        if _url and _token:
            if st.button("Test Connection", key="_jira_test_conn"):
                result = _test_jira_connection()
                if result.get("ok"):
                    projects = result.get("projects", [])
                    st.success(f"Connected! Found {len(projects)} projects: {', '.join(projects[:5])}")
                else:
                    st.error(f"Connection failed: {result.get('error', 'Unknown error')}")


# ── P2: Jira REST API ─────────────────────────────────────────────────


def _get_jira_auth() -> dict[str, str]:
    """Build auth headers for Jira API."""
    server_type = st.session_state.get("_jira_server_type", "cloud")
    token = st.session_state.get("_jira_token", "")
    if server_type == "cloud":
        email = st.session_state.get("_jira_email", "")
        cred = b64encode(f"{email}:{token}".encode()).decode()
        return {"Authorization": f"Basic {cred}", "Content-Type": "application/json"}
    else:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _jira_api_version() -> str:
    """Return '3' for Cloud, '2' for Server."""
    return "3" if st.session_state.get("_jira_server_type", "cloud") == "cloud" else "2"


def _test_jira_connection() -> dict[str, Any]:
    """Test Jira connectivity by fetching projects."""
    url = st.session_state.get("_jira_url", "")
    api_ver = _jira_api_version()
    try:
        req = urllib.request.Request(
            f"{url}/rest/api/{api_ver}/project?maxResults=10",
            headers=_get_jira_auth(),
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            projects = [p.get("key", "") for p in data] if isinstance(data, list) else []
            return {"ok": True, "projects": projects}
    except Exception as ex:
        return {"ok": False, "error": str(ex)}


def _build_description_adf(markdown_text: str) -> dict:
    """Convert markdown description to Atlassian Document Format (Cloud API v3)."""
    # ADF requires structured content; we use a code block for reliable rendering
    return {
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "codeBlock",
                "attrs": {"language": "markdown"},
                "content": [{"type": "text", "text": markdown_text}],
            }
        ],
    }


def _create_jira_issues(tickets: list[dict]) -> None:
    """Create Jira issues for selected tickets."""
    url = st.session_state.get("_jira_url", "")
    project = st.session_state.get("_jira_project", "")
    issue_type = st.session_state.get("_jira_issue_type", "Bug")
    api_ver = _jira_api_version()
    is_cloud = api_ver == "3"
    headers = _get_jira_auth()

    created_keys: list[str] = []
    errors: list[str] = []

    progress = st.progress(0, text="Creating tickets...")

    for i, ticket in enumerate(tickets):
        progress.progress((i + 1) / len(tickets), text=f"Creating ticket {i + 1}/{len(tickets)}...")

        # Build priority name (strip "P1 "/"P2 "/"P3 " prefix for Jira)
        priority_map = {"P1 Critical": "Critical", "P2 Major": "Major", "P3 Minor": "Minor"}
        jira_priority = priority_map.get(ticket["priority"], "Major")

        fields: dict[str, Any] = {
            "project": {"key": project},
            "summary": ticket["summary"][:255],  # Jira limit
            "issuetype": {"name": issue_type},
            "priority": {"name": jira_priority},
        }

        if ticket["labels"]:
            # Jira labels can't contain spaces
            fields["labels"] = [l.replace(" ", "-") for l in ticket["labels"][:10]]

        if is_cloud:
            fields["description"] = _build_description_adf(ticket["description"])
        else:
            fields["description"] = ticket["description"]

        payload = json.dumps({"fields": fields}).encode()

        try:
            req = urllib.request.Request(
                f"{url}/rest/api/{api_ver}/issue",
                data=payload, headers=headers, method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                key = data.get("key", "")
                created_keys.append(key)
                _log.info("jira Created %s for '%s'", key, ticket["summary"][:50])
        except urllib.error.HTTPError as ex:
            body = ex.read().decode("utf-8", errors="replace")[:500]
            errors.append(f"Ticket '{ticket['summary'][:50]}': {ex.code} — {body}")
            _log.error("jira Failed: %s %s", ex.code, body[:200])
        except Exception as ex:
            errors.append(f"Ticket '{ticket['summary'][:50]}': {ex}")

    progress.empty()

    # Link tickets (root cause → downstream)
    if len(created_keys) >= 2:
        _link_jira_issues(created_keys, url, api_ver, headers)

    # Show results
    if created_keys:
        links = [f"[{k}]({url}/browse/{k})" for k in created_keys]
        st.success(f"Created {len(created_keys)} ticket(s): {', '.join(links)}")
    if errors:
        for err in errors:
            st.error(err)


def _link_jira_issues(keys: list[str], url: str, api_ver: str, headers: dict) -> None:
    """Create 'Causes' links between tickets: first → rest."""
    root_key = keys[0]
    for downstream_key in keys[1:]:
        payload = json.dumps({
            "type": {"name": "Causes"},
            "inwardIssue": {"key": root_key},
            "outwardIssue": {"key": downstream_key},
        }).encode()
        try:
            req = urllib.request.Request(
                f"{url}/rest/api/{api_ver}/issueLink",
                data=payload, headers=headers, method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as ex:
            _log.warning("jira Link %s→%s failed: %s", root_key, downstream_key, ex)


# ── P3: Confluence publishing ──────────────────────────────────────────


def _html_to_confluence_storage(html: str) -> str:
    """Convert LogPilot HTML report to Confluence Storage Format.

    Strips CSS/JS, converts unsupported tags to Confluence macros.
    """
    import re
    # Remove <style> and <script> blocks
    result = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
    result = re.sub(r'<script[^>]*>.*?</script>', '', result, flags=re.DOTALL)

    # Convert <details><summary>X</summary>Y</details> → Confluence expand macro
    def _expand_repl(m):
        title = m.group(1).strip()
        body = m.group(2).strip()
        return (
            f'<ac:structured-macro ac:name="expand">'
            f'<ac:parameter ac:name="title">{title}</ac:parameter>'
            f'<ac:rich-text-body>{body}</ac:rich-text-body>'
            f'</ac:structured-macro>'
        )
    result = re.sub(
        r'<details[^>]*>\s*<summary>(.*?)</summary>(.*?)</details>',
        _expand_repl, result, flags=re.DOTALL,
    )

    # Convert <pre><code>X</code></pre> → Confluence code macro
    def _code_repl(m):
        code = m.group(1)
        return (
            f'<ac:structured-macro ac:name="code">'
            f'<ac:plain-text-body><![CDATA[{code}]]></ac:plain-text-body>'
            f'</ac:structured-macro>'
        )
    result = re.sub(
        r'<pre[^>]*>\s*<code[^>]*>(.*?)</code>\s*</pre>',
        _code_repl, result, flags=re.DOTALL,
    )

    # Remove remaining HTML/head/body wrapper (keep content)
    result = re.sub(r'</?(?:html|head|body|meta|link|title)[^>]*>', '', result)
    # Remove class/style/id attributes (Confluence ignores them)
    result = re.sub(r'\s+(?:class|style|id|data-\w+)="[^"]*"', '', result)

    return result.strip()


def _publish_confluence_report(analysis: dict) -> None:
    """Publish the HTML report to Confluence as a wiki page."""
    from logpilot import render_html_report, ReportConfig

    url = st.session_state.get("_jira_url", "").rstrip("/")
    space = st.session_state.get("_confluence_space", "")
    parent_id = st.session_state.get("_confluence_parent", "")
    headers = _get_jira_auth()

    events = analysis.get("events", [])
    if not events:
        st.error("No events to publish.")
        return

    with st.spinner("Generating and publishing report..."):
        # Generate HTML report
        cfg = ReportConfig(
            events=events,
            top_n=analysis.get("top_n", 10),
            samples_n=analysis.get("samples_n", 5),
            hist_minutes=analysis.get("hist_minutes", 1),
            analysis=analysis,
        )
        html_report = render_html_report(cfg)
        storage_body = _html_to_confluence_storage(html_report)

        # Build title
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        primary_name = ""
        grouped = analysis.get("grouped", {})
        if isinstance(grouped, dict):
            groups = grouped.get("groups", [])
            if groups:
                primary_name = groups[0].get("name", "")
        title = f"Incident Report — {primary_name} ({now})" if primary_name else f"LogPilot Incident Report ({now})"

        # Create page
        page_data: dict[str, Any] = {
            "type": "page",
            "title": title,
            "space": {"key": space},
            "body": {
                "storage": {
                    "value": storage_body,
                    "representation": "storage",
                }
            },
        }
        if parent_id:
            page_data["ancestors"] = [{"id": parent_id}]

        api_base = f"{url}/wiki/rest/api/content" if "atlassian.net" in url else f"{url}/rest/api/content"

        try:
            req = urllib.request.Request(
                api_base, data=json.dumps(page_data).encode(),
                headers=headers, method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                page_id = data.get("id", "")
                page_url = data.get("_links", {}).get("base", url) + data.get("_links", {}).get("webui", "")
                st.success(f"Published: [{title}]({page_url})")
                _log.info("confluence Published page %s: %s", page_id, title)

                # Store for cross-linking
                st.session_state["_confluence_page_url"] = page_url
                st.session_state["_confluence_page_id"] = page_id
        except urllib.error.HTTPError as ex:
            body = ex.read().decode("utf-8", errors="replace")[:500]
            st.error(f"Confluence publish failed: {ex.code} — {body}")
        except Exception as ex:
            st.error(f"Confluence publish failed: {ex}")
