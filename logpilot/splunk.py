"""Splunk query generation and hung thread analysis."""
from __future__ import annotations

import re
from typing import Any

from .event import LogEvent
from .parser import (
    HUNG_THREAD_RE, HUNG_THREAD_NAME_RE, STACK_LINE_RE, CAUSED_BY_RE, WAS_CODE_RE,
)

_SPLUNK_PREFIX = 'index=APP sourcetype=WAS'


def _extract_hung_thread_name(text: str) -> str | None:
    """Extract thread name from a hung-thread event."""
    m = HUNG_THREAD_NAME_RE.search(text)
    if m:
        return next((g for g in m.groups() if g is not None), None)
    return None


def _extract_stack_sample(text: str, max_lines: int = 5) -> list[str]:
    """Extract up to max_lines of stack trace from event text."""
    lines: list[str] = []
    for line in text.splitlines():
        if STACK_LINE_RE.match(line) or CAUSED_BY_RE.match(line):
            lines.append(line.strip())
            if len(lines) >= max_lines:
                break
    return lines


def hung_thread_drilldown(events: list[LogEvent]) -> list[dict[str, Any]]:
    """Analyze hung/stuck thread events. Returns list of thread info dicts sorted by count."""
    threads: dict[str, dict] = {}

    for e in events:
        text = e.text or ""
        if not HUNG_THREAD_RE.search(text):
            continue

        thread_name = _extract_hung_thread_name(text)
        if not thread_name:
            thread_name = f"0x{e.thread_id}" if e.thread_id else "unknown"

        ts = e.ts

        if thread_name not in threads:
            threads[thread_name] = {
                "thread_name": thread_name,
                "count": 0,
                "first_ts": ts,
                "last_ts": ts,
                "hex_ids": set(),
                "stack_sample": [],
            }

        info = threads[thread_name]
        info["count"] += 1
        if ts:
            if not info["first_ts"]:
                info["first_ts"] = ts
            info["last_ts"] = ts
        if e.thread_id:
            info["hex_ids"].add(e.thread_id)
        if not info["stack_sample"]:
            info["stack_sample"] = _extract_stack_sample(text)

    results = []
    for info in threads.values():
        results.append({
            "thread_name": info["thread_name"],
            "count": info["count"],
            "first_ts": info["first_ts"],
            "last_ts": info["last_ts"],
            "hex_ids": sorted(info["hex_ids"]),
            "stack_sample": info["stack_sample"],
            "splunk_query": f'{_SPLUNK_PREFIX} "{info["thread_name"]}"',
        })
    results.sort(key=lambda r: -r["count"])
    return results


def suggested_splunk_queries(summary: dict, causes: list[dict], hist: list[tuple]) -> list[dict[str, str]]:
    """Generate Splunk query strings based on detected issues."""
    queries: list[dict[str, str]] = []

    queries.append({
        "description": "All errors and severe events",
        "query": f'{_SPLUNK_PREFIX} (ERROR OR SEVERE OR FATAL)',
    })

    for exc_name, count in summary.get("exceptions", [])[:3]:
        short = exc_name.rsplit(".", 1)[-1]
        queries.append({
            "description": f"Events matching {short} ({count} seen)",
            "query": f'{_SPLUNK_PREFIX} "{short}"',
        })

    seen_prefixes: set[str] = set()
    for code, count in summary.get("codes", [])[:5]:
        prefix = re.match(r'[A-Z]+', code)
        if prefix:
            p = prefix.group()
            if p not in seen_prefixes and len(seen_prefixes) < 3:
                seen_prefixes.add(p)
                queries.append({
                    "description": f"All {p}* message codes",
                    "query": f'{_SPLUNK_PREFIX} "{p}*"',
                })

    tag_queries = {
        "SSL/TLS": {
            "description": "SSL/TLS handshake failures",
            "query": f'{_SPLUNK_PREFIX} (SSLHandshakeException OR "PKIX path building failed" OR CWPKI*)',
        },
        "OOM/GC": {
            "description": "OutOfMemory and GC pressure events",
            "query": f'{_SPLUNK_PREFIX} (OutOfMemoryError OR "GC overhead limit exceeded" OR "Java heap space")',
        },
        "DB/Pool": {
            "description": "Connection pool exhaustion",
            "query": f'{_SPLUNK_PREFIX} (J2CA* OR "pool exhausted" OR "ConnectionWaitTimeout")',
        },
        "HungThreads": {
            "description": "Hung/stuck thread detections",
            "query": f'{_SPLUNK_PREFIX} (WSVR0605W OR WSVR0606W OR ThreadMonitor OR CWWKE0701E)',
        },
    }
    for tag, _ in summary.get("tags", []):
        if tag in tag_queries and tag_queries[tag] not in queries:
            queries.append(tag_queries[tag])

    if hist:
        queries.append({
            "description": "Error spike timeline (adjust span to match your bucket size)",
            "query": f'{_SPLUNK_PREFIX} (ERROR OR SEVERE OR FATAL) | timechart span=1m count by sourcetype',
        })

    return queries[:8]
