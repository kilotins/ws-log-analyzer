"""Heuristic pattern matching, correlations, incident grouping, and burst detection."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from .event import LogEvent

_log = logging.getLogger(__name__)

from .event import ERROR_LEVELS  # noqa: F401


def _load_heuristics_from_yaml() -> tuple[list[dict] | None, list[dict] | None, list[dict] | None]:
    """Load heuristics, correlations, and incident groups from YAML data file.

    Tries logpilot/heuristics_data.yaml first (structured format with top-level keys),
    then falls back to the legacy heuristics.yaml (flat list, heuristics only).

    Returns (heuristics, correlations, incident_groups) — any may be None if unavailable.
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return None, None, None

    # Try new structured data file first
    yaml_path = Path(__file__).parent / "heuristics_data.yaml"
    if not yaml_path.is_file():
        # Fall back to legacy flat file
        yaml_path = Path(__file__).parent.parent / "heuristics.yaml"
        if not yaml_path.is_file():
            return None, None, None

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return None, None, None

    # Structured format (dict with top-level keys)
    if isinstance(data, dict):
        heuristics = _compile_heuristics(data.get("heuristics", []))
        correlations = data.get("correlations")
        incident_groups = _compile_incident_groups(data.get("incident_groups"))
        return heuristics, correlations, incident_groups

    # Legacy flat list format (heuristics only)
    if isinstance(data, list):
        return _compile_heuristics(data), None, None

    return None, None, None


def _compile_heuristics(entries: list[dict] | None) -> list[dict] | None:
    """Compile regex patterns in heuristic entries loaded from YAML."""
    if not entries:
        return None
    try:
        heuristics = []
        for entry in entries:
            heuristics.append({
                "id": entry["id"],
                "title": entry["title"],
                "match": re.compile(entry["pattern"], re.IGNORECASE),
                "cause": entry["cause"],
                "fixes": entry["fixes"],
            })
        return heuristics
    except (KeyError, TypeError, ValueError):
        return None


def _compile_incident_groups(entries: list[dict] | None) -> list[dict] | None:
    """Convert incident group lists from YAML to sets for trigger_ids/effect_ids."""
    if not entries:
        return None
    try:
        groups = []
        for entry in entries:
            groups.append({
                "id": entry["id"],
                "name": entry["name"],
                "trigger_ids": set(entry["trigger_ids"]),
                "effect_ids": set(entry["effect_ids"]),
                "narrative": entry["narrative"],
            })
        return groups
    except (KeyError, TypeError):
        return None


def _load_all_data() -> tuple[list[dict], list[dict[str, Any]], list[dict[str, Any]]]:
    """Load heuristics, correlations, and incident groups from YAML or fallback.

    Returns (heuristics, correlations, incident_groups) — always populated.
    """
    from ._heuristics_fallback import (
        _HEURISTICS_INLINE,
        _CORRELATIONS_INLINE,
        _INCIDENT_GROUPS_INLINE,
    )

    yaml_h, yaml_c, yaml_ig = _load_heuristics_from_yaml()

    # Heuristics: YAML overrides inline by id; inline-only entries are kept
    if yaml_h:
        yaml_ids = {h["id"] for h in yaml_h}
        heuristics = yaml_h + [h for h in _HEURISTICS_INLINE if h["id"] not in yaml_ids]
        _log.debug("Loaded %d heuristics from YAML (%d from fallback)", len(yaml_h),
                    len(heuristics) - len(yaml_h))
    else:
        heuristics = _HEURISTICS_INLINE
        _log.debug("Using fallback inline heuristics (%d entries)", len(heuristics))

    correlations = yaml_c if yaml_c is not None else _CORRELATIONS_INLINE
    incident_groups = yaml_ig if yaml_ig is not None else _INCIDENT_GROUPS_INLINE

    return heuristics, correlations, incident_groups


_HEURISTICS, _CORRELATIONS, _INCIDENT_GROUPS = _load_all_data()


# ── P1: Evidence extraction regexes ─────────────────────────────────

_IP_PORT_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)\b')
_DURATION_RE = re.compile(r'(\d[\d,]*)\s*(ms|milliseconds?|seconds?|s)\b', re.IGNORECASE)
_HOSTNAME_RE = re.compile(r'(?:upstream|connecting to|host)\s+["\']?([a-zA-Z][a-zA-Z0-9._-]*\.[a-zA-Z0-9._-]+(?::\d+)?)', re.IGNORECASE)


def extract_evidence(events: list[LogEvent], match_re: re.Pattern) -> dict[str, Any]:  # type: ignore[type-arg]
    """Extract concrete details from events matching a heuristic pattern.

    Returns dict with first/last timestamps, affected systems, IP addresses,
    durations, hostnames, and a sample line — all extracted from the actual events.
    """
    from .analysis import normalize_ts_utc

    first_ts: str | None = None
    last_ts: str | None = None
    first_dt = None
    last_dt = None
    systems: set[str] = set()
    ips: set[str] = set()
    hostnames: set[str] = set()
    durations: list[str] = []
    exceptions: set[str] = set()
    threads: set[str] = set()
    sample_line: str = ""

    for e in events:
        text = e.text or ""
        if not match_re.search(text):
            continue

        # Timestamps
        if e.ts_utc or e.ts:
            dt = normalize_ts_utc(e.ts, tz_hint=e.tz_hint)
            if dt:
                if first_dt is None or dt < first_dt:
                    first_dt = dt
                    first_ts = e.ts_utc or e.ts
                if last_dt is None or dt > last_dt:
                    last_dt = dt
                    last_ts = e.ts_utc or e.ts

        # Systems
        if e.system_label:
            systems.add(e.system_label)

        # IPs
        for m in _IP_PORT_RE.finditer(text):
            ip = m.group(1)
            if not ip.startswith("0.") and not ip.startswith("127."):
                ips.add(ip)

        # Durations
        for m in _DURATION_RE.finditer(text):
            durations.append(f"{m.group(1)} {m.group(2)}")

        # Hostnames (exclude bare IPs — those go in ip_addresses)
        for m in _HOSTNAME_RE.finditer(text):
            host = m.group(1)
            if not re.match(r'^\d{1,3}(\.\d{1,3}){3}', host):
                hostnames.add(host)

        # Exceptions
        if e.exception:
            short = e.exception.rsplit(".", 1)[-1] if "." in e.exception else e.exception
            exceptions.add(short)

        # Threads
        if e.thread_id:
            threads.add(e.thread_id)

        # Sample line (first match, truncated)
        if not sample_line:
            first_line = text.split("\n")[0][:200]
            sample_line = first_line

    span_seconds = None
    if first_dt and last_dt:
        span_seconds = (last_dt - first_dt).total_seconds()

    return {
        "first_ts": first_ts,
        "last_ts": last_ts,
        "span_seconds": span_seconds,
        "affected_systems": sorted(systems),
        "ip_addresses": sorted(ips)[:5],
        "hostnames": sorted(hostnames)[:5],
        "durations": durations[:5],
        "exceptions": sorted(exceptions)[:5],
        "threads": sorted(threads)[:5],
        "sample_line": sample_line,
    }


# ── P2: Incident ranking ───────────────────────────────────────────


def rank_incident_groups(groups: list[dict[str, Any]], causes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank incident groups by temporal order and causal depth.

    Determines which group is the root cause (earliest triggers, no upstream parent)
    and labels others as downstream or concurrent.

    Mutates groups in-place and returns them sorted by rank.
    """
    if not groups:
        return groups

    # Collect all trigger/effect IDs per group
    group_trigger_ids = []
    group_effect_ids = []
    for g in groups:
        tids = {t["id"] for t in g.get("triggers", [])}
        eids = {e["id"] for e in g.get("effects", [])}
        group_trigger_ids.append(tids)
        group_effect_ids.append(eids)

    # Build causal depth: if group A's triggers appear as group B's effects, A is downstream of B
    for i, g in enumerate(groups):
        g["_upstream_of"] = set()
        for j, other in enumerate(groups):
            if i == j:
                continue
            # If my triggers are effects of another group, that group is my upstream
            if group_trigger_ids[i] & group_effect_ids[j]:
                g["_upstream_of"].add(j)

    # Find root groups (no upstream parent)
    root_ids = {id(g) for g in groups if not g["_upstream_of"]}

    # Temporal ordering: earliest first_trigger_ts
    for g in groups:
        evidence_list = [t.get("evidence", {}) for t in g.get("triggers", []) if t.get("evidence")]
        timestamps = [ev.get("first_ts") for ev in evidence_list if ev.get("first_ts")]
        g["first_trigger_ts"] = min(timestamps) if timestamps else None

        # Collect affected systems from all triggers + effects
        all_systems: set[str] = set()
        for item in g.get("triggers", []) + g.get("effects", []):
            ev = item.get("evidence", {})
            all_systems.update(ev.get("affected_systems", []))
        g["affected_systems"] = sorted(all_systems)

    # Sort: roots first (by timestamp), then downstream (by timestamp)
    def _sort_key(g):
        is_root = id(g) in root_ids
        ts = g.get("first_trigger_ts") or "9999"
        return (0 if is_root else 1, ts)

    groups.sort(key=_sort_key)

    # Assign rank and cascade labels
    primary_name = groups[0]["name"] if groups else ""
    for rank, g in enumerate(groups, 1):
        g["rank"] = rank
        is_root = id(g) in root_ids

        if rank == 1:
            g["is_primary"] = True
            g["cascade_order"] = "root cause"
        elif is_root:
            g["is_primary"] = False
            g["cascade_order"] = "concurrent"
        else:
            g["is_primary"] = False
            g["cascade_order"] = f"downstream of {primary_name}"

        # Build investigate_first directive
        trigger_names = [t["title"] for t in g.get("triggers", [])][:2]
        trigger_str = ", ".join(trigger_names) if trigger_names else "unknown"
        systems_str = ", ".join(g.get("affected_systems", [])[:3]) or "unknown"
        ts_str = g.get("first_trigger_ts", "")

        if g.get("is_primary"):
            g["investigate_first"] = f"Start here: check {systems_str} around {ts_str} for {trigger_str}"
        elif g["cascade_order"] == "concurrent":
            g["investigate_first"] = f"Separate issue — investigate {systems_str} independently"
        else:
            g["investigate_first"] = f"Likely caused by {primary_name}. Fix that first."

    # Clean internal fields
    for g in groups:
        g.pop("_upstream_of", None)

    return groups


# ── P3: Narrative builder ───────────────────────────────────────────


def build_narrative(group: dict[str, Any]) -> str:
    """Build a rich narrative for an incident group using extracted evidence.

    Replaces the static narrative template with one that includes specific
    timestamps, systems, IPs, and cascade information.
    """
    parts: list[str] = []
    triggers = group.get("triggers", [])
    effects = group.get("effects", [])
    cascade_order = group.get("cascade_order", "")
    first_ts = group.get("first_trigger_ts", "")

    # Opening: what and when
    trigger_names = [t["title"] for t in triggers]
    systems = group.get("affected_systems", [])

    if first_ts:
        ts_short = first_ts.split("T")[-1][:8] if "T" in first_ts else first_ts
        parts.append(f"Starting at {ts_short}")
    if systems:
        parts.append(f"on {', '.join(systems[:3])}")

    # What triggered it
    if trigger_names:
        parts.append(f"— {', '.join(trigger_names[:2])} detected")

    # Specific evidence from triggers
    all_ips: list[str] = []
    all_durations: list[str] = []
    for t in triggers:
        ev = t.get("evidence", {})
        all_ips.extend(ev.get("ip_addresses", []))
        all_durations.extend(ev.get("durations", []))

    if all_ips:
        unique_ips = sorted(set(all_ips))[:2]
        parts.append(f"(target: {', '.join(unique_ips)})")
    if all_durations:
        parts.append(f"[{', '.join(all_durations[:2])}]")

    # Effects cascade
    if effects:
        effect_summary = []
        for e in effects[:4]:
            ev = e.get("evidence", {})
            sys_str = ""
            if ev.get("affected_systems"):
                sys_str = f" on {', '.join(ev['affected_systems'][:2])}"
            effect_summary.append(f"{e['title']} ({e['count']}){sys_str}")
        parts.append(f". This cascaded to: {'; '.join(effect_summary)}.")
    else:
        parts.append(".")

    # Total impact
    total = group.get("total_count", 0)
    if total and systems:
        parts.append(f" {total} events across {len(systems)} system{'s' if len(systems) != 1 else ''}.")

    narrative = " ".join(parts)
    # Clean up double spaces and awkward punctuation
    narrative = narrative.replace(" .", ".").replace("..", ".").replace("  ", " ")
    return narrative


def _merge_evidence(evidence_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge evidence from multiple contributing causes (for correlations)."""
    merged: dict[str, Any] = {
        "first_ts": None, "last_ts": None, "span_seconds": None,
        "affected_systems": [], "ip_addresses": [], "hostnames": [],
        "durations": [], "exceptions": [], "threads": [], "sample_line": "",
    }
    all_systems: set[str] = set()
    all_ips: set[str] = set()
    all_hostnames: set[str] = set()
    for ev in evidence_list:
        if not ev:
            continue
        ts = ev.get("first_ts")
        if ts and (merged["first_ts"] is None or ts < merged["first_ts"]):
            merged["first_ts"] = ts
        ts = ev.get("last_ts")
        if ts and (merged["last_ts"] is None or ts > merged["last_ts"]):
            merged["last_ts"] = ts
        all_systems.update(ev.get("affected_systems", []))
        all_ips.update(ev.get("ip_addresses", []))
        all_hostnames.update(ev.get("hostnames", []))
        merged["durations"].extend(ev.get("durations", []))
        merged["exceptions"].extend(ev.get("exceptions", []))
        merged["threads"].extend(ev.get("threads", []))
        if not merged["sample_line"] and ev.get("sample_line"):
            merged["sample_line"] = ev["sample_line"]
    merged["affected_systems"] = sorted(all_systems)
    merged["ip_addresses"] = sorted(all_ips)[:5]
    merged["hostnames"] = sorted(all_hostnames)[:5]
    merged["durations"] = merged["durations"][:5]
    merged["exceptions"] = sorted(set(merged["exceptions"]))[:5]
    merged["threads"] = sorted(set(merged["threads"]))[:5]
    return merged


# ── M54: Confidence scoring ────────────────────────────────────────


def compute_confidence(
    group: dict[str, Any],
    events: list[LogEvent] | None = None,
) -> dict[str, Any]:
    """Compute confidence score for an incident group.

    Returns {"score": float 0-1, "label": "Low"/"Medium"/"High", "factors": list[str]}.
    """
    if events is None:
        return {"score": 0.50, "label": "Medium", "factors": ["default (no events provided)"]}

    factors: list[str] = []
    score = 0.10
    factors.append("base +0.10")

    # Frequency
    total = group.get("total_count", 0)
    freq = min(total / 50, 0.25)
    if freq > 0:
        score += freq
        factors.append(f"frequency ({total} events) +{freq:.2f}")

    # Cascade depth
    effects = group.get("effects", [])
    depth = min(len(effects) * 0.05, 0.15)
    if depth > 0:
        score += depth
        factors.append(f"cascade depth ({len(effects)} effects) +{depth:.2f}")

    # System spread
    systems = group.get("affected_systems", [])
    spread = min(len(systems) * 0.05, 0.15)
    if spread > 0:
        score += spread
        factors.append(f"system spread ({len(systems)} systems) +{spread:.2f}")

    # Primary flag
    if group.get("is_primary"):
        score += 0.10
        factors.append("primary incident +0.10")

    # Cross-system corroboration: same IP/hostname in events from 2+ systems
    trigger_ips: set[str] = set()
    trigger_hosts: set[str] = set()
    for t in group.get("triggers", []):
        ev = t.get("evidence", {})
        trigger_ips.update(ev.get("ip_addresses", []))
        trigger_hosts.update(ev.get("hostnames", []))

    targets = trigger_ips | trigger_hosts
    if targets:
        systems_with_target: set[str] = set()
        for e in events:
            text = (e.text or "").lower()
            for target in targets:
                if target.lower() in text:
                    label = e.system_label or ""
                    if label:
                        systems_with_target.add(label)
                    break
        if len(systems_with_target) >= 2:
            score += 0.15
            factors.append(f"cross-system corroboration ({len(systems_with_target)} systems share target) +0.15")

    # Trace correlation: shared trace ID pattern across systems
    _trace_re = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
    trigger_traces: set[str] = set()
    for t in group.get("triggers", []):
        sample = t.get("evidence", {}).get("sample_line", "")
        trigger_traces.update(_trace_re.findall(sample))

    if trigger_traces:
        trace_systems: set[str] = set()
        for e in events:
            text = e.text or ""
            for tid in trigger_traces:
                if tid in text:
                    label = e.system_label or ""
                    if label:
                        trace_systems.add(label)
                    break
        if len(trace_systems) >= 2:
            score += 0.10
            factors.append(f"trace correlation ({len(trace_systems)} systems share trace ID) +0.10")

    score = min(score, 1.0)
    if score < 0.35:
        label = "Low"
    elif score < 0.65:
        label = "Medium"
    else:
        label = "High"

    return {"score": score, "label": label, "factors": factors}


# ── M54: Failure chain builder ─────────────────────────────────────


def build_failure_chain(
    groups: list[dict[str, Any]],
    cascades: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build explicit failure chain from incident groups and cross-system cascades.

    Returns {
        "primary_chain": list[str],       # max 5 steps
        "chain_text": str,                # "A → B → C → ..."
        "secondary_findings": list[str],  # concurrent groups not in chain
    }
    """
    if not groups:
        return {"primary_chain": [], "chain_text": "", "secondary_findings": []}

    # Find primary group
    primary = next((g for g in groups if g.get("is_primary")), groups[0])

    # Build chain: trigger titles → effect titles
    chain: list[str] = []
    seen: set[str] = set()
    for t in primary.get("triggers", []):
        title = t["title"]
        if title not in seen:
            chain.append(title)
            seen.add(title)
    for e in primary.get("effects", []):
        title = e["title"]
        if title not in seen:
            chain.append(title)
            seen.add(title)

    # Append cascade downstream labels if available
    if cascades:
        for c in cascades[:3]:
            pattern = c.get("pattern", "")
            if pattern and pattern not in seen:
                chain.append(pattern)
                seen.add(pattern)

    # Cap at 5
    chain = chain[:5]

    # Secondary findings: concurrent groups
    secondary: list[str] = []
    for g in groups:
        if g.get("cascade_order") == "concurrent":
            secondary.append(f"{g['name']} ({g.get('total_count', 0)} events)")

    return {
        "primary_chain": chain,
        "chain_text": " → ".join(chain) if chain else "",
        "secondary_findings": secondary,
    }


def collect_group_evidence(group: dict[str, Any]) -> list[str]:
    """Collect deduplicated evidence lines from all triggers in a group.

    Returns a list of unique "Key: value" strings suitable for display.
    """
    all_ips: set[str] = set()
    all_durations: list[str] = []
    all_exceptions: set[str] = set()
    all_hostnames: set[str] = set()

    for t in group.get("triggers", []):
        ev = t.get("evidence", {})
        all_ips.update(ev.get("ip_addresses", []))
        for d in ev.get("durations", []):
            if d not in all_durations:
                all_durations.append(d)
        all_exceptions.update(ev.get("exceptions", []))
        all_hostnames.update(ev.get("hostnames", []))

    lines: list[str] = []
    if all_ips:
        lines.append(f"Targets: {', '.join(sorted(all_ips))}")
    if all_hostnames:
        lines.append(f"Hosts: {', '.join(sorted(all_hostnames))}")
    if all_durations:
        lines.append(f"Durations: {', '.join(all_durations[:4])}")
    if all_exceptions:
        lines.append(f"Exceptions: {', '.join(sorted(all_exceptions))}")
    return lines


def _heuristic_keywords(h: dict) -> list[str]:
    """Extract quick-check keywords from a heuristic's regex pattern."""
    pattern = h["match"].pattern
    parts = re.split(r'[|()\\.\[\]*+?{}^$]', pattern)
    keywords = [p.strip().lower() for p in parts if len(p.strip()) >= 4 and p.strip().isalnum()]
    parts2 = re.split(r'[|()\\*+?{}^$\[\]]', pattern)
    for p in parts2:
        p = p.strip().lower()
        if len(p) >= 4 and all(c.isalnum() or c in ' .-_' for c in p):
            if p not in keywords:
                keywords.append(p)
    return keywords


def group_into_incidents(
    causes: list[dict[str, Any]],
    events: list[LogEvent] | None = None,
) -> dict[str, Any]:
    """Group related likely causes into incident groups.

    Returns dict with:
      - groups: list of incident dicts with trigger, effects, narrative, confidence
      - ungrouped: list of causes that don't fit any incident group
    """
    if not causes:
        return {"groups": [], "ungrouped": []}

    cause_ids = {c["id"] for c in causes}
    cause_by_id = {c["id"]: c for c in causes}
    used_ids: set[str] = set()
    groups: list[dict[str, Any]] = []

    for ig in _INCIDENT_GROUPS:
        trigger_matches = ig["trigger_ids"] & cause_ids
        effect_matches = ig["effect_ids"] & cause_ids
        if not trigger_matches:
            continue

        # Build trigger and effects lists
        triggers = [cause_by_id[cid] for cid in trigger_matches]
        effects = [cause_by_id[cid] for cid in effect_matches]
        all_ids = trigger_matches | effect_matches

        # Skip if this group would duplicate a group that already covers these
        if all_ids <= used_ids:
            continue

        # Build narrative
        effect_names = [cause_by_id[cid]["title"] for cid in effect_matches] if effect_matches else []
        narrative = ig["narrative"].format(
            effects=", ".join(effect_names) if effect_names else "no downstream effects detected"
        )

        total_count = sum(c["count"] for c in triggers) + sum(c["count"] for c in effects)

        groups.append({
            "id": ig["id"],
            "name": ig["name"],
            "narrative": narrative,
            "triggers": triggers,
            "effects": effects,
            "total_count": total_count,
        })
        used_ids |= all_ids

    # Rank groups: primary incident, cascade ordering, investigate-first directives
    rank_incident_groups(groups, causes)

    # Build rich narratives with evidence
    for g in groups:
        g["narrative"] = build_narrative(g)

    # Compute confidence scores
    for g in groups:
        g["confidence"] = compute_confidence(g, events)

    # Ungrouped causes (skip correlation entries — they're explained by their parent causes)
    ungrouped = [c for c in causes if c["id"] not in used_ids
                 and not c.get("correlated_from")]

    return {"groups": groups, "ungrouped": ungrouped}


def _detect_burst(events: list[LogEvent], window_seconds: float = 120.0, threshold: int = 50) -> list[dict[str, Any]]:
    """Detect error bursts — many errors in a short time window."""
    from .analysis import parse_ts_datetime

    error_events = [e for e in events if e.level in ERROR_LEVELS]
    if len(error_events) < threshold:
        return []

    # Parse timestamps and find bursts
    timed: list[tuple[float, LogEvent]] = []
    for e in error_events:
        dt = parse_ts_datetime(e.ts)
        if dt is None:
            continue
        timed.append((dt.timestamp(), e))

    if len(timed) < threshold:
        return []

    timed.sort(key=lambda x: x[0])
    results: list[dict[str, Any]] = []

    # Sliding window
    i = 0
    for j in range(len(timed)):
        while timed[j][0] - timed[i][0] > window_seconds:
            i += 1
        window_count = j - i + 1
        if window_count >= threshold:
            # Count unique error types in burst
            burst_types: dict[str, int] = {}
            for k in range(i, j + 1):
                exc = timed[k][1].exception or timed[k][1].code or "unknown"
                burst_types[exc] = burst_types.get(exc, 0) + 1
            top_type = max(burst_types, key=burst_types.get)  # type: ignore[arg-type]

            results.append({
                "id": "burst-detected",
                "title": f"Error Storm Detected ({window_count} errors in {window_seconds/60:.0f} min)",
                "count": window_count,
                "cause": f"A burst of {window_count} errors occurred in a {window_seconds/60:.0f}-minute window. "
                         f"Top error: {top_type} ({burst_types[top_type]} occurrences). "
                         f"This suggests a cascading failure, deployment issue, or sudden load spike.",
                "fixes": [
                    "Check if a deployment or config change happened just before the burst started.",
                    f"Investigate the primary error type ({top_type}) — fixing it may resolve the cascade.",
                    "Check for upstream dependency failures (database, external API, DNS) that triggered the storm.",
                    "Review auto-scaling and circuit breaker settings to prevent future cascades.",
                ],
                "severity": "critical",
            })
            break  # Report the worst burst only

    return results


def _severity_score(events: list[LogEvent], match_re: re.Pattern) -> int:  # type: ignore[type-arg]
    """Score a heuristic higher if it matches FATAL/SEVERE events."""
    score = 0
    for e in events:
        if match_re.search(e.text or ""):
            level = e.level or ""
            if level in ("FATAL", "SEVERE"):
                score += 10
            elif level == "ERROR":
                score += 3
            else:
                score += 1
    return score


def likely_causes(events: list[LogEvent]) -> list[dict[str, Any]]:
    """Return list of {id, title, count, cause, fixes} for detected heuristic patterns.

    Includes single-pattern heuristics, multi-signal correlations,
    burst detection, and severity-weighted ranking.
    """
    h_keywords = []
    for h in _HEURISTICS:
        h_keywords.append(_heuristic_keywords(h))

    candidates: set[int] = {idx for idx, kws in enumerate(h_keywords) if not kws}
    texts_lower = [(e.text or "").lower() for e in events]
    for text_lower in texts_lower:
        for idx, kws in enumerate(h_keywords):
            if idx in candidates:
                continue
            for kw in kws:
                if kw in text_lower:
                    candidates.add(idx)
                    break
        if len(candidates) == len(_HEURISTICS):
            break

    # --- Single-pattern heuristics ---
    results = []
    matched_ids: set[str] = set()
    for idx in candidates:
        h = _HEURISTICS[idx]
        count = 0
        sev = 0
        match_re = h["match"]
        for e in events:
            if match_re.search(e.text or ""):  # type: ignore[union-attr,misc]
                count += 1
                if count <= 1000:  # Cap severity sampling
                    level = e.level or ""
                    if level in ("FATAL", "SEVERE"):
                        sev += 10
                    elif level == "ERROR":
                        sev += 3
                    else:
                        sev += 1
        if count:
            evidence = extract_evidence(events, match_re)
            results.append({
                "id": h["id"],
                "title": h["title"],
                "count": count,
                "cause": h["cause"],
                "fixes": list(h["fixes"]),  # type: ignore[arg-type]
                "evidence": evidence,
                "_sev": sev,
            })
            matched_ids.add(h["id"])

    # --- Correlation rules (multi-signal) ---
    for corr in _CORRELATIONS:
        if all(rid in matched_ids for rid in corr["requires"]):
            # Sum counts of contributing causes
            contributing = [r for r in results if r["id"] in corr["requires"]]
            total_count = sum(r["count"] for r in contributing)
            max_sev = max((r["_sev"] for r in contributing), default=0)
            # Merge evidence from contributing causes
            corr_evidence = _merge_evidence([r.get("evidence", {}) for r in contributing])
            results.append({
                "id": corr["id"],
                "title": corr["title"],
                "count": total_count,
                "cause": corr["cause"],
                "fixes": list(corr["fixes"]),
                "evidence": corr_evidence,
                "_sev": max_sev + 5,  # Boost correlations above individual causes
                "correlated_from": list(corr["requires"]),
            })

    # --- Burst detection ---
    bursts = _detect_burst(events)
    for b in bursts:
        b["_sev"] = b["count"] * 2  # Bursts rank very high
        results.append(b)

    # --- Sort by severity score (descending), then by count ---
    results.sort(key=lambda r: (-r.get("_sev", 0), -r["count"]))

    # Clean up internal scoring field
    for r in results:
        r.pop("_sev", None)

    return results


def incident_fingerprint(causes: list[dict]) -> str:
    """Create a stable fingerprint from heuristic findings.

    Combines sorted heuristic IDs and top exception names into a
    deterministic string key for comparing incidents.

    Args:
        causes: List of cause dicts from likely_causes(), each with 'id' and optionally 'title'.

    Returns:
        A stable fingerprint string (hash).
    """
    import hashlib
    # Extract heuristic IDs
    ids = sorted(set(c.get("id", c.get("title", "")) for c in causes))
    # Extract top exception names from cause descriptions
    exceptions = sorted(set(
        c.get("title", "")
        for c in causes
        if any(kw in c.get("title", "").lower() for kw in ("exception", "error", "failure", "oom", "timeout"))
    ))
    fingerprint_data = "|".join(ids) + "||" + "|".join(exceptions)
    return hashlib.sha256(fingerprint_data.encode("utf-8")).hexdigest()[:16]


def match_similar_incidents(current_causes: list[dict],
                            history: list[dict]) -> list[dict]:
    """Compare current incident against a history of past analyses.

    Uses Jaccard similarity on heuristic ID sets.

    Args:
        current_causes: Current cause dicts from likely_causes().
        history: List of past incident dicts, each with 'fingerprint', 'ids', 'timestamp'.

    Returns:
        List of matching incidents with similarity >= 0.5, each containing:
        {fingerprint, timestamp, similarity}.
    """
    if not current_causes or not history:
        return []

    current_ids = set(c.get("id", c.get("title", "")) for c in current_causes)
    if not current_ids:
        return []

    matches = []
    for past in history:
        past_ids = set(past.get("ids", []))
        if not past_ids:
            continue

        # Jaccard similarity
        intersection = len(current_ids & past_ids)
        union = len(current_ids | past_ids)
        if union == 0:
            continue
        similarity = intersection / union

        if similarity >= 0.5:
            matches.append({
                "fingerprint": past.get("fingerprint", ""),
                "timestamp": past.get("timestamp", ""),
                "similarity": round(similarity, 2),
            })

    # Sort by similarity descending
    matches.sort(key=lambda m: -m["similarity"])
    return matches
