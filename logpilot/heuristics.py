"""Heuristic pattern matching, correlations, incident grouping, and burst detection."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from .event import LogEvent

_log = logging.getLogger(__name__)

ERROR_LEVELS = ("ERROR", "SEVERE", "FATAL")


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


def group_into_incidents(causes: list[dict[str, Any]]) -> dict[str, Any]:
    """Group related likely causes into incident groups.

    Returns dict with:
      - groups: list of incident dicts with trigger, effects, narrative
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

    # Sort groups by total event count (most impactful first)
    groups.sort(key=lambda g: -g["total_count"])

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
            results.append({
                "id": h["id"],
                "title": h["title"],
                "count": count,
                "cause": h["cause"],
                "fixes": list(h["fixes"]),  # type: ignore[arg-type]
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
            results.append({
                "id": corr["id"],
                "title": corr["title"],
                "count": total_count,
                "cause": corr["cause"],
                "fixes": list(corr["fixes"]),
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
