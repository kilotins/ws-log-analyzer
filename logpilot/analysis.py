"""Analysis functions: summarize, timeline, heuristics, splunk, hung threads."""
from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from .event import LogEvent

_log = logging.getLogger(__name__)

ERROR_LEVELS = ("ERROR", "SEVERE", "FATAL")

# Re-export public API from submodules for backwards compatibility
from .heuristics import group_into_incidents, likely_causes  # noqa: F401
from .splunk import hung_thread_drilldown, suggested_splunk_queries  # noqa: F401


def parse_ts_datetime(ts: str | None) -> datetime | None:
    """Parse a timestamp string into a datetime object. Returns None on failure."""
    if not ts:
        return None
    try:
        for fmt in ("%m/%d/%y %H:%M:%S:%f", "%m/%d/%Y %H:%M:%S:%f"):
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        normalized = ts.replace("T", " ").replace(",", ".")
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue
    except (ValueError, TypeError, AttributeError):
        pass
    _log.debug("parse_ts_datetime: could not parse timestamp %r", ts)
    return None


# Mapping of common timezone abbreviations to UTC offset in hours
_TZ_ABBREV_OFFSETS: dict[str, float] = {
    "UTC": 0, "GMT": 0, "Z": 0,
    "BST": +1, "CET": +1,
    "CEST": +2,
    "EST": -5, "EDT": -4,
    "CST": -6, "CDT": -5,
    "MST": -7, "MDT": -6,
    "PST": -8, "PDT": -7,
    "IST": +5.5,
    "JST": +9, "KST": +9,
    "AEST": +10,
}

# Regex to detect ISO offset embedded in a timestamp string
_TS_EMBED_OFFSET_RE = re.compile(
    r'(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+-]\d{2}:?\d{2}|Z)\s*$'
)
_TS_EMBED_Z_RE = re.compile(r'Z\s*$')


def normalize_ts_utc(ts: str | None, tz_hint: str | None = None) -> datetime | None:
    """Parse timestamp and normalize to UTC. Returns None on failure.

    Args:
        ts: Raw timestamp string from log event
        tz_hint: Timezone hint (e.g. "CEST", "+02:00", "Europe/Stockholm").
                 If None, assumes UTC.
    """
    if not ts:
        return None

    # Strip trailing timezone indicators before calling parse_ts_datetime
    # so we can parse the bare datetime, then reattach the tz.
    ts_bare = ts.strip()
    embedded_offset: str | None = None

    # Check for embedded offset in the timestamp string itself
    m = _TS_EMBED_OFFSET_RE.search(ts_bare)
    if m:
        embedded_offset = m.group(1)
        ts_bare = ts_bare[:m.start(1)].strip()
    elif _TS_EMBED_Z_RE.search(ts_bare):
        embedded_offset = "Z"
        ts_bare = ts_bare[:-1].strip()

    dt = parse_ts_datetime(ts_bare) or parse_ts_datetime(ts)
    if dt is None:
        return None

    # Determine the tzinfo to attach
    tz_source = tz_hint or embedded_offset
    tz_info: datetime.tzinfo | None = None

    if tz_source:
        tz_src = tz_source.strip()

        if tz_src in ("Z", "UTC", "GMT"):
            tz_info = timezone.utc

        elif tz_src in _TZ_ABBREV_OFFSETS:
            offset_hours = _TZ_ABBREV_OFFSETS[tz_src]
            tz_info = timezone(timedelta(hours=offset_hours))

        elif re.match(r'^[+-]\d{2}:?\d{2}$', tz_src):
            # ISO offset: +02:00 or +0200
            sign = 1 if tz_src[0] == '+' else -1
            tz_clean = tz_src[1:].replace(":", "")
            hours = int(tz_clean[:2])
            minutes = int(tz_clean[2:])
            tz_info = timezone(sign * timedelta(hours=hours, minutes=minutes))

        else:
            # Try IANA name via zoneinfo (Python 3.9+)
            try:
                from zoneinfo import ZoneInfo
                tz_info = ZoneInfo(tz_src)
            except Exception:
                _log.debug("normalize_ts_utc: unrecognized tz_hint %r, assuming UTC", tz_src)
                tz_info = timezone.utc

    if tz_info is None:
        tz_info = timezone.utc

    # Attach timezone to naive datetime, then convert to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz_info)
    return dt.astimezone(timezone.utc)


def sort_events_chronologically(events: list[LogEvent], tz_hint: str | None = None) -> None:
    """Sort events in-place by UTC-normalized timestamp. Events without timestamps go last."""
    for e in events:
        if e.ts_utc is None:
            dt = normalize_ts_utc(e.ts, tz_hint=(e.tz_hint or tz_hint))
            e.ts_utc = dt.isoformat() if dt else None

    events.sort(key=lambda e: (e.ts_utc is None, e.ts_utc or ""))


def summarize(events: list[LogEvent], top_n: int) -> dict[str, Any]:
    """Count top codes, exceptions, levels, tags; return summary dict."""
    by_level = Counter(e.level or "UNKNOWN" for e in events)
    by_code = Counter(e.code for e in events if e.code)
    by_exc = Counter(e.exception for e in events if e.exception)
    by_tag = Counter(tag for e in events for tag in e.tags)

    def top(counter: Counter) -> list[tuple[str, int]]:
        return counter.most_common(top_n)

    return {
        "total_events": len(events),
        "levels": top(by_level),
        "codes": top(by_code),
        "exceptions": top(by_exc),
        "tags": top(by_tag),
    }


def incident_timeline(events: list[LogEvent], window_seconds: int = 30) -> dict[str, Any] | None:
    """Build an incident timeline around the first error.

    Returns dict with:
      - trigger_event: the first error event
      - trigger_dt: datetime of the trigger
      - window_events: list of {event, dt, offset_seconds} within +/- window
      - window_seconds: the window used
    Returns None if no error events with timestamps exist.
    """
    ts_cache: dict[str, Any] = {}
    for e in events:
        ts = e.ts
        if ts and ts not in ts_cache:
            ts_cache[ts] = parse_ts_datetime(ts)

    trigger = None
    trigger_dt = None
    for e in events:
        if e.level in ERROR_LEVELS:
            dt = ts_cache.get(e.ts or "")
            if dt:
                trigger = e
                trigger_dt = dt
                break

    if not trigger:
        return None

    window_events = []
    for e in events:
        dt = ts_cache.get(e.ts or "")
        if not dt:
            continue
        offset = (dt - trigger_dt).total_seconds()
        if -window_seconds <= offset <= window_seconds:
            window_events.append({
                "event": e,
                "dt": dt,
                "offset_seconds": offset,
            })

    window_events.sort(key=lambda w: w["dt"])

    return {
        "trigger_event": trigger,
        "trigger_dt": trigger_dt,
        "window_events": window_events,
        "window_seconds": window_seconds,
    }


def _parse_ts_parts(ts: str) -> tuple[str | None, int, int] | None:
    """Extract (date_str, hour, minute) from a timestamp string. Returns None on failure."""
    dt = parse_ts_datetime(ts)
    if dt:
        return (dt.strftime("%Y-%m-%d"), dt.hour, dt.minute)
    # Fallback for formats parse_ts_datetime doesn't cover
    try:
        parts = ts.split()
        if len(parts) > 1:
            date_part = parts[0]
            time_part = parts[-1]
        else:
            time_part = parts[0]
            date_part = None
            if "T" in time_part:
                iso_parts = time_part.split("T", 1)
                date_part = iso_parts[0]
                time_part = iso_parts[1] if len(iso_parts) > 1 else time_part
        hms = re.split(r'[:.]', time_part)
        if len(hms) < 2:
            return None
        h, m = int(hms[0]), int(hms[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            return None
        return (date_part, h, m)
    except (ValueError, IndexError):
        return None


def time_histogram(events: list[LogEvent], bucket_minutes: int = 1) -> list[tuple[str, int, int]]:
    """Group events by time bucket and return list of (bucket_label, total, error_count)."""
    buckets: dict[str, dict[str, int]] = {}
    dates_seen: set[str] = set()
    for e in events:
        ts = e.ts
        if not ts:
            continue
        parsed = _parse_ts_parts(ts)
        if not parsed:
            continue
        date_part, h, m = parsed
        date_key = date_part or "_"
        dates_seen.add(date_key)
        total_minutes = h * 60 + m
        floored = (total_minutes // bucket_minutes) * bucket_minutes
        bh, bm = divmod(floored, 60)
        key = f"{date_key} {bh:02d}:{bm:02d}"
        if key not in buckets:
            buckets[key] = {"total": 0, "errors": 0}
        buckets[key]["total"] += 1
        if e.level in ERROR_LEVELS:
            buckets[key]["errors"] += 1

    if not buckets:
        return []

    real_dates = dates_seen - {"_"}
    if real_dates and "_" in dates_seen:
        buckets = {k: v for k, v in buckets.items() if not k.startswith("_ ")}

    if len(dates_seen - {"_"}) <= 1:
        buckets = {k.split(" ", 1)[1]: v for k, v in buckets.items()}

    return [(k, buckets[k]["total"], buckets[k]["errors"]) for k in sorted(buckets)]


def compact_histogram(hist: list[tuple[str, int, int]], max_rows: int = 60) -> list[tuple[str, int, int]]:
    """Aggregate histogram buckets if there are too many rows.

    Groups by hour or by day depending on how many rows remain.
    Returns a new histogram list with the same (label, total, errors) format.
    """
    if len(hist) <= max_rows:
        return hist

    # Try aggregating by hour (strip minutes)
    hourly: dict[str, list[int]] = {}
    for label, total, errors in hist:
        # label is "DATE HH:MM" or "HH:MM"
        if " " in label:
            parts = label.rsplit(" ", 1)
            date_part = parts[0]
            time_part = parts[1]
            hour_key = f"{date_part} {time_part.split(':')[0]}:00"
        else:
            hour_key = f"{label.split(':')[0]}:00"
        if hour_key not in hourly:
            hourly[hour_key] = [0, 0]
        hourly[hour_key][0] += total
        hourly[hour_key][1] += errors

    hourly_hist = [(k, v[0], v[1]) for k, v in sorted(hourly.items())]
    if len(hourly_hist) <= max_rows:
        return hourly_hist

    # Still too many — aggregate by day
    daily: dict[str, list[int]] = {}
    for label, total, errors in hist:
        if " " in label:
            day_key = label.rsplit(" ", 1)[0]
        else:
            day_key = "all"
        if day_key not in daily:
            daily[day_key] = [0, 0]
        daily[day_key][0] += total
        daily[day_key][1] += errors

    return [(k, v[0], v[1]) for k, v in sorted(daily.items())]


def render_histogram(hist: list[tuple[str, int, int]], bar_width: int = 40) -> list[str]:
    """Render ASCII bar chart lines from histogram data."""
    if not hist:
        return ["- _(no timestamped events)_"]
    max_total = max(t for _, t, _ in hist)
    lines = []
    for label, total, errors in hist:
        bar_len = int((total / max_total) * bar_width) if max_total else 0
        bar = "#" * bar_len
        err_suffix = f"  ({errors} err)" if errors else ""
        lines.append(f"  {label} | {bar} {total}{err_suffix}")
    return lines


def pick_samples(events: list[LogEvent], n: int) -> list[LogEvent]:
    """Select diverse sample events (by code/exception/tag)."""
    seen: set[tuple] = set()
    unique = []
    for e in events:
        key = (e.level, e.code, e.exception)
        if key not in seen:
            seen.add(key)
            unique.append(e)

    def score(e: LogEvent) -> int:
        s = 0
        if e.level in ("FATAL",): s += 4
        if e.level in ("ERROR", "SEVERE"): s += 3
        if e.level in ("WARNING", "WARN"): s += 1
        if e.exception: s += 2
        if e.code: s += 1
        if e.tags: s += 1
        return -s
    return sorted(unique, key=score)[:n]


def per_file_summary(events: list[LogEvent]) -> list[tuple[str, int, int]]:
    """Return list of (filename, total, error_count) for each source file."""
    files: dict[str, dict[str, int]] = {}
    for e in events:
        f = e.file
        if f not in files:
            files[f] = {"total": 0, "errors": 0}
        files[f]["total"] += 1
        if e.level in ERROR_LEVELS:
            files[f]["errors"] += 1
    return [(f, files[f]["total"], files[f]["errors"]) for f in sorted(files)]


# --- Cross-system cascade patterns ---
_CASCADE_PATTERNS: list[dict[str, Any]] = [
    {"upstream_tags": {"DB/Pool"}, "downstream_tags": {"HTTP"}, "max_delay_s": 30,
     "label": "Database failure → HTTP errors"},
    {"upstream_tags": {"SSL/TLS"}, "downstream_tags": {"HTTP"}, "max_delay_s": 10,
     "label": "SSL failure → connection errors"},
    {"upstream_tags": {"OOM/GC"}, "downstream_tags": {"HungThreads"}, "max_delay_s": 60,
     "label": "Memory pressure → thread starvation"},
    {"upstream_tags": {"OOM/GC"}, "downstream_tags": {"HTTP"}, "max_delay_s": 60,
     "label": "Memory pressure → HTTP errors"},
    {"upstream_tags": {"DB/Pool"}, "downstream_tags": {"HungThreads"}, "max_delay_s": 30,
     "label": "Database exhaustion → hung threads"},
    {"upstream_tags": {"HungThreads"}, "downstream_tags": {"HTTP"}, "max_delay_s": 15,
     "label": "Hung threads → HTTP timeouts"},
]


def detect_cross_system_cascades(events: list[LogEvent], max_delay_s: int = 60) -> list[dict[str, Any]]:
    """Detect error cascades across different system sources.

    Looks for temporal patterns where errors in one system are followed by
    errors in another system within a time window, matching known cascade patterns.

    Returns list of cascade dicts:
        {pattern, upstream_event, downstream_events, delay_seconds, confidence}
    """
    # Need events sorted by ts_utc with at least 2 sources
    error_events = [e for e in events if e.level in ERROR_LEVELS and e.ts_utc]
    if len(error_events) < 2:
        return []

    sources = set(e.system_label or "" for e in error_events)
    if len(sources) < 2:
        return []

    # Parse ts_utc to float for fast comparison
    timed_errors: list[tuple[float, LogEvent]] = []
    for e in error_events:
        try:
            dt = datetime.fromisoformat(e.ts_utc)
            timed_errors.append((dt.timestamp(), e))
        except (ValueError, TypeError):
            continue

    timed_errors.sort(key=lambda x: x[0])
    cascades: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str, str]] = set()  # (pattern_label, upstream_source, downstream_source)

    for i, (t_up, e_up) in enumerate(timed_errors):
        up_tags = set(e_up.tags)
        up_source = e_up.system_label or ""
        if not up_tags:
            continue

        for pattern in _CASCADE_PATTERNS:
            if not pattern["upstream_tags"] & up_tags:
                continue

            # Look for downstream events in other sources within the delay window
            downstream = []
            for j in range(i + 1, len(timed_errors)):
                t_down, e_down = timed_errors[j]
                delay = t_down - t_up
                if delay > pattern["max_delay_s"]:
                    break
                if delay < 0:
                    continue

                down_source = e_down.system_label or ""
                if down_source == up_source:
                    continue  # Same source, not a cross-system cascade

                down_tags = set(e_down.tags)
                if pattern["downstream_tags"] & down_tags:
                    downstream.append({"event": e_down, "delay_s": round(delay, 1)})

            if downstream:
                pair_key = (pattern["label"], up_source, downstream[0]["event"].system_label or "")
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                confidence = min(0.9, 0.5 + 0.1 * len(downstream))
                cascades.append({
                    "pattern": pattern["label"],
                    "upstream_event": e_up,
                    "upstream_source": up_source,
                    "downstream_events": downstream[:5],  # Limit to 5
                    "downstream_source": downstream[0]["event"].system_label or "",
                    "delay_seconds": downstream[0]["delay_s"],
                    "confidence": confidence,
                })

    # Sort by confidence descending
    cascades.sort(key=lambda c: -c["confidence"])
    return cascades[:10]  # Top 10 cascades


def per_source_summary(events: list[LogEvent]) -> list[dict[str, Any]]:
    """Return summary per system_label: label, format, total, errors, top codes, top exceptions."""
    sources: dict[str, dict] = {}
    for e in events:
        label = e.system_label or "unknown"
        if label not in sources:
            sources[label] = {"label": label, "format": e.format or "unknown",
                              "total": 0, "errors": 0, "codes": Counter(), "exceptions": Counter()}
        sources[label]["total"] += 1
        if e.level in ERROR_LEVELS:
            sources[label]["errors"] += 1
        if e.code:
            sources[label]["codes"][e.code] += 1
        if e.exception:
            sources[label]["exceptions"][e.exception] += 1

    result = []
    for s in sorted(sources.values(), key=lambda x: x["errors"], reverse=True):
        result.append({
            "label": s["label"],
            "format": s["format"],
            "total": s["total"],
            "errors": s["errors"],
            "top_codes": s["codes"].most_common(3),
            "top_exceptions": s["exceptions"].most_common(3),
        })
    return result


def correlate_by_trace_id(events: list[LogEvent]) -> dict[str, list[LogEvent]]:
    """Group events by shared trace/correlation IDs across sources.

    Returns dict mapping trace_id -> list of events, only including
    IDs that appear in events from 2+ different system_labels.
    """
    # Build trace_id -> events mapping
    id_events: dict[str, list[LogEvent]] = {}
    for e in events:
        for tid in e.trace_ids:
            if tid not in id_events:
                id_events[tid] = []
            id_events[tid].append(e)

    # Keep only cross-system correlations
    cross_system: dict[str, list[LogEvent]] = {}
    for tid, evts in id_events.items():
        sources = set(e.system_label or "" for e in evts)
        if len(sources) >= 2:
            # Sort by timestamp
            cross_system[tid] = sorted(evts, key=lambda e: e.ts_utc or "")

    return cross_system


def find_cross_system_chains(events: list[LogEvent], max_chains: int = 10) -> list[dict]:
    """Find request flows that span multiple systems via trace IDs.

    Returns list of chain dicts:
        {trace_id, systems, event_count, has_errors, events}
    """
    correlations = correlate_by_trace_id(events)

    chains = []
    for tid, evts in correlations.items():
        systems = list(dict.fromkeys(e.system_label or "unknown" for e in evts))
        has_errors = any(e.level in ERROR_LEVELS for e in evts)
        chains.append({
            "trace_id": tid,
            "systems": systems,
            "event_count": len(evts),
            "has_errors": has_errors,
            "events": evts,
        })

    # Sort: errors first, then by event count
    chains.sort(key=lambda c: (not c["has_errors"], -c["event_count"]))
    return chains[:max_chains]


def precompute_analysis(events: list[LogEvent], top_n: int = 10, samples_n: int = 5, hist_minutes: int = 1, progress_callback=None) -> dict[str, Any]:
    """Compute all shared analysis data once. Returns a dict."""
    def _progress(text: str, frac: float) -> None:
        if progress_callback:
            progress_callback(text, frac)

    _progress("Summarizing events...", 0.0)
    s = summarize(events, top_n)

    _progress("Picking samples...", 0.10)
    samples = pick_samples(events, samples_n)

    _progress("Building timeline...", 0.20)
    hist = time_histogram(events, bucket_minutes=hist_minutes)

    _progress("Per-file summary...", 0.30)
    file_summary = per_file_summary(events)

    _progress("Running heuristics...", 0.40)
    causes = likely_causes(events)

    _progress("Generating Splunk queries...", 0.70)
    splunk = suggested_splunk_queries(s, causes, hist)

    _progress("Analyzing hung threads...", 0.80)
    hung = hung_thread_drilldown(events)

    _progress("Detecting cascades...", 0.90)
    cascades = detect_cross_system_cascades(events)

    _progress("Analysis complete", 1.0)
    return {
        "summary": s,
        "samples": samples,
        "hist": hist,
        "file_summary": file_summary,
        "causes": causes,
        "splunk": splunk,
        "hung": hung,
        "cascades": cascades,
    }


def compare_periods(events: list[LogEvent], split: str = "day") -> list[dict]:
    """Compare consecutive time periods to find new/disappeared error patterns.

    Groups events by date, then for each consecutive pair computes:
    - New/disappeared message codes and exceptions
    - Significant volume changes (>2x increase or >50% drop)
    - New/disappeared signal tags

    Args:
        events: List of parsed log events.
        split: Grouping period ("day" supported).

    Returns:
        List of dicts with keys: date, new_codes, gone_codes, new_exceptions,
        gone_exceptions, volume_changes, new_tags, gone_tags.
    """
    # Group events by date
    by_date: dict[str, list[LogEvent]] = {}
    for e in events:
        if not e.ts:
            continue
        parsed = _parse_ts_parts(e.ts)
        if not parsed or not parsed[0]:
            continue
        date_str = parsed[0]
        if date_str not in by_date:
            by_date[date_str] = []
        by_date[date_str].append(e)

    if len(by_date) < 2:
        return []

    sorted_dates = sorted(by_date.keys())
    deltas: list[dict] = []

    for i in range(1, len(sorted_dates)):
        prev_date = sorted_dates[i - 1]
        curr_date = sorted_dates[i]
        prev_events = by_date[prev_date]
        curr_events = by_date[curr_date]

        # Collect codes, exceptions, tags per day
        prev_codes = Counter(e.code for e in prev_events if e.code)
        curr_codes = Counter(e.code for e in curr_events if e.code)
        prev_exc = Counter(e.exception for e in prev_events if e.exception)
        curr_exc = Counter(e.exception for e in curr_events if e.exception)
        prev_tags = set(tag for e in prev_events for tag in e.tags)
        curr_tags = set(tag for e in curr_events for tag in e.tags)

        # New and disappeared
        new_codes = sorted(set(curr_codes) - set(prev_codes))
        gone_codes = sorted(set(prev_codes) - set(curr_codes))
        new_exceptions = sorted(set(curr_exc) - set(prev_exc))
        gone_exceptions = sorted(set(prev_exc) - set(curr_exc))
        new_tags = sorted(curr_tags - prev_tags)
        gone_tags = sorted(prev_tags - curr_tags)

        # Volume changes (codes present in both periods)
        volume_changes: list[dict] = []
        for code in sorted(set(prev_codes) & set(curr_codes)):
            prev_count = prev_codes[code]
            curr_count = curr_codes[code]
            if prev_count == 0:
                continue
            ratio = curr_count / prev_count
            if ratio >= 2.0 or ratio <= 0.5:
                volume_changes.append({
                    "code": code,
                    "prev_count": prev_count,
                    "curr_count": curr_count,
                    "ratio": round(ratio, 2),
                    "direction": "up" if ratio >= 2.0 else "down",
                })

        deltas.append({
            "date": curr_date,
            "prev_date": prev_date,
            "new_codes": new_codes,
            "gone_codes": gone_codes,
            "new_exceptions": new_exceptions,
            "gone_exceptions": gone_exceptions,
            "volume_changes": volume_changes,
            "new_tags": new_tags,
            "gone_tags": gone_tags,
        })

    return deltas


# --- Noise scoring for AI prompt reduction ---

# Codes that should never be filtered (critical signals)
_NEVER_FILTER_PATTERNS = re.compile(
    r'OutOfMemory|OOM|HungThread|WSVR0605W|WSVR0606W|WSVR0661W'
    r'|FATAL|Deadlock|StackOverflow',
    re.IGNORECASE,
)


def compute_noise_scores(events: list[LogEvent]) -> dict[str, float]:
    """Score each message code 0.0–1.0 for noise likelihood.

    Scoring rules:
    - High frequency + identical text → 0.8 base
    - INFO/AUDIT severity → +0.3
    - Near error window → −0.5 (protect from filtering)
    - Never-filter patterns (OOM, hung thread, etc.) → always 0.0

    Returns:
        Dict mapping code → noise_score (0.0 = keep, 1.0 = definitely noise).
    """
    code_events: dict[str, list[LogEvent]] = {}
    for e in events:
        if not e.code:
            continue
        if e.code not in code_events:
            code_events[e.code] = []
        code_events[e.code].append(e)

    if not code_events:
        return {}

    # Find error timestamps for "near error" protection
    error_ts: list[str] = []
    for e in events:
        if e.level in ERROR_LEVELS and e.ts:
            error_ts.append(e.ts)

    # Parse error timestamps for proximity check
    error_dts: list[datetime] = []
    for ts in error_ts[:50]:  # Limit for performance
        dt = parse_ts_datetime(ts)
        if dt:
            error_dts.append(dt)

    total_events = len(events)
    scores: dict[str, float] = {}

    for code, code_evts in code_events.items():
        # Never-filter check
        if _NEVER_FILTER_PATTERNS.search(code):
            scores[code] = 0.0
            continue
        # Check event text too
        if any(_NEVER_FILTER_PATTERNS.search(e.text or "") for e in code_evts[:3]):
            scores[code] = 0.0
            continue

        score = 0.0
        count = len(code_evts)

        # High frequency: if this code appears > 5% of all events
        if total_events > 0 and count / total_events > 0.05:
            score += 0.4

        # Identical text check: if >80% of events with this code have identical text
        texts = [e.text for e in code_evts if e.text]
        if texts:
            most_common_text = Counter(texts).most_common(1)[0]
            if most_common_text[1] / len(texts) > 0.8:
                score += 0.4

        # INFO/AUDIT severity bonus
        info_count = sum(1 for e in code_evts if e.level in ("INFO", "AUDIT", "DEBUG"))
        if info_count > len(code_evts) * 0.8:
            score += 0.3

        # Near-error protection: if any event with this code is near an error
        if error_dts:
            near_error = False
            for e in code_evts[:10]:
                if not e.ts:
                    continue
                e_dt = parse_ts_datetime(e.ts)
                if not e_dt:
                    continue
                for err_dt in error_dts:
                    if abs((e_dt - err_dt).total_seconds()) < 30:
                        near_error = True
                        break
                if near_error:
                    break
            if near_error:
                score -= 0.5

        scores[code] = max(0.0, min(1.0, round(score, 2)))

    return scores


def filter_noise(events: list[LogEvent], threshold: float = 0.6,
                 noise_scores: dict[str, float] | None = None) -> list[LogEvent]:
    """Remove noisy events based on noise scores.

    Always keeps ERROR/SEVERE/FATAL events regardless of noise score.

    Args:
        events: Full event list.
        threshold: Noise score threshold (0.0–1.0). Events with score >= threshold are removed.
        noise_scores: Pre-computed noise scores. If None, computed automatically.

    Returns:
        Filtered event list.
    """
    if noise_scores is None:
        noise_scores = compute_noise_scores(events)

    if not noise_scores:
        return events

    return [
        e for e in events
        if e.level in ERROR_LEVELS
        or not e.code
        or noise_scores.get(e.code, 0.0) < threshold
    ]
