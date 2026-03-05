#!/usr/bin/env python3
import argparse
import gzip
import re
import json
from collections import Counter
from pathlib import Path
import sys

# --- Common patterns (WebSphere / Java-ish) ---
TS_PATTERNS = [
    # WebSphere classic: [10/12/15 21:22:04:257 CEST]
    re.compile(r'\[(?P<ts>\d{1,2}/\d{1,2}/\d{2,4}\s+\d{2}:\d{2}:\d{2}:\d{3})\s+\w+\]'),
    # WebSphere common: [2025-03-05 12:34:56:789 CET] or similar variants
    re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,:.]\d{3,6})?)'),
    # ISO-like without date brackets
    re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.:]\d{3,6})?)'),
]

LEVEL_RE = re.compile(r'\b(SEVERE|ERROR|WARN|WARNING|INFO|DEBUG|FINE|FINER|FINEST)\b', re.IGNORECASE)

# WebSphere uses single-letter severity after thread ID: [ts] threadid Component X
# I=Info, A=Audit, W=Warning, E=Error, O=SystemOut/SystemErr, F=Fatal, R=Report, D=Detail
WAS_LEVEL_RE = re.compile(r'\]\s+[0-9a-f]+\s+\S+\s+([IAWEOFRD])\s')
WAS_LEVEL_MAP = {
    'I': 'INFO', 'A': 'AUDIT', 'W': 'WARNING', 'E': 'ERROR',
    'O': 'STDOUT', 'F': 'FATAL', 'R': 'REPORT', 'D': 'DEBUG',
}

# Thread ID: hex digits between ] and component name
WAS_THREAD_RE = re.compile(r'\]\s+([0-9a-f]{8})\s+')

# WebSphere / Liberty message codes (general pattern: 4-5 uppercase letters + 4 digits + severity letter)
WAS_CODE_RE = re.compile(r'\b([A-Z]{4,5}\d{4}[A-Z])\b')

# Java exceptions / errors
EXC_HEAD_RE = re.compile(r'\b([a-zA-Z_$]+(?:\.[a-zA-Z_$]+)+(?:Exception|Error))\b')
STACK_LINE_RE = re.compile(r'^\s+at\s+[\w.$]+\(.*\)$')
CAUSED_BY_RE = re.compile(r'^\s*Caused by:\s+(?P<cause>.+)$')

OOM_RE = re.compile(r'OutOfMemoryError|Java heap space|GC overhead limit exceeded', re.IGNORECASE)
HUNG_THREAD_RE = re.compile(r'hung thread|ThreadMonitor|WSVR0605|stuck thread', re.IGNORECASE)
DB_POOL_RE = re.compile(r'connection pool|J2CA|pool.*exhaust|Timeout waiting for idle object', re.IGNORECASE)
SSL_RE = re.compile(r'SSLHandshakeException|handshake_failure|PKIX path building failed|unable to find valid certification path', re.IGNORECASE)
HTTP_RE = re.compile(r'\b(4\d\d|5\d\d)\b.*\b(HTTP|SRVE)\b', re.IGNORECASE)

# Basic secret-ish redaction
SECRET_REPLACERS = [
    (re.compile(r'(?i)\b(authorization:\s*bearer)\s+[A-Za-z0-9._-]+\b'), r'\1 [REDACTED]'),
    (re.compile(r'(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*\S+'), r'\1=[REDACTED]'),
]

def open_text(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", errors="ignore")
    return path.open("r", errors="ignore")

def redact(s: str) -> str:
    for rx, repl in SECRET_REPLACERS:
        s = rx.sub(repl, s)
    return s

def extract_ts(line: str):
    for rx in TS_PATTERNS:
        m = rx.search(line)
        if m:
            return m.group("ts")
    return None

def bucket_tags(text: str):
    tags = set()
    if OOM_RE.search(text): tags.add("OOM/GC")
    if HUNG_THREAD_RE.search(text): tags.add("HungThreads")
    if DB_POOL_RE.search(text): tags.add("DB/Pool")
    if SSL_RE.search(text): tags.add("SSL/TLS")
    if HTTP_RE.search(text): tags.add("HTTP")
    return tags


def classify_event(text):
    """Classify a block of log text and return a dict of metadata (no file/ts)."""
    # Level — prefer WAS single-letter (authoritative) over keyword match
    lvl = None
    wm = WAS_LEVEL_RE.search(text)
    if wm:
        lvl = WAS_LEVEL_MAP.get(wm.group(1), wm.group(1))
    else:
        m = LEVEL_RE.search(text)
        if m:
            lvl = m.group(1).upper()

    # Thread ID
    thread_id = None
    tm = WAS_THREAD_RE.search(text)
    if tm:
        thread_id = tm.group(1)

    # WAS message code
    code = None
    cm = WAS_CODE_RE.search(text)
    if cm:
        code = cm.group(1)

    # Exception (first match)
    exc = None
    em = EXC_HEAD_RE.search(text)
    if em:
        exc = em.group(1)

    # Root cause — deepest "Caused by:" exception
    root_cause = None
    for line in text.splitlines():
        cb = CAUSED_BY_RE.match(line)
        if cb:
            cause_text = cb.group("cause")
            ce = EXC_HEAD_RE.search(cause_text)
            if ce:
                root_cause = ce.group(1)

    tags = bucket_tags(text)

    return {
        "level": lvl,
        "thread_id": thread_id,
        "code": code,
        "exception": exc,
        "root_cause": root_cause,
        "tags": sorted(tags),
    }


def parse_file(path: Path, max_lines: int = None):
    events = []
    current = []
    current_meta = {"file": str(path), "first_ts": None}
    has_stacktrace = False
    seen_first_ts = False

    def flush():
        nonlocal current, current_meta, has_stacktrace
        if not current:
            return
        # Skip preamble block (lines before first timestamp in the file)
        if not seen_first_ts:
            current = []
            current_meta = {"file": str(path), "first_ts": None}
            has_stacktrace = False
            return

        text = "\n".join(current)
        text = redact(text)
        meta = classify_event(text)
        meta["file"] = current_meta["file"]
        meta["ts"] = current_meta["first_ts"]
        meta["text"] = text
        events.append(meta)
        current = []
        current_meta = {"file": str(path), "first_ts": None}
        has_stacktrace = False

    with open_text(path) as f:
        for i, line in enumerate(f, start=1):
            if max_lines and i > max_lines:
                break
            line = line.rstrip("\n")
            ts = extract_ts(line)

            # Heuristic: new event starts when a timestamp appears AND we are not inside a stacktrace block
            if ts and current and not STACK_LINE_RE.match(line) and not CAUSED_BY_RE.match(line):
                flush()
            if ts and current_meta["first_ts"] is None:
                current_meta["first_ts"] = ts
            if ts and not seen_first_ts:
                seen_first_ts = True

            current.append(line)

            # Track stacktrace state
            if STACK_LINE_RE.match(line) or CAUSED_BY_RE.match(line):
                has_stacktrace = True

            # If we hit blank line after a stacktrace, flush
            if not line.strip() and current and has_stacktrace:
                flush()

    flush()
    return events

def summarize(events, top_n):
    by_level = Counter(e["level"] or "UNKNOWN" for e in events)
    by_code = Counter(e["code"] for e in events if e["code"])
    by_exc = Counter(e["exception"] for e in events if e["exception"])
    by_tag = Counter(tag for e in events for tag in e["tags"])

    def top(counter):
        return counter.most_common(top_n)

    return {
        "total_events": len(events),
        "levels": top(by_level),
        "codes": top(by_code),
        "exceptions": top(by_exc),
        "tags": top(by_tag),
    }

def _parse_ts_parts(ts):
    """Extract (date_str, hour, minute) from a timestamp string. Returns None on failure."""
    parts = ts.split()
    if len(parts) > 1:
        # WAS format: "MM/DD/YY HH:MM:SS:mmm"
        date_part = parts[0]
        time_part = parts[-1]
    else:
        # ISO: "2025-03-05T12:34:56.789" or "12:34:56.789"
        time_part = parts[0]
        date_part = None
        if "T" in time_part:
            iso_parts = time_part.split("T")
            date_part = iso_parts[0]
            time_part = iso_parts[1]
    hms = re.split(r'[:.]', time_part)
    if len(hms) < 2:
        return None
    return (date_part, int(hms[0]), int(hms[1]))


def time_histogram(events, bucket_minutes=1):
    """Group events by time bucket and return list of (bucket_label, total, error_count)."""
    # Single pass: always key with date, strip date suffix at end if only one date seen
    buckets = {}
    dates_seen = set()
    for e in events:
        ts = e.get("ts")
        if not ts:
            continue
        parsed = _parse_ts_parts(ts)
        if not parsed:
            continue
        date_part, h, m = parsed
        date_key = date_part or "_"
        dates_seen.add(date_key)
        floored = (m // bucket_minutes) * bucket_minutes
        key = f"{date_key} {h:02d}:{floored:02d}"
        if key not in buckets:
            buckets[key] = {"total": 0, "errors": 0}
        buckets[key]["total"] += 1
        if e.get("level") in ("ERROR", "SEVERE", "FATAL"):
            buckets[key]["errors"] += 1

    if not buckets:
        return []

    # If single date, strip the date prefix from keys
    if len(dates_seen) == 1:
        buckets = {k.split(" ", 1)[1]: v for k, v in buckets.items()}

    return [(k, buckets[k]["total"], buckets[k]["errors"]) for k in sorted(buckets)]


def render_histogram(hist, bar_width=40):
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


def pick_samples(events, n):
    # deduplicate by (level, code, exception) to avoid showing near-identical events
    seen = set()
    unique = []
    for e in events:
        key = (e["level"], e["code"], e["exception"])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    # prioritize: ERROR/SEVERE, then with exception, then tagged
    def score(e):
        s = 0
        if e["level"] in ("FATAL",): s += 4
        if e["level"] in ("ERROR", "SEVERE"): s += 3
        if e["level"] in ("WARNING",): s += 1
        if e["exception"]: s += 2
        if e["code"]: s += 1
        if e["tags"]: s += 1
        return -s
    return sorted(unique, key=score)[:n]

def per_file_summary(events):
    """Return list of (filename, total, error_count) for each source file."""
    files = {}
    for e in events:
        f = e["file"]
        if f not in files:
            files[f] = {"total": 0, "errors": 0}
        files[f]["total"] += 1
        if e.get("level") in ("ERROR", "SEVERE", "FATAL"):
            files[f]["errors"] += 1
    return [(f, files[f]["total"], files[f]["errors"]) for f in sorted(files)]


def render_markdown_report(events, top_n=10, samples_n=5, hist_minutes=1):
    """Generate a complete markdown triage report from parsed events."""
    s = summarize(events, top_n)
    samples = pick_samples(events, samples_n)
    hist = time_histogram(events, bucket_minutes=hist_minutes)
    file_summary = per_file_summary(events)

    md = []
    md.append("# WebSphere/Java Log Triage Report")
    md.append("")
    md.append(f"- Files: {len(file_summary)}")
    md.append(f"- Parsed events: {s['total_events']}")
    md.append("")

    if len(file_summary) > 1:
        md.append("## Per-File Breakdown")
        for fname, total, errors in file_summary:
            err_note = f" ({errors} errors)" if errors else ""
            md.append(f"- `{fname}`: {total} events{err_note}")
        md.append("")

    md.append("## Top Levels")
    md += [f"- **{k}**: {v}" for k, v in s["levels"]]
    md.append("")
    md.append("## Top WebSphere/Liberty Codes")
    md += [f"- `{k}`: {v}" for k, v in s["codes"]] or ["- _(none detected)_"]
    md.append("")
    md.append("## Top Exceptions/Errors")
    md += [f"- `{k}`: {v}" for k, v in s["exceptions"]] or ["- _(none detected)_"]
    md.append("")
    md.append("## Signal Tags")
    md += [f"- **{k}**: {v}" for k, v in s["tags"]] or ["- _(none detected)_"]
    md.append("")
    md.append("## Timeline (events per minute)")
    md.append("")
    md.append("```")
    md += render_histogram(hist)
    md.append("```")
    md.append("")
    md.append("## Sample Events (sanitized)")
    md.append("")
    for idx, e in enumerate(samples, start=1):
        header = f"### {idx}. {e['level'] or 'UNKNOWN'}"
        if e["code"]: header += f" `{e['code']}`"
        if e["exception"]: header += f" -- {e['exception']}"
        if e["ts"]: header += f" ({e['ts']})"
        md.append(header)
        parts = []
        if e["tags"]:
            parts.append(f"Tags: {', '.join(e['tags'])}")
        if e["thread_id"]:
            parts.append(f"Thread: 0x{e['thread_id']}")
        if e["root_cause"] and e["root_cause"] != e["exception"]:
            parts.append(f"Root cause: `{e['root_cause']}`")
        if parts:
            md.append(f"- {' | '.join(parts)}")
        md.append("")
        md.append("```")
        md.append(e["text"][:4000])
        if len(e["text"]) > 4000:
            md.append("\n...[TRUNCATED]...")
        md.append("```")
        md.append("")

    return "\n".join(md)


def main():
    ap = argparse.ArgumentParser(description="WebSphere/Java log analyzer (quick triage).")
    ap.add_argument("paths", nargs="+", help="Log files (supports .gz). Globs allowed by shell.")
    ap.add_argument("--max-lines", type=int, default=None, help="Limit lines per file (speed/safety).")
    ap.add_argument("--top", type=int, default=10, help="Top-N items in summary.")
    ap.add_argument("--samples", type=int, default=5, help="How many sample events to print.")
    ap.add_argument("--hist-minutes", type=int, default=1, help="Histogram bucket size in minutes.")
    ap.add_argument("--out", default="report.md", help="Write markdown report to this file.")
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format.")
    ap.add_argument("--claude", action="store_true", help="Also ask Claude for root-cause suggestions (sanitized).")
    args = ap.parse_args()

    all_events = []
    for p in args.paths:
        path = Path(p).expanduser()
        if not path.exists():
            print(f"Skip (not found): {path}", file=sys.stderr)
            continue
        all_events.extend(parse_file(path, args.max_lines))

    if not all_events:
        print("No events parsed. Are the files empty or binary/scanned?", file=sys.stderr)
        sys.exit(2)

    out_path = Path(args.out)

    if args.format == "json":
        s = summarize(all_events, args.top)
        samples = pick_samples(all_events, args.samples)
        hist = time_histogram(all_events, bucket_minutes=args.hist_minutes)
        file_summary = per_file_summary(all_events)
        data = {
            "files": [{"file": f, "events": t, "errors": e} for f, t, e in file_summary],
            "total_events": s["total_events"],
            "levels": dict(s["levels"]),
            "codes": dict(s["codes"]),
            "exceptions": dict(s["exceptions"]),
            "tags": dict(s["tags"]),
            "timeline": [{"bucket": b, "total": t, "errors": e} for b, t, e in hist],
            "samples": [
                {
                    "level": e["level"],
                    "thread_id": e["thread_id"],
                    "code": e["code"],
                    "exception": e["exception"],
                    "root_cause": e["root_cause"],
                    "ts": e["ts"],
                    "tags": e["tags"],
                    "text": e["text"][:4000],
                }
                for e in samples
            ],
        }
        report = json.dumps(data, indent=2)
        if out_path.suffix == ".md":
            out_path = out_path.with_suffix(".json")
        out_path.write_text(report, encoding="utf-8")
        print(f"Wrote report: {out_path}")
    else:
        report = render_markdown_report(all_events, top_n=args.top, samples_n=args.samples, hist_minutes=args.hist_minutes)
        out_path.write_text(report, encoding="utf-8")
        print(f"Wrote report: {out_path}")

    if args.claude:
        try:
            from anthropic import Anthropic
        except ImportError:
            print("anthropic package not installed. Install with: pip install anthropic", file=sys.stderr)
            sys.exit(1)

        prompt = (
            "You are a senior Java/WebSphere SRE. Based on this TRIAGE REPORT (sanitized), give:\n"
            "1) likely root causes (ranked),\n"
            "2) next debugging steps (specific),\n"
            "3) quick mitigations,\n"
            "4) what extra info you would ask for.\n\n"
            "Be careful not to request secrets. If data seems truncated, note assumptions.\n\n"
            f"--- TRIAGE REPORT START ---\n{report[:12000]}\n--- TRIAGE REPORT END ---"
        )
        try:
            client = Anthropic()
            message = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            analysis = message.content[0].text
            analysis_path = out_path.parent / "claude-analysis.md"
            analysis_path.write_text(analysis, encoding="utf-8")
            print(f"Wrote claude-analysis.md: {analysis_path}")
        except Exception as ex:
            print(f"Claude API call failed: {ex}", file=sys.stderr)
            print("Tip: ensure ANTHROPIC_API_KEY is set.", file=sys.stderr)

if __name__ == "__main__":
    main()
