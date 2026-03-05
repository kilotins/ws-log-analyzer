#!/usr/bin/env python3
import argparse
import gzip
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import sys

# --- Common patterns (WebSphere / Java-ish) ---
TS_PATTERNS = [
    # WebSphere common: [2025-03-05 12:34:56:789 CET] or similar variants
    re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,:.]\d{3,6})?)'),
    # ISO-like without date brackets
    re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.:]\d{3,6})?)'),
]

LEVEL_RE = re.compile(r'\b(SEVERE|ERROR|WARN|WARNING|INFO|DEBUG|FINE|FINER|FINEST)\b', re.IGNORECASE)

# WebSphere / Liberty codes you often see
WAS_CODE_RE = re.compile(r'\b(SRVE\d{4}[A-Z]?|WSWS\d{4}[A-Z]?|J2CA\d{4}[A-Z]?|HMGR\d{4}[A-Z]?|TRAS\d{4}[A-Z]?|CWWKZ\d{4}[A-Z]?|CWWKE\d{4}[A-Z]?|CWWKT\d{4}[A-Z]?)\b')

# Java exceptions / errors
EXC_HEAD_RE = re.compile(r'\b([a-zA-Z_.$]+Exception|Error)\b')
STACK_LINE_RE = re.compile(r'^\s+at\s+[\w.$]+\(.*\)$')
CAUSED_BY_RE = re.compile(r'^\s*Caused by:\s+(?P<cause>.+)$')

OOM_RE = re.compile(r'OutOfMemoryError|Java heap space|GC overhead limit exceeded', re.IGNORECASE)
HUNG_THREAD_RE = re.compile(r'hung thread|ThreadMonitor|WSVR\d{4}|stuck thread', re.IGNORECASE)
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

def parse_file(path: Path, max_lines: int):
    events = []
    current = []
    current_meta = {"file": str(path), "first_ts": None}

    def flush():
        nonlocal current, current_meta
        if not current:
            return
        text = "\n".join(current)
        text = redact(text)
        # classify
        lvl = None
        m = LEVEL_RE.search(text)
        if m: lvl = m.group(1).upper()
        code = None
        cm = WAS_CODE_RE.search(text)
        if cm: code = cm.group(1)
        exc = None
        em = EXC_HEAD_RE.search(text)
        if em: exc = em.group(1)
        tags = bucket_tags(text)

        events.append({
            "file": current_meta["file"],
            "ts": current_meta["first_ts"],
            "level": lvl,
            "code": code,
            "exception": exc,
            "tags": sorted(tags),
            "text": text
        })
        current = []
        current_meta = {"file": str(path), "first_ts": None}

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

            current.append(line)

            # If we hit blank line after a stacktrace, flush
            if not line.strip() and current and any(STACK_LINE_RE.match(x) or "Caused by:" in x for x in current):
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

def pick_samples(events, n):
    # prioritize: ERROR/SEVERE, then with exception, then tagged
    def score(e):
        s = 0
        if e["level"] in ("ERROR", "SEVERE"): s += 3
        if e["exception"]: s += 2
        if e["code"]: s += 1
        if e["tags"]: s += 1
        return -s
    return sorted(events, key=score)[:n]

def main():
    ap = argparse.ArgumentParser(description="WebSphere/Java log analyzer (quick triage).")
    ap.add_argument("paths", nargs="+", help="Log files (supports .gz). Globs allowed by shell.")
    ap.add_argument("--max-lines", type=int, default=None, help="Limit lines per file (speed/safety).")
    ap.add_argument("--top", type=int, default=10, help="Top-N items in summary.")
    ap.add_argument("--samples", type=int, default=5, help="How many sample events to print.")
    ap.add_argument("--out", default="report.md", help="Write markdown report to this file.")
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

    s = summarize(all_events, args.top)
    samples = pick_samples(all_events, args.samples)

    md = []
    md.append("# WebSphere/Java Log Triage Report")
    md.append("")
    md.append(f"- Files: {len(set(e['file'] for e in all_events))}")
    md.append(f"- Parsed events: {s['total_events']}")
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
    md.append("## Sample Events (sanitized)")
    md.append("")
    for idx, e in enumerate(samples, start=1):
        header = f"### {idx}. {e['level'] or 'UNKNOWN'}"
        if e["code"]: header += f" `{e['code']}`"
        if e["exception"]: header += f" — {e['exception']}"
        if e["ts"]: header += f" ({e['ts']})"
        md.append(header)
        if e["tags"]:
            md.append(f"- Tags: {', '.join(e['tags'])}")
        md.append("")
        md.append("```")
        md.append(e["text"][:4000])  # avoid huge dump
        if len(e["text"]) > 4000:
            md.append("\n...[TRUNCATED]...")
        md.append("```")
        md.append("")

    report = "\n".join(md)
    Path(args.out).write_text(report, encoding="utf-8")
    print(f"✅ Wrote report: {args.out}")

    if args.claude:
        # Keep it short and safe: send summary + samples only (already redacted)
        prompt = f"""
You are a senior Java/WebSphere SRE. Based on this TRIAGE REPORT (sanitized),
give:
1) likely root causes (ranked),
2) next debugging steps (specific),
3) quick mitigations,
4) what extra info you would ask for.

Be careful not to request secrets. If data seems truncated, note assumptions.

--- TRIAGE REPORT START ---
{report[:12000]}
--- TRIAGE REPORT END ---
"""
        # Call Claude via CLI if present
        import subprocess
        try:
            out = subprocess.check_output(["claude"], input=prompt.encode("utf-8"))
            Path("claude-analysis.md").write_bytes(out)
            print("✅ Wrote claude-analysis.md")
        except Exception as ex:
            print(f"⚠️ Claude call failed: {ex}", file=sys.stderr)
            print("Tip: run `claude doctor` and ensure you're authenticated.", file=sys.stderr)

if __name__ == "__main__":
    main()
