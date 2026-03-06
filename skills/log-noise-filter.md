# Log Noise Filtering

## Purpose

Production WAS logs are noisy. Filtering noise from signal speeds up triage and reduces AI analysis costs (fewer tokens).

## Safe-to-Ignore Patterns

### Informational Lifecycle Messages
These appear during normal operation and carry no diagnostic value:
- `SRVE0242I` — Servlet loaded (expected during startup)
- `SESN0176I` — Session invalidated (normal timeout)
- `WSVR0001I` / `WSVR0024I` — Server start/ready (unless unexpected restart)
- `CWWKF0012I` — Feature bundle resolved
- `DSRA7600I` — Datasource cleanup
- `CWWKZ0009I` — Application stopped (if deliberate)

### Periodic Health/Heartbeat
- DCS heartbeat messages (`DCSV*I`)
- HAManager status (`HMGR*I`)
- Session replication pings
- Timer tick logs

### Known Harmless Warnings
Some warnings are cosmetic or known-won't-fix:
- `SESN0066W` with "non-serializable attribute" for dev-time debugging objects
- `SRVE0190E` with "broken pipe" — client disconnected, not a server problem
- `TCPC0002W` with "connection reset" — client-side abort

## Noise Detection Heuristics

### Frequency-Based
If a message code appears > 1000 times with identical text, it's likely noise:
```python
# High-frequency identical messages are noise candidates
if count > 1000 and unique_messages == 1:
    noise_score += 0.8
```

### Severity-Based
- `I` (info) messages are noise unless correlated with an error window
- `A` (audit) messages are noise for performance triage, signal for security triage

### Time-Based
Messages that appear at regular intervals (e.g., every 60s) are typically scheduled tasks or health checks, not symptoms.

## Noise-Aware Analysis

### Before AI Analysis
1. Count events by message code
2. Remove codes where count > threshold AND severity is I/A
3. Keep all E and W severity events
4. Keep I/A events only within +/- 5 minutes of an error cluster

### Reducing Prompt Size
When building AI prompts from many events:
1. Deduplicate identical stacktraces (show count instead)
2. Show only top N unique error patterns
3. Truncate repeated log lines to first occurrence + count
4. Strip framework noise lines from stacktraces

## Never Filter

These should never be filtered regardless of frequency:
- Any `E` severity message with a stacktrace
- `OutOfMemoryError` (any occurrence)
- `WSVR0605W` (hung thread)
- `DSRA0080E` (connection pool exhausted)
- Security audit failures (`CWWKS1100A`, `CWWKS9104A`)
- Certificate errors (`CWPKI*E`)
- Transaction errors (`WTRN*E`)
