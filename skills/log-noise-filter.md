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
- Deployment failures (`CWWKZ0013E`, `CWWKZ0002E`)
- JNDI failures (`CWNEN1001E`)

## Application-Specific Noise

Custom application logging often generates repetitive messages:
```
INFO com.example.scheduler.HealthPing: Service alive [OK]     ← every 10s, noise
INFO com.example.cache.CacheManager: Cache stats: hits=1234   ← every 60s, noise
```

Detection heuristics:
- Same logger class + same message template + regular interval = noise
- Extract the logger class name and group by it
- If count > 100 and no associated errors → safe to filter

## Noisy But Correlated Events

Some events appear often but cluster around real errors. These should NOT be filtered:
```
DSRA7600I: Datasource cleanup    ← normally noise (routine cleanup)
DSRA7600I × 50 in 1 minute      ← signal! Pool churn indicates connection instability
```

Rules:
- If a normally-noisy code appears at 10x its normal rate → treat as signal
- If a noise code appears within 30 seconds of an E-severity event → keep it for context
- Calculate baseline rate per code over a 24h window; spikes above 3x baseline = signal

## Time-Series Noise Patterns

### Daily Recurring Patterns
Some errors appear at the same time daily (batch jobs, scheduled tasks):
```
03:00 WSVR0605W × 5  ← hung threads during nightly batch, resolves by 03:15
```
If same pattern appears every day at same time → scheduled job, not an incident.

Detection: Group errors by hour-of-day across 7 days. Consistent patterns = scheduled.

### Startup Noise Burst
Every server restart produces a burst of I/W messages:
```
WSVR0001I → CWPKI0003I → SRVE0169I → SRVE0242I × many → WSVR0024I
```
Filter strategy: Suppress all I-severity messages between WSVR0001I and WSVR0024I unless E-severity also appears in that window.

## Noise Scoring Model

Assign a noise score (0.0 = pure signal, 1.0 = pure noise) to each event:

| Factor | Score Impact |
|--------|-------------|
| Severity I or A | +0.3 |
| Appears > 1000 times identical | +0.4 |
| Regular interval (±5% timing) | +0.2 |
| Same message in last 24h, no incident | +0.1 |
| Appears within 60s of E-severity | -0.5 |
| Rate spike > 3x baseline | -0.3 |
| On never-filter list | score = 0.0 |

Events with score > 0.7 are candidates for filtering. Always review before permanently suppressing.

## See Also

- [message-codes.md](message-codes.md) — Identifying safe-to-ignore I-suffix codes
- [splunk-query.md](splunk-query.md) — Splunk queries to measure noise ratios
- [gc-performance.md](gc-performance.md) — Filtering verbose GC log noise
