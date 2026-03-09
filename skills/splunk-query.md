# Splunk Query Patterns for WAS Logs

## Index Conventions

Typical WAS log indexes:
- `index=websphere` — main application logs
- `index=was_systemout` — SystemOut.log
- `index=was_systemerr` — SystemErr.log
- `index=liberty` — Liberty server logs

Common fields: `source`, `host`, `sourcetype`, `severity`, `msg_code`

## Essential Queries

### Error Spike Detection
```spl
index=websphere severity=E
| timechart span=5m count by msg_code
```

### Top Error Codes in Time Range
```spl
index=websphere severity=E earliest=-4h
| stats count by msg_code
| sort -count
| head 20
```

### Specific Message Code with Context
```spl
index=websphere msg_code="SRVE0255E"
| table _time host source msg_code _raw
| sort -_time
```

### Exception Frequency
```spl
index=websphere "Exception"
| rex field=_raw "(?P<exception>\w+Exception)"
| stats count by exception
| sort -count
```

### Hung Thread Timeline
```spl
index=websphere msg_code="WSVR0605W"
| timechart span=1h count by host
```

### Connection Pool Exhaustion
```spl
index=websphere (msg_code="DSRA0080E" OR msg_code="J2CA0045E")
| timechart span=10m count by host
```

### SSL Certificate Errors
```spl
index=websphere msg_code="CWPKI*"
| stats count by msg_code
| sort -count
```

### Server Restart Detection
```spl
index=websphere (msg_code="WSVR0001I" OR msg_code="WSVR0024I")
| table _time host msg_code
| sort -_time
```

## Correlation Queries

### Errors Leading Up to Outage
```spl
index=websphere severity=E earliest=-30m@m latest=@m
| stats count by msg_code host
| sort -count
```

### Multi-Host Error Comparison
```spl
index=websphere severity=E
| stats count by host msg_code
| xyseries host msg_code count
```

### Error Rate vs Normal Baseline
```spl
index=websphere severity=E
| timechart span=1h count as error_count
| predict error_count as predicted
| eval anomaly=if(error_count > predicted + 2*stdev, 1, 0)
| where anomaly=1
```

## Query Building Tips

- Always scope with `earliest=` / `latest=` to limit scan
- Use `msg_code` field extraction instead of raw text search when possible
- `stats count by` is cheaper than `timechart` for large datasets
- Chain `| head 20` to limit results during exploration
- Use `| transaction` sparingly — it's expensive on large datasets

## Field Extraction Setup

If `msg_code` and `severity` aren't pre-extracted, add these to your Splunk props/transforms:

### Inline Extraction (search-time)
```spl
index=websphere
| rex field=_raw "\]\s+[0-9a-f]+\s+\S+\s+(?P<severity>[IAWEOFRD])\s"
| rex field=_raw "(?P<msg_code>[A-Z]{4,5}\d{4}[A-Z])"
```

### Props.conf (permanent extraction)
```ini
[websphere:systemout]
EXTRACT-severity = \]\s+[0-9a-f]+\s+\S+\s+(?P<severity>[IAWEOFRD])\s
EXTRACT-msg_code = (?P<msg_code>[A-Z]{4,5}\d{4}[A-Z])
EXTRACT-thread_id = \]\s+(?P<thread_id>[0-9a-f]{8})\s+
EXTRACT-exception = (?P<exception>[a-zA-Z_$]+(?:\.[a-zA-Z_$]+)+(?:Exception|Error))
```

## JSON Log Parsing (Liberty)

Liberty JSON logs need different field extraction:
```spl
index=liberty sourcetype=_json
| spath loglevel | spath message | spath module
| search loglevel="ERROR"
```

For mixed environments (some servers text, some JSON):
```spl
(index=websphere sourcetype=websphere:systemout severity=E)
OR (index=liberty sourcetype=_json loglevel="ERROR")
```

## Transaction Tracing

Following a single request across log entries:
```spl
index=websphere "requestId=abc123"
| sort _time
| table _time host thread_id msg_code _raw
```

If no request ID, correlate by thread:
```spl
index=websphere thread_id="0000004e" earliest="2024-01-15T10:30:00" latest="2024-01-15T10:31:00"
| sort _time
| table _time msg_code _raw
```

## Log Source Variations

Different WAS versions log to different files:
| File | Content | Splunk sourcetype |
|------|---------|-------------------|
| SystemOut.log | tWAS stdout, app logs | websphere:systemout |
| SystemErr.log | tWAS stderr, stacktraces | websphere:systemerr |
| messages.log | Liberty primary log | liberty:messages |
| trace.log | Detailed trace (verbose) | liberty:trace |
| ffdc/*.log | First Failure Data Capture | websphere:ffdc |

### FFDC Files (often overlooked)
```spl
index=websphere sourcetype=websphere:ffdc
| stats count by exception_name
| sort -count
```
FFDC captures detailed diagnostics on first occurrence of an error — often contains more context than SystemOut.

## Alert Patterns

### Critical: OOM or Hung Thread Spike
```spl
index=websphere (msg_code="WSVR0605W" OR "OutOfMemoryError")
| timechart span=5m count
| where count > 5
```
Alert action: Page on-call, take thread dump/heap dump immediately.

### Warning: Error Rate Anomaly
```spl
index=websphere severity=E
| timechart span=15m count as errors
| predict errors as predicted future_timespan=0
| eval deviation = errors - predicted
| where deviation > 3 * stdev
```

### Info: Unexpected Restart
```spl
index=websphere msg_code="WSVR0001I"
| where date_wday NOT IN ("saturday","sunday")
| where date_hour >= 8 AND date_hour <= 18
```
Server restarts during business hours outside maintenance windows.

## Lookup Tables for Enrichment

Create a CSV lookup to enrich WAS codes with descriptions:
```
msg_code,description,severity_level,runbook_url
SRVE0255E,"Uncaught servlet exception",critical,https://wiki/runbook/srve0255
DSRA0080E,"Connection pool exhausted",critical,https://wiki/runbook/dsra0080
WSVR0605W,"Possible hung thread",warning,https://wiki/runbook/wsvr0605
```

Use in searches:
```spl
index=websphere severity=E
| lookup was_codes msg_code OUTPUT description runbook_url
| table _time host msg_code description runbook_url
```
