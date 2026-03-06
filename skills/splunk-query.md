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
