# PostgreSQL Log Analysis

## Log Format

PostgreSQL has its own log format that is NOT Log4j, despite superficial similarity.

### Default Format (log_line_prefix = '%m [%p] ')
```
2025-03-11 10:15:33.123 UTC [1234] LOG:  database system is ready to accept connections
2025-03-11 10:15:34.456 UTC [5678] ERROR:  relation "missing_table" does not exist at character 15
2025-03-11 10:15:35.789 UTC [9999] FATAL:  too many connections for role "appuser"
2025-03-11 10:15:36.012 UTC [4321] WARNING:  deadlock detected
```

**Pattern**: `YYYY-MM-DD HH:MM:SS.sss TZ [PID] LEVEL: message`

### Extended Format (log_line_prefix = '%m [%p] %q%u@%d ')
```
2025-03-11 10:15:33.123 UTC [1234] appuser@mydb LOG:  statement: SELECT * FROM users
2025-03-11 10:15:34.456 UTC [5678] appuser@mydb ERROR:  permission denied for table admin_config
```

### Key Differences from Log4j
| Aspect | PostgreSQL | Log4j |
|--------|-----------|-------|
| PID | `[1234]` after timezone | No PID in brackets |
| Level suffix | `LOG:`, `ERROR:`, `FATAL:` (with colon) | `ERROR`, `WARN` (no colon) |
| Level names | `LOG`, `FATAL`, `PANIC`, `DETAIL`, `HINT`, `STATEMENT` | `INFO`, `ERROR`, `WARN`, `DEBUG`, `TRACE` |
| No logger name | No package/class path | `com.example.Class` |
| Continuation | `DETAIL:`, `HINT:`, `STATEMENT:` lines | Stacktrace, `Caused by:` |

### Level Mapping
| PG Level | LogPilot Level | Meaning |
|----------|---------------|---------|
| PANIC | FATAL | Server shutdown required |
| FATAL | ERROR | Session terminated |
| ERROR | ERROR | Command failed |
| WARNING | WARNING | Potential issue |
| LOG | INFO | Normal operation (confusing name!) |
| INFO | INFO | Requested by user (VACUUM VERBOSE etc) |
| NOTICE | INFO | Helpful hint to user |
| DEBUG1-5 | DEBUG | Developer debugging |
| DETAIL | (continuation) | Extra detail for previous message |
| HINT | (continuation) | Suggested fix for previous error |
| STATEMENT | (continuation) | SQL that caused the error |

### Detection Regex
```python
# PostgreSQL timestamp + PID + level
PG_LINE_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+'
    r'(?P<tz>\S+)\s+'
    r'\[(?P<pid>\d+)\]\s+'
    r'(?:(?P<user>\S+)@(?P<db>\S+)\s+)?'
    r'(?P<level>LOG|ERROR|FATAL|PANIC|WARNING|INFO|NOTICE|DEBUG[1-5]|DETAIL|HINT|STATEMENT|CONTEXT):\s+'
    r'(?P<message>.*)'
)

# Continuation: DETAIL, HINT, STATEMENT, CONTEXT lines
PG_CONTINUATION_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\S+\s+\[\d+\]\s+'
    r'(?:DETAIL|HINT|STATEMENT|CONTEXT):\s+'
)
```

## High-Impact Error Patterns

### Connection Limits
```
FATAL:  too many connections for role "appuser"
FATAL:  remaining connection slots are reserved for non-replication superuser connections
FATAL:  sorry, too many clients already
```
**SQLSTATE**: `53300` (too_many_connections)

### Deadlocks
```
ERROR:  deadlock detected
DETAIL:  Process 1234 waits for ShareLock on transaction 5678; blocked by process 9999.
         Process 9999 waits for ShareLock on transaction 1234; blocked by process 1234.
HINT:  See server log for query details.
STATEMENT:  UPDATE accounts SET balance = balance - 100 WHERE id = 42
```
**SQLSTATE**: `40P01` (deadlock_detected)

### Disk Full
```
PANIC:  could not write to file "pg_wal/xlog": No space left on device
FATAL:  could not extend file "base/16384/12345": No space left on device
WARNING:  terminating connection because of crash of another server process
```
**SQLSTATE**: `53100` (disk_full)

### Authentication
```
FATAL:  password authentication failed for user "appuser"
FATAL:  no pg_hba.conf entry for host "192.168.1.100", user "appuser", database "mydb"
LOG:  could not receive data from client: Connection reset by peer
```

### Replication
```
FATAL:  could not start WAL streaming: ERROR: replication slot "replica1" does not exist
LOG:  started streaming WAL from primary at 0/5000000 on timeline 1
ERROR:  requested WAL segment 000000010000000000000005 has already been removed
```

### Query Performance
```
LOG:  duration: 15234.567 ms  statement: SELECT * FROM large_table WHERE unindexed_column = 'value'
LOG:  temporary file: path "base/pgsql_tmp/pgsql_tmp1234.5", size 104857600
WARNING:  worker process: parallel worker for PID 1234 (PID 5678) was terminated by signal 9: Killed
```

### Corruption / Recovery
```
PANIC:  could not locate a valid checkpoint record
LOG:  database system was not properly shut down; automatic recovery in progress
LOG:  redo starts at 0/1234567
LOG:  consistent recovery state reached at 0/2345678
LOG:  database system is ready to accept connections
```

## Signal Tags

| Tag | Trigger patterns |
|-----|-----------------|
| `DB/Pool` | `too many connections`, `connection slots`, `too many clients`, SQLSTATE 53300 |
| `OOM/GC` | `out of memory`, `Killed`, signal 9 |
| `SSL/TLS` | `SSL`, `certificate`, `pg_hba.conf` with SSL |
| `Auth` | `authentication failed`, `no pg_hba.conf entry`, `password` |
| `Disk` | `No space left`, `could not extend file`, `could not write`, SQLSTATE 53100 |
| `Replication` | `WAL`, `streaming`, `replication slot`, `primary`, `standby` |

## Multiline Events

PostgreSQL multiline events have a specific pattern:
```
ERROR:  syntax error at or near "SELCT"         ← main event
DETAIL:  Expected keyword "SELECT".              ← continuation (same PID, same timestamp)
HINT:  Check your SQL syntax.                    ← continuation
STATEMENT:  SELCT * FROM users                   ← continuation (the actual SQL)
```

`DETAIL`, `HINT`, `STATEMENT`, and `CONTEXT` lines belong to the preceding `ERROR`/`FATAL`/`WARNING` line. They share the same PID.

## Relevance for LogPilot SaaS

PostgreSQL is LogPilot's own database in team/SaaS mode. Being able to analyze our own Postgres logs with LogPilot is:
1. A quality signal ("eat your own dog food")
2. Useful for debugging our own production issues
3. A demo opportunity

## Related Skills
- `skills/database-errors.md` — PostgreSQL SQLSTATE codes in Java applications
- `skills/syslog-analysis.md` — PostgreSQL often logs via syslog in production
