# Database Error Codes in Java Application Logs

## Overview

This skill covers database-specific error codes as they appear **inside Java application logs** — particularly WebSphere/Liberty logs where the JVM catches and re-wraps JDBC errors. These are not database log parsers. LogPilot matches these codes in event text, JDBC stack traces, and WAS DSRA/J2CA wrappers.

Key source locations in WAS logs:
- `DSRA0010E` — encapsulates the raw `SQLException` with embedded database error text
- `J2CA0081E` / `J2CA0046E` — connection pool failures that often expose database codes
- `SRVE0255E` — uncaught servlet exception whose root `Caused by:` is a database error

---

## Oracle (ORA- codes)

Oracle errors appear verbatim inside `java.sql.SQLException` messages and DSRA wrappers.

### Top Production Errors

| Code | Meaning | Typical Cause | What to Check |
|------|---------|--------------|---------------|
| `ORA-00001` | Unique constraint violated | Duplicate insert; race condition in batch | Constraint name in message; check idempotency of insert logic |
| `ORA-00054` | Resource busy / NOWAIT timeout | DML locked table; SELECT FOR UPDATE contention | Blocking session in V$SESSION; missing COMMIT after prior DML |
| `ORA-00060` | Deadlock detected | Two sessions waiting on each other's row locks | AWR deadlock graph; fix transaction ordering or add retry |
| `ORA-00942` | Table or view does not exist | Schema mismatch; wrong DB user; missing synonym | JDBC user's privileges; deployed schema version |
| `ORA-01000` | Maximum open cursors exceeded | JDBC cursor leak; PreparedStatement not closed | Increase OPEN_CURSORS or fix cursor close in finally blocks |
| `ORA-01017` | Invalid username/password; logon denied | Credentials changed; wrong datasource config | WAS JDBC datasource auth alias; DB password rotation |
| `ORA-01555` | Snapshot too old | UNDO tablespace too small; long-running query vs high DML | Increase UNDO_RETENTION; add UNDO tablespace space |
| `ORA-01652` | Unable to extend temp segment | TEMP tablespace full | Sort operations; add TEMP space or limit query sort volume |
| `ORA-01653` | Unable to extend table in tablespace | Data tablespace full | Add datafiles or resize existing; check DF occupancy |
| `ORA-03113` | End-of-file on communication channel | DB listener/process died; network cut mid-session | Alert log for ORA-600/ORA-7445; network stability |
| `ORA-03114` | Not connected to ORACLE | Session was killed or connection lost | Connection pool stale connections; enable connection validation |
| `ORA-04031` | Unable to allocate shared pool memory | Shared pool exhausted; large SQL parse storm | Pin packages; flush shared_pool; check parse/execute ratio |
| `ORA-12170` | TNS: Connect timeout occurred | DB host unreachable; firewall blocking 1521 | Network path, firewall rules, listener status |
| `ORA-12514` | TNS: listener does not know of service | Wrong service name in JDBC URL | tnsnames.ora / JDBC URL service name vs registered services |
| `ORA-12541` | TNS: no listener | Listener not running or wrong port | `lsnrctl status` on DB host; JDBC URL host/port |
| `ORA-28000` | Account is locked | Too many failed logins; DBA locked account | `ALTER USER ... ACCOUNT UNLOCK`; check for brute-force loops |

### Oracle Regex Pattern (LogPilot)

```python
r"ORA-\d{4,5}"
```

### Oracle in Java Stacktraces

```
java.sql.SQLException: ORA-12514: TNS:listener does not currently know of service requested in connect descriptor
    at oracle.jdbc.driver.T4CTTIoer.processError(T4CTTIoer.java:447)
    ...
Caused by: oracle.net.ns.NetException: The Network Adapter could not establish the connection
```

```
com.ibm.websphere.ce.cm.StaleConnectionException: [jcc][t4][20128][10761][...] Error opening socket to server. ERRORCODE=...
Caused by: java.sql.SQLException: ORA-00060: deadlock detected while waiting for resource
```

---

## DB2 (SQLCODE / SQL0xxx)

DB2 errors appear as `SQLCODE -NNN` or embedded in `com.ibm.db2.jcc.am.SqlException` messages.

### Top Production Errors

| SQLCODE | SQLSTATE | Meaning | Typical Cause | What to Check |
|---------|----------|---------|--------------|---------------|
| `-204` | `42704` | Object not defined to DB2 | Table/index missing; wrong schema | Schema name in JDBC URL; deployment ran DDL? |
| `-530` | `23503` | FK referential constraint violation | Insert/update referencing nonexistent parent key | Parent row missing; data quality issue |
| `-803` | `23505` | Duplicate key value | Unique constraint or PK violation | Sequence reset; race condition; idempotent insert |
| `-904` | `57011` | Resource unavailable | Lock escalation; DB2 tablespace unavailable | DB2 diagnostic log; HADR state; tablespace status |
| `-911` | `40001` | Deadlock or timeout; transaction rolled back | Two transactions deadlocked; lock timeout exceeded | DB2 deadlock event monitor; `LOCKTIMEOUT` DB config |
| `-1024` | `58004` | More than one row from subquery | Subquery returning multiple rows where scalar expected | Application SQL logic error |
| `-1034` | `57019` | Database is not available | DB2 instance not activated; crash recovery | `db2 activate db`; check db2diag.log |
| `-1224` | `55032` | DB2 agent not available | Max agents exhausted; DB2 instance overloaded | `MAXAGENTS`/`MAX_CONNECTIONS` DB config; connection pool sizing |
| `-1585` | `54048` | Log file space exhausted | Transaction log full; long uncommitted transaction | Increase `LOGFILSIZ`/`LOGPRIMARY`; check for runaway transactions |
| `-4499` | `08001` | Failed to connect to DB2 | Network failure; DB down; wrong host/port | JDBC URL; DB2 instance status; firewall |
| `-30081` | `08001` | Communication error | Network interruption; DB2 TCP listener down | DB2 TCPIP service name; network path |
| `-30082` | `08001` | Connection failed; security reason | Wrong password; Kerberos failure | Auth mechanism in JDBC URL; DB2 SYSIBM.SYSDUMMY1 test |
| `-911` | `40001` | Row lock timeout (timeout variant) | `LOCKTIMEOUT` seconds exceeded | Increase `LOCKTIMEOUT`; add retry; check blocking transactions |
| `-964` | `57011` | Transaction log full | High insert/update volume; no log archiving | LOGARCHMETH1; increase log space |
| `-20542` | `57053` | BLU columnar table read error | Internal catalog inconsistency | IBM support; run REORG |

### DB2 SQLSTATE Patterns in Java

| SQLSTATE | Meaning | Maps To |
|----------|---------|---------|
| `40001` | Deadlock | `-911` deadlock rollback |
| `57011` | Insufficient resources | `-904` (lock) or `-964` (log) |
| `08001` | Connection failure | `-4499`, `-30081` |
| `23505` | Unique violation | `-803` |
| `42704` | Object not found | `-204` |

### DB2 Regex Patterns (LogPilot)

```python
r"SQLCODE[= ]-?\d+"          # matches "SQLCODE=-911" or "SQLCODE -911"
r"SQL\d{4,5}[NW]?"           # matches "SQL0904N", "SQL1585N"
r"com\.ibm\.db2\.jcc\.am\."  # DB2 JDBC driver class prefix
r"ERRORCODE=-\d+"             # DB2 JCC error code in exception message
```

### DB2 in Java Stacktraces

```
com.ibm.db2.jcc.am.SqlTransactionRollbackException: DB2 SQL Error: SQLCODE=-911, SQLSTATE=40001,
SQLERRMC=68, DRIVER=4.22.29
    at com.ibm.db2.jcc.am.id.a(id.java:660)
    ...
Caused by: com.ibm.db2.jcc.am.SqlException: DB2 SQL Error: SQLCODE=-911, SQLSTATE=40001
```

---

## Microsoft SQL Server (Msg xxx / SQLServerException)

SQL Server errors appear as `com.microsoft.sqlserver.jdbc.SQLServerException` with embedded `Msg NNNN` text.

### Top Production Errors

| Msg | Meaning | Typical Cause | What to Check |
|-----|---------|--------------|---------------|
| `823` | I/O error reading/writing database page | Disk hardware failure; storage path issue | Windows event log; disk health (SMART); SQL Server error log |
| `824` | SQL Server detected logical consistency-based I/O error | Torn page; storage corruption | DBCC CHECKDB; storage firmware; RAID controller cache |
| `845` | Timeout waiting for memory resource at buffer pool | Memory pressure; non-uniform allocation | SQL Server memory grants; `max server memory`; AWE config |
| `1204` | Could not allocate lock resources; insufficient memory | Lock memory exhausted under high concurrency | `max server memory`; `locks` configuration option |
| `1205` | Transaction was deadlocked; chosen as deadlock victim | Circular lock dependency | Trace flag 1222 deadlock graph; fix transaction ordering |
| `4064` | Cannot open user default database | User's default DB offline or deleted | `ALTER LOGIN ... WITH DEFAULT_DATABASE` |
| `8645` | Timeout waiting for memory grant | Query needing sort/hash spill can't get memory | Query plan; missing indexes; `max server memory` |
| `9002` | Transaction log for database is full | Log not being backed up; FULL recovery + no log backup | Log backup job; switch to SIMPLE recovery; add log space |
| `17803` | Insufficient memory available | SQL Server process OOM at OS level | Windows memory; `max server memory` cap |
| `17806` | SSPI handshake failed | Kerberos/NTLM auth failure | SPN registration; clock skew; domain controller availability |
| `17836` | Length specified in network packet payload did not match | Corrupted TDS packet; network driver bug | Network driver update; disable TCP chimney offload |
| `18456` | Login failed for user | Wrong password; account disabled; wrong DB | SQL error log state code (state 5 = bad password, state 38 = DB issue) |
| `18452` | Login failed; not associated with trusted connection | Windows auth on SQL auth-only instance | Authentication mode in SQL Server properties |
| `701` | There is insufficient system memory | OS-level memory exhaustion | Physical RAM; SQL `max server memory`; other processes |
| `1222` | Lock request timeout exceeded | `SET LOCK_TIMEOUT` exceeded | Blocking query; lock timeout setting in connection |

### SQL Server State Codes for Msg 18456

| State | Meaning |
|-------|---------|
| 5 | Invalid password |
| 6 | Attempt to use Windows login via SQL auth |
| 7 | Login disabled and password mismatch |
| 11 | Login valid but no server access |
| 38 | Login valid, database missing or no access |

### SQL Server Regex Patterns (LogPilot)

```python
r"Msg \d{3,5},\s*Level \d+"              # T-SQL error header
r"com\.microsoft\.sqlserver\.jdbc\."      # MSSQL JDBC driver prefix
r"SQLServerException"                     # exception class name
r"ErrorCode:\s*\d+"                       # JDBC error code in message
```

### SQL Server in Java Stacktraces

```
com.microsoft.sqlserver.jdbc.SQLServerException: Transaction (Process ID 72) was deadlocked on
lock resources with another process and has been chosen as the deadlock victim. Rerun the transaction.
    at com.microsoft.sqlserver.jdbc.SQLServerException.makeFromDatabaseError(SQLServerException.java:258)
    ...
```

```
com.microsoft.sqlserver.jdbc.SQLServerException: The transaction log for database 'AppDB' is full
due to 'LOG_BACKUP'.
```

---

## PostgreSQL (SQLSTATE xxxxx)

PostgreSQL errors surface via `org.postgresql.util.PSQLException` with embedded SQLSTATE codes.

### Top Production Errors

| SQLSTATE | Meaning | Typical Cause | What to Check |
|----------|---------|--------------|---------------|
| `08006` | Connection failure | DB server down; network cut | `pg_isready`; network path; `max_connections` |
| `08001` | Unable to connect | JDBC URL wrong; pg_hba.conf rejects | pg_hba.conf; PostgreSQL listen_addresses |
| `23505` | Unique violation | Duplicate insert; concurrent write race | Constraint name; add ON CONFLICT clause |
| `23503` | FK violation | Referenced row missing or deleted | Parent table population; delete cascade |
| `40P01` | Deadlock detected | Circular row lock dependency | Enable `log_lock_waits`; fix transaction order |
| `53100` | Disk full | Data volume or WAL volume exhausted | Disk usage; WAL accumulation; vacuum frequency |
| `53300` | Too many connections | Connection pool over limit; app leaking connections | `max_connections` in postgresql.conf; PgBouncer sizing |
| `57014` | Query cancelled (statement timeout) | `statement_timeout` hit; client cancelled | `statement_timeout` setting; slow query log |
| `57P01` | Admin shutdown | pg_ctl stop; OS SIGTERM | PostgreSQL log; planned vs unplanned shutdown |
| `42P01` | Undefined table | Schema mismatch; wrong search_path | `search_path` in connection; migration ran? |
| `XX000` | Internal error | PostgreSQL assertion / panic | pg_log for FATAL/PANIC; pg_resetwal (last resort) |
| `25P02` | In failed transaction | Prior error not handled; autocommit off | Application error handling; connection returned in error state |

### PostgreSQL Regex Patterns (LogPilot)

```python
r"org\.postgresql\.util\.PSQLException"   # PgSQL JDBC driver
r"SQLSTATE:\s*[A-Z0-9]{5}"               # five-char state in message
r"ERROR:\s+[A-Z].*\(SQLSTATE"            # Hibernate/Spring format
```

### PostgreSQL in Java Stacktraces

```
org.postgresql.util.PSQLException: FATAL: sorry, too many clients already
    at org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2553)
    ...
```

```
org.postgresql.util.PSQLException: ERROR: deadlock detected
  Detail: Process 12345 waits for ShareLock on transaction 7890; blocked by process 67890.
```

---

## MySQL / MariaDB (Error xxxx)

MySQL errors appear in `com.mysql.cj.jdbc.exceptions.CommunicationsException` or `java.sql.SQLException` with embedded `Error Code: NNNN`.

### Top Production Errors

| Error | Meaning | Typical Cause | What to Check |
|-------|---------|--------------|---------------|
| `1040` | Too many connections | `max_connections` exhausted; pool misconfigured | `SHOW STATUS LIKE 'Threads_connected'`; increase `max_connections`; check pool size |
| `1045` | Access denied for user | Wrong password or host not in grant | GRANT table; password rotation; `bind-address` |
| `1062` | Duplicate entry for key | Unique/PK violation; concurrent insert | Application upsert logic; `INSERT IGNORE` or `ON DUPLICATE KEY` |
| `1146` | Table doesn't exist | Missing migration; wrong database | `SHOW TABLES`; current database in JDBC URL |
| `1205` | Lock wait timeout exceeded | Row lock held too long; slow transaction | `innodb_lock_wait_timeout`; find blocking thread with `SHOW ENGINE INNODB STATUS` |
| `1213` | Deadlock found; try restarting transaction | Circular InnoDB row lock | InnoDB status deadlock section; fix row access ordering; add retry |
| `1215` | Cannot add foreign key constraint | FK reference to nonexistent index/type mismatch | Schema migration order; column type alignment |
| `1366` | Incorrect integer value / truncated data | Data type mismatch on insert | `sql_mode=STRICT_*`; application data validation |
| `2003` | Can't connect to MySQL server | DB host unreachable; wrong port | Network; `bind-address`; firewall; MySQL running? |
| `2006` | MySQL server has gone away | Connection idle too long (`wait_timeout`); packet too large | `wait_timeout`/`interactive_timeout`; `max_allowed_packet`; connection validation |
| `2013` | Lost connection to MySQL server during query | Network drop mid-query; query killed | `net_read_timeout`; query timeout; network stability |
| `1064` | SQL syntax error | Application-generated bad SQL; ORM mismatch | SQL text in exception; ORM version vs MySQL version |

### MySQL Regex Patterns (LogPilot)

```python
r"com\.mysql\.(cj\.)?jdbc\."                 # MySQL Connector/J driver
r"Error Code:\s*\d{4}"                       # Connector/J error code
r"CommunicationsException"                   # MySQL network/timeout wrapper
r"MySQLSyntaxErrorException"                 # SQL syntax
r"MySQLTransactionRollbackException"         # Deadlock / lock timeout
```

### MySQL in Java Stacktraces

```
com.mysql.cj.jdbc.exceptions.CommunicationsException: Communications link failure
Last packet sent to the server was 0 ms ago. The driver has not received any packets from the server.
    at sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
    ...
Caused by: java.net.ConnectException: Connection refused (Connection refused)
```

```
com.mysql.cj.jdbc.exceptions.MySQLTransactionRollbackException: Deadlock found when trying to get lock;
try restarting transaction
    at com.mysql.cj.jdbc.exceptions.SQLExceptionsMapping.translateException(SQLExceptionsMapping.java:122)
```

---

## How These Errors Appear in Java/WAS Logs

### Raw JDBC Exception

The database error is embedded directly in `java.sql.SQLException` message text:

```
java.sql.SQLException: ORA-00060: deadlock detected while waiting for resource
    at oracle.jdbc.driver.DatabaseError.throwSqlException(DatabaseError.java:112)
    at oracle.jdbc.driver.T4CTTIoer.processError(T4CTTIoer.java:331)
```

### WAS DSRA Codes Wrapping Database Errors

WebSphere wraps JDBC errors in `DSRA` codes. The raw database error is in the `Caused by:` chain:

| DSRA Code | Meaning | Inner Exception |
|-----------|---------|-----------------|
| `DSRA0010E` | SQL Exception occurred | Contains full `SQLException` text with ORA/DB2/Msg code |
| `DSRA0080A` | Exception caught | Audit trail of exception propagation |
| `DSRA9110E` | Connection is not valid | Wraps connection validation failure (stale) |
| `DSRA9010E` | Unable to get connection | Pool-level failure; inner cause is database error |

Example:

```
[ERROR] DSRA0010E: SQL State = 61000, Error Code = 60, Message: ORA-00060: deadlock detected
    while waiting for resource
```

### J2CA Connection Pool Hiding Database Error

```
[ERROR] J2CA0046E: Method createManagedConnectionWithMCWrapper caught an exception during
creation of the ManagedConnection for resource jdbc/AppDS:
com.ibm.ws.rsadapter.exceptions.DataStoreAdapterException:
...
Caused by: java.sql.SQLRecoverableException: IO Error: The Network Adapter could not establish
the connection
Caused by: oracle.net.ns.NetException: The Network Adapter could not establish the connection
```

The WAS-level code `J2CA0046E` is the visible signal; the database error (`ORA-12541`-equivalent) is in `Caused by:` depth 3+.

### Connection Pool Exhaustion Before Database Error

When all connections are in use, the pool error appears **before** the database error:

```
[ERROR] J2CA0020E: Connection pool is full with max connections: 50
```

No database code is visible here. The root cause may be:
- Slow queries caused by `ORA-01555` or `ORA-00060` holding connections
- Application not returning connections (`finally` block missing close)

### Spring / Hibernate Wrapping

Spring translates `SQLExceptions` to its own hierarchy. The database code is in the message:

```
org.springframework.dao.DeadlockLoserDataAccessException: ...;
SQL state [40001]; error code [1213]; Deadlock found when trying to get lock; ...
nested exception is com.mysql.cj.jdbc.exceptions.MySQLTransactionRollbackException
```

Hibernate adds a layer:

```
org.hibernate.exception.LockAcquisitionException: could not execute statement
    at org.hibernate.exception.internal.SQLStateConversionDelegate.convert(...)
Caused by: com.microsoft.sqlserver.jdbc.SQLServerException: Transaction (Process ID 68)
was deadlocked on lock resources with another process...
```

---

## Signal Tags

### Mapping to Existing LogPilot Signal Tags

| Signal Tag | Database Errors That Trigger It |
|------------|--------------------------------|
| `DB/Pool` | ORA-01000, ORA-03113, ORA-03114, SQLCODE -1224, Msg 9002, Error 2006, Error 2013, J2CA0046E, DSRA9010E, DSRA9110E |
| `DB/Pool` | ORA-00060, SQLCODE -911, Msg 1205, PostgreSQL 40P01, MySQL 1213 (deadlock sub-pattern) |
| `SSL/TLS` | ORA-28000 (account locked — adjacent to auth), Msg 17806 (SSPI/Kerberos) |

### Suggested Additional Heuristic Patterns

```python
# Deadlock — all databases
r"(ORA-00060|SQLCODE[= ]-911|Msg 1205|40P01|Error 1213|deadlock detected|deadlock found)"

# Connection exhaustion
r"(ORA-12541|ORA-12514|ORA-12170|SQLCODE[= ]-30081|CommunicationsException|53300|too many connections|max connections)"

# Authentication failure
r"(ORA-01017|ORA-28000|SQLCODE[= ]-30082|Msg 18456|1045.*Access denied)"

# Space / resource exhaustion
r"(ORA-01652|ORA-01653|SQLCODE[= ]-1585|Msg 9002|53100|disk full|log.*full)"

# Cursor / open handle leak
r"ORA-01000"   # Oracle only — unique to cursor exhaustion

# Stale / dropped connection
r"(ORA-03113|ORA-03114|SQLCODE[= ]-4499|CommunicationsException|server has gone away|08006)"
```

---

## Cross-Database Patterns

### Deadlock

All five databases surface deadlock. LogPilot can unify them:

| Database | Code / Class | Message Fragment |
|----------|-------------|-----------------|
| Oracle | `ORA-00060` | `deadlock detected while waiting for resource` |
| DB2 | `SQLCODE -911` / `SQLSTATE 40001` | `deadlock or timeout, SQLSTATE=40001` |
| SQL Server | `Msg 1205` | `was deadlocked on lock resources` / `deadlock victim` |
| PostgreSQL | `SQLSTATE 40P01` | `ERROR: deadlock detected` |
| MySQL | `Error 1213` | `Deadlock found when trying to get lock` |

Unified regex:

```python
r"(?i)(ORA-00060|SQLCODE[= ]-911|Msg 1205|SQLSTATE[= ]40P01|Error 1213|deadlock\s+(detected|found|victim))"
```

### Connection Exhaustion

| Database | Signal |
|----------|--------|
| Oracle | `ORA-12514` (service unknown) / `ORA-12541` (no listener) / pool full at WAS layer |
| DB2 | `SQLCODE -1224` (no agent) / `SQLCODE -30081` (comm error) |
| SQL Server | `Msg 17803` (OOM) / connection pool timeout in JDBC |
| PostgreSQL | `SQLSTATE 53300` (too many connections) |
| MySQL | `Error 1040` (too many connections) / `Error 2003` (can't connect) |

### Authentication Failures

| Database | Code | Notes |
|----------|------|-------|
| Oracle | `ORA-01017` (bad creds) / `ORA-28000` (locked) | Both appear after password rotation |
| DB2 | `SQLCODE -30082` | State 08001 auth variant |
| SQL Server | `Msg 18456` | Check state code in SQL errorlog for root cause |
| PostgreSQL | `pg_hba.conf` rejection | Appears as connection refused (08001), not auth SQLSTATE |
| MySQL | `Error 1045` | Host-based grant check; user@host must match |

### Disk / Space Issues

| Database | Code | Resource |
|----------|------|---------|
| Oracle | `ORA-01652` / `ORA-01653` | TEMP or data tablespace |
| DB2 | `SQLCODE -1585` | Transaction log |
| SQL Server | `Msg 9002` | Transaction log (`LOG_BACKUP` cause) |
| PostgreSQL | `SQLSTATE 53100` | Data directory or WAL volume |
| MySQL | OS-level `errno 28` in error log; Error `2006` as symptom | InnoDB data files |

### Network / Communication Failures

| Database | Code |
|----------|------|
| Oracle | `ORA-03113` / `ORA-03114` / `ORA-12170` |
| DB2 | `SQLCODE -30081` / `SQLCODE -4499` |
| SQL Server | `Msg 17836` / `SQLServerException` CommunicationsException |
| PostgreSQL | `SQLSTATE 08006` / `08001` |
| MySQL | `Error 2003` / `Error 2006` / `Error 2013` / `CommunicationsException` |

Unified regex:

```python
r"(?i)(ORA-0311[34]|ORA-12170|SQLCODE[= ]-30081|SQLCODE[= ]-4499|CommunicationsException|08006|Error 200[36]|server has gone away|lost connection)"
```

---

## Quick Lookup: DSRA / J2CA Code to Database Error Flow

```
J2CA0046E (pool create failed)
  └─ DSRA0010E (SQL exception)
       └─ java.sql.SQLException: ORA-12541 / SQLCODE -30081 / Msg 18456 / ...
            └─ Driver-specific: oracle.jdbc / com.ibm.db2.jcc / com.microsoft.sqlserver.jdbc / org.postgresql / com.mysql.cj.jdbc
```

When LogPilot sees `DSRA0010E`, the real database error code is always within 1–3 lines in the same event (same stacktrace block). Parse both the DSRA wrapper and the embedded raw code for accurate signal tagging.
