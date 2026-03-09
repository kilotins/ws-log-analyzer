# JMS and SIB Messaging Analysis

## Overview

WebSphere's Service Integration Bus (SIB) provides the JMS messaging backbone. Messages flow through bus members (servers/clusters), destinations (queues/topics), and mediation points. Failures appear as CWSID* (SIB destination), CWSJY* (JMS resource adapter), and CWSIV* (SIB internal) codes.

## Message Code Format

SIB/JMS codes follow standard WAS format `PPPPNNNNs`:
- `CWSID` — SIB destination and messaging engine
- `CWSJY` — JMS resource adapter (RA)
- `CWSIV` — SIB internal/virtualization
- `CWSIT` — SIB transport (inter-bus communication)
- `CWSIA` — SIB API layer
- `CWSJC` — JMS connection factory

## Common Prefixes

| Prefix | Component |
|--------|-----------|
| CWSID | SIB destination manager — queue/topic lifecycle |
| CWSJY | JMS resource adapter — MDB delivery, activation specs |
| CWSIV | SIB engine internals — message stores, data tier |
| CWSIT | SIB transport — ME-to-ME communication |
| CWSIA | SIB API — application-facing messaging calls |
| CWSJC | JMS connection factory — connection creation/pooling |

## High-Impact Codes

### SIB Destination (CWSID)

- **CWSID0005E** — Destination not found on messaging engine. Check bus destination name matches JNDI binding.
- **CWSID0007E** — Destination is full (max depth reached). Messages cannot be produced until consumers drain the queue.
- **CWSID0008I** — Destination created (informational).
- **CWSID0012E** — Send to destination failed. Check stacktrace for root cause (auth, full queue, ME unavailable).
- **CWSID0016W** — Destination capacity warning threshold reached. Consumers are falling behind.
- **CWSID0020E** — Message cannot be delivered, sent to exception destination. Check the exception destination for stuck messages.
- **CWSID0024E** — Destination UUID mismatch — bus topology out of sync after migration or misconfiguration.

### JMS Resource Adapter (CWSJY)

- **CWSJY0003E** — JMS connection failed. ME is unreachable or not started.
- **CWSJY0006E** — MDB activation failed. Activation spec cannot connect to the target destination.
- **CWSJY0009W** — MDB delivery paused due to repeated failures. WAS stops delivering after `maxSequentialMessageFailure` threshold.
- **CWSJY0013E** — Message delivery to MDB failed. Check MDB `onMessage()` stacktrace.
- **CWSJY0016I** — Activation spec started (informational).
- **CWSJY0017I** — Activation spec stopped (informational).
- **CWSJY0020E** — JMS resource adapter internal error. Often a classloading or serialization problem.

### SIB Internal (CWSIV)

- **CWSIV0524E** — Message store error (file store or data store). Possible disk full or database connectivity failure.
- **CWSIV0535W** — Messaging engine failover in progress. Messages may be temporarily unavailable.
- **CWSIV0777E** — ME failed to start. Critical — check data store connectivity and lock contention.
- **CWSIV0787I** — ME started successfully (informational).

### SIB Transport (CWSIT)

- **CWSIT0001E** — Cannot establish connection to remote messaging engine. Network or firewall issue.
- **CWSIT0006W** — Inter-bus link disconnected. Messages between buses will queue until reconnection.

## Thread Naming

JMS/SIB threads follow these naming conventions:

| Thread Name | Purpose |
|-------------|---------|
| `SIBJMSRAThreadPool : N` | JMS RA threads delivering messages to MDBs |
| `SIB Messaging Engine N` | Core messaging engine processing |
| `SIBFAPChannel : N` | SIB transport (inter-ME) communication |
| `Mediation_N` | Mediation processing threads |
| `WMQJCAResourceAdapter : N` | IBM MQ resource adapter threads (if using MQ link) |

### SIBJMSRAThreadPool Patterns

The `SIBJMSRAThreadPool` threads deliver messages to Message-Driven Beans. Hung or exhausted pool indicates MDB processing problems.

**Pool exhaustion pattern:**
```
[timestamp] SIBJMSRAThreadPool : 0  W WSVR0605W: Thread "SIBJMSRAThreadPool : 0" has been active for 620,000 milliseconds
[timestamp] SIBJMSRAThreadPool : 1  W WSVR0605W: Thread "SIBJMSRAThreadPool : 1" has been active for 615,000 milliseconds
```

All SIBJMSRAThreadPool threads hung = MDB processing is blocked (DB calls, remote service calls, deadlocks). No new messages will be delivered.

**Diagnosis:**
1. Capture thread dump — look for SIBJMSRAThreadPool threads
2. Check where they are stuck (same `Stuck At` analysis as WebContainer threads)
3. Common causes: slow DB queries in `onMessage()`, lock contention, external service timeout

## Common JMS Exceptions

| Exception | Meaning | Action |
|-----------|---------|--------|
| `javax.jms.JMSException` | Generic JMS error | Read `getCause()` chain for real cause |
| `com.ibm.websphere.sib.exception.SIBException` | SIB internal error | Check ME status and data store |
| `javax.jms.MessageFormatException` | Message body type mismatch | Producer/consumer disagree on message type |
| `javax.jms.InvalidDestinationException` | Queue/topic doesn't exist | Check JNDI name and bus destination config |
| `javax.jms.JMSSecurityException` | Auth failure for messaging | Check bus security settings and role mapping |
| `com.ibm.websphere.sib.exception.SIBNotAuthorizedException` | SIB-level auth denied | User/group not in bus connector role |
| `javax.jms.ResourceAllocationException` | Connection/session limit reached | Increase connection pool or fix connection leak |
| `javax.jms.TransactionRolledBackException` | Message transaction rolled back | Check XA transaction logs, possible timeout |

## Queue Depth and Stuck Message Scenarios

### Messages Accumulating (Queue Depth Growing)

Symptoms:
- CWSID0016W warnings (threshold reached)
- CWSID0007E errors (queue full)
- Application response times increasing

Triage:
1. **Consumers stopped?** — Check MDB activation spec status (CWSJY0017I = stopped)
2. **Consumers too slow?** — Check thread dumps for SIBJMSRAThreadPool, look for slow processing
3. **Consumer failing?** — Check CWSJY0013E for MDB exceptions, messages going to exception destination
4. **Producer burst?** — Upstream system flooding the queue, check producer rate
5. **Poison messages?** — Same message keeps failing, redelivered up to `maxFailedDeliveries`, then sent to exception destination

### Poison Message Detection

A poison message fails processing repeatedly:
```
CWSJY0013E: Message delivery to MDB failed (attempt 1)
CWSJY0013E: Message delivery to MDB failed (attempt 2)
...
CWSID0020E: Message sent to exception destination _SYSTEM.Exception.Destination.queue1
```

After `maxFailedDeliveries` (default 5), the message moves to the exception destination. Check:
1. The exception destination for the stuck message content
2. MDB logs for the exception thrown during `onMessage()`
3. Whether the message format changed (schema evolution issue)

### Messages Not Being Consumed

If consumers are running but queue depth is static:
- **Message selector mismatch** — Consumer's selector doesn't match message properties
- **Transaction not committed** — Consumer receives but never commits (XA timeout)
- **Wrong destination** — Producer and consumer point to different queues

## Codes That Appear Together

| First Code | Often Followed By | Root Cause |
|------------|-------------------|------------|
| CWSID0007E (queue full) | CWSJY0013E (MDB failure) | Consumer failing, messages backing up |
| CWSJY0006E (activation fail) | CWSID0016W (depth warning) | MDB not consuming, queue growing |
| CWSIV0777E (ME start fail) | CWSJY0003E (connection fail) | ME down, all JMS operations fail |
| CWSJY0009W (delivery paused) | CWSID0020E (exception dest) | Repeated MDB failures trigger pause |
| CWSIT0001E (remote ME fail) | CWSID0012E (send fail) | Inter-bus link down, cross-bus messages fail |
| WSVR0605W (hung thread) on SIBJMSRAThreadPool | CWSID0016W (depth warning) | MDB processing blocked, queue growing |

## Real Log Line Examples

```
[10/12/24 09:15:22:100 CET] 0000006a SIBJMSRAThre  E CWSJY0013E: Message delivery to the message-driven bean MyMDB failed with exception: javax.ejb.EJBException: DB connection timeout
[10/12/24 09:15:23:050 CET] 0000006b SIBDestinati  W CWSID0016W: The destination queue://MyQueue has reached 80% of its configured depth.
[10/12/24 09:15:25:200 CET] 0000006c SIBJMSRAThre  W CWSJY0009W: Message delivery to MDB MyMDB has been paused because 5 sequential message failures were detected.
[10/12/24 09:15:26:300 CET] 0000006d SIBMessaging  E CWSID0020E: The message with ID 0A1B2C3D was moved to the exception destination _SYSTEM.Exception.Destination.MyQueue.
```

## Diagnostic Queries

### Splunk — JMS Error Overview
```spl
index=websphere msg_code="CWSID*" OR msg_code="CWSJY*"
| stats count by msg_code severity
| sort -count
```

### Splunk — Queue Depth Warnings Over Time
```spl
index=websphere msg_code="CWSID0016W"
| rex field=_raw "destination (?P<queue_name>\S+)"
| timechart span=5m count by queue_name
```

### Splunk — MDB Delivery Failures
```spl
index=websphere msg_code="CWSJY0013E"
| rex field=_raw "message-driven bean (?P<mdb_name>\S+)"
| stats count by mdb_name
| sort -count
```

### Splunk — Messaging Engine Health
```spl
index=websphere msg_code IN ("CWSIV0777E","CWSIV0787I","CWSIV0535W")
| table _time host msg_code _raw
| sort _time
```

### Splunk — SIBJMSRAThreadPool Hung Threads
```spl
index=websphere msg_code="WSVR0605W" "SIBJMSRAThreadPool"
| timechart span=10m count
| where count > 0
```

## Incident Response Playbook

### Scenario: Queue Depth Alert (Messages Backing Up)
1. Check MDB activation spec status — is the consumer running?
2. Look for CWSJY0013E — is the MDB throwing exceptions?
3. Check SIBJMSRAThreadPool threads — are they hung?
4. If MDB is failing: fix the root cause (DB, external service)
5. If MDB is paused (CWSJY0009W): fix the issue, then resume activation spec
6. If queue is full: consider increasing max depth as temporary relief while fixing consumers

### Scenario: Messaging Engine Won't Start (CWSIV0777E)
1. Check data store connectivity — is the database backing the ME accessible?
2. Check for ME lock contention — another ME instance may hold the database lock
3. Verify file store permissions (if using file-based persistence)
4. Check for corrupted message store — may require ME recovery procedure
5. Review the full stacktrace in CWSIV0777E for specific error
6. Restart the ME after fixing the underlying issue
