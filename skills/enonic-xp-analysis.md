# Enonic XP Log Analysis

## Overview

Enonic XP is a Java-based CMS/platform built on OSGi with an embedded Elasticsearch cluster and Jetty web server. It produces two main log types plus audit logs.

## Log Files

| File | Location | Format | Content |
|------|----------|--------|---------|
| `server.log` | `$XP_HOME/logs/` | Logback | Application logs (main) |
| `jetty-yyyy_mm_dd.request.log` | `$XP_HOME/logs/` | NCSA/Extended | HTTP access logs |
| Audit log | Via API (`/api/audit`) | JSON | Content CRUD operations |

### server.log Format

Default Logback pattern:
```
10:15:33.123 ERROR c.e.x.core.SomeService - Something failed
```
Pattern: `%d{HH:mm:ss.SSS} %-5level %logger{36} - %msg%n`

Console format (development):
```
2025-03-11T10:15:33.123+01:00 ERROR c.e.x.core.SomeService - Something failed
```
Pattern: `%d{ISO8601} %highlight(%-5level) %cyan(%logger{36}) - %msg%n`

**Note**: Default `server.log` timestamps lack date — only `HH:mm:ss.SSS`. Use file rolling date (`server.2025-03-11.0.log`) to infer the date, or configure ISO8601 timestamps.

### Jetty Request Log Format

NCSA Extended format (when `log.extended=true`):
```
192.168.1.1 - admin [11/Mar/2025:10:15:33 +0100] "GET /admin/tool HTTP/1.1" 200 12345 "https://cms.example.com/" "Mozilla/5.0..."
```

Configuration in `$XP_HOME/config/com.enonic.xp.web.jetty.cfg`:
```properties
log.enabled=true
log.file=${xp.home}/logs/jetty-yyyy_mm_dd.request.log
log.extended=true
log.retainDays=31
log.append=true
```

### JSON Log Format (optional)

Requires additional JARs in `$XP_HOME/lib/`:
- logback-json-classic, logback-jackson, logback-json-core
- jackson-databind, jackson-core, jackson-annotations

Output:
```json
{"timestamp":"2025-03-11 10:15:33.123","level":"ERROR","thread":"main","logger":"c.e.x.core.SomeService","message":"Something failed","context":"default"}
```

## Key Logger Names

| Logger | Component |
|--------|-----------|
| `c.e.xp.core.*` | Core platform |
| `c.e.xp.repo.*` | Content repository (node storage) |
| `c.e.xp.blob.*` | Blob storage (binaries, attachments) |
| `c.e.xp.index.*` | Elasticsearch indexing |
| `c.e.xp.cluster.*` | Cluster management |
| `c.e.xp.web.*` | Web/HTTP layer (Jetty) |
| `c.e.xp.task.*` | Background tasks |
| `c.e.xp.app.*` | Application lifecycle |
| `c.e.xp.export.*` | Export/import operations |
| `c.e.xp.dump.*` | System dump/load |
| `c.e.xp.security.*` | Authentication/authorization |
| `c.e.xp.audit.*` | Audit logging |
| `c.e.xp.content.*` | Content API operations |
| `c.e.xp.portal.*` | Portal rendering |
| `c.e.xp.script.*` | JavaScript controller execution |
| `Events.Service` | Event bus (default set to WARN) |

## Common Exceptions & Errors

### Startup / Lifecycle

| Exception | Meaning | Fix |
|-----------|---------|-----|
| `JettyActivator` bind failure | Port already in use (8080/4848) | Kill process on port or change `com.enonic.xp.web.jetty.cfg` |
| `EngineCreationFailureException` | Elasticsearch index corruption | Delete and rebuild index, or restore from snapshot |
| `ApplicationInstallException` | App JAR failed to install | Check OSGi dependencies, rebuild app |
| `BundleException` | OSGi bundle lifecycle error | Version conflict, missing dependency |

### Repository / Content

| Exception | Meaning | Fix |
|-----------|---------|-----|
| `NodeNotFoundException` | Content node doesn't exist | Deleted content, broken reference |
| `NodeAlreadyExistAtPathException` | Duplicate content path | Name collision, concurrent create |
| `NodeAccessException` | Permission denied on node | Check role/permissions |
| `BlobStoreException: Failed to create directory` | Blob storage dir issue | Disk permissions, disk full |
| `BlobNotFoundException` | Binary attachment missing | Broken blob reference, incomplete dump/restore |
| `ContentAlreadyMovedException` | Move target path conflict | Content already exists at target |

### Elasticsearch / Indexing

| Pattern | Meaning | Fix |
|---------|---------|-----|
| `Cluster health in state 'RED'` | Shards unassigned, data at risk | Check disk space, node availability |
| `Cluster health in state 'YELLOW'` | Replicas unassigned (single-node is always YELLOW) | Add node or accept for dev |
| `IndexNotFoundException` | ES index missing | Reindex from repository |
| `SearchPhaseExecutionException` | Query failed | Corrupt index, OOM, complex query |
| `read past EOF` | Corrupt ES segment files | Known ES 1.5.x bug, reindex |
| `MapperParsingException` | Index mapping conflict | Schema change, reindex needed |
| `CircuitBreakingException` | ES memory limit hit | Increase heap or reduce query complexity |

### Task Execution

| Exception | Meaning | Fix |
|-----------|---------|-----|
| `TaskNotFoundException` | Background task missing | After upgrade, task scripts not loaded |
| `TaskAlreadyRunningException` | Duplicate task execution | Previous task still running, check scheduler |
| `ScriptExecutionException` | JavaScript error in controller | Check app code, null references |

### Cluster

| Pattern | Meaning |
|---------|---------|
| `Node joined cluster` | New node discovered |
| `Node left cluster` | Node disconnected (network/crash) |
| `Master node changed` | Cluster leadership election |
| `Split brain detected` | Network partition — CRITICAL |
| `Failed to send join request` | Node can't reach master |

### Web / Portal

| Pattern | Meaning |
|---------|---------|
| `404 Page not found` | Content/controller not mapped |
| `XSRF token validation failed` | Cross-site request forgery blocked |
| `WebSocketException` | Live-edit WebSocket failed |
| `PortalRequestTimeout` | Controller execution too slow |

## Signal Tags

| Tag | Detection pattern |
|-----|-------------------|
| `Enonic/Cluster` | `Cluster health`, `node joined`, `node left`, `split brain`, `master.*changed` |
| `Enonic/Repo` | `NodeNotFoundException`, `BlobStore`, `BlobNotFoundException`, `NodeAccess` |
| `Enonic/Index` | `IndexNotFoundException`, `SearchPhaseExecution`, `CircuitBreaking`, `reindex` |
| `Enonic/App` | `ApplicationInstall`, `BundleException`, `ScriptExecution` |
| `Enonic/Task` | `TaskNotFoundException`, `TaskAlreadyRunning` |
| `OOM/GC` | `OutOfMemoryError`, `GC overhead`, `Java heap space` |
| `DiskFull` | `No space left`, `Failed to create directory` |
| `SSL/TLS` | `SSLHandshakeException`, `PKIX path building failed` |

## Dump / Export / Import Operations

System dump logs show per-repository results:
```
Dump completed: system-repo (2 branches, 1523 nodes) | com.enonic.cms.default (2 branches, 45231 nodes)
```

Common issues:
- `BlobNotFoundException` during dump → missing binary attachments
- Import with IDs onto existing data → renaming/reordering may not work
- Dump must be in `$XP_HOME/data/dump/`, export in `$XP_HOME/data/export/`

## Rolling File Configuration

Default rotation:
```
server.%d{yyyy-MM-dd}.%i.log
```
- Max file size: 100MB per file
- Max history: 7 days
- Total size cap: 3GB

## Triage Strategy

1. **Check cluster health** — RED/YELLOW in logs is the #1 Enonic production issue
2. **Group by logger** — `c.e.xp.repo` = content store, `c.e.xp.index` = search/ES
3. **Check blob storage** — `BlobStoreException` = disk full or permissions
4. **App lifecycle** — `ApplicationInstallException` after deploy = broken app JAR
5. **JavaScript errors** — `ScriptExecutionException` = bug in XP app controller code
6. **Correlate request log** — match slow/failing requests with server.log errors by timestamp
7. **After upgrades** — check for `TaskNotFoundException`, index compatibility issues

## Useful Splunk Queries

```spl
# Cluster health changes
index=cms sourcetype=enonic "Cluster health" | timechart count by health_state

# Blob storage errors
index=cms sourcetype=enonic "BlobStoreException" OR "BlobNotFoundException" | stats count by host

# Slow portal requests (if request_time logged)
index=cms sourcetype=enonic_access request_time>5 | top limit=20 uri

# App deployment failures
index=cms sourcetype=enonic "ApplicationInstall" OR "BundleException" | table _time host message

# Content repository errors
index=cms sourcetype=enonic "NodeNotFoundException" OR "NodeAccessException" | timechart count span=1h

# Elasticsearch issues
index=cms sourcetype=enonic "SearchPhaseExecution" OR "CircuitBreaking" OR "IndexNotFound" | stats count by exception_type
```

Sources:
- [Enonic XP Configuration](https://developer.enonic.com/docs/xp/stable/deployment/config)
- [Enonic XP Monitoring](https://xp.readthedocs.io/en/stable/operations/monitoring.html)
- [Cluster Health Discussion](https://discuss.enonic.com/t/cluster-health-in-state-red/455)
- [Blob Storage Issues](https://discuss.enonic.com/t/blob-storage-issues-in-enonic-xp-missing-files-and-failed-directory-creation/3302)
