# Scenario Builder — Test Incident Generation for LogPilot

## Purpose

Build realistic multi-system incident scenarios to test LogPilot's parsing, heuristics, correlations, incident grouping, confidence scoring, and AI analysis. Each scenario simulates a real-world outage with cascading failures across multiple log formats.

## Supported Formats

| Format | Plugin | Typical system |
|--------|--------|----------------|
| WAS | `was` | WebSphere Application Server — J2EE, JDBC pools, sessions |
| Log4j | `log4j` | Spring Boot, HikariCP, Kafka, Java services |
| nginx | `nginx` | Load balancers, reverse proxies, access/error logs |
| JSON | `json_log` | Node.js (Bunyan/Pino), Python (structlog), Docker |
| CRI-O | `crio` | Kubernetes pods, klog, OpenShift |
| Python | `python_log` | Django, Flask, FastAPI, Celery workers |
| syslog | `syslog` | Linux system logs, journald, OOM killer |
| Enonic XP | `enonic` | Enonic XP CMS, Jetty, Elasticsearch |
| DataPower | `datapower` | IBM DataPower API gateway, SSL, AAA, APIC |

## Scenario Structure

Each scenario lives in `tests/fixtures/scenario-<name>/` with:

```
scenario-<name>/
├── README.md              # Storyline, timeline, root cause, systems
├── <system1>.log          # Log file per system
├── <system2>.log
├── ...
├── simulated_error.html   # Browser error page (for screenshot)
└── simulated_screenshot.png  # Rendered screenshot
```

## Building a Scenario

### 1. Define the incident

- **Root cause**: One specific failure (DB crash, cert expiry, OOM, network partition, config error)
- **Cascade path**: How the root cause propagates through systems (DB → pool exhaustion → hung threads → 502)
- **Timeline**: 15-30 minute window with clear before/during/after phases
- **Impact**: What the end user sees (error page, timeout, degraded service)

### 2. Design the timeline

```
Phase 1: Healthy (5-10 min before incident)
  - Normal transactions, health checks passing
  - Establishes baseline for "What Changed?" detection

Phase 2: Trigger (single event)
  - The root cause event (deadlock, OOM kill, cert expiry)
  - Must have a precise timestamp

Phase 3: Cascade (2-5 min)
  - Each system fails in sequence, with realistic delays
  - Connection pools exhaust, threads hang, errors propagate
  - Trace IDs link events across systems

Phase 4: Recovery (5-10 min after)
  - Systems recover in reverse order
  - Health checks pass, backlogs clear
```

### 3. Write log files

For each system, include:

- **Timestamps**: Consistent across all files (same timezone or UTC)
- **Trace IDs**: Shared UUIDs across 2+ systems for cross-system correlation
- **Error codes**: Format-specific codes (J2CA0045E for WAS, 0x80e00001 for DataPower)
- **Stacktraces**: At least one multiline event with `Caused by:` chain
- **Signal tags**: Events that trigger heuristic signal tags (OOM, SSL, DB/Pool, etc.)
- **IP addresses**: Shared target IPs across systems for cross-system corroboration

### 4. Heuristic coverage targets

Each scenario should trigger:
- At least **5 unique heuristic IDs**
- At least **2 correlation rules** (multi-signal)
- At least **2 incident groups** with trigger/effect relationships
- At least **1 burst detection** (50+ errors in 2 min window) — for larger scenarios
- **Cross-system cascades** via `detect_cross_system_cascades()`

### 5. Create screenshot + symptom description

- HTML error page simulating what the end user sees
- Render to PNG with Playwright
- Write a symptom description (2-3 sentences) for the AI assistant input field

## Log Format Templates

### DataPower
```
YYYYMMDDTHHMMSS.sssZ [domain][level][0xHEXCODE] message
```
Domains: `default`, `ssl`, `aaa`, `network`, `mpgw`, `apiconnect`, `xmlparse`, `crypto`
Levels: `info`, `warn`, `error`, `critical`, `emergency`

### WAS
```
[M/DD/YY HH:MM:SS:mmm TZ] threadid component severity msgcode message
```

### Log4j / Spring Boot
```
YYYY-MM-DD HH:MM:SS.mmm LEVEL [thread] class - message
```

### nginx access
```
IP - user [DD/Mon/YYYY:HH:MM:SS +ZONE] "METHOD path HTTP/x.x" status bytes "ref" "ua" rt=x.xxx
```

### nginx error
```
YYYY/MM/DD HH:MM:SS [level] pid#tid: *conn message
```

### JSON structured
```json
{"timestamp":"ISO","level":"error","message":"...","service":"...","trace_id":"..."}
```

### Python / Celery
```
YYYY-MM-DD HH:MM:SS,mmm LEVEL module message
```

### CRI-O / Kubernetes
```
YYYY-MM-DDTHH:MM:SS.nnnnnnnnn+ZZ:ZZ stderr F message
```

### syslog
```
Mon DD HH:MM:SS hostname process[pid]: message
```

### PostgreSQL
```
YYYY-MM-DD HH:MM:SS.mmm TZ [pid] LEVEL: message
```

## Existing Scenarios

### scenario/ — E-commerce Checkout Outage
- **Root cause**: Kubernetes node OOM → PostgreSQL crash → connection pool cascade
- **Systems**: WAS, nginx, Log4j, JSON, CRI-O, Python + PostgreSQL, K8s events, GC, thread dump, WAS systemout, rollout history
- **12 log files**, 300 events, 4 incident groups

### scenario-bank/ — Bank Payment Processing Outage (KLP-style)
- **Root cause**: PostgreSQL deadlock on salary batch → temp file overflow → DB shutdown
- **Systems**: DataPower gateway, WAS, Log4j (Spring Boot), nginx, PostgreSQL
- **External services**: NAV (income API), VPS (securities), AML register (Finanstilsynet), LDAP
- **5 log files**, 123 events, 4 incident groups

## Validation Checklist

After creating a scenario, verify:

- [ ] All log files auto-detect correct format (`detect_format()`)
- [ ] All events parse without errors (`parse_file()`)
- [ ] Heuristics find ≥5 causes (`likely_causes()`)
- [ ] Incident groups form with root cause + downstream (`group_into_incidents()`)
- [ ] Primary incident has High confidence
- [ ] Failure chain is non-empty
- [ ] Cross-system cascades detected (if ≥2 system_labels)
- [ ] Screenshot renders correctly
- [ ] Symptom description triggers relevant AI analysis
