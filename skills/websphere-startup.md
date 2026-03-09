# WebSphere Startup Sequence Analysis

## Normal Startup Sequence

### Traditional WAS (tWAS)
```
WSVR0001I  Server <name> starting
WSVR0002I  Config loaded
CWPKI0003I SSL initialization
DCSV*      DCS/cluster join (clustered envs)
HMGR*      HA manager initialization
SRVE0169I  Loading web module: <app>
SRVE0242I  Servlet <name> loaded
CNTR0167I  EJB module started
WSVR0024I  Server <name> open for e-business
```

### Liberty
```
CWWKE0001I Liberty starting
CWWKF0007I Feature installation
CWWKS4105I LTPA keys created/loaded
CWWKZ0001I Application <name> started
CWWKF0012I Feature bundle resolved
CWWKT0016I Web application available at <url>
CWWKZ0001I All apps started
CWWKF0011I Server <name> ready to run a smarter planet
```

## Startup Failure Patterns

### Application Failed to Start
```
CWWKZ0013E Application <name> failed to start
CWWKZ0002E Exception during startup of <app>
```
Check: Missing dependencies, datasource not configured, class loading errors.

### Feature Conflict (Liberty)
```
CWWKF0033E Multiple bundles providing same capability
```
Check: `server.xml` feature list for conflicts.

### Port Already In Use
```
TCPC0003E TCP Channel could not bind to port <N>
CHFW0019I Channel not started, port in use
```
Check: Another instance running, or OS-level port conflict.

### Datasource Failure at Startup
```
DSRA8020E JDBC connection failed during server start
DSRA0010E SQL exception
```
Check: Database not reachable, wrong credentials, driver JAR missing.

### SSL Initialization Failure
```
CWPKI0022E Certificate chain not trusted
CWPKI0033E Certificate expired
```
Check: Truststore configuration, certificate validity.

## Startup Timing Analysis

### Slow Startup Indicators
- Time between WSVR0001I and WSVR0024I > 5 minutes (typical threshold)
- Large gap between feature install and app start = app initialization problem
- Multiple DSRA retries = DB connectivity issues slowing startup

### Measuring Startup Phases
1. Parse timestamps from WSVR0001I (start) and WSVR0024I (ready)
2. Calculate delta for total startup time
3. Look for gaps > 30s between consecutive log entries during startup
4. Identify which component caused the delay

## Restart Detection

Unexpected restart pattern:
```
WSVR0024I  (server was running)
...gap or errors...
WSVR0001I  (server starting again)
WSVR0024I  (server ready)
```

If no deliberate restart was scheduled, investigate:
- OOM before restart (check for OutOfMemoryError)
- Node agent auto-restart after crash
- Health check failure triggering restart

## Cluster Startup Patterns

### Node Agent Sequence (tWAS)
The Node Agent starts before application servers:
```
ADMU0116I  Node agent starting
ADMU3000I  Node agent ready
ADMU0512I  Starting server <name> on node <node>
WSVR0001I  Server <name> starting
```
If ADMU0512I appears without subsequent WSVR0001I → server failed to launch.

### Cluster Member Join
After server startup, cluster members register:
```
DCSV1033I  DCS Stack at Member cell\node\server: Started
DCSV8050I  DCS joined existing core group
HMGR0207I  Node joined the high availability domain
```
Missing DCSV8050I = cluster membership failed. Check:
- Multicast/unicast transport configuration
- Firewall between cluster members
- DCS port conflicts

### Staggered Startup
In large clusters, servers start sequentially to avoid resource contention:
- Expected gap between WSVR0024I on different members: 30-120 seconds
- If all members start simultaneously → higher risk of DB connection pool storms

## Initialization Order Problems

Some components depend on others being ready:
```
CWWKZ0013E Application failed to start
Caused by: CWNEN1001E: JNDI name jdbc/myDS not found
```
This happens when the app starts before the datasource feature is loaded.

Liberty fix: Use `<application startAfter="DataSourceService"/>` or ensure feature order in `server.xml`.

tWAS fix: Set startup weight to ensure datasource is configured before app starts.

## Security-Enabled Startup

Enabling security adds startup time:
```
CWWKS4105I  LTPA keys created               ← +2-5 seconds (key generation)
CWWKS3005E  LDAP connection failed           ← blocks until timeout (30-60s default)
CWPKI0003I  SSL initialization completed     ← +1-3 seconds
```
If startup is slow, check LDAP connectivity first — a 60s timeout on LDAP blocks the entire startup.

## Hung During Startup vs Slow Startup

| Indicator | Slow Startup | Hung During Startup |
|-----------|-------------|---------------------|
| Log activity | Messages still appearing, just slow | No new messages for > 2 minutes |
| CPU usage | Active (loading classes, initializing) | Near zero |
| Thread dump | Threads in RUNNABLE state | Threads in WAITING/BLOCKED |
| Common cause | Large app, many features, slow DB | Deadlock, unreachable dependency |
| Action | Wait, or optimize config | Take thread dump, investigate blocker |

## Incident Response Playbook

### Scenario: Server Won't Start
1. Find the last message code before logs stop → that component is the blocker
2. If DSRA* → database unreachable, check DB and network
3. If CWPKI* → SSL/cert issue, check keystores
4. If CWWKZ0013E → app initialization failed, check app dependencies
5. If TCPC0003E → port conflict, find the other process: `lsof -i :<port>`
6. If no errors but no WSVR0024I → hung during startup, take thread dump
