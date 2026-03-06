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
