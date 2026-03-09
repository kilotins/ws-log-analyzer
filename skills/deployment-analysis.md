# Application Deployment Analysis

## Deployment Lifecycle

```
Install -> Start -> Running -> Stop -> Uninstall
                      |
                    Update (redeploy)
```

## Successful Deployment (Liberty)

```
CWWKZ0018I: Preparing to start application <name>
CWWKZ0001I: Application <name> started in X seconds
CWWKT0016I: Web application available at <url>
```

## Successful Deployment (tWAS)

```
ADMA5013I: Application <name> installed
SRVE0169I: Loading web module: <name>
SRVE0242I: Servlet <name> loaded successfully
WSVR0221I: Application <name> started
```

## Deployment Failure Patterns

### Missing Dependencies
```
CWWKZ0013E: Application failed to start
Caused by: ClassNotFoundException
```
Root cause: JAR missing from `WEB-INF/lib` or shared library not configured.

### Datasource Not Found
```
CWNEN1001E: JNDI name not found: jdbc/myDS
```
Check: `server.xml` datasource config, JNDI name matches `web.xml` resource-ref.

### Context Root Conflict
```
CWWKZ0014W: Application already exists at context root /app
```
Two applications deployed to the same path. Undeploy the old one first.

### Version Conflict After Redeploy
```
ClassCastException: com.app.MyClass cannot be cast to com.app.MyClass
```
Two classloaders loaded the same class. Cause: Stale session objects from the old deployment contain classes from the old classloader.
Fix: Invalidate sessions during redeploy, or restart.

### EAR/WAR Structure Issues
```
CWWKZ0002E: Exception occurred while starting application
Caused by: ... error parsing deployment descriptor
```
Check: `web.xml` or `application.xml` has syntax errors or references missing modules.

## Rollback Indicators

Signs a deployment should be rolled back:
1. CWWKZ0013E immediately after deploy
2. Spike in SRVE0255E (500 errors) after deploy
3. New exception types appearing that weren't in previous version
4. Health checks failing (CWMMH0052W)
5. Response time increase correlated with deploy timestamp

## Zero-Downtime Deployment Checks

For rolling deployments across a cluster:
1. Verify CWWKZ0001I on each node
2. Check no CWWKZ0013E on any node
3. Confirm health checks pass (CWMMH) before routing traffic
4. Monitor error rate for 5-10 minutes post-deploy per node

## Container / Kubernetes Deployments

### Pod Startup Sequence
In containerized Liberty, the log sequence is:
```
CWWKE0001I  → Liberty JVM starting inside container
CWWKF0007I  → Features loading
CWWKZ0001I  → App started
CWWKF0011I  → Server ready ← readiness probe should check after this
```

### Container-Specific Failure Patterns
| Log Pattern | Likely Cause |
|-------------|-------------|
| CWWKZ0013E at pod startup | Missing ConfigMap/Secret mount → env vars not set |
| DSRA8020E at pod startup | DB Service not yet available (pod started before DB) |
| CWPKI0022E at pod startup | TLS secret not mounted or wrong secret name |
| OOMKilled (not in WAS logs) | Container memory limit too low for JVM heap |

### Detecting Partial Rollouts
When only some pods updated (stuck rollout):
```
Pod A: CWWKZ0001I Application MyApp-v2.1 started   ← new version
Pod B: CWWKZ0001I Application MyApp-v2.0 started   ← old version
```
Compare app version strings across pods. Mixed versions = incomplete rollout.

## ClassLoader Cleanup After Redeploy

Failed cleanup causes memory leaks across redeploys:
```
WARNING: The web application [MyApp] registered the JDBC driver [oracle.jdbc.OracleDriver]
but failed to unregister it when the web application was stopped. To prevent a memory leak,
the JDBC driver has been forcibly unregistered.
```

Detection:
- Metaspace/PermGen growth after each redeploy without restart
- `ClassCastException` with identical class names (same class, different classloaders)
- Thread local values surviving redeploy (`ThreadLocal` leak)

Fix: Always restart after multiple hot redeploys in production.

## Canary Deployment Verification

When doing canary deploys (small % of traffic to new version):
1. Compare error rates: `msg_code=SRVE0255E` on canary vs stable pods
2. Compare response times: canary latency should match or improve
3. Watch for new exception types: any `Caused by:` not seen on stable pods = regression
4. Minimum soak time: 15-30 minutes before promoting to full rollout

## Incident Response Playbook

### Scenario: Deploy Broke Production
1. Check timestamp of CWWKZ0001I — does it correlate with error spike?
2. Compare error types before/after deploy timestamp
3. If new exceptions appeared → rollback immediately
4. If same exceptions but higher rate → likely a performance regression, investigate
5. Rollback: redeploy previous artifact, verify CWWKZ0001I with old version string
6. Post-mortem: diff the deployment artifacts to find the breaking change

## See Also

- [websphere-startup.md](websphere-startup.md) — Startup sequence and failure patterns during deployment
- [servlet-errors.md](servlet-errors.md) — Servlet lifecycle errors that appear after deployment
- [message-codes.md](message-codes.md) — CWWKZ and WSVR codes related to app install/start
