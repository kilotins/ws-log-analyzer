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
