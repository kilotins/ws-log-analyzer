# Java/WAS Stacktrace Analysis

## Stacktrace Structure

```
com.ibm.ws.SomeException: Error message
    at com.ibm.ws.module.Class.method(Class.java:123)
    at com.ibm.ws.module.Caller.invoke(Caller.java:45)
    ... 15 more
Caused by: java.sql.SQLException: Connection refused
    at oracle.jdbc.driver.T4CConnection.logon(T4CConnection.java:489)
    at com.ibm.ws.rsadapter.jdbc.WSJdbcConnection.init(WSJdbcConnection.java:78)
```

## Reading Strategy

1. **Start at the bottom** — the deepest `Caused by:` is the root cause
2. **Find the boundary** between framework and application code
3. **Note the exception type** — it tells you the failure category
4. **Check the message** — often contains the specific resource that failed

## Common Root Cause Exceptions

| Exception | Meaning | Check |
|-----------|---------|-------|
| `NullPointerException` | Null reference | Application bug, check the line number |
| `ClassNotFoundException` | Missing class at runtime | Classpath, missing JAR, classloader |
| `NoClassDefFoundError` | Class found at compile, missing at runtime | Classloader isolation, shared libs |
| `OutOfMemoryError` | Heap or metaspace exhausted | Heap dump, memory leak |
| `StackOverflowError` | Infinite recursion | Recursive call chain in trace |
| `SQLException` | Database operation failed | Connection, query, schema |
| `ConnectException` | TCP connection refused | Target host/port down |
| `SocketTimeoutException` | TCP read/connect timeout | Network latency, target overloaded |
| `SSLHandshakeException` | TLS negotiation failed | Certs, protocol version, cipher mismatch |
| `IllegalStateException` | Object in wrong state | Lifecycle bug, concurrent modification |
| `ConcurrentModificationException` | Collection modified during iteration | Thread safety issue |

## WAS-Specific Patterns

### Classloader Chain
WAS uses a hierarchical classloader: Bootstrap -> Extensions -> App -> WAR/Module.
`ClassNotFoundException` in WAS often means:
- JAR in wrong classloader scope (app vs shared)
- Parent-first vs parent-last misconfiguration
- Duplicate JARs at different classloader levels

### Connection Pool Exhaustion
```
Caused by: com.ibm.websphere.ce.cm.ConnectionWaitTimeoutException
```
All connections in use. Check: pool max size, connection leak (missing close()), slow queries.

### Transaction Timeout
```
Caused by: com.ibm.websphere.ce.cm.StaleConnectionException
```
Transaction exceeded timeout, connection invalidated. Check: `totalTranLifetimeTimeout`, long-running queries.

### Thread Dump Correlation
When a stacktrace appears with WSVR0605W (hung thread):
1. The stacktrace shows what the thread is stuck doing
2. Look for lock contention (`waiting to lock`, `BLOCKED`)
3. Check if multiple threads are stuck at the same point (systemic issue)

## Noise vs Signal

**Skip these** (framework internals, not actionable):
- `at sun.reflect.NativeMethodAccessorImpl.invoke`
- `at com.ibm.ws.webcontainer.servlet.ServletWrapper.service`
- `at java.lang.Thread.run`

**Focus on these** (application and integration boundaries):
- Lines with your application's package name
- JDBC driver classes (connection issues)
- JNDI lookup classes (resource configuration)
- SSL/TLS classes (certificate issues)

## Suppressed Exceptions

Java 7+ can attach suppressed exceptions (from try-with-resources):
```
java.sql.SQLException: Connection failed
    at com.example.dao.UserDAO.query(UserDAO.java:45)
    Suppressed: java.sql.SQLException: Failed to close connection
        at com.ibm.ws.rsadapter.jdbc.WSJdbcConnection.close(WSJdbcConnection.java:200)
```
The suppressed exception is the cleanup failure — the primary exception above it is the real problem. But suppressed exceptions can reveal resource leaks.

## Truncated Stacktraces

```
    at com.example.service.OrderService.process(OrderService.java:88)
    ... 42 more
```
`... 42 more` means the remaining frames are identical to the enclosing exception's trace. To reconstruct:
1. Find the parent exception's stacktrace
2. The truncated frames are the bottom 42 lines of that parent trace
3. JVM does this to save log space — the information is not lost

## Lambda and Anonymous Class Names

Modern Java stacktraces contain synthetic names:
```
at com.example.OrderService.lambda$processOrders$0(OrderService.java:55)
at com.example.OrderService$$Lambda$42/0x0000000800123456.run(Unknown Source)
```
- `lambda$methodName$N` — lambda defined inside `methodName`, Nth lambda in that method
- `$$Lambda$42` — JVM-generated class, no source file (ignore this frame)
- `$1`, `$2` — anonymous inner classes, numbered by declaration order

## Native Method Frames

```
at java.net.PlainSocketImpl.socketConnect(Native Method)
at java.base/java.net.Socket.connect(Socket.java:600)
```
- `(Native Method)` = JNI call into native code, no Java source line
- `java.base/` prefix = Java module (Java 9+), tells you which module the class belongs to
- Native frames in network/IO code are normal; in application code they suggest JNI usage

## Multi-Exception Patterns

### Cascading Failures
When one error triggers others, look for the earliest timestamp:
```
14:22:04 SQLException: Connection refused     ← ROOT CAUSE (DB down)
14:22:04 EJBException: Method failed          ← consequence
14:22:04 ServletException: Request failed     ← consequence of consequence
```
Always fix the first exception chronologically — the rest usually resolve.

### Repeated Same Exception
If the exact same stacktrace repeats 100+ times:
- The problem is systemic, not a one-off
- Often: DB down, external service unreachable, config error
- Fix the underlying issue rather than investigating each occurrence

## See Also

- [message-codes.md](message-codes.md) — Correlating stacktraces with WAS message codes
- [thread-correlation.md](thread-correlation.md) — Matching stacktraces to thread dumps
- [servlet-errors.md](servlet-errors.md) — Common servlet exceptions and root causes
