# Thread Correlation Analysis

## WAS Thread Naming

WebSphere threads follow naming conventions:
- `WebContainer : N` — HTTP request processing threads
- `Default Executor-thread-N` — Liberty managed threads
- `SIBJMSRAThreadPool : N` — JMS/messaging threads
- `ORB.thread.pool : N` — IIOP/RMI threads
- `TimerThread-N` — Scheduled task threads
- `HAManager.thread.pool : N` — High availability threads
- `server.startup : N` — Server startup threads

## Hung Thread Detection

WAS logs WSVR0605W when a thread exceeds the hung thread threshold (default 10 min).

### Correlation Steps

1. **Find the thread name** in the WSVR0605W message
2. **Search for the same thread name** in surrounding log entries
3. **Build a timeline**: what was the thread doing before it hung?
4. **Check the stacktrace**: where is it stuck?

### Common Hung Thread Causes

| Stuck At | Likely Cause | Fix |
|----------|-------------|-----|
| `java.net.SocketInputStream.read` | Waiting for remote response | Check target service, add timeouts |
| `java.lang.Object.wait` | Waiting for lock/notify | Thread contention, deadlock |
| `oracle.jdbc.driver.T4C*` | Waiting for DB response | Slow query, DB overloaded |
| `com.ibm.ws.rsadapter.*` | Connection pool wait | Pool exhausted, increase max or fix leak |
| `javax.naming.InitialContext` | JNDI lookup hanging | LDAP/naming service down |

## Thread Pool Exhaustion

When all WebContainer threads are busy:
- New HTTP requests queue up
- Clients see timeouts
- Log pattern: many concurrent WSVR0605W for `WebContainer` threads

### Diagnosis
```
Count threads by state:
- RUNNABLE at same method = systemic bottleneck
- BLOCKED on same lock = lock contention
- WAITING at Object.wait = resource exhaustion
```

## Cross-Thread Correlation

Events from the same request may span threads (async processing):
1. Look for request IDs or correlation IDs in the log message
2. Match timestamps within a narrow window
3. Follow the chain: WebContainer -> EJB -> JMS -> Timer

## Deadlock Detection

### Log Pattern
```
1LKDEADLOCK    Deadlock detected !!!
2LKDEADLOCKTHR  Thread "WebContainer : 5" (0x00000000)
3LKDEADLOCKWTR    is waiting for:
4LKDEADLOCKMON      sys_mon_t:0x00007F lock (owner: "WebContainer : 8")
2LKDEADLOCKTHR  Thread "WebContainer : 8" (0x00000000)
3LKDEADLOCKWTR    is waiting for:
4LKDEADLOCKMON      sys_mon_t:0x00008A lock (owner: "WebContainer : 5")
```

Deadlock vs hung thread:
- **Deadlock**: Two+ threads each hold a lock the other needs — permanent, requires restart
- **Hung thread**: Single thread waiting on external resource — may resolve when resource responds

### Triage Steps for Deadlocks
1. Find the `1LKDEADLOCK` section in the thread dump
2. Identify the lock objects and their owning threads
3. Trace both threads' stacktraces — find the code that acquires locks in different order
4. Fix: always acquire locks in a consistent order, or use `java.util.concurrent` locks with `tryLock(timeout)`

## Thread State Analysis

| State | Meaning | Action |
|-------|---------|--------|
| `RUNNABLE` | Thread is executing CPU work | If many at same method = CPU bottleneck |
| `BLOCKED` | Waiting to acquire a monitor/lock | Lock contention — find the lock owner |
| `WAITING` | Waiting indefinitely (Object.wait, park) | Resource exhaustion — waiting for notify |
| `TIMED_WAITING` | Waiting with timeout (sleep, poll) | Usually normal — check if timeout is too long |

### Systemic Pattern Detection
```
Multiple threads in same state at same code location:
- 10x BLOCKED at com.ibm.ws.rsadapter → connection pool lock contention
- 15x WAITING at java.lang.Object.wait → pool exhausted, all waiting for connections
- 8x RUNNABLE at org.apache.xml.* → CPU-bound XML parsing bottleneck
```

## Lock Wait Chains

A lock chain shows cascading contention:
```
Thread A (BLOCKED) → waiting for lock held by Thread B
Thread B (BLOCKED) → waiting for lock held by Thread C
Thread C (RUNNABLE) → executing slow database query
```

Root cause is Thread C's slow query. Fixing it unblocks the entire chain.

How to read from thread dump:
1. Find BLOCKED threads and note which lock they wait for
2. Find the lock owner thread
3. If owner is also BLOCKED, follow the chain
4. The final thread in the chain is the root cause

## Thread Leak Detection

Symptoms:
- Thread count grows over time (monitor via JMX or `jstack | grep "WebContainer" | wc -l`)
- Eventually `java.lang.OutOfMemoryError: unable to create native thread`
- WSVR0606W warnings about thread pool nearing capacity

Common causes:
- Application code creating raw `Thread` objects instead of using the WAS thread pool
- Executors created with `Executors.newCachedThreadPool()` without shutdown
- Async servlets that never call `complete()` on the `AsyncContext`

## GC Pauses vs Application Hangs

GC pauses look like hung threads but resolve automatically:
- **GC pause**: All threads freeze simultaneously, resume after GC completes
- **Application hang**: Specific threads freeze, others continue

How to distinguish:
1. Check GC logs for pause events at the same time as WSVR0605W
2. If all WebContainer threads report hung at the same second = likely GC pause
3. GC pauses: `[GC pause (G1 Evacuation Pause)]` or `<af type="tenured">`
4. Fix: tune GC settings, not the application

## Liberty Thread Dumps

Liberty uses `server javadump <serverName>` to produce thread dumps.
The dump file contains:
- All thread stacks
- Lock information
- Memory summary

Key sections:
- `1LKDEADLOCK` — deadlock detected (critical)
- `3XMTHREADBLOCK` — thread blocked waiting for lock
- `2LKMONINUSE` — monitors currently held

## Incident Response Playbook

### Scenario: Thread Pool Exhaustion
1. Capture thread dump immediately: `kill -3 <pid>` or `wsadmin > javacore`
2. Count threads by state: `grep "State:" javacore.txt | sort | uniq -c`
3. If most BLOCKED → find lock owner, likely a single slow thread
4. If most WAITING → resource exhaustion (DB pool, external service)
5. If most RUNNABLE at same line → CPU bottleneck in application code
6. Short-term: restart server. Long-term: fix the root cause identified above

## See Also

- [gc-performance.md](gc-performance.md) — GC pauses causing hung thread alerts
- [stacktrace-analysis.md](stacktrace-analysis.md) — Reading thread dump stacktraces
- [splunk-query.md](splunk-query.md) — Splunk queries for hung thread patterns
