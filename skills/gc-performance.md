# GC and Performance Analysis

## Overview

Garbage collection logs reveal memory pressure, allocation failures, and pause times that directly impact application performance. WebSphere supports multiple GC policies (gencon, balanced, metronome) and JDK collectors (G1GC, ZGC, Shenandoah). Verbose GC logs are the primary diagnostic tool for memory-related issues.

## Enabling Verbose GC

### Traditional WAS (IBM J9 JVM)
```
Generic JVM arguments: -verbose:gc -Xverbosegclog:verbosegc.%Y%m%d.%H%M%S.%pid.log,20,50000
```
Format: up to 20 files, 50,000 GC cycles per file.

### Liberty
```xml
<jvmOptions>-verbose:gc -Xverbosegclog:logs/verbosegc.log,20,50000</jvmOptions>
```

### HotSpot JVM (Liberty on OpenJDK/Oracle)
```
-Xlog:gc*:file=logs/gc.log:time,uptime,level,tags:filecount=10,filesize=50m
```

## Verbose GC Log Patterns

### IBM J9 JVM (Traditional WAS)

#### Allocation Failure (Nursery/Tenured Full)
```xml
<af type="nursery" id="12345" timestamp="2024-10-12T14:22:04.257" intervalms="1502.33">
  <minimum requested_bytes="1048592" />
  <time exclusiveaccessms="2.100" />
  <nursery freebytes="0" totalbytes="536870912" percent="0" />
  <tenured freebytes="104857600" totalbytes="1073741824" percent="9" />
  <gc type="scavenge" id="12345" totalid="67890" intervalms="1502.33">
    <time totalms="45.200" />
  </gc>
</af>
```

Key fields:
- `type="nursery"` — young generation full (normal, frequent)
- `type="tenured"` — old generation full (concerning if frequent)
- `requested_bytes` — allocation size that triggered GC
- `exclusiveaccessms` — time to stop all threads (STW pause start)
- `totalms` — total GC pause duration

#### Global GC (Full Collection)
```xml
<sys type="global" id="500" timestamp="..." intervalms="3600000">
  <time exclusiveaccessms="5.000" totalms="2500.000" />
  <tenured freebytes="52428800" totalbytes="1073741824" percent="4" />
</sys>
```
Global GC is a full stop-the-world collection. If `totalms` > 1000ms, application will experience noticeable pauses.

#### Compaction
```xml
<compact id="50" movecount="250000" movebytes="125000000" reason="fragmentation" />
```
Compaction reorganizes heap to reduce fragmentation. Expensive — causes long pauses.

### HotSpot JVM (G1GC)

#### G1 Young Collection
```
[2024-10-12T14:22:04.257+0000] GC(1234) Pause Young (Normal) (G1 Evacuation Pause) 1500M->800M(2048M) 25.5ms
```

#### G1 Mixed Collection
```
[2024-10-12T14:22:05.000+0000] GC(1235) Pause Young (Mixed) (G1 Evacuation Pause) 1800M->1200M(2048M) 45.2ms
```
Mixed collections reclaim old-gen regions alongside young-gen. Triggered when old-gen occupancy hits `InitiatingHeapOccupancyPercent`.

#### G1 Full GC (Critical)
```
[2024-10-12T14:22:06.000+0000] GC(1236) Pause Full (Allocation Failure) 2000M->900M(2048M) 3500.0ms
```
Full GC in G1 is a fallback — means G1's concurrent collection couldn't keep up. Application pauses for seconds.

### HotSpot JVM (ZGC)

#### ZGC Pause (Sub-millisecond)
```
[2024-10-12T14:22:04.257+0000] GC(500) Pause Mark Start 0.015ms
[2024-10-12T14:22:04.400+0000] GC(500) Pause Mark End 0.010ms
[2024-10-12T14:22:04.500+0000] GC(500) Pause Relocate Start 0.012ms
```
ZGC pauses are typically < 1ms regardless of heap size.

#### ZGC Allocation Stall (Critical)
```
[2024-10-12T14:22:04.257+0000] Allocation Stall (main) 250.000ms
```
ZGC couldn't free memory fast enough. Application thread was blocked waiting for GC. Indicates heap too small or allocation rate too high.

## OOM Detection Patterns

### java.lang.OutOfMemoryError Variants

| Error Message | Meaning | Action |
|---------------|---------|--------|
| `Java heap space` | Heap exhausted | Increase `-Xmx`, fix leak, or reduce footprint |
| `GC overhead limit exceeded` | >98% time spent in GC, <2% heap recovered | Memory leak — GC is fighting a losing battle |
| `Metaspace` / `PermGen space` | Class metadata exhausted | Classloader leak (redeployments), increase `-XX:MaxMetaspaceSize` |
| `unable to create native thread` | OS thread limit or native memory exhausted | Thread leak, or increase `ulimit -u` |
| `Requested array size exceeds VM limit` | Single allocation > max array size | Application bug — trying to allocate impossibly large array |
| `Direct buffer memory` | NIO direct buffers exhausted | Increase `-XX:MaxDirectMemorySize`, fix NIO buffer leak |
| `Compressed class space` | Compressed class pointer space full | Increase `-XX:CompressedClassSpaceSize` |

### OOM in WAS Logs
```
[10/12/24 14:22:04:257 CET] 0000004e WebContainer  E SRVE0255E: A WebGroup/Virtual Host error occurred
Caused by: java.lang.OutOfMemoryError: Java heap space
    at com.example.service.LargeQueryService.loadAll(LargeQueryService.java:112)
```

### Pre-OOM Warning Signs
1. **GC frequency increasing** — interval between GCs shortening over time
2. **GC reclaiming less** — free bytes after GC decreasing trend
3. **GC pause times increasing** — full GCs taking longer
4. **Tenured occupancy climbing** — post-GC tenured percent trending up
5. **Allocation failures in tenured** — `<af type="tenured">` appearing frequently

## Heap Dump Triggers and Analysis

### Triggering Heap Dumps

#### Automatic on OOM
```
-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/path/to/dumps/
```

#### Manual (IBM J9)
```bash
# Via wsadmin
wsadmin> AdminControl.invoke(jvm, 'generateHeapDump')

# Via kill signal
kill -3 <pid>    # produces javacore (thread dump) + heapdump
```

#### Manual (HotSpot)
```bash
jmap -dump:format=b,file=heap.hprof <pid>
jcmd <pid> GC.heap_dump /path/to/heap.hprof
```

### Heap Dump Analysis Approach

1. **Open in Eclipse MAT** (Memory Analyzer Tool) or IBM IDDE
2. **Run Leak Suspects report** — identifies objects retaining the most memory
3. **Check dominator tree** — shows which objects "own" the most heap
4. **Look for:**
   - Large collections (HashMap, ArrayList with millions of entries)
   - Duplicate strings (enable `-XX:+UseStringDeduplication` with G1)
   - Session objects holding large data
   - Cache without eviction (unbounded growth)
   - Classloader leaks (multiple copies of same class from different loaders)

### Heap Dump File Sizes

Heap dumps are roughly the size of the heap (`-Xmx`). Ensure disk has enough space:
- 2 GB heap = ~2 GB dump file
- 8 GB heap = ~8 GB dump file
- Compressed dumps (`.phd` on IBM J9) are smaller but less detailed

## GC Tuning Parameters

### IBM J9 (Traditional WAS)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Xms` | 256m | Initial heap size |
| `-Xmx` | 512m | Maximum heap size |
| `-Xmn` | varies | Nursery (young gen) size |
| `-Xgcpolicy:gencon` | default | Generational concurrent (recommended) |
| `-Xgcpolicy:balanced` | — | Balanced GC for large heaps (>4GB) |
| `-Xgcpolicy:optthruput` | — | Throughput-optimized (longer pauses, higher throughput) |
| `-Xgcpolicy:metronome` | — | Real-time GC, sub-ms pauses (specialized) |
| `-Xgcthreads` | CPU count | Number of GC worker threads |

### G1GC Tuning (HotSpot / Liberty on OpenJDK)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-XX:+UseG1GC` | JDK 9+ default | Enable G1 collector |
| `-XX:MaxGCPauseMillis` | 200 | Target max pause time (ms) |
| `-XX:InitiatingHeapOccupancyPercent` | 45 | Old-gen % to trigger concurrent mark |
| `-XX:G1HeapRegionSize` | auto | Region size (1-32MB, power of 2) |
| `-XX:G1ReservePercent` | 10 | Reserve % for evacuation failures |
| `-XX:ConcGCThreads` | varies | Concurrent GC worker threads |
| `-XX:ParallelGCThreads` | varies | STW GC worker threads |

**G1 tuning tips:**
- Set `-Xms` = `-Xmx` to avoid heap resizing
- Start with default `MaxGCPauseMillis=200` and adjust
- If full GCs occur, increase heap or lower `InitiatingHeapOccupancyPercent`
- Monitor region size — too small = many regions = overhead

### ZGC Tuning (JDK 15+)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-XX:+UseZGC` | — | Enable ZGC collector |
| `-XX:+ZGenerational` | JDK 21+ default | Enable generational ZGC |
| `-XX:SoftMaxHeapSize` | = `-Xmx` | GC tries to stay below this |
| `-XX:ZCollectionInterval` | 0 (auto) | Force GC every N seconds |
| `-XX:ZAllocationSpikeTolerance` | 2.0 | Headroom for allocation spikes |

**ZGC tuning tips:**
- Set `-Xmx` generously — ZGC works best with headroom (2-3x live data)
- Use generational ZGC on JDK 21+ for better throughput
- If allocation stalls occur, increase heap or reduce allocation rate
- ZGC pauses are O(1) — heap size doesn't affect pause time

## Memory Leak Indicators

### In GC Logs
```
Pattern: post-GC heap usage trends upward across multiple full GC cycles

GC(100) Pause Full ... 1800M->1500M(2048M)   # recovered 300M
GC(200) Pause Full ... 1900M->1600M(2048M)   # recovered 300M
GC(300) Pause Full ... 1950M->1700M(2048M)   # recovered 250M
GC(400) Pause Full ... 1980M->1800M(2048M)   # recovered 180M  ← leak
```
Post-GC floor rising = leaked objects accumulating in tenured/old gen.

### In Application Logs
- `OutOfMemoryError` after hours/days of uptime (not immediately after start)
- Increasing response times over time (GC pauses growing)
- WSVR0605W (hung threads) correlating with GC activity

### Common Leak Sources

| Pattern | Cause | Fix |
|---------|-------|-----|
| Session objects growing | Storing large data in HTTP session | Limit session scope, use external cache |
| Static collections growing | `static Map` or `List` without eviction | Use bounded cache (Caffeine, Guava) |
| Classloader leak | Redeploy creates new classloader, old not GC'd | Fix static references from app to container classes |
| JDBC connection leak | Connections not returned to pool | Use try-with-resources, check connection pool monitors |
| ThreadLocal not cleaned | Values persist across request reuse in thread pool | Call `ThreadLocal.remove()` in finally block |
| Listener/callback accumulation | Event listeners registered but never removed | Deregister in `destroy()` or use weak references |

## Codes That Appear Together

| First Event | Often Followed By | Root Cause |
|-------------|-------------------|------------|
| Frequent `<af type="tenured">` | `OutOfMemoryError: Java heap space` | Heap too small or memory leak |
| `GC overhead limit exceeded` | SRVE0255E with OOM stacktrace | Leak — application unusable |
| WSVR0605W (all threads) at same time | Global GC with long `totalms` | Long GC pause froze all threads |
| `OutOfMemoryError: Metaspace` | CWWKZ0013E (app start fail) | Classloader leak after redeploys |
| ZGC `Allocation Stall` | Increased response times | Heap undersized for allocation rate |

## Real Log Line Examples

```
[10/12/24 14:22:04:257 CET] 0000004e GCLogger      I   <af type="tenured" id="890" timestamp="2024-10-12T14:22:04.257" intervalms="45000">
[10/12/24 14:22:06:500 CET] 0000004e GCLogger      I     <gc type="global" totalms="2245.000" />
[10/12/24 14:22:06:510 CET] 0000004e GCLogger      I     <tenured freebytes="31457280" totalbytes="1073741824" percent="2" />
[10/12/24 14:22:06:510 CET] 0000004e GCLogger      I   </af>
[10/12/24 14:22:06:520 CET] 0000004e WebContainer  E SRVE0255E: Uncaught exception
  java.lang.OutOfMemoryError: Java heap space
    at com.example.cache.InMemoryCache.put(InMemoryCache.java:89)
```

## Diagnostic Queries

### Splunk — OOM Events
```spl
index=websphere "OutOfMemoryError"
| rex field=_raw "OutOfMemoryError:?\s*(?P<oom_type>[^\n]+)"
| stats count by host oom_type
| sort -count
```

### Splunk — GC Pause Impact (Hung Thread Correlation)
```spl
index=websphere msg_code="WSVR0605W"
| bin _time span=1m
| stats dc(thread_name) as hung_threads by _time host
| where hung_threads > 5
```

### Splunk — OOM After Redeploy (Classloader Leak)
```spl
index=websphere ("OutOfMemoryError" AND "Metaspace") OR msg_code="CWWKZ0001I"
| transaction host maxspan=1h
| where eventcount > 1
```

### Splunk — Memory Pressure Trending
```spl
index=websphere "tenured freebytes"
| rex field=_raw "freebytes=\"(?P<free>\d+)\" totalbytes=\"(?P<total>\d+)\""
| eval pct_used=round((1-(free/total))*100,1)
| timechart span=5m avg(pct_used) by host
```

### Splunk — Allocation Failures by Type
```spl
index=websphere "af type="
| rex field=_raw "<af type=\"(?P<af_type>\w+)\""
| timechart span=5m count by af_type
```

## Incident Response Playbook

### Scenario: OutOfMemoryError in Production
1. **Immediate**: Check if `-XX:+HeapDumpOnOutOfMemoryError` is set — if yes, locate the dump file
2. **Capture**: If no auto-dump, manually trigger before restarting: `jcmd <pid> GC.heap_dump /tmp/heap.hprof`
3. **Restart**: Restart the affected server to restore service
4. **Analyze**: Open heap dump in Eclipse MAT, run Leak Suspects
5. **GC logs**: Review verbose GC logs for the hours before OOM — look for rising post-GC baseline
6. **Root cause**: Identify the leaking object type and trace to source code
7. **Fix**: Deploy fix, monitor GC logs to confirm leak is resolved

### Scenario: Long GC Pauses Causing Timeouts
1. **Identify GC type**: Is it young GC (normal) or full GC (concerning)?
2. **Check pause duration**: Young GC > 200ms or Full GC > 2s = needs tuning
3. **If full GCs are frequent**: Heap is too small or there's a leak (see Memory Leak Indicators)
4. **If young GC pauses are long**: Nursery/young gen too large, reduce `-Xmn` or let GC auto-size
5. **Consider collector change**: G1GC or ZGC for latency-sensitive workloads
6. **Correlate**: Match GC pause timestamps with WSVR0605W to confirm GC is causing hung threads
