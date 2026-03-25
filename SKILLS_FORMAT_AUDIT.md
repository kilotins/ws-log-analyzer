# Skills vs Format Plugin Audit

Reviewed directory: `/Users/eric/ai-workshop/ws-log-analyzer-codex`  
Reviewed branch: `codex-work`

## Findings

### 1. High: `skills/json-structured-logs.md` materially overstates what `logpilot/formats/json_log.py` actually supports

- Skill: `skills/json-structured-logs.md`
- Plugin: `logpilot/formats/json_log.py`
- Plugin references: `logpilot/formats/json_log.py:13-18`, `logpilot/formats/json_log.py:39-49`, `logpilot/formats/json_log.py:292-301`

The skill describes support for `structlog` `event`, `python-json-logger` `levelname`/`asctime`, CloudWatch `@message`, GCP `textPayload`/`jsonPayload`, nested `record.level.name`, and tag families like `Timeout`, `Auth`, `RateLimit`, `CircuitBreaker`, `DiskFull`, and `DNS`. The plugin does not implement those field names or those signal tags.

What the plugin actually supports:
- Timestamps: `timestamp`, `time`, `ts`, `@timestamp`, `datetime`, `date`, `t`
- Levels: `level`, `severity`, `lvl`, `loglevel`, `log_level`, `priority`
- Messages: `msg`, `message`, `short_message`, `text`
- Tags: `OOM/GC`, `SSL/TLS`, `DB/Pool`, `HTTP`

Main gaps:
- The skill promises field coverage the plugin does not parse.
- The skill’s signal-tag taxonomy is mostly different from the plugin’s.
- Connection failures are bucketed as `DB/Pool` in the plugin, not as `Connection`, `Timeout`, `DNS`, or `RateLimit`.

### 2. High: `skills/syslog-analysis.md` claims journald JSON and tag granularity the syslog plugin does not implement

- Skill: `skills/syslog-analysis.md`
- Plugin: `logpilot/formats/syslog.py`
- Plugin references: `logpilot/formats/syslog.py:11-47`, `logpilot/formats/syslog.py:82-120`, `logpilot/formats/syslog.py:265-278`

The skill explicitly says journald JSON is part of detection heuristics. The plugin only detects RFC 3164, RFC 5424, and priority-prefixed journald text lines. It does not parse journald JSON objects.

Tag mismatches:
- Skill tags: `OOM`, `Segfault`, `DiskFull`, `DiskError`, `Auth`, `ServiceFail`, `Network`, `Kernel`
- Plugin tags: `OOM`, `Auth`, `Disk`, `Network`, `Service`, `Kernel`

Pattern mismatches:
- The skill calls out `nf_conntrack.*full`, `SYN flooding`, `link timed out`, `restart counter`, `segfault at`, and `kernel:` facility semantics.
- The plugin regexes do not cover most of those exact patterns. `NETWORK_RE`, `SERVICE_RE`, and `KERNEL_RE` are materially narrower.

### 3. High: `skills/python-logging-analysis.md` documents formats and tags that `logpilot/formats/python_log.py` does not recognize

- Skill: `skills/python-logging-analysis.md`
- Plugin: `logpilot/formats/python_log.py`
- Plugin references: `logpilot/formats/python_log.py:14-38`, `logpilot/formats/python_log.py:75-99`, `logpilot/formats/python_log.py:323-340`

The skill treats these as first-class:
- default stdlib `ERROR:django.request:...`
- `structlog` key-value logs
- framework tags `Django`, `Flask`, `FastAPI`
- `Timeout`

The plugin does not have explicit detection regexes for:
- stdlib colon format without timestamp
- `structlog` key-value output
- framework-specific tags
- timeout-specific tagging

What the plugin actually tags:
- `Import`, `DB`, `Template`, `Auth`, `HTTP`, `Celery`, `OOM`

What the skill omits:
- `Template`
- `HTTP`

### 4. High: `skills/enonic-xp-analysis.md` promises Enonic tags and exception families that `logpilot/formats/enonic.py` does not bucket

- Skill: `skills/enonic-xp-analysis.md`
- Plugin: `logpilot/formats/enonic.py`
- Plugin references: `logpilot/formats/enonic.py:88-127`, `logpilot/formats/enonic.py:295-315`

The skill advertises signal tags for:
- `Enonic/App`
- `Enonic/Task`
- `DiskFull`
- `SSL/TLS`
- `Enonic/Cluster`
- `Enonic/Repo`
- `Enonic/Index`

The plugin only implements:
- `OOM/GC`
- `SSL/TLS`
- `Enonic/Cluster`
- `Enonic/Repo`
- `Enonic/Index`
- `Enonic/Content`
- `Enonic/HTTP`

Main gaps:
- No `Enonic/App` tag
- No `Enonic/Task` tag
- No explicit disk-full tag
- The skill omits `Enonic/Content` and `Enonic/HTTP`, which the plugin does emit
- Many documented exceptions such as `ApplicationInstallException`, `BundleException`, `TaskNotFoundException`, and `TaskAlreadyRunningException` are not represented in plugin regexes

### 5. High: `skills/postgresql-log-analysis.md` uses a different signal-tag model than `logpilot/formats/postgresql.py`

- Skill: `skills/postgresql-log-analysis.md`
- Plugin: `logpilot/formats/postgresql.py`
- Plugin references: `logpilot/formats/postgresql.py:50-92`, `logpilot/formats/postgresql.py:196-225`

The skill uses generic tags:
- `DB/Pool`
- `OOM/GC`
- `SSL/TLS`
- `Auth`
- `Disk`
- `Replication`

The plugin emits PostgreSQL-specific tags:
- `PG/Conn`
- `PG/Lock`
- `PG/Replication`
- `PG/Disk`
- `PG/Auth`
- `PG/Vacuum`
- `PG/SlowQuery`
- `PG/Shutdown`
- `OOM/GC`

Main gaps:
- The skill omits `PG/Lock`, `PG/Vacuum`, `PG/SlowQuery`, and `PG/Shutdown`
- The skill describes `SSL/TLS`, but the plugin has no SSL-focused bucket regex
- The skill’s generic tags do not match the plugin’s actual output taxonomy

### 6. Medium: `skills/openshift-k8s-analysis.md` covers operator/audit cases beyond what `logpilot/formats/crio.py` can detect

- Skill: `skills/openshift-k8s-analysis.md`
- Plugin: `logpilot/formats/crio.py`
- Plugin references: `logpilot/formats/crio.py:44-72`, `logpilot/formats/crio.py:293-315`

The skill includes:
- API server audit JSON
- OAuth/audit event examples
- cluster operator health (`Degraded=True`, `Available=False`)
- signal tag `K8s/Operator`
- generic `OOM`

The plugin supports:
- CRI-O envelope
- klog
- K8s metadata JSON envelope
- tags `K8s/Pod`, `K8s/Network`, `K8s/Storage`, `K8s/Auth`, `OOM/GC`, `OpenShift/Route`

Main gaps:
- No `K8s/Operator` tag
- No dedicated operator-health regex
- No audit-event JSON parsing logic
- Skill says `OOM`; plugin emits `OOM/GC`

### 7. Medium: `skills/datapower-analysis.md` is richer than `logpilot/formats/datapower.py`, but its tag section omits three plugin tags

- Skill: `skills/datapower-analysis.md`
- Plugin: `logpilot/formats/datapower.py`
- Plugin references: `logpilot/formats/datapower.py:41-87`, `logpilot/formats/datapower.py:170-198`

The skill’s signal tags section lists:
- `SSL/TLS`
- `DB/Pool`
- `HTTP`
- `Auth`
- `Network`

The plugin also emits:
- `XML`
- `APIC`
- `Crypto`
- `OOM/GC`

Pattern caveat:
- The skill frames some tags as domain-driven (`domain=ssl`, `domain=aaa`, `domain=network`).
- The plugin does not structurally inspect `domain`; it relies on regexes over the full text plus code prefixes and keywords.

### 8. Medium: `skills/log4j-analysis.md` and `logpilot/formats/log4j.py` diverge on the signal-tag set

- Skill: `skills/log4j-analysis.md`
- Plugin: `logpilot/formats/log4j.py`
- Plugin references: `logpilot/formats/log4j.py:56-80`, `logpilot/formats/log4j.py:183-196`

Skill tags:
- `DB/Pool`
- `OOM/GC`
- `SpringBoot`
- `Kafka`
- `Auth`
- `Timeout`
- `HungThreads`

Plugin tags:
- `OOM/GC`
- `SSL/TLS`
- `DB/Pool`
- `Spring`
- `Kafka`
- `HTTP`

Main gaps:
- Skill uses `SpringBoot`; plugin emits `Spring`
- Skill omits `SSL/TLS` and `HTTP`
- Skill includes `Auth`, `Timeout`, and `HungThreads`, but the plugin has no matching bucket rules

### 9. Medium: `skills/tomcat-analysis.md` and `logpilot/formats/tomcat.py` disagree on both tag names and incident emphasis

- Skill: `skills/tomcat-analysis.md`
- Plugin: `logpilot/formats/tomcat.py`
- Plugin references: `logpilot/formats/tomcat.py:38-68`, `logpilot/formats/tomcat.py:146-169`

Skill tags:
- `OOM/GC`
- `DB/Pool`
- `SSL/TLS`
- `HTTP`
- `Deploy`
- `Thread`

Plugin tags:
- `Deploy`
- `Connector`
- `Session`
- `DB/Pool`
- `SSL/TLS`
- `Valve`
- `OOM/GC`

Main gaps:
- Skill omits `Connector`, `Session`, and `Valve`
- Plugin has no `HTTP` or `Thread` tag
- The skill’s thread-pool examples are only partially reflected by `TOMCAT_CONNECTOR_RE`

### 10. Medium: `skills/nginx-analysis.md` is mostly aligned, but the skill taxonomy is still not the plugin taxonomy

- Skill: `skills/nginx-analysis.md`
- Plugin: `logpilot/formats/nginx.py`
- Plugin references: `logpilot/formats/nginx.py:52-71`, `logpilot/formats/nginx.py:254-278`

Skill tags:
- `HTTP/5xx`
- `HTTP/4xx`
- `Upstream`
- `SSL/TLS`
- `Timeout`
- `RateLimit`
- `DiskFull`
- `Permission`

Plugin tags:
- `HTTP`
- `Upstream`
- `SSL/TLS`
- `RateLimit`
- `Timeout`
- `DiskFull`
- `Permission`

Main gaps:
- The plugin does not distinguish `HTTP/4xx` from `HTTP/5xx`; it emits only `HTTP`
- The plugin also supports Apache access and error logs, while the skill is written as nginx-only guidance

### 11. Medium: `skills/docker-analysis.md` over-describes Kubernetes lifecycle patterns that `logpilot/formats/docker_json.py` does not bucket

- Skill: `skills/docker-analysis.md`
- Plugin: `logpilot/formats/docker_json.py`
- Plugin references: `logpilot/formats/docker_json.py:173-190`

The plugin emits:
- `OOM/GC`
- `K8s/Pod`
- `Network`
- `SSL/TLS`
- `DB/Pool`
- `HTTP`

The skill heavily emphasizes:
- `CrashLoopBackOff`
- `ImagePullBackOff`
- exit `137`
- lifecycle transitions

Main gaps:
- The plugin does not explicitly detect `CrashLoopBackOff`
- The plugin does not explicitly detect `ImagePullBackOff`
- The plugin does not look for exit `137`
- `K8s/Pod` is only triggered for OOM-related pod text, not the broader pod lifecycle catalog in the skill

### 12. Medium: WAS-adjacent skills are much richer than `logpilot/formats/was.py`, but there is no matching plugin coverage for most of that guidance

- Skills: `skills/liberty-analysis.md`, `skills/websphere-startup.md`, `skills/servlet-errors.md`, `skills/thread-correlation.md`, `skills/security-analysis.md`, `skills/deployment-analysis.md`, `skills/jms-messaging.md`, `skills/message-codes.md`, `skills/database-errors.md`, `skills/stacktrace-analysis.md`, `skills/gc-performance.md`
- Primary plugin: `logpilot/formats/was.py`
- Plugin references: `logpilot/formats/was.py:32-42`, `logpilot/formats/was.py:127-137`

The WAS plugin only buckets:
- `OOM/GC`
- `HungThreads`
- `DB/Pool`
- `SSL/TLS`
- `HTTP`

Those skills cover substantially more:
- startup sequencing
- Liberty feature/config issues
- servlet lifecycle failures
- JMS/SIB patterns
- security code families
- deployment order problems
- GC and performance heuristics
- detailed message-code analysis

This is not necessarily wrong if those skills are intended as prompt-time domain knowledge, but they are not grounded in plugin-level tag detection. The sharpest example is `skills/liberty-analysis.md`, which documents Liberty JSON logging even though JSON Liberty logs are parsed by `logpilot/formats/json_log.py`, not `logpilot/formats/was.py`.

## Mapping

### Direct format-to-skill pairs reviewed

| Skill | Corresponding plugin | Audit result |
|------|----------------------|-------------|
| `skills/nginx-analysis.md` | `logpilot/formats/nginx.py` | Mostly aligned, taxonomy mismatch |
| `skills/log4j-analysis.md` | `logpilot/formats/log4j.py` | Material tag mismatch |
| `skills/json-structured-logs.md` | `logpilot/formats/json_log.py` | Major capability mismatch |
| `skills/python-logging-analysis.md` | `logpilot/formats/python_log.py` | Major capability mismatch |
| `skills/syslog-analysis.md` | `logpilot/formats/syslog.py` | Major format/tag mismatch |
| `skills/tomcat-analysis.md` | `logpilot/formats/tomcat.py` | Material tag mismatch |
| `skills/postgresql-log-analysis.md` | `logpilot/formats/postgresql.py` | Material taxonomy mismatch |
| `skills/datapower-analysis.md` | `logpilot/formats/datapower.py` | Broadly aligned but incomplete |
| `skills/enonic-xp-analysis.md` | `logpilot/formats/enonic.py` | Major gap on app/task/disk tags |
| `skills/openshift-k8s-analysis.md` | `logpilot/formats/crio.py` | Broader than implementation |
| `skills/docker-analysis.md` | `logpilot/formats/docker_json.py` | Broader than implementation |
| `skills/liberty-analysis.md` | `logpilot/formats/was.py` and `logpilot/formats/json_log.py` | Hybrid skill, no single faithful plugin match |

### Cross-cutting skills without a single direct format-plugin match

These skills are real domain knowledge, but they do not have a 1:1 corresponding file in `logpilot/formats/` for a bucket-tag/regex audit:

- `skills/cross-system-analysis.md`
- `skills/database-errors.md`
- `skills/deployment-analysis.md`
- `skills/gc-performance.md`
- `skills/jms-messaging.md`
- `skills/log-noise-filter.md`
- `skills/message-codes.md`
- `skills/security-analysis.md`
- `skills/servlet-errors.md`
- `skills/stacktrace-analysis.md`
- `skills/thread-correlation.md`
- `skills/websphere-startup.md`

For these, the closest implementation hooks are usually shared extraction in:
- `logpilot/formats/base.py`
- `logpilot/formats/was.py`
- `logpilot/parser.py`

But they are not represented as dedicated format plugins with matching `bucket_tags()` contracts.

## Pair Notes

### `skills/json-structured-logs.md` vs `logpilot/formats/json_log.py`

- Actual tag overlap: `OOM/GC`, `HTTP`
- Missing from plugin but present in skill: `Timeout`, `Auth`, `RateLimit`, `CircuitBreaker`, `DiskFull`, `DNS`
- Missing from skill but present in plugin: `SSL/TLS`, `DB/Pool`
- Regex/field mismatch: skill documents `event`, `levelname`, `asctime`, `@message`, `textPayload`, `jsonPayload`, nested `record.*`; plugin does not parse these

### `skills/python-logging-analysis.md` vs `logpilot/formats/python_log.py`

- Actual tag overlap: `DB`, `Auth`, `Import`, `Celery`, `OOM`
- Missing from plugin but present in skill: `Django`, `Flask`, `FastAPI`, `Timeout`
- Missing from skill but present in plugin: `Template`, `HTTP`
- Detection mismatch: skill’s plain stdlib `ERROR:logger:message` and `structlog` key-value examples are not explicitly recognized by `detect()`

### `skills/syslog-analysis.md` vs `logpilot/formats/syslog.py`

- Actual tag overlap: `OOM`, `Auth`, `Network`, `Kernel`
- Missing from plugin but present in skill: `Segfault`, `DiskFull`, `DiskError`, `ServiceFail`
- Missing from skill but present in plugin: generic `Disk`, generic `Service`
- Format mismatch: skill says journald JSON; plugin does not implement it

### `skills/log4j-analysis.md` vs `logpilot/formats/log4j.py`

- Actual tag overlap: `DB/Pool`, `OOM/GC`, `Kafka`
- Missing from plugin but present in skill: `Auth`, `Timeout`, `HungThreads`
- Missing from skill but present in plugin: `SSL/TLS`, `HTTP`
- Naming mismatch: `SpringBoot` in skill vs `Spring` in plugin

### `skills/nginx-analysis.md` vs `logpilot/formats/nginx.py`

- Actual tag overlap: `Upstream`, `SSL/TLS`, `Timeout`, `RateLimit`, `DiskFull`, `Permission`
- Taxonomy mismatch: skill splits `HTTP/4xx` and `HTTP/5xx`; plugin emits only `HTTP`
- Coverage mismatch: plugin includes Apache error/access parsing, skill does not

### `skills/tomcat-analysis.md` vs `logpilot/formats/tomcat.py`

- Actual tag overlap: `Deploy`, `DB/Pool`, `SSL/TLS`, `OOM/GC`
- Missing from plugin but present in skill: `HTTP`, `Thread`
- Missing from skill but present in plugin: `Connector`, `Session`, `Valve`

### `skills/postgresql-log-analysis.md` vs `logpilot/formats/postgresql.py`

- Actual tag overlap: `OOM/GC`
- Skill uses generic tags; plugin uses `PG/*` tags
- Missing from skill but present in plugin: `PG/Lock`, `PG/Vacuum`, `PG/SlowQuery`, `PG/Shutdown`
- Missing from plugin but present in skill: `SSL/TLS`

### `skills/datapower-analysis.md` vs `logpilot/formats/datapower.py`

- Actual tag overlap: `SSL/TLS`, `DB/Pool`, `HTTP`, `Auth`, `Network`
- Missing from skill but present in plugin: `XML`, `APIC`, `Crypto`, `OOM/GC`
- Domain-based wording in the skill is stronger than the actual regex implementation

### `skills/enonic-xp-analysis.md` vs `logpilot/formats/enonic.py`

- Actual tag overlap: `Enonic/Cluster`, `Enonic/Repo`, `Enonic/Index`, `OOM/GC`, `SSL/TLS`
- Missing from plugin but present in skill: `Enonic/App`, `Enonic/Task`, `DiskFull`
- Missing from skill but present in plugin: `Enonic/Content`, `Enonic/HTTP`

### `skills/openshift-k8s-analysis.md` vs `logpilot/formats/crio.py`

- Actual tag overlap: `K8s/Pod`, `K8s/Network`, `K8s/Storage`, `K8s/Auth`, `OpenShift/Route`
- Naming mismatch: skill uses `OOM`; plugin emits `OOM/GC`
- Missing from plugin but present in skill: `K8s/Operator`, audit/OAuth event coverage

### `skills/docker-analysis.md` vs `logpilot/formats/docker_json.py`

- Actual tag overlap: `SSL/TLS`, `DB/Pool`, `HTTP`
- Partial overlap: OOM and pod semantics
- Missing from plugin but present in skill: `CrashLoopBackOff`, `ImagePullBackOff`, exit `137`

## Overall Assessment

The skill library is valuable, but it is not consistently grounded in what the format plugins actually classify.

The strongest mismatches are:
- JSON
- Python
- Syslog
- Enonic
- PostgreSQL

The root pattern is consistent:
- skills often describe richer incident concepts than the parser emits as tags
- several skills use a tag vocabulary that does not match the plugin vocabulary
- some skills describe formats or payload structures the corresponding plugin does not actually parse

That means prompt-time guidance is often ahead of parser-time detection. If that is intentional, it should be treated as documentation/prompt guidance rather than as a faithful description of runtime classification behavior.

## Method

I compared:
- each skill file under `skills/`
- the corresponding format plugin under `logpilot/formats/`
- `bucket_tags()` implementations
- plugin regex definitions used for detection and classification
- shared extraction behavior in `logpilot/formats/base.py` and `logpilot/parser.py` where relevant
