# syslog / journald Analysis

## Formats

### RFC 3164 (BSD syslog — most common)

```
Mar 11 10:15:33 web01 sshd[12345]: Failed password for root from 198.51.100.1 port 54321 ssh2
Mar 11 10:15:33 web01 kernel: [123456.789] Out of memory: Killed process 5678 (java)
Mar 11 10:15:33 web01 nginx[12345]: 2025/03/11 10:15:33 [error] connect() failed
```

| Field | Position | Meaning |
|-------|----------|---------|
| Timestamp | 1-3 | `Mon DD HH:MM:SS` (no year!) |
| Hostname | 4 | Source host |
| Process | 5 | `program[pid]:` |
| Message | 6+ | Free-form text |

**Note**: RFC 3164 timestamps lack year. Infer from file modification date or current year.

### RFC 5424 (IETF syslog — structured)

```
<165>1 2025-03-11T10:15:33.123456+01:00 web01 nginx 12345 - [meta key="value"] Connection refused
```

| Field | Position | Meaning |
|-------|----------|---------|
| Priority | `<NNN>` | Facility × 8 + severity |
| Version | After `>` | Always `1` for RFC 5424 |
| Timestamp | 3 | ISO 8601 with microseconds |
| Hostname | 4 | Source host |
| App-name | 5 | Application |
| ProcID | 6 | Process ID |
| MsgID | 7 | Message type identifier |
| Structured data | `[...]` | Key-value pairs |
| Message | Rest | Free-form text |

### journald (systemd journal)

#### Text output (`journalctl`)
```
Mar 11 10:15:33 web01 systemd[1]: Started nginx.service - A high performance web server.
Mar 11 10:15:33 web01 kernel: oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),task=java,pid=5678
```

#### JSON output (`journalctl -o json`)
```json
{
  "__REALTIME_TIMESTAMP": "1710151533123456",
  "_HOSTNAME": "web01",
  "_SYSTEMD_UNIT": "nginx.service",
  "SYSLOG_IDENTIFIER": "nginx",
  "PRIORITY": "3",
  "MESSAGE": "connect() failed (111: Connection refused)",
  "_PID": "12345"
}
```

PRIORITY maps to syslog severity (0=emerg, 3=error, 4=warning, 6=info, 7=debug).

## Detection Heuristics

**RFC 3164**: Line starts with `Mon DD HH:MM:SS hostname process` pattern.

**RFC 5424**: Line starts with `<NNN>1` followed by ISO timestamp.

**journald JSON**: JSON with `_HOSTNAME`, `MESSAGE`, `PRIORITY` fields.

Score 0.9+ if >50% of lines match the pattern.

## Facility Codes

| Code | Name | Typical sources |
|------|------|-----------------|
| 0 | `kern` | Kernel messages (OOM, hardware) |
| 1 | `user` | User-space programs |
| 2 | `mail` | Mail system (postfix, sendmail) |
| 3 | `daemon` | System daemons (cron, sshd, nginx) |
| 4 | `auth` | Security/auth (sshd, sudo, pam) |
| 5 | `syslog` | Syslog daemon itself |
| 6 | `lpr` | Printing |
| 7 | `news` | Network news |
| 10 | `authpriv` | Private auth messages |
| 11 | `ftp` | FTP daemon |
| 16-23 | `local0-7` | Custom / application use |

## Severity Levels

| Code | Name | Normalized | Meaning |
|------|------|------------|---------|
| 0 | `emerg` | ERROR | System unusable |
| 1 | `alert` | ERROR | Immediate action required |
| 2 | `crit` | ERROR | Critical condition |
| 3 | `err` | ERROR | Error condition |
| 4 | `warning` | WARN | Warning condition |
| 5 | `notice` | INFO | Normal but significant |
| 6 | `info` | INFO | Informational |
| 7 | `debug` | DEBUG | Debug messages |

## Critical System Events

### OOM Killer

```
kernel: Out of memory: Killed process 5678 (java), UID 1000, total-vm:4194304kB, anon-rss:2097152kB
kernel: oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=/system.slice/myapp.service,task_memcg=/system.slice/myapp.service,task=java,pid=5678,uid=1000
kernel: java invoked oom-killer: gfp_mask=0x100cca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0
```

**Triage**:
1. Which process was killed? (`task=java,pid=5678`)
2. How much memory was it using? (`anon-rss` = physical memory)
3. What triggered it? Check cgroup constraints (`oom_memcg=`)
4. Is it a memory leak or undersized limits?

### Disk Issues

```
kernel: EXT4-fs error (device sda1): ext4_find_entry: reading directory lblock 0
kernel: Buffer I/O error on device sda1, logical block 12345
systemd: myapp.service: Failed with result 'signal': SIGKILL (likely OOM)
```

### Segfaults

```
kernel: myapp[5678]: segfault at 0000000000000000 ip 00007f1234567890 sp 00007ffd12345678 error 4 in libc.so.6
```

Error codes: `4` = user read, `6` = user write, `5` = user exec. See `arch/x86/mm/fault.c`.

### systemd Service Failures

```
systemd[1]: myapp.service: Main process exited, code=exited, status=1/FAILURE
systemd[1]: myapp.service: Failed with result 'exit-code'.
systemd[1]: Failed to start myapp.service - My Application.
systemd[1]: myapp.service: Scheduled restart job, restart counter is at 5.
systemd[1]: myapp.service: Start request repeated too quickly, refusing to start.
```

**Restart loop**: `Scheduled restart ... counter is at N` followed by `repeated too quickly` = service crashing on startup.

### SSH / Auth Failures

```
sshd[12345]: Failed password for root from 198.51.100.1 port 54321 ssh2
sshd[12345]: Invalid user admin from 198.51.100.1 port 54321
sshd[12345]: Accepted publickey for deploy from 10.0.0.5 port 54321 ssh2
sudo: pam_unix(sudo:auth): authentication failure; logname=eric uid=1000
```

**Brute force detection**: >10 `Failed password` from same IP in 1 minute.

### Filesystem Full

```
kernel: No space left on device
systemd-journald[123]: Failed to rotate journal: No space left on device
rsyslogd: error writing to /var/log/messages: No space left on device
```

### Network

```
kernel: nf_conntrack: table full, dropping packet
kernel: TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies.
NetworkManager[123]: <warn> device (eth0): link timed out.
```

## Signal Tags

| Tag | Detection pattern |
|-----|-------------------|
| `OOM` | `Out of memory`, `oom-kill`, `oom_killer`, `Killed process` |
| `Segfault` | `segfault at`, `SIGSEGV` |
| `DiskFull` | `No space left`, `ENOSPC` |
| `DiskError` | `I/O error`, `EXT4-fs error`, `read error` |
| `Auth` | `Failed password`, `authentication failure`, `Invalid user` |
| `ServiceFail` | `Failed with result`, `Failed to start`, `restart counter` |
| `Network` | `nf_conntrack.*full`, `SYN flooding`, `link timed out` |
| `Kernel` | `kernel:` facility, hardware errors |

## Triage Strategy

1. **Filter by severity** — emerg/alert/crit first, then err
2. **Group by process** — which daemon is failing?
3. **Check kernel messages** — OOM kills, disk errors, segfaults are root causes
4. **Auth patterns** — burst of failed logins = brute force or misconfigured service
5. **Service restarts** — `restart counter` increasing = crash loop
6. **Timeline** — correlate OOM kill timestamp with application errors
7. **Cross-host** — same error on multiple hosts = systemic (deploy, config push, upstream)

## Useful Splunk Queries

```spl
# OOM kills
index=os sourcetype=syslog "Out of memory" OR "oom-kill" | table _time host process message

# Failed SSH logins (brute force)
index=os sourcetype=syslog "Failed password" | stats count by src_ip | where count>10

# Service restart loops
index=os sourcetype=syslog "restart counter" | rex "counter is at (?<count>\d+)" | where count>3

# Disk errors
index=os sourcetype=syslog "I/O error" OR "EXT4-fs error" OR "No space left" | timechart count by host

# Segfaults
index=os sourcetype=syslog "segfault at" | stats count by process host
```
