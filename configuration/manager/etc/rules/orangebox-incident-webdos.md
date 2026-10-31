# Incident-derived detection matrix

This document records the detection coverage added after a production web-server availability incident.

## Web attack / abuse

| Rule | Trigger | Response |
| --- | --- | --- |
| `10820` | Sensitive paths: `.git`, `.env`, cloud credential paths, `credentials.json`, `firebase-adminsdk*.json`, `wp-config.php`, backup/config/database artifacts | Context |
| `10821` | High-confidence credential path returns HTTP 2xx | 24h `firewall-drop`, except validated reverse proxies |
| `10822` | 3 different sensitive URLs from same source in 60s | 24h `firewall-drop`, except validated reverse proxies |
| `10823` | Same sensitive URL repeated 3 times in 30s | 24h `firewall-drop`, except validated reverse proxies |
| `10824` | `Serf/1.3.9` + `mod_pagespeed/1.13.35.2` User-Agent | Context |
| `10825` | 20 `mod_pagespeed` signals from same source in 30s | Alert only; never block local source |
| `10826` | `Claude-SearchBot` / `SemrushBot` with `?k=xxxxx` / `page=` cache-bypass pattern | Context |
| `10827` | Same bot/cache-bypass URL repeated 20 times in 60s | Alert only |
| `10828` | HTTP 200 URL containing known SEO-spam/betting indicators such as `gg-bet` / `zaklady-esportowe` | Alert only; investigate compromise |

## Host availability

| Rule | Trigger | Response |
| --- | --- | --- |
| `10829` | Same source keeps >=20 SYN-RECV sockets to the same destination/port for 3 samples within 180s; sampled every 60s | 1h `firewall-drop`; suppress repeated rule firing for 2 min so other sources remain detectable |
| `10830` | Total SYN-RECV reaches 50 or more; sampled every 60s | Alert only; suppress repeats for 5 min |
| `10831` | Aggregate `ksoftirqd` CPU >=20% of one-core equivalent averaged between 5-minute samples | Alert only; suppress repeats for 5 min |
| `10832` | Load 1m is above CPU count for 3 samples within 900s; sampled every 300s | Alert only; suppress repeats for 15 min |
| `10833` | Individual PHP-FPM worker >=25% of one core during an approximately 1s sample; checked every 60s | Context |
| `10834` | Same PHP-FPM account remains hot for 3 samples within 180s; sampled every 60s | Alert only; suppress repeats for 5 min |

## Existing SYN flood rules

The existing firewall rules remain authoritative for event-rate based SYN flood detection:

- `10450`: TCP SYN support event, `RES=0x00 SYN URGP=0`, `no_log`.
- `10454`: 1000 SYN events / 10s, same source/destination/destination port; level 11 and existing `firewall-drop` for 1h.
- `10455`: 200 different source IPs / 10s to the same destination port; level 12, no automatic block.

The new `10829`/`10830` layer is intentionally different: it measures persistent **socket state** (`SYN-RECV`) rather than only packet/event rate. This closes the gap exposed by the incident where the RCA observed 77 simultaneous SYN-RECV sockets without evidence that a single source reached the old `10454` threshold.

## Prerequisite: remote command execution on cPanel agents

The command-monitoring entries below use `command` or `full_command` in the centralized `agent.conf`. Wazuh agents ignore these entries by default unless each affected cPanel endpoint has this setting in its **local** `/var/ossec/etc/local_internal_options.conf`:

```ini
logcollector.remote_commands=1
```

For the OrangeBox OPT agent package, whose agent home is `/opt/ossec`, the corresponding endpoint file is `/opt/ossec/etc/local_internal_options.conf`; for a standard installation under `/var/ossec`, use `/var/ossec/etc/local_internal_options.conf`. This is a security-sensitive change: it permits the Wazuh Manager to send commands that the agent executes with elevated privileges. Enable it only on the intended cPanel agents, verify the change through the approved configuration-management process, and restart the affected agent to apply it. The Manager's `configuration/manager/etc/local_internal_options.conf` does **not** enable this on endpoints.

## Endpoint telemetry

The cPanel profile now collects lightweight command telemetry every 60–300 seconds for:

- SYN-RECV grouped by source/destination/port every 60 seconds, emitting only groups with 20 or more sockets; total count is checked every 60 seconds but emitted only at 50 or more sockets;
- aggregate `ksoftirqd` CPU averaged across the interval since the previous sample and emitted only when >=20% of one-core equivalent; its first run initializes state and does not alert;
- load average every 300 seconds, emitted only when 1m load exceeds the CPU count;
- PHP-FPM workers every 60 seconds, measuring individual worker CPU over a roughly one-second sample and emitting only when a worker exceeds 25% of one core.

The `ksoftirqd` command persists `utime + stime` counters from `/proc/<pid>/stat` and compares them on its next run, nominally 300 seconds later. It reports average CPU consumed by matching kernel threads across that interval, not an instantaneous sample. On first run, after a gap longer than 900 seconds, or without a valid prior sample, it only refreshes state. Its percentage is expressed as a percentage of one logical core-equivalent, so it can exceed 100% on a multi-core host. PHP-FPM still measures each worker over a roughly one-second window, but that check runs every 60 seconds; brief spikes between samples may be missed. Thresholds remain 20% for `ksoftirqd` and 25% for a PHP-FPM worker.

The telemetry is decoded by `orangebox-incident-metrics.xml` and consumed by the rules above.

## Validation procedure

Before production rollout, validate XML syntax, test the decoder/rules, and verify that the affected cPanel agents accept centralized command monitoring. The prerequisite above must be completed on each test endpoint before expecting command telemetry.

Run `/var/ossec/bin/wazuh-logtest` and enter each line as a separate event. Use a fresh session for each frequency-correlation scenario.

### Apache access-log rules

Use representative Apache access-log lines:

```text
203.0.113.10 - - [24/Oct/2026:12:00:00 -0300] "GET /.env HTTP/1.1" 404 120 "-" "curl/8.5.0"
203.0.113.10 - - [24/Oct/2026:12:00:01 -0300] "GET /.env HTTP/1.1" 200 123 "-" "curl/8.5.0"
```

Expected: rule `10820` for the sensitive-path probe; rule `10821` for the HTTP 2xx response unless the source IP is in the validated reverse-proxy CDB.

For rule `10822`, submit three distinct sensitive URLs from the same source within 60 seconds, for example `/.env`, `/.git/config`, and `/credentials.json`. For rule `10823`, submit the same sensitive URL three times from one source within 30 seconds. Use a different source IP for each scenario.

### Command-monitoring decoders and host rules

Command output is wrapped by Logcollector. Include the alias prefix in the test event; passing only the `ORANGEBOX_...` payload will not exercise the current decoder prematch.

- Rule `10829`: enter this line three times in the same session, changing only the timestamp/session context as needed:

```text
ossec: output: 'orangebox-synrecv': ORANGEBOX_SYNRECV count=20 srcip=203.0.113.10 dstip=192.0.2.17 dstport=443
```

- Rule `10830`:

```text
ossec: output: 'orangebox-synrecv-total': ORANGEBOX_SYNRECV_TOTAL count=77
```

- Rule `10831`:

```text
ossec: output: 'orangebox-ksoftirq': ORANGEBOX_KSOFTIRQ cpu=23.00
```

- Rule `10832`: enter the following line three times in one session:

```text
ossec: output: 'orangebox-load': ORANGEBOX_LOAD cpus=4 load1=6.30 load5=5.80 load15=4.90
```

- Rule `10833`:

```text
ossec: output: 'orangebox-phpfpm': ORANGEBOX_PHPFPM user=work2019 cpu=53.74 command=php-fpm pool work2019
```

- Rule `10834`: enter the PHP-FPM event three times in one session, using the same `user` value each time.

`wazuh-logtest` validates decoding and rule selection; it does not execute the configured Active Responses. Verify the actual `firewall-drop` execution separately in a staging cPanel agent. For rules `10821`, `10822`, `10823`, and `10829`, confirm that the reverse-proxy/source exclusions behave as intended before any production enablement.
