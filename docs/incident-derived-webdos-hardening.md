# Incident-derived web / DoS hardening

## Purpose

This document explains the detection and response changes derived from a production availability incident on a Linux/cPanel workload. It is intentionally sanitized: it contains no customer hostnames, real source addresses, private account names, or deployment-specific internal addresses.

The goal is not to encode one incident as a permanent IOC list. The goal is to convert the observed failure modes into reusable Wazuh controls.

## What the incident taught us

The load spike was not one attack. It was a stack of independent pressures that amplified each other:

1. TCP connection pressure left many sockets in `SYN-RECV`, consuming kernel/network processing.
2. Internal HTTP activity associated with `mod_pagespeed` produced repeated loopback-style requests.
3. Automated probes for cloud credentials and application secrets reached PHP-backed error handling and consumed PHP-FPM capacity.
4. Search/bot traffic used changing query parameters that reduced cache effectiveness and pushed requests into PHP and the database.
5. Web content returned an SEO-spam page with HTTP 200, indicating a compromise/content-injection signal rather than simple scanning.
6. Existing packet/event-rate SYN detection did not directly measure persistent socket state.

The resulting design therefore observes both **attack intent** and **resource impact**.

## Detection matrix

| Rule | Signal | Why it exists | Response |
| --- | --- | --- | --- |
| `10820` | Request for `.env`, `.git`, cloud credential/config paths, `credentials.json`, Firebase service-account JSON, etc. | Establishes a low-cost, high-value reconnaissance signal. | Context |
| `10821` | High-confidence secret/credential path returns HTTP 2xx | A successful 2xx response is materially different from a normal 404 scan: it may represent exposure. | 24h `firewall-drop`, excluding validated reverse proxies |
| `10822` | 3 different sensitive URLs from one source in 60s | Distinguishes an automated scanner from an isolated typo. | 24h `firewall-drop`, excluding validated reverse proxies |
| `10823` | Same sensitive URL repeated 3 times in 30s | Catches persistent automated discovery even when the scanner repeats one target. | 24h `firewall-drop`, excluding validated reverse proxies |
| `10824` | `Serf/1.3.9` + `mod_pagespeed/1.13.35.2` signature | Captures the internal request-loop signature without assuming every such request is malicious. | Context |
| `10825` | 20 matching mod_pagespeed signals in 30s | Converts a single signature into an availability warning when it becomes repetitive. | Alert only |
| `10826` | Claude/Semrush bot plus `k=` / `page=` cache-bypass pattern | Identifies a request shape that can defeat normal caching and increase PHP/database work. | Context |
| `10827` | Same bot/cache-bypass URL repeated 20 times in 60s | Separates occasional crawling from a burst capable of exhausting application resources. | Alert only |
| `10828` | HTTP 200 URL containing SEO/betting spam indicators | Detects possible content injection/SEO compromise even when the HTTP server considers the request successful. | Alert only; investigate compromise |
| `10829` | Same source maintains >=20 SYN-RECV sockets to one destination/port across 3 samples | Measures persistent socket state, not only packet/event rate. | 1h `firewall-drop` |
| `10830` | Total SYN-RECV exceeds 50 | Detects distributed connection pressure where no single source necessarily crosses the single-source threshold. | Alert only |
| `10831` | Aggregate `ksoftirqd` CPU exceeds 20% | Captures kernel/network processing impact caused by connection pressure. | Alert only |
| `10832` | 1-minute load exceeds CPU count for 3 samples | Turns the resource symptom into a correlated availability alert instead of a generic load alarm. | Alert only |
| `10833` | PHP-FPM worker >=25% CPU | Identifies the hot application workers that can become the bottleneck. | Context |
| `10834` | Same PHP-FPM account remains hot for 3 samples/60s | Correlates worker pressure by account and avoids reacting to a single transient worker. | Alert only |

## Why the existing SYN rules remain

The existing SYN controls are still useful:

- `10454`: high event-rate SYN flood from one source/destination/port.
- `10455`: distributed SYN pressure using many source IPs.
- `10456`: TCP port scanning.

The new `10829`/`10830` rules are complementary. They consume endpoint socket-state telemetry, so they can detect a persistent `SYN-RECV` condition even when the packet/event-rate thresholds are not reached in the exact same way.

This separation is deliberate: packet-rate detection answers **"how many SYN events are arriving?"**, while socket-state telemetry answers **"how many half-open connections are actually consuming state right now?"**.

## Why the web rules distinguish 404 from 200

A scanner requesting `/.env` or `/.git/config` and receiving 404 is still useful reconnaissance and should contribute to correlation. A sensitive path returning 2xx is a higher-confidence exposure signal and can justify immediate containment.

This is why `10820` is intentionally broad and low severity, while `10821` is narrow and high severity.

## Why reverse-proxy exceptions are a CDB

Blocking the address visible in Apache logs can be dangerous when a reverse proxy, load balancer, or security service is the actual source seen by the backend. The CDB `orangebox-web-discovery-proxies` is therefore an explicit trust boundary.

The public repository contains only documentation/example addresses. Production deployments must populate the list with their own validated proxy addresses.

## Endpoint telemetry design

The cPanel profile emits lightweight command telemetry at short intervals:

- every 5s: total and grouped `SYN-RECV` sockets;
- every 10s: aggregate `ksoftirqd` CPU, only when above threshold;
- every 30s: load average, only when 1-minute load exceeds CPU count;
- every 10s: PHP-FPM workers, only when an individual worker is above threshold.

The commands are intentionally filtered before output. This reduces Wazuh event volume and avoids shipping normal-state noise every interval.

## FIM coverage

The cPanel profile also watches high-value web entry points:

- `/home/*/public_html/.htaccess`
- `/home/*/public_html/wp-config.php`
- `/home/*/public_html/index.php`
- `/home/*/public_html/functions.php`

The purpose is to detect the most relevant persistence/content-injection changes without recursively monitoring every web file and generating excessive FIM noise.

## Active Response policy

Two new response groups are intentionally narrow:

- `orangebox_web_auto_block`: 24-hour `firewall-drop` for high-confidence remote web reconnaissance/exposure.
- `orangebox_syn_flood_block`: 1-hour `firewall-drop` for persistent single-source SYN-RECV pressure.

Distributed SYN pressure is detected but not automatically blocked by these rules. A single source is easier to attribute safely; distributed traffic should be handled with upstream/network controls rather than indiscriminate local blocking.

Likewise, bot identity, SEO indicators, load, `ksoftirqd`, and PHP-FPM pressure are alerts rather than automatic blocks because those signals can have legitimate causes or require application-level remediation.

## Sanitization policy for the public repository

The public repository must never contain:

- customer or production hostnames;
- real source IPs or private infrastructure addresses;
- customer account names;
- incident-specific credentials, tokens, or secrets;
- deployment-specific proxy allowlists;
- permanent IOC entries copied from a one-off incident unless explicitly classified as public threat intelligence.

The public version keeps the **detection logic, thresholds, architecture, rationale, and validation examples**, while replacing environment-specific values with generic or RFC 5737 documentation addresses.

## Validation before production rollout

Run Wazuh rule testing with representative samples for:

1. `/.env`, `/.git/config`, `/credentials.json`, and `/firebase-adminsdk.json` returning both 404 and 200.
2. Three different sensitive URLs from one source.
3. Repeated `Serf/1.3.9 ... mod_pagespeed/1.13.35.2` access-log events.
4. `ORANGEBOX_SYNRECV count=20 srcip=203.0.113.10 dstip=192.0.2.10 dstport=443` repeated three times.
5. `ORANGEBOX_SYNRECV_TOTAL count=77`.
6. `ORANGEBOX_KSOFTIRQ cpu=23.00`.
7. `ORANGEBOX_LOAD cpus=4 load1=6.30 load5=5.80 load15=4.90` repeated three times.
8. `ORANGEBOX_PHPFPM user=example_account cpu=53.74 command=php-fpm pool example_account` repeated three times.

Validate both the alert rule IDs and the Active Response decision. In particular, confirm that proxy exceptions prevent blocking and that `10829` exposes a valid `srcip` to `firewall-drop`.

## Operational follow-up

The incident also identified host-hardening measures that belong alongside Wazuh detection: TCP SYN backlog/syncookie tuning, disabling problematic `mod_pagespeed` deployments, early rejection of clearly malicious web probes, and application/web-server fixes that prevent missing paths from being routed into expensive PHP execution.

Wazuh should detect and contain the abuse; it should not be used as a substitute for fixing the underlying web-server and application behavior.
