# GeoIP local DB-IP Lite

OrangeBox Wazuh reports can use local DB-IP Lite MMDB databases to enrich source IPs without performing one external API request per IP.

## Databases

The updater maintains:

- `/var/lib/orangebox/geoip/dbip-city-lite.mmdb`
- `/var/lib/orangebox/geoip/dbip-asn-lite.mmdb`

City Lite provides country, region/state and city information. ASN Lite provides ASN information.

DB-IP Lite publishes monthly releases.

## Updater

Script:

`tools/update-orangebox-geoip.sh`

The updater:

1. checks the current monthly release and falls back to the previous month if needed;
2. avoids downloading a release that is already installed;
3. downloads only when a new release is available;
4. validates the gzip archive;
5. validates the MMDB with `mmdblookup`;
6. replaces each database atomically;
7. keeps the current database if an update fails;
8. does not restart `wazuh-manager`.

## Periodic update

Because DB-IP Lite is monthly, a daily cron is sufficient.

Use `/etc/cron.d/orangebox-geoip`:

```cron
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
20 3 * * * root /usr/local/sbin/update-orangebox-geoip.sh >> /var/log/orangebox-geoip-update.log 2>&1
```

To install it manually:

```bash
cat > /etc/cron.d/orangebox-geoip <<'EOF'
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
20 3 * * * root /usr/local/sbin/update-orangebox-geoip.sh >> /var/log/orangebox-geoip-update.log 2>&1
EOF

chown root:root /etc/cron.d/orangebox-geoip
chmod 0644 /etc/cron.d/orangebox-geoip
```

Verify:

```bash
cat /etc/cron.d/orangebox-geoip
ls -l /etc/cron.d/orangebox-geoip
```

The exact execution time is not important; the updater is designed for daily execution and only downloads when a new monthly release is available.

## Installation

From the repository root, as root:

```bash
install -o root -g root -m 0750 \
  tools/install-orangebox-geoip.sh \
  /usr/local/sbin/install-orangebox-geoip.sh

/usr/local/sbin/install-orangebox-geoip.sh
```

The installer copies the updater to `/usr/local/sbin`, creates the cron file, prepares the database directory and runs the first update.

## Security and attribution

Do not commit MMDB databases to the repository. They are downloaded at installation/update time.

DB-IP Lite is distributed under CC BY 4.0 and requires attribution to DB-IP. Reports using this data should identify the source and treat geolocation as approximate.
