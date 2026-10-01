#!/usr/bin/env bash
set -euo pipefail
GEOIP_DIR="${ORANGEBOX_GEOIP_DIR:-/var/lib/orangebox/geoip}"
LOCK_FILE="${ORANGEBOX_GEOIP_LOCK:-/var/run/orangebox-geoip-update.lock}"
BASE_URL="https://download.db-ip.com/free"
TMP_DIR="$(mktemp -d /var/tmp/orangebox-geoip.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT
for c in curl gzip mmdblookup install flock mv date sed head stat; do command -v "$c" >/dev/null 2>&1 || { echo "ERROR: falta $c" >&2; exit 1; }; done
[[ "$(id -u)" -eq 0 ]] || exit 1
mkdir -p "$GEOIP_DIR"; chown root:wazuh "$GEOIP_DIR" 2>/dev/null || true; chmod 0750 "$GEOIP_DIR"
exec 9>"$LOCK_FILE"; flock -n 9 || exit 0
release="$(date -u +%Y-%m)"; previous="$(date -u -d '1 month ago' +%Y-%m)"
update(){ local prefix="$1" dst="$2" test="$3" r url gz db; for r in "$release" "$previous"; do url="$BASE_URL/${prefix}-${r}.mmdb.gz"; gz="$TMP_DIR/${prefix}-${r}.gz"; db="$TMP_DIR/${prefix}-${r}.mmdb"; curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 "$url" -o "$gz" || continue; gzip -t "$gz"; gzip -dc "$gz" > "$db"; "$test" "$db" || continue; install -o root -g wazuh -m 0640 "$db" "$dst"; printf '%s\n' "$r" > "$dst.release"; chown root:wazuh "$dst.release"; chmod 0640 "$dst.release"; return 0; done; [[ -f "$dst" ]]; }
validate_city(){ mmdblookup --file "$1" --ip 8.8.8.8 country names en >/dev/null 2>&1 && mmdblookup --file "$1" --ip 8.8.8.8 city names en >/dev/null 2>&1; }
validate_asn(){ mmdblookup --file "$1" --ip 8.8.8.8 autonomous_system_number >/dev/null 2>&1; }
update dbip-city-lite "$GEOIP_DIR/dbip-city-lite.mmdb" validate_city
update dbip-asn-lite "$GEOIP_DIR/dbip-asn-lite.mmdb" validate_asn
echo "GeoIP actualizado sin reiniciar wazuh-manager."
