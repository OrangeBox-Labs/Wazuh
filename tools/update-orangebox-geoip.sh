#!/usr/bin/env bash
set -euo pipefail

# OrangeBox - DB-IP Lite GeoIP updater
#
# Maintains local MMDB databases used by OrangeBox Wazuh reports:
#   /var/lib/orangebox/geoip/dbip-city-lite.mmdb
#   /var/lib/orangebox/geoip/dbip-asn-lite.mmdb
#
# Downloads the monthly release, validates the gzip and MMDB content
# with mmdblookup, then replaces it atomically.
# DB-IP publishes monthly MMDB files directly at download.db-ip.com.
# No wazuh-manager restart is required.

GEOIP_DIR="${ORANGEBOX_GEOIP_DIR:-/var/lib/orangebox/geoip}"
LOCK_FILE="${ORANGEBOX_GEOIP_LOCK:-/var/run/orangebox-geoip-update.lock}"

BASE_URL="https://download.db-ip.com/free"
CITY_PREFIX="dbip-city-lite"
ASN_PREFIX="dbip-asn-lite"

TMP_DIR="$(mktemp -d /var/tmp/orangebox-geoip.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: falta el comando '$1'." >&2
        exit 1
    }
}

for cmd in curl gzip mmdblookup install flock mv date awk sed head stat; do
    need_cmd "$cmd"
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: este actualizador debe ejecutarse como root." >&2
    exit 1
fi

mkdir -p "$GEOIP_DIR"
chown root:wazuh "$GEOIP_DIR" 2>/dev/null || true
chmod 0750 "$GEOIP_DIR"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "INFO: ya existe otra ejecución de update-orangebox-geoip.sh; se omite."
    exit 0
fi

current_release="$(date -u +%Y-%m)"
previous_release="$(date -u -d '1 month ago' +%Y-%m)"

download_text() {
    local url="$1"
    local destination="$2"
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
        "$url" -o "$destination"
}

lookup_text() {
    local db="$1"
    local ip="$2"
    shift 2

    mmdblookup --file "$db" --ip "$ip" "$@" 2>/dev/null |
        sed -n 's/^[[:space:]]*"\(.*\)" <utf8_string>/\1/p' |
        head -n 1
}

validate_city_db() {
    local db="$1"
    local country city
    country="$(lookup_text "$db" 8.8.8.8 country names en)"
    city="$(lookup_text "$db" 8.8.8.8 city names en)"

    if [[ -z "$country" || -z "$city" ]]; then
        echo "ERROR: DB-IP City Lite invalida: no devolvio country/city para 8.8.8.8." >&2
        return 1
    fi
}

validate_asn_db() {
    local db="$1"
    local asn
    asn="$(mmdblookup --file "$db" --ip 8.8.8.8 autonomous_system_number 2>/dev/null |
        sed -n 's/^[[:space:]]*\([0-9][0-9]*\) <uint32>/\1/p' |
        head -n 1)"

    if [[ -z "$asn" ]]; then
        echo "ERROR: DB-IP ASN Lite invalida: no devolvio ASN para 8.8.8.8." >&2
        return 1
    fi
}

update_db() {
    local kind="$1"
    local prefix="$2"
    local destination="$3"
    local validator="$4"
    local metadata="${destination}.release"

    local release url archive db_file

    for release in "$current_release" "$previous_release"; do
        url="$BASE_URL/${prefix}-${release}.mmdb.gz"

        if [[ -f "$destination" && -f "$metadata" ]] &&
           [[ "$(cat "$metadata" 2>/dev/null || true)" == "$release" ]]; then
            echo "Sin cambios: $kind DB-IP release $release."
            return 0
        fi

        archive="$TMP_DIR/${prefix}-${release}.mmdb.gz"
        db_file="$TMP_DIR/${prefix}-${release}.mmdb"

        echo "Intentando $kind DB-IP release $release..."
        if ! download_text "$url" "$archive"; then
            echo "INFO: release $release no disponible; intentando la anterior." >&2
            continue
        fi

        gzip -t "$archive"
        gzip -dc "$archive" > "$db_file"
        "$validator" "$db_file"

        chown root:wazuh "$db_file"
        chmod 0640 "$db_file"

        # Reemplazo atomico; no requiere reiniciar Wazuh.
        mv -f "$db_file" "$destination"

        printf '%s\n' "$release" > "${metadata}.tmp"
        chown root:wazuh "${metadata}.tmp"
        chmod 0640 "${metadata}.tmp"
        mv -f "${metadata}.tmp" "$metadata"

        echo "Actualizada: $destination"
        echo "  release: $release"
        echo "  size:    $(stat -c '%s' "$destination") bytes"
        return 0
    done

    if [[ -f "$destination" ]]; then
        echo "INFO: no hay una release nueva disponible para $kind; se conserva la DB actual."
        return 0
    fi

    echo "ERROR: no se encontro una release DB-IP valida para $kind." >&2
    return 1
}

update_db     "City"     "$CITY_PREFIX"     "$GEOIP_DIR/dbip-city-lite.mmdb"     validate_city_db

update_db     "ASN"     "$ASN_PREFIX"     "$GEOIP_DIR/dbip-asn-lite.mmdb"     validate_asn_db

echo
echo "=== OrangeBox GeoIP local ==="
ls -lh "$GEOIP_DIR"/dbip-*-lite.mmdb
echo "GeoIP actualizado sin reiniciar wazuh-manager."
