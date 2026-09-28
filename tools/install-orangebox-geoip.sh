#!/usr/bin/env bash
set -euo pipefail

# OrangeBox - instala el soporte local DB-IP Lite para los reportes Wazuh.
# Ejecutar desde la raiz del repositorio.

SCRIPT_SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/update-orangebox-geoip.sh"
SCRIPT_DEST="/usr/local/sbin/update-orangebox-geoip.sh"
CRON_FILE="/etc/cron.d/orangebox-geoip"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: ejecutar como root." >&2
    exit 1
fi

for cmd in install command curl gzip md5sum mmdblookup; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: falta el comando '$cmd'." >&2
        exit 1
    }
done

[[ -f "$SCRIPT_SOURCE" ]] || {
    echo "ERROR: no existe $SCRIPT_SOURCE." >&2
    exit 1
}

install -o root -g root -m 0750 "$SCRIPT_SOURCE" "$SCRIPT_DEST"

cat > "${CRON_FILE}.tmp" <<'EOF'
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
20 3 * * * root /usr/local/sbin/update-orangebox-geoip.sh >> /var/log/orangebox-geoip-update.log 2>&1
EOF

install -o root -g root -m 0644 "${CRON_FILE}.tmp" "$CRON_FILE"
rm -f "${CRON_FILE}.tmp"

mkdir -p /var/lib/orangebox/geoip
chown root:wazuh /var/lib/orangebox/geoip
chmod 0750 /var/lib/orangebox/geoip

echo "Ejecutando primera actualización GeoIP..."
"$SCRIPT_DEST"

echo
echo "=== Instalación OrangeBox GeoIP ==="
echo "Updater: $SCRIPT_DEST"
echo "Cron:    $CRON_FILE"
echo "DB dir:  /var/lib/orangebox/geoip"
echo "Listo."
