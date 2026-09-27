#!/bin/bash
#
# OrangeBox - Actualiza whitelist dinamica de BackupPC
#
# Resuelve el hostname autorizado y mantiene actualizada la CDB
# utilizada por la regla 20001 de orangebox-auth.xml.
#

set -euo pipefail

HOSTNAME="vizcachas.orangebox.cl"
CDB="/var/ossec/etc/lists/orangebox-backuppc"
LOCK="/var/run/orangebox-update-backuppc.lock"

exec 9>"$LOCK"
flock -n 9 || exit 0

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

mapfile -t IPS < <(
    getent ahostsv4 "$HOSTNAME" |
    awk '{print $1}' |
    sort -u
)

if [ "${#IPS[@]}" -eq 0 ]; then
    echo "ERROR: No se pudo resolver IPv4 para $HOSTNAME" >&2
    exit 1
fi

for ip in "${IPS[@]}"; do
    if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "ERROR: IPv4 invalida obtenida para $HOSTNAME: $ip" >&2
        exit 1
    fi
    echo "$ip:"
done > "$TMP"

if [ -f "$CDB" ] && cmp -s "$TMP" "$CDB"; then
    exit 0
fi

install -o root -g wazuh -m 0640 "$TMP" "$CDB"

echo "BackupPC whitelist actualizada:"
cat "$CDB"

echo "Reiniciando wazuh-manager para recargar la CDB..."
systemctl restart wazuh-manager
