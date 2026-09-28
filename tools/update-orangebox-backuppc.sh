#!/bin/bash
#
# OrangeBox - Actualiza whitelist dinamica de BackupPC
#
# Resuelve el hostname autorizado y mantiene actualizada la CDB
# utilizada por la regla 20001 de orangebox-auth.xml.
#
# El host autorizado debe resolver a una sola IPv4.
# La whitelist se reemplaza completamente en cada actualizacion:
# nunca se conservan IPs historicas.
#
# En la implementacion real, reemplace TU_HOSTNAME por el FQDN
# del servidor BackupPC autorizado.
#

set -euo pipefail

HOSTNAME="TU_HOSTNAME"
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

if [ "${#IPS[@]}" -ne 1 ]; then
    echo "ERROR: $HOSTNAME debe resolver a una sola IPv4; se obtuvieron ${#IPS[@]}: ${IPS[*]}" >&2
    exit 1
fi

ip="${IPS[0]}"

if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "ERROR: IPv4 invalida obtenida para $HOSTNAME: $ip" >&2
    exit 1
fi

printf '%s:\n' "$ip" > "$TMP"

if [ -f "$CDB" ] && cmp -s "$TMP" "$CDB"; then
    exit 0
fi

install -o root -g wazuh -m 0640 "$TMP" "$CDB"

echo "BackupPC whitelist actualizada:"
cat "$CDB"

echo "Reiniciando wazuh-manager para recargar la CDB..."
systemctl restart wazuh-manager
