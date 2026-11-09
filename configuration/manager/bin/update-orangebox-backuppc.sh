#!/bin/bash
#
# OrangeBox - Actualiza whitelist dinamica de BackupPC
#
# La lista estatica y la lista dinamica son independientes.
#
#   /var/ossec/etc/lists/orangebox-backuppc-static
#       IPs administradas manualmente. Este script NUNCA la modifica.
#
#   /var/ossec/etc/lists/orangebox-backuppc-dynamic
#       IPs obtenidas desde DNS. Esta lista se reemplaza completamente
#       cuando cambia el resultado DNS.
#
# La regla 20001/20002 de orangebox-auth.xml consume ambas listas.
#

set -euo pipefail

HOSTNAME="${BACKUPPC_HOSTNAME:-backuppc.example.invalid}"
CDB="/var/ossec/etc/lists/orangebox-backuppc-dynamic"
LOCK="/var/run/orangebox-update-backuppc.lock"

# El lock evita que dos consultas DNS reemplacen la CDB al mismo tiempo.
exec 9>"$LOCK"
flock -n 9 || exit 0

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Resuelve solo IPv4 y elimina direcciones repetidas antes de validar.
mapfile -t IPS < <(
    getent ahostsv4 "$HOSTNAME" |
    awk '{print $1}' |
    sort -u
)

# Fail-closed: ante una respuesta DNS vacía o múltiple, conserva la CDB anterior.
if [ "${#IPS[@]}" -eq 0 ]; then
    echo "ERROR: No se pudo resolver IPv4 para $HOSTNAME" >&2
    exit 1
fi

if [ "${#IPS[@]}" -ne 1 ]; then
    echo "ERROR: $HOSTNAME debe resolver a una sola IPv4; se obtuvieron ${#IPS[@]}: ${IPS[*]}" >&2
    exit 1
fi

# A partir de aquí solo se acepta una IPv4 obtenida por DNS.
ip="${IPS[0]}"

if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "ERROR: IPv4 invalida obtenida para $HOSTNAME: $ip" >&2
    exit 1
fi

# Convierte la IP validada al formato clave:valor que espera una CDB.
printf '%s:\n' "$ip" > "$TMP"

if [ -f "$CDB" ] && cmp -s "$TMP" "$CDB"; then
    exit 0
fi

# Reemplaza solo la lista dinámica; la whitelist estática nunca se modifica.
install -o root -g wazuh -m 0640 "$TMP" "$CDB"

echo "BackupPC whitelist dinamica actualizada:"
cat "$CDB"

echo "Reiniciando wazuh-manager para recargar la CDB..."
systemctl restart wazuh-manager
