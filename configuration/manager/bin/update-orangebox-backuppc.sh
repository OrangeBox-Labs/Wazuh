#!/bin/bash
# OrangeBox - actualiza whitelist dinamica de BackupPC.
set -euo pipefail
HOSTNAME="backup.example.invalid"
CDB="/var/ossec/etc/lists/orangebox-backuppc-dynamic"
LOCK="/var/run/orangebox-update-backuppc.lock"
exec 9>"$LOCK"; flock -n 9 || exit 0
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
mapfile -t IPS < <(getent ahostsv4 "$HOSTNAME" | awk '{print $1}' | sort -u)
[[ "${#IPS[@]}" -eq 1 ]] || { echo "ERROR: el host debe resolver a una sola IPv4" >&2; exit 1; }
ip="${IPS[0]}"; [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || exit 1
printf '%s:\n' "$ip" > "$TMP"
[[ -f "$CDB" ]] && cmp -s "$TMP" "$CDB" && exit 0
install -o root -g wazuh -m 0640 "$TMP" "$CDB"
systemctl restart wazuh-manager
