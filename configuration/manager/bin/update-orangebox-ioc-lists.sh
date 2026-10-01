#!/usr/bin/env bash
set -euo pipefail
WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
LIST_DIR="$WAZUH_HOME/etc/lists/malicious-ioc"
TMP_DIR="$(mktemp -d /var/tmp/orangebox-ioc.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT
LOCK_FILE="/var/run/orangebox-ioc-lists.lock"
exec 9>"$LOCK_FILE"
flock -n 9 || exit 0
mkdir -p "$LIST_DIR"
need_cmd(){ command -v "$1" >/dev/null 2>&1 || { echo "ERROR: falta $1" >&2; exit 1; }; }
for c in curl awk grep sort comm install systemctl; do need_cmd "$c"; done
curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 https://urlhaus.abuse.ch/downloads/text_recent/ -o "$TMP_DIR/urlhaus.txt"
curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 https://urlhaus.abuse.ch/downloads/hostfile/ -o "$TMP_DIR/urlhaus.hosts"
curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 https://rules.emergingthreats.net/blockrules/compromised-ips.txt -o "$TMP_DIR/et.txt"
awk '!/^[[:space:]]*#/ { line=$0; sub(/^https?:\/\//,"",line); sub(/[:\/].*/,"",line); if(line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print line }' "$TMP_DIR/urlhaus.txt" > "$TMP_DIR/ip1"
awk '!/^[[:space:]]*#/ { for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){print $i;break} }' "$TMP_DIR/et.txt" > "$TMP_DIR/ip2"
cat "$TMP_DIR/ip1" "$TMP_DIR/ip2" | sort -u | awk '{print $0 ":"}' > "$TMP_DIR/malicious-ip"
awk '!/^[[:space:]]*#/ && NF>=2 { d=$2; gsub(/\r/,"",d); sub(/[;,].*/,"",d); if(d ~ /^[[:alnum:]][[:alnum:].-]*\.[[:alnum:]][[:alnum:].-]*$/){d=tolower(d);sub(/\.$/,"",d);print d ":"} }' "$TMP_DIR/urlhaus.hosts" | sort -u > "$TMP_DIR/malicious-domains"
[[ -s "$TMP_DIR/malicious-ip" && -s "$TMP_DIR/malicious-domains" ]] || { echo "ERROR: IOC incompleto" >&2; exit 1; }
changed=0
for name in malicious-ip malicious-domains; do
  src="$TMP_DIR/$name"; dst="$LIST_DIR/$name"
  if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then continue; fi
  install -o wazuh -g wazuh -m 0640 "$src" "$dst"; changed=1
done
if (( changed )); then systemctl restart wazuh-manager; fi
