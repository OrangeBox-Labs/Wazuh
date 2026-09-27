#!/usr/bin/env bash
set -euo pipefail

# OrangeBox Wazuh - IOC list updater
#
# Updates:
#   etc/lists/malicious-ioc/malicious-ip
#   etc/lists/malicious-ioc/malicious-domains
#   etc/lists/malicious-ioc/malware-hashes
#
# Sources:
#   IPs:     URLhaus recent URLs + Emerging Threats compromised IPs
#   Domains: URLhaus hostfile
#   Hashes:  MalwareBazaar recent detections

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
LIST_DIR="$WAZUH_HOME/etc/lists/malicious-ioc"
TMP_DIR="$(mktemp -d /var/tmp/orangebox-ioc.XXXXXX)"

URLHAUS_TEXT="https://urlhaus.abuse.ch/downloads/text_recent/"
URLHAUS_HOSTS="https://urlhaus.abuse.ch/downloads/hostfile/"
ET_COMPROMISED_IPS="https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
MB_API="https://mb-api.abuse.ch/api/v1/"

# Replace this during installation with the MalwareBazaar Auth-Key.
MB_AUTH_KEY='REPLACE_WITH_MALWAREBAZAAR_AUTH_KEY'

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: falta el comando '$1'." >&2
        exit 1
    }
}

count_lines() {
    wc -l < "$1"
}

need_cmd curl
need_cmd awk
need_cmd grep
need_cmd sort
need_cmd comm
need_cmd install
need_cmd systemctl

mkdir -p "$LIST_DIR"

echo "Descargando fuentes IOC..."

curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
    "$URLHAUS_TEXT" -o "$TMP_DIR/urlhaus.txt"

curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
    "$URLHAUS_HOSTS" -o "$TMP_DIR/urlhaus.hosts"

curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
    "$ET_COMPROMISED_IPS" -o "$TMP_DIR/et-compromised.txt"

# -------------------------
# Malicious IPs
# -------------------------
awk '
    /^[[:space:]]*#/ { next }
    {
        line=$0
        sub(/^https?:\/\//, "", line)
        sub(/[:\/].*$/, "", line)
        if (line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
            print line
        }
    }
' "$TMP_DIR/urlhaus.txt" > "$TMP_DIR/ip-urlhaus"

awk '
    /^[[:space:]]*#/ { next }
    {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                print $i
                break
            }
        }
    }
' "$TMP_DIR/et-compromised.txt" > "$TMP_DIR/ip-et"

cat "$TMP_DIR/ip-urlhaus" "$TMP_DIR/ip-et" |
    sort -u |
    awk '{ print $0 ":" }' > "$TMP_DIR/malicious-ip"

[[ -s "$TMP_DIR/malicious-ip" ]] || {
    echo "ERROR: no se obtuvieron IPs IOC validas." >&2
    exit 1
}

# -------------------------
# Malicious domains
# -------------------------
awk '
    /^[[:space:]]*#/ { next }
    NF >= 2 {
        d=$2
        gsub(/\r/, "", d)
        sub(/[;,].*$/, "", d)
        if (d ~ /^[[:alnum:]][[:alnum:].-]*\.[[:alnum:]][[:alnum:].-]*$/) {
            d=tolower(d)
            sub(/\.$/, "", d)
            if (d !~ /^(localhost|localhost\.localdomain|broadcasthost|ip6-)/) {
                print d ":"
            }
        }
    }
' "$TMP_DIR/urlhaus.hosts" |
    sort -u > "$TMP_DIR/malicious-domains"

[[ -s "$TMP_DIR/malicious-domains" ]] || {
    echo "ERROR: no se obtuvieron dominios IOC validos." >&2
    exit 1
}

# -------------------------
# Malware hashes
# -------------------------
if [[ -n "$MB_AUTH_KEY" && "$MB_AUTH_KEY" != 'REPLACE_WITH_MALWAREBAZAAR_AUTH_KEY' ]]; then
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
        -H "Auth-Key: $MB_AUTH_KEY" \
        --data 'query=recent_detections&hours=24' \
        "$MB_API" -o "$TMP_DIR/malware.json"

    grep -oE '"sha256_hash"[[:space:]]*:[[:space:]]*"[A-Fa-f0-9]{64}"' \
        "$TMP_DIR/malware.json" > "$TMP_DIR/malware-matches" || true

    if [[ ! -s "$TMP_DIR/malware-matches" ]]; then
        echo "ERROR: MalwareBazaar no devolvio hashes SHA256 validos; se conserva la lista existente." >&2
        exit 1
    fi

    awk -F'"' '{ print tolower($4) ":" }' \
        "$TMP_DIR/malware-matches" |
        sort -u > "$TMP_DIR/malware-hashes"

    [[ -s "$TMP_DIR/malware-hashes" ]] || {
        echo "ERROR: no se pudo construir malware-hashes." >&2
        exit 1
    }
else
    echo "INFO: MB_AUTH_KEY sin configurar; malware-hashes se conserva sin cambios."
fi

# -------------------------
# Safety check: reject >50% drops
# -------------------------
for name in malicious-ip malicious-domains; do
    old="$LIST_DIR/$name"
    new="$TMP_DIR/$name"

    [[ -s "$old" ]] || continue

    old_count="$(count_lines "$old")"
    new_count="$(count_lines "$new")"

    if (( old_count > 0 && new_count * 2 < old_count )); then
        echo "ERROR: $name bajo de $old_count a $new_count entradas; se rechaza la actualizacion." >&2
        exit 1
    fi

    added="$(comm -13 <(sort -u "$old") <(sort -u "$new") | awk 'NF {n++} END {print n+0}')"
    removed="$(comm -23 <(sort -u "$old") <(sort -u "$new") | awk 'NF {n++} END {print n+0}')"

    printf '%-16s previous=%s new=%s added=%s removed=%s\n' \
        "$name" "$old_count" "$new_count" "$added" "$removed"
done

if [[ -s "$TMP_DIR/malware-hashes" ]]; then
    old_count=0
    new_count="$(count_lines "$TMP_DIR/malware-hashes")"
    added=0
    removed=0

    if [[ -s "$LIST_DIR/malware-hashes" ]]; then
        old_count="$(count_lines "$LIST_DIR/malware-hashes")"
        added="$(comm -13 <(sort -u "$LIST_DIR/malware-hashes") <(sort -u "$TMP_DIR/malware-hashes") | awk 'NF {n++} END {print n+0}')"
        removed="$(comm -23 <(sort -u "$LIST_DIR/malware-hashes") <(sort -u "$TMP_DIR/malware-hashes") | awk 'NF {n++} END {print n+0}')"

        if (( old_count > 0 && new_count * 2 < old_count )); then
            echo "ERROR: malware-hashes bajo de $old_count a $new_count entradas; se rechaza la actualizacion." >&2
            exit 1
        fi
    else
        added="$new_count"
    fi

    printf '%-16s previous=%s new=%s added=%s removed=%s\n' \
        "malware-hashes" "$old_count" "$new_count" "$added" "$removed"
else
    current_count=0
    [[ -s "$LIST_DIR/malware-hashes" ]] && current_count="$(count_lines "$LIST_DIR/malware-hashes")"
    printf '%-16s previous=%s new=%s added=%s removed=%s\n' \
        "malware-hashes" "$current_count" "$current_count" "0" "0"
fi

# -------------------------
# Validate formats
# -------------------------
if ! awk -F: '
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { next }
    { exit 1 }
' "$TMP_DIR/malicious-ip"; then
    echo "ERROR: malicious-ip contiene entradas invalidas." >&2
    exit 1
fi

if ! awk -F: '
    $1 ~ /^[[:alnum:]][[:alnum:].-]*\.[[:alnum:]][[:alnum:].-]*$/ { next }
    { exit 1 }
' "$TMP_DIR/malicious-domains"; then
    echo "ERROR: malicious-domains contiene entradas invalidas." >&2
    exit 1
fi

if [[ -s "$TMP_DIR/malware-hashes" ]] && ! awk -F: '
    length($1) == 64 && $1 ~ /^[A-Fa-f0-9]+$/ { next }
    { exit 1 }
' "$TMP_DIR/malware-hashes"; then
    echo "ERROR: malware-hashes contiene entradas invalidas." >&2
    exit 1
fi

# -------------------------
# Install and rebuild CDB
# -------------------------
install -o wazuh -g wazuh -m 0640 \
    "$TMP_DIR/malicious-ip" "$LIST_DIR/malicious-ip"

install -o wazuh -g wazuh -m 0640 \
    "$TMP_DIR/malicious-domains" "$LIST_DIR/malicious-domains"

if [[ -s "$TMP_DIR/malware-hashes" ]]; then
    install -o wazuh -g wazuh -m 0640 \
        "$TMP_DIR/malware-hashes" "$LIST_DIR/malware-hashes"
fi

echo "=== OrangeBox IOC lists updated ==="
printf 'IPs:     %s entries\n' "$(count_lines "$LIST_DIR/malicious-ip")"
printf 'Domains: %s entries\n' "$(count_lines "$LIST_DIR/malicious-domains")"
printf 'Hashes:  %s entries\n' "$(count_lines "$LIST_DIR/malware-hashes" 2>/dev/null || true)"

systemctl restart wazuh-manager
echo "Wazuh manager restarted; CDB lists rebuilt on startup."
