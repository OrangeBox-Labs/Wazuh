#!/bin/bash
#
# OrangeBox Wazuh - sincronizador automatico de agentes Zimbra / Carbonio
# Fuente de verdad: grupo Wazuh "zimbra".
#
set -euo pipefail

OSSEC_HOME="/var/ossec"
GROUP="zimbra"
OUTPUT="${OSSEC_HOME}/etc/lists/orangebox-zimbra-agents"
TMP="${OUTPUT}.tmp.$$"
AGENT_GROUPS="${OSSEC_HOME}/bin/agent_groups"

cleanup() {
    rm -f "$TMP"
}
trap cleanup EXIT

if [[ ! -x "$AGENT_GROUPS" ]]; then
    echo "ERROR: no existe $AGENT_GROUPS" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

"$AGENT_GROUPS" -l -g "$GROUP" 2>/dev/null |
awk '
    BEGIN { IGNORECASE=1 }
    match($0, /name:[[:space:]]*([^,]+)/, m) {
        name=m[1]
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
        sub(/\.$/, "", name)
        if (name != "") print name
    }
' |
sort -fu |
while IFS= read -r hostname; do
    [[ -z "$hostname" ]] && continue

    printf '%s:zimbra\n' "$hostname"

    if [[ "$hostname" == *.* ]]; then
        short="${hostname%%.*}"
        [[ -n "$short" ]] && printf '%s:zimbra\n' "$short"
    fi
done |
sort -fu > "$TMP"

if [[ -f "$OUTPUT" ]] && cmp -s "$TMP" "$OUTPUT"; then
    exit 0
fi

install -o root -g wazuh -m 0640 "$TMP" "$OUTPUT"

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wazuh-manager; then
    systemctl reload wazuh-manager >/dev/null 2>&1 || true
fi
exit 0
