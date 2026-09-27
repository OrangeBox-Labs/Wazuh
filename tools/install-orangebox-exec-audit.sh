#!/usr/bin/env bash
set -euo pipefail

# OrangeBox Wazuh - auditd execution monitoring
# Installs audit rules that tag execve activity from high-risk temporary
# directories with the key "orangebox_exec".

RULE_FILE="/etc/audit/rules.d/99-orangebox-exec.rules"
KEY="orangebox_exec"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: falta el comando '$1'." >&2
        exit 1
    }
}

require_cmd auditctl

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: ejecutar como root." >&2
    exit 1
fi

mkdir -p "$(dirname "$RULE_FILE")"

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
WAZUH_CONF="$WAZUH_HOME/etc/ossec.conf"

if [[ -f "$WAZUH_CONF" ]] && ! grep -q '<log_format>audit</log_format>' "$WAZUH_CONF"; then
    cp -a "$WAZUH_CONF" "${WAZUH_CONF}.before-orangebox-exec"
    python3 - "$WAZUH_CONF" <<'PY'
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
s = p.read_text()
block = """  <!-- OrangeBox: auditd execution events -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
"""
idx = s.rfind("</ossec_config>")
if idx < 0:
    raise SystemExit("ERROR: no se encontro </ossec_config>.")
p.write_text(s[:idx] + block + s[idx:])
PY
    echo "OK: Wazuh agent configurado para leer /var/log/audit/audit.log."
fi

cat > "$RULE_FILE" <<'EOF'
# OrangeBox: detect execution from high-risk temporary directories.
# The audit key is consumed by Wazuh rule 10600.
-a always,exit -F arch=b64 -S execve -F dir=/tmp -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b32 -S execve -F dir=/tmp -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b32 -S execve -F dir=/var/tmp -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b32 -S execve -F dir=/dev/shm -F auid>=0 -F auid!=4294967295 -k orangebox_exec
EOF

# Avoid duplicate active rules when the installer is rerun.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
else
    auditctl -R "$RULE_FILE"
fi

echo "=== OrangeBox audit execution monitoring ==="
auditctl -l | grep -F "$KEY" || {
    echo "ERROR: las reglas $KEY no quedaron cargadas." >&2
    exit 1
}

if command -v systemctl >/dev/null 2>&1; then
    systemctl restart wazuh-agent
elif command -v service >/dev/null 2>&1; then
    service wazuh-agent restart
fi

echo "OK: auditd monitoriza ejecuciones en /tmp, /var/tmp y /dev/shm."
