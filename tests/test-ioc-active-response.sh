#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGTEST="/var/ossec/bin/wazuh-logtest"
FIXTURE="$ROOT/tests/fixtures/web-ioc-99906.log"

if [[ ! -x "$LOGTEST" ]]; then
    echo "ERROR: no existe $LOGTEST; ejecutar en el Wazuh Manager." >&2
    exit 1
fi

echo "========== UNIT TESTS: FIREWALL-DROP POLICY =========="
PYTHONPATH="$ROOT/configuration/manager/integrations" \
    python3 -m unittest discover -s "$ROOT/tests" -p 'test_*.py' -v

echo
echo "========== LIVE MANAGER POLICY =========="
PYTHONPATH="$ROOT/configuration/manager/integrations" python3 - <<'PY'
from orangebox_active_response import firewall_drop_policy_for_alert

expected = {
    "10460": 604800, "10461": 604800, "10462": 604800, "10463": 604800,
    "99903": 604800, "99904": 604800, "99905": 604800,
    "99907": 604800, "99908": 604800, "99911": 604800,
    "99912": 604800, "99913": 604800, "99914": 604800,
    "99906": 2592000, "10053": 2592000, "10051": 86400,
}
# Comprueba políticas IOC, PHP2Shell IOC y escaneo repetido con su grupo exacto.
for rule_id, seconds in expected.items():
    groups = ["orangebox_web_auto_block"] if rule_id == "10051" else ["web", "accesslog"]
    result = firewall_drop_policy_for_alert(
        rule_id, 12 if rule_id == "10051" else 14, groups, "/var/ossec/etc/ossec.conf"
    )
    if result["status"] != "configured" or result["timeout_seconds"] != seconds:
        raise SystemExit(f"FAIL rule={rule_id}: {result}")
    print(f"OK rule={rule_id}: firewall-drop {seconds}s ({result['location']})")
PY

echo
echo "========== WAZUH-LOGTEST: INCIDENT IOC + PHP2SHELL =========="
index=0
# Envía cada muestra de log a wazuh-logtest y valida la regla esperada para ese caso.
while IFS= read -r log_line || [[ -n "$log_line" ]]; do
    [[ -z "$log_line" ]] && continue
    index=$((index + 1))
    output="$(printf '%s\n' "$log_line" | "$LOGTEST" -v 2>&1)"
    printf '%s\n' "$output"

    if (( index == 1 )); then
        if ! grep -Fq "*Rule 10050 matched" <<<"$output"; then
            echo "FAIL: sample 1 did not match the PHP2Shell/PEAR classifier 10050." >&2
            exit 1
        fi
        if ! grep -Fq "*Rule 10053 matched" <<<"$output"; then
            echo "FAIL: sample 1 did not route to IOC child 10053." >&2
            exit 1
        fi
        if ! grep -Eq "id: ['\"]?10053['\"]?" <<<"$output"; then
            echo "FAIL: sample 1 final alert is not rule 10053." >&2
            exit 1
        fi
        echo "OK: sample 1 matched 10050 and finished as IOC rule 10053 (30-day policy)."
    elif (( index == 2 )); then
        if grep -Fq "*Rule 10050 matched" <<<"$output"; then
            echo "FAIL: sample 2 must not match PHP2Shell rule 10050 alone." >&2
            exit 1
        fi
        if ! grep -Eq "id: ['\"]?99906['\"]?" <<<"$output"; then
            echo "FAIL: sample 2 did not retain generic IOC web rule 99906." >&2
            exit 1
        fi
        echo "OK: sample 2 bypassed PHP2Shell and retained IOC rule 99906."
    fi
done < "$FIXTURE"

if (( index != 2 )); then
    echo "FAIL: expected 2 log samples, processed $index." >&2
    exit 1
fi

cat <<'EOF'

NOTE:
wazuh-logtest valida decoders/reglas en sandbox y NO ejecuta Active Response.
La ejecución real se verifica después de una alerta real/sintética inyectada
por el pipeline de eventos, comprobando:
  - evento 651 / regla OrangeBox 10458 en alerts.json del Manager;
  - /var/ossec/logs/active-responses.log en el agente;
  - el estado del firewall del agente.
EOF

echo "ALL TESTS PASSED"
