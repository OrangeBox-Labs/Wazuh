#!/bin/bash
#
# OrangeBox Wazuh - sincronizador automatico de agentes cPanel
# =============================================================
#
# PROPOSITO:
#   Mantener automaticamente la CDB utilizada por las reglas del Manager
#   para reconocer servidores que pertenecen al grupo Wazuh "cpanel".
#
# FUENTE DE VERDAD:
#   La pertenencia al grupo Wazuh "cpanel".
#
# IMPORTANTE:
#   - NO mantener una lista manual de agentes.
#   - Se generan hostname y hostname corto.
#   - El parser no depende de extensiones no portables de awk.
#   - Un fallo de consulta no puede vaciar la whitelist existente.
#   - El archivo se reemplaza atomicamente solo cuando cambia.
#
# Salida:
#   /var/ossec/etc/lists/orangebox-cpanel-agents
#
# Ejecucion automatica:
#   /etc/cron.d/orangebox-cpanel-agents
#   Cada 10 minutos.
#

set -euo pipefail

OSSEC_HOME="/var/ossec"
GROUP="cpanel"
OUTPUT="${OSSEC_HOME}/etc/lists/orangebox-cpanel-agents"
GROUP_OUTPUT="${OUTPUT}.group.tmp.$$"
TMP="${OUTPUT}.tmp.$$"
AGENT_GROUPS="${OSSEC_HOME}/bin/agent_groups"

cleanup() {
    rm -f "$GROUP_OUTPUT" "$TMP"
}
trap cleanup EXIT

if [[ ! -x "$AGENT_GROUPS" ]]; then
    echo "ERROR: no existe $AGENT_GROUPS" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

# Consultamos la salida completa. Nunca ocultamos los errores:
# un fallo de agent_groups no debe convertirse en una whitelist vacia.
if ! "$AGENT_GROUPS" -l -g "$GROUP" >"$GROUP_OUTPUT" 2>&1; then
    echo "ERROR: no se pudo consultar el grupo Wazuh '$GROUP'." >&2
    cat "$GROUP_OUTPUT" >&2
    exit 1
fi

# agent_groups devuelve lineas similares a:
#   ID: 012  Name: server.example.cl.
#
# Extraemos solo el campo Name. Toleramos diferencias de mayusculas/minusculas
# en "Name" y no dependemos del texto de la cabecera.
HOSTS=$(
    sed -nE 's/^[[:space:]]*ID:[[:space:]]*[0-9]+[[:space:]]+[Nn][Aa][Mm][Ee]:[[:space:]]*(.*)[[:space:]]*$/\1/p' "$GROUP_OUTPUT" |
    sed -E 's/[[:space:]]+$//; s/\.$//' |
    sed '/^[[:space:]]*$/d' |
    sort -fu
)

ACTUAL_AGENTS=$(printf '%s\n' "$HOSTS" | sed '/^[[:space:]]*$/d' | wc -l)

# Fail-closed: si Wazuh respondio pero no pudimos extraer agentes,
# conservamos la whitelist existente y dejamos el error visible.
if [[ "$ACTUAL_AGENTS" -eq 0 ]]; then
    echo "ERROR: el grupo '$GROUP' no devolvio agentes reconocibles." >&2
    echo "ERROR: no se reemplaza $OUTPUT para evitar vaciar una whitelist valida." >&2
    cat "$GROUP_OUTPUT" >&2
    exit 1
fi

while IFS= read -r hostname; do
    [[ -z "$hostname" ]] && continue

    printf '%s:cpanel\n' "$hostname"

    if [[ "$hostname" == *.* ]]; then
        short="${hostname%%.*}"
        [[ -n "$short" ]] && printf '%s:cpanel\n' "$short"
    fi
done <<< "$HOSTS" |
sort -fu > "$TMP"

# Idempotencia: si no cambio la lista, no tocamos el archivo ni reiniciamos
# el Manager.
if [[ -f "$OUTPUT" ]] && cmp -s "$TMP" "$OUTPUT"; then
    exit 0
fi

install -o root -g wazuh -m 0640 "$TMP" "$OUTPUT"

# Las CDB se cargan al iniciar el analysis engine. Reiniciamos solo cuando
# hubo un cambio real en la lista.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wazuh-manager; then
    if ! systemctl restart wazuh-manager; then
        echo "ERROR: se actualizo $OUTPUT pero no fue posible reiniciar wazuh-manager para cargar la nueva CDB." >&2
        exit 1
    fi
fi

exit 0
