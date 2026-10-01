#!/bin/bash
#
# OrangeBox Wazuh - sincronizador automatico de agentes cPanel
# =============================================================
#
# Genera la CDB utilizada por las reglas del Manager para reconocer
# servidores que pertenecen al grupo Wazuh "cpanel".
#
# IMPORTANTE:
#   - NO mantener una lista manual de agentes.
#   - La fuente de verdad es la pertenencia al grupo Wazuh "cpanel".
#   - Se generan hostname y hostname corto para soportar ambos formatos
#     que pueden aparecer en Phase 1 de wazuh-logtest.
#   - El archivo se reemplaza atomicamente solo cuando cambia.
#
# Salida:
#   /var/ossec/etc/lists/orangebox-cpanel-agents
#
# Uso:
#   /var/ossec/etc/lists/update-orangebox-cpanel-agents.sh
#
# Recomendacion:
#   Ejecutar desde cron cada 5-10 minutos.
#

set -euo pipefail

OSSEC_HOME="/var/ossec"
GROUP="cpanel"
OUTPUT="${OSSEC_HOME}/etc/lists/orangebox-cpanel-agents"
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

# agent_groups -l -g cpanel devuelve los agentes asociados al grupo.
# Extraemos el campo Name para no depender del ID ni de la IP del agente.
# Se aceptan las variantes de mayusculas/minusculas de la salida del CLI.
"$AGENT_GROUPS" -l -g "$GROUP" 2>/dev/null |
awk '
    BEGIN { IGNORECASE=1 }
    match($0, /name:[[:space:]]*([^,]+)/, m) {
        name=m[1]
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
        if (name != "") print name
    }
' |
sort -fu |
while IFS= read -r hostname; do
    [[ -z "$hostname" ]] && continue

    # Hostname completo.
    printf '%s:cpanel\n' "$hostname"

    # Tambien registrar el hostname corto. Esto permite que una misma
    # maquina funcione tanto si el evento llega como FQDN como si llega
    # con el hostname corto del sistema.
    if [[ "$hostname" == *.* ]]; then
        short="${hostname%%.*}"
        [[ -n "$short" ]] && printf '%s:cpanel\n' "$short"
    fi
done |
sort -fu > "$TMP"

# Evitar escrituras y recargas innecesarias si no hubo cambios.
if [[ -f "$OUTPUT" ]] && cmp -s "$TMP" "$OUTPUT"; then
    exit 0
fi

install -o root -g wazuh -m 0640 "$TMP" "$OUTPUT"

# La CDB se carga por analysisd. Si el contenido cambio, solicitar una
# recarga controlada del Manager para que la nueva lista quede disponible.
# No reiniciar nada si la lista no cambio.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wazuh-manager; then
    systemctl reload wazuh-manager >/dev/null 2>&1 || {
        echo "AVISO: wazuh-manager no soporta reload; la nueva CDB quedara disponible al proximo restart del Manager." >&2
    }
fi

exit 0
