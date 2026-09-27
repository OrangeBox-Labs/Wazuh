#!/usr/bin/env bash
set -u

# OrangeBox Wazuh - chequeo simple de salud
#
# No reinicia servicios ni modifica configuracion.
# Devuelve:
#   0 = OK
#   1 = advertencia
#   2 = problema critico

WARN=0
CRIT=0
WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
OSSEC_CONF="${WAZUH_HOME}/etc/ossec.conf"
INTEGRATION="${WAZUH_HOME}/integrations/custom-orangebox-email.py"
ALERTS_JSON="${WAZUH_HOME}/logs/alerts/alerts.json"

ok()   { echo "OK: $*"; }
warn() { echo "ADVERTENCIA: $*"; WARN=1; }
crit() { echo "CRITICO: $*"; CRIT=1; }

check_service() {
    local service="$1"
    if ! systemctl list-unit-files "${service}.service" --no-legend 2>/dev/null | grep -q "${service}.service"; then
        echo "INFO: servicio $service no esta instalado."
        return 0
    fi

    if systemctl is-active --quiet "$service"; then
        ok "$service activo."
    else
        crit "$service no esta activo."
    fi
}

echo "=== OrangeBox Wazuh - Salud ==="

check_service "wazuh-manager"
check_service "postfix"

if pgrep -x wazuh-integratord >/dev/null 2>&1; then
    ok "wazuh-integratord ejecutandose."
else
    crit "wazuh-integratord no esta ejecutandose."
fi

if systemctl list-unit-files wazuh-indexer.service --no-legend 2>/dev/null | grep -q "wazuh-indexer.service"; then
    if systemctl is-active --quiet wazuh-indexer; then
        ok "wazuh-indexer activo."
    else
        warn "wazuh-indexer instalado pero no esta activo."
    fi
else
    echo "INFO: wazuh-indexer no esta instalado localmente."
fi

if [[ -f "$ALERTS_JSON" ]]; then
    ok "alerts.json existe."
else
    crit "No existe $ALERTS_JSON."
fi

if [[ -f "$INTEGRATION" ]]; then
    ok "Integracion OrangeBox existe."
    if grep -q '"/usr/sbin/sendmail", "-t", "-i"' "$INTEGRATION"; then
        ok "Integracion usa maildrop Postfix."
    else
        crit "Integracion no usa /usr/sbin/sendmail -t -i."
    fi
else
    crit "No existe $INTEGRATION."
fi

if [[ -f "$OSSEC_CONF" ]]; then
    grep -q '<jsonout_output>yes</jsonout_output>' "$OSSEC_CONF"         && ok "JSON de alertas habilitado."         || crit "jsonout_output no esta en yes."

    grep -q '<alerts_log>no</alerts_log>' "$OSSEC_CONF"         && ok "alerts.log deshabilitado."         || crit "alerts_log no esta en no."

    grep -q '<log_alert_level>5</log_alert_level>' "$OSSEC_CONF"         && ok "umbral de persistencia en nivel 5."         || crit "log_alert_level no esta en 5."

    grep -q '<email_log_source>alerts.json</email_log_source>' "$OSSEC_CONF"         && ok "fuente de correo en alerts.json."         || crit "email_log_source no esta en alerts.json."
else
    crit "No existe $OSSEC_CONF."
fi

VAR_USE="$(df -P /var 2>/dev/null | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
if [[ "$VAR_USE" =~ ^[0-9]+$ ]]; then
    if (( VAR_USE >= 90 )); then
        crit "El uso de /var esta en ${VAR_USE}%."
    elif (( VAR_USE >= 85 )); then
        warn "El uso de /var esta en ${VAR_USE}%."
    else
        ok "El uso de /var esta en ${VAR_USE}%."
    fi
else
    warn "No se pudo obtener el uso de /var."
fi

if command -v postqueue >/dev/null 2>&1; then
    QUEUE_COUNT="$(postqueue -p 2>/dev/null | awk 'BEGIN{n=0} /^[A-F0-9]+[[:space:]]/ {n++} END{print n}')"
    QUEUE_COUNT="${QUEUE_COUNT:-0}"
    if [[ "$QUEUE_COUNT" =~ ^[0-9]+$ ]]; then
        if (( QUEUE_COUNT >= 100 )); then
            warn "Postfix tiene ${QUEUE_COUNT} mensajes en cola."
        else
            ok "Postfix tiene ${QUEUE_COUNT} mensajes en cola."
        fi
    fi
fi

if (( CRIT )); then
    echo "RESULTADO: CRITICO"
    exit 2
elif (( WARN )); then
    echo "RESULTADO: ADVERTENCIA"
    exit 1
else
    echo "RESULTADO: OK"
    exit 0
fi
