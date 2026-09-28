#!/bin/bash
# OrangeBox - Wazuh Agent para cPanel / CSF
# RPM OPT: /opt/ossec
# El agent.conf se hereda desde el Wazuh Manager.

DEFAULT_MANAGER="wazuh.orangebox.cl"
DEFAULT_GROUP="OrangeBox"
DEFAULT_AGENT_NAME="$HOSTNAME"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RPM_FILE="$SCRIPT_DIR/../packages/agent/wazuh-agent_4.14.7-0_x86_64_OPT.rpm"
[ -n "$WAZUH_AGENT_RPM" ] 2>/dev/null && RPM_FILE="$WAZUH_AGENT_RPM" || true

CSF_CONF="/etc/csf/csf.conf"
CSF_POST="/usr/local/csf/bin/csfpost.sh"
ORANGEBOX_FIREWALL="/usr/local/sbin/orangebox-firewall"

fail() { echo "ERROR: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }
has() { command -v "$1" >/dev/null 2>&1; }

yesno() {
    local a
    while true; do
        read -r -p "$1 (s/N): " a
        case "$a" in
            s|S) return 0 ;;
            n|N|"") return 1 ;;
            *) echo "Responde s o n." ;;
        esac
    done
}

[ "$(id -u)" -eq 0 ] || fail "Debes ejecutar como root."
[ -f "$RPM_FILE" ] || fail "No existe el RPM: $RPM_FILE"
[ -f "$CSF_CONF" ] || fail "No existe $CSF_CONF. Este instalador requiere CSF."
[ -f "$CSF_POST" ] || fail "No existe $CSF_POST. No se puede integrar con CSF."

MANAGER="$DEFAULT_MANAGER"
GROUP="$DEFAULT_GROUP"
AGENT_NAME="$DEFAULT_AGENT_NAME"
PASSWORD=""

[ -n "$WAZUH_MANAGER" ] 2>/dev/null && MANAGER="$WAZUH_MANAGER" || true
[ -n "$WAZUH_AGENT_GROUP" ] 2>/dev/null && GROUP="$WAZUH_AGENT_GROUP" || true
[ -n "$WAZUH_AGENT_NAME" ] 2>/dev/null && AGENT_NAME="$WAZUH_AGENT_NAME" || true
[ -n "$WAZUH_REGISTRATION_PASSWORD" ] 2>/dev/null && PASSWORD="$WAZUH_REGISTRATION_PASSWORD" || true

echo
echo "============================================================"
echo " OrangeBox - Wazuh Agent para cPanel / CSF"
echo "============================================================"
echo
echo "RPM    : $RPM_FILE"
echo "Manager: $MANAGER"
echo "Grupo  : $GROUP"
echo "Nombre : $AGENT_NAME"
echo

if ! yesno "¿El hostname/nombre del agente, Manager y grupo están correctos?"; then
    read -r -p "Nombre [$AGENT_NAME]: " v; [ -n "$v" ] && AGENT_NAME="$v"
    read -r -p "Manager [$MANAGER]: " v; [ -n "$v" ] && MANAGER="$v"
    read -r -p "Grupo [$GROUP]: " v; [ -n "$v" ] && GROUP="$v"
fi

if [ -z "$PASSWORD" ]; then
    read -r -s -p "Password de enrolamiento: " PASSWORD
    echo
fi
[ -n "$PASSWORD" ] || fail "La password de enrolamiento está vacía."

echo
echo "=== CONFIRMACIÓN ==="
echo "Nombre : $AGENT_NAME"
echo "Manager: $MANAGER"
echo "Grupo  : $GROUP"
echo "Password: [oculta]"
yesno "¿Proceder con la instalación?" || fail "Instalación cancelada."

echo
echo "==> Instalando Wazuh Agent OPT en /opt/ossec..."
WAZUH_MANAGER="$MANAGER" \
WAZUH_AGENT_GROUP="$GROUP" \
WAZUH_AGENT_NAME="$AGENT_NAME" \
WAZUH_REGISTRATION_PASSWORD="$PASSWORD" \
rpm -ihv "$RPM_FILE" || fail "Falló la instalación del RPM Wazuh Agent OPT."

[ -x /opt/ossec/bin/wazuh-control ] || fail "El RPM no dejó /opt/ossec/bin/wazuh-control."
[ -f /opt/ossec/etc/ossec.conf ] || fail "No existe /opt/ossec/etc/ossec.conf."
ok "Wazuh Agent instalado en /opt/ossec."

backup_file() {
    local f="$1"
    cp -p "$f" "$f.orangebox-backup.$(date +%Y%m%d%H%M%S)" || fail "No se pudo respaldar $f."
}

csf_tcp_out_has_port() {
    local port="$1"
    awk -v p="$port" '
        /^[[:space:]]*TCP_OUT[[:space:]]*=/ {
            line=$0
            sub(/#.*/, "", line)
            if (line ~ "(^|[,[:space:]\"])" p "([,:\"]|$)") found=1
        }
        END { exit !found }
    ' "$CSF_CONF"
}

ensure_csf_tcp_out() {
    csf_tcp_out_has_port 1514 && csf_tcp_out_has_port 1515 && {
        ok "TCP_OUT ya contiene 1514 y 1515."
        return 0
    }

    backup_file "$CSF_CONF"

    awk '
        /^[[:space:]]*TCP_OUT[[:space:]]*=/ && $0 !~ /^[[:space:]]*#/ {
            line=$0
            if (line !~ /1514([,:\"]|$)/) sub(/"$/, ",1514\"", line)
            if (line !~ /1515([,:\"]|$)/) sub(/"$/, ",1515\"", line)
            print line
            next
        }
        { print }
    ' "$CSF_CONF" > "$CSF_CONF.orangebox.tmp" || fail "No se pudo preparar $CSF_CONF."

    mv "$CSF_CONF.orangebox.tmp" "$CSF_CONF" || fail "No se pudo actualizar $CSF_CONF."
    csf_tcp_out_has_port 1514 || fail "No se pudo validar TCP_OUT=1514."
    csf_tcp_out_has_port 1515 || fail "No se pudo validar TCP_OUT=1515."
    ok "CSF TCP_OUT actualizado con 1514,1515."
}

ensure_csf_tcp_out

# Detect the public/private pair used by GCP full NAT hairpin.
# Values can be overridden explicitly when installing on another server.
ORANGEBOX_PUBLIC_IP="${ORANGEBOX_PUBLIC_IP:-}"
ORANGEBOX_PRIVATE_IP="${ORANGEBOX_PRIVATE_IP:-}"

if [ -z "$ORANGEBOX_PRIVATE_IP" ]; then
    ORANGEBOX_PRIVATE_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')"
fi

if [ -z "$ORANGEBOX_PUBLIC_IP" ] && has curl; then
    ORANGEBOX_PUBLIC_IP="$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
fi

if [[ "$ORANGEBOX_PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$ORANGEBOX_PRIVATE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ok "Hairpin GCP detectado/configurado: $ORANGEBOX_PUBLIC_IP -> $ORANGEBOX_PRIVATE_IP."
else
    ORANGEBOX_PUBLIC_IP=""
    ORANGEBOX_PRIVATE_IP=""
    echo "AVISO: no se pudo determinar el par público/privado para excluir hairpin GCP."
fi

cat > "$ORANGEBOX_FIREWALL" <<EOF
#!/bin/bash
set -u
IPTABLES=/usr/sbin/iptables
PUBLIC_IP="$ORANGEBOX_PUBLIC_IP"
PRIVATE_IP="$ORANGEBOX_PRIVATE_IP"

$IPTABLES -N ORANGEBOX-FW 2>/dev/null || true
$IPTABLES -F ORANGEBOX-FW

if [ -n "$PUBLIC_IP" ] && [ -n "$PRIVATE_IP" ]; then
    $IPTABLES -A ORANGEBOX-FW \
        ! -i lo \
        -p tcp \
        --syn \
        -s "$PUBLIC_IP" \
        -d "$PRIVATE_IP" \
        -j RETURN
fi

$IPTABLES -A ORANGEBOX-FW \
    ! -i lo \
    -p tcp \
    --syn \
    -j LOG \
    --log-prefix "ORANGEBOX-FW: " \
    --log-level 4

$IPTABLES -A ORANGEBOX-FW -j RETURN
EOF
chmod 700 "$ORANGEBOX_FIREWALL" || fail "No se pudieron establecer permisos en $ORANGEBOX_FIREWALL."
ok "Helper ORANGEBOX-FW instalado."

MARKER="# OrangeBox - Wazuh firewall logging"
if ! grep -Fqx "$ORANGEBOX_FIREWALL" "$CSF_POST" 2>/dev/null; then
    backup_file "$CSF_POST"
    {
        cat "$CSF_POST"
        echo
        echo "$MARKER"
        echo "$ORANGEBOX_FIREWALL"
    } > "$CSF_POST.orangebox.tmp" || fail "No se pudo preparar $CSF_POST."
    chmod --reference="$CSF_POST" "$CSF_POST.orangebox.tmp" 2>/dev/null || chmod 700 "$CSF_POST.orangebox.tmp"
    chown --reference="$CSF_POST" "$CSF_POST.orangebox.tmp" 2>/dev/null || true
    mv "$CSF_POST.orangebox.tmp" "$CSF_POST" || fail "No se pudo actualizar $CSF_POST."
    ok "Hook ORANGEBOX-FW agregado a $CSF_POST."
else
    ok "Hook ORANGEBOX-FW ya existe en $CSF_POST."
fi

has csf || fail "No existe el comando csf."

echo
echo "==> Recargando CSF..."
csf -r || fail "CSF rechazó la configuración."

"$ORANGEBOX_FIREWALL" || fail "No se pudieron cargar las reglas ORANGEBOX-FW."

iptables -L ORANGEBOX-FW -n >/dev/null 2>&1 || fail "No existe ORANGEBOX-FW."
iptables -L INPUT -n 2>/dev/null | grep -Fq "ORANGEBOX-FW" || fail "INPUT no quedó conectado a ORANGEBOX-FW."
csf_tcp_out_has_port 1514 || fail "TCP_OUT no contiene 1514."
csf_tcp_out_has_port 1515 || fail "TCP_OUT no contiene 1515."
ok "CSF recargado y ORANGEBOX-FW validado."

echo
echo "==> Iniciando Wazuh Agent..."
if has systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent\.service'; then
    systemctl enable --now wazuh-agent || fail "No se pudo iniciar wazuh-agent."
    systemctl is-active --quiet wazuh-agent || fail "wazuh-agent no quedó activo."
else
    /opt/ossec/bin/wazuh-control start || fail "No se pudo iniciar Wazuh Agent."
fi
ok "Wazuh Agent activo."

echo
echo "============================================================"
echo " Instalación cPanel completada"
echo "============================================================"
echo " Wazuh    : /opt/ossec"
echo " Manager  : $MANAGER"
echo " Grupo    : $GROUP"
echo " Agente   : $AGENT_NAME"
echo " CSF      : TCP_OUT 1514,1515"
echo " Firewall : ORANGEBOX-FW"
echo "============================================================"
