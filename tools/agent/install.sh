#!/bin/bash

# OrangeBox - Wazuh Agent unificado / Firewall Logging
# Compatible: CentOS 6/7/8 and AlmaLinux 8/9/10.
#
# Logging backend by Enterprise Linux major version:
#   EL 6    : iptables -> rsyslog -> /var/log/orangebox-firewall.log -> Wazuh
#   EL 7+   : iptables -> journald -> Wazuh
#
# Idempotent: existing correct settings are preserved; missing settings are added;
# unexpected existing settings cause an error instead of guessing.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

# ---------------------------------------------------------------------------
# CONFIGURACION - EDITAR SOLO ESTA SECCION
# ---------------------------------------------------------------------------
IS_CPANEL=''
WAZUH_VERSION='4.14.7'
WAZUH_MANAGER='wazuh.orangebox.cl'
WAZUH_AGENT_GROUP='default'
WAZUH_AGENT_NAME=''
WAZUH_REGISTRATION_PASSWORD='tu_pass'
WAZUH_AGENT_RPM=''
WAZUH_OSSEC_SIZE='1G'
WAZUH_OSSEC_LV='wazuh'
WAZUH_OSSEC_VG=''
YARA_RULES_REPO='https://github.com/Yara-Rules/rules.git'
YARA_RULES_BRANCH='master'
YARA_BIN=''
YARA_NO_PACKAGE_INSTALL='no'
ORANGEBOX_PUBLIC_IP=''
ORANGEBOX_PRIVATE_IP=''

WAZUH_HOME='/var/ossec'
FIREWALL_LOG="/var/log/orangebox-firewall.log"
LOGROTATE_FILE="/etc/logrotate.d/orangebox-firewall"
RSYSLOG_FILE="/etc/rsyslog.d/orangebox-firewall.conf"
WAZUH_FIREWALL_HELPER="/var/ossec/bin/orangebox-iptables"
WAZUH_FIREWALL_STOP_HELPER="/var/ossec/bin/orangebox-iptables-stop"
WAZUH_FIREWALL_SERVICE="/etc/systemd/system/orangebox-iptables.service"
EL_MAJOR=""
LOGGING_BACKEND=""

ERROR_COUNT=0

step_error() {
    echo "ERROR: $*" >&2
    ERROR_COUNT=$((ERROR_COUNT + 1))
}

fail() { echo "ERROR: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }
warn() { echo "AVISO: $*" >&2; }
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

# ---------------------------------------------------------------------------
# 0. Plataforma / backend de logging
# ---------------------------------------------------------------------------

# Detecta la major de Enterprise Linux.
# Preferimos la macro %{rhel} de RPM y dejamos /etc/redhat-release como fallback.
detect_platform() {
    if has rpm; then
        EL_MAJOR="$(rpm -E '%{rhel}' 2>/dev/null || true)"
        case "$EL_MAJOR" in
            ""|"%{rhel}") EL_MAJOR="" ;;
        esac
    fi

    if [ -z "$EL_MAJOR" ] && [ -f /etc/redhat-release ]; then
        EL_MAJOR="$(sed -n 's/.*release \([0-9][0-9]*\).*/\1/p' /etc/redhat-release | head -n1)"
    fi

    case "$EL_MAJOR" in
        6)
            LOGGING_BACKEND="rsyslog"
            ;;
        7|8|9|10)
            LOGGING_BACKEND="journald"
            ;;
        *)
            fail "Versión de Enterprise Linux no soportada o no detectada: ${EL_MAJOR}."
            ;;
    esac

    ok "Enterprise Linux ${EL_MAJOR}: backend de logging ${LOGGING_BACKEND}."
}

# ---------------------------------------------------------------------------
# 1. Wazuh Agent
# ---------------------------------------------------------------------------

agent_installed() {
    rpm -q wazuh-agent >/dev/null 2>&1 || [ -x "$WAZUH_HOME/bin/wazuh-control" ]
}

agent_version() {
    rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' wazuh-agent 2>/dev/null || echo "desconocida"
}

ossec_mount_options() {
    awk -v mp="$WAZUH_HOME" '$2 == mp { print $4; exit }' /proc/mounts 2>/dev/null
}

ossec_mount_source() {
    awk -v mp="$WAZUH_HOME" '$2 == mp { print $1; exit }' /proc/mounts 2>/dev/null
}

ossec_mount_ready() {
    mountpoint -q "$WAZUH_HOME" 2>/dev/null || return 1

    local opts
    opts="$(ossec_mount_options)"

    case ",$opts," in
        *,noexec,*) return 1 ;;
    esac

    case ",$opts," in
        *,nosuid,*) ;;
        *) return 1 ;;
    esac

    case ",$opts," in
        *,nodev,*) ;;
        *) return 1 ;;
    esac

    return 0
}

agent_usable() {
    agent_installed || return 1
    ossec_mount_ready || return 1
    [ -s "$WAZUH_HOME/etc/client.keys" ] || return 1
    [ -x "$WAZUH_HOME/bin/wazuh-control" ] || return 1
}

ensure_lvm() {
    if has vgs && has lvs && has lvcreate; then
        return 0
    fi

    echo "==> Instalando lvm2..."
    if has yum; then
        yum install -y lvm2 >/dev/null 2>&1 \
            || fail "No se pudo instalar lvm2."
    elif has dnf; then
        dnf install -y lvm2 >/dev/null 2>&1 \
            || fail "No se pudo instalar lvm2."
    else
        fail "No existe yum ni dnf para instalar lvm2."
    fi

    has vgs && has lvs && has lvcreate \
        || fail "Las herramientas LVM no quedaron disponibles."
}

find_ossec_vg() {
    if [ -n "$WAZUH_OSSEC_VG" ]; then
        vgs "$WAZUH_OSSEC_VG" >/dev/null 2>&1 \
            || fail "El Volume Group $WAZUH_OSSEC_VG no existe."
        echo "$WAZUH_OSSEC_VG"
        return 0
    fi

    local vg
    vg="$(vgs --noheadings --units m --nosuffix -o vg_name,vg_free 2>/dev/null |
        awk '
            {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
                if (($2 + 0) >= 1024) {
                    print $1
                    exit
                }
            }')"

    [ -n "$vg" ] \
        || fail "No se encontró un Volume Group con al menos 1 GiB libres para /var/ossec."

    echo "$vg"
}

backup_fstab() {
    cp -p /etc/fstab "/etc/fstab.orangebox-backup.$(date +%Y%m%d%H%M%S)" \
        || fail "No se pudo respaldar /etc/fstab."
}

write_ossec_fstab() {
    local uuid="$1"
    local fstype="$2"
    local existing

    existing="$(grep -E '^[[:space:]]*[^#[:space:]][^[:space:]]*[[:space:]]+/var/ossec[[:space:]]' /etc/fstab 2>/dev/null | head -n1 || true)"

    if [ -n "$existing" ]; then
        local current_device
        current_device="$(printf '%s\n' "$existing" | awk '{print $1}')"

        case "$current_device" in
            "UUID=$uuid")
                ;;
            *)
                fail "/var/ossec ya tiene una entrada distinta en /etc/fstab ($current_device). No se sobrescribe."
                ;;
        esac

        backup_fstab

        awk -v uuid="$uuid" -v fstype="$fstype" '
            $0 ~ /^[[:space:]]*[^#[:space:]][^[:space:]]*[[:space:]]+\/var\/ossec[[:space:]]/ {
                print "UUID=" uuid " /var/ossec " fstype " nodev,nosuid 1 2"
                next
            }
            { print }
        ' /etc/fstab > /etc/fstab.orangebox.tmp \
            || fail "No se pudo preparar /etc/fstab."

        mv /etc/fstab.orangebox.tmp /etc/fstab \
            || fail "No se pudo actualizar /etc/fstab."
    else
        backup_fstab
        printf 'UUID=%s /var/ossec %s nodev,nosuid 1 2\n' \
            "$uuid" "$fstype" >> /etc/fstab \
            || fail "No se pudo agregar /var/ossec a /etc/fstab."
    fi
}

prepare_ossec_storage() {
    [ "$IS_CPANEL" = "yes" ] && return 0
    has mountpoint || fail "mountpoint no está disponible."
    has mount || fail "mount no está disponible."
    has blkid || fail "blkid no está disponible."
    has mkfs.ext4 || fail "mkfs.ext4 no está disponible."

    if mountpoint -q /var/ossec 2>/dev/null; then
        if ossec_mount_ready; then
            ok "/var/ossec ya está montado con exec,nosuid,nodev."
            return 0
        fi

        local source uuid fstype
        source="$(ossec_mount_source)"
        [ -n "$source" ] \
            || fail "/var/ossec está montado pero no se pudo determinar el dispositivo."

        uuid="$(blkid -s UUID -o value "$source" 2>/dev/null || true)"
        fstype="$(blkid -s TYPE -o value "$source" 2>/dev/null || true)"
        [ -n "$uuid" ] && [ -n "$fstype" ] \
            || fail "No se pudo determinar UUID/filesystem de $source."

        echo "==> Corrigiendo opciones de montaje de /var/ossec..."
        mount -o remount,exec,nosuid,nodev /var/ossec \
            || fail "No se pudo remontar /var/ossec con exec,nosuid,nodev."

        ossec_mount_ready \
            || fail "/var/ossec no quedó con exec,nosuid,nodev."

        write_ossec_fstab "$uuid" "$fstype"
        ok "/var/ossec corregido: exec,nosuid,nodev."
        return 0
    fi

    if [ -L /var/ossec ]; then
        fail "/var/ossec es un enlace simbólico. No se modificará."
    fi

    ensure_lvm

    local backup_dir=""
    if [ -d /var/ossec ] && [ "$(ls -A /var/ossec 2>/dev/null)" ]; then
        backup_dir="/var/ossec.pre-lvm.$(date +%Y%m%d%H%M%S)"
        mv /var/ossec "$backup_dir" \
            || fail "No se pudo preservar el contenido existente de /var/ossec."
        ok "Contenido existente preservado en $backup_dir."
    elif [ -d /var/ossec ]; then
        rmdir /var/ossec 2>/dev/null || true
    fi

    mkdir -p /var/ossec || fail "No se pudo crear /var/ossec."

    local vg lv_device uuid fstype
    vg="$(find_ossec_vg)"

    if lvs --noheadings --options lv_name "$vg" 2>/dev/null |
        awk -v target="$WAZUH_OSSEC_LV" '$1 == target { found=1 } END { exit !found }'
    then
        ok "LV $WAZUH_OSSEC_LV ya existe en VG $vg; se reutilizará."
    else
        echo "==> Creando LV $WAZUH_OSSEC_LV de $WAZUH_OSSEC_SIZE en $vg..."
        lvcreate -n "$WAZUH_OSSEC_LV" -L "$WAZUH_OSSEC_SIZE" "$vg" \
            || fail "No se pudo crear el LV $WAZUH_OSSEC_LV."
    fi

    lv_device="/dev/$vg/$WAZUH_OSSEC_LV"
    [ -b "$lv_device" ] || fail "El dispositivo $lv_device no existe."

    fstype="$(blkid -s TYPE -o value "$lv_device" 2>/dev/null || true)"
    if [ -z "$fstype" ]; then
        echo "==> Creando filesystem ext4 en $lv_device..."
        mkfs.ext4 -F "$lv_device" >/dev/null 2>&1 \
            || fail "No se pudo crear el filesystem ext4 en $lv_device."
        fstype="ext4"
    fi

    uuid="$(blkid -s UUID -o value "$lv_device" 2>/dev/null || true)"
    [ -n "$uuid" ] || fail "No se pudo obtener UUID de $lv_device."

    write_ossec_fstab "$uuid" "$fstype"

    mount /var/ossec \
        || fail "No se pudo montar /var/ossec."

    ossec_mount_ready \
        || fail "/var/ossec no quedó montado con exec,nosuid,nodev."

    chmod 0755 /var/ossec

    if [ -n "$backup_dir" ]; then
        echo "==> Restaurando contenido previo de /var/ossec..."
        cp -a "$backup_dir"/. /var/ossec/ \
            || fail "No se pudo restaurar el contenido previo de /var/ossec."
        ok "Contenido previo restaurado desde $backup_dir."
    fi

    ok "/var/ossec montado en $lv_device con exec,nosuid,nodev."
}

detect_wazuh_agent_name() {
    # Respetar siempre un nombre explicitamente configurado.
    if [ -n "$WAZUH_AGENT_NAME" ]; then
        printf '%s\n' "$WAZUH_AGENT_NAME"
        return 0
    fi

    local candidate=""
    local short_hostname=""

    short_hostname="$(hostname 2>/dev/null || true)"

    # Primero usar hostname -f cuando el sistema ya puede resolver el FQDN.
    candidate="$(hostname -f 2>/dev/null || true)"
    case "$candidate" in
        *.*)
            case "$candidate" in
                localhost|localhost.*|*.localhost) ;;
                *[!0-9.]*)
                    printf '%s\n' "$candidate"
                    return 0
                    ;;
            esac
            ;;
    esac

    # Algunos servidores mantienen hostname corto pero hostname -A conoce
    # correctamente el FQDN (caso habitual con /etc/hosts/DNS).
    candidate="$(hostname -A 2>/dev/null | awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /\./ && $i !~ /^[0-9.]+$/ &&
                    $i !~ /^localhost([.]|$)/) {
                    print $i
                    exit
                }
            }
        }' || true)"

    case "$candidate" in
        *.*)
            printf '%s\n' "$candidate"
            return 0
            ;;
    esac

    [ -n "$short_hostname" ] && printf '%s\n' "$short_hostname"
}

install_agent() {
    AGENT_NAME=""
    MANAGER="$WAZUH_MANAGER"
    GROUP="$WAZUH_AGENT_GROUP"
    PASSWORD="$WAZUH_REGISTRATION_PASSWORD"

    AGENT_NAME="$(detect_wazuh_agent_name)"
    [ -n "$AGENT_NAME" ] || fail "No se pudo determinar un nombre para el agente Wazuh."

    echo
    echo "=== DATOS DE ENROLAMIENTO ==="
    echo "Nombre : $AGENT_NAME"
    echo "Manager: $MANAGER"
    echo "Grupo base: default"

    read -r -p "Grupos adicionales (coma separados, Enter = ninguno): " ADDITIONAL_GROUPS

    if [ -n "$ADDITIONAL_GROUPS" ]; then
        ADDITIONAL_GROUPS="$(printf '%s' "$ADDITIONAL_GROUPS" | tr -d '[:space:]')"
        GROUP="default,$ADDITIONAL_GROUPS"
    else
        GROUP="default"
    fi

    echo "Grupos : $GROUP"
    echo "Tipo   : $([ "$IS_CPANEL" = "yes" ] && echo "cPanel / RPM OPT" || echo "Linux normal")"

    if ! yesno "¿Los datos están correctos?"; then
        read -r -p "Nombre [$AGENT_NAME]: " v; [ -n "$v" ] && AGENT_NAME="$v"
        read -r -p "Manager [$MANAGER]: " v; [ -n "$v" ] && MANAGER="$v"
    fi
    if [ -z "$PASSWORD" ]; then read -r -s -p "Password de enrolamiento: " PASSWORD; echo; fi
    [ -n "$PASSWORD" ] || fail "La password de enrolamiento está vacía."

    echo "=== CONFIRMACIÓN ==="
    echo "Nombre : $AGENT_NAME"
    echo "Manager: $MANAGER"
    echo "Grupo  : $GROUP"
    echo "Wazuh  : $WAZUH_HOME"
    echo "Password: [oculta]"
    yesno "¿Proceder?" || fail "Instalación cancelada."

    if [ "$IS_CPANEL" = "yes" ]; then
        local rpm_file="$SCRIPT_DIR/wazuh-agent_${WAZUH_VERSION}-0_x86_64_OPT.rpm"
        [ -n "$WAZUH_AGENT_RPM" ] && rpm_file="$WAZUH_AGENT_RPM"
        [ -f "$rpm_file" ] || fail "No existe el RPM OPT: $rpm_file"
        WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_GROUP="$GROUP" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_REGISTRATION_PASSWORD="$PASSWORD" \
            rpm -ihv "$rpm_file" || fail "Falló la instalación del RPM Wazuh Agent OPT."
    else
        prepare_ossec_storage
        local rpm_file="wazuh-agent-$WAZUH_VERSION-1.x86_64.rpm"
        local url="https://packages.wazuh.com/4.x/yum/$rpm_file"
        has curl || fail "curl no está instalado."
        curl -fL -o "/tmp/$rpm_file" "$url" || fail "Falló la descarga."
        WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_GROUP="$GROUP" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_REGISTRATION_PASSWORD="$PASSWORD" \
            rpm -ihv "/tmp/$rpm_file" || fail "Falló la instalación de wazuh-agent."
        rm -f "/tmp/$rpm_file"
    fi

    agent_installed || fail "Wazuh Agent no quedó instalado."
    [ -f "$WAZUH_HOME/etc/ossec.conf" ] || fail "No existe $WAZUH_HOME/etc/ossec.conf."
    ok "Wazuh Agent disponible en $WAZUH_HOME: $(agent_version)"
}
restart_agent() {
    if has systemctl; then
        systemctl enable --now wazuh-agent || fail "No se pudo habilitar/iniciar wazuh-agent."
        systemctl is-active --quiet wazuh-agent || fail "wazuh-agent no está activo."

        if [ "$IS_CPANEL" != "yes" ] && systemctl is-enabled orangebox-iptables.service >/dev/null 2>&1; then
            systemctl start orangebox-iptables.service || fail "No se pudo iniciar orangebox-iptables.service."
            systemctl is-active --quiet orangebox-iptables.service || fail "orangebox-iptables.service no está activo."
        fi
    else
        chkconfig wazuh-agent on >/dev/null 2>&1 || true
        service wazuh-agent restart || fail "No se pudo reiniciar wazuh-agent."
        service wazuh-agent status >/dev/null 2>&1 || fail "No se pudo validar wazuh-agent."
    fi
    ok "wazuh-agent activo."
}

# ---------------------------------------------------------------------------
# 2. Firewall: Shorewall > firewalld > iptables
# ---------------------------------------------------------------------------

shorewall_installed() {
    has shorewall || (has rpm && rpm -q shorewall >/dev/null 2>&1)
}

configure_shorewall() {
    local rules_file="/etc/shorewall/rules"
    local started_file="/etc/shorewall/started"
    local changed=0

    has shorewall || fail "Shorewall está instalado pero el comando shorewall no existe."
    [ -f "$rules_file" ] || fail "Shorewall está instalado pero no existe $rules_file."

    detect_orangebox_ips

    # Shorewall 5.2.x permite cargar reglas propias después de crear la
    # infraestructura del firewall mediante /etc/shorewall/started.
    # Mantenemos ORANGEBOX-FW como una cadena iptables real y no usamos
    # Actions, para no depender de la sintaxis de Actions de cada versión.
    if [ -f "$started_file" ] &&
       grep -Fq "# BEGIN ORANGEBOX WAZUH FIREWALL" "$started_file"; then
        ok "Bloque ORANGEBOX-FW ya existe en $started_file; no se duplica."
    else
        if [ -f "$started_file" ]; then
            cp -p "$started_file" \
                "$started_file.orangebox-backup.$(date +%Y%m%d%H%M%S)" \
                || fail "No se pudo respaldar $started_file."
        else
            mkdir -p "$(dirname "$started_file")" || fail "No se pudo crear el directorio de Shorewall."
            : > "$started_file" || fail "No se pudo crear $started_file."
        fi

        cat >> "$started_file" <<'ORANGEBOX_START'

# BEGIN ORANGEBOX WAZUH FIREWALL
# OrangeBox - Wazuh firewall logging
# Se ejecuta después de que Shorewall haya creado el firewall.
IPTABLES="$(command -v iptables 2>/dev/null || true)"
if [ -n "$IPTABLES" ]; then
    "$IPTABLES" -N ORANGEBOX-FW 2>/dev/null || true
    "$IPTABLES" -F ORANGEBOX-FW 2>/dev/null || true

    ORANGEBOX_PRIVATE_IP="$(ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')"
    ORANGEBOX_PUBLIC_IP="$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"

    if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
        "$IPTABLES" -A ORANGEBOX-FW ! -i lo -p tcp --syn \
            -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || true
    fi

    "$IPTABLES" -A ORANGEBOX-FW ! -i lo -p tcp --syn \
        -m limit --limit 20/second --limit-burst 40 \
        -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4 || true
    "$IPTABLES" -A ORANGEBOX-FW -j RETURN || true

    if ! "$IPTABLES" -L INPUT -n 2>/dev/null |
        awk '$2=="ORANGEBOX-FW"{found=1} END{exit !found}'; then
        "$IPTABLES" -I INPUT 1 \
            -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 \
            -j ORANGEBOX-FW || true
    fi
fi
# END ORANGEBOX WAZUH FIREWALL
ORANGEBOX_START
        chmod 755 "$started_file" || fail "No se pudieron establecer permisos en $started_file."
        changed=1
        ok "Bloque ORANGEBOX-FW agregado a $started_file."
    fi

    # Migrar la regla OrangeBox anterior de /etc/shorewall/rules. La cadena
    # ahora vive en started; no dejamos dos mecanismos de logging activos.
    local tmp_rules="${rules_file}.orangebox.tmp"
    awk '
        /^[[:space:]]*LOG:info:ORANGEBOX-FW[[:space:]]+all-[[:space:]]+\$FW[[:space:]]+tcp[[:space:]]/ { next }
        { print }
    ' "$rules_file" > "$tmp_rules" || fail "No se pudo preparar $rules_file."

    if ! cmp -s "$tmp_rules" "$rules_file"; then
        cp -p "$rules_file" \
            "$rules_file.orangebox-backup.$(date +%Y%m%d%H%M%S)" \
            || fail "No se pudo respaldar $rules_file."
        mv "$tmp_rules" "$rules_file" || fail "No se pudo actualizar $rules_file."
        changed=1
        ok "Regla OrangeBox antigua retirada de $rules_file."
    else
        rm -f "$tmp_rules"
    fi

    shorewall check >/dev/null 2>&1 \
        || fail "Shorewall rechazó la configuración OrangeBox."

    if [ "$changed" -eq 1 ]; then
        if has service && service shorewall status >/dev/null 2>&1; then
            shorewall restart >/dev/null 2>&1 \
                || fail "Se actualizó Shorewall, pero no se pudo reiniciar."
        elif has systemctl && systemctl is-active --quiet shorewall 2>/dev/null; then
            shorewall restart >/dev/null 2>&1 \
                || fail "Se actualizó Shorewall, pero no se pudo reiniciar."
        else
            warn "Shorewall está instalado pero no activo; la configuración quedó persistente."
        fi
    fi

    if [ "$changed" -eq 1 ]; then
        if ! iptables -L ORANGEBOX-FW -n >/dev/null 2>&1; then
            fail "Shorewall se reinició, pero la cadena ORANGEBOX-FW no quedó creada."
        fi
        if ! iptables -L ORANGEBOX-FW -n 2>/dev/null | grep -Fq "ORANGEBOX-FW"; then
            fail "La cadena ORANGEBOX-FW no contiene la regla LOG esperada."
        fi
        if ! iptables -L INPUT -n 2>/dev/null | grep -Fq "ORANGEBOX-FW"; then
            fail "INPUT no quedó conectado a ORANGEBOX-FW."
        fi
    fi

    ok "Shorewall OrangeBox configurado mediante /etc/shorewall/started: public=${ORANGEBOX_PUBLIC_IP:-desconocida}, private=${ORANGEBOX_PRIVATE_IP:-desconocida}."
}
# iptables -C no es suficientemente portable para todas las versiones antiguas
# soportadas (especialmente EL6). La detección se hace sobre iptables -L.
iptables_input_rule_exists() {
    iptables -L INPUT -n 2>/dev/null |
        grep -F 'ORANGEBOX-FW' >/dev/null 2>&1
}

iptables_chain_exists() {
    iptables -L ORANGEBOX-FW -n >/dev/null 2>&1
}

iptables_log_rule_exists() {
    iptables -L ORANGEBOX-FW -n 2>/dev/null |
        grep -F 'LOG' |
        grep -F 'ORANGEBOX-FW' >/dev/null 2>&1
}

iptables_return_rule_exists() {
    iptables -L ORANGEBOX-FW -n 2>/dev/null |
        grep -F 'RETURN' >/dev/null 2>&1
}

configure_wazuh_agent_firewall_service() {
    if ! has systemctl; then
        warn "systemctl no está disponible; no se instalará orangebox-iptables.service."
        return 1
    fi

    # Retirar el antiguo drop-in de ExecStartPre creado por versiones anteriores.
    # Solo se elimina si contiene exactamente nuestro hook anterior.
    local legacy_dropin="/etc/systemd/system/wazuh-agent.service.d/20-orangebox-firewall.conf"
    if [ -f "$legacy_dropin" ] && grep -Fxq 'ExecStartPre=-/var/ossec/bin/orangebox-iptables' "$legacy_dropin" 2>/dev/null; then
        rm -f "$legacy_dropin" || {
            step_error "No se pudo retirar el antiguo drop-in OrangeBox de wazuh-agent."
            return 1
        }
        rmdir "$(dirname "$legacy_dropin")" 2>/dev/null || true
        ok "Antiguo hook ExecStartPre OrangeBox retirado."
    fi
    systemctl cat wazuh-agent.service >/dev/null 2>&1 || {
        step_error "El servicio wazuh-agent.service no existe; no se pudo crear la dependencia del firewall."
        return 1
    }

    mkdir -p "$(dirname "$WAZUH_FIREWALL_HELPER")" || {
        step_error "No se pudo crear el directorio de los helpers del firewall."
        return 1
    }

    cat > "$WAZUH_FIREWALL_HELPER" <<'EOF'
#!/bin/bash
# OrangeBox - carga únicamente las reglas de firewall administradas por OrangeBox.
set -u
IPTABLES="$(command -v iptables 2>/dev/null || true)"
[ -n "$IPTABLES" ] || exit 0

chain_exists() {
    "$IPTABLES" -L ORANGEBOX-FW -n >/dev/null 2>&1
}

log_rule_exists() {
    "$IPTABLES" -L ORANGEBOX-FW -n 2>/dev/null |
        awk '$1 == "LOG" && /ORANGEBOX-FW/ { found=1 } END { exit !found }'
}

return_rule_exists() {
    "$IPTABLES" -L ORANGEBOX-FW -n 2>/dev/null |
        awk '$1 == "RETURN" { found=1 } END { exit !found }'
}

input_rule_exists() {
    "$IPTABLES" -L INPUT -n 2>/dev/null |
        awk '$1 == "ORANGEBOX-FW" { found=1 } END { exit !found }'
}

chain_exists || "$IPTABLES" -N ORANGEBOX-FW || exit 1
"$IPTABLES" -F ORANGEBOX-FW || exit 1
PRIVATE_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' || true)"
PUBLIC_IP="$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
if [ -n "$PUBLIC_IP" ] && [ -n "$PRIVATE_IP" ]; then
    "$IPTABLES" -A ORANGEBOX-FW ! -i lo -p tcp --syn -s "$PUBLIC_IP" -d "$PRIVATE_IP" -j RETURN || exit 1
fi
"$IPTABLES" -A ORANGEBOX-FW -m limit --limit 20/second --limit-burst 40 -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4 || exit 1
"$IPTABLES" -A ORANGEBOX-FW -j RETURN || exit 1
input_rule_exists || "$IPTABLES" -I INPUT 1 \
    -p tcp --tcp-flags SYN SYN \
    ! -s 127.0.0.0/8 \
    -j ORANGEBOX-FW || exit 1

chain_exists || exit 1
log_rule_exists || exit 1
return_rule_exists || exit 1
input_rule_exists || exit 1
exit 0
EOF

    cat > "$WAZUH_FIREWALL_STOP_HELPER" <<'EOF'
#!/bin/bash
# OrangeBox - retira únicamente las reglas administradas por OrangeBox.
set -u
IPTABLES="$(command -v iptables 2>/dev/null || true)"
[ -n "$IPTABLES" ] || exit 0

while true; do
    rule_no="$("$IPTABLES" -L INPUT -n --line-numbers 2>/dev/null |
        awk '$2 == "ORANGEBOX-FW" { print $1; exit }')"
    [ -n "$rule_no" ] || break
    "$IPTABLES" -D INPUT "$rule_no" || exit 1
done

if "$IPTABLES" -L ORANGEBOX-FW -n >/dev/null 2>&1; then
    while true; do
        rule_no="$("$IPTABLES" -L ORANGEBOX-FW -n --line-numbers 2>/dev/null |
            awk '$2 == "LOG" && /ORANGEBOX-FW/ { print $1; exit }
                 $2 == "RETURN" { print $1; exit }')"
        [ -n "$rule_no" ] || break
        "$IPTABLES" -D ORANGEBOX-FW "$rule_no" || exit 1
    done

    # Si quedaron reglas ajenas dentro de la cadena, no la eliminamos.
    if [ -z "$("$IPTABLES" -L ORANGEBOX-FW -n 2>/dev/null | tail -n +3)" ]; then
        "$IPTABLES" -X ORANGEBOX-FW || exit 1
    fi
fi

exit 0
EOF
    chmod 755 "$WAZUH_FIREWALL_HELPER" "$WAZUH_FIREWALL_STOP_HELPER" || {
        step_error "No se pudieron hacer ejecutables los helpers de iptables."
        return 1
    }

    cat > "$WAZUH_FIREWALL_SERVICE" <<'EOF'
[Unit]
Description=OrangeBox iptables rules for Wazuh Agent
Requires=wazuh-agent.service
After=wazuh-agent.service
PartOf=wazuh-agent.service
BindsTo=wazuh-agent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$WAZUH_FIREWALL_HELPER
ExecStop=/var/ossec/bin/orangebox-iptables-stop

[Install]
WantedBy=wazuh-agent.service
EOF
    chmod 644 "$WAZUH_FIREWALL_SERVICE" || {
        step_error "No se pudieron establecer permisos en $WAZUH_FIREWALL_SERVICE."
        return 1
    }

    systemctl daemon-reload || {
        step_error "systemctl daemon-reload falló al instalar orangebox-iptables.service."
        return 1
    }

    systemctl enable orangebox-iptables.service >/dev/null 2>&1 || {
        step_error "No se pudo habilitar orangebox-iptables.service como dependencia de wazuh-agent."
        return 1
    }

    "$WAZUH_FIREWALL_HELPER" || {
        step_error "No se pudieron cargar/validar las reglas OrangeBox de iptables."
        return 1
    }

    ok "orangebox-iptables.service configurado para cargar reglas al iniciar Wazuh y retirarlas al detenerlo."
    return 0
}
detect_orangebox_ips() {
    local detected_private=""
    local detected_public=""
    detected_private="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' || true)"
    if [ -z "$detected_private" ]; then
        detected_private="$(ip -4 route show default 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' || true)"
    fi
    if has curl; then
        detected_public="$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
    fi
    ORANGEBOX_PRIVATE_IP="${ORANGEBOX_PRIVATE_IP:-$detected_private}"
    ORANGEBOX_PUBLIC_IP="${ORANGEBOX_PUBLIC_IP:-$detected_public}"
    [ -n "$ORANGEBOX_PRIVATE_IP" ] || warn "No se pudo autodetectar la IP privada."
    [ -n "$ORANGEBOX_PUBLIC_IP" ] || warn "No se pudo autodetectar la IP publica."
    if [ -n "$ORANGEBOX_PRIVATE_IP" ] || [ -n "$ORANGEBOX_PUBLIC_IP" ]; then
        ok "IPs detectadas: privada=${ORANGEBOX_PRIVATE_IP:-desconocida}, publica=${ORANGEBOX_PUBLIC_IP:-desconocida}."
    fi
}
configure_iptables() {
    if ! has iptables; then
        step_error "iptables no está instalado."
        return 1
    fi

    local failed=0
    detect_orangebox_ips

    if iptables_chain_exists; then
        ok "Cadena ORANGEBOX-FW ya existe; no se crea otra."
    else
        echo "==> Creando cadena ORANGEBOX-FW..."
        if iptables -N ORANGEBOX-FW; then
            ok "Cadena ORANGEBOX-FW creada."
        else
            step_error "No se pudo crear la cadena ORANGEBOX-FW."
            return 1
        fi
    fi

    if iptables_chain_exists; then
        ok "Validación: cadena ORANGEBOX-FW existe."
    else
        step_error "Validación fallida: la cadena ORANGEBOX-FW no existe."
        return 1
    fi

    if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
        if iptables -L ORANGEBOX-FW -n 2>/dev/null | grep -Fq "$ORANGEBOX_PUBLIC_IP" &&            iptables -L ORANGEBOX-FW -n 2>/dev/null | grep -Fq "$ORANGEBOX_PRIVATE_IP"; then
            ok "Exclusión de la IP pública propia ($ORANGEBOX_PUBLIC_IP -> $ORANGEBOX_PRIVATE_IP) ya existe."
        elif iptables -I ORANGEBOX-FW 1 ! -i lo -p tcp --syn -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN; then
            ok "Exclusión de la IP pública propia ($ORANGEBOX_PUBLIC_IP -> $ORANGEBOX_PRIVATE_IP) configurada."
        else
            step_error "No se pudo configurar la exclusión de la IP pública propia."
            failed=1
        fi
    fi

    if iptables_log_rule_exists; then
        ok "Regla LOG ORANGEBOX-FW ya existe; no se agrega otra."
    else
        echo "==> Agregando LOG a ORANGEBOX-FW..."
        if iptables -A ORANGEBOX-FW \
            -m limit --limit 20/second --limit-burst 40 \
            -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4; then
            if iptables_log_rule_exists; then
                ok "Validación: regla LOG ORANGEBOX-FW instalada."
            else
                step_error "La regla LOG fue agregada pero no pudo validarse."
                failed=1
            fi
        else
            step_error "No se pudo agregar la regla LOG ORANGEBOX-FW."
            failed=1
        fi
    fi

    if iptables_return_rule_exists; then
        ok "RETURN de ORANGEBOX-FW ya existe; no se agrega otro."
    else
        echo "==> Agregando RETURN a ORANGEBOX-FW..."
        if iptables -A ORANGEBOX-FW -j RETURN; then
            if iptables_return_rule_exists; then
                ok "Validación: RETURN de ORANGEBOX-FW instalado."
            else
                step_error "La regla RETURN fue agregada pero no pudo validarse."
                failed=1
            fi
        else
            step_error "No se pudo agregar RETURN a ORANGEBOX-FW."
            failed=1
        fi
    fi

    if iptables_input_rule_exists; then
        ok "Regla INPUT -> ORANGEBOX-FW ya existe; no se agrega otra."
    else
        echo "==> Conectando INPUT con ORANGEBOX-FW..."
        if iptables -I INPUT 1 \
            -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 \
            -j ORANGEBOX-FW; then
            if iptables_input_rule_exists; then
                ok "Validación: regla INPUT -> ORANGEBOX-FW instalada."
            else
                step_error "La regla INPUT -> ORANGEBOX-FW fue agregada pero no pudo validarse."
                failed=1
            fi
        else
            step_error "No se pudo conectar INPUT con ORANGEBOX-FW."
            failed=1
        fi
    fi

    if iptables_chain_exists; then
        ok "Validación final: cadena ORANGEBOX-FW presente."
    else
        step_error "Validación final fallida: cadena ORANGEBOX-FW ausente."
        failed=1
    fi

    if iptables_log_rule_exists; then
        ok "Validación final: regla LOG presente."
    else
        step_error "Validación final fallida: regla LOG ausente."
        failed=1
    fi

    if iptables_return_rule_exists; then
        ok "Validación final: regla RETURN presente."
    else
        step_error "Validación final fallida: regla RETURN ausente."
        failed=1
    fi

    if iptables_input_rule_exists; then
        ok "Validación final: regla INPUT presente."
    else
        step_error "Validación final fallida: regla INPUT -> ORANGEBOX-FW ausente."
        failed=1
    fi

    if [ "$EL_MAJOR" -ge 7 ] 2>/dev/null; then
        if configure_wazuh_agent_firewall_service; then
            ok "Persistencia del firewall mediante orangebox-iptables.service configurada."
        else
            failed=1
        fi
    elif [ -f /etc/sysconfig/iptables ]; then
        if has service && service iptables save >/dev/null 2>&1; then
            ok "Configuración iptables persistida para EL6."
        elif iptables-save > /etc/sysconfig/iptables; then
            ok "Configuración iptables persistida mediante iptables-save."
        else
            step_error "No se pudo persistir la configuración iptables en /etc/sysconfig/iptables."
            failed=1
        fi
    else
        warn "No existe /etc/sysconfig/iptables en EL6; no se fuerza persistencia."
    fi

    if [ "$failed" -eq 0 ]; then
        ok "Configuración ORANGEBOX-FW de iptables validada."
        return 0
    fi

    step_error "Configuración ORANGEBOX-FW de iptables terminó con uno o más errores; se continuará con los demás pasos."
    return 1
}

configure_firewalld() {
    has firewall-cmd || fail "firewalld está activo pero firewall-cmd no existe."
    detect_orangebox_ips
    if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
        if ! firewall-cmd --direct --query-rule ipv4 filter INPUT 0 -p tcp --tcp-flags SYN SYN -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1; then
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -p tcp --tcp-flags SYN SYN -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || fail "No se pudo agregar la exclusión de la IP pública propia a firewalld."
        fi
    fi

    # firewall-cmd --direct --add-rule recibe los argumentos de iptables
    # como argumentos separados. No se debe pasar toda la regla como una
    # única cadena entre comillas: firewalld terminará entregándola a
    # iptables-restore como un solo argumento y la regla será inválida.
    # Se pasan directamente como argumentos para mantener compatibilidad
    # incluso cuando el instalador se invoque mediante "sh script.sh".
    if firewall-cmd --direct --query-rule ipv4 filter INPUT 0 \
        -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 \
        -m limit --limit 20/second --limit-burst 40 \
        -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4 >/dev/null 2>&1; then
        ok "Regla ORANGEBOX-FW ya existe en firewalld."
    else
        echo "==> Agregando regla ORANGEBOX-FW a firewalld..."
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
            -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 \
            -m limit --limit 20/second --limit-burst 40 \
            -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4 \
            || fail "No se pudo agregar la regla a firewalld."
        firewall-cmd --reload || fail "No se pudo recargar firewalld."
        firewall-cmd --direct --query-rule ipv4 filter INPUT 0 \
            -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 \
            -m limit --limit 20/second --limit-burst 40 \
            -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4 >/dev/null 2>&1 \
            || fail "No se pudo validar la regla firewalld."
        ok "Regla ORANGEBOX-FW instalada en firewalld."
    fi
}

configure_cpanel_firewall() {
    local csf_conf="/etc/csf/csf.conf"
    local csf_post="/usr/local/csf/bin/csfpost.sh"

    # cPanel no implica necesariamente CSF. Preferir CSF si está realmente
    # instalado y operativo; de lo contrario usar firewalld o iptables.
    if [ -f "$csf_conf" ] && [ -f "$csf_post" ] && has csf; then
        echo "==> cPanel detectado: usando CSF."

        has iptables || {
            step_error "CSF está instalado pero iptables no está disponible."
            return 1
        }

        csf_tcp_out_has_port() {
            local port="$1"
            awk -v p="$port" '
                /^[[:space:]]*TCP_OUT[[:space:]]*=/ {
                    line=$0; sub(/#.*/, "", line)
                    if (line ~ "(^|[,[:space:]\"])" p "([,:\"]|$)") found=1
                }
                END { exit !found }
            ' "$csf_conf"
        }

        if csf_tcp_out_has_port 1514 && csf_tcp_out_has_port 1515; then
            ok "CSF TCP_OUT ya contiene 1514 y 1515."
        else
            cp -p "$csf_conf" "$csf_conf.orangebox-backup.$(date +%Y%m%d%H%M%S)" || fail "No se pudo respaldar $csf_conf."
            awk '
                /^[[:space:]]*TCP_OUT[[:space:]]*=/ && $0 !~ /^[[:space:]]*#/ {
                    line=$0
                    if (line !~ /1514([,:\"]|$)/) sub(/"$/, ",1514\"", line)
                    if (line !~ /1515([,:\"]|$)/) sub(/"$/, ",1515\"", line)
                    print line; next
                }
                { print }
            ' "$csf_conf" > "$csf_conf.orangebox.tmp" || fail "No se pudo preparar $csf_conf."
            mv "$csf_conf.orangebox.tmp" "$csf_conf" || fail "No se pudo actualizar $csf_conf."
            csf_tcp_out_has_port 1514 || fail "No se pudo validar TCP_OUT=1514."
            csf_tcp_out_has_port 1515 || fail "No se pudo validar TCP_OUT=1515."
            ok "CSF TCP_OUT actualizado con 1514,1515."
        fi

        detect_orangebox_ips
        local public_ip="$ORANGEBOX_PUBLIC_IP"
        local private_ip="$ORANGEBOX_PRIVATE_IP"

        local firewall="/usr/local/sbin/orangebox-firewall"
        cat > "$firewall" <<EOF
#!/bin/bash
set -u
IPTABLES=/usr/sbin/iptables
PUBLIC_IP="$public_ip"
PRIVATE_IP="$private_ip"
\$IPTABLES -N ORANGEBOX-FW 2>/dev/null || true
\$IPTABLES -F ORANGEBOX-FW
if [ -n "\$PUBLIC_IP" ] && [ -n "\$PRIVATE_IP" ]; then
    \$IPTABLES -A ORANGEBOX-FW ! -i lo -p tcp --syn -s "\$PUBLIC_IP" -d "\$PRIVATE_IP" -j RETURN
fi
\$IPTABLES -A ORANGEBOX-FW ! -i lo -p tcp --syn -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4
\$IPTABLES -A ORANGEBOX-FW -j RETURN
if ! \$IPTABLES -L INPUT -n 2>/dev/null | awk '\$2 == "ORANGEBOX-FW" { found=1 } END { exit !found }'; then
    \$IPTABLES -I INPUT 1 \
        -p tcp --tcp-flags SYN SYN \
        ! -s 127.0.0.0/8 \
        -j ORANGEBOX-FW || exit 1
fi
EOF
        chmod 700 "$firewall" || fail "No se pudieron establecer permisos en $firewall."

        if ! grep -Fqx "$firewall" "$csf_post" 2>/dev/null; then
            cp -p "$csf_post" "$csf_post.orangebox-backup.$(date +%Y%m%d%H%M%S)" || fail "No se pudo respaldar $csf_post."
            { cat "$csf_post"; echo; echo "# OrangeBox - Wazuh firewall logging"; echo "$firewall"; } > "$csf_post.orangebox.tmp" || fail "No se pudo preparar $csf_post."
            chmod --reference="$csf_post" "$csf_post.orangebox.tmp" 2>/dev/null || chmod 700 "$csf_post.orangebox.tmp"
            chown --reference="$csf_post" "$csf_post.orangebox.tmp" 2>/dev/null || true
            mv "$csf_post.orangebox.tmp" "$csf_post" || fail "No se pudo actualizar $csf_post."
            ok "Hook ORANGEBOX-FW agregado a $csf_post."
        else
            ok "Hook ORANGEBOX-FW ya existe en $csf_post."
        fi

        local csf_reload_log="/tmp/orangebox-csf-reload.log"
        if csf -r >"$csf_reload_log" 2>&1; then
            :
        else
            echo "ERROR: CSF rechazó la configuración. Última salida de csf -r:" >&2
            tail -n 40 "$csf_reload_log" >&2 2>/dev/null || cat "$csf_reload_log" >&2
            rm -f "$csf_reload_log"
            return 1
        fi
        rm -f "$csf_reload_log"

        "$firewall" || fail "No se pudieron cargar las reglas ORANGEBOX-FW."
        iptables -L ORANGEBOX-FW -n >/dev/null 2>&1 || fail "No existe ORANGEBOX-FW."
        iptables -L INPUT -n 2>/dev/null | grep -Fq "ORANGEBOX-FW" || fail "INPUT no quedó conectado a ORANGEBOX-FW."
        csf_tcp_out_has_port 1514 || fail "TCP_OUT no contiene 1514."
        csf_tcp_out_has_port 1515 || fail "TCP_OUT no contiene 1515."
        ok "CSF recargado y ORANGEBOX-FW validado."
        return 0
    fi

    warn "cPanel detectado, pero CSF no está instalado/operativo."
    if has firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        ok "Usando firewalld como backend de firewall para cPanel."
        configure_firewalld
        return $?
    fi

    if ! has iptables; then
        echo "==> No hay CSF, firewalld ni iptables; instalando iptables..."
        if has dnf; then
            dnf install -y iptables iptables-nft || {
                step_error "No se pudo instalar iptables."
                return 1
            }
        elif has yum; then
            yum install -y iptables || {
                step_error "No se pudo instalar iptables."
                return 1
            }
        else
            step_error "No existe dnf ni yum para instalar iptables."
            return 1
        fi
    fi

    has iptables || {
        step_error "iptables no quedó disponible después de la instalación."
        return 1
    }

    ok "Usando iptables como backend de firewall para cPanel."
    configure_iptables
    return $?
}

configure_firewall() {
    if [ "$IS_CPANEL" = "yes" ]; then
        configure_cpanel_firewall
        return $?
    fi
    if shorewall_installed; then
        ok "Shorewall instalado; usando configuración persistente de Shorewall."
        (configure_shorewall) || step_error "El paso Shorewall falló; se continuará con logging."
    elif has firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        ok "firewalld activo."
        (configure_firewalld) || step_error "El paso firewalld falló; se continuará con logging."
    else
        ok "Shorewall no instalado y firewalld no activo; usando iptables."
        configure_iptables || true
    fi
}

# ---------------------------------------------------------------------------
# 3. Logging EL6: rsyslog
# ---------------------------------------------------------------------------

rsyslog_rule_exists() {
    [ -f "$RSYSLOG_FILE" ] &&     grep -Fq ':msg, contains, "ORANGEBOX-FW" -/var/log/orangebox-firewall.log' "$RSYSLOG_FILE" &&     grep -Fxq ':msg, contains, "ORANGEBOX-FW" ~' "$RSYSLOG_FILE" && \
    grep -Fq ':msg, contains, "LOG:ORANGEB" -/var/log/orangebox-firewall.log' "$RSYSLOG_FILE" && \
    grep -Fxq ':msg, contains, "LOG:ORANGEB" ~' "$RSYSLOG_FILE"
}

remove_legacy_rsyslog_rule() {
    [ -f /etc/rsyslog.conf ] || return 1

    if grep -Fq ':msg, contains, "ORANGEBOX-FW" -/var/log/orangebox-firewall.log' /etc/rsyslog.conf; then
        cp -p /etc/rsyslog.conf             "/etc/rsyslog.conf.orangebox-backup.$(date +%Y%m%d%H%M%S)"             || fail "No se pudo respaldar rsyslog.conf."

        awk '
            $0 == ":msg, contains, \"ORANGEBOX-FW\" -/var/log/orangebox-firewall.log" {
                skip_next = 1
                next
            }
            skip_next && ($0 == "stop" || $0 == "~") {
                skip_next = 0
                next
            }
            {
                skip_next = 0
                print
            }
        ' /etc/rsyslog.conf > /etc/rsyslog.conf.orangebox.tmp             || fail "No se pudo limpiar la regla OrangeBox antigua de rsyslog.conf."

        mv /etc/rsyslog.conf.orangebox.tmp /etc/rsyslog.conf             || fail "No se pudo actualizar rsyslog.conf."

        ok "Regla OrangeBox antigua removida de rsyslog.conf."
        return 0
    fi

    return 1
}

configure_rsyslog() {
    has rsyslogd || fail "rsyslogd no está instalado."
    has logger || fail "logger no está instalado."

    if [ -f "$FIREWALL_LOG" ]; then
        chmod 640 "$FIREWALL_LOG"
        chown root:root "$FIREWALL_LOG"
    else
        touch "$FIREWALL_LOG"
        chmod 640 "$FIREWALL_LOG"
        chown root:root "$FIREWALL_LOG"
    fi

    local rsyslog_changed=0

    if remove_legacy_rsyslog_rule; then
        rsyslog_changed=1
    fi

    if [ -f "$RSYSLOG_FILE" ]; then
        if rsyslog_rule_exists; then
            ok "Configuración rsyslog OrangeBox ya existe; no se modifica."
        else
            fail "$RSYSLOG_FILE existe pero no contiene la configuración OrangeBox esperada. No se sobrescribe."
        fi
    else
        cat > "$RSYSLOG_FILE" <<'EOF'
# OrangeBox - Wazuh firewall logging
:msg, contains, "ORANGEBOX-FW" -/var/log/orangebox-firewall.log
:msg, contains, "ORANGEBOX-FW" ~
:msg, contains, "LOG:ORANGEB" -/var/log/orangebox-firewall.log
:msg, contains, "LOG:ORANGEB" ~
EOF
        chmod 644 "$RSYSLOG_FILE"
        rsyslog_changed=1
        ok "Configuración rsyslog OrangeBox creada en /etc/rsyslog.d/."
    fi

    rsyslog_rule_exists || fail "No se pudo validar la configuración rsyslog OrangeBox."
    rsyslogd -N1 >/dev/null 2>&1 || fail "rsyslogd rechazó la configuración."

    if [ "$rsyslog_changed" -eq 1 ]; then
        if has systemctl; then
            systemctl restart rsyslog || fail "No se pudo reiniciar rsyslog."
        else
            service rsyslog restart || fail "No se pudo reiniciar rsyslog."
        fi
    fi

    local marker="ORANGEBOX-RSYSLOG-TEST-$(date +%s)"
    logger -p kern.info "$marker ORANGEBOX-FW: test"
    sleep 1

    grep -Fq "$marker" "$FIREWALL_LOG" || fail "El test rsyslog no llegó al log dedicado."
    grep -Fq "$marker" /var/log/messages && fail "El test rsyslog también llegó a messages."

    ok "rsyslog validado para EL6."
}

# ---------------------------------------------------------------------------
# 4. Logging EL7+: journald
# ---------------------------------------------------------------------------

configure_journald() {
    has journalctl || fail "journalctl no está disponible; no se puede usar journald."
    has logger || fail "logger no está disponible para validar journald."

    journalctl -n 1 --no-pager >/dev/null 2>&1 \
        || fail "No se pudo consultar journald."

    local marker="ORANGEBOX-JOURNALD-TEST-$(date +%s)"
    logger -p kern.info -t kernel "$marker ORANGEBOX-FW: test"
    sleep 1

    journalctl --no-pager -n 100 2>/dev/null | grep -Fq "$marker" \
        || fail "El test journald no quedó registrado en el journal."

    ok "journald validado para EL${EL_MAJOR}+."
}

# ---------------------------------------------------------------------------
# 5. logrotate
# ---------------------------------------------------------------------------

configure_logrotate() {
    has logrotate || fail "logrotate no está instalado."

    if [ -f "$LOGROTATE_FILE" ]; then
        ok "Configuración logrotate OrangeBox ya existe; no se modifica."
    else
        cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/orangebox-firewall.log {
    daily
    rotate 0
    missingok
    notifempty
    copytruncate
}
EOF
        chmod 644 "$LOGROTATE_FILE"
        ok "Configuración logrotate OrangeBox creada."
    fi

    logrotate -d "$LOGROTATE_FILE" >/dev/null 2>&1 || fail "logrotate rechazó la configuración."

    grep -Fq 'daily' "$LOGROTATE_FILE" || fail "Falta daily."
    grep -Fq 'rotate 0' "$LOGROTATE_FILE" || fail "Falta rotate 0."
    grep -Fq 'copytruncate' "$LOGROTATE_FILE" || fail "Falta copytruncate."

    ok "logrotate validado para EL6."
}

configure_logging() {
    case "$LOGGING_BACKEND" in
        rsyslog)
            echo "==> Configurando rsyslog + logrotate para EL6..."
            (configure_rsyslog) || step_error "El paso rsyslog falló; se continuará con logrotate y el resto de la instalación."
            echo "==> Configurando logrotate para EL6..."
            (configure_logrotate) || step_error "El paso logrotate falló; se continuará con el resto de la instalación."
            ;;
        journald)
            echo "==> Configurando journald para EL${EL_MAJOR}+..."
            (configure_journald) || step_error "El paso journald falló; se continuará con el resto de la instalación."
            ;;
        *)
            step_error "Backend de logging no definido: ${LOGGING_BACKEND}."
            ;;
    esac
}

# ---------------------------------------------------------------------------
# 6. Ejecución
# ---------------------------------------------------------------------------

echo
echo "============================================================"
echo " OrangeBox - Wazuh Agent unificado / Firewall Logging"
echo "============================================================"

if [ -z "$IS_CPANEL" ]; then
    echo
    echo "¿Este servidor utiliza cPanel/CSF?"
    if yesno "¿Es cPanel?"; then IS_CPANEL="yes"; else IS_CPANEL="no"; fi
fi

if [ "$IS_CPANEL" = "yes" ]; then
    WAZUH_HOME="/opt/ossec"
else
    WAZUH_HOME="/var/ossec"
fi

FIREWALL_LOG="/var/log/orangebox-firewall.log"
LOGROTATE_FILE="/etc/logrotate.d/orangebox-firewall"
RSYSLOG_FILE="/etc/rsyslog.d/orangebox-firewall.conf"
WAZUH_FIREWALL_HELPER="$WAZUH_HOME/bin/orangebox-iptables"
WAZUH_FIREWALL_STOP_HELPER="$WAZUH_HOME/bin/orangebox-iptables-stop"

detect_platform

if agent_installed; then
    ok "Wazuh Agent ya instalado: $(agent_version)"
else
    warn "Wazuh Agent no está instalado."
    install_agent
fi

configure_firewall
configure_logging
restart_agent

# ---------------------------------------------------------------------------
# 7. Componentes OrangeBox integrados: auditd + YARA
# ---------------------------------------------------------------------------
configure_exec_audit() {
    local RULE_FILE="/etc/audit/rules.d/orangebox-wazuh.rules"
    local KEY_TEMP="orangebox_exec"
    local KEY_BEHAVIOR="audit-wazuh-c"

    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: ejecutar como root." >&2
        return 1
    fi

    echo "==> Verificando paquetes audit..."

    # EL10 separa auditctl/augenrules en audit-rules.
    # EL6-EL9 entregan estas herramientas mediante el paquete audit.
    if ! rpm -q audit >/dev/null 2>&1; then
        echo "==> Instalando audit..."
        if has dnf; then
            dnf install -y audit || fail "No se pudo instalar auditd."
        elif has yum; then
            yum install -y audit || fail "No se pudo instalar auditd."
        else
            fail "No existe dnf/yum para instalar auditd."
        fi
    fi

    if [[ "$EL_MAJOR" -ge 10 ]] 2>/dev/null; then
        if ! rpm -q audit-rules >/dev/null 2>&1; then
            echo "==> Instalando audit-rules para Enterprise Linux ${EL_MAJOR}..."
            if has dnf; then
                dnf install -y audit-rules || fail "No se pudo instalar audit-rules."
            elif has yum; then
                yum install -y audit-rules || fail "No se pudo instalar audit-rules."
            else
                fail "No existe dnf/yum para instalar audit-rules."
            fi
        fi
    fi

    # Resolver auditctl/augenrules aunque /usr/sbin no esté en PATH.
    for audit_tool in auditctl augenrules; do
        if ! has "$audit_tool"; then
            for audit_tool_path in "/usr/sbin/$audit_tool" "/sbin/$audit_tool"; do
                if [ -x "$audit_tool_path" ]; then
                    PATH="$(dirname "$audit_tool_path"):$PATH"
                    break
                fi
            done
        fi
    done

    has auditctl || fail "auditctl no quedó disponible después de instalar audit."
    has augenrules || fail "augenrules no quedó disponible después de instalar audit."

    mkdir -p "$(dirname "$RULE_FILE")"

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

    # Garantizar que auditd quede habilitado y activo.
    if has systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^auditd\.service'; then
        systemctl enable auditd >/dev/null 2>&1 || warn "No se pudo habilitar auditd con systemctl."
        if ! systemctl is-active --quiet auditd; then
            systemctl start auditd || fail "No se pudo iniciar auditd."
        fi
    elif has chkconfig && chkconfig auditd on >/dev/null 2>&1; then
        :
    elif has service; then
        service auditd status >/dev/null 2>&1 || service auditd start || fail "No se pudo iniciar auditd."
    fi

    # Migración idempotente de la implementación OrangeBox antigua.
    # Versiones anteriores usaban 99-orangebox-exec.rules; conservarlo junto al
    # archivo canónico provoca reglas duplicadas y "Rule exists" en augenrules.
    local legacy_audit_file="/etc/audit/rules.d/99-orangebox-exec.rules"
    if [ -f "$legacy_audit_file" ] &&
       grep -Eq '(orangebox_exec|audit-wazuh-c)' "$legacy_audit_file"; then
        cp -p "$legacy_audit_file" \
            "$legacy_audit_file.orangebox-backup.$(date +%Y%m%d%H%M%S)" \
            || fail "No se pudo respaldar la regla auditd antigua $legacy_audit_file."
        rm -f "$legacy_audit_file" \
            || fail "No se pudo retirar la regla auditd antigua $legacy_audit_file."
        ok "Regla auditd OrangeBox antigua migrada desde $legacy_audit_file."
    fi
    SCANNER_COMMANDS=(
        nmap nmap6 masscan rustscan zmap naabu unicornscan arp-scan netdiscover
        fping hping hping2 hping3 nc ncat netcat socat telnet nping zgrab zgrab2
        nikto gobuster ffuf feroxbuster dirb dirsearch wfuzz whatweb wafw00f
        dnsrecon dnsenum amass subfinder massdns
    )

    RECON_COMMANDS=(
        hostname hostnamectl uname ip ss netstat lsof ps pstree who w last lastlog
        find locate id groups getent route arp ifconfig nmcli
    )

    # Reemplazamos solamente nuestro archivo: no tocamos reglas de otros paquetes.
    # Los directorios /tmp, /var/tmp y /dev/shm existen en todos los EL soportados.
    cat > "$RULE_FILE" <<'EOF'
# OrangeBox: detect execution from high-risk temporary directories.
# Consumed by OrangeBox/Wazuh rules.
-a always,exit -F arch=b64 -S execve -F dir=/tmp -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b32 -S execve -F dir=/tmp -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b32 -S execve -F dir=/var/tmp -F auid>=0 -F auid!=4294967295 -k orangebox_exec
-a always,exit -F arch=b32 -S execve -F dir=/dev/shm -F auid>=0 -F auid!=4294967295 -k orangebox_exec
EOF

    add_behavior_rule() {
        local command="$1"
        local path
        path="$(command -v "$command" 2>/dev/null || true)"

        [[ -n "$path" && -f "$path" && -x "$path" ]] || return 0
        [[ "$path" = /* ]] || return 0

        for arch in b64 b32; do
            local rule="-a always,exit -F arch=${arch} -S execve -F exe=${path} -F auid>=0 -F auid!=4294967295 -k audit-wazuh-c"
            if ! grep -Fqx -- "$rule" "$RULE_FILE" 2>/dev/null; then
                printf '%s\n' "$rule" >> "$RULE_FILE"
            fi
        done
    }

    for command in "${SCANNER_COMMANDS[@]}" "${RECON_COMMANDS[@]}"; do
        add_behavior_rule "$command"
    done

    # EL6+ soportado: augenrules procesa /etc/audit/rules.d/*.rules.
    # Si una instalación antigua no trae augenrules, auditctl -R deja las reglas
    # activas para esta sesión; audit.rules queda gestionado por el sistema.
    if has augenrules; then
        augenrules --load || fail "augenrules no pudo cargar las reglas OrangeBox."
    else
        auditctl -R "$RULE_FILE" || fail "auditctl no pudo cargar las reglas OrangeBox."
    fi

    echo "=== OrangeBox audit execution monitoring ==="

    if ! auditctl -l | grep -F -- "-k ${KEY_TEMP}" >/dev/null 2>&1 &&
       ! auditctl -l | grep -F -- "-F key=${KEY_TEMP}" >/dev/null 2>&1; then
        echo "ERROR: las reglas base ${KEY_TEMP} no quedaron cargadas." >&2
        return 1
    fi
    ok "Reglas de ejecución en /tmp, /var/tmp y /dev/shm cargadas."

    if auditctl -l | grep -E -- '(-k[[:space:]]+|-F[[:space:]]+key=)audit-wazuh-c' >/dev/null 2>&1; then
        ok "Reglas de scanners/reconocimiento cargadas."
    else
        ok "No se detectaron ejecutables scanner/recon adicionales; no se agregaron reglas ${KEY_BEHAVIOR}."
    fi

    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent\\.service'; then
        systemctl restart wazuh-agent || fail "No se pudo reiniciar wazuh-agent después de configurar auditd."
    elif command -v service >/dev/null 2>&1 && service wazuh-agent status >/dev/null 2>&1; then
        service wazuh-agent restart || fail "No se pudo reiniciar wazuh-agent después de configurar auditd."
    elif [ -x "${WAZUH_HOME}/bin/wazuh-control" ]; then
        "${WAZUH_HOME}/bin/wazuh-control" restart || fail "No se pudo reiniciar wazuh-agent después de configurar auditd."
    else
        fail "No se pudo encontrar un mecanismo para reiniciar wazuh-agent."
    fi

    ok "auditd monitoriza ejecuciones en zonas temporales, scanners y herramientas de reconocimiento."
}

configure_yara() {
    # El runtime YARA vive en el arbol de configuracion para que su ruta
    # coincida con /var/ossec/active-response/bin al desplegarlo.
    local REPO_ROOT
    REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
    local SCRIPT_SRC="${REPO_ROOT}/configuration/agent/active-response/bin/orangebox-yara.sh"

    if [[ ! -f "${SCRIPT_SRC}" ]]; then
        echo "ERROR: falta el runtime YARA versionado: ${SCRIPT_SRC}" >&2
        return 1
    fi

    # El resto de esta funcion instala dependencias, valida el script,
    # descarga el ruleset oficial y lo copia al runtime del agente.
    chmod 750 "$SCRIPT_SRC"
    # OrangeBox Wazuh - instalador YARA para agentes
# ==============================================
#
# Instala la integracion FIM -> YARA y descarga EXCLUSIVAMENTE el ruleset
# oficial de Yara-Rules/rules.
#
# No contiene ni instala reglas YARA propias de OrangeBox.
#
# /opt/ossec tiene prioridad sobre /var/ossec.
# No modifica ossec.conf ni la configuracion del Manager.

YARA_RULES_REPO="$YARA_RULES_REPO"
YARA_RULES_BRANCH="$YARA_RULES_BRANCH"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: ejecutar como root." >&2
    return 1
fi

if [[ ! -x "${WAZUH_HOME}/bin/wazuh-control" ]]; then
    echo "ERROR: no se encontro un Wazuh Agent en ${WAZUH_HOME}." >&2
    return 1
fi

DEST_BIN="${WAZUH_HOME}/active-response/bin"
DEST_YARA="${DEST_BIN}/yara"
DEST_RULES="${DEST_YARA}/rules"
RULESET_DIR="${DEST_RULES}/yara-rules"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

echo "==> Usando instalador: ${SCRIPT_DIR}"
echo "==> Wazuh home: ${WAZUH_HOME}"

install_missing_packages() {
    local manager=""
    local -a packages=()

    if command -v dnf >/dev/null 2>&1; then
        manager="dnf"
    elif command -v yum >/dev/null 2>&1; then
        manager="yum"
    elif command -v apt-get >/dev/null 2>&1; then
        manager="apt-get"
    else
        echo "ERROR: no se encontro dnf, yum ni apt-get para instalar dependencias." >&2
        return 1
    fi

    command -v jq >/dev/null 2>&1 || packages+=(jq)
    command -v git >/dev/null 2>&1 || packages+=(git)

    local yara_found="no"
    for candidate in /usr/local/bin/yara /usr/bin/yara /usr/local/sbin/yara; do
        if [[ -x "${candidate}" ]]; then
            yara_found="yes"
            break
        fi
    done
    [[ "${yara_found}" == "yes" ]] || packages+=(yara)

    if (( ${#packages[@]} == 0 )); then
        return 0
    fi

    echo "==> Instalando dependencias faltantes: ${packages[*]}"

    case "${manager}" in
        dnf|yum)
            if "${manager}" install -y "${packages[@]}"; then
                return 0
            fi

            # CloudLinux 9 no publica actualmente el paquete yara en su
            # AppStream. cPanel/CloudLinux además tiene antecedentes de
            # conflictos entre YARA de EPEL e Imunify360, por lo que NO
            # habilitamos EPEL como fallback.
            if [[ "${EL_MAJOR}" == "9" && "${IS_CPANEL}" == "yes" &&
                  -f /etc/redhat-release &&
                  "$(grep -qi 'CloudLinux' /etc/redhat-release; echo $?)" -eq 0 &&
                  " ${packages[*]} " == *" yara "* ]]; then
                local cloudlinux_yara_rpm_url="https://repo.almalinux.org/almalinux/9/AppStream/x86_64/os/Packages/yara-4.5.2-1.el9.x86_64.rpm"
                local cloudlinux_yara_rpm="/tmp/yara-4.5.2-1.el9.x86_64.rpm"

                echo "==> YARA no esta disponible en los repos habilitados de CloudLinux 9."
                echo "==> Instalando YARA EL9 desde AlmaLinux AppStream (solo este RPM)..."

                has curl || {
                    echo "ERROR: curl es requerido para descargar el RPM YARA de fallback." >&2
                    return 1
                }

                curl -fL -o "${cloudlinux_yara_rpm}" "${cloudlinux_yara_rpm_url}" || {
                    echo "ERROR: no se pudo descargar el RPM YARA EL9." >&2
                    rm -f "${cloudlinux_yara_rpm}"
                    return 1
                }

                "${manager}" install -y "${cloudlinux_yara_rpm}" || {
                    echo "ERROR: no se pudo instalar el RPM YARA EL9." >&2
                    rm -f "${cloudlinux_yara_rpm}"
                    return 1
                }

                rm -f "${cloudlinux_yara_rpm}"

                # La transacción anterior pudo haber fallado completa por
                # la ausencia de yara; instalar ahora cualquier dependencia
                # restante por separado.
                local remaining_packages=()
                local pkg=""
                for pkg in "${packages[@]}"; do
                    [ "${pkg}" = "yara" ] && continue
                    if ! rpm -q "${pkg}" >/dev/null 2>&1; then
                        remaining_packages+=("${pkg}")
                    fi
                done

                if (( ${#remaining_packages[@]} > 0 )); then
                    "${manager}" install -y "${remaining_packages[@]}" || return 1
                fi

                return 0
            fi

            return 1
            ;;
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            "${manager}" update
            "${manager}" install -y "${packages[@]}"
            ;;
    esac
}

if [[ "$YARA_NO_PACKAGE_INSTALL" != "yes" ]]; then
    install_missing_packages
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq es requerido por orangebox-yara.sh." >&2
    echo "Instale jq o use ORANGEBOX_YARA_NO_PACKAGE_INSTALL=yes si ya esta disponible por otra ruta." >&2
    return 1
fi

YARA_BIN="$YARA_BIN"
if [[ -n "${YARA_BIN}" ]]; then
    [[ -x "${YARA_BIN}" ]] || {
        echo "ERROR: ORANGEBOX_YARA_BIN no es ejecutable: ${YARA_BIN}" >&2
        return 1
    }
else
    for candidate in /usr/local/bin/yara /usr/bin/yara /usr/local/sbin/yara; do
        if [[ -x "${candidate}" ]]; then
            YARA_BIN="${candidate}"
            break
        fi
    done
fi

if [[ -z "${YARA_BIN}" ]]; then
    echo "ERROR: no se encontro YARA despues de instalar las dependencias." >&2
    echo "Si YARA esta instalado en otra ruta, use ORANGEBOX_YARA_BIN=/ruta/al/yara." >&2
    return 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

[[ -f "${SCRIPT_SRC}" ]] || {
    echo "ERROR: falta el único source of truth del runtime: ${SCRIPT_SRC}" >&2
    return 1
}

bash -n "${SCRIPT_SRC}" || {
    echo "ERROR: el runtime YARA fuente tiene error de sintaxis: ${SCRIPT_SRC}" >&2
    return 1
}
if ! command -v git >/dev/null 2>&1; then
    echo "ERROR: git es requerido para descargar el ruleset oficial Yara-Rules." >&2
    return 1
fi

WAZUH_GROUP="$(stat -c '%G' "${DEST_BIN}" 2>/dev/null || true)"
if [[ -z "${WAZUH_GROUP}" || "${WAZUH_GROUP}" == "UNKNOWN" ]]; then
    WAZUH_GROUP="wazuh"
fi

install -d -m 750 -o root -g "${WAZUH_GROUP}" "${DEST_BIN}" "${DEST_YARA}" "${DEST_RULES}"
if [[ "${SCRIPT_SRC}" != "${DEST_BIN}/orangebox-yara.sh" ]]; then
    install -m 750 -o root -g "${WAZUH_GROUP}" "${SCRIPT_SRC}" "${DEST_BIN}/orangebox-yara.sh"
else
    chmod 750 "${SCRIPT_SRC}"
fi

echo "==> Descargando Yara-Rules oficial..."
git clone --depth 1 --branch "${YARA_RULES_BRANCH}"     "${YARA_RULES_REPO}" "${TMP_DIR}/rules"

RULESET_COMMIT="$(git -C "${TMP_DIR}/rules" rev-parse HEAD)"

# Validar el ruleset completo antes de reemplazar el instalado.
for index in webshells_index.yar malware_index.yar; do
    INDEX_PATH="${TMP_DIR}/rules/${index}"

    [[ -s "${INDEX_PATH}" ]] || {
        echo "ERROR: falta el indice oficial ${index}." >&2
        return 1
    }

    "${YARA_BIN}" -w "${INDEX_PATH}" /dev/null >/dev/null 2>&1 || {
        echo "ERROR: YARA no pudo cargar el indice ${index}." >&2
        return 1
    }
done

# No conservar el .git del clon: el agente solo necesita las firmas.
rm -rf "${TMP_DIR}/rules/.git"

# Sustitucion controlada: conservar el ruleset anterior hasta activar el nuevo.
rm -rf "${RULESET_DIR}.new"
mv "${TMP_DIR}/rules" "${RULESET_DIR}.new" || {
    echo "ERROR: no se pudo preparar el nuevo ruleset." >&2
    return 1
}
if [[ -d "${RULESET_DIR}" ]]; then
    rm -rf "${RULESET_DIR}.previous"
    mv "${RULESET_DIR}" "${RULESET_DIR}.previous" || {
        echo "ERROR: no se pudo preservar el ruleset anterior." >&2
        return 1
    }
fi
mv "${RULESET_DIR}.new" "${RULESET_DIR}" || {
    echo "ERROR: no se pudo activar el nuevo ruleset." >&2
    if [[ -d "${RULESET_DIR}.previous" && ! -d "${RULESET_DIR}" ]]; then
        mv "${RULESET_DIR}.previous" "${RULESET_DIR}" || true
    fi
    return 1
}
rm -rf "${RULESET_DIR}.previous"

printf '%s\n' "${RULESET_COMMIT}" > "${DEST_RULES}/YARA-RULES-COMMIT"
printf '%s\n' "${YARA_RULES_REPO}" > "${DEST_RULES}/YARA-RULES-REPOSITORY"
printf '%s\n' "${YARA_RULES_BRANCH}" > "${DEST_RULES}/YARA-RULES-BRANCH"

# Eliminar restos de la antigua implementacion OrangeBox CORE/EXTENDED.
rm -f     "${DEST_RULES}/orangebox-webshell-core.yar"     "${DEST_RULES}/orangebox-webshell-extended.yar"

# Reparar propietarios/permisos. Los directorios son atravesables por
# root/wazuh; las firmas son de solo lectura.
chown -R root:"${WAZUH_GROUP}" "${DEST_YARA}"
find "${DEST_YARA}" -type d -exec chmod 750 {} +
find "${DEST_YARA}" -type f -exec chmod 640 {} +
chmod 750 "${DEST_BIN}/orangebox-yara.sh"
chmod 640     "${DEST_RULES}/YARA-RULES-COMMIT"     "${DEST_RULES}/YARA-RULES-REPOSITORY"     "${DEST_RULES}/YARA-RULES-BRANCH"

# Actualizacion automatica diaria de Yara-Rules.
YARA_UPDATE_SCRIPT="/usr/local/sbin/orangebox-yara-update"
YARA_UPDATE_CRON="/etc/cron.d/orangebox-yara-update"

cat > "${YARA_UPDATE_SCRIPT}" <<'YARA_UPDATE'
#!/usr/bin/env bash
set -u
set -o pipefail

WAZUH_HOME='@@WAZUH_HOME@@'
YARA_RULES_REPO='@@YARA_RULES_REPO@@'
YARA_RULES_BRANCH='@@YARA_RULES_BRANCH@@'
YARA_BIN='@@YARA_BIN@@'
DEST_RULES="${WAZUH_HOME}/active-response/bin/yara/rules"
RULESET_DIR="${DEST_RULES}/yara-rules"
LOG_FILE="${WAZUH_HOME}/logs/orangebox-yara-update.log"

mkdir -p "${DEST_RULES}"
exec >>"${LOG_FILE}" 2>&1

echo "=== $(date '+%Y-%m-%d %H:%M:%S') OrangeBox YARA update ==="

if ! command -v git >/dev/null 2>&1; then
    echo "ERROR: git no esta instalado."
    exit 1
fi

if [[ ! -x "${YARA_BIN}" ]]; then
    echo "ERROR: YARA no esta disponible en ${YARA_BIN}."
    exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

git clone --depth 1 --branch "${YARA_RULES_BRANCH}" \
    "${YARA_RULES_REPO}" "${TMP_DIR}/rules"

NEW_COMMIT="$(git -C "${TMP_DIR}/rules" rev-parse HEAD)"
OLD_COMMIT="$(cat "${DEST_RULES}/YARA-RULES-COMMIT" 2>/dev/null || true)"

if [[ -n "${OLD_COMMIT}" && "${OLD_COMMIT}" == "${NEW_COMMIT}" ]]; then
    echo "OK: Yara-Rules ya esta actualizado en ${NEW_COMMIT}."
    exit 0
fi

for index in webshells_index.yar malware_index.yar; do
    INDEX_PATH="${TMP_DIR}/rules/${index}"
    [[ -s "${INDEX_PATH}" ]] || {
        echo "ERROR: falta el indice oficial ${index}."
        exit 1
    }
    "${YARA_BIN}" -w "${INDEX_PATH}" /dev/null >/dev/null 2>&1 || {
        echo "ERROR: YARA no pudo cargar ${index}; se conserva el ruleset actual."
        exit 1
    }
done

rm -rf "${TMP_DIR}/rules/.git"
rm -rf "${RULESET_DIR}.new"
mv "${TMP_DIR}/rules" "${RULESET_DIR}.new" || {
    echo "ERROR: no se pudo preparar el nuevo ruleset."
    exit 1
}

if [[ -d "${RULESET_DIR}" ]]; then
    rm -rf "${RULESET_DIR}.previous"
    mv "${RULESET_DIR}" "${RULESET_DIR}.previous" || {
        echo "ERROR: no se pudo preservar el ruleset actual."
        exit 1
    }
fi

if ! mv "${RULESET_DIR}.new" "${RULESET_DIR}"; then
    echo "ERROR: no se pudo activar el nuevo ruleset."
    if [[ -d "${RULESET_DIR}.previous" && ! -d "${RULESET_DIR}" ]]; then
        mv "${RULESET_DIR}.previous" "${RULESET_DIR}" || true
    fi
    exit 1
fi

rm -rf "${RULESET_DIR}.previous"
printf '%s\n' "${NEW_COMMIT}" > "${DEST_RULES}/YARA-RULES-COMMIT"
printf '%s\n' "${YARA_RULES_REPO}" > "${DEST_RULES}/YARA-RULES-REPOSITORY"
printf '%s\n' "${YARA_RULES_BRANCH}" > "${DEST_RULES}/YARA-RULES-BRANCH"

WAZUH_GROUP="$(stat -c '%G' "${WAZUH_HOME}/active-response/bin" 2>/dev/null || echo wazuh)"
chown -R root:"${WAZUH_GROUP}" "${DEST_RULES}" 2>/dev/null || true
find "${DEST_RULES}" -type d -exec chmod 750 {} + 2>/dev/null || true
find "${DEST_RULES}" -type f -exec chmod 640 {} + 2>/dev/null || true

echo "OK: Yara-Rules actualizado: ${OLD_COMMIT:-ninguno} -> ${NEW_COMMIT}."
YARA_UPDATE

sed -i \
    -e "s|@@WAZUH_HOME@@|${WAZUH_HOME}|g" \
    -e "s|@@YARA_RULES_REPO@@|${YARA_RULES_REPO}|g" \
    -e "s|@@YARA_RULES_BRANCH@@|${YARA_RULES_BRANCH}|g" \
    -e "s|@@YARA_BIN@@|${YARA_BIN}|g" \
    "${YARA_UPDATE_SCRIPT}"

bash -n "${YARA_UPDATE_SCRIPT}" || {
    echo "ERROR: el updater YARA generado tiene un error de sintaxis." >&2
    rm -f "${YARA_UPDATE_SCRIPT}"
    return 1
}

chmod 750 "${YARA_UPDATE_SCRIPT}"
cat > "${YARA_UPDATE_CRON}" <<'YARA_CRON'
17 3 * * * root /usr/local/sbin/orangebox-yara-update
YARA_CRON
chmod 644 "${YARA_UPDATE_CRON}"

echo "OK: actualizacion automatica diaria de Yara-Rules configurada a las 03:17."
echo
echo "==> Instalacion validada."
echo
echo "OrangeBox YARA instalado:"
echo "  Wazuh home : ${WAZUH_HOME}"
echo "  Script      : ${DEST_BIN}/orangebox-yara.sh"
echo "  Rules       : ${RULESET_DIR}"
echo "  Rules repo  : ${YARA_RULES_REPO}"
echo "  Branch      : ${YARA_RULES_BRANCH}"
echo "  Commit      : ${RULESET_COMMIT} (snapshot instalado; se actualiza diariamente)"
echo "  YARA        : ${YARA_BIN}"
echo "  Grupo       : ${WAZUH_GROUP}"
echo
echo "No se reinicio el agente automaticamente."

}

configure_components() {
    echo
    echo "==> Verificando/configurando auditd..."
    configure_exec_audit || fail "Falló la configuración de auditd OrangeBox."
    echo
    echo "==> Verificando/configurando YARA..."
    configure_yara || fail "Falló la configuración YARA OrangeBox."
    ok "auditd + YARA configurados."
}
configure_components

agent_installed || fail "Verificación final: Wazuh Agent no quedó correctamente instalado."
[ -x "$WAZUH_HOME/active-response/bin/orangebox-yara.sh" ] || fail "Verificación final: orangebox-yara.sh ausente."

if [ "$LOGGING_BACKEND" = "rsyslog" ]; then
    [ -f "$FIREWALL_LOG" ] || fail "Verificación final: log ausente."
    [ -f "$LOGROTATE_FILE" ] || fail "Verificación final: logrotate ausente."
else
    journalctl -n 1 --no-pager >/dev/null 2>&1 || fail "Verificación final: journald no está disponible."
fi

if [ "$ERROR_COUNT" -gt 0 ]; then
    echo
    echo "============================================================" >&2
    echo " OrangeBox completado con $ERROR_COUNT error(es)." >&2
    echo " Revise los mensajes ERROR anteriores; los demás pasos sí se ejecutaron." >&2
    echo "============================================================" >&2
    exit 1
fi

ok "Configuración OrangeBox completada."
