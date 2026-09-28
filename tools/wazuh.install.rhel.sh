#!/bin/bash

# OrangeBox - Wazuh Agent / Firewall Logging
# Compatible: CentOS 6/7/8 and AlmaLinux 8/9/10.
#
# Logging backend by Enterprise Linux major version:
#   EL 6    : iptables -> rsyslog -> /var/log/orangebox-firewall.log -> Wazuh
#   EL 7+   : iptables -> journald -> Wazuh
#
# Idempotent: existing correct settings are preserved; missing settings are added;
# unexpected existing settings cause an error instead of guessing.

set -u

WAZUH_VERSION="4.14.7"
DEFAULT_MANAGER="wazuh.example.com"
DEFAULT_GROUP="OrangeBox"
DEFAULT_AGENT_NAME="$HOSTNAME"
WAZUH_OSSEC_SIZE="1G"
WAZUH_OSSEC_LV="wazuh"
WAZUH_OSSEC_VG="${WAZUH_OSSEC_VG:-}"

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
            fail "Versión de Enterprise Linux no soportada o no detectada: ${EL_MAJOR:-desconocida}."
            ;;
    esac

    ok "Enterprise Linux ${EL_MAJOR}: backend de logging ${LOGGING_BACKEND}."
}

# ---------------------------------------------------------------------------
# 1. Wazuh Agent
# ---------------------------------------------------------------------------

agent_installed() {
    rpm -q wazuh-agent >/dev/null 2>&1 || [ -x /var/ossec/bin/wazuh-control ]
}

agent_version() {
    rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' wazuh-agent 2>/dev/null || echo "desconocida"
}

ossec_mount_options() {
    awk '$2 == "/var/ossec" { print $4; exit }' /proc/mounts 2>/dev/null
}

ossec_mount_source() {
    awk '$2 == "/var/ossec" { print $1; exit }' /proc/mounts 2>/dev/null
}

ossec_mount_ready() {
    mountpoint -q /var/ossec 2>/dev/null || return 1

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
    [ -s /var/ossec/etc/client.keys ] || return 1
    [ -x /var/ossec/bin/wazuh-control ] || return 1
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

install_agent() {
    AGENT_NAME="${WAZUH_AGENT_NAME:-$DEFAULT_AGENT_NAME}"
    MANAGER="${WAZUH_MANAGER:-$DEFAULT_MANAGER}"
    GROUP="${WAZUH_AGENT_GROUP:-$DEFAULT_GROUP}"
    PASSWORD="${WAZUH_REGISTRATION_PASSWORD:-}"

    echo
    echo "=== DATOS DE ENROLAMIENTO ==="
    echo "Nombre : $AGENT_NAME"
    echo "Manager: $MANAGER"
    echo "Grupo  : $GROUP"
    [ -n "$PASSWORD" ] && echo "Password: [definida por entorno]" || echo "Password: [no definida]"

    if ! yesno "¿Los datos están correctos?"; then
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
    yesno "¿Proceder?" || fail "Instalación cancelada."

    prepare_ossec_storage

    local rpm_file="wazuh-agent-$WAZUH_VERSION-1.x86_64.rpm"
    local url="https://packages.wazuh.com/4.x/yum/$rpm_file"

    has curl || fail "curl no está instalado."
    info="Descargando $rpm_file..."
    echo "==> $info"
    curl -fL -o "/tmp/$rpm_file" "$url" || fail "Falló la descarga."

    echo "==> Instalando wazuh-agent con enrolamiento..."
    WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_GROUP="$GROUP" \
    WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_REGISTRATION_PASSWORD="$PASSWORD" \
    rpm -ihv "/tmp/$rpm_file" \
    || fail "Falló la instalación de wazuh-agent."

    rm -f "/tmp/$rpm_file"
    agent_installed || fail "Wazuh Agent no quedó instalado."
    [ -f /var/ossec/etc/ossec.conf ] || fail "La instalación no generó /var/ossec/etc/ossec.conf."
    ok "Wazuh Agent instalado/reparado: $(agent_version)"
}

restart_agent() {
    if has systemctl; then
        systemctl enable --now wazuh-agent || fail "No se pudo habilitar/iniciar wazuh-agent."
        systemctl is-active --quiet wazuh-agent || fail "wazuh-agent no está activo."

        if systemctl is-enabled orangebox-iptables.service >/dev/null 2>&1; then
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
    has shorewall || fail "Shorewall está instalado pero el comando shorewall no existe."
    [ -f /etc/shorewall/rules ] || fail "Shorewall está instalado pero no existe /etc/shorewall/rules."

    # La regla se identifica por el tag ORANGEBOX-FW. No se agrega una segunda
    # regla aunque ya exista una variante equivalente en el archivo.
    local shorewall_changed=0

    if grep -Fq 'ORANGEBOX-FW' /etc/shorewall/rules; then
        ok "Regla ORANGEBOX-FW ya existe en Shorewall; no se modifica."
    else
        cp -p /etc/shorewall/rules \
            "/etc/shorewall/rules.orangebox-backup.$(date +%Y%m%d%H%M%S)" \
            || fail "No se pudo respaldar /etc/shorewall/rules."

        cat >> /etc/shorewall/rules <<'EOF'

# OrangeBox - Wazuh firewall logging
# SOURCE: todos los orígenes externos hacia el firewall.
# RATE: 20 conexiones/segundo, burst 40.
LOG:info:ORANGEBOX-FW    all-    $FW    tcp    -    -    -    20/sec:40
EOF
        shorewall_changed=1

        shorewall check >/dev/null 2>&1 \
            || fail "Shorewall rechazó la configuración ORANGEBOX-FW."

        ok "Regla ORANGEBOX-FW agregada y validada en Shorewall."
    fi

    shorewall check >/dev/null 2>&1 \
        || fail "Shorewall rechazó la configuración existente."

    # La configuración queda persistente en /etc/shorewall/rules.
    # En EL6 Shorewall puede estar gestionado por init.d y el comando
    # Solo reiniciamos Shorewall si acabamos de modificar la configuración.
    # Si ORANGEBOX-FW ya existía, no se toca el firewall.
    if [ "$shorewall_changed" -eq 1 ]; then
        if has service && service shorewall status >/dev/null 2>&1; then
            if shorewall restart >/dev/null 2>&1; then
                ok "Shorewall reiniciado con la configuración OrangeBox."
            else
                fail "Se agregó la regla OrangeBox, pero no se pudo reiniciar Shorewall."
            fi
        elif has systemctl && systemctl is-active --quiet shorewall 2>/dev/null; then
            if shorewall restart >/dev/null 2>&1; then
                ok "Shorewall reiniciado con la configuración OrangeBox."
            else
                fail "Se agregó la regla OrangeBox, pero no se pudo reiniciar Shorewall."
            fi
        else
            warn "Se agregó la regla OrangeBox, pero Shorewall no está activo; la configuración quedó persistente y será aplicada al iniciar Shorewall."
        fi
    fi
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
log_rule_exists || "$IPTABLES" -A ORANGEBOX-FW \
    -m limit --limit 20/second --limit-burst 40 \
    -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4 || exit 1
return_rule_exists || "$IPTABLES" -A ORANGEBOX-FW -j RETURN || exit 1
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
ExecStart=/var/ossec/bin/orangebox-iptables
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
configure_iptables() {
    if ! has iptables; then
        step_error "iptables no está instalado."
        return 1
    fi

    local failed=0

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

configure_firewall() {
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
            step_error "Backend de logging no definido: ${LOGGING_BACKEND:-vacío}."
            ;;
    esac
}

# ---------------------------------------------------------------------------
# 6. Ejecución
# ---------------------------------------------------------------------------

echo
echo "============================================================"
echo " OrangeBox - Wazuh Agent / Firewall Logging"
echo "============================================================"

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

agent_installed || fail "Verificación final: Wazuh Agent no quedó correctamente instalado."

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
