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
WAZUH_VERSION='4.14.8'
WAZUH_MANAGER='TU_HOSTNAME'
WAZUH_AGENT_GROUP='default'
WAZUH_AGENT_NAME=''
WAZUH_REGISTRATION_PASSWORD=''
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
PYTHON3_BIN=''
EPEL6_ARCHIVE_BASEURL='http://mirror.math.princeton.edu/pub/fedora-archive/epel/6/$basearch'
EPEL6_RELEASE_RPM_URL='http://mirror.math.princeton.edu/pub/fedora-archive/epel/6/x86_64/epel-release-6-8.noarch.rpm'
EPEL6_REPO_FILE='/etc/yum.repos.d/orangebox-epel6.repo'

WAZUH_HOME='/var/ossec'
FIREWALL_LOG="/var/log/orangebox-firewall.log"
LOGROTATE_FILE="/etc/logrotate.d/orangebox-firewall"
RSYSLOG_FILE="/etc/rsyslog.d/orangebox-firewall.conf"
WAZUH_FIREWALL_SERVICE="/etc/systemd/system/orangebox-iptables.service"
EL_MAJOR=""
LOGGING_BACKEND=""

ERROR_COUNT=0
STEP_OK=()
STEP_FAILED=()
AGENT_ACTION_REQUIRED=0
AGENT_ACTION_FILE="/tmp/orangebox-agent-action-required.$"
rm -f "$AGENT_ACTION_FILE"
trap 'rm -f "$AGENT_ACTION_FILE"' EXIT

request_agent_action() {
    : > "$AGENT_ACTION_FILE"
}

step_error() {
    echo "ERROR: $*" >&2
    ERROR_COUNT=$((ERROR_COUNT + 1))
}

record_step_ok() {
    STEP_OK+=("$1")
}

record_step_failed() {
    STEP_FAILED+=("$1")
}

run_step() {
    local label="$1"
    shift

    echo
    echo "============================================================"
    echo " PASO: ${label}"
    echo "============================================================"

    # Cada etapa corre en un subshell: un fail/exit queda contenido
    # y no aborta el instalador completo.
    if ( "$@" ); then
        record_step_ok "${label}"
        ok "Paso completado: ${label}."
    else
        record_step_failed "${label}"
        echo "ERROR: ${label} falló; se continuará con el siguiente paso." >&2
    fi

    # Las etapas se ejecutan en subshell; recuperar solicitudes de activación
    # mediante un archivo para que el estado sobreviva al subshell.
    if [ -f "$AGENT_ACTION_FILE" ]; then
        AGENT_ACTION_REQUIRED=1
    fi

    return 0
}

fail() { echo "ERROR: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }
warn() { echo "AVISO: $*" >&2; }
has() { command -v "$1" >/dev/null 2>&1; }

# Reemplaza un archivo administrado solo cuando su contenido o metadatos
# difieren del estado deseado. Devuelve 0 si hizo cambios y 1 si no hizo nada.
sync_managed_file() {
    local source_file="$1"
    local target_file="$2"
    local mode="$3"
    local owner="$4"
    local group="$5"
    local changed=0

    if [ -f "$target_file" ] && cmp -s "$source_file" "$target_file"; then
        local current_mode current_owner current_group
        current_mode="$(stat -c '%a' "$target_file" 2>/dev/null || true)"
        current_owner="$(stat -c '%U' "$target_file" 2>/dev/null || true)"
        current_group="$(stat -c '%G' "$target_file" 2>/dev/null || true)"

        if [ "$current_mode" != "$mode" ]; then
            chmod "$mode" "$target_file" || fail "No se pudo corregir permisos de $target_file."
            changed=1
        fi

        if [ "$current_owner" != "$owner" ]; then
            chown "$owner" "$target_file" || fail "No se pudo corregir propietario de $target_file."
            changed=1
        fi

        if [ "$current_group" != "$group" ]; then
            chgrp "$group" "$target_file" || fail "No se pudo corregir grupo de $target_file."
            changed=1
        fi

        rm -f "$source_file"
        return "$([ "$changed" -eq 1 ] && echo 0 || echo 1)"
    fi

    if [ -e "$target_file" ] || [ -L "$target_file" ]; then
        cp -p "$target_file" "$target_file.orangebox-backup.$(date +%Y%m%d%H%M%S)" \
            || fail "No se pudo respaldar $target_file."
    fi

    install -m "$mode" -o "$owner" -g "$group" "$source_file" "$target_file" \
        || fail "No se pudo instalar $target_file."
    rm -f "$source_file"
    return 0
}


ensure_epel6() {
    [ "$EL_MAJOR" = "6" ] || return 0
    has yum || fail "EL6 requiere yum para habilitar EPEL6."

    local epel_was_installed="yes"
    if ! rpm -q epel-release >/dev/null 2>&1; then
        epel_was_installed="no"
        echo "==> EPEL6 no está instalado; instalando epel-release 6-8 desde el archivo de Fedora..."
        yum install -y "$EPEL6_RELEASE_RPM_URL" || fail "No se pudo instalar epel-release para EL6."
    fi

    [ -f /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-6 ] || \
        fail "epel-release quedó instalado pero falta RPM-GPG-KEY-EPEL-6."

    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-6 >/dev/null 2>&1 || \
        fail "No se pudo importar la llave GPG de EPEL6."

    local epel_repo_tmp
    epel_repo_tmp="$(mktemp)" || fail "No se pudo crear temporal para el repositorio EPEL6."
    cat > "$epel_repo_tmp" <<'EPEL6_REPO'
[orangebox-epel6]
name=OrangeBox EPEL 6 archive
baseurl=@@EPEL6_ARCHIVE_BASEURL@@
enabled=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-6
EPEL6_REPO
    sed -i "s|@@EPEL6_ARCHIVE_BASEURL@@|$EPEL6_ARCHIVE_BASEURL|g" "$epel_repo_tmp" ||
        fail "No se pudo preparar el repositorio OrangeBox EPEL6."

    if sync_managed_file "$epel_repo_tmp" "$EPEL6_REPO_FILE" 644 root root; then
        ok "Repositorio OrangeBox EPEL6 actualizado."
    else
        ok "Repositorio OrangeBox EPEL6 ya coincide; no se modifica."
    fi

    # El epel.repo original apunta a mirrorlist ya retirado. Si nosotros
    # acabamos de instalar epel-release, lo dejamos deshabilitado y usamos
    # exclusivamente el repo archivado de OrangeBox para EL6.
    if [ "$epel_was_installed" = "no" ] && [ -f /etc/yum.repos.d/epel.repo ]; then
        sed -i 's/^[[:space:]]*enabled[[:space:]]*=[[:space:]]*1[[:space:]]*$/enabled=0/' \
            /etc/yum.repos.d/epel.repo || fail "No se pudo deshabilitar el EPEL6 mirrorlist antiguo."
    fi

    ok "EPEL6 archivado disponible para dependencias OrangeBox."
}

ensure_python3() {
    if has python3; then
        PYTHON3_BIN="$(command -v python3)"
        return 0
    fi

    local python_package="python3"
    if [ "$EL_MAJOR" = "6" ]; then
        python_package="python34"
    fi

    echo "==> Python 3 no encontrado; instalando $python_package..."

    if has yum; then
        if [ "$EL_MAJOR" = "6" ]; then
            ensure_epel6
            yum --disablerepo='epel*' --enablerepo=orangebox-epel6 install -y "$python_package" || \
                fail "No se pudo instalar $python_package para Python 3 desde EPEL6 archivado."
        else
            yum install -y "$python_package" || fail "No se pudo instalar $python_package para Python 3."
        fi
    elif has dnf; then
        dnf install -y "$python_package" || fail "No se pudo instalar $python_package para Python 3."
    else
fail "No existe yum ni dnf para instalar Python 3."
    fi

    if has python3; then
        PYTHON3_BIN="$(command -v python3)"
        ok "Python 3 disponible: $PYTHON3_BIN."
        return 0
    fi

    # EL6/EPEL entrega python3.4 sin necesariamente crear el alias python3.
    # Crear el alias solo si no existe otro python3; nunca tocar Python 2.
    local python3_candidate=""
    for python3_candidate in /usr/bin/python3.4 /usr/local/bin/python3.4; do
        if [ -x "$python3_candidate" ]; then
            if [ ! -e /usr/bin/python3 ] && [ ! -L /usr/bin/python3 ]; then
                ln -s "$python3_candidate" /usr/bin/python3 || \
                    fail "No se pudo crear /usr/bin/python3 -> $python3_candidate."
            fi
            break
        fi
    done

    has python3 || fail "Python 3 no quedó disponible después de instalar $python_package."
    PYTHON3_BIN="$(command -v python3)"
    ok "Python 3 disponible: $PYTHON3_BIN."
}
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
            echo "ERROR: Versión de Enterprise Linux no soportada o no detectada: ${EL_MAJOR}." >&2
            return 1
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

find_ossec_vg() {
    if [ -n "$WAZUH_OSSEC_VG" ]; then
        vgs "$WAZUH_OSSEC_VG" >/dev/null 2>&1 || return 1
        local configured_vg_free
        configured_vg_free="$(vgs --noheadings --units m --nosuffix -o vg_free "$WAZUH_OSSEC_VG" 2>/dev/null |
            awk 'NR==1 {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1); print $1}')"
        [ -n "$configured_vg_free" ] && [ "$(printf '%.0f\n' "$configured_vg_free")" -ge 1024 ] 2>/dev/null ||
            return 1
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

    [ -n "$vg" ] || return 1

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

    if mountpoint -q /var/ossec 2>/dev/null; then
        has mountpoint || fail "mountpoint no está disponible."
        has mount || fail "mount no está disponible."
        has blkid || fail "blkid no está disponible."

        if ossec_mount_ready; then
            ok "/var/ossec ya está montado con exec,nosuid,nodev."
            return 0
        fi

        local source uuid fstype
        source="$(ossec_mount_source)"
        [ -n "$source" ] || fail "/var/ossec está montado pero no se pudo determinar el dispositivo."
        uuid="$(blkid -s UUID -o value "$source" 2>/dev/null || true)"
        fstype="$(blkid -s TYPE -o value "$source" 2>/dev/null || true)"
        [ -n "$uuid" ] && [ -n "$fstype" ] || fail "No se pudo determinar UUID/filesystem de $source."

        mount -o remount,exec,nosuid,nodev /var/ossec ||
            fail "No se pudo remontar /var/ossec con exec,nosuid,nodev."
        ossec_mount_ready || fail "/var/ossec no quedó con exec,nosuid,nodev."
        write_ossec_fstab "$uuid" "$fstype"
        ok "/var/ossec corregido: exec,nosuid,nodev."
        return 0
    fi

    if [ -L /var/ossec ]; then
        fail "/var/ossec es un enlace simbólico. No se modificará."
    fi

    # LVM es una optimización, no un requisito.
    if ! has vgs || ! has lvs || ! has lvcreate || ! has blkid || ! has mkfs.ext4 || ! has mount; then
        warn "LVM o sus herramientas auxiliares no están disponibles; se omitirá el volumen separado para /var/ossec."
        mkdir -p /var/ossec || fail "No se pudo crear /var/ossec."
        ok "Se continuará usando el filesystem existente para /var/ossec."
        return 0
    fi

    local vg
    vg="$(find_ossec_vg || true)"
    if [ -z "$vg" ]; then
        warn "No hay un Volume Group con al menos 1 GiB libre; se omitirá el volumen separado para /var/ossec."
        mkdir -p /var/ossec || fail "No se pudo crear /var/ossec."
        ok "Se continuará usando el filesystem existente para /var/ossec."
        return 0
    fi

    local lv_device="/dev/$vg/$WAZUH_OSSEC_LV"
    local lv_created=0
    local fstype=""

    if lvs --noheadings --options lv_name "$vg" 2>/dev/null |
        awk -v target="$WAZUH_OSSEC_LV" '$1 == target { found=1 } END { exit !found }'; then
        ok "LV $WAZUH_OSSEC_LV ya existe en VG $vg; se reutilizará."
    else
        echo "==> Creando LV $WAZUH_OSSEC_LV de $WAZUH_OSSEC_SIZE en $vg..."
        if ! lvcreate -n "$WAZUH_OSSEC_LV" -L "$WAZUH_OSSEC_SIZE" "$vg"; then
            warn "No se pudo crear el LV $WAZUH_OSSEC_LV; se continuará sin volumen separado para /var/ossec."
            mkdir -p /var/ossec || fail "No se pudo crear /var/ossec."
            return 0
        fi
        lv_created=1
    fi

    [ -b "$lv_device" ] || {
        [ "$lv_created" -eq 1 ] && lvremove -fy "$lv_device" >/dev/null 2>&1 || true
        warn "El LV $lv_device no quedó disponible; se continuará con el filesystem existente."
        mkdir -p /var/ossec || fail "No se pudo crear /var/ossec."
        return 0
    }

    fstype="$(blkid -s TYPE -o value "$lv_device" 2>/dev/null || true)"
    if [ -z "$fstype" ]; then
        echo "==> Creando filesystem ext4 en $lv_device..."
        if ! mkfs.ext4 -F "$lv_device" >/dev/null 2>&1; then
            [ "$lv_created" -eq 1 ] && lvremove -fy "$lv_device" >/dev/null 2>&1 || true
            warn "No se pudo crear el filesystem de $lv_device; se continuará sin volumen separado."
            mkdir -p /var/ossec || fail "No se pudo crear /var/ossec."
            return 0
        fi
        fstype="ext4"
    fi

    local uuid
    uuid="$(blkid -s UUID -o value "$lv_device" 2>/dev/null || true)"
    if [ -z "$uuid" ]; then
        [ "$lv_created" -eq 1 ] && lvremove -fy "$lv_device" >/dev/null 2>&1 || true
        warn "No se pudo obtener UUID de $lv_device; se continuará sin volumen separado."
        mkdir -p /var/ossec || fail "No se pudo crear /var/ossec."
        return 0
    fi

    local backup_dir=""
    local fstab_backup="/etc/fstab.orangebox-transaction.$(date +%Y%m%d%H%M%S)"
    cp -p /etc/fstab "$fstab_backup" || {
        [ "$lv_created" -eq 1 ] && lvremove -fy "$lv_device" >/dev/null 2>&1 || true
        fail "No se pudo respaldar /etc/fstab."
    }

    if [ -d /var/ossec ] && [ "$(ls -A /var/ossec 2>/dev/null)" ]; then
        backup_dir="/var/ossec.pre-lvm.$(date +%Y%m%d%H%M%S)"
        mv /var/ossec "$backup_dir" || {
            [ "$lv_created" -eq 1 ] && lvremove -fy "$lv_device" >/dev/null 2>&1 || true
            rm -f "$fstab_backup"
            fail "No se pudo preservar el contenido existente de /var/ossec."
        }
    elif [ -d /var/ossec ]; then
        rmdir /var/ossec 2>/dev/null || true
    fi

    mkdir -p /var/ossec || fail "No se pudo crear /var/ossec."

    write_ossec_fstab "$uuid" "$fstype" || {
        cp -p "$fstab_backup" /etc/fstab
        rm -f "$fstab_backup"
        rm -rf /var/ossec 2>/dev/null || true
        [ -n "$backup_dir" ] && mv "$backup_dir" /var/ossec 2>/dev/null || true
        [ "$lv_created" -eq 1 ] && lvremove -fy "$lv_device" >/dev/null 2>&1 || true
        warn "No se pudo preparar /var/ossec en LVM; se restauró el estado anterior."
        return 0
    }

    if ! mount /var/ossec; then
        cp -p "$fstab_backup" /etc/fstab
        rm -rf /var/ossec 2>/dev/null || true
        [ -n "$backup_dir" ] && mv "$backup_dir" /var/ossec 2>/dev/null || true
        [ "$lv_created" -eq 1 ] && lvremove -fy "$lv_device" >/dev/null 2>&1 || true
        warn "No se pudo montar $lv_device; se restauró el estado anterior y se continuará sin LVM."
        return 0
    fi

    if ! ossec_mount_ready; then
        umount /var/ossec >/dev/null 2>&1 || true
        cp -p "$fstab_backup" /etc/fstab
        rm -rf /var/ossec 2>/dev/null || true
        [ -n "$backup_dir" ] && mv "$backup_dir" /var/ossec 2>/dev/null || true
        [ "$lv_created" -eq 1 ] && lvremove -fy "$lv_device" >/dev/null 2>&1 || true
        warn "/var/ossec no quedó con las opciones deseadas; se restauró el estado anterior y se continuará sin LVM."
        return 0
    fi

    chmod 0755 /var/ossec

    if [ -n "$backup_dir" ]; then
        echo "==> Restaurando contenido previo de /var/ossec..."
        cp -a "$backup_dir"/. /var/ossec/ || {
            umount /var/ossec >/dev/null 2>&1 || true
            cp -p "$fstab_backup" /etc/fstab
            rm -rf /var/ossec 2>/dev/null || true
            mv "$backup_dir" /var/ossec 2>/dev/null || true
            [ "$lv_created" -eq 1 ] && lvremove -fy "$lv_device" >/dev/null 2>&1 || true
            warn "No se pudo restaurar el contenido previo; se restauró el estado anterior."
            return 0
        }
    fi

    rm -f "$fstab_backup"
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

agent_current_version() {
    rpm -q --qf '%{VERSION}\n' wazuh-agent 2>/dev/null || true
}

reconcile_agent() {
    local changed=0
    local current=""

    if ! agent_installed; then
        warn "Wazuh Agent no está instalado; se ejecutará la instalación inicial."
        install_agent
        return 0
    fi

    current="$(agent_current_version)"

    if [ "$current" = "$WAZUH_VERSION" ]; then
        ok "Wazuh Agent ya coincide con la versión deseada: $WAZUH_VERSION."
    elif [ -n "$current" ] && command -v sort >/dev/null 2>&1 &&
         [ "$(printf '%s\n' "$WAZUH_VERSION" "$current" | sort -V | tail -n1)" = "$current" ]; then
        warn "Wazuh Agent instalado ($current) es más nuevo que el deseado ($WAZUH_VERSION); no se hace downgrade."
    else
        echo "==> Actualizando Wazuh Agent: $current -> $WAZUH_VERSION..."
        if [ "$IS_CPANEL" = "yes" ]; then
            local rpm_file="$SCRIPT_DIR/wazuh-agent_$WAZUH_VERSION-0_x86_64_OPT.rpm"
            [ -n "$WAZUH_AGENT_RPM" ] && rpm_file="$WAZUH_AGENT_RPM"
            [ -f "$rpm_file" ] || fail "No existe el RPM OPT: $rpm_file"
            rpm -Uvh "$rpm_file" || fail "No se pudo actualizar Wazuh Agent OPT."
        else
            local rpm_file="/tmp/wazuh-agent-$WAZUH_VERSION-1.x86_64.rpm"
            local url="https://packages.wazuh.com/4.x/yum/wazuh-agent-$WAZUH_VERSION-1.x86_64.rpm"
            has curl || fail "curl no está instalado."
            curl -fL -o "$rpm_file" "$url" || fail "Falló la descarga de Wazuh Agent."
            rpm -Uvh "$rpm_file" || fail "No se pudo actualizar wazuh-agent."
            rm -f "$rpm_file"
        fi
        changed=1
        ok "Wazuh Agent actualizado a $WAZUH_VERSION."
    fi

    agent_installed || fail "Wazuh Agent no quedó instalado."
    [ -f "$WAZUH_HOME/etc/ossec.conf" ] || fail "No existe $WAZUH_HOME/etc/ossec.conf."

    if has systemctl; then
        if systemctl is-enabled wazuh-agent >/dev/null 2>&1; then
            ok "wazuh-agent ya está habilitado."
        else
            systemctl enable wazuh-agent >/dev/null 2>&1 || fail "No se pudo habilitar wazuh-agent."
            changed=1
            ok "wazuh-agent habilitado."
        fi

        if systemctl is-active --quiet wazuh-agent; then
            ok "wazuh-agent ya está activo."
        else
            warn "wazuh-agent no está activo; se programará su activación al final del instalador."
            changed=1
        fi
    elif has service; then
        if service wazuh-agent status >/dev/null 2>&1; then
            ok "wazuh-agent ya está activo."
        else
            warn "wazuh-agent no está activo; se programará su activación al final del instalador."
            changed=1
        fi
    fi

    if [ "$changed" -eq 1 ]; then
        request_agent_action
    fi
    return 0
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
    request_agent_action
    ok "Wazuh Agent disponible en $WAZUH_HOME: $(agent_version)"
}
activate_agent_final() {
    agent_installed || fail "No se puede activar Wazuh: el agente no está instalado."

    if has systemctl; then
        if systemctl is-enabled wazuh-agent >/dev/null 2>&1; then
            ok "wazuh-agent ya está habilitado."
        else
            systemctl enable wazuh-agent >/dev/null 2>&1 || fail "No se pudo habilitar wazuh-agent."
            ok "wazuh-agent habilitado."
        fi

        if [ "$AGENT_ACTION_REQUIRED" -eq 1 ]; then
            if systemctl is-active --quiet wazuh-agent; then
                systemctl restart wazuh-agent || fail "No se pudo reiniciar wazuh-agent."
            else
                systemctl start wazuh-agent || fail "No se pudo iniciar wazuh-agent."
            fi
            ok "wazuh-agent aplicado una sola vez al final."
        elif ! systemctl is-active --quiet wazuh-agent; then
            systemctl start wazuh-agent || fail "wazuh-agent no está activo."
            ok "wazuh-agent iniciado porque estaba detenido."
        else
            ok "wazuh-agent activo; no se reinicia."
        fi

        systemctl is-active --quiet wazuh-agent || fail "wazuh-agent no está activo."

        if [ "$IS_CPANEL" != "yes" ] && systemctl is-enabled orangebox-iptables.service >/dev/null 2>&1; then
            systemctl is-active --quiet orangebox-iptables.service ||
                systemctl start orangebox-iptables.service ||
                fail "No se pudo iniciar orangebox-iptables.service."
            systemctl is-active --quiet orangebox-iptables.service ||
                fail "orangebox-iptables.service no está activo."
        fi
    else
        if command -v chkconfig >/dev/null 2>&1; then
            chkconfig wazuh-agent on >/dev/null 2>&1 || true
        fi

        if [ "$AGENT_ACTION_REQUIRED" -eq 1 ]; then
            if service wazuh-agent status >/dev/null 2>&1; then
                service wazuh-agent restart || fail "No se pudo reiniciar wazuh-agent."
            else
                service wazuh-agent start || fail "No se pudo iniciar wazuh-agent."
            fi
            ok "wazuh-agent aplicado una sola vez al final."
        elif ! service wazuh-agent status >/dev/null 2>&1; then
            service wazuh-agent start || fail "No se pudo iniciar wazuh-agent."
            ok "wazuh-agent iniciado porque estaba detenido."
        else
            ok "wazuh-agent activo; no se reinicia."
        fi

        service wazuh-agent status >/dev/null 2>&1 || fail "wazuh-agent no está activo."
    fi

    ok "Activación final del agente completada."
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
    local desired_tmp current_tmp rules_tmp
    local changed=0

    has shorewall || fail "Shorewall está instalado pero el comando shorewall no existe."
    [ -f "$rules_file" ] || fail "Shorewall está instalado pero no existe $rules_file."

    detect_orangebox_ips

    desired_tmp="$(mktemp)" || fail "No se pudo crear temporal para Shorewall."
    cat > "$desired_tmp" <<'ORANGEBOX_START'
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

    while "$IPTABLES" -C INPUT -p tcp --tcp-flags SYN SYN \
        ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1; do
        "$IPTABLES" -D INPUT -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW || break
    done

    while "$IPTABLES" -C INPUT -p udp \
        ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1; do
        "$IPTABLES" -D INPUT -p udp \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW || break
    done

    if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
        while "$IPTABLES" -C INPUT -p tcp --tcp-flags SYN SYN \
            -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1; do
            "$IPTABLES" -D INPUT -p tcp --tcp-flags SYN SYN \
                -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || break
        done
        while "$IPTABLES" -C INPUT -p udp \
            -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1; do
            "$IPTABLES" -D INPUT -p udp \
                -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || break
        done

        "$IPTABLES" -I INPUT 1 -p tcp --tcp-flags SYN SYN \
            -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || true
        "$IPTABLES" -I INPUT 2 -p udp \
            -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || true
    fi

    "$IPTABLES" -A ORANGEBOX-FW \
        -m limit --limit 20/second --limit-burst 40 \
        -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7 || true
    "$IPTABLES" -A ORANGEBOX-FW -j RETURN || true

    if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
        "$IPTABLES" -I INPUT 3 -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW || true
        "$IPTABLES" -I INPUT 4 -p udp \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW || true
    else
        "$IPTABLES" -I INPUT 1 -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW || true
        "$IPTABLES" -I INPUT 2 -p udp \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW || true
    fi
fi
# END ORANGEBOX WAZUH FIREWALL
ORANGEBOX_START

    if [ -f "$started_file" ] && grep -Fq "# BEGIN ORANGEBOX WAZUH FIREWALL" "$started_file"; then
        current_tmp="$(mktemp)" || {
            rm -f "$desired_tmp"
            fail "No se pudo crear temporal para comparar Shorewall."
        }
        sed -n '/^# BEGIN ORANGEBOX WAZUH FIREWALL$/,/^# END ORANGEBOX WAZUH FIREWALL$/p' "$started_file" > "$current_tmp"

        if cmp -s "$current_tmp" "$desired_tmp"; then
            ok "Bloque OrangeBox de Shorewall ya coincide; no se modifica."
        else
            cp -p "$started_file" "$started_file.orangebox-backup.$(date +%Y%m%d%H%M%S)" ||
                fail "No se pudo respaldar $started_file."

            awk -v desired_file="$desired_tmp" '
                $0 == "# BEGIN ORANGEBOX WAZUH FIREWALL" {
                    while ((getline line < desired_file) > 0) print line
                    close(desired_file)
                    inside=1
                    next
                }
                $0 == "# END ORANGEBOX WAZUH FIREWALL" && inside {
                    inside=0
                    next
                }
                !inside { print }
            ' "$started_file" > "$started_file.orangebox.tmp" ||
                fail "No se pudo preparar la actualización de $started_file."

            mv "$started_file.orangebox.tmp" "$started_file" ||
                fail "No se pudo actualizar $started_file."
            chmod 755 "$started_file"
            changed=1
            ok "Bloque OrangeBox de Shorewall actualizado."
        fi
        rm -f "$current_tmp"
    else
        if [ -f "$started_file" ]; then
            cp -p "$started_file" "$started_file.orangebox-backup.$(date +%Y%m%d%H%M%S)" ||
                fail "No se pudo respaldar $started_file."
        else
            mkdir -p "$(dirname "$started_file")" || fail "No se pudo crear el directorio de Shorewall."
            : > "$started_file" || fail "No se pudo crear $started_file."
        fi
        cat "$desired_tmp" >> "$started_file" ||
            fail "No se pudo agregar el bloque OrangeBox a $started_file."
        chmod 755 "$started_file"
        changed=1
        ok "Bloque OrangeBox de Shorewall agregado."
    fi
    rm -f "$desired_tmp"

    rules_tmp="$rules_file.orangebox.tmp"
    awk '
        /^[[:space:]]*LOG:info:ORANGEBOX-FW[[:space:]]+all-[[:space:]]+\$FW[[:space:]]+tcp[[:space:]]/ { next }
        { print }
    ' "$rules_file" > "$rules_tmp" || fail "No se pudo preparar $rules_file."

    if ! cmp -s "$rules_tmp" "$rules_file"; then
        cp -p "$rules_file" "$rules_file.orangebox-backup.$(date +%Y%m%d%H%M%S)" ||
            fail "No se pudo respaldar $rules_file."
        mv "$rules_tmp" "$rules_file" || fail "No se pudo actualizar $rules_file."
        changed=1
        ok "Regla OrangeBox legacy retirada de $rules_file."
    else
        rm -f "$rules_tmp"
    fi

    shorewall check >/dev/null 2>&1 || fail "Shorewall rechazó la configuración OrangeBox."

    local runtime_ok=1
    iptables_chain_exists || runtime_ok=0

    if [ "$runtime_ok" -eq 1 ]; then
        local chain_rules expected_chain
        chain_rules="$(iptables -S ORANGEBOX-FW 2>/dev/null | sed '/^$/d')"
        expected_chain="$(printf '%s\n%s\n' \
            '-A ORANGEBOX-FW -m limit --limit 20/sec --limit-burst 40 -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7' \
            '-A ORANGEBOX-FW -j RETURN')"
        [ "$chain_rules" = "$expected_chain" ] || runtime_ok=0
    fi

    if [ "$runtime_ok" -eq 1 ] && [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
        iptables -C INPUT -p tcp --tcp-flags SYN SYN \
            -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1 || runtime_ok=0
        iptables -C INPUT -p udp \
            -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1 || runtime_ok=0
    fi

    if [ "$runtime_ok" -eq 1 ]; then
        iptables -C INPUT -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || runtime_ok=0
        iptables -C INPUT -p udp \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || runtime_ok=0
    fi

    local active=0
    if has systemctl && systemctl is-active --quiet shorewall 2>/dev/null; then
        active=1
    elif has service && service shorewall status >/dev/null 2>&1; then
        active=1
    fi

    if [ "$changed" -eq 1 ] || [ "$runtime_ok" -eq 0 ]; then
        if [ "$active" -eq 1 ]; then
            shorewall restart >/dev/null 2>&1 || fail "Shorewall debía actualizarse/repararse, pero no se pudo reiniciar."
        else
            warn "Shorewall está inactivo; la configuración persistente quedó actualizada."
        fi
    else
        ok "Runtime Shorewall/ORANGEBOX-FW ya coincide; no se reinicia."
    fi

    iptables_chain_exists || fail "La cadena ORANGEBOX-FW no quedó creada."
    iptables -C INPUT -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
        fail "INPUT no quedó conectado a ORANGEBOX-FW para TCP."
    iptables -C INPUT -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
        fail "INPUT no quedó conectado a ORANGEBOX-FW para UDP."

    ok "Shorewall OrangeBox reconciliado: public=$ORANGEBOX_PUBLIC_IP, private=$ORANGEBOX_PRIVATE_IP."
}
# iptables -C no es suficientemente portable para todas las versiones antiguas
# soportadas (especialmente EL6). La detección se hace sobre iptables -L.
iptables_chain_exists() {
    iptables -L ORANGEBOX-FW -n >/dev/null 2>&1
}

# LOG de firewall en severidad debug (7): se conserva en journald/rsyslog
# para Wazuh, pero no llega a la consola con el console_loglevel normal.
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

    detect_orangebox_ips

    local changed=0
    local actual_chain expected_chain runtime_ok=1
    local service_changed=0
    local iptables_bin="/usr/sbin/iptables"
    local iptables_save="/usr/sbin/iptables-save"

    [ -x "$iptables_bin" ] || iptables_bin="$(command -v iptables 2>/dev/null || true)"
    [ -x "$iptables_save" ] || iptables_save="$(command -v iptables-save 2>/dev/null || true)"
    [ -n "$iptables_bin" ] || {
        step_error "No se encontró el ejecutable iptables."
        return 1
    }
    [ -n "$iptables_save" ] || {
        step_error "No se encontró iptables-save."
        return 1
    }

    if ! "$iptables_bin" -L ORANGEBOX-FW -n >/dev/null 2>&1; then
        "$iptables_bin" -N ORANGEBOX-FW || {
            step_error "No se pudo crear la cadena ORANGEBOX-FW."
            return 1
        }
        changed=1
        ok "Cadena ORANGEBOX-FW creada."
    fi

    actual_chain="$("$iptables_bin" -S ORANGEBOX-FW 2>/dev/null | sed '/^$/d')"
    expected_chain="$(printf '%s\n%s\n' \
        '-A ORANGEBOX-FW -m limit --limit 20/sec --limit-burst 40 -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7' \
        '-A ORANGEBOX-FW -j RETURN')"

    if [ "$actual_chain" = "$expected_chain" ]; then
        ok "Cadena ORANGEBOX-FW ya coincide con el estado deseado."
    else
        "$iptables_bin" -F ORANGEBOX-FW || {
            step_error "No se pudo normalizar la cadena ORANGEBOX-FW."
            return 1
        }
        "$iptables_bin" -A ORANGEBOX-FW -m limit --limit 20/second --limit-burst 40 \
            -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7 || {
            step_error "No se pudo configurar LOG en ORANGEBOX-FW."
            return 1
        }
        "$iptables_bin" -A ORANGEBOX-FW -j RETURN || {
            step_error "No se pudo configurar RETURN en ORANGEBOX-FW."
            return 1
        }
        changed=1
        ok "Cadena ORANGEBOX-FW actualizada al estado deseado."
    fi

    local managed_ok=1
    local tcp_hook_count udp_hook_count tcp_exception_count udp_exception_count

    tcp_hook_count="$("$iptables_bin" -S INPUT 2>/dev/null | grep -F -- "-p tcp -m tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW" | wc -l)"
    udp_hook_count="$("$iptables_bin" -S INPUT 2>/dev/null | grep -F -- "-p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW" | wc -l)"

    if [ "$tcp_hook_count" -ne 1 ] || [ "$udp_hook_count" -ne 1 ]; then
        managed_ok=0
    fi

    if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
        tcp_exception_count="$("$iptables_bin" -S INPUT 2>/dev/null |
            grep -F -- "-s $ORANGEBOX_PUBLIC_IP/32 -d $ORANGEBOX_PRIVATE_IP/32 -p tcp" |
            grep -F -- "-j RETURN" | wc -l)"
        udp_exception_count="$("$iptables_bin" -S INPUT 2>/dev/null |
            grep -F -- "-s $ORANGEBOX_PUBLIC_IP/32 -d $ORANGEBOX_PRIVATE_IP/32 -p udp" |
            grep -F -- "-j RETURN" | wc -l)"

        [ "$tcp_exception_count" -eq 1 ] || managed_ok=0
        [ "$udp_exception_count" -eq 1 ] || managed_ok=0

        "$iptables_bin" -S INPUT | grep -E '^-A INPUT ' | sed -n '1p' |
            grep -F -- "-s $ORANGEBOX_PUBLIC_IP/32 -d $ORANGEBOX_PRIVATE_IP/32 -p tcp" |
            grep -F -- "-j RETURN" >/dev/null 2>&1 || managed_ok=0
        "$iptables_bin" -S INPUT | grep -E '^-A INPUT ' | sed -n '2p' |
            grep -F -- "-s $ORANGEBOX_PUBLIC_IP/32 -d $ORANGEBOX_PRIVATE_IP/32 -p udp" |
            grep -F -- "-j RETURN" >/dev/null 2>&1 || managed_ok=0

        "$iptables_bin" -S INPUT | grep -E '^-A INPUT ' | sed -n '3p' |
            grep -F -- "-p tcp -m tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW" >/dev/null 2>&1 || managed_ok=0
        "$iptables_bin" -S INPUT | grep -E '^-A INPUT ' | sed -n '4p' |
            grep -F -- "-p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW" >/dev/null 2>&1 || managed_ok=0
    else
        "$iptables_bin" -S INPUT | grep -E '^-A INPUT ' | sed -n '1p' |
            grep -F -- "-p tcp -m tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW" >/dev/null 2>&1 || managed_ok=0
        "$iptables_bin" -S INPUT | grep -E '^-A INPUT ' | sed -n '2p' |
            grep -F -- "-p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW" >/dev/null 2>&1 || managed_ok=0
    fi

    if [ "$managed_ok" -eq 1 ]; then
        "$iptables_bin" -S INPUT | grep -E '^-A INPUT ' | sed -n '3p' |
            grep -F -- "! -s 127.0.0.0/8 -p tcp" |
            grep -F -- "-j ORANGEBOX-FW" >/dev/null 2>&1 || managed_ok=0
        "$iptables_bin" -S INPUT | grep -E '^-A INPUT ' | sed -n '4p' |
            grep -F -- "! -s 127.0.0.0/8 -p udp" |
            grep -F -- "-j ORANGEBOX-FW" >/dev/null 2>&1 || managed_ok=0
    fi

    if [ "$managed_ok" -eq 1 ]; then
        ok "Reglas INPUT TCP/UDP y excepciones ya coinciden; no se modifican."
    else
        # Retirar únicamente los hooks OrangeBox conocidos. No se toca ninguna
        # regla de otros componentes.
        while "$iptables_bin" -C INPUT -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1; do
            "$iptables_bin" -D INPUT -p tcp --tcp-flags SYN SYN \
                ! -s 127.0.0.0/8 -j ORANGEBOX-FW || break
        done

        while "$iptables_bin" -C INPUT -p udp \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1; do
            "$iptables_bin" -D INPUT -p udp \
                ! -s 127.0.0.0/8 -j ORANGEBOX-FW || break
        done

        if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
            while "$iptables_bin" -C INPUT -p tcp --tcp-flags SYN SYN \
                -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1; do
                "$iptables_bin" -D INPUT -p tcp --tcp-flags SYN SYN \
                    -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || break
            done

            while "$iptables_bin" -C INPUT -p udp \
                -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1; do
                "$iptables_bin" -D INPUT -p udp \
                    -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || break
            done

            "$iptables_bin" -I INPUT 1 -p tcp --tcp-flags SYN SYN \
                -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || {
                step_error "No se pudo instalar la excepción TCP de la IP pública propia."
                return 1
            }
            "$iptables_bin" -I INPUT 2 -p udp \
                -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN || {
                step_error "No se pudo instalar la excepción UDP de la IP pública propia."
                return 1
            }
        fi

        if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
            "$iptables_bin" -I INPUT 3 -p tcp --tcp-flags SYN SYN \
                ! -s 127.0.0.0/8 -j ORANGEBOX-FW || {
                step_error "No se pudo instalar el hook TCP de ORANGEBOX-FW."
                return 1
            }
            "$iptables_bin" -I INPUT 4 -p udp \
                ! -s 127.0.0.0/8 -j ORANGEBOX-FW || {
                step_error "No se pudo instalar el hook UDP de ORANGEBOX-FW."
                return 1
            }
        else
            "$iptables_bin" -I INPUT 1 -p tcp --tcp-flags SYN SYN \
                ! -s 127.0.0.0/8 -j ORANGEBOX-FW || {
                step_error "No se pudo instalar el hook TCP de ORANGEBOX-FW."
                return 1
            }
            "$iptables_bin" -I INPUT 2 -p udp \
                ! -s 127.0.0.0/8 -j ORANGEBOX-FW || {
                step_error "No se pudo instalar el hook UDP de ORANGEBOX-FW."
                return 1
            }
        fi

        changed=1
        ok "Reglas INPUT TCP/UDP reconciliadas al estado deseado."
    fi

    if [ -f /etc/sysconfig/iptables ]; then
        local current_rules_tmp
        current_rules_tmp="$(mktemp)" || {
            step_error "No se pudo crear temporal para comparar persistencia iptables."
            return 1
        }
        "$iptables_save" > "$current_rules_tmp" || {
            rm -f "$current_rules_tmp"
            step_error "No se pudo obtener el estado actual de iptables-save."
            return 1
        }

        if cmp -s "$current_rules_tmp" /etc/sysconfig/iptables; then
            ok "Persistencia iptables ya coincide con el estado runtime."
        else
            cat "$current_rules_tmp" > /etc/sysconfig/iptables ||
                fail "No se pudo actualizar /etc/sysconfig/iptables."
            changed=1
            ok "Persistencia iptables actualizada."
        fi
        rm -f "$current_rules_tmp"
    else
        "$iptables_save" > /etc/sysconfig/iptables ||
            fail "No se pudo crear /etc/sysconfig/iptables."
        changed=1
        ok "Persistencia iptables creada."
    fi

    # La unidad persistente también se reconcilia: si es idéntica, no se escribe.
    if has systemctl && systemctl cat wazuh-agent.service >/dev/null 2>&1; then
        local service_tmp
        service_tmp="$(mktemp)" || fail "No se pudo crear temporal para orangebox-iptables.service."

        cat > "$service_tmp" <<EOF
[Unit]
Description=OrangeBox iptables rules for Wazuh Agent
Requires=wazuh-agent.service
After=wazuh-agent.service
PartOf=wazuh-agent.service
BindsTo=wazuh-agent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-$iptables_bin -N ORANGEBOX-FW
ExecStart=$iptables_bin -F ORANGEBOX-FW
ExecStart=$iptables_bin -A ORANGEBOX-FW -m limit --limit 20/second --limit-burst 40 -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7
ExecStart=$iptables_bin -A ORANGEBOX-FW -j RETURN
EOF

        if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
            cat >> "$service_tmp" <<EOF
ExecStart=/bin/bash -c '$iptables_bin -D INPUT -p tcp --tcp-flags SYN SYN -s $ORANGEBOX_PUBLIC_IP -d $ORANGEBOX_PRIVATE_IP -j RETURN >/dev/null 2>&1 || true; $iptables_bin -I INPUT 1 -p tcp --tcp-flags SYN SYN -s $ORANGEBOX_PUBLIC_IP -d $ORANGEBOX_PRIVATE_IP -j RETURN'
ExecStart=/bin/bash -c '$iptables_bin -D INPUT -p udp -s $ORANGEBOX_PUBLIC_IP -d $ORANGEBOX_PRIVATE_IP -j RETURN >/dev/null 2>&1 || true; $iptables_bin -I INPUT 2 -p udp -s $ORANGEBOX_PUBLIC_IP -d $ORANGEBOX_PRIVATE_IP -j RETURN'
ExecStart=/bin/bash -c '$iptables_bin -D INPUT -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || true; $iptables_bin -I INPUT 3 -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW'
ExecStart=/bin/bash -c '$iptables_bin -D INPUT -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || true; $iptables_bin -I INPUT 4 -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW'
EOF
        else
            cat >> "$service_tmp" <<EOF
ExecStart=/bin/bash -c '$iptables_bin -D INPUT -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || true; $iptables_bin -I INPUT 1 -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW'
ExecStart=/bin/bash -c '$iptables_bin -D INPUT -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || true; $iptables_bin -I INPUT 2 -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW'
EOF
        fi

        cat >> "$service_tmp" <<EOF
ExecStart=/bin/bash -c '$iptables_save > /etc/sysconfig/iptables'

[Install]
WantedBy=wazuh-agent.service
EOF

        if sync_managed_file "$service_tmp" "$WAZUH_FIREWALL_SERVICE" 644 root root; then
            service_changed=1
            ok "orangebox-iptables.service actualizado."
        else
            ok "orangebox-iptables.service ya coincide; no se modifica."
        fi

        systemd-analyze verify "$WAZUH_FIREWALL_SERVICE" >/dev/null 2>&1 ||
            fail "La unidad orangebox-iptables.service no pasó la validación de systemd."

        systemctl daemon-reload || fail "systemctl daemon-reload falló."

        if ! systemctl is-enabled orangebox-iptables.service >/dev/null 2>&1; then
            systemctl enable orangebox-iptables.service >/dev/null 2>&1 ||
                fail "No se pudo habilitar orangebox-iptables.service."
            changed=1
            ok "orangebox-iptables.service habilitado."
        fi

        if [ "$service_changed" -eq 1 ] || [ "$changed" -eq 1 ]; then
            systemctl restart orangebox-iptables.service >/dev/null 2>&1 ||
                fail "No se pudo aplicar orangebox-iptables.service."
            ok "orangebox-iptables.service aplicado."
        elif ! systemctl is-active --quiet orangebox-iptables.service; then
            systemctl start orangebox-iptables.service >/dev/null 2>&1 ||
                fail "No se pudo iniciar orangebox-iptables.service."
            ok "orangebox-iptables.service iniciado."
        else
            ok "orangebox-iptables.service activo; no se reinicia."
        fi
    else
        warn "wazuh-agent.service todavía no existe; no se crea la unidad persistente del firewall."
    fi

    # Verificación final exacta.
    "$iptables_bin" -C ORANGEBOX-FW -m limit --limit 20/second --limit-burst 40 \
        -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7 >/dev/null 2>&1 ||
        fail "Falta la regla LOG deseada en ORANGEBOX-FW."

    "$iptables_bin" -C ORANGEBOX-FW -j RETURN >/dev/null 2>&1 ||
        fail "Falta RETURN en ORANGEBOX-FW."

    "$iptables_bin" -C INPUT -p tcp --tcp-flags SYN SYN \
        ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
        fail "Falta el hook TCP de ORANGEBOX-FW."

    "$iptables_bin" -C INPUT -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
        fail "Falta el hook UDP de ORANGEBOX-FW."

    ok "Configuración ORANGEBOX-FW de iptables reconciliada y validada."
    return 0
}

disable_orangebox_iptables_service() {
    has systemctl || return 0
    local service_file="$WAZUH_FIREWALL_SERVICE"
    if [ -f "$service_file" ] && grep -Fq "Description=OrangeBox iptables rules for Wazuh Agent" "$service_file"; then
        systemctl disable --now orangebox-iptables.service >/dev/null 2>&1 || true
        rm -f "$service_file" || fail "No se pudo retirar $service_file al usar firewalld."
        systemctl daemon-reload || fail "No se pudo recargar systemd después de retirar orangebox-iptables.service."
        ok "orangebox-iptables.service deshabilitado porque firewalld es el backend activo."
    fi
}

cleanup_legacy_orangebox_firewalld() {
    local direct_file="/etc/firewalld/direct.xml"
    local backup_file=""
    local check_cmd=""
    [ -f "$direct_file" ] || return 0

    if has firewall-offline-cmd; then
        check_cmd="firewall-offline-cmd"
    elif has firewall-cmd; then
        check_cmd="firewall-cmd"
    fi

    if grep -Fq "ORANGEBOX-FW" "$direct_file" &&        { grep -Eq "'-p tcp|--log-level 4" "$direct_file" ||          { [ -n "$check_cmd" ] && ! "$check_cmd" --check-config >/dev/null 2>&1; }; }; then
        backup_file="$direct_file.orangebox-backup.$(date +%Y%m%d%H%M%S)"
        cp -p "$direct_file" "$backup_file" || fail "No se pudo respaldar $direct_file."
        awk '!/ORANGEBOX-FW/' "$direct_file" > /etc/firewalld/direct.xml.orangebox.tmp ||             fail "No se pudo preparar la limpieza de reglas OrangeBox antiguas."
        mv /etc/firewalld/direct.xml.orangebox.tmp "$direct_file" ||             fail "No se pudo actualizar $direct_file."
        if [ -n "$check_cmd" ] && ! "$check_cmd" --check-config >/dev/null 2>&1; then
            cp -p "$backup_file" "$direct_file" || true
            fail "La limpieza de reglas OrangeBox dejó inválida la configuración de firewalld; se restauró el respaldo."
        fi
        ok "Reglas OrangeBox antiguas de firewalld retiradas; respaldo: $backup_file."
    fi
}

configure_firewalld() {
    has firewall-cmd || fail "firewalld está activo pero firewall-cmd no existe."

    disable_orangebox_iptables_service
    cleanup_legacy_orangebox_firewalld
    detect_orangebox_ips

    local changed=0

    # Estado deseado:
    # INPUT priority 0: excepción TCP propia
    # INPUT priority 1: excepción UDP propia
    # INPUT priority 2: TCP SYN -> ORANGEBOX-FW
    # INPUT priority 3: UDP -> ORANGEBOX-FW
    # ORANGEBOX-FW priority 0: LOG
    # ORANGEBOX-FW priority 1: RETURN

    if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
        if ! firewall-cmd --permanent --direct --query-rule ipv4 filter INPUT 0 \
            -p tcp --tcp-flags SYN SYN -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1 ||
           ! firewall-cmd --permanent --direct --query-rule ipv4 filter INPUT 1 \
            -p udp -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1 ||
           ! firewall-cmd --permanent --direct --query-rule ipv4 filter INPUT 2 \
            -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
           ! firewall-cmd --permanent --direct --query-rule ipv4 filter INPUT 3 \
            -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
           ! firewall-cmd --permanent --direct --query-rule ipv4 filter ORANGEBOX-FW 0 \
            -m limit --limit 20/second --limit-burst 40 \
            -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7 >/dev/null 2>&1 ||
           ! firewall-cmd --permanent --direct --query-rule ipv4 filter ORANGEBOX-FW 1 \
            -j RETURN >/dev/null 2>&1; then
            changed=1
        fi
    else
        warn "No se pudieron determinar ambas IP; se configurará firewalld sin excepciones de IP propia."
        if ! firewall-cmd --permanent --direct --query-rule ipv4 filter INPUT 0 \
            -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
           ! firewall-cmd --permanent --direct --query-rule ipv4 filter INPUT 1 \
            -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1; then
            changed=1
        fi
    fi

    if ! firewall-cmd --permanent --direct --get-chains ipv4 filter 2>/dev/null |
        grep -Fxq "ORANGEBOX-FW"; then
        changed=1
    fi

    if [ "$changed" -eq 1 ]; then
        firewall-cmd --permanent --direct --add-chain ipv4 filter ORANGEBOX-FW >/dev/null 2>&1 || true

        # Retirar variantes conocidas de la configuración OrangeBox anterior.
        if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p tcp --tcp-flags SYN SYN -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1 || true
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p udp -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1 || true
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 1 \
                -p udp -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1 || true
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || true
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 2 \
                -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || true
        else
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || true
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 1 \
                -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 || true
        fi

        firewall-cmd --permanent --direct --remove-rule ipv4 filter ORANGEBOX-FW 0 \
            -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 \
            -m limit --limit 20/second --limit-burst 40 \
            -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7 >/dev/null 2>&1 || true
        firewall-cmd --permanent --direct --remove-rule ipv4 filter ORANGEBOX-FW 0 \
            -m limit --limit 20/second --limit-burst 40 \
            -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7 >/dev/null 2>&1 || true
        firewall-cmd --permanent --direct --remove-rule ipv4 filter ORANGEBOX-FW 1 -j RETURN >/dev/null 2>&1 || true

        if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
                -p tcp --tcp-flags SYN SYN -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN ||
                fail "No se pudo configurar la excepción TCP en firewalld."
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
                -p udp -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN ||
                fail "No se pudo configurar la excepción UDP en firewalld."
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 2 \
                -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW ||
                fail "No se pudo configurar el hook TCP en firewalld."
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 3 \
                -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW ||
                fail "No se pudo configurar el hook UDP en firewalld."
        else
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
                -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW ||
                fail "No se pudo configurar el hook TCP en firewalld."
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
                -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW ||
                fail "No se pudo configurar el hook UDP en firewalld."
        fi

        firewall-cmd --permanent --direct --add-rule ipv4 filter ORANGEBOX-FW 0 \
            -m limit --limit 20/second --limit-burst 40 \
            -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7 ||
            fail "No se pudo configurar LOG en ORANGEBOX-FW."
        firewall-cmd --permanent --direct --add-rule ipv4 filter ORANGEBOX-FW 1 -j RETURN ||
            fail "No se pudo configurar RETURN en ORANGEBOX-FW."

        firewall-cmd --reload || fail "No se pudo recargar firewalld."
        ok "Firewalld OrangeBox actualizado."
    else
        ok "Firewalld OrangeBox ya coincide con el estado deseado; no se modifica ni recarga."
    fi

    firewall-cmd --direct --get-chains ipv4 filter 2>/dev/null |
        grep -Fxq "ORANGEBOX-FW" ||
        fail "La cadena runtime ORANGEBOX-FW no quedó activa."

    firewall-cmd --direct --query-rule ipv4 filter ORANGEBOX-FW 0 \
        -m limit --limit 20/second --limit-burst 40 \
        -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7 >/dev/null 2>&1 ||
        fail "La regla LOG runtime no quedó activa."

    firewall-cmd --direct --query-rule ipv4 filter ORANGEBOX-FW 1 -j RETURN >/dev/null 2>&1 ||
        fail "El RETURN runtime no quedó activo."

    if [ -n "$ORANGEBOX_PUBLIC_IP" ] && [ -n "$ORANGEBOX_PRIVATE_IP" ]; then
        firewall-cmd --direct --query-rule ipv4 filter INPUT 0 \
            -p tcp --tcp-flags SYN SYN -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1 ||
            fail "La excepción TCP runtime no quedó activa."
        firewall-cmd --direct --query-rule ipv4 filter INPUT 1 \
            -p udp -s "$ORANGEBOX_PUBLIC_IP" -d "$ORANGEBOX_PRIVATE_IP" -j RETURN >/dev/null 2>&1 ||
            fail "La excepción UDP runtime no quedó activa."
        firewall-cmd --direct --query-rule ipv4 filter INPUT 2 \
            -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
            fail "El hook TCP runtime no quedó activo."
        firewall-cmd --direct --query-rule ipv4 filter INPUT 3 \
            -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
            fail "El hook UDP runtime no quedó activo."
    else
        firewall-cmd --direct --query-rule ipv4 filter INPUT 0 \
            -p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
            fail "El hook TCP runtime no quedó activo."
        firewall-cmd --direct --query-rule ipv4 filter INPUT 1 \
            -p udp ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
            fail "El hook UDP runtime no quedó activo."
    fi

    ok "Firewalld OrangeBox reconciliado: INPUT -> excepciones -> ORANGEBOX-FW -> LOG -> RETURN."
}
configure_cpanel_firewall() {
    local csf_conf="/etc/csf/csf.conf"
    local csf_post="/usr/local/csf/bin/csfpost.sh"

    # cPanel no implica necesariamente CSF. Preferir CSF si realmente está
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
                    line=$0
                    sub(/#.*/, "", line)
                    sub(/^[^=]*=/, "", line)
                    gsub(/[[:space:]"]/ , "", line)
                    n=split(line, ports, ",")
                    for (i=1; i<=n; i++) {
                        if (ports[i] == p) {
                            found=1
                            break
                        }
                    }
                }
                END { exit !found }
            ' "$csf_conf"
        }
        local changed=0

        if csf_tcp_out_has_port 1514 && csf_tcp_out_has_port 1515; then
            ok "CSF TCP_OUT ya contiene 1514 y 1515."
        else
            cp -p "$csf_conf" "$csf_conf.orangebox-backup.$(date +%Y%m%d%H%M%S)" ||
                fail "No se pudo respaldar $csf_conf."

            awk '
                /^[[:space:]]*TCP_OUT[[:space:]]*=/ && $0 !~ /^[[:space:]]*#/ {
                    line=$0
                    if (line !~ /1514([,:"]|$)/) sub(/"$/, ",1514\"", line)
                    if (line !~ /1515([,:"]|$)/) sub(/"$/, ",1515\"", line)
                    print line
                    next
                }
                { print }
            ' "$csf_conf" > "$csf_conf.orangebox.tmp" ||
                fail "No se pudo preparar $csf_conf."

            mv "$csf_conf.orangebox.tmp" "$csf_conf" ||
                fail "No se pudo actualizar $csf_conf."

            changed=1
            ok "CSF TCP_OUT actualizado con 1514,1515."
        fi

        detect_orangebox_ips
        local public_ip="$ORANGEBOX_PUBLIC_IP"
        local private_ip="$ORANGEBOX_PRIVATE_IP"

        local firewall="/usr/local/sbin/orangebox-firewall"
        local firewall_tmp
        firewall_tmp="$(mktemp)" || fail "No se pudo crear temporal para $firewall."

        cat > "$firewall_tmp" <<EOF
#!/bin/bash
set -u

IPTABLES=/usr/sbin/iptables
PUBLIC_IP="$public_ip"
PRIVATE_IP="$private_ip"

chain_ok() {
    [ -x "\$IPTABLES" ] || return 1
    local actual expected
    actual="\$(\$IPTABLES -S ORANGEBOX-FW 2>/dev/null | sed '/^$/d')"
    expected="\$(printf '%s\\n%s\\n' \
        '-A ORANGEBOX-FW -m limit --limit 20/sec --limit-burst 40 -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7' \
        '-A ORANGEBOX-FW -j RETURN')"
    [ "\$actual" = "\$expected" ]
}

runtime_ok() {
    chain_ok || return 1

    if [ -n "\$PUBLIC_IP" ] && [ -n "\$PRIVATE_IP" ]; then
        \$IPTABLES -S INPUT | grep -E '^-A INPUT ' | sed -n '1p' |
            grep -F -- "-s \$PUBLIC_IP/32 -d \$PRIVATE_IP/32 -p tcp" |
            grep -F -- "-j RETURN" >/dev/null 2>&1 || return 1
        \$IPTABLES -S INPUT | grep -E '^-A INPUT ' | sed -n '2p' |
            grep -F -- "-s \$PUBLIC_IP/32 -d \$PRIVATE_IP/32 -p udp" |
            grep -F -- "-j RETURN" >/dev/null 2>&1 || return 1

        \$IPTABLES -S INPUT | grep -E '^-A INPUT ' | sed -n '3p' |
            grep -F -- "! -s 127.0.0.0/8 -p tcp" |
            grep -F -- "-j ORANGEBOX-FW" >/dev/null 2>&1 || return 1
        \$IPTABLES -S INPUT | grep -E '^-A INPUT ' | sed -n '4p' |
            grep -F -- "! -s 127.0.0.0/8 -p udp" |
            grep -F -- "-j ORANGEBOX-FW" >/dev/null 2>&1 || return 1
    else
        \$IPTABLES -S INPUT | grep -E '^-A INPUT ' | sed -n '1p' |
            grep -F -- "! -s 127.0.0.0/8 -p tcp" |
            grep -F -- "-j ORANGEBOX-FW" >/dev/null 2>&1 || return 1
        \$IPTABLES -S INPUT | grep -E '^-A INPUT ' | sed -n '2p' |
            grep -F -- "! -s 127.0.0.0/8 -p udp" |
            grep -F -- "-j ORANGEBOX-FW" >/dev/null 2>&1 || return 1
    fi

    return 0
}

sync_firewall() {
    "\$IPTABLES" -N ORANGEBOX-FW 2>/dev/null || true

    if runtime_ok; then
        exit 0
    fi

    "\$IPTABLES" -F ORANGEBOX-FW

    while "\$IPTABLES" -C INPUT -p tcp --tcp-flags SYN SYN \
        ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1; do
        "\$IPTABLES" -D INPUT -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW || break
    done

    while "\$IPTABLES" -C INPUT -p udp \
        ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1; do
        "\$IPTABLES" -D INPUT -p udp \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW || break
    done

    if [ -n "\$PUBLIC_IP" ] && [ -n "\$PRIVATE_IP" ]; then
        while "\$IPTABLES" -C INPUT -p tcp --tcp-flags SYN SYN \
            -s "\$PUBLIC_IP" -d "\$PRIVATE_IP" -j RETURN >/dev/null 2>&1; do
            "\$IPTABLES" -D INPUT -p tcp --tcp-flags SYN SYN \
                -s "\$PUBLIC_IP" -d "\$PRIVATE_IP" -j RETURN || break
        done

        while "\$IPTABLES" -C INPUT -p udp \
            -s "\$PUBLIC_IP" -d "\$PRIVATE_IP" -j RETURN >/dev/null 2>&1; do
            "\$IPTABLES" -D INPUT -p udp \
                -s "\$PUBLIC_IP" -d "\$PRIVATE_IP" -j RETURN || break
        done

        "\$IPTABLES" -I INPUT 1 -p tcp --tcp-flags SYN SYN \
            -s "\$PUBLIC_IP" -d "\$PRIVATE_IP" -j RETURN
        "\$IPTABLES" -I INPUT 2 -p udp \
            -s "\$PUBLIC_IP" -d "\$PRIVATE_IP" -j RETURN
        "\$IPTABLES" -I INPUT 3 -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW
        "\$IPTABLES" -I INPUT 4 -p udp \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW
    else
        "\$IPTABLES" -I INPUT 1 -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW
        "\$IPTABLES" -I INPUT 2 -p udp \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW
    fi

    "\$IPTABLES" -A ORANGEBOX-FW \
        -m limit --limit 20/second --limit-burst 40 \
        -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 7
    "\$IPTABLES" -A ORANGEBOX-FW -j RETURN
}

sync_firewall
EOF

        if sync_managed_file "$firewall_tmp" "$firewall" 700 root root; then
            changed=1
            ok "Helper OrangeBox de CSF actualizado."
        else
            ok "Helper OrangeBox de CSF ya coincide; no se modifica."
        fi

        if ! grep -Fxq "$firewall" "$csf_post" 2>/dev/null; then
            cp -p "$csf_post" "$csf_post.orangebox-backup.$(date +%Y%m%d%H%M%S)" ||
                fail "No se pudo respaldar $csf_post."

            { cat "$csf_post"; echo; echo "# OrangeBox - Wazuh firewall logging"; echo "$firewall"; } \
                > "$csf_post.orangebox.tmp" ||
                fail "No se pudo preparar $csf_post."

            chmod --reference="$csf_post" "$csf_post.orangebox.tmp" 2>/dev/null || chmod 700 "$csf_post.orangebox.tmp"
            chown --reference="$csf_post" "$csf_post.orangebox.tmp" 2>/dev/null || true
            mv "$csf_post.orangebox.tmp" "$csf_post" ||
                fail "No se pudo actualizar $csf_post."

            changed=1
            ok "Hook OrangeBox agregado a $csf_post."
        else
            ok "Hook OrangeBox ya existe en $csf_post."
        fi

        if [ "$changed" -eq 1 ]; then
            local csf_reload_log="/tmp/orangebox-csf-reload.log"
            if ! csf -r >"$csf_reload_log" 2>&1; then
                echo "ERROR: CSF rechazó la configuración. Última salida:" >&2
                tail -n 40 "$csf_reload_log" >&2 2>/dev/null || cat "$csf_reload_log" >&2
                rm -f "$csf_reload_log"
                return 1
            fi
            rm -f "$csf_reload_log"
            ok "CSF recargado porque la configuración cambió."
        fi

        "$firewall" || fail "No se pudieron reconciliar las reglas ORANGEBOX-FW."

        iptables -L ORANGEBOX-FW -n >/dev/null 2>&1 ||
            fail "No existe ORANGEBOX-FW."

        iptables -C INPUT -p tcp --tcp-flags SYN SYN \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
            fail "INPUT no quedó conectado a ORANGEBOX-FW para TCP."

        iptables -C INPUT -p udp \
            ! -s 127.0.0.0/8 -j ORANGEBOX-FW >/dev/null 2>&1 ||
            fail "INPUT no quedó conectado a ORANGEBOX-FW para UDP."

        csf_tcp_out_has_port 1514 || fail "TCP_OUT no contiene 1514."
        csf_tcp_out_has_port 1515 || fail "TCP_OUT no contiene 1515."

        ok "CSF/OrangeBox reconciliado."
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
    local failed=0

    if [ "$IS_CPANEL" = "yes" ]; then
        if configure_cpanel_firewall; then
            :
        else
            echo "ERROR: el backend de firewall cPanel falló." >&2
            failed=1
        fi
        return "$failed"
    fi

    if shorewall_installed; then
        ok "Shorewall instalado; usando configuración persistente de Shorewall."
        if ! (configure_shorewall); then
            echo "ERROR: el paso Shorewall falló; se continuará con logging." >&2
            failed=1
        fi
    elif has firewall-cmd && has systemctl && \
        systemctl is-active --quiet firewalld 2>/dev/null && \
        ! systemctl is-enabled firewalld 2>/dev/null | grep -qx "masked" && \
        firewall-cmd --state 2>/dev/null | grep -qx "running"; then
        ok "firewalld activo y en ejecución; usando firewalld."
        if ! (configure_firewalld); then
            echo "ERROR: el paso firewalld falló; no se iniciará el servicio OrangeBox de iptables." >&2
            failed=1
        fi
    else
        ok "Shorewall no instalado y firewalld no está activo; usando iptables."
        if ! configure_iptables; then
            echo "ERROR: el paso iptables falló; se continuará con logging." >&2
            failed=1
        fi
    fi

    return "$failed"
}

# ---------------------------------------------------------------------------
# 3. Logging EL6: rsyslog
# ---------------------------------------------------------------------------

rsyslog_rule_exists() {
    [ -f "$RSYSLOG_FILE" ] && \
        grep -Fq ':msg, contains, "ORANGEBOX-FW" -/var/log/orangebox-firewall.log' "$RSYSLOG_FILE" && \
        grep -Fxq ':msg, contains, "ORANGEBOX-FW" ~' "$RSYSLOG_FILE" && \
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

    local rsyslog_changed=0

    if [ -f "$RSYSLOG_FILE" ]; then
        if grep -Fqx ':msg, contains, "ORANGEBOX-FW" -/var/log/orangebox-firewall.log' "$RSYSLOG_FILE" &&
           grep -Fqx ':msg, contains, "ORANGEBOX-FW" ~' "$RSYSLOG_FILE" &&
           grep -Fqx ':msg, contains, "LOG:ORANGEB" -/var/log/orangebox-firewall.log' "$RSYSLOG_FILE" &&
           grep -Fqx ':msg, contains, "LOG:ORANGEB" ~' "$RSYSLOG_FILE"; then
            ok "Configuración rsyslog OrangeBox ya coincide; no se modifica."
        else
            local desired_tmp
            desired_tmp="$(mktemp)" || fail "No se pudo crear temporal para rsyslog."
            cat > "$desired_tmp" <<'EOF'
# OrangeBox - Wazuh firewall logging
:msg, contains, "ORANGEBOX-FW" -/var/log/orangebox-firewall.log
:msg, contains, "ORANGEBOX-FW" ~
:msg, contains, "LOG:ORANGEB" -/var/log/orangebox-firewall.log
:msg, contains, "LOG:ORANGEB" ~
EOF
            sync_managed_file "$desired_tmp" "$RSYSLOG_FILE" 644 root root >/dev/null
            rsyslog_changed=1
            ok "Configuración rsyslog OrangeBox actualizada."
        fi
    else
        local desired_tmp
        desired_tmp="$(mktemp)" || fail "No se pudo crear temporal para rsyslog."
        cat > "$desired_tmp" <<'EOF'
# OrangeBox - Wazuh firewall logging
:msg, contains, "ORANGEBOX-FW" -/var/log/orangebox-firewall.log
:msg, contains, "ORANGEBOX-FW" ~
:msg, contains, "LOG:ORANGEB" -/var/log/orangebox-firewall.log
:msg, contains, "LOG:ORANGEB" ~
EOF
        sync_managed_file "$desired_tmp" "$RSYSLOG_FILE" 644 root root >/dev/null
        rsyslog_changed=1
        ok "Configuración rsyslog OrangeBox creada."
    fi

    # Migración puntual de una regla OrangeBox antigua en /etc/rsyslog.conf.
    if remove_legacy_rsyslog_rule; then
        rsyslog_changed=1
    fi

    rsyslog_rule_exists || fail "No se pudo validar la configuración rsyslog OrangeBox."
    rsyslogd -N1 >/dev/null 2>&1 || fail "rsyslogd rechazó la configuración."

    if [ "$rsyslog_changed" -eq 1 ]; then
        if has systemctl; then
            systemctl restart rsyslog || fail "No se pudo reiniciar rsyslog."
        else
            service rsyslog restart || fail "No se pudo reiniciar rsyslog."
        fi
    else
        ok "rsyslog no requiere reinicio."
    fi

    if [ -f "$FIREWALL_LOG" ]; then
        local current_mode current_owner current_group
        current_mode="$(stat -c '%a' "$FIREWALL_LOG" 2>/dev/null || true)"
        current_owner="$(stat -c '%U' "$FIREWALL_LOG" 2>/dev/null || true)"
        current_group="$(stat -c '%G' "$FIREWALL_LOG" 2>/dev/null || true)"
        if [ "$current_mode" != "640" ]; then chmod 640 "$FIREWALL_LOG"; fi
        if [ "$current_owner" != "root" ]; then chown root "$FIREWALL_LOG"; fi
        if [ "$current_group" != "root" ]; then chgrp root "$FIREWALL_LOG"; fi
    else
        touch "$FIREWALL_LOG" || fail "No se pudo crear $FIREWALL_LOG."
        chmod 640 "$FIREWALL_LOG"
        chown root:root "$FIREWALL_LOG"
    fi

    ok "rsyslog validado para EL6."
}

# ---------------------------------------------------------------------------
# 4. Logging EL7+: journald
# ---------------------------------------------------------------------------

configure_journald() {
    has journalctl || fail "journalctl no está disponible; no se puede usar journald."
    has logger || fail "logger no está disponible para validar journald."

    journalctl -n 1 --no-pager >/dev/null 2>&1 ||
        fail "No se pudo consultar journald."

    # En EL7+ OrangeBox no necesita modificar journald: solo verifica que el
    # backend requerido esté disponible. No genera eventos de prueba ni cambia
    # archivos cuando el estado ya es correcto.
    ok "journald disponible y en el estado esperado; no se modifica."
}

# ---------------------------------------------------------------------------
# 5. logrotate
# ---------------------------------------------------------------------------

configure_logrotate() {
    has logrotate || fail "logrotate no está instalado."

    local desired_tmp
    desired_tmp="$(mktemp)" || fail "No se pudo crear temporal para logrotate."

    cat > "$desired_tmp" <<'EOF'
/var/log/orangebox-firewall.log {
    daily
    rotate 0
    missingok
    notifempty
    copytruncate
}
EOF

    if [ -f "$LOGROTATE_FILE" ] && cmp -s "$desired_tmp" "$LOGROTATE_FILE"; then
        ok "Configuración logrotate OrangeBox ya coincide; no se modifica."
        rm -f "$desired_tmp"
    else
        sync_managed_file "$desired_tmp" "$LOGROTATE_FILE" 644 root root >/dev/null
        ok "Configuración logrotate OrangeBox actualizada."
    fi

    logrotate -d "$LOGROTATE_FILE" >/dev/null 2>&1 ||
        fail "logrotate rechazó la configuración."

    grep -Fqx '    daily' "$LOGROTATE_FILE" || fail "Falta daily."
    grep -Fqx '    rotate 0' "$LOGROTATE_FILE" || fail "Falta rotate 0."
    grep -Fqx '    copytruncate' "$LOGROTATE_FILE" || fail "Falta copytruncate."

    ok "logrotate validado para EL6."
}

# ---------------------------------------------------------------------------
# 6. Ejecución
# ---------------------------------------------------------------------------

configure_logging() {
    case "$LOGGING_BACKEND" in
        rsyslog)
            configure_rsyslog || return 1
            configure_logrotate || return 1
            ;;
        journald)
            configure_journald || return 1
            ;;
        *)
            fail "Backend de logging no definido o no soportado: ${LOGGING_BACKEND:-vacío}."
            ;;
    esac
}

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

echo
echo "==> Detectando plataforma..."
if detect_platform; then
    record_step_ok "Plataforma / backend de logging"
else
    record_step_failed "Plataforma / backend de logging"
    echo "ERROR: no se pudo determinar la plataforma; se continuará con las etapas restantes." >&2
fi

run_step "Wazuh Agent" reconcile_agent

run_step "Firewall" configure_firewall
run_step "Logging" configure_logging
# El agente se activa una sola vez al final, si alguna etapa lo requiere.

# ---------------------------------------------------------------------------
# 7. Componentes OrangeBox integrados: auditd + YARA
# ---------------------------------------------------------------------------
configure_exec_audit() {
    local RULE_FILE="/etc/audit/rules.d/70-orangebox-wazuh.rules"
    local KEY_TEMP="orangebox_exec"
    local WAZUH_CONF="$WAZUH_HOME/etc/ossec.conf"
    local rules_changed=0
    local ossec_changed=0
    local packages_changed=0

    [[ $EUID -eq 0 ]] || {
        echo "ERROR: ejecutar como root." >&2
        return 1
    }

    ensure_python3 || return 1

    echo "==> Verificando paquetes audit..."

    if ! rpm -q audit >/dev/null 2>&1; then
        echo "==> Instalando audit..."
        if has dnf; then
            dnf install -y audit || fail "No se pudo instalar auditd."
        elif has yum; then
            yum install -y audit || fail "No se pudo instalar auditd."
        else
            fail "No existe dnf/yum para instalar auditd."
        fi
        packages_changed=1
    fi

    if [[ "$EL_MAJOR" -ge 10 ]] 2>/dev/null && ! rpm -q audit-rules >/dev/null 2>&1; then
        echo "==> Instalando audit-rules para Enterprise Linux $EL_MAJOR..."
        if has dnf; then
            dnf install -y audit-rules || fail "No se pudo instalar audit-rules."
        elif has yum; then
            yum install -y audit-rules || fail "No se pudo instalar audit-rules."
        else
            fail "No existe dnf/yum para instalar audit-rules."
        fi
        packages_changed=1
    fi

    if ! rpm -q audispd-plugins >/dev/null 2>&1; then
        echo "==> Instalando audispd-plugins..."
        if has dnf; then
            dnf install -y audispd-plugins || fail "No se pudo instalar audispd-plugins."
        elif has yum; then
            yum install -y audispd-plugins || fail "No se pudo instalar audispd-plugins."
        else
            fail "No existe dnf/yum para instalar audispd-plugins."
        fi
        packages_changed=1
    fi

    # OrangeBox procesa los eventos de ejecución directamente desde audit.log
    # mediante la integración nativa de Wazuh. No dependemos de audisp-af_unix.
    # En EL7 (audit 2.x) ese ejecutable no existe y no es necesario.
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

    # Migrar solo archivos legacy todavía existentes.
    local legacy_audit_file="/etc/audit/rules.d/99-orangebox-exec.rules"
    if [ -f "$legacy_audit_file" ] && grep -Eq '(orangebox_exec|audit-wazuh-c)' "$legacy_audit_file"; then
        cp -p "$legacy_audit_file" "$legacy_audit_file.orangebox-backup.$(date +%Y%m%d%H%M%S)" ||
            fail "No se pudo respaldar $legacy_audit_file."
        rm -f "$legacy_audit_file" || fail "No se pudo retirar $legacy_audit_file."
        rules_changed=1
        ok "Regla auditd legacy retirada."
    fi

    local old_orangebox_audit="/etc/audit/rules.d/orangebox-wazuh.rules"
    if [ -f "$old_orangebox_audit" ]; then
        cp -p "$old_orangebox_audit" "$old_orangebox_audit.orangebox-backup.$(date +%Y%m%d%H%M%S)" ||
            fail "No se pudo respaldar $old_orangebox_audit."
        rm -f "$old_orangebox_audit" || fail "No se pudo retirar $old_orangebox_audit."
        rules_changed=1
        ok "Regla auditd legacy retirada."
    fi

    local desired_rules_tmp
    desired_rules_tmp="$(mktemp)" || fail "No se pudo crear temporal para reglas auditd."

    cat > "$desired_rules_tmp" <<'EOF'
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

        if [ "$EL_MAJOR" = "6" ]; then
            local rule="-w $path -p x -k audit-wazuh-c"
            grep -Fqx -- "$rule" "$desired_rules_tmp" || printf '%s\n' "$rule" >> "$desired_rules_tmp"
        else
            for arch in b64 b32; do
                local rule="-a always,exit -F arch=$arch -S execve -F exe=$path -F auid>=0 -F auid!=4294967295 -k audit-wazuh-c"
                grep -Fqx -- "$rule" "$desired_rules_tmp" ||
                    printf '%s\n' "$rule" >> "$desired_rules_tmp"
            done
        fi
    }

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

    for command in "${SCANNER_COMMANDS[@]}" "${RECON_COMMANDS[@]}"; do
        add_behavior_rule "$command"
    done

    if [ ! -f "$RULE_FILE" ] || ! cmp -s "$desired_rules_tmp" "$RULE_FILE"; then
        if [ -f "$RULE_FILE" ]; then
            cp -p "$RULE_FILE" "$RULE_FILE.orangebox-backup.$(date +%Y%m%d%H%M%S)" ||
                fail "No se pudo respaldar $RULE_FILE."
        fi
        install -m 640 -o root -g root "$desired_rules_tmp" "$RULE_FILE" ||
            fail "No se pudo actualizar $RULE_FILE."
        rules_changed=1
        ok "Reglas auditd OrangeBox actualizadas."
    else
        rm -f "$desired_rules_tmp"
        ok "Reglas auditd OrangeBox ya coinciden; no se modifica."
    fi

    if [ -f "$WAZUH_CONF" ]; then
        if grep -Fq '<log_format>audit</log_format>' "$WAZUH_CONF" &&
           grep -Fq '<location>/var/log/audit/audit.log</location>' "$WAZUH_CONF"; then
            ok "Wazuh ya lee audit.log; no se modifica ossec.conf."
        else
            cp -p "$WAZUH_CONF" "$WAZUH_CONF.before-orangebox-exec.$(date +%Y%m%d%H%M%S)" ||
                fail "No se pudo respaldar $WAZUH_CONF."
            "$PYTHON3_BIN" - "$WAZUH_CONF" <<'PY'
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
if block not in s:
    idx = s.rfind("</ossec_config>")
    if idx < 0:
        raise SystemExit("ERROR: no se encontró </ossec_config>.")
    p.write_text(s[:idx] + block + s[idx:])
PY
            ossec_changed=1
            ok "Wazuh configurado para leer audit.log."
        fi
    fi

    if has systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^auditd\.service'; then
        if systemctl is-enabled auditd >/dev/null 2>&1; then
            ok "auditd ya está habilitado; no se modifica."
        else
            systemctl enable auditd >/dev/null 2>&1 ||
                warn "No se pudo habilitar auditd con systemctl."
            packages_changed=1
        fi
    fi

    if has service && service auditd status >/dev/null 2>&1; then
        if [ "$packages_changed" -eq 1 ]; then
            service auditd restart || fail "No se pudo reiniciar auditd."
        else
            ok "auditd ya está activo; no se reinicia."
        fi
    elif has service; then
        service auditd start || fail "No se pudo iniciar auditd."
        packages_changed=1
    elif has systemctl && ! systemctl is-active --quiet auditd; then
        systemctl start auditd || fail "No se pudo iniciar auditd."
        packages_changed=1
    fi

    local audit_enabled
    audit_enabled="$(auditctl -s 2>/dev/null | awk '$1=="enabled" {print $2; exit}')"
    local audit_runtime_ok=1
    local desired_rule normalized_rule

    audit_rule_loaded() {
        desired_rule="$1"
        normalized_rule="$desired_rule"

        if auditctl -l 2>/dev/null | grep -Fqx -- "$desired_rule"; then
            return 0
        fi

        normalized_rule="$(printf '%s\n' "$desired_rule" |
            sed -e 's/-k /-F key=/' -e 's/auid!=4294967295/auid!=-1/g')"
        auditctl -l 2>/dev/null | grep -Fqx -- "$normalized_rule"
    }

    while IFS= read -r desired_rule; do
        [[ -z "$desired_rule" || "$desired_rule" =~ ^[[:space:]]*# ]] && continue
        if ! audit_rule_loaded "$desired_rule"; then
            audit_runtime_ok=0
            break
        fi
    done < "$RULE_FILE"

    echo "=== OrangeBox audit execution monitoring ==="

    if [ "$audit_enabled" = "2" ]; then
        if [ "$audit_runtime_ok" -eq 1 ]; then
            ok "Audit inmutable: reglas OrangeBox ya están activas."
        else
            warn "Audit inmutable (-e 2): las reglas persistentes requieren reinicio."
        fi
    elif [ "$rules_changed" -eq 1 ] || [ "$audit_runtime_ok" -eq 0 ]; then
        augenrules --load || fail "augenrules no pudo cargar las reglas OrangeBox."
        audit_runtime_ok=1
        ok "Reglas auditd OrangeBox cargadas."
    else
        ok "Reglas auditd ya están cargadas; no se recargan."
    fi

    if auditctl -l | grep -E -- '(-k[[:space:]]+|-F[[:space:]]+key=)audit-wazuh-c' >/dev/null 2>&1; then
        ok "Reglas de scanners/reconocimiento cargadas."
    else
        ok "No se detectaron ejecutables scanner/recon adicionales."
    fi

    if [ "$rules_changed" -eq 1 ] || [ "$ossec_changed" -eq 1 ] || [ "$packages_changed" -eq 1 ]; then
        request_agent_action
    fi

    if [ "$audit_enabled" = "2" ] && [ "$audit_runtime_ok" -eq 0 ]; then
        warn "auditd tiene cambios OrangeBox pendientes de activar tras reinicio."
    fi

    ok "auditd reconciliado: persistencia y runtime comparados."
}

configure_yara() {
    ensure_python3 || return 1

    build_yara_correlation() {
        local rules_dir="$1"
        local output_file="$2"

        "$PYTHON3_BIN" - "$rules_dir" "$output_file" <<'PY'
import os
import re
import sys

rules_dir = sys.argv[1]
output_file = sys.argv[2]

rule_re = re.compile(
    r'^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b',
    re.IGNORECASE,
)
condition_re = re.compile(r'^\s*condition\s*:', re.IGNORECASE)
identifier_re = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')
string_re = re.compile(r'"(?:\\.|[^"\\])*"')

rule_names = set()
conditions = {}

for root, _dirs, files in os.walk(rules_dir):
    for filename in sorted(files):
        if not filename.endswith(('.yar', '.yara')):
            continue

        path = os.path.join(root, filename)
        with open(path, 'r', encoding='utf-8', errors='replace') as source:
            current = None
            collecting = False
            condition_lines = []

            for raw_line in source:
                line = raw_line.rstrip('\n')
                match = rule_re.match(line)

                if match:
                    if current and collecting:
                        conditions[current] = '\n'.join(condition_lines)
                    current = match.group(1)
                    rule_names.add(current)
                    collecting = False
                    condition_lines = []
                    continue

                if current and condition_re.match(line):
                    collecting = True
                    condition_lines = [line.split(':', 1)[1]]

                    if re.search(r'}\s*$', condition_lines[0]):
                        condition_lines[0] = condition_lines[0].rsplit('}', 1)[0]
                        conditions[current] = '\n'.join(condition_lines)
                        current = None
                        collecting = False
                        condition_lines = []

                    continue

                if current and collecting:
                    if re.match(r'^\s*}\s*$', line):
                        conditions[current] = '\n'.join(condition_lines)
                        current = None
                        collecting = False
                        condition_lines = []
                    else:
                        condition_lines.append(line)

            if current and collecting:
                conditions[current] = '\n'.join(condition_lines)

children = {name: set() for name in rule_names}

for rule_name, condition in conditions.items():
    condition = re.sub(r'/\*.*?\*/', ' ', condition, flags=re.S)
    condition = re.sub(r'//.*$', ' ', condition, flags=re.M)
    condition = string_re.sub(' ', condition)

    for identifier in identifier_re.findall(condition):
        if identifier in rule_names and identifier != rule_name:
            children[rule_name].add(identifier)

# In YARA a rule can be a logical parent of several child rules.
# Correlation must normalize every child to the highest unique parent,
# so a match of "WarpStrings" plus its parent "Warp" counts as one
# logical signature, not two different signatures.
parents_of = {name: set() for name in rule_names}
for parent, child_rules in children.items():
    for child in child_rules:
        parents_of[child].add(parent)

memo = {}

def roots(rule_name, visiting):
    if rule_name in memo:
        return memo[rule_name]

    if rule_name in visiting:
        return set()

    direct = parents_of.get(rule_name, set())
    if not direct:
        result = {rule_name}
    else:
        result = set()
        next_visiting = visiting | {rule_name}
        for parent in direct:
            result.update(roots(parent, next_visiting))

    memo[rule_name] = result
    return result

with open(output_file, 'w', encoding='utf-8') as destination:
    for child in sorted(rule_names):
        root_set = roots(child, set())

        # Solo se normaliza cuando existe una unica raiz logica.
        # Si varias reglas padre independientes alcanzan a la misma firma,
        # se conserva el nombre propio para no inventar una correlacion.
        if len(root_set) == 1:
            root = next(iter(root_set))
            if root != child:
                destination.write("{}|{}\n".format(child, root))
PY

        [[ -f "$output_file" ]] || {
            echo "ERROR: no se pudo generar la tabla de correlacion YARA." >&2
            return 1
        }

        return 0
    }

    local SCRIPT_SRC="$WAZUH_HOME/active-response/bin/orangebox-yara.sh"
    mkdir -p "$(dirname "$SCRIPT_SRC")" || fail "No se pudo crear el directorio Active Response."

    # El instalador es autosuficiente: genera directamente el runtime del agente.
    # Este instalador es el unico source of truth del runtime desplegado.
    local SCRIPT_TMP
    SCRIPT_TMP="$(mktemp)" || fail "No se pudo crear temporal para orangebox-yara.sh."
    cat > "$SCRIPT_TMP" <<'ORANGEBOX_YARA_RUNTIME'
#!/usr/bin/env bash
set -u
set -o pipefail

# OrangeBox Wazuh - Active Response FIM -> YARA
# Analiza solo el archivo indicado por FIM con el ruleset oficial Yara-Rules.
# Esta etapa detecta; no elimina ni modifica el archivo.
#
# El stdin de Active Response contiene un JSON por linea. No usar cat aqui:
# cat espera EOF y puede dejar el proceso colgado indefinidamente.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WAZUH_HOME="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"

# Solo los matches YARA van a active-responses.log porque las reglas Wazuh
# consumen ese texto para generar la alerta 10501. El resto va a un log propio
# para evitar feedback innecesario con Logcollector.
AR_LOG="${WAZUH_HOME}/logs/active-responses.log"
YARA_LOG="${WAZUH_HOME}/logs/orangebox-yara.log"
LOCK_FILE="${WAZUH_HOME}/logs/orangebox-yara.lock"
RULES_DIR="${SCRIPT_DIR}/yara/rules/yara-rules"
CORRELATION_FILE="${RULES_DIR}/YARA-RULE-CORRELATION"
MAX_FILE_SIZE='5242880'
YARA_TIMEOUT='15'

log_info() {
    printf 'wazuh-yara: INFO - %s\n' "$*" >> "${YARA_LOG}"
}

log_error() {
    printf 'wazuh-yara: ERROR - %s\n' "$*" >> "${YARA_LOG}"
}

mkdir -p "${WAZUH_HOME}/logs" 2>/dev/null || true

# Evitar varias ejecuciones YARA simultaneas en ráfagas de FIM.
if command -v flock >/dev/null 2>&1; then
    exec 9>"${LOCK_FILE}"
    flock -n 9 || exit 0
fi

# Active Response entrega el JSON como una linea. Leer una sola linea evita
# bloquear el proceso esperando EOF, que nunca tiene por que llegar.
INPUT_JSON=""
if ! IFS= read -r INPUT_JSON; then
    log_error "No se recibio JSON de Active Response."
    exit 0
fi

command -v jq >/dev/null 2>&1 || {
    log_error "jq no esta instalado."
    exit 1
}

ACTION="$(printf '%s' "${INPUT_JSON}" | jq -r '.command // .action // empty' 2>/dev/null || true)"
FILENAME="$(printf '%s' "${INPUT_JSON}" | jq -r '.parameters.alert.syscheck.path // empty' 2>/dev/null || true)"

[[ "${ACTION}" != "add" && -n "${ACTION}" ]] && exit 0
[[ -n "${FILENAME}" && "${FILENAME}" != "null" ]] || {
    log_error "No se obtuvo el path FIM."
    exit 1
}

# Los archivos temporales pueden desaparecer entre FIM y Active Response.
# Es un caso esperado: no generar ERROR ni alerta falsa.
if [[ ! -e "${FILENAME}" ]]; then
    log_info "El archivo ya no existe al iniciar el escaneo: ${FILENAME}"
    exit 0
fi

[[ ! -L "${FILENAME}" ]] || {
    log_info "Archivo omitido por ser symlink: ${FILENAME}"
    exit 0
}

[[ -f "${FILENAME}" ]] || {
    log_info "Archivo omitido por no ser regular: ${FILENAME}"
    exit 0
}
# Dar una pequeña ventana para que una escritura recién terminada se estabilice,
# pero sin bloquear el Active Response durante segundos.
sleep 0.2

[[ -f "${FILENAME}" ]] || {
    log_info "El archivo desaparecio antes del escaneo: ${FILENAME}"
    exit 0
}

FILE_SIZE="$(stat -c '%s' -- "${FILENAME}" 2>/dev/null || echo 0)"
if [[ "${FILE_SIZE}" =~ ^[0-9]+$ ]] && (( FILE_SIZE > MAX_FILE_SIZE )); then
    log_info "Archivo omitido por superar 5 MiB: ${FILENAME}"
    exit 0
fi

YARA_BIN="${ORANGEBOX_YARA_BIN:-}"
if [[ -z "${YARA_BIN}" ]]; then
    for candidate in /usr/local/bin/yara /usr/bin/yara /usr/local/sbin/yara; do
        [[ -x "${candidate}" ]] && { YARA_BIN="${candidate}"; break; }
    done
fi

[[ -x "${YARA_BIN}" ]] || {
    log_error "No se encontro YARA."
    exit 1
}

[[ -d "${RULES_DIR}" ]] || {
    log_error "No se encontro el ruleset oficial: ${RULES_DIR}"
    exit 1
}

declare -A YARA_CORRELATIONS=()
if [[ -r "${CORRELATION_FILE}" ]]; then
    while IFS='|' read -r child root; do
        [[ -z "${child}" || -z "${root}" ]] && continue
        YARA_CORRELATIONS["${child}"]="${root}"
    done < "${CORRELATION_FILE}"
fi

correlation_for_rule() {
    local rule_name="$1"
    local correlation="${rule_name}"

    if [[ -n "${YARA_CORRELATIONS[${rule_name}]+x}" ]]; then
        correlation="${YARA_CORRELATIONS[${rule_name}]}"
    fi

    printf '%s\n' "${correlation}"
}

command -v timeout >/dev/null 2>&1 || {
    log_error "timeout no esta disponible; no se ejecutara YARA."
    exit 1
}

run_scan() {
    local category="$1"
    local index_file="$2"
    local output_file
    local yara_status
    local line
    local rule_name
    local scanned_path

    [[ -s "${index_file}" ]] || {
        log_error "Falta el indice YARA: ${index_file}"
        return 1
    }

    output_file="$(mktemp "${YARA_LOG}.XXXXXX")" || {
        log_error "No se pudo crear temporal para salida YARA."
        return 1
    }

    if timeout "${YARA_TIMEOUT}s" "${YARA_BIN}" -w -r "${index_file}" "${FILENAME}" >"${output_file}" 2>>"${YARA_LOG}"; then
        yara_status=0
    else
        yara_status=$?
    fi

    case "${yara_status}" in
        0)
            ;;
        1)
            rm -f "${output_file}"
            return 0
            ;;
        124|137)
            log_error "YARA excedio el timeout de ${YARA_TIMEOUT}s: ${FILENAME} (categoria=${category})"
            rm -f "${output_file}"
            return 0
            ;;
        *)
            log_error "YARA fallo con codigo ${yara_status}: ${FILENAME} (categoria=${category})"
            rm -f "${output_file}"
            return 1
            ;;
    esac

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        rule_name="${line%% *}"
        scanned_path="${line#* }"

        [[ -n "${rule_name}" && -n "${scanned_path}" && "${rule_name}" != "${line}" ]] || continue

        correlation="$(correlation_for_rule "${rule_name}")"

        # rule conserva el nombre original; correlation identifica la raiz logica.
        printf 'wazuh-yara: ALERT - Match: category=%s rule=%s correlation=%s path=%s\n' \
            "${category}" "${rule_name}" "${correlation}" "${scanned_path}" >> "${AR_LOG}"
    done < "${output_file}"

    rm -f "${output_file}"
    return 0
}

run_scan "webshells" "${RULES_DIR}/webshells_index.yar" || exit 0
run_scan "malware" "${RULES_DIR}/malware_index.yar" || exit 0

exit 0

ORANGEBOX_YARA_RUNTIME
    local WAZUH_GROUP
    WAZUH_GROUP="$(stat -c '%G' "$WAZUH_HOME/active-response/bin" 2>/dev/null || echo wazuh)"
    [[ -n "$WAZUH_GROUP" && "$WAZUH_GROUP" != "UNKNOWN" ]] || WAZUH_GROUP="wazuh"
    if sync_managed_file "$SCRIPT_TMP" "$SCRIPT_SRC" 750 root "$WAZUH_GROUP"; then
        ok "Runtime YARA actualizado porque el estado difiere."
    else
        ok "Runtime YARA ya coincide; no se modifica."
    fi
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
            # En CentOS/EL6, jq y YARA viven en EPEL6. Como EL6 está archivado,
            # usar el repositorio OrangeBox archivado y no el mirrorlist retirado.
            if [[ "${EL_MAJOR}" == "6" && "${IS_CPANEL}" != "yes" &&
                  ( " ${packages[*]} " == *" jq "* || " ${packages[*]} " == *" yara "* ) ]]; then
                ensure_epel6
                "${manager}" --disablerepo='epel*' --enablerepo=orangebox-epel6 install -y "${packages[@]}" || {
                    echo "ERROR: no se pudieron instalar las dependencias EL6 desde EPEL6 archivado." >&2
                    return 1
                }
                return 0
            fi

            if "${manager}" install -y "${packages[@]}"; then
                return 0
            fi

            # CentOS 7 ya no publica todos los paquetes auxiliares en los
            # repositorios configurados. jq y YARA se distribuyen normalmente
            # mediante EPEL. Solo habilitar EPEL cuando estamos en EL7 y
            # realmente faltan dependencias de esta etapa.
            if [[ "${EL_MAJOR}" == "7" && "${IS_CPANEL}" != "yes" &&
                  -f /etc/redhat-release ]] &&
               grep -qi "CentOS" /etc/redhat-release &&
               [[ " ${packages[*]} " == *" jq "* ||
                  " ${packages[*]} " == *" yara "* ]]; then
                echo "==> Dependencias EL7 no disponibles; habilitando EPEL..."
                "${manager}" install -y epel-release || {
                    echo "ERROR: no se pudo instalar epel-release." >&2
                    return 1
                }

                "${manager}" install -y "${packages[@]}" || {
                    echo "ERROR: no se pudieron instalar las dependencias desde EPEL." >&2
                    return 1
                }

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

OLD_YARA_COMMIT="$(cat "$DEST_RULES/YARA-RULES-COMMIT" 2>/dev/null || true)"
REMOTE_YARA_COMMIT="$(git ls-remote --heads "$YARA_RULES_REPO" "refs/heads/$YARA_RULES_BRANCH" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
yara_local_state_matches() {
    [ -n "$OLD_YARA_COMMIT" ] || return 1
    [ -n "$REMOTE_YARA_COMMIT" ] || return 1
    [ "$OLD_YARA_COMMIT" = "$REMOTE_YARA_COMMIT" ] || return 1
    [ -s "$RULESET_DIR/webshells_index.yar" ] || return 1
    [ -s "$RULESET_DIR/malware_index.yar" ] || return 1
    [ -s "$RULESET_DIR/YARA-RULE-CORRELATION" ] || return 1
    [ -s "$DEST_RULES/YARA-RULES-MANIFEST" ] || return 1
    [ "$(cat "$DEST_RULES/YARA-RULES-REPOSITORY" 2>/dev/null || true)" = "$YARA_RULES_REPO" ] || return 1
    [ "$(cat "$DEST_RULES/YARA-RULES-BRANCH" 2>/dev/null || true)" = "$YARA_RULES_BRANCH" ] || return 1
    (cd "$DEST_RULES" && sha256sum -c "YARA-RULES-MANIFEST" >/dev/null 2>&1)
}

yara_local_state_usable() {
    [ -n "$OLD_YARA_COMMIT" ] || return 1
    [ -s "$RULESET_DIR/webshells_index.yar" ] || return 1
    [ -s "$RULESET_DIR/malware_index.yar" ] || return 1
    [ -s "$RULESET_DIR/YARA-RULE-CORRELATION" ] || return 1
    [ -s "$DEST_RULES/YARA-RULES-MANIFEST" ] || return 1
    [ "$(cat "$DEST_RULES/YARA-RULES-REPOSITORY" 2>/dev/null || true)" = "$YARA_RULES_REPO" ] || return 1
    [ "$(cat "$DEST_RULES/YARA-RULES-BRANCH" 2>/dev/null || true)" = "$YARA_RULES_BRANCH" ] || return 1
    (cd "$DEST_RULES" && sha256sum -c "YARA-RULES-MANIFEST" >/dev/null 2>&1)
}

if yara_local_state_matches; then
    RULESET_COMMIT="$OLD_YARA_COMMIT"
    ok "Yara-Rules ya coincide con el repositorio oficial ($RULESET_COMMIT); no se descarga ni reemplaza el ruleset."
elif [ -z "$REMOTE_YARA_COMMIT" ] && yara_local_state_usable; then
    RULESET_COMMIT="$OLD_YARA_COMMIT"
    YARA_RULESET_CHANGED=0
    warn "No se pudo consultar el repositorio Yara-Rules; se conserva el ruleset local existente."
else
    echo "==> Descargando Yara-Rules oficial..."
git clone --depth 1 --branch "${YARA_RULES_BRANCH}"     "${YARA_RULES_REPO}" "${TMP_DIR}/rules"

RULESET_COMMIT="$(cd "${TMP_DIR}/rules" && git rev-parse HEAD)"

# Algunas YARA empaquetadas para EL7 no incluyen el modulo Cuckoo.
# El snapshot usado por OrangeBox tiene una regla activa que lo importa:
# malware/MALW_AZORULT.yar. Solo se excluye esa regla cuando el modulo falta.
CUCKOO_TEST="${TMP_DIR}/orangebox-cuckoo-test.yar"
printf "%s\n" 'import "cuckoo"' 'rule orangebox_cuckoo_test { condition: cuckoo.sync.mutex(/orangebox/) }' > "${CUCKOO_TEST}"
YARA_RULES_ADJUSTMENTS=""
if ! "${YARA_BIN}" -w "${CUCKOO_TEST}" /dev/null >/dev/null 2>&1; then
    AZORULT_INCLUDE='include "./malware/MALW_AZORULT.yar"'
    if grep -Fqx "${AZORULT_INCLUDE}" "${TMP_DIR}/rules/malware_index.yar"; then
        grep -Fvx "${AZORULT_INCLUDE}" "${TMP_DIR}/rules/malware_index.yar" > "${TMP_DIR}/malware_index.yar.tmp" || return 1
        mv "${TMP_DIR}/malware_index.yar.tmp" "${TMP_DIR}/rules/malware_index.yar" || return 1
        YARA_RULES_ADJUSTMENTS="malware/MALW_AZORULT.yar"
        echo "AVISO: YARA no tiene Cuckoo; se excluye malware/MALW_AZORULT.yar del indice malware."
    fi
fi

# Validar el ruleset completo antes de reemplazar el instalado.
for index in webshells_index.yar malware_index.yar; do
    INDEX_PATH="${TMP_DIR}/rules/${index}"

    [[ -s "${INDEX_PATH}" ]] || {
        echo "ERROR: falta el indice oficial ${index}." >&2
        return 1
    }

    local yara_check_output=""
    if ! yara_check_output="$("${YARA_BIN}" -w "${INDEX_PATH}" /dev/null 2>&1)"; then
        echo "ERROR: YARA no pudo cargar el indice ${index}." >&2
        printf "%s\n" "${yara_check_output}" >&2
        return 1
    fi
done

    build_yara_correlation "${TMP_DIR}/rules" "${TMP_DIR}/rules/YARA-RULE-CORRELATION" || return 1

    # Fix OrangeBox: relaciones requeridas por las reglas Warp.
    CORRELATION_FILE="${TMP_DIR}/rules/YARA-RULE-CORRELATION"
    grep -qxF 'WarpStrings|Warp' "${CORRELATION_FILE}" || echo 'WarpStrings|Warp' >> "${CORRELATION_FILE}"
    grep -qxF 'WarpCode|Warp' "${CORRELATION_FILE}" || echo 'WarpCode|Warp' >> "${CORRELATION_FILE}"
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
    (cd "${DEST_RULES}" && find "yara-rules" -type f -print0 | sort -z | xargs -0 sha256sum > "YARA-RULES-MANIFEST") ||
        return 1
if [[ -n "${YARA_RULES_ADJUSTMENTS}" ]]; then
    printf "%s\n" "${YARA_RULES_ADJUSTMENTS}" > "${DEST_RULES}/YARA-RULES-ADJUSTMENTS"
else
    rm -f "${DEST_RULES}/YARA-RULES-ADJUSTMENTS"
fi
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
fi
# Actualizacion automatica diaria de Yara-Rules.
YARA_UPDATE_SCRIPT="/usr/local/sbin/orangebox-yara-update"
YARA_UPDATE_CRON="/etc/cron.d/orangebox-yara-update"

cat > "${YARA_UPDATE_SCRIPT}.tmp" <<'YARA_UPDATE'
#!/usr/bin/env bash
set -u
set -o pipefail

WAZUH_HOME='@@WAZUH_HOME@@'
YARA_RULES_REPO='@@YARA_RULES_REPO@@'
YARA_RULES_BRANCH='@@YARA_RULES_BRANCH@@'
YARA_BIN='@@YARA_BIN@@'
PYTHON3_BIN='@@PYTHON3_BIN@@'
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

OLD_COMMIT="$(cat "${DEST_RULES}/YARA-RULES-COMMIT" 2>/dev/null || true)"
REMOTE_COMMIT="$(git ls-remote --heads "${YARA_RULES_REPO}" "refs/heads/${YARA_RULES_BRANCH}" 2>/dev/null | awk 'NR==1 {print $1}' || true)"

MANIFEST_OK=0
if [ -s "${DEST_RULES}/YARA-RULES-MANIFEST" ] &&
   (cd "${DEST_RULES}" && sha256sum -c "YARA-RULES-MANIFEST" >/dev/null 2>&1); then
    MANIFEST_OK=1
fi

if [ -n "${OLD_COMMIT}" ] &&
   [ -n "${REMOTE_COMMIT}" ] &&
   [ "${OLD_COMMIT}" = "${REMOTE_COMMIT}" ] &&
   [ -s "${RULESET_DIR}/webshells_index.yar" ] &&
   [ -s "${RULESET_DIR}/malware_index.yar" ] &&
   [ -s "${RULESET_DIR}/YARA-RULE-CORRELATION" ] &&
   [ -s "${DEST_RULES}/YARA-RULES-MANIFEST" ] &&
   [ -s "${DEST_RULES}/YARA-RULES-REPOSITORY" ] &&
   [ -s "${DEST_RULES}/YARA-RULES-BRANCH" ] &&
   [ "$(cat "${DEST_RULES}/YARA-RULES-REPOSITORY" 2>/dev/null)" = "${YARA_RULES_REPO}" ] &&
   [ "$(cat "${DEST_RULES}/YARA-RULES-BRANCH" 2>/dev/null)" = "${YARA_RULES_BRANCH}" ] &&
   [ "${MANIFEST_OK}" -eq 1 ]; then
    echo "OK: Yara-Rules sin cambios (${OLD_COMMIT})."
    exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

git clone --depth 1 --branch "${YARA_RULES_BRANCH}" \
    "${YARA_RULES_REPO}" "${TMP_DIR}/rules"

NEW_COMMIT="$(cd "${TMP_DIR}/rules" && git rev-parse HEAD)"
build_yara_correlation() {
    local rules_dir="$1"
    local output_file="$2"

    "$PYTHON3_BIN" - "$rules_dir" "$output_file" <<'PY'
import os
import re
import sys

rules_dir = sys.argv[1]
output_file = sys.argv[2]

rule_re = re.compile(
    r'^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b',
    re.IGNORECASE,
)
condition_re = re.compile(r'^\s*condition\s*:', re.IGNORECASE)
identifier_re = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')
string_re = re.compile(r'"(?:\\.|[^"\\])*"')

rule_names = set()
conditions = {}

for root, _dirs, files in os.walk(rules_dir):
    for filename in sorted(files):
        if not filename.endswith(('.yar', '.yara')):
            continue

        path = os.path.join(root, filename)
        with open(path, 'r', encoding='utf-8', errors='replace') as source:
            current = None
            collecting = False
            condition_lines = []

            for raw_line in source:
                line = raw_line.rstrip('\n')
                match = rule_re.match(line)

                if match:
                    if current and collecting:
                        conditions[current] = '\n'.join(condition_lines)
                    current = match.group(1)
                    rule_names.add(current)
                    collecting = False
                    condition_lines = []
                    continue

                if current and condition_re.match(line):
                    collecting = True
                    condition_lines = [line.split(':', 1)[1]]

                    if re.search(r'}\s*$', condition_lines[0]):
                        condition_lines[0] = condition_lines[0].rsplit('}', 1)[0]
                        conditions[current] = '\n'.join(condition_lines)
                        current = None
                        collecting = False
                        condition_lines = []

                    continue

                if current and collecting:
                    if re.match(r'^\s*}\s*$', line):
                        conditions[current] = '\n'.join(condition_lines)
                        current = None
                        collecting = False
                        condition_lines = []
                    else:
                        condition_lines.append(line)

            if current and collecting:
                conditions[current] = '\n'.join(condition_lines)

children = {name: set() for name in rule_names}

for rule_name, condition in conditions.items():
    condition = re.sub(r'/\*.*?\*/', ' ', condition, flags=re.S)
    condition = re.sub(r'//.*$', ' ', condition, flags=re.M)
    condition = string_re.sub(' ', condition)

    for identifier in identifier_re.findall(condition):
        if identifier in rule_names and identifier != rule_name:
            children[rule_name].add(identifier)

# In YARA a rule can be a logical parent of several child rules.
# Correlation must normalize every child to the highest unique parent,
# so a match of "WarpStrings" plus its parent "Warp" counts as one
# logical signature, not two different signatures.
parents_of = {name: set() for name in rule_names}
for parent, child_rules in children.items():
    for child in child_rules:
        parents_of[child].add(parent)

memo = {}

def roots(rule_name, visiting):
    if rule_name in memo:
        return memo[rule_name]

    if rule_name in visiting:
        return set()

    direct = parents_of.get(rule_name, set())
    if not direct:
        result = {rule_name}
    else:
        result = set()
        next_visiting = visiting | {rule_name}
        for parent in direct:
            result.update(roots(parent, next_visiting))

    memo[rule_name] = result
    return result

with open(output_file, 'w', encoding='utf-8') as destination:
    for child in sorted(rule_names):
        root_set = roots(child, set())

        # Solo se normaliza cuando existe una unica raiz logica.
        # Si varias reglas padre independientes alcanzan a la misma firma,
        # se conserva el nombre propio para no inventar una correlacion.
        if len(root_set) == 1:
            root = next(iter(root_set))
            if root != child:
                destination.write("{}|{}\n".format(child, root))
PY

    [[ -f "$output_file" ]] || {
        echo "ERROR: no se pudo generar la tabla de correlacion YARA." >&2
        return 1
    }

    return 0
}

# Mantener la misma compatibilidad del instalador: YARA sin Cuckoo
# no puede compilar MALW_AZORULT.yar del snapshot oficial.
CUCKOO_TEST="${TMP_DIR}/orangebox-cuckoo-test.yar"
printf "%s\n" 'import "cuckoo"' 'rule orangebox_cuckoo_test { condition: cuckoo.sync.mutex(/orangebox/) }' > "${CUCKOO_TEST}"
YARA_RULES_ADJUSTMENTS=""
if ! "${YARA_BIN}" -w "${CUCKOO_TEST}" /dev/null >/dev/null 2>&1; then
    AZORULT_INCLUDE='include "./malware/MALW_AZORULT.yar"'
    if grep -Fqx "${AZORULT_INCLUDE}" "${TMP_DIR}/rules/malware_index.yar"; then
        grep -Fvx "${AZORULT_INCLUDE}" "${TMP_DIR}/rules/malware_index.yar" > "${TMP_DIR}/malware_index.yar.tmp" || exit 1
        mv "${TMP_DIR}/malware_index.yar.tmp" "${TMP_DIR}/rules/malware_index.yar" || exit 1
        YARA_RULES_ADJUSTMENTS="malware/MALW_AZORULT.yar"
        echo "AVISO: YARA no tiene Cuckoo; se excluye malware/MALW_AZORULT.yar del indice malware."
    fi
fi

if [[ -n "${OLD_COMMIT}" && "${OLD_COMMIT}" == "${NEW_COMMIT}" && -f "${RULESET_DIR}/YARA-RULE-CORRELATION" ]]; then
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

build_yara_correlation "${TMP_DIR}/rules" "${TMP_DIR}/rules/YARA-RULE-CORRELATION" || exit 1

# Fix OrangeBox: relaciones requeridas por las reglas Warp.
CORRELATION_FILE="${TMP_DIR}/rules/YARA-RULE-CORRELATION"
grep -qxF 'WarpStrings|Warp' "${CORRELATION_FILE}" || echo 'WarpStrings|Warp' >> "${CORRELATION_FILE}"
grep -qxF 'WarpCode|Warp' "${CORRELATION_FILE}" || echo 'WarpCode|Warp' >> "${CORRELATION_FILE}"

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
(cd "${DEST_RULES}" && find "yara-rules" -type f -print0 | sort -z | xargs -0 sha256sum > "YARA-RULES-MANIFEST") || exit 1
if [[ -n "${YARA_RULES_ADJUSTMENTS}" ]]; then
    printf "%s\n" "${YARA_RULES_ADJUSTMENTS}" > "${DEST_RULES}/YARA-RULES-ADJUSTMENTS"
else
    rm -f "${DEST_RULES}/YARA-RULES-ADJUSTMENTS"
fi
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
    -e "s|@@PYTHON3_BIN@@|${PYTHON3_BIN}|g" \
    "${YARA_UPDATE_SCRIPT}.tmp"

bash -n "${YARA_UPDATE_SCRIPT}.tmp" || {
    echo "ERROR: el updater YARA generado tiene un error de sintaxis." >&2
    rm -f "${YARA_UPDATE_SCRIPT}.tmp"
    return 1
}

if sync_managed_file "${YARA_UPDATE_SCRIPT}.tmp" "${YARA_UPDATE_SCRIPT}" 750 root "${WAZUH_GROUP}"; then
    ok "Updater YARA actualizado porque el estado difiere."
else
    ok "Updater YARA ya coincide; no se modifica."
fi

local yara_cron_tmp
yara_cron_tmp="$(mktemp)" || fail "No se pudo crear temporal para el cron de YARA."
cat > "${yara_cron_tmp}" <<'YARA_CRON'
17 3 * * * root /usr/local/sbin/orangebox-yara-update
YARA_CRON

if sync_managed_file "${yara_cron_tmp}" "${YARA_UPDATE_CRON}" 644 root root; then
    ok "Cron diario de YARA actualizado."
else
    ok "Cron diario de YARA ya coincide; no se modifica."
fi

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
echo "No se reinicio el agente durante este paso."

}

configure_quarantine() {
    ensure_python3 || return 1
    local SCRIPT_SRC="$WAZUH_HOME/active-response/bin/orangebox-quarantine.py"
    local WAZUH_GROUP

    mkdir -p "$(dirname "$SCRIPT_SRC")" || fail "No se pudo crear el directorio Active Response."

    # La cuarentena también se genera desde este instalador para que un agente
    # quede completo sin depender de rsync ni de una copia posterior.
    local SCRIPT_TMP
    SCRIPT_TMP="$(mktemp)" || fail "No se pudo crear temporal para orangebox-quarantine.py."
    cat > "$SCRIPT_TMP" <<'ORANGEBOX_QUARANTINE_RUNTIME'
#!/usr/bin/env python3
"""
OrangeBox Wazuh Active Response: cuarentena de archivo confirmado por la regla 99901.

La cuarentena conserva evidencia, verifica SHA-256 y falla de forma segura:
si una comprobacion falla, el archivo original no se elimina.
"""

import datetime
import hashlib
import json
import os
import stat
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WAZUH_HOME = os.path.abspath(os.path.join(SCRIPT_DIR, "../.."))
QUARANTINE_ROOT = os.path.join(WAZUH_HOME, "quarantine")
LOG_FILE = os.path.join(WAZUH_HOME, "logs", "active-responses.log")


def log(message):
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(
                "{} orangebox-quarantine: {}\n".format(
                    datetime.datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S"),
                    message,
                )
            )
    except Exception:
        pass


def main():
    raw = sys.stdin.readline()
    if not raw:
        log("ERROR: entrada Active Response vacia")
        return 1

    try:
        message = json.loads(raw)
    except Exception as exc:
        log("ERROR: JSON invalido: {}".format(exc))
        return 1

    if message.get("command") != "add":
        log("Ignorando command={!r}".format(message.get("command")))
        return 0

    alert = message.get("parameters", {}).get("alert", {}) or {}
    syscheck = alert.get("syscheck", {}) or {}
    path = syscheck.get("path")
    expected = (syscheck.get("sha256") or syscheck.get("sha256_after") or "").lower()
    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", ""))
    agent = alert.get("agent", {}) or {}

    if rule_id != "99901":
        log("Ignorando regla inesperada {}".format(rule_id))
        return 0

    if not path or len(expected) != 64:
        log("ERROR: falta syscheck.path o SHA-256 valido")
        return 1

    source_fd = None
    source_stat = None

    try:
        open_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            open_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            open_flags |= os.O_CLOEXEC
        source_fd = os.open(path, open_flags)
        source_stat = os.fstat(source_fd)

        if not stat.S_ISREG(source_stat.st_mode):
            log("ERROR: el objetivo no es un archivo regular: {}".format(path))
            return 1

        os.lseek(source_fd, 0, os.SEEK_SET)
        source_digest = hashlib.sha256()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            source_digest.update(chunk)

        actual = source_digest.hexdigest()
        if actual.lower() != expected:
            log("ABORTADO: SHA-256 no coincide para {}".format(path))
            return 1

        os.makedirs(QUARANTINE_ROOT, mode=0o700, exist_ok=True)
        os.chmod(QUARANTINE_ROOT, 0o700)

        qdir = os.path.join(QUARANTINE_ROOT, expected)
        os.makedirs(qdir, mode=0o700, exist_ok=True)
        os.chmod(qdir, 0o700)

        base = os.path.basename(path) or "quarantined-file"
        destination = os.path.join(qdir, base)
        if os.path.exists(destination):
            stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            destination = os.path.join(qdir, "{}-{}".format(stamp, base))

        temp_fd, temp_path = tempfile.mkstemp(prefix=".quarantine-", dir=qdir)

        try:
            copied_hash = hashlib.sha256()
            with os.fdopen(os.dup(source_fd), "rb") as source_file, os.fdopen(temp_fd, "wb") as target_file:
                while True:
                    chunk = source_file.read(1024 * 1024)
                    if not chunk:
                        break
                    copied_hash.update(chunk)
                    target_file.write(chunk)
                target_file.flush()
                os.fsync(target_file.fileno())

            if copied_hash.hexdigest().lower() != expected:
                os.unlink(temp_path)
                log("ABORTADO: SHA-256 de la copia no coincide para {}".format(path))
                return 1

            os.chmod(temp_path, 0o400)
            os.rename(temp_path, destination)
            os.chmod(destination, 0o400)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

        current_stat = os.stat(path, follow_symlinks=False)
        same_identity = (
            current_stat.st_dev == source_stat.st_dev
            and current_stat.st_ino == source_stat.st_ino
            and current_stat.st_size == source_stat.st_size
            and getattr(current_stat, "st_mtime_ns", int(current_stat.st_mtime * 1e9))
            == getattr(source_stat, "st_mtime_ns", int(source_stat.st_mtime * 1e9))
            and getattr(current_stat, "st_ctime_ns", int(current_stat.st_ctime * 1e9))
            == getattr(source_stat, "st_ctime_ns", int(source_stat.st_ctime * 1e9))
        )

        if not same_identity:
            log("ABORTADO: el archivo cambio antes de eliminarlo: {}".format(path))
            return 1

        metadata = {
            "quarantine_time_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rule_id": rule_id,
            "sha256": expected,
            "original_path": path,
            "quarantine_path": destination,
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "uid": source_stat.st_uid,
            "gid": source_stat.st_gid,
            "mode": "{:04o}".format(stat.S_IMODE(source_stat.st_mode)),
            "size": source_stat.st_size,
            "mtime_epoch": source_stat.st_mtime,
        }

        metadata_path = os.path.join(qdir, "metadata.json")
        temp_metadata = metadata_path + ".tmp"
        with open(temp_metadata, "w") as metadata_file:
            json.dump(metadata, metadata_file, indent=2, sort_keys=True)
            metadata_file.write("\n")

        os.chmod(temp_metadata, 0o400)
        os.rename(temp_metadata, metadata_path)
        os.chmod(metadata_path, 0o400)

        os.unlink(path)
    except Exception as exc:
        log("ERROR: no se pudo completar la cuarentena de {}: {}".format(path, exc))
        return 1
    finally:
        if source_fd is not None:
            try:
                os.close(source_fd)
            except OSError:
                pass

    log(
        "QUARANTINED: {} -> {} sha256={} rule={} agent={}".format(
            path, destination, expected, rule_id, agent.get("name", "unknown")
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

ORANGEBOX_QUARANTINE_RUNTIME

    [ -n "$PYTHON3_BIN" ] || fail "Python 3 no quedó disponible para orangebox-quarantine.py."
    WAZUH_GROUP="$(stat -c '%G' "$WAZUH_HOME/active-response/bin" 2>/dev/null || echo wazuh)"
    [[ -n "$WAZUH_GROUP" && "$WAZUH_GROUP" != "UNKNOWN" ]] || WAZUH_GROUP="wazuh"

    if sync_managed_file "$SCRIPT_TMP" "$SCRIPT_SRC" 750 root "$WAZUH_GROUP"; then
        ok "Runtime de cuarentena actualizado porque el estado difiere."
    else
        ok "Runtime de cuarentena ya coincide; no se modifica."
    fi
    if ! "$PYTHON3_BIN" - "$SCRIPT_SRC" <<'PY' >/dev/null 2>&1
import sys
path = sys.argv[1]
with open(path, "r") as source_file:
    source = source_file.read()
compile(source, path, "exec")
PY
    then
        fail "orangebox-quarantine.py tiene un error de sintaxis."
    fi
}

run_step "Auditd / monitoreo de ejecución" configure_exec_audit
run_step "YARA" configure_yara
run_step "Cuarentena Active Response" configure_quarantine
run_step "Activación final del agente" activate_agent_final

final_verification() {
    local failed=0

    if agent_installed && [ -f "$WAZUH_HOME/etc/ossec.conf" ]; then
        ok "Verificación: Wazuh Agent disponible y ossec.conf presente."
    else
        echo "ERROR: Verificación final: Wazuh Agent u ossec.conf no están disponibles." >&2
        failed=1
    fi

    if [ -x "$WAZUH_HOME/active-response/bin/orangebox-yara.sh" ]; then
        ok "Verificación: orangebox-yara.sh presente."
    else
        echo "ERROR: Verificación final: orangebox-yara.sh ausente." >&2
        failed=1
    fi

    if [ -x "$WAZUH_HOME/active-response/bin/orangebox-quarantine.py" ]; then
        ok "Verificación: orangebox-quarantine.py presente."
    else
        echo "ERROR: Verificación final: orangebox-quarantine.py ausente." >&2
        failed=1
    fi

    case "$LOGGING_BACKEND" in
        rsyslog)
            if [ -f "$FIREWALL_LOG" ] && [ -f "$LOGROTATE_FILE" ]; then
                ok "Verificación: log y logrotate disponibles para EL6."
            else
                echo "ERROR: Verificación final: falta log o logrotate para EL6." >&2
                failed=1
            fi
            ;;
        journald)
            if journalctl -n 1 --no-pager >/dev/null 2>&1; then
                ok "Verificación: journald disponible."
            else
                echo "ERROR: Verificación final: journald no está disponible." >&2
                failed=1
            fi
            ;;
        *)
            echo "ERROR: Verificación final: backend de logging no definido." >&2
            failed=1
            ;;
    esac

    return "$failed"
}

run_step "Verificación final" final_verification

echo
echo "============================================================"
echo " RESUMEN DE INSTALACIÓN"
echo "============================================================"

if [ "${#STEP_OK[@]}" -gt 0 ]; then
    echo
    echo "OK - PASOS COMPLETADOS:"
    for step in "${STEP_OK[@]}"; do
        echo "  [OK] ${step}"
    done
fi

if [ "${#STEP_FAILED[@]}" -gt 0 ]; then
    echo
    echo "ERROR - PASOS CON FALLAS:"
    for step in "${STEP_FAILED[@]}"; do
        echo "  [ERROR] ${step}"
    done
fi

echo
echo "Totales: ${#STEP_OK[@]} OK / ${#STEP_FAILED[@]} con errores."

if [ "${#STEP_FAILED[@]}" -gt 0 ]; then
    echo
    echo "OrangeBox terminó con errores. Los pasos posteriores al fallo fueron ejecutados igualmente."
    exit 1
fi

echo
ok "Configuración OrangeBox completada."
