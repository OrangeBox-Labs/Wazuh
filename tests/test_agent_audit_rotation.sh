#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROTATOR="$ROOT_DIR/tools/agent/auditd-logrotate.sh"
INSTALLER="$ROOT_DIR/tools/agent/install.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[PASS] %s\n' "$*"; }
new_workspace() { WORK_DIR="$(mktemp -d "$TMP_DIR/work.XXXXXX")"; }

# Comprueba las condiciones básicas del helper de rotación.
test_helper_contract() {
    [[ -f "$ROTATOR" ]] || { echo "falta auditd-logrotate.sh" >&2; return 1; }
    bash -n "$ROTATOR" || { echo "el helper tiene errores de sintaxis" >&2; return 1; }
    grep -Fq '# ORANGEBOX_AUDIT_LOG_ROTATION' "$ROTATOR" || return 1
    grep -Eq '^KEEP_DAYS=7$' "$ROTATOR" || return 1
    grep -Fq 'auditd rotate' "$ROTATOR" || return 1
    grep -Fq "name 'audit.log.orangebox.*.gz'" "$ROTATOR" || return 1
}

# Comprueba que el instalador valide precondiciones antes de aplicar la política.
test_installer_contract() {
    [[ -f "$INSTALLER" ]] || { echo "falta tools/agent/install.sh" >&2; return 1; }
    bash -n "$INSTALLER" || { echo "el instalador tiene errores de sintaxis Bash" >&2; return 1; }

    local required
    for required in \
        'orangebox_cron_scheduler_ready() {' \
        'systemctl is-active --quiet crond.service' \
        'systemctl is-enabled crond.service' \
        'service crond status' \
        'chkconfig --list crond' \
        'configure_audit_log_rotation() {' \
        'orangebox_cron_scheduler_ready ||' \
        '/etc/logrotate.d/*' \
        '/etc/cron.daily/orangebox-audit-logrotate' \
        'max_log_file_action = ignore' \
        'Auditd / rotación, compresión y retención 7 días' \
        'política de rotación/compresión de auditd ausente o incompleta'; do
        grep -Fq "$required" "$INSTALLER" || {
            echo "falta en el instalador: $required" >&2
            return 1
        }
    done

    local preflight_line install_line
    preflight_line="$(grep -nF 'orangebox_cron_scheduler_ready ||' "$INSTALLER" | head -n 1 | cut -d: -f1)"
    install_line="$(grep -nF 'sync_managed_file "$tmp" "$rotation_script" 750 root root' "$INSTALLER" | head -n 1 | cut -d: -f1)"
    [[ -n "$preflight_line" && -n "$install_line" && "$preflight_line" -lt "$install_line" ]] || {
        echo "el preflight de crond debe ocurrir antes de instalar la tarea" >&2
        return 1
    }
}

# Comprueba que el helper sea inocuo en hosts sin el directorio de logs audit.
test_missing_audit_directory_is_noop() {
    new_workspace
    ORANGEBOX_AUDIT_LOG_DIR="$WORK_DIR/no-audit-directory" \
    ORANGEBOX_AUDIT_SERVICE_BIN="$WORK_DIR/service-does-not-exist" \
        bash "$ROTATOR" || {
            echo "el helper debe salir correctamente si no existe el directorio audit" >&2
            return 1
        }
}

# Prueba la rotación en un directorio temporal mediante un service simulado.
test_rotation_compression_and_retention() {
    new_workspace
    local audit_dir="$WORK_DIR/audit"
    local bin_dir="$WORK_DIR/bin"
    local archive combined_content=""
    local archives=()

    mkdir -p "$audit_dir" "$bin_dir"
    printf 'active-before-rotation\n' > "$audit_dir/audit.log"
    printf 'previous-generation\n' > "$audit_dir/audit.log.1"
    printf 'old-managed-archive\n' > "$audit_dir/audit.log.orangebox.20000101_000000.946684800.1.gz"
    printf 'unmanaged-archive\n' > "$audit_dir/other-audit-backup.gz"
    touch -d '8 days ago' \
        "$audit_dir/audit.log.orangebox.20000101_000000.946684800.1.gz" \
        "$audit_dir/other-audit-backup.gz"

    cat > "$bin_dir/service" <<'SERVICE'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" = "auditd" && "$2" = "rotate" ]] || exit 2
mv -- "$TEST_AUDIT_DIR/audit.log" "$TEST_AUDIT_DIR/audit.log.1"
: > "$TEST_AUDIT_DIR/audit.log"
SERVICE
    chmod 700 "$bin_dir/service"

    ORANGEBOX_AUDIT_LOG_DIR="$audit_dir" \
    ORANGEBOX_AUDIT_SERVICE_BIN="$bin_dir/service" \
    TEST_AUDIT_DIR="$audit_dir" \
        bash "$ROTATOR" || {
            echo "el helper no terminó correctamente" >&2
            return 1
        }

    [[ -f "$audit_dir/audit.log" ]] || { echo "se perdió el audit.log activo" >&2; return 1; }
    [[ ! -e "$audit_dir/audit.log.1" ]] || { echo "quedó una generación sin archivar" >&2; return 1; }
    [[ ! -e "$audit_dir/audit.log.orangebox.20000101_000000.946684800.1.gz" ]] || {
        echo "no eliminó el archivo OrangeBox antiguo" >&2
        return 1
    }
    [[ -f "$audit_dir/other-audit-backup.gz" ]] || {
        echo "eliminó un archivo que no pertenece a OrangeBox" >&2
        return 1
    }

    mapfile -t archives < <(find "$audit_dir" -maxdepth 1 -type f -name 'audit.log.orangebox.*.gz' | sort)
    [[ "${#archives[@]}" -eq 2 ]] || {
        echo "se esperaban dos archivos comprimidos; se encontraron ${#archives[@]}" >&2
        return 1
    }

    for archive in "${archives[@]}"; do
        gzip -t "$archive" || { echo "archivo gzip inválido: $archive" >&2; return 1; }
        combined_content+="$(gzip -cd "$archive")"$'\n'
    done
    [[ "$combined_content" == *"previous-generation"* ]] || {
        echo "no se conserva la generación anterior" >&2
        return 1
    }
    [[ "$combined_content" == *"active-before-rotation"* ]] || {
        echo "no se conserva la generación activa rotada" >&2
        return 1
    }
}

# Comprueba que el fallo de auditd rotate se propague y preserve el log activo.
test_rotation_failure_is_reported() {
    new_workspace
    local audit_dir="$WORK_DIR/audit"
    local bin_dir="$WORK_DIR/bin"
    local status=0

    mkdir -p "$audit_dir" "$bin_dir"
    printf 'must-survive\n' > "$audit_dir/audit.log"
    cat > "$bin_dir/service" <<'SERVICE'
#!/usr/bin/env bash
[[ "$1" = "auditd" && "$2" = "rotate" ]] || exit 2
exit 23
SERVICE
    chmod 700 "$bin_dir/service"

    if ORANGEBOX_AUDIT_LOG_DIR="$audit_dir" \
        ORANGEBOX_AUDIT_SERVICE_BIN="$bin_dir/service" \
        bash "$ROTATOR"; then
        echo "el helper ocultó el fallo de auditd rotate" >&2
        return 1
    else
        status=$?
    fi

    [[ "$status" -eq 23 ]] || { echo "se esperaba código 23 y se recibió $status" >&2; return 1; }
    [[ -f "$audit_dir/audit.log" ]] || { echo "desapareció el log activo" >&2; return 1; }
    grep -Fq 'must-survive' "$audit_dir/audit.log" || {
        echo "cambió el contenido del log activo" >&2
        return 1
    }
}

run_test() {
    local name="$1"
    shift
    if "$@"; then
        pass "$name"
    else
        fail "$name"
    fi
}

run_test "sintaxis y contrato del helper auditd" test_helper_contract
run_test "contrato y preflight del instalador Wazuh" test_installer_contract
run_test "directorio audit ausente: salida sin cambios" test_missing_audit_directory_is_noop
run_test "rotación, gzip, retención y preservación de archivos externos" test_rotation_compression_and_retention
run_test "fallo de rotación: código propagado y log activo preservado" test_rotation_failure_is_reported

printf '\nTodas las pruebas de rotación de auditd finalizaron correctamente.\n'
