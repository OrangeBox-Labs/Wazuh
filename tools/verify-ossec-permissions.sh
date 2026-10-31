#!/usr/bin/env bash
set -u
set -o pipefail

# OrangeBox Wazuh - revision y reparacion de permisos
# Por defecto solo revisa. Use --fix para aplicar los permisos definidos aqui.
# No toca /var/lib/wazuh-indexer ni otros componentes fuera de /var/ossec.

OSSEC_HOME="/var/ossec"
FIX=0

# Imprime las opciones admitidas por el verificador de permisos.
usage() { echo "Uso: $0 [--check] [--fix] [--path /var/ossec]"; }

# Procesa los argumentos --check, --fix y --path antes de inspeccionar el árbol.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) FIX=0 ;;
        --fix) FIX=1 ;;
        --path) [[ $# -ge 2 ]] || { usage; exit 2; }; OSSEC_HOME="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Opcion no reconocida: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

[[ "$EUID" -eq 0 ]] || { echo "ERROR: ejecutar como root." >&2; exit 2; }
[[ -d "$OSSEC_HOME" ]] || { echo "ERROR: no existe $OSSEC_HOME." >&2; exit 2; }

PASS=0
FAIL=0
# Registra un control de permisos aprobado y aumenta el contador PASS.
ok() { echo "[OK]   $*"; PASS=$((PASS + 1)); }
# Registra un incumplimiento de permisos y aumenta el contador FAIL.
fail() { echo "[FAIL] $*"; FAIL=$((FAIL + 1)); }

# Comprueba tipo de archivo, propietario, grupo y modo de una ruta concreta.
check_path() {
    local path="$1" owner="$2" group="$3" mode="$4"
    [[ -e "$path" ]] || return 0
    local current_owner current_group current_mode
    current_owner="$(stat -c '%U' "$path")"
    current_group="$(stat -c '%G' "$path")"
    current_mode="$(stat -c '%a' "$path")"

    if [[ "$current_owner" == "$owner" && "$current_group" == "$group" && "$current_mode" == "$mode" ]]; then
        ok "$path -> $owner:$group $mode"
        return
    fi

    if (( FIX )); then
        chown "$owner:$group" "$path" || { fail "No se pudo cambiar owner/grupo: $path"; return; }
        chmod "$mode" "$path" || { fail "No se pudo cambiar modo: $path"; return; }
        ok "$path reparado -> $owner:$group $mode"
    else
        fail "$path -> actual $current_owner:$current_group $current_mode; esperado $owner:$group $mode"
    fi
}

# Recorre el árbol de Wazuh y verifica permisos de los archivos y directorios administrados.
check_tree() {
    local root="$1" owner="$2" group="$3" dir_mode="$4" file_mode="$5"
    [[ -d "$root" ]] || return 0
    check_path "$root" "$owner" "$group" "$dir_mode"

    # Lee rutas terminadas en NUL para conservar nombres con espacios durante la auditoría.
    while IFS= read -r -d '' path; do
        if [[ -d "$path" ]]; then
            check_path "$path" "$owner" "$group" "$dir_mode"
        elif [[ -f "$path" ]]; then
            check_path "$path" "$owner" "$group" "$file_mode"
        fi
    done < <(find "$root" -mindepth 1 -xdev -print0)
}

echo "=== OrangeBox - permisos de /var/ossec ==="
echo "Ruta: $OSSEC_HOME"
echo "Modo: $([[ $FIX -eq 1 ]] && echo REPARAR || echo SOLO REVISION)"
echo

check_tree "$OSSEC_HOME/etc" root wazuh 750 640
check_tree "$OSSEC_HOME/active-response/bin" root wazuh 750 750
check_tree "$OSSEC_HOME/integrations" root wazuh 750 750
check_tree "$OSSEC_HOME/logs" wazuh wazuh 750 640
check_tree "$OSSEC_HOME/queue" wazuh wazuh 750 640
check_tree "$OSSEC_HOME/stats" wazuh wazuh 750 640
check_tree "$OSSEC_HOME/var" wazuh wazuh 750 640

echo
echo "=== Archivos especialmente sensibles ==="
# Revisa por separado los archivos que contienen claves o credenciales sensibles.
for file in     "$OSSEC_HOME/etc/client.keys"     "$OSSEC_HOME/etc/authd.pass"     "$OSSEC_HOME/etc/sslmanager.key"; do
    check_path "$file" root wazuh 640
done

# Archivo usado por los reportes para consultar el indexador.
# Debe quedar restringido al usuario root.
check_path "$OSSEC_HOME/etc/orangebox-indexer.conf" root root 600

echo
echo "=== Resultado ==="
echo "OK: $PASS"
echo "FAIL: $FAIL"

(( FAIL == 0 )) && exit 0
exit 1
