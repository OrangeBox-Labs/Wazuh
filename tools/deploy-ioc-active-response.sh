#!/usr/bin/env bash
set -Eeuo pipefail

# Deploy IOC Active Response, web detection and PHP2Shell rule fixes from this checkout.
# Backs up every touched file, patches only the IOC Active Response XML block
# in the live ossec.conf (preserving host-specific settings), validates, tests,
# restarts wazuh-manager and rolls back automatically on failure.
#
# IOC feeds are NOT refreshed here. Their first source reclassification is
# deliberately a separate, reviewed operation.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
OSSEC_CONF="$WAZUH_HOME/etc/ossec.conf"
CONFIRMED_SOURCE_SEED="$ROOT/configuration/manager/etc/lists/malicious-ioc/orangebox-confirmed-source-ip"
CONFIRMED_SOURCE_TARGET="$WAZUH_HOME/etc/lists/malicious-ioc/orangebox-confirmed-source-ip"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: ejecutar como root." >&2
    exit 1
fi

if [[ ! -x "$WAZUH_HOME/bin/wazuh-analysisd" || ! -f "$OSSEC_CONF" ]]; then
    echo "ERROR: no parece un Wazuh Manager válido en $WAZUH_HOME." >&2
    exit 1
fi

WAZUH_GROUP="$(stat -c '%G' "$OSSEC_CONF")"
if ! getent group "$WAZUH_GROUP" >/dev/null 2>&1; then
    echo "ERROR: no existe el grupo propietario $WAZUH_GROUP." >&2
    exit 1
fi

RUN_ID="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/orangebox-wazuh-ioc-deploy/$RUN_ID"
mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

declare -a SOURCE_FILES=(
    "configuration/manager/etc/rules/orangebox-ioc.xml"
    "configuration/manager/etc/rules/orangebox-web.xml"
    "configuration/manager/etc/rules/orangebox-php2shell.xml"
    "configuration/manager/integrations/custom-orangebox-email.py"
    "configuration/manager/integrations/orangebox_active_response.py"
    "configuration/manager/bin/update-orangebox-ioc-lists.sh"
)
declare -a TARGET_FILES=(
    "etc/rules/orangebox-ioc.xml"
    "etc/rules/orangebox-web.xml"
    "etc/rules/orangebox-php2shell.xml"
    "integrations/custom-orangebox-email.py"
    "integrations/orangebox_active_response.py"
    "bin/update-orangebox-ioc-lists.sh"
)
declare -a MODES=("0640" "0640" "0640" "0750" "0640" "0750")
declare -a OBSOLETE_TARGETS=("bin/update-orangebox-ioc-lists-v2.sh" "bin/parse_urlhaus_recent.py")
declare -a ROLLBACK_FILES=("etc/ossec.conf" "${TARGET_FILES[@]}" "${OBSOLETE_TARGETS[@]}" "etc/lists/malicious-ioc/orangebox-confirmed-source-ip")

if [[ ! -f "$CONFIRMED_SOURCE_SEED" ]]; then
    echo "ERROR: falta la lista semilla $CONFIRMED_SOURCE_SEED." >&2
    exit 1
fi

# Comprueba todos los archivos versionados antes de tocar el Manager.
# Instala reglas, integración y updater con propietario y modos definidos.
for i in "${!SOURCE_FILES[@]}"; do
    src="$ROOT/${SOURCE_FILES[$i]}"
    [[ -f "$src" ]] || {
        echo "ERROR: falta archivo versionado $src." >&2
        exit 1
    }
done

# Back up existing files and remember paths that did not exist before deploy.
# Guarda cada destino existente y registra cuáles deben borrarse durante rollback.
for rel in "${ROLLBACK_FILES[@]}"; do
    dst="$WAZUH_HOME/$rel"
    saved="$BACKUP_DIR/$rel"
    mkdir -p "$(dirname "$saved")"
    if [[ -e "$dst" ]]; then
        cp -a "$dst" "$saved"
    else
        : > "$BACKUP_DIR/$rel.__MISSING__"
    fi
done

ROLLBACK_REQUIRED=1
PY_CACHE=""
MERGE_TMP=""

# Limpia temporales y restaura todos los destinos si alguna validación o reinicio falla.
cleanup() {
    local rc="$?"
    if [[ -n "$PY_CACHE" && -d "$PY_CACHE" ]]; then
        rm -rf "$PY_CACHE"
    fi
    if [[ -n "$MERGE_TMP" && -f "$MERGE_TMP" ]]; then
        rm -f "$MERGE_TMP"
    fi
    if (( rc != 0 && ROLLBACK_REQUIRED == 1 )); then
        echo
        echo "ERROR: falló el despliegue. Restaurando archivos desde $BACKUP_DIR..."
        # Restaura los archivos respaldados y elimina los que antes no existían.
        for rel in "${ROLLBACK_FILES[@]}"; do
            target="$WAZUH_HOME/$rel"
            saved="$BACKUP_DIR/$rel"
            missing="$BACKUP_DIR/$rel.__MISSING__"
            if [[ -f "$saved" ]]; then
                mkdir -p "$(dirname "$target")"
                cp -a "$saved" "$target"
            elif [[ -f "$missing" ]]; then
                rm -f "$target"
            fi
        done
        systemctl restart wazuh-manager || true
        echo "Rollback terminado. Backup conservado en $BACKUP_DIR."
    fi
    exit "$rc"
}
trap cleanup EXIT

echo "========== BACKUP =========="
echo "Backup: $BACKUP_DIR"

echo
echo "========== DEPLOY FILES =========="
for i in "${!SOURCE_FILES[@]}"; do
    src="$ROOT/${SOURCE_FILES[$i]}"
    dst="$WAZUH_HOME/${TARGET_FILES[$i]}"
    mode="${MODES[$i]}"
    install -D -o root -g "$WAZUH_GROUP" -m "$mode" "$src" "$dst"
    echo "INSTALLED: ${TARGET_FILES[$i]}"
done

echo
echo "========== MERGE CONFIRMED SOURCE-IP SEED =========="
mkdir -p "$(dirname "$CONFIRMED_SOURCE_TARGET")"
MERGE_TMP="$BACKUP_DIR/orangebox-confirmed-source-ip.merged"
python3 - "$CONFIRMED_SOURCE_SEED" "$CONFIRMED_SOURCE_TARGET" "$MERGE_TMP" <<'PY'
import ipaddress
import sys
from pathlib import Path

seed_path, live_path, output_path = map(Path, sys.argv[1:4])
addresses = set()

# Combina la semilla versionada con la lista local sin retirar IOC existentes.
for path in (seed_path, live_path):
    if not path.is_file():
        continue
# Valida cada entrada: acepta comentarios/vacíos y solo IPv4 en formato CDB.
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.endswith(":"):
            raise SystemExit(f"ERROR: entrada inválida en {path}:{line_number}; se esperaba IPv4:.")
        try:
            address = ipaddress.ip_address(line[:-1].strip())
        except ValueError as exc:
            raise SystemExit(f"ERROR: IP inválida en {path}:{line_number}: {exc}")
        if not isinstance(address, ipaddress.IPv4Address):
            raise SystemExit(f"ERROR: solo se aceptan IPv4 en {path}:{line_number}.")
        addresses.add(str(address))

# Una semilla pública sin IOC es válida. Si el Manager ya tiene entradas
# locales, se preservan; si no, se instala una CDB vacía hasta agregar IOC
# confirmados manualmente. El feed automático Emerging Threats sigue aparte.
ordered = sorted(addresses, key=lambda value: tuple(int(part) for part in value.split(".")))
output_path.write_text("".join(f"{address}:\n" for address in ordered), encoding="ascii")
print(f"Confirmed source IPs preserved/seeded: {len(ordered)}")
PY
install -o root -g "$WAZUH_GROUP" -m 0640 "$MERGE_TMP" "$CONFIRMED_SOURCE_TARGET"
rm -f "$MERGE_TMP"
MERGE_TMP=""
echo "INSTALLED/MERGED: etc/lists/malicious-ioc/orangebox-confirmed-source-ip"

echo
echo "========== REMOVE OBSOLETE IOC HELPERS =========="
# Retira helpers de versiones antiguas que ya no forman parte del instalador.
for rel in "${OBSOLETE_TARGETS[@]}"; do
    if [[ -e "$WAZUH_HOME/$rel" ]]; then
        rm -f "$WAZUH_HOME/$rel"
        echo "REMOVED: $rel"
    fi
done

echo
echo "========== PATCH LIVE IOC ACTIVE RESPONSE =========="
python3 "$ROOT/tools/patch-ioc-active-response-conf.py" --config "$OSSEC_CONF"

echo
echo "========== PYTHON SYNTAX =========="
PY_CACHE="$(mktemp -d /var/tmp/orangebox-pycache.XXXXXX)"
PYTHONPYCACHEPREFIX="$PY_CACHE" python3 -m py_compile \
    "$WAZUH_HOME/integrations/custom-orangebox-email.py" \
    "$WAZUH_HOME/integrations/orangebox_active_response.py"
rm -rf "$PY_CACHE"
PY_CACHE=""
echo "Python syntax OK."

echo
echo "========== XML SYNTAX =========="
python3 - "$OSSEC_CONF" \
    "$WAZUH_HOME/etc/rules/orangebox-ioc.xml" \
    "$WAZUH_HOME/etc/rules/orangebox-web.xml" \
    "$WAZUH_HOME/etc/rules/orangebox-php2shell.xml" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

# Valida sintaxis de cada archivo XML después del parcheo.
for path in sys.argv[1:]:
    content = open(path, encoding="utf-8").read()
    content = re.sub(r"<\?xml[^?]*\?>", "", content, flags=re.IGNORECASE)
    ET.fromstring("<orangebox-validation-root>" + content + "</orangebox-validation-root>")
    print(f"XML fragment OK: {path}")
PY

echo
echo "========== WAZUH RULESET =========="
"$WAZUH_HOME/bin/wazuh-analysisd" -t

echo
echo "========== IOC ACTIVE RESPONSE REGRESSION =========="
bash "$ROOT/tests/test-ioc-active-response.sh"

echo
echo "========== RESTART MANAGER =========="
systemctl restart wazuh-manager
systemctl is-active --quiet wazuh-manager

ROLLBACK_REQUIRED=0
trap - EXIT

echo
echo "DEPLOYMENT OK"
echo "Manager activo."
echo "Backup: $BACKUP_DIR"
echo
echo "IMPORTANTE: las listas IOC no fueron actualizadas por este despliegue."
echo "Primero revisar los conteos de la reclasificación:"
echo "  ORANGEBOX_IOC_DRY_RUN=1 $WAZUH_HOME/bin/update-orangebox-ioc-lists.sh"
echo "Luego, solo tras revisar y aprobar el diff, ejecutar una vez:"
echo "  ORANGEBOX_IOC_ALLOW_SOURCE_RECLASSIFICATION=1 $WAZUH_HOME/bin/update-orangebox-ioc-lists.sh"
echo "La primera actualización aprobada crea:"
echo "  $WAZUH_HOME/var/.orangebox-ioc-source-ip-separated"
echo "El cron abortará sin cambios hasta que ese marcador exista."
