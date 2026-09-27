#!/usr/bin/env bash
set -euo pipefail

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

YARA_RULES_REPO="https://github.com/Yara-Rules/rules.git"
YARA_RULES_BRANCH="${ORANGEBOX_YARA_RULES_BRANCH:-master}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: ejecutar como root." >&2
    exit 1
fi

if [[ -x /opt/ossec/bin/wazuh-control ]]; then
    WAZUH_HOME="/opt/ossec"
elif [[ -x /var/ossec/bin/wazuh-control ]]; then
    WAZUH_HOME="/var/ossec"
else
    echo "ERROR: no se encontro un Wazuh Agent en /opt/ossec ni /var/ossec." >&2
    exit 1
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
        exit 1
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
            "${manager}" install -y "${packages[@]}"
            ;;
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            "${manager}" update
            "${manager}" install -y "${packages[@]}"
            ;;
    esac
}

if [[ "${ORANGEBOX_YARA_NO_PACKAGE_INSTALL:-no}" != "yes" ]]; then
    install_missing_packages
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq es requerido por orangebox-yara.sh." >&2
    echo "Instale jq o use ORANGEBOX_YARA_NO_PACKAGE_INSTALL=yes si ya esta disponible por otra ruta." >&2
    exit 1
fi

YARA_BIN="${ORANGEBOX_YARA_BIN:-}"
if [[ -n "${YARA_BIN}" ]]; then
    [[ -x "${YARA_BIN}" ]] || {
        echo "ERROR: ORANGEBOX_YARA_BIN no es ejecutable: ${YARA_BIN}" >&2
        exit 1
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
    exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

SCRIPT_SRC="${TMP_DIR}/orangebox-yara.sh"

cat > "${SCRIPT_SRC}" <<'ORANGEBOX_YARA_SCRIPT'
#!/usr/bin/env bash
set -u
set -o pipefail

# OrangeBox Wazuh - Active Response FIM -> YARA
# ==============================================
#
# Analiza unicamente el archivo que disparo FIM y utiliza EXCLUSIVAMENTE
# los indices oficiales descargados desde:
#   https://github.com/Yara-Rules/rules
#
# No contiene firmas YARA propias de OrangeBox.
# No elimina, mueve, cuarentena ni modifica archivos.
#
# Compatibilidad:
#   - Wazuh agent normal: /var/ossec
#   - OrangeBox cPanel/Enterprise: /opt/ossec
#
# El Manager decide que eventos son candidatos mediante 10420/10421.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WAZUH_HOME="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
LOG_FILE="${WAZUH_HOME}/logs/active-responses.log"
RULES_DIR="${SCRIPT_DIR}/yara/rules"
RULESET_DIR="${RULES_DIR}/yara-rules"
MAX_FILE_SIZE="${ORANGEBOX_YARA_MAX_FILE_SIZE:-52428800}"

log_info() {
    printf 'wazuh-yara: INFO - %s\n' "$*" >> "${LOG_FILE}"
}

log_error() {
    printf 'wazuh-yara: ERROR - %s\n' "$*" >> "${LOG_FILE}"
}

log_match() {
    printf 'wazuh-yara: ALERT - Match: category=%s rule=%s path=%s\n' "$1" "$2" "$3" >> "${LOG_FILE}"
}

INPUT_JSON=""

if [[ $# -ge 1 && -n "${1:-}" ]]; then
    INPUT_JSON="$1"
else
    IFS= read -r INPUT_JSON || true
fi

if [[ -z "${INPUT_JSON}" ]]; then
    log_error "No se recibio payload JSON de Active Response por argumento ni STDIN."
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    log_error "jq no esta instalado; no se puede procesar el evento FIM."
    exit 1
fi

if ! printf "%s" "${INPUT_JSON}" | jq -e . >/dev/null 2>&1; then
    log_error "Payload de Active Response invalido; no es JSON."
    exit 1
fi

ACTION="$(printf '%s' "${INPUT_JSON}" | jq -r '.command // .action // empty' 2>/dev/null || true)"
FILENAME="$(printf '%s' "${INPUT_JSON}" | jq -r '.parameters.alert.syscheck.path // empty' 2>/dev/null || true)"

if [[ -n "${ACTION}" && "${ACTION}" != "add" ]]; then
    exit 0
fi

if [[ -z "${FILENAME}" || "${FILENAME}" == "null" ]]; then
    log_error "No se pudo obtener parameters.alert.syscheck.path."
    exit 1
fi

if [[ ! -e "${FILENAME}" ]]; then
    log_error "El archivo ya no existe: ${FILENAME}"
    exit 0
fi

if [[ -L "${FILENAME}" ]]; then
    log_info "Archivo omitido por ser symlink: ${FILENAME}"
    exit 0
fi

if [[ ! -f "${FILENAME}" ]]; then
    log_info "Archivo omitido por no ser regular: ${FILENAME}"
    exit 0
fi

FILE_SIZE="$(stat -c '%s' -- "${FILENAME}" 2>/dev/null || echo 0)"

if [[ "${FILE_SIZE}" =~ ^[0-9]+$ ]] && (( FILE_SIZE > MAX_FILE_SIZE )); then
    log_info "Archivo omitido por superar el limite de ${MAX_FILE_SIZE} bytes: ${FILENAME}"
    exit 0
fi

PREV_SIZE="${FILE_SIZE}"
for _ in 1 2 3 4 5; do
    sleep 1

    [[ -f "${FILENAME}" ]] || {
        log_error "El archivo desaparecio durante la espera: ${FILENAME}"
        exit 0
    }

    CURRENT_SIZE="$(stat -c '%s' -- "${FILENAME}" 2>/dev/null || echo 0)"

    if [[ "${CURRENT_SIZE}" == "${PREV_SIZE}" ]]; then
        break
    fi

    PREV_SIZE="${CURRENT_SIZE}"
done

YARA_BIN="${ORANGEBOX_YARA_BIN:-}"
if [[ -z "${YARA_BIN}" ]]; then
    for candidate in /usr/local/bin/yara /usr/bin/yara /usr/local/sbin/yara; do
        if [[ -x "${candidate}" ]]; then
            YARA_BIN="${candidate}"
            break
        fi
    done
fi

if [[ -z "${YARA_BIN}" || ! -x "${YARA_BIN}" ]]; then
    log_error "No se encontro el binario YARA."
    exit 1
fi

WEBSHELL_INDEX="${RULESET_DIR}/webshells_index.yar"
MALWARE_INDEX="${RULESET_DIR}/malware_index.yar"

for index in "${WEBSHELL_INDEX}" "${MALWARE_INDEX}"; do
    if [[ ! -s "${index}" ]]; then
        log_error "Falta el indice YARA oficial: ${index}"
        exit 1
    fi
done

run_scan() {
    local category="$1"
    local rules_file="$2"
    local yara_output
    local yara_rc
    local line
    local rule_name
    local scanned_path

    yara_output="$( "${YARA_BIN}" -w "${rules_file}" "${FILENAME}" 2>>"${LOG_FILE}" )"
    yara_rc=$?

    if (( yara_rc > 1 )); then
        log_error "YARA fallo para category=${category} path=${FILENAME} rc=${yara_rc}"
        return 1
    fi

    [[ -z "${yara_output}" ]] && return 0

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        rule_name="${line%% *}"
        scanned_path="${line#* }"

        if [[ -z "${rule_name}" || -z "${scanned_path}" || "${rule_name}" == "${line}" ]]; then
            log_error "Salida YARA inesperada para category=${category}: ${line}"
            continue
        fi

        log_match "${category}" "${rule_name}" "${scanned_path}"
    done <<< "${yara_output}"

    return 0
}

run_scan "webshells" "${WEBSHELL_INDEX}"
run_scan "malware" "${MALWARE_INDEX}"

exit 0
ORANGEBOX_YARA_SCRIPT

chmod 750 "${SCRIPT_SRC}"
bash -n "${SCRIPT_SRC}"

if ! command -v git >/dev/null 2>&1; then
    echo "ERROR: git es requerido para descargar el ruleset oficial Yara-Rules." >&2
    exit 1
fi

WAZUH_GROUP="$(stat -c '%G' "${DEST_BIN}" 2>/dev/null || true)"
if [[ -z "${WAZUH_GROUP}" || "${WAZUH_GROUP}" == "UNKNOWN" ]]; then
    WAZUH_GROUP="wazuh"
fi

install -d -m 750 -o root -g "${WAZUH_GROUP}" "${DEST_BIN}" "${DEST_YARA}" "${DEST_RULES}"
install -m 750 -o root -g "${WAZUH_GROUP}" "${SCRIPT_SRC}" "${DEST_BIN}/orangebox-yara.sh"

echo "==> Descargando Yara-Rules oficial..."
git clone --depth 1 --branch "${YARA_RULES_BRANCH}"     "${YARA_RULES_REPO}" "${TMP_DIR}/rules"

RULESET_COMMIT="$(git -C "${TMP_DIR}/rules" rev-parse HEAD)"

# Validar el ruleset completo antes de reemplazar el instalado.
for index in webshells_index.yar malware_index.yar; do
    INDEX_PATH="${TMP_DIR}/rules/${index}"

    [[ -s "${INDEX_PATH}" ]] || {
        echo "ERROR: falta el indice oficial ${index}." >&2
        exit 1
    }

    "${YARA_BIN}" -w "${INDEX_PATH}" /dev/null >/dev/null 2>&1 || {
        echo "ERROR: YARA no pudo cargar el indice ${index}." >&2
        exit 1
    }
done

# No conservar el .git del clon: el agente solo necesita las firmas.
rm -rf "${TMP_DIR}/rules/.git"

# Sustitucion controlada: el agente queda con el ruleset validado o con el
# anterior intacto si la descarga/validacion fallo.
rm -rf "${RULESET_DIR}.new"
mv "${TMP_DIR}/rules" "${RULESET_DIR}.new"
rm -rf "${RULESET_DIR}"
mv "${RULESET_DIR}.new" "${RULESET_DIR}"

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

echo "==> Instalacion validada."
echo
echo "OrangeBox YARA instalado:"
echo "  Wazuh home : ${WAZUH_HOME}"
echo "  Script      : ${DEST_BIN}/orangebox-yara.sh"
echo "  Rules       : ${RULESET_DIR}"
echo "  Rules repo  : ${YARA_RULES_REPO}"
echo "  Branch      : ${YARA_RULES_BRANCH}"
echo "  Commit      : ${RULESET_COMMIT}"
echo "  YARA        : ${YARA_BIN}"
echo "  Grupo       : ${WAZUH_GROUP}"
echo
echo "No se reinicio el agente automaticamente."
