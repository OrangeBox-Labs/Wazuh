#!/usr/bin/env bash
set -u
set -o pipefail

# OrangeBox Wazuh - Active Response FIM -> YARA
# ==============================================
# Recibe el JSON de Active Response por stdin, obtiene el path del evento
# FIM y analiza solamente ese archivo con el ruleset oficial Yara-Rules.
#
# Este componente NO contiene reglas YARA propias de OrangeBox.
# El instalador descarga Yara-Rules/rules en:
#   <wazuh>/active-response/bin/yara/rules/yara-rules/
#
# No elimina, mueve, cuarentena ni modifica archivos.
# Esta etapa es estrictamente de DETECCION.
#
# Compatibilidad:
#   - Wazuh agent normal: /var/ossec
#   - OrangeBox cPanel agent: /opt/ossec

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WAZUH_HOME="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
LOG_FILE="${WAZUH_HOME}/logs/active-responses.log"
RULES_DIR="${SCRIPT_DIR}/yara/rules/yara-rules"
MAX_FILE_SIZE="${ORANGEBOX_YARA_MAX_FILE_SIZE:-52428800}"  # 50 MiB

log_info() {
    printf 'wazuh-yara: INFO - %s\n' "$*" >> "${LOG_FILE}"
}

log_error() {
    printf 'wazuh-yara: ERROR - %s\n' "$*" >> "${LOG_FILE}"
}

INPUT_JSON="$(cat)"

if ! command -v jq >/dev/null 2>&1; then
    log_error "jq no esta instalado; no se puede procesar el evento FIM."
    exit 1
fi

ACTION="$(printf '%s' "${INPUT_JSON}" | jq -r '.command // .action // empty' 2>/dev/null || true)"
FILENAME="$(printf '%s' "${INPUT_JSON}" | jq -r '.parameters.alert.syscheck.path // empty' 2>/dev/null || true)"

# Procesar solamente eventos ADD cuando Active Response entrega la accion.
# Algunas variantes no incluyen command/action; en ese caso se procesa
# por presencia del path FIM.
if [[ "${ACTION}" != "add" && -n "${ACTION}" ]]; then
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

# FIM puede dispararse antes de terminar una escritura.
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

if [[ ! -d "${RULES_DIR}" ]]; then
    log_error "No se encontro el ruleset oficial: ${RULES_DIR}"
    exit 1
fi

run_scan() {
    local category="$1"
    local index_file="$2"
    local yara_output
    local line
    local rule_name
    local scanned_path

    [[ -s "${index_file}" ]] || {
        log_error "Falta el indice YARA oficial: ${index_file}"
        return 1
    }

    yara_output="$("${YARA_BIN}" -w -r "${index_file}" "${FILENAME}" 2>>"${LOG_FILE}" || true)"

    [[ -z "${yara_output}" ]] && return 0

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        rule_name="${line%% *}"
        scanned_path="${line#* }"

        if [[ -z "${rule_name}" || -z "${scanned_path}" || "${rule_name}" == "${line}" ]]; then
            log_error "Salida YARA inesperada: ${line}"
            continue
        fi

        printf 'wazuh-yara: ALERT - Match: category=%s rule=%s path=%s\n'             "${category}" "${rule_name}" "${scanned_path}" >> "${LOG_FILE}"
    done <<< "${yara_output}"
}

run_scan "webshells" "${RULES_DIR}/webshells_index.yar"
run_scan "malware" "${RULES_DIR}/malware_index.yar"

exit 0
