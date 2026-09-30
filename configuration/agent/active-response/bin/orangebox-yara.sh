#!/usr/bin/env bash
set -u
set -o pipefail

# OrangeBox Wazuh - Active Response FIM -> YARA
# Analiza solo el archivo indicado por FIM con el ruleset oficial Yara-Rules.
# Esta etapa detecta; no elimina ni modifica el archivo.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WAZUH_HOME="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
LOG_FILE="${WAZUH_HOME}/logs/active-responses.log"
RULES_DIR="${SCRIPT_DIR}/yara/rules/yara-rules"
MAX_FILE_SIZE='5242880'

log_info() { printf 'wazuh-yara: INFO - %s\n' "$*" >> "${LOG_FILE}"; }
log_error() { printf 'wazuh-yara: ERROR - %s\n' "$*" >> "${LOG_FILE}"; }

INPUT_JSON="$(cat)"
command -v jq >/dev/null 2>&1 || { log_error "jq no esta instalado."; exit 1; }

ACTION="$(printf '%s' "${INPUT_JSON}" | jq -r '.command // .action // empty' 2>/dev/null || true)"
FILENAME="$(printf '%s' "${INPUT_JSON}" | jq -r '.parameters.alert.syscheck.path // empty' 2>/dev/null || true)"

[[ "${ACTION}" != "add" && -n "${ACTION}" ]] && exit 0
[[ -n "${FILENAME}" && "${FILENAME}" != "null" ]] || { log_error "No se obtuvo el path FIM."; exit 1; }
[[ -e "${FILENAME}" ]] || { log_error "El archivo ya no existe: ${FILENAME}"; exit 0; }
[[ ! -L "${FILENAME}" ]] || { log_info "Archivo omitido por ser symlink: ${FILENAME}"; exit 0; }
[[ -f "${FILENAME}" ]] || { log_info "Archivo omitido por no ser regular: ${FILENAME}"; exit 0; }

FILE_SIZE="$(stat -c '%s' -- "${FILENAME}" 2>/dev/null || echo 0)"
if [[ "${FILE_SIZE}" =~ ^[0-9]+$ ]] && (( FILE_SIZE > MAX_FILE_SIZE )); then
    log_info "Archivo omitido por superar 5 MiB: ${FILENAME}"
    exit 0
fi

PREV_SIZE="${FILE_SIZE}"
for _ in 1 2 3 4 5; do
    sleep 1
    [[ -f "${FILENAME}" ]] || exit 0
    CURRENT_SIZE="$(stat -c '%s' -- "${FILENAME}" 2>/dev/null || echo 0)"
    [[ "${CURRENT_SIZE}" == "${PREV_SIZE}" ]] && break
    PREV_SIZE="${CURRENT_SIZE}"
done

YARA_BIN="${ORANGEBOX_YARA_BIN:-}"
if [[ -z "${YARA_BIN}" ]]; then
    for candidate in /usr/local/bin/yara /usr/bin/yara /usr/local/sbin/yara; do
        [[ -x "${candidate}" ]] && { YARA_BIN="${candidate}"; break; }
    done
fi

[[ -x "${YARA_BIN}" ]] || { log_error "No se encontro YARA."; exit 1; }
[[ -d "${RULES_DIR}" ]] || { log_error "No se encontro el ruleset oficial."; exit 1; }

run_scan() {
    local category="$1" index_file="$2" yara_output line rule_name scanned_path
    [[ -s "${index_file}" ]] || { log_error "Falta el indice YARA: ${index_file}"; return 1; }
    yara_output="$("${YARA_BIN}" -w -r "${index_file}" "${FILENAME}" 2>>"${LOG_FILE}" || true)"
    [[ -z "${yara_output}" ]] && return 0
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        rule_name="${line%% *}"
        scanned_path="${line#* }"
        [[ -n "${rule_name}" && -n "${scanned_path}" && "${rule_name}" != "${line}" ]] || continue
        printf 'wazuh-yara: ALERT - Match: category=%s rule=%s path=%s\n'             "${category}" "${rule_name}" "${scanned_path}" >> "${LOG_FILE}"
    done <<< "${yara_output}"
}

run_scan "webshells" "${RULES_DIR}/webshells_index.yar"
run_scan "malware" "${RULES_DIR}/malware_index.yar"
exit 0
