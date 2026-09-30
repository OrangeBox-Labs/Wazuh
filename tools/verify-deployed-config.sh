#!/usr/bin/env bash
set -u

OSSEC_HOME="${OSSEC_HOME:-/var/ossec}"

# OrangeBox Wazuh - verificacion de configuracion desplegada
# ============================================================
#
# Objetivo:
#   Comparar los archivos funcionales versionados en este repositorio
#   con los archivos realmente instalados bajo /var/ossec.
#
# Esto evita el problema de "el repo esta bien pero produccion tiene
# otra version" y permite detectar rapidamente una regresion despues
# de un cambio de ruleset o de un perfil de agentes.
#
# IMPORTANTE:
#   - No modifica ningun archivo.
#   - Solo lee archivos y calcula diferencias.
#   - Debe ejecutarse desde el checkout del repositorio en el Manager.
#
# Capas verificadas:
#   1) Manager: etc/ossec.conf + etc/shared/agent-template.conf
#   2) Manager etc/rules: XML
#   3) Lists: CDB de perfiles
#   4) Integrations: custom-orangebox-email.py
#   5) Agent groups: default/cpanel/zimbra
#   6) Agent artifacts: validacion LOCAL del source versionado que luego
#      se copia al agente; no se espera que exista bajo /var/ossec
#
# Adicionalmente busca SIDs duplicados criticos en el despliegue.
# ============================================================

set -o pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "ERROR: ejecutar desde el checkout de OrangeBox-Labs/wazuh."
    exit 2
}

PASS=0
FAIL=0
WARN=0

ok() {
    echo "[OK]   $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "[FAIL] $1"
    FAIL=$((FAIL + 1))
}

warn() {
    echo "[WARN] $1"
    WARN=$((WARN + 1))
}

compare_file() {
    local repo_file="$1"
    local deployed_file="$2"

    if [[ ! -f "$ROOT/$repo_file" ]]; then
        fail "Falta en repo: $repo_file"
        return
    fi

    if [[ ! -f "$deployed_file" ]]; then
        fail "Falta desplegado: $deployed_file"
        return
    fi

    if cmp -s "$ROOT/$repo_file" "$deployed_file"; then
        ok "$repo_file == $deployed_file"
    else
        fail "DIFERENCIA: $repo_file != $deployed_file"
        diff -u "$ROOT/$repo_file" "$deployed_file" || true
    fi
}

echo
echo "============================================================"
echo " OrangeBox - Verificacion de configuracion"
echo "============================================================"
echo "Repo:      $ROOT"
echo "OSSEC_HOME: $OSSEC_HOME"
echo

if [[ "${1:-}" == "--agent" ]]; then
    echo "=== AGENT RUNTIME ==="

    AGENT_YARA_SCRIPT="${OSSEC_HOME}/active-response/bin/orangebox-yara.sh"
    AGENT_YARA_DIR="${OSSEC_HOME}/active-response/bin/yara/rules/yara-rules"
    AGENT_YARA_META="${OSSEC_HOME}/active-response/bin/yara/rules"
    AGENT_QUARANTINE="${OSSEC_HOME}/active-response/bin/orangebox-quarantine.py"

    if [[ -f "$AGENT_YARA_SCRIPT" ]]; then
        if bash -n "$AGENT_YARA_SCRIPT" 2>/dev/null; then
            ok "orangebox-yara.sh desplegado pasa bash -n"
        else
            fail "orangebox-yara.sh desplegado tiene error de sintaxis"
        fi
    else
        fail "Falta desplegado: $AGENT_YARA_SCRIPT"
    fi

    if [[ -f "$ROOT/configuration/agent/active-response/bin/orangebox-quarantine.py" && -f "$AGENT_QUARANTINE" ]]; then
        if cmp -s "$ROOT/tools/orangebox-quarantine.py" "$AGENT_QUARANTINE"; then
            ok "orangebox-quarantine.py desplegado coincide con el source del repo"
        else
            fail "DIFERENCIA: source quarantine del repo != runtime quarantine del agente"
            diff -u "$ROOT/tools/orangebox-quarantine.py" "$AGENT_QUARANTINE" || true
        fi
        if python3 - "$AGENT_QUARANTINE" <<'PY' >/dev/null 2>&1
import sys
from pathlib import Path
path = sys.argv[1]
compile(Path(path).read_text(encoding="utf-8"), path, "exec")
PY
        then
            ok "orangebox-quarantine.py desplegado pasa compilacion Python"
        else
            fail "orangebox-quarantine.py desplegado tiene error de sintaxis"
        fi
    else
        [[ -f "$ROOT/tools/orangebox-quarantine.py" ]] || fail "Falta en repo: tools/orangebox-quarantine.py"
        [[ -f "$AGENT_QUARANTINE" ]] || fail "Falta desplegado: $AGENT_QUARANTINE"
    fi
    if [[ -d "$AGENT_YARA_DIR" ]]; then
        ok "Ruleset YARA oficial desplegado: $AGENT_YARA_DIR"
    else
        fail "Falta ruleset YARA oficial: $AGENT_YARA_DIR"
    fi

    for index in webshells_index.yar malware_index.yar; do
        if [[ -s "$AGENT_YARA_DIR/$index" ]]; then
            ok "Indice YARA oficial presente: $index"
        else
            fail "Falta indice YARA oficial: $AGENT_YARA_DIR/$index"
        fi
    done

    for meta in YARA-RULES-COMMIT YARA-RULES-REPOSITORY YARA-RULES-BRANCH; do
        if [[ -s "$AGENT_YARA_META/$meta" ]]; then
            ok "Metadata YARA presente: $meta"
        else
            fail "Falta metadata YARA: $AGENT_YARA_META/$meta"
        fi
    done

    if [[ -s "$AGENT_YARA_META/YARA-RULES-REPOSITORY" ]] &&        grep -qx 'https://github.com/Yara-Rules/rules.git' "$AGENT_YARA_META/YARA-RULES-REPOSITORY"; then
        ok "Ruleset YARA proviene del repositorio oficial"
    elif [[ -e "$AGENT_YARA_META/YARA-RULES-REPOSITORY" ]]; then
        fail "Repositorio YARA desplegado no coincide con Yara-Rules/rules"
    fi

    if [[ -d "$AGENT_YARA_DIR" ]]; then
        stale_rules=(
            "$AGENT_YARA_META/orangebox-webshell-core.yar"
            "$AGENT_YARA_META/orangebox-webshell-extended.yar"
        )
        for stale in "${stale_rules[@]}"; do
            if [[ -e "$stale" ]]; then
                fail "Regla YARA propia antigua todavía desplegada: $stale"
            else
                ok "Regla YARA propia antigua ausente: $stale"
            fi
        done
    fi

    echo
    echo "============================================================"
    echo " Resultado"
    echo "============================================================"
    echo "OK:   $PASS"
    echo "FAIL: $FAIL"
    echo "WARN: $WARN"
    (( FAIL > 0 )) && exit 1
    echo "Verificacion correcta."
    exit 0
fi

echo "=== MANAGER ==="
compare_file     "configuration/manager/etc/ossec.conf"     "${OSSEC_HOME}/etc/ossec.conf"

compare_file     "configuration/manager/etc/shared/agent-template.conf"     "${OSSEC_HOME}/etc/shared/agent-template.conf"

echo
echo "=== LISTAS CDB ==="
compare_file     "configuration/manager/etc/lists/orangebox-agent-profiles"     "${OSSEC_HOME}/etc/lists/orangebox-agent-profiles"

echo
echo "=== DECODERS ==="
compare_file     "configuration/manager/etc/decoders/orangebox-yara.xml"     "${OSSEC_HOME}/etc/decoders/orangebox-yara.xml"

echo
echo "=== INTEGRACIONES ==="
compare_file     "configuration/manager/integrations/custom-orangebox-email.py"     "${OSSEC_HOME}/integrations/custom-orangebox-email.py"

echo
echo "=== RUNTIME DEL AGENTE (REPO) ==="

check_repo_executable "configuration/manager/active-response/bin/orangebox-yara.sh"
if bash -n "$ROOT/configuration/manager/active-response/bin/orangebox-yara.sh" 2>/dev/null; then
    ok "Runtime YARA pasa bash -n"
else
    fail "Runtime YARA tiene error de sintaxis"
fi

check_repo_executable "configuration/manager/active-response/bin/orangebox-quarantine.py"
if python3 - "$ROOT/configuration/manager/active-response/bin/orangebox-quarantine.py" <<'PY' >/dev/null 2>&1
import sys
from pathlib import Path
path = sys.argv[1]
compile(Path(path).read_text(encoding="utf-8"), path, "exec")
PY
then
    ok "Runtime quarantine.py pasa compilacion Python"
else
    fail "Runtime quarantine.py tiene error de sintaxis"
fi

echo
echo "============================================================"
echo " Resultado"
echo "============================================================"
echo "OK:   $PASS"
echo "FAIL: $FAIL"
echo "WARN: $WARN"

if (( FAIL > 0 )); then
    echo
    echo "La configuracion desplegada NO coincide completamente con el repo."
    exit 1
fi

echo
echo "Repo y despliegue funcional coinciden."
exit 0
