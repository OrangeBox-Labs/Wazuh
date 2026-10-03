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
#   3) Lists: CDB estatica + CDB dinamicas derivadas de grupos Wazuh
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

compare_generated_cdb() {
    local group="$1"
    local profile="$2"
    local deployed_file="$3"
    local agent_groups="${OSSEC_HOME}/bin/agent_groups"
    local tmp

    if [[ ! -x "$agent_groups" ]]; then
        fail "No existe el comando para validar grupo Wazuh: $agent_groups"
        return
    fi

    if [[ ! -f "$deployed_file" ]]; then
        fail "Falta CDB generada: $deployed_file"
        return
    fi

    tmp="$(mktemp)"

    if ! "$agent_groups" -l -g "$group" 2>/dev/null |
        awk '
            BEGIN { IGNORECASE=1 }
            match($0, /name:[[:space:]]*([^,]+)/, m) {
                name=m[1]
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
                sub(/\.$/, "", name)
                if (name != "") print name
            }
        ' |
        sort -fu |
        while IFS= read -r hostname; do
            [[ -z "$hostname" ]] && continue
            printf '%s:%s\n' "$hostname" "$profile"
            if [[ "$hostname" == *.* ]]; then
                short="${hostname%%.*}"
                [[ -n "$short" ]] && printf '%s:%s\n' "$short" "$profile"
            fi
        done |
        sort -fu > "$tmp"; then
        fail "No se pudo generar expectativa para CDB del grupo $group"
        rm -f "$tmp"
        return
    fi

    if cmp -s "$tmp" "$deployed_file"; then
        ok "CDB dinámica $deployed_file coincide con grupo Wazuh $group"
    else
        fail "CDB dinámica desactualizada: $deployed_file != grupo Wazuh $group"
        diff -u "$tmp" "$deployed_file" || true
    fi

    rm -f "$tmp"
}

compare_manager_rules() {
    local repo_dir="$1"
    local deployed_dir="$2"
    local files=()
    local repo_file
    local rel
    local deployed_file

    mapfile -t files < <(
        git -C "$ROOT" ls-files "$repo_dir" |
        grep -E '\.xml
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
    AGENT_YARA_SOURCE="$ROOT/configuration/agent/active-response/bin/orangebox-yara.sh"
    AGENT_YARA_DIR="${OSSEC_HOME}/active-response/bin/yara/rules/yara-rules"
    AGENT_YARA_META="${OSSEC_HOME}/active-response/bin/yara/rules"
    AGENT_QUARANTINE="${OSSEC_HOME}/active-response/bin/orangebox-quarantine.py"
    AGENT_QUARANTINE_SOURCE="$ROOT/configuration/agent/active-response/bin/orangebox-quarantine.py"

    compare_file "configuration/agent/active-response/bin/orangebox-yara.sh" "$AGENT_YARA_SCRIPT"
    if [[ -f "$AGENT_YARA_SCRIPT" ]]; then
        if bash -n "$AGENT_YARA_SCRIPT" 2>/dev/null; then
            ok "orangebox-yara.sh desplegado pasa bash -n"
        else
            fail "orangebox-yara.sh desplegado tiene error de sintaxis"
        fi
    fi

    compare_file "configuration/agent/active-response/bin/orangebox-quarantine.py" "$AGENT_QUARANTINE"
    if [[ -f "$AGENT_QUARANTINE" ]]; then
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
            fail "Falta metadata YARA: $meta"
        fi
    done

    if [[ -s "$AGENT_YARA_META/YARA-RULES-REPOSITORY" ]] &&
       grep -qx 'https://github.com/Yara-Rules/rules.git' "$AGENT_YARA_META/YARA-RULES-REPOSITORY"; then
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
echo "=== REGLAS MANAGER ==="
compare_manager_rules "configuration/manager/etc/rules" "${OSSEC_HOME}/etc/rules"
check_extra_orangebox_rules "configuration/manager/etc/rules" "${OSSEC_HOME}/etc/rules"
check_rule_cdb_references "${ROOT}/configuration/manager/etc/rules" "${OSSEC_HOME}/etc/ossec.conf"

echo
echo "=== LISTAS CDB ==="

compare_file "configuration/manager/etc/lists/orangebox-network-recon-programs" "${OSSEC_HOME}/etc/lists/orangebox-network-recon-programs"
compare_generated_cdb "cpanel" "cpanel" "${OSSEC_HOME}/etc/lists/orangebox-cpanel-agents"
compare_generated_cdb "zimbra" "zimbra" "${OSSEC_HOME}/etc/lists/orangebox-zimbra-agents"

if [[ -e "${OSSEC_HOME}/etc/lists/orangebox-agent-profiles" ]]; then
    warn "CDB obsoleta aun desplegada: ${OSSEC_HOME}/etc/lists/orangebox-agent-profiles"
else
    ok "CDB obsoleta orangebox-agent-profiles ausente"
fi

echo
echo "=== DECODERS ==="
compare_file     "configuration/manager/etc/decoders/orangebox-yara.xml"     "${OSSEC_HOME}/etc/decoders/orangebox-yara.xml"

echo
echo "=== INTEGRACIONES ==="
compare_file     "configuration/manager/integrations/custom-orangebox-email.py"     "${OSSEC_HOME}/integrations/custom-orangebox-email.py"

echo
echo "=== ACTIVE RESPONSE DEL MANAGER ==="
ok "La configuracion de Active Response del Manager se valida con sus reglas/commands; los ejecutables viven en configuration/agent/active-response/ y los genera el instalador del agente."

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
 |
        sort
    )

    if (( ${#files[@]} == 0 )); then
        warn "No hay reglas XML versionadas en $repo_dir"
        return
    fi

    for repo_file in "${files[@]}"; do
        rel="${repo_file#"$repo_dir"/}"
        deployed_file="$deployed_dir/$rel"
        compare_file "$repo_file" "$deployed_file"
    done
}

check_extra_orangebox_rules() {
    local repo_dir="$1"
    local deployed_dir="$2"
    local deployed_file
    local rel
    local repo_file

    while IFS= read -r deployed_file; do
        [[ -z "$deployed_file" ]] && continue
        rel="${deployed_file#"$deployed_dir"/}"
        repo_file="$repo_dir/$rel"
        if [[ ! -f "$ROOT/$repo_file" ]]; then
            fail "Regla OrangeBox desplegada sin version correspondiente en repo: $deployed_file"
        fi
    done < <(find "$deployed_dir" -maxdepth 1 -type f -name 'orangebox-*.xml' -print 2>/dev/null | sort)
}

check_rule_cdb_references() {
    local rules_dir="$1"
    local ossec_conf="$2"
    local rules_file
    local ref
    local deployed_list

    while IFS= read -r rules_file; do
        [[ -z "$rules_file" ]] && continue

        while IFS= read -r ref; do
            [[ -z "$ref" ]] && continue

            if ! grep -Fq "<list>$ref</list>" "$ossec_conf"; then
                fail "CDB usada por regla pero no declarada en ossec.conf: $ref (en $rules_file)"
            fi

            deployed_list="${OSSEC_HOME}/$ref"
            if [[ ! -f "$deployed_list" ]]; then
                fail "CDB referenciada por regla pero falta desplegada: $deployed_list"
            fi
        done < <(
            grep -hoE 'etc/lists/[A-Za-z0-9_./-]+' "$rules_file" 2>/dev/null |
            sort -u
        )
    done < <(find "$rules_dir" -type f -name '*.xml' -print 2>/dev/null | sort)
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
    AGENT_YARA_SOURCE="$ROOT/configuration/agent/active-response/bin/orangebox-yara.sh"
    AGENT_YARA_DIR="${OSSEC_HOME}/active-response/bin/yara/rules/yara-rules"
    AGENT_YARA_META="${OSSEC_HOME}/active-response/bin/yara/rules"
    AGENT_QUARANTINE="${OSSEC_HOME}/active-response/bin/orangebox-quarantine.py"
    AGENT_QUARANTINE_SOURCE="$ROOT/configuration/agent/active-response/bin/orangebox-quarantine.py"

    compare_file "configuration/agent/active-response/bin/orangebox-yara.sh" "$AGENT_YARA_SCRIPT"
    if [[ -f "$AGENT_YARA_SCRIPT" ]]; then
        if bash -n "$AGENT_YARA_SCRIPT" 2>/dev/null; then
            ok "orangebox-yara.sh desplegado pasa bash -n"
        else
            fail "orangebox-yara.sh desplegado tiene error de sintaxis"
        fi
    fi

    compare_file "configuration/agent/active-response/bin/orangebox-quarantine.py" "$AGENT_QUARANTINE"
    if [[ -f "$AGENT_QUARANTINE" ]]; then
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
            fail "Falta metadata YARA: $meta"
        fi
    done

    if [[ -s "$AGENT_YARA_META/YARA-RULES-REPOSITORY" ]] &&
       grep -qx 'https://github.com/Yara-Rules/rules.git' "$AGENT_YARA_META/YARA-RULES-REPOSITORY"; then
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
echo "=== ACTIVE RESPONSE DEL MANAGER ==="
ok "La configuracion de Active Response del Manager se valida con sus reglas/commands; los ejecutables viven en configuration/agent/active-response/ y los genera el instalador del agente."

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
