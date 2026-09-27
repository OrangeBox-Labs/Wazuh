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

    if [[ -f "$AGENT_YARA_SCRIPT" ]]; then
        if bash -n "$AGENT_YARA_SCRIPT" 2>/dev/null; then
            ok "orangebox-yara.sh existe y pasa bash -n"
        else
            fail "orangebox-yara.sh tiene error de sintaxis"
        fi
    else
        fail "Falta desplegado: $AGENT_YARA_SCRIPT"
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
echo "=== AGENT GROUPS ==="
compare_file     "configuration/manager/etc/shared/default/agent.conf"     "${OSSEC_HOME}/etc/shared/default/agent.conf"

compare_file     "configuration/manager/etc/shared/cpanel/agent.conf"     "${OSSEC_HOME}/etc/shared/cpanel/agent.conf"

compare_file     "configuration/manager/etc/shared/zimbra/agent.conf"     "${OSSEC_HOME}/etc/shared/zimbra/agent.conf"

compare_file     "configuration/manager/etc/shared/webserver/agent.conf"     "${OSSEC_HOME}/etc/shared/webserver/agent.conf"

echo
echo "=== RULES XML/YARA ==="

shopt -s nullglob
for repo_file in "$ROOT"/configuration/manager/etc/rules/*.xml; do
    base="$(basename "$repo_file")"
    compare_file         "configuration/manager/etc/rules/$base"         "${OSSEC_HOME}/etc/rules/$base"
done
shopt -u nullglob

echo
echo "=== SIDs CRITICOS ==="

echo "-- Reglas OrangeBox duplicadas en ${OSSEC_HOME}/etc/rules --"
mapfile -t duplicate_sids < <(
    grep -Rho '<rule id="[0-9][0-9]*"' ${OSSEC_HOME}/etc/rules --include='*.xml' 2>/dev/null |
        sed -E 's/.*id="([0-9]+)".*/\1/' |
        sort |
        uniq -d
)

if (( ${#duplicate_sids[@]} == 0 )); then
    ok "No hay SIDs duplicados en el ruleset desplegado"
else
    fail "SIDs duplicados detectados:"
    for sid in "${duplicate_sids[@]}"; do
        grep -Rns "<rule id=\"$sid\"" ${OSSEC_HOME}/etc/rules --include='*.xml' 2>/dev/null || true
    done
fi

echo
echo "-- SIDs Zimbra antiguos que NO deben existir --"
for stale_sid in 20100 120100; do
    mapfile -t stale_hits < <(
        grep -Rns "<rule id=\"$stale_sid\"" ${OSSEC_HOME}/etc/rules --include='*.xml' 2>/dev/null || true
    )

    if (( ${#stale_hits[@]} == 0 )); then
        ok "SID antiguo $stale_sid ausente"
    else
        fail "SID antiguo $stale_sid todavia desplegado:"
        printf '       %s\n' "${stale_hits[@]}"
    fi
done

echo
echo "-- Regla 110100 (Zimbra/Carbonio) --"
mapfile -t sid110100 < <(
    grep -Rns '<rule id="110100"' ${OSSEC_HOME}/etc/rules --include='*.xml' 2>/dev/null || true
)

if (( ${#sid110100[@]} == 0 )); then
    fail "110100 no esta desplegada"
elif (( ${#sid110100[@]} == 1 )); then
    ok "110100 desplegada una sola vez: ${sid110100[0]}"
else
    fail "110100 DUPLICADA:"
    printf '       %s\n' "${sid110100[@]}"
fi

echo
echo "-- Colisiones con ruleset nativo --"
native110100="$(grep -Rhc '<rule id="110100"' ${OSSEC_HOME}/ruleset/rules --include='*.xml' 2>/dev/null | awk '{s+=$1} END{print s+0}')"
if [[ "$native110100" == "0" ]]; then
    ok "110100 no colisiona con ruleset nativo"
else
    fail "110100 aparece $native110100 veces en ruleset nativo"
fi

echo
echo "-- Regla 10005 --"
count10005="$(grep -Rhc '<rule id="10005"' ${OSSEC_HOME}/etc/rules --include='*.xml' 2>/dev/null | awk '{s+=$1} END{print s+0}')"
if [[ "$count10005" == "1" ]]; then
    ok "10005 desplegada una sola vez"
else
    fail "10005 aparece $count10005 veces"
fi

echo
echo "-- Perfiles CDB --"
if grep -q '^srv27:cpanel$' ${OSSEC_HOME}/etc/lists/orangebox-agent-profiles 2>/dev/null; then
    ok "Perfil cPanel srv27"
else
    fail "Falta srv27:cpanel"
fi

if grep -q '^TU_HOSTNAME:cpanel$' ${OSSEC_HOME}/etc/lists/orangebox-agent-profiles 2>/dev/null; then
    ok "Perfil cPanel TU_HOSTNAME"
else
    fail "Falta TU_HOSTNAME:cpanel"
fi

zimbra_profile_count="$(grep -c ':zimbra$' ${OSSEC_HOME}/etc/lists/orangebox-agent-profiles 2>/dev/null || true)"
ok "Entradas de perfil zimbra registradas: $zimbra_profile_count"
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
