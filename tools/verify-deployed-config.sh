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

    if [[ -f "$ROOT/tools/orangebox-quarantine.py" && -f "$AGENT_QUARANTINE" ]]; then
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
if grep -q '^cpanel01:cpanel$' ${OSSEC_HOME}/etc/lists/orangebox-agent-profiles 2>/dev/null; then
    ok "Perfil cPanel cpanel01"
else
    fail "Falta cpanel01:cpanel"
fi

if grep -q '^cpanel01.example.com:cpanel$' ${OSSEC_HOME}/etc/lists/orangebox-agent-profiles 2>/dev/null; then
    ok "Perfil cPanel cpanel01.example.com"
else
    fail "Falta cpanel01.example.com:cpanel"
fi

zimbra_profile_count="$(grep -c ':zimbra$' ${OSSEC_HOME}/etc/lists/orangebox-agent-profiles 2>/dev/null || true)"
ok "Entradas de perfil zimbra registradas: $zimbra_profile_count"
echo
echo "=== CDB CRITICAS ==="

WAZUH_GROUP="$(stat -c "%G" "$OSSEC_HOME" 2>/dev/null || echo wazuh)"
[[ "$WAZUH_GROUP" == "UNKNOWN" || -z "$WAZUH_GROUP" ]] && WAZUH_GROUP="wazuh"

CRITICAL_LISTS=(
    "orangebox-agent-profiles"
    "orangebox-private-networks"
    "orangebox-backuppc-static"
    "orangebox-backuppc-dynamic"
    "orangebox-sftp-external-user"
    "orangebox-web-auth-proxies"
    "orangebox-web-discovery-proxies"
    "orangebox-suspicious-programs"
    "orangebox-recon-programs"
)

for name in "${CRITICAL_LISTS[@]}"; do
    repo_list="$ROOT/configuration/manager/etc/lists/$name"
    deployed_list="$OSSEC_HOME/etc/lists/$name"
    if [[ ! -f "$repo_list" ]]; then
        fail "Falta en repo: $repo_list"
        continue
    fi
    if [[ ! -f "$deployed_list" ]]; then
        fail "Falta desplegado: $deployed_list"
        continue
    fi
    if cmp -s "$repo_list" "$deployed_list"; then
        ok "CDB source $name coincide con repo"
    else
        fail "DIFERENCIA CDB source: $name"
    fi
    mode="$(stat -c "%a" "$deployed_list" 2>/dev/null || echo 0)"
    owner="$(stat -c "%U" "$deployed_list" 2>/dev/null || echo UNKNOWN)"
    group="$(stat -c "%G" "$deployed_list" 2>/dev/null || echo UNKNOWN)"
    [[ "$mode" == "640" ]] && ok "Permiso 640: $deployed_list" || fail "Permiso inesperado $deployed_list: $mode (esperado 640)"
    [[ "$owner" == "root" ]] && ok "Owner root: $deployed_list" || fail "Owner inesperado $deployed_list: $owner"
    [[ "$group" == "$WAZUH_GROUP" ]] && ok "Grupo $WAZUH_GROUP: $deployed_list" || warn "Grupo CDB $deployed_list: $group (grupo Wazuh detectado: $WAZUH_GROUP)"
    cdb="${deployed_list}.cdb"
    if [[ ! -s "$cdb" ]]; then
        fail "CDB binaria ausente/vacía: $cdb"
    elif [[ "$cdb" -ot "$deployed_list" ]]; then
        fail "CDB binaria desactualizada respecto al source: $cdb"
    else
        ok "CDB binaria presente y no más antigua que source: $name"
    fi
done

echo
echo "=== AGENT ARTIFACLIENTE_01 (REPO) ==="
check_repo_executable() {
    local repo_file="$1"
    local mode

    if [[ ! -f "$ROOT/$repo_file" ]]; then
        fail "Falta en repo: $repo_file"
        return
    fi

    mode="$(stat -c "%a" "$ROOT/$repo_file" 2>/dev/null || echo 0)"
    [[ "$mode" == "755" ]] && ok "Permiso 755 en repo: $repo_file" || fail "Permiso inesperado en repo $repo_file: $mode (esperado 755)"

    if git -C "$ROOT" ls-files --stage -- "$repo_file" | grep -Eq '^100755 [0-9a-f]+ 0\s'; then
        ok "Git registra $repo_file como ejecutable (100755)"
    else
        fail "Git no registra $repo_file como ejecutable (100755)"
    fi
}

check_repo_executable "tools/orangebox-yara/install-orangebox-yara.sh"
if bash -n "$ROOT/tools/orangebox-yara/install-orangebox-yara.sh" 2>/dev/null; then
    ok "Installer YARA pasa bash -n"
else
    fail "Installer YARA tiene error de sintaxis"
fi

check_repo_executable "tools/orangebox-quarantine.py"
if python3 - "$ROOT/tools/orangebox-quarantine.py" <<'PY' >/dev/null 2>&1
import sys
from pathlib import Path
path = sys.argv[1]
compile(Path(path).read_text(encoding="utf-8"), path, "exec")
PY
then
    ok "Source orangebox-quarantine.py pasa compilacion Python"
else
    fail "Source orangebox-quarantine.py tiene error de sintaxis"
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
