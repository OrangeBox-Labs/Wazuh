#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
INSTALLER="$ROOT_DIR/tools/agent/install.sh"

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[PASS] %s\n' "$*"; }

[[ -f "$INSTALLER" ]] || fail "falta tools/agent/install.sh"
bash -n "$INSTALLER" || fail "el instalador no tiene sintaxis Bash válida"

grep -Fq 'configure_audit_log_rotation()' "$INSTALLER" || fail "falta configure_audit_log_rotation"
grep -Fq 'orangebox_cron_scheduler_ready()' "$INSTALLER" || fail "el instalador debe comprobar crond activo y habilitado antes de cambiar auditd.conf"
grep -Fq '/etc/logrotate.d/*' "$INSTALLER" || fail "el instalador debe buscar reglas logrotate externas"
grep -Fq '/etc/cron.daily/orangebox-audit-logrotate' "$INSTALLER" || fail "falta la tarea diaria administrada"
ROTATOR="$ROOT_DIR/tools/agent/auditd-logrotate.sh"
grep -Fq '# ORANGEBOX_AUDIT_LOG_ROTATION' "$ROTATOR" || fail "falta el marcador idempotente"
grep -Fq 'KEEP_DAYS=7' "$ROTATOR" || fail "la retención local debe ser de siete días"
grep -Fq 'auditd rotate' "$ROTATOR" || fail "debe solicitar la rotación al daemon auditd"
grep -Fq 'gzip' "$INSTALLER" || fail "debe comprimir las generaciones cerradas"
grep -Fq 'max_log_file_action = ignore' "$INSTALLER" || fail "debe desactivar la rotación automática por tamaño"
grep -Fq 'Auditd / rotación, compresión y retención 7 días' "$INSTALLER" || fail "el paso de retención no se ejecuta"
grep -Fq 'política de rotación/compresión de auditd ausente o incompleta' "$INSTALLER" || fail "la verificación final no valida la política"

pass "el instalador valida e instala rotación diaria, gzip y retención auditd de siete días"
