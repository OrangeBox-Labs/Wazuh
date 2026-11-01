#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROTATOR="$ROOT_DIR/tools/agent/auditd-logrotate.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[PASS] %s\n' "$*"; }

[[ -f "$ROTATOR" ]] || fail "falta auditd-logrotate.sh"
bash -n "$ROTATOR" || fail "el rotador tiene errores de sintaxis"
grep -Fq '# ORANGEBOX_AUDIT_LOG_ROTATION' "$ROTATOR" || fail "falta el marcador administrado"
grep -Eq '^KEEP_DAYS=7$' "$ROTATOR" || fail "KEEP_DAYS debe ser siete"
grep -Fq 'auditd rotate' "$ROTATOR" || fail "debe pedir la rotación al daemon auditd"

AUDIT_DIR="$TMP_DIR/audit"
BIN_DIR="$TMP_DIR/bin"
mkdir -p "$AUDIT_DIR" "$BIN_DIR"
printf 'active-before-rotation\n' > "$AUDIT_DIR/audit.log"
printf 'previous-generation\n' > "$AUDIT_DIR/audit.log.1"
printf 'old-managed-archive\n' > "$AUDIT_DIR/audit.log.orangebox.20000101_000000.946684800.1.gz"
printf 'unmanaged-archive\n' > "$AUDIT_DIR/other-audit-backup.gz"
touch -d '8 days ago' "$AUDIT_DIR/audit.log.orangebox.20000101_000000.946684800.1.gz" "$AUDIT_DIR/other-audit-backup.gz"

cat > "$BIN_DIR/service" <<'SERVICE'
#!/usr/bin/env bash
set -e
[[ "$1" = "auditd" && "$2" = "rotate" ]] || exit 2
mv -- "$TEST_AUDIT_DIR/audit.log" "$TEST_AUDIT_DIR/audit.log.1"
: > "$TEST_AUDIT_DIR/audit.log"
SERVICE
chmod 700 "$BIN_DIR/service"

ORANGEBOX_AUDIT_LOG_DIR="$AUDIT_DIR" \
ORANGEBOX_AUDIT_SERVICE_BIN="$BIN_DIR/service" \
TEST_AUDIT_DIR="$AUDIT_DIR" \
bash "$ROTATOR" || fail "el rotador no terminó correctamente"

[[ -f "$AUDIT_DIR/audit.log" ]] || fail "se perdió el audit.log activo"
[[ ! -e "$AUDIT_DIR/audit.log.1" ]] || fail "quedó una generación numerada sin archivar"
[[ ! -e "$AUDIT_DIR/audit.log.orangebox.20000101_000000.946684800.1.gz" ]] || fail "no eliminó el archivo OrangeBox antiguo"
[[ -f "$AUDIT_DIR/other-audit-backup.gz" ]] || fail "eliminó un archivo que no pertenece a OrangeBox"

archives=("$AUDIT_DIR"/audit.log.orangebox.*.gz)
[[ ${#archives[@]} -eq 2 ]] || fail "se esperaban dos archivos comprimidos recientes; se encontraron ${#archives[@]}"
for archive in "${archives[@]}"; do
    gzip -t "$archive" || fail "archivo gzip inválido: $archive"
done
gzip -cd "${archives[0]}" "${archives[1]}" | grep -q 'previous-generation\|active-before-rotation' ||
    fail "no se conserva el contenido de los logs rotados"

pass "rotación auditd, compresión gzip y retención de siete días verificadas en directorio temporal"
