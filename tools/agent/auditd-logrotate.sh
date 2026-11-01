#!/usr/bin/env bash
set -u

# ORANGEBOX_AUDIT_LOG_ROTATION
# Solicita la rotación al daemon auditd, comprime los archivos cerrados y conserva siete días.
export PATH="/sbin:/bin:/usr/sbin:/usr/bin:$PATH"
AUDIT_LOG_DIR="${ORANGEBOX_AUDIT_LOG_DIR:-/var/log/audit}"
KEEP_DAYS=7
KEEP_MINUTES=$((KEEP_DAYS * 1440))
SERVICE_BIN="${ORANGEBOX_AUDIT_SERVICE_BIN:-service}"

log_message() {
    # Envía el resultado a syslog sin escribir dentro del propio audit.log.
    if command -v logger >/dev/null 2>&1; then
        logger -t orangebox-audit-rotation -- "$*"
    fi
}

archive_rotated_logs() {
    local file suffix timestamp epoch archive staging

    # Solo procesa generaciones numeradas que auditd ya cerró; nunca toca audit.log activo.
    for file in "$AUDIT_LOG_DIR"/audit.log.[0-9]*; do
        [[ -f "$file" ]] || continue
        suffix="${file##*.}"
        [[ "$suffix" =~ ^[0-9]+$ ]] || continue

        timestamp="$(date -r "$file" '+%Y%m%d_%H%M%S')" || return 1
        epoch="$(date -r "$file" '+%s')" || return 1
        archive="$AUDIT_LOG_DIR/audit.log.orangebox.$timestamp.$epoch.$suffix.gz"
        [[ ! -e "$archive" ]] || archive="$AUDIT_LOG_DIR/audit.log.orangebox.$timestamp.$epoch.$suffix.$$.gz"
        staging="$archive.tmp"

        mv -- "$file" "$staging" || return 1
        if ! gzip -f -- "$staging"; then
            mv -- "$staging" "$file" 2>/dev/null || true
            return 1
        fi
        mv -- "$staging.gz" "$archive" || return 1
    done
}

# En hosts sin auditd o sin su directorio de logs, no hay nada que rotar.
[[ -d "$AUDIT_LOG_DIR" ]] || exit 0
command -v gzip >/dev/null 2>&1 || { log_message "ERROR: gzip no está disponible"; exit 1; }
command -v "$SERVICE_BIN" >/dev/null 2>&1 || { log_message "ERROR: service no está disponible"; exit 1; }

# Archiva generaciones previas antes de que auditd pueda reutilizar audit.log.1.
archive_rotated_logs || { log_message "ERROR: no se pudieron archivar logs audit previos"; exit 1; }

# auditd recibe la orden de rotación; el script no renombra ni trunca su archivo activo.
"$SERVICE_BIN" auditd rotate
rotate_status=$?
if [[ "$rotate_status" -ne 0 ]]; then
    log_message "ERROR: auditd rotate terminó con código $rotate_status"
    exit "$rotate_status"
fi

# Permite que auditd cierre la generación anterior y cree el nuevo audit.log.
sleep 2
archive_rotated_logs || { log_message "ERROR: no se pudieron comprimir logs audit rotados"; exit 1; }

# Elimina exclusivamente archivos OrangeBox que superan siete días completos.
find "$AUDIT_LOG_DIR" -maxdepth 1 -type f -name 'audit.log.orangebox.*.gz' \
    -mmin "+$KEEP_MINUTES" -exec rm -f -- {} +

log_message "Rotación diaria completada; gzip y retención local de siete días."
exit 0
