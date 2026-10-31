#!/usr/bin/env bash
set -euo pipefail

# Do not leak API credentials when an operator starts this script with bash -x.
case "$-" in
    *x*) set +x ;;
esac
umask 077
SECRETS_FILE="${ORANGEBOX_IOC_SECRETS_FILE:-/etc/orangebox-ioc-secrets}"

configure_auth_key() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "ERROR: ejecutar como root." >&2
        return 1
    fi

    local auth_key confirm_key target_dir tmp_file
    read -r -s -p "Ingrese el nuevo abuse.ch Auth-Key (entrada oculta): " auth_key
    printf '\n'
    read -r -s -p "Confirme el abuse.ch Auth-Key: " confirm_key
    printf '\n'

    if [[ "$auth_key" != "$confirm_key" ]]; then
        unset auth_key confirm_key
        echo "ERROR: las claves no coinciden; no se modificó el archivo." >&2
        return 1
    fi
    unset confirm_key

    if [[ ! "$auth_key" =~ ^[A-Za-z0-9_-]{16,128}$ ]]; then
        unset auth_key
        echo "ERROR: formato de Auth-Key no válido; no se modificó el archivo." >&2
        return 1
    fi

    target_dir="$(dirname "$SECRETS_FILE")"
    mkdir -p "$target_dir"
    tmp_file="$(mktemp "$target_dir/.orangebox-ioc-secrets.XXXXXX")"
    if ! printf 'URLHAUS_AUTH_KEY=%s\nMB_AUTH_KEY=%s\n' "$auth_key" "$auth_key" > "$tmp_file"; then
        rm -f "$tmp_file"
        unset auth_key
        echo "ERROR: no se pudo escribir el archivo de credenciales." >&2
        return 1
    fi
    chown root:root "$tmp_file"
    chmod 0600 "$tmp_file"
    mv -f "$tmp_file" "$SECRETS_FILE"
    unset auth_key

    echo "Auth-Key abuse.ch guardado correctamente."
    echo "Archivo: $SECRETS_FILE"
    stat -c 'Permisos: %A %U:%G' "$SECRETS_FILE"
}

case "${1:-}" in
    --configure-key)
        [[ "$#" -eq 1 ]] || {
            echo "Uso: $0 --configure-key" >&2
            exit 2
        }
        configure_auth_key
        exit $?
        ;;
    --help|-h)
        cat <<'HELP'
Uso:
  update-orangebox-ioc-lists.sh
  update-orangebox-ioc-lists.sh --configure-key
  ORANGEBOX_IOC_DRY_RUN=1 update-orangebox-ioc-lists.sh

--configure-key solicita la Auth-Key abuse.ch sin mostrarla y la guarda
en /etc/orangebox-ioc-secrets (root:root 0600). No descarga ni modifica IOC.
HELP
        exit 0
        ;;
    "")
        ;;
    *)
        echo "ERROR: argumento no reconocido. Use --help." >&2
        exit 2
        ;;
esac


# OrangeBox Wazuh - IOC list updater
#
# Updates:
#   etc/lists/malicious-ioc/malicious-ip       (source-IP IOC: Emerging Threats)
#   etc/lists/malicious-ioc/malware-host-ip    (URLhaus hosting IPs; destination IOC only)
#   etc/lists/malicious-ioc/malicious-domains
#   etc/lists/malicious-ioc/malware-hashes
#
# Sources:
#   Source IPs: Emerging Threats compromised IPs + OrangeBox curated confirmed sources.
#   Malware hosts: URLhaus recent URLs; kept separate and NEVER used as source-IP IOC.
#   Domains: URLhaus hostfile
#   Hashes:  MalwareBazaar recent detections

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
LIST_DIR="$WAZUH_HOME/etc/lists/malicious-ioc"
CONFIRMED_SOURCE_LIST="$LIST_DIR/orangebox-confirmed-source-ip"
SOURCE_IP_MIGRATION_MARKER="$WAZUH_HOME/var/.orangebox-ioc-source-ip-separated"
TMP_DIR="$(mktemp -d /var/tmp/orangebox-ioc.XXXXXX)"

ET_COMPROMISED_IPS="https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
MB_API="https://mb-api.abuse.ch/api/v1/"

# URLhaus and MalwareBazaar use the same personal abuse.ch Auth-Key.
# Keep it outside Git in a root-only environment file.
if [[ -f "$SECRETS_FILE" ]]; then
    secrets_owner="$(stat -c '%u' "$SECRETS_FILE")"
    secrets_mode="$(stat -c '%a' "$SECRETS_FILE")"
    if [[ "$secrets_owner" != "0" ]] || (( (8#$secrets_mode & 077) != 0 )); then
        echo "ERROR: $SECRETS_FILE debe ser root-owned y no tener permisos de grupo/otros (0600 recomendado)." >&2
        exit 1
    fi
    set -a
    # shellcheck disable=SC1090
    source "$SECRETS_FILE"
    set +a
fi

ABUSECH_AUTH_KEY="${ABUSECH_AUTH_KEY:-}"
MB_AUTH_KEY="${MB_AUTH_KEY:-${ABUSECH_AUTH_KEY:-REPLACE_WITH_MALWAREBAZAAR_AUTH_KEY}}"
URLHAUS_AUTH_KEY="${URLHAUS_AUTH_KEY:-${ABUSECH_AUTH_KEY:-$MB_AUTH_KEY}}"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: falta el comando '$1'." >&2
        exit 1
    }
}

count_lines() {
    wc -l < "$1"
}

need_cmd curl
need_cmd awk
need_cmd grep
need_cmd sort
need_cmd comm
need_cmd install
need_cmd systemctl
need_cmd flock
need_cmd stat
need_cmd python3

LOCK_FILE="/var/run/orangebox-ioc-lists.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "INFO: ya existe otra ejecución de update-orangebox-ioc-lists.sh; se omite esta ejecución."
    exit 0
fi

mkdir -p "$LIST_DIR"

if [[ ! -r "$CONFIRMED_SOURCE_LIST" ]]; then
    echo "ERROR: falta la lista administrada $CONFIRMED_SOURCE_LIST; no se modificaron las CDB." >&2
    echo "Ejecute tools/deploy-ioc-active-response.sh para instalar/conservar la lista semilla." >&2
    exit 1
fi
CONFIRMED_SOURCE_OWNER="$(stat -c '%u' "$CONFIRMED_SOURCE_LIST")"
CONFIRMED_SOURCE_MODE="$(stat -c '%a' "$CONFIRMED_SOURCE_LIST")"
if [[ "$CONFIRMED_SOURCE_OWNER" != "0" ]] || (( (8#$CONFIRMED_SOURCE_MODE & 022) != 0 )); then
    echo "ERROR: $CONFIRMED_SOURCE_LIST debe pertenecer a root y no ser escribible por grupo/otros." >&2
    exit 1
fi

echo "Descargando fuentes IOC autenticadas..."

if [[ -z "$URLHAUS_AUTH_KEY" ]]; then
    echo "ERROR: falta Auth-Key abuse.ch. Recuperar/configurar en $SECRETS_FILE (root:root 0600)." >&2
    exit 1
fi

# The export URL embeds the Auth-Key. Only the private temporary curl config
# contains it; curl argv, xtrace and normal error output never display it.
if [[ ! "$URLHAUS_AUTH_KEY" =~ ^[A-Za-z0-9_-]{16,128}$ ]]; then
    echo "ERROR: formato de Auth-Key abuse.ch no válido." >&2
    exit 1
fi

URLHAUS_RECENT_CSV_URL="https://urlhaus-api.abuse.ch/v2/files/exports/$URLHAUS_AUTH_KEY/recent.csv"
URLHAUS_HOSTFILE_URL="https://urlhaus-api.abuse.ch/v2/files/exports/$URLHAUS_AUTH_KEY/hostfile.txt"

printf 'url = "%s"\n' "$URLHAUS_RECENT_CSV_URL" > "$TMP_DIR/urlhaus-recent.curl"
printf 'url = "%s"\n' "$URLHAUS_HOSTFILE_URL" > "$TMP_DIR/urlhaus-hostfile.curl"
chmod 0600 "$TMP_DIR/urlhaus-recent.curl" "$TMP_DIR/urlhaus-hostfile.curl"

if ! curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 \
    --config "$TMP_DIR/urlhaus-recent.curl" -o "$TMP_DIR/urlhaus-recent.csv" \
    2>"$TMP_DIR/urlhaus-recent.err"; then
    echo "ERROR: descarga URLhaus recent.csv fallida (Auth-Key/acceso/disponibilidad). No se modificaron las CDB." >&2
    exit 1
fi

if ! curl -fsSL --retry 3 --connect-timeout 15 --max-time 180 \
    --config "$TMP_DIR/urlhaus-hostfile.curl" -o "$TMP_DIR/urlhaus.hosts" \
    2>"$TMP_DIR/urlhaus-hostfile.err"; then
    echo "ERROR: descarga URLhaus hostfile.txt fallida (Auth-Key/acceso/disponibilidad). No se modificaron las CDB." >&2
    exit 1
fi

curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
    "$ET_COMPROMISED_IPS" -o "$TMP_DIR/et-compromised.txt"

# -------------------------
# Source-IP IOC: Emerging Threats + OrangeBox confirmed source IPs
# -------------------------
awk '
    /^[[:space:]]*#/ { next }
    {
        for (i=1; i<=NF; i++) {
            if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                print $i
                break
            }
        }
    }
' "$TMP_DIR/et-compromised.txt" |
    sort -u |
    awk '{ print $0 ":" }' > "$TMP_DIR/emerging-threats-source-ip"

[[ -s "$TMP_DIR/emerging-threats-source-ip" ]] || {
    echo "ERROR: Emerging Threats no devolvio IPs de origen validas; se conserva la lista actual." >&2
    exit 1
}

# Validate the locally curated source-IP list without changing its source file.
# Blank lines and comments are allowed; only individual IPv4 entries in CDB
# format (address:) are accepted. URLs/hosting IPs must never be added here.
python3 - "$CONFIRMED_SOURCE_LIST" "$TMP_DIR/orangebox-confirmed-source-ip" <<'PY'
import ipaddress
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
addresses = set()

for line_number, raw_line in enumerate(
    source_path.read_text(encoding="utf-8").splitlines(), start=1
):
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if not line.endswith(":"):
        raise SystemExit(
            f"ERROR: formato inválido en {source_path}:{line_number}; "
            "se esperaba IPv4:."
        )
    try:
        address = ipaddress.ip_address(line[:-1].strip())
    except ValueError as exc:
        raise SystemExit(
            f"ERROR: IP inválida en {source_path}:{line_number}: {exc}"
        )
    if not isinstance(address, ipaddress.IPv4Address):
        raise SystemExit(
            f"ERROR: solo se permiten IPv4 en {source_path}:{line_number}."
        )
    addresses.add(str(address))

# Una lista curada vacía es válida: Emerging Threats sigue alimentando
# los IOC de origen. Las IP adicionales se agregan localmente tras revisión.
output_path.write_text(
    "".join(f"{address}:\n" for address in sorted(
        addresses, key=lambda value: tuple(int(part) for part in value.split("."))
    )),
    encoding="ascii",
)
print(f"OrangeBox confirmed source IPs: {len(addresses)}")
PY

# The single active source-IP CDB is the union of independent, auditable sources.
# This preserves native Wazuh IOC rules 99905/99906 and OrangeBox source rules.
cat "$TMP_DIR/emerging-threats-source-ip" "$TMP_DIR/orangebox-confirmed-source-ip" |
    sort -u > "$TMP_DIR/malicious-ip"

[[ -s "$TMP_DIR/malicious-ip" ]] || {
    echo "ERROR: la union de IOC de origen quedo vacia; se conserva la lista actual." >&2
    exit 1
}

# -------------------------
# URLhaus IP hosts: keep separate from source-IP IOC
# -------------------------
python3 - "$TMP_DIR/urlhaus-recent.csv" "$TMP_DIR/malware-host-ip" <<'PY'
import csv
import ipaddress
import sys
from pathlib import Path
from urllib.parse import urlsplit

csv_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])

# URLhaus prepends comments to its CSV export. Its column header is itself
# commented (for example: "# id,dateadded,url,url_status,..."). Find that
# exact CSV header instead of discarding every comment before DictReader.
raw_lines = csv_path.read_text(encoding="utf-8-sig").splitlines(keepends=True)
header_index = None
header_line = None

for index, raw_line in enumerate(raw_lines):
    candidate = raw_line.strip()
    if not candidate:
        continue
    if candidate.startswith("#"):
        candidate = candidate[1:].lstrip()
    try:
        columns = next(csv.reader([candidate]))
    except (csv.Error, StopIteration):
        continue

    normalized_columns = {
        column.strip().lstrip("\ufeff").casefold()
        for column in columns
    }
    if "url" in normalized_columns:
        header_index = index
        header_line = candidate + "\n"
        break

if header_index is None or header_line is None:
    raise SystemExit(
        "ERROR: URLhaus recent.csv no contiene una cabecera CSV reconocible "
        "con columna 'url'; no se modificaron las CDB."
    )

# Start at the discovered header; ignore only later comment/blank lines.
data_lines = [header_line]
data_lines.extend(
    line for line in raw_lines[header_index + 1:]
    if line.strip() and not line.lstrip().startswith("#")
)

reader = csv.DictReader(data_lines)
url_column = next(
    (
        name for name in (reader.fieldnames or [])
        if name.strip().lstrip("\ufeff").casefold() == "url"
    ),
    None,
)
if not url_column:
    raise SystemExit(
        "ERROR: URLhaus recent.csv no contiene columna 'url'; "
        "no se modificaron las CDB."
    )

hosts = set()
for row in reader:
    raw_url = (row.get(url_column) or "").strip()
    if not raw_url:
        continue
    try:
        parsed = urlsplit(raw_url if "://" in raw_url else f"//{raw_url}")
        hostname = parsed.hostname
        if not hostname:
            continue
        address = ipaddress.ip_address(hostname)
    except ValueError:
        continue
    if isinstance(address, ipaddress.IPv4Address) and address.is_global:
        hosts.add(str(address))

ordered_hosts = sorted(
    hosts, key=lambda value: tuple(int(part) for part in value.split("."))
)
output_path.write_text(
    "".join(f"{host}:\n" for host in ordered_hosts),
    encoding="ascii",
)
print(f"URLhaus IPv4 malware hosts: {len(ordered_hosts)}")
PY

# URLhaus hosts are indicators of malware distribution infrastructure.
# They are not automatically trusted as hostile source IPs and are never
# merged into malicious-ip (used by rules matching srcip).

# -------------------------
# Malicious domains
# -------------------------
awk '
    /^[[:space:]]*#/ { next }
    NF >= 2 {
        d=$2
        gsub(/\r/, "", d)
        sub(/[;,].*$/, "", d)
        if (d ~ /^[[:alnum:]][[:alnum:].-]*\.[[:alnum:]][[:alnum:].-]*$/) {
            d=tolower(d)
            sub(/\.$/, "", d)
            if (d !~ /^(localhost|localhost\.localdomain|broadcasthost|ip6-)/) {
                print d ":"
            }
        }
    }
' "$TMP_DIR/urlhaus.hosts" |
    sort -u > "$TMP_DIR/malicious-domains"

[[ -s "$TMP_DIR/malicious-domains" ]] || {
    echo "ERROR: no se obtuvieron dominios IOC validos." >&2
    exit 1
}

# -------------------------
# Malware hashes
# -------------------------
if [[ -n "$MB_AUTH_KEY" && "$MB_AUTH_KEY" != 'REPLACE_WITH_MALWAREBAZAAR_AUTH_KEY' ]]; then
    # Keep the Auth-Key out of curl's process arguments.
    printf 'url = "%s"\nheader = "Auth-Key: %s"\ndata = "query=recent_detections&hours=24"\n' \
        "$MB_API" "$MB_AUTH_KEY" > "$TMP_DIR/malwarebazaar.curl"
    chmod 0600 "$TMP_DIR/malwarebazaar.curl"

    if ! curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
        --config "$TMP_DIR/malwarebazaar.curl" -o "$TMP_DIR/malware.json" \
        2>"$TMP_DIR/malwarebazaar.err"; then
        echo "ERROR: MalwareBazaar no respondió correctamente; se conserva la lista existente." >&2
        exit 1
    fi

    grep -oE '"sha256_hash"[[:space:]]*:[[:space:]]*"[A-Fa-f0-9]{64}"' \
        "$TMP_DIR/malware.json" > "$TMP_DIR/malware-matches" || true

    if [[ ! -s "$TMP_DIR/malware-matches" ]]; then
        echo "ERROR: MalwareBazaar no devolvio hashes SHA256 validos; se conserva la lista existente." >&2
        exit 1
    fi

    awk -F'"' '{ print tolower($4) ":" }' \
        "$TMP_DIR/malware-matches" |
        sort -u > "$TMP_DIR/malware-hashes"

    [[ -s "$TMP_DIR/malware-hashes" ]] || {
        echo "ERROR: no se pudo construir malware-hashes." >&2
        exit 1
    }
else
    echo "INFO: MB_AUTH_KEY sin configurar; malware-hashes se conserva sin cambios."
fi

# -------------------------
# Safety check: reject >50% drops
# -------------------------
for name in malicious-ip malicious-domains malware-host-ip; do
    old="$LIST_DIR/$name"
    new="$TMP_DIR/$name"

    if [[ ! -s "$new" ]]; then
        if [[ "$name" == "malware-host-ip" ]]; then
            echo "INFO: URLhaus no devolvio IP hosts; se conserva $name sin cambios."
            continue
        fi
        echo "ERROR: la nueva lista $name esta vacia; se conserva la lista actual." >&2
        exit 1
    fi

    old_count=0
    if [[ -s "$old" ]]; then
        old_count="$(count_lines "$old")"
    fi
    new_count="$(count_lines "$new")"

    if (( old_count > 0 && new_count * 2 < old_count )); then
        if [[ "$name" == "malicious-ip" && ! -f "$SOURCE_IP_MIGRATION_MARKER" && "${ORANGEBOX_IOC_DRY_RUN:-0}" == "1" ]]; then
            echo "DRY RUN WARNING: la separación de fuentes reducirá malicious-ip de $old_count a $new_count entradas."
        elif [[ "$name" == "malicious-ip" && ! -f "$SOURCE_IP_MIGRATION_MARKER" && "${ORANGEBOX_IOC_ALLOW_SOURCE_RECLASSIFICATION:-0}" == "1" ]]; then
            echo "WARNING: se aprueba explícitamente la reclasificación inicial de malicious-ip (URLhaus separado de Emerging Threats): $old_count -> $new_count."
        else
            echo "ERROR: $name bajo de $old_count a $new_count entradas; se rechaza la actualización." >&2
            if [[ "$name" == "malicious-ip" ]]; then
                echo "La aprobación inicial solo se permite una vez: primero ejecutar ORANGEBOX_IOC_DRY_RUN=1, revisar el diff y después usar ORANGEBOX_IOC_ALLOW_SOURCE_RECLASSIFICATION=1." >&2
            fi
            exit 1
        fi
    fi

    if [[ -s "$old" ]]; then
        added="$(comm -13 <(sort -u "$old") <(sort -u "$new") | awk 'NF {n++} END {print n+0}')"
        removed="$(comm -23 <(sort -u "$old") <(sort -u "$new") | awk 'NF {n++} END {print n+0}')"
    else
        added="$new_count"
        removed=0
    fi

    printf '%-16s previous=%s new=%s added=%s removed=%s\n' "$name" "$old_count" "$new_count" "$added" "$removed"
done

echo "Source-IP IOC components:"
printf '  Emerging Threats: %s entries\n' "$(count_lines "$TMP_DIR/emerging-threats-source-ip")"
printf '  OrangeBox confirmed: %s entries\n' "$(count_lines "$TMP_DIR/orangebox-confirmed-source-ip")"

if [[ -s "$TMP_DIR/malware-hashes" ]]; then
    old_count=0
    new_count="$(count_lines "$TMP_DIR/malware-hashes")"
    added=0
    removed=0

    if [[ -s "$LIST_DIR/malware-hashes" ]]; then
        old_count="$(count_lines "$LIST_DIR/malware-hashes")"
        added="$(comm -13 <(sort -u "$LIST_DIR/malware-hashes") <(sort -u "$TMP_DIR/malware-hashes") | awk 'NF {n++} END {print n+0}')"
        removed="$(comm -23 <(sort -u "$LIST_DIR/malware-hashes") <(sort -u "$TMP_DIR/malware-hashes") | awk 'NF {n++} END {print n+0}')"

        if (( old_count > 0 && new_count * 2 < old_count )); then
            echo "ERROR: malware-hashes bajo de $old_count a $new_count entradas; se rechaza la actualizacion." >&2
            exit 1
        fi
    else
        added="$new_count"
    fi

    printf '%-16s previous=%s new=%s added=%s removed=%s\n' \
        "malware-hashes" "$old_count" "$new_count" "$added" "$removed"
else
    current_count=0
    [[ -s "$LIST_DIR/malware-hashes" ]] && current_count="$(count_lines "$LIST_DIR/malware-hashes")"
    printf '%-16s previous=%s new=%s added=%s removed=%s\n' \
        "malware-hashes" "$current_count" "$current_count" "0" "0"
fi

# -------------------------
# Validate formats
# -------------------------
if ! awk -F: '
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { next }
    { exit 1 }
' "$TMP_DIR/malicious-ip"; then
    echo "ERROR: malicious-ip contiene entradas invalidas." >&2
    exit 1
fi

if ! awk -F: '
    $1 ~ /^[[:alnum:]][[:alnum:].-]*\.[[:alnum:]][[:alnum:].-]*$/ { next }
    { exit 1 }
' "$TMP_DIR/malicious-domains"; then
    echo "ERROR: malicious-domains contiene entradas invalidas." >&2
    exit 1
fi

if [[ -s "$TMP_DIR/malware-hashes" ]] && ! awk -F: '
    length($1) == 64 && $1 ~ /^[A-Fa-f0-9]+$/ { next }
    { exit 1 }
' "$TMP_DIR/malware-hashes"; then
    echo "ERROR: malware-hashes contiene entradas invalidas." >&2
    exit 1
fi

if [[ -s "$TMP_DIR/malware-host-ip" ]] && ! awk -F: '
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { next }
    { exit 1 }
' "$TMP_DIR/malware-host-ip"; then
    echo "ERROR: malware-host-ip contiene entradas invalidas." >&2
    exit 1
fi

if [[ "${ORANGEBOX_IOC_DRY_RUN:-0}" == "1" ]]; then
    if [[ ! -f "$SOURCE_IP_MIGRATION_MARKER" ]]; then
        echo "DRY RUN: la primera separación de IP de origen requiere aprobación manual; no se creó el marcador."
    fi
    echo "DRY RUN: no se modificaron listas ni se reinició wazuh-manager."
    exit 0
fi

# La reclasificación inicial de malicious-ip siempre requiere un DRY_RUN
# revisado y una aprobación explícita. El marcador evita que cron pueda
# cambiar la semántica de malicious-ip sin una decisión manual.
if [[ ! -f "$SOURCE_IP_MIGRATION_MARKER" && "${ORANGEBOX_IOC_ALLOW_SOURCE_RECLASSIFICATION:-0}" != "1" ]]; then
    echo "ERROR: la separación inicial de fuentes IOC aún no fue aprobada." >&2
    echo "Ejecutar primero ORANGEBOX_IOC_DRY_RUN=1 y revisar previous/new/added/removed." >&2
    echo "Después de revisar, ejecutar una sola vez con ORANGEBOX_IOC_ALLOW_SOURCE_RECLASSIFICATION=1." >&2
    exit 1
fi

# -------------------------
# Instalar solo si hubo cambios
# -------------------------
#
# No reiniciamos Wazuh por cada ejecución del actualizador. Las fuentes
# se descargan y validan primero. Solo si alguna lista cambia se instala
# la nueva versión y se reinicia el manager para reconstruir las CDB.
CHANGED=0

install_if_changed() {
    local name="$1"
    local source="$TMP_DIR/$name"
    local destination="$LIST_DIR/$name"

    if [[ -f "$destination" ]] && cmp -s "$source" "$destination"; then
        echo "Sin cambios: $name"
        return 0
    fi

    install -o wazuh -g wazuh -m 0640 "$source" "$destination"
    echo "Actualizada: $name"
    CHANGED=1
}

install_if_changed "malicious-ip"
install_if_changed "malicious-domains"

if [[ -s "$TMP_DIR/malware-host-ip" ]]; then
    install_if_changed "malware-host-ip"
fi

if [[ -s "$TMP_DIR/malware-hashes" ]]; then
    install_if_changed "malware-hashes"
fi

echo "=== OrangeBox IOC lists ==="
printf 'Source-IP IOC (combined): %s entries\n' "$(count_lines "$LIST_DIR/malicious-ip")"
printf '  Emerging Threats: %s entries\n' "$(count_lines "$TMP_DIR/emerging-threats-source-ip")"
printf '  OrangeBox confirmed: %s entries\n' "$(count_lines "$TMP_DIR/orangebox-confirmed-source-ip")"
printf 'URLhaus malware-host IPs (not source-ban IOC): %s entries\n' "$(count_lines "$LIST_DIR/malware-host-ip" 2>/dev/null || true)"
printf 'Domains: %s entries\n' "$(count_lines "$LIST_DIR/malicious-domains")"
printf 'Hashes:  %s entries\n' "$(count_lines "$LIST_DIR/malware-hashes" 2>/dev/null || true)"

if (( CHANGED == 1 )); then
    echo "Hay cambios en las listas; reiniciando wazuh-manager para recargar las CDB..."
    systemctl restart wazuh-manager
    echo "Wazuh manager reiniciado; CDB listas reconstruidas."
else
    echo "No hubo cambios en las listas; no se reinicia wazuh-manager."
fi

if [[ ! -f "$SOURCE_IP_MIGRATION_MARKER" && "${ORANGEBOX_IOC_ALLOW_SOURCE_RECLASSIFICATION:-0}" == "1" ]]; then
    install -D -o root -g wazuh -m 0640 /dev/null "$SOURCE_IP_MIGRATION_MARKER"
    echo "Reclasificación inicial de IP de origen aprobada y registrada en $SOURCE_IP_MIGRATION_MARKER."
fi
