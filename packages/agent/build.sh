#!/usr/bin/env bash
set -euo pipefail

# OrangeBox - Wazuh Agent RPM builder
# Uses Wazuh's official package-generation procedure without modifying the
# Wazuh source, RPM spec, compiler toolchain, or container build environment.
#
# Official procedure:
#   git clone https://github.com/wazuh/wazuh
#   cd wazuh/packages
#   git checkout v4.14.8
#   ./generate_package.sh -t agent -a amd64 -p /opt/ossec --system rpm
#
# Requirements: Docker and Git
# Output: one official Wazuh RPM for x86_64, installed under /opt/ossec.

# Mantener la versión por defecto alineada con el RPM OPT incluido y el instalador unificado.
WAZUH_VERSION="${WAZUH_VERSION:-4.14.8}"
JOBS="${JOBS:-2}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
OUTDIR="${OUTDIR:-${SCRIPT_DIR}/output}"
SOURCE_DIR="${SOURCE_DIR:-/tmp/wazuh-${WAZUH_VERSION}}"

# Comprueba Git antes de borrar o descargar archivos de trabajo.
if ! command -v git >/dev/null 2>&1; then
    echo "ERROR: git no está instalado." >&2
    exit 1
fi

# Selecciona Docker o Podman; el generador oficial necesita un runtime OCI.
CONTAINER_RUNTIME=""

# Prioriza Docker cuando está instalado.
if command -v docker >/dev/null 2>&1; then
    CONTAINER_RUNTIME="docker"
# Usa Podman como alternativa sin cambiar el generador oficial.
elif command -v podman >/dev/null 2>&1; then
    CONTAINER_RUNTIME="podman"
else
    echo "ERROR: se requiere Docker o Podman para ejecutar el builder oficial de Wazuh." >&2
    exit 1
fi

# Limpia el directorio de salida administrado por el builder para no mezclar RPM antiguos.
rm -rf "${OUTDIR}"
mkdir -p "${OUTDIR}"
# Descarta el checkout temporal anterior para compilar una fuente limpia.
rm -rf "${SOURCE_DIR}"

echo "==> Wazuh Agent RPM ${WAZUH_VERSION}"
echo "==> Procedimiento oficial de Wazuh"
echo "==> Arquitectura: amd64 / x86_64"
echo "==> Instalación: /opt/ossec"
echo "==> Runtime: ${CONTAINER_RUNTIME} ($(command -v "${CONTAINER_RUNTIME}"))"

echo "==> Clonando Wazuh..."
# Descarga exactamente el tag de Wazuh solicitado, sin historial innecesario.
git clone --depth 1 --branch "v${WAZUH_VERSION}" \
    https://github.com/wazuh/wazuh.git "${SOURCE_DIR}"

# Entra al directorio que contiene el generador de paquetes oficial.
cd "${SOURCE_DIR}/packages"

echo "==> Generando RPM con generate_package.sh oficial..."

# Wazuh's generate_package.sh hard-codes the Docker CLI. When only
# Podman is available, provide a temporary Docker-compatible wrapper and
# execute the official generator unchanged.
# Crea un wrapper temporal para adaptar la llamada docker del generador a Podman.
RUNTIME_WRAPPER_DIR="$(mktemp -d)"
trap 'rm -rf "${RUNTIME_WRAPPER_DIR}"' EXIT
if [[ "${CONTAINER_RUNTIME}" == "podman" ]]; then
    cat > "${RUNTIME_WRAPPER_DIR}/docker" <<'EOF'
#!/usr/bin/env bash
exec podman "$@"
EOF
    chmod +x "${RUNTIME_WRAPPER_DIR}/docker"
    export PATH="${RUNTIME_WRAPPER_DIR}:${PATH}"
fi

# Ejecuta el generador oficial para un agente RPM amd64 instalado en /opt/ossec.
./generate_package.sh \
    -t agent \
    -a amd64 \
    -p /opt/ossec \
    --system rpm \
    -j "${JOBS}" \
    -s "${OUTDIR}" \
    -c

# Evita que el patrón *.rpm quede como texto cuando el directorio está vacío.
shopt -s nullglob
rpms=("${OUTDIR}"/*.rpm)

if (( ${#rpms[@]} == 0 )); then
    echo "ERROR: Wazuh no generó ningún RPM." >&2
    exit 1
fi

agent_rpms=()
# Separa el paquete instalable de los RPM auxiliares de depuración.
for rpm_file in "${rpms[@]}"; do
    case "$(basename "${rpm_file}")" in
        *debuginfo*) ;;
        *) agent_rpms+=("${rpm_file}") ;;
    esac
done

if (( ${#agent_rpms[@]} != 1 )); then
    echo "ERROR: se esperaba exactamente un RPM de wazuh-agent." >&2
    printf '  %s\n' "${rpms[@]}" >&2
    exit 1
fi

RPM="${agent_rpms[0]}"

# Si rpm está disponible, inspecciona el contenido para comprobar el prefijo /opt/ossec.
if command -v rpm >/dev/null 2>&1; then
    if ! rpm -qpl "${RPM}" | grep -q '^/opt/ossec\(/\|\$\)'; then
        echo "ERROR: el RPM generado no contiene /opt/ossec." >&2
        exit 1
    fi
fi

echo
echo "RPM generado correctamente por el procedimiento oficial de Wazuh:"
ls -lh "${RPM}"
echo "Instalación: /opt/ossec"

# Publicar el artefacto directamente junto al instalador unificado.
INSTALLER_DIR="${SCRIPT_DIR}/../../tools/agent"
INSTALLER_RPM="${INSTALLER_DIR}/wazuh-agent_${WAZUH_VERSION}-0_x86_64_OPT.rpm"
mkdir -p "${INSTALLER_DIR}"
# Publica el artefacto versionado junto al instalador de agentes y fija permisos de lectura.
cp -f "${RPM}" "${INSTALLER_RPM}"
chmod 0644 "${INSTALLER_RPM}"
echo "RPM publicado para el instalador unificado:"
ls -lh "${INSTALLER_RPM}"
