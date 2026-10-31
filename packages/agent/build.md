# Builder del RPM OPT de Wazuh Agent

Script: `packages/agent/build.sh`.

## Propósito

Construye el RPM oficial del Wazuh Agent para arquitectura `amd64/x86_64`, configurado para instalar en `/opt/ossec`. No modifica el código fuente oficial, el spec RPM ni el toolchain. El resultado se publica junto al instalador unificado de Agent.

## Secuencia

1. Comprueba Git y selecciona Docker o Podman.
2. Limpia el directorio de salida administrado por el builder (`OUTDIR`) y el checkout temporal (`SOURCE_DIR`).
3. Clona el tag oficial `v<WAZUH_VERSION>` con profundidad 1.
4. Entra al directorio `packages/` de la fuente oficial.
5. Si solo existe Podman, crea un wrapper temporal `docker` que redirige al runtime Podman, sin editar el generador oficial.
6. Ejecuta `generate_package.sh` para `agent`, arquitectura `amd64`, prefijo `/opt/ossec` y formato RPM.
7. Exige un único RPM instalable, excluyendo los paquetes `debuginfo`.
8. Cuando `rpm` está disponible, inspecciona el contenido y confirma que el paquete instala bajo `/opt/ossec`.
9. Copia el RPM al directorio `tools/agent/` con nombre versionado y permisos 0644.
10. El wrapper Podman se elimina al terminar. El checkout temporal queda hasta la siguiente ejecución.

## Variables

| Variable | Default | Uso |
|---|---|---|
| `WAZUH_VERSION` | `4.14.8` | Tag oficial que se construye. |
| `JOBS` | `2` | Trabajos paralelos del generador. |
| `OUTDIR` | `packages/agent/output` | RPM de salida; se limpia al comienzo. |
| `SOURCE_DIR` | `/tmp/wazuh-<versión>` | Checkout temporal; se elimina antes de clonar. |

**Cuidado:** `OUTDIR` y `SOURCE_DIR` se eliminan al inicio. No deben apuntar a directorios con datos ajenos al builder.

## Requisitos y resultado

Requiere Git y Docker o Podman. La verificación del contenido del RPM se ejecuta si `rpm` está instalado. El paquete queda en `OUTDIR` y se publica junto al instalador Agent.

La versión por defecto del builder público es 4.14.8 y coincide con el RPM OPT distribuido junto a `tools/agent/install.sh`. Antes de actualizarla, validar el RPM, comprobar el prefijo `/opt/ossec` y confirmar que el instalador consume el mismo artefacto. Para probar otra versión se puede indicar `WAZUH_VERSION=<versión> ./build.sh`; no cambiar el valor por defecto hasta aprobar el despliegue.
