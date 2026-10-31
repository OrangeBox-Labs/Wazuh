# Builder del RPM OPT de Wazuh Agent

Script: `packages/agent/build.sh`.

## Propósito

Construye el RPM oficial del Wazuh Agent para arquitectura `amd64/x86_64`, configurado para instalar en `/opt/ossec`. No modifica el código fuente oficial, el spec RPM ni el toolchain. El instalador unificado de este repositorio consume `tools/agent/wazuh-agent_4.14.8-0_x86_64_OPT.rpm`.

## Secuencia

1. Comprueba Git y selecciona Docker o Podman.
2. Limpia `OUTDIR` y el checkout temporal `SOURCE_DIR` del builder.
3. Clona el tag oficial `v<WAZUH_VERSION>` con profundidad 1.
4. Entra en `packages/` del checkout.
5. Si se utiliza Podman, crea un wrapper temporal `docker` que redirige los argumentos al runtime; el generador oficial permanece sin modificar.
6. Ejecuta `generate_package.sh` para `agent`, `amd64`, prefijo `/opt/ossec`, formato RPM.
7. Exige exactamente un RPM instalable y excluye `debuginfo`.
8. Si el comando `rpm` está disponible, comprueba que el paquete contiene rutas bajo `/opt/ossec`.
9. Publica el RPM junto al instalador de Agent, con nombre versionado y permisos 0644.
10. El wrapper temporal se elimina al salir; el checkout queda hasta la siguiente ejecución.

## Variables

| Variable | Default | Uso |
|---|---|---|
| `WAZUH_VERSION` | `4.14.8` | Tag oficial que se construye. |
| `JOBS` | `2` | Trabajos paralelos del generador. |
| `OUTDIR` | `packages/agent/output` | RPM de salida; se limpia al comienzo. |
| `SOURCE_DIR` | `/tmp/wazuh-<versión>` | Checkout temporal; se elimina antes de clonar. |

**Cuidado:** `OUTDIR` y `SOURCE_DIR` se eliminan al inicio. No apuntar estas variables a directorios con datos ajenos al builder.

## Requisitos y resultado

Requiere Git y Docker o Podman. La inspección del contenido del RPM depende de disponer de `rpm`. El resultado queda en `OUTDIR` y se copia al directorio `tools/agent/`.

La versión pública se mantiene en 4.14.8 para corresponder al RPM OPT incluido y al instalador de agentes de este repositorio.
