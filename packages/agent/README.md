# RPM del agente Wazuh para `/opt/ossec`

Acá se construye el RPM del agente Wazuh para OrangeBox.

La idea es simple: instalar Wazuh en `/opt/ossec` y dejar `/var/ossec` tranquilo para evitar peleas con Imunify y compañía.

## Plataformas objetivo

- AlmaLinux 8, 9 y 10
- Rocky Linux 8, 9 y 10
- Otras distribuciones compatibles con el modelo RPM de Wazuh

El paquete se construye usando el generador oficial de Wazuh. No estamos reinventando la rueda.

## Construir el RPM

Necesitas:

- Git
- Docker o Podman

Ejecuta:

```bash
./build.sh
```

También puedes cambiar la versión y la cantidad de trabajos:

```bash
WAZUH_VERSION=4.14.8 JOBS=4 ./build.sh
```

El RPM queda en `output/`.

## ¿Por qué `/opt/ossec`?

El RPM oficial usa `/var/ossec`. Nosotros usamos `/opt/ossec` para separar completamente el agente y evitar que Imunify se meta donde no lo llamaron.

No hay trucos ni symlinks. No hacemos esto:

```text
/var/ossec -> /opt/ossec
```

El RPM instala directamente en `/opt/ossec`.

## Importante

El RPM sale del empaquetado oficial de Wazuh. Así mantenemos los scripts del servicio, dependencias, SELinux y estructura del agente alineados con la versión de Wazuh que estamos construyendo.

La versión por defecto del builder es **4.14.8**. Primero se prueba. Después se manda a producción. No al revés. 😈

## Ciclo interno de `build.sh`

El builder usa el generador oficial de Wazuh y deja la fuente original sin modificaciones:

1. Comprueba Git y detecta Docker o Podman.
2. Limpia `OUTDIR` y el checkout temporal `SOURCE_DIR` administrados por el builder.
3. Clona el tag oficial `v<WAZUH_VERSION>`.
4. Entra a `packages/` y prepara un wrapper temporal si solo hay Podman.
5. Ejecuta `generate_package.sh` para agente `amd64`, prefijo `/opt/ossec` y formato RPM.
6. Exige un solo RPM instalable y descarta los auxiliares `debuginfo`.
7. Si está disponible `rpm`, comprueba que el paquete instala bajo `/opt/ossec`.
8. Copia el artefacto versionado junto a `tools/agent/install.sh`; el wrapper temporal se elimina al terminar.

| Variable | Valor por defecto | Función |
|---|---|---|
| `WAZUH_VERSION` | `4.14.8` | Tag oficial a construir. |
| `JOBS` | `2` | Trabajos paralelos. |
| `OUTDIR` | `packages/agent/output` | RPM generado; se limpia al inicio. |
| `SOURCE_DIR` | `/tmp/wazuh-<versión>` | Checkout temporal; se elimina antes de clonar. |

**Cuidado:** `OUTDIR` y `SOURCE_DIR` se eliminan al inicio. No deben apuntar a directorios con información ajena al builder. La versión pública permanece en 4.14.8 para coincidir con el RPM OPT incluido y con `tools/agent/install.sh`.
