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
WAZUH_VERSION=4.14.9 JOBS=4 ./build.sh
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

La versión por defecto del builder es **4.14.9**. Primero se prueba. Después se manda a producción. No al revés. 😈

## Ciclo interno de `build.sh`

El builder no parchea ni modifica el código fuente de Wazuh. Ejecuta el procedimiento oficial en un checkout temporal y publica el RPM resultante:

1. Comprueba Git y detecta Docker o Podman.
2. Limpia el directorio de salida administrado por el builder y el checkout temporal de la versión seleccionada.
3. Clona el tag `v<WAZUH_VERSION>` y entra en `packages/`.
4. Cuando se utiliza Podman, crea un wrapper temporal llamado `docker` para satisfacer al generador oficial; el script oficial se ejecuta sin editarlo.
5. Ejecuta `generate_package.sh` para `agent`, arquitectura `amd64`, prefijo `/opt/ossec`, formato RPM.
6. Filtra los RPM auxiliares de depuración y exige exactamente un RPM instalable.
7. Cuando el comando `rpm` está disponible, inspecciona la lista de archivos y confirma que el paquete instala bajo `/opt/ossec`.
8. Copia el paquete junto a `tools/agent/install.sh` con el nombre versionado que espera el instalador unificado.

El wrapper de Podman se elimina al terminar. El checkout se conserva bajo `SOURCE_DIR` hasta la siguiente compilación; `OUTDIR` se reemplaza en cada ejecución. No apuntar estas variables a directorios que contengan datos ajenos al builder.

Variables admitidas:

| Variable | Valor por defecto | Uso |
|---|---|---|
| `WAZUH_VERSION` | `4.14.9` | Tag oficial de Wazuh que se compila. |
| `JOBS` | `2` | Trabajos paralelos del generador. |
| `OUTDIR` | `packages/agent/output` | Directorio de RPM generados; se limpia al inicio. |
| `SOURCE_DIR` | `/tmp/wazuh-<versión>` | Checkout temporal de la fuente oficial. |

Antes de publicar un RPM, comparar la versión con el paquete que consume `tools/agent/install.sh`. El paquete OPT incluido en el repositorio público es una versión independiente y saneada para distribución pública.
