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
- Docker

Ejecuta:

```bash
./build.sh
```

También puedes cambiar la versión y la cantidad de trabajos:

```bash
WAZUH_VERSION=4.14.7 JOBS=4 ./build.sh
```

El RPM queda en `output/`.

## ¿Por qué `/opt/ossec`?

El RPM oficial usa `/var/ossec`. Nosotros usamos `/opt/ossec` para separar completamente el agente y evitar que Imunify se meta donde no lo llamaron.

No hay trucos ni symlinks. No hacemos esto:

```text
/var/ossec -> /opt/ossec
```

El RPM instala directamente en `/opt/ossec`.

## ¿Cuándo usar este paquete?

Este RPM está pensado para servidores que ya tienen **Imunify** u otro software de seguridad que utilice el componente o árbol `/var/ossec` y pueda entrar en conflicto con la instalación estándar del agente Wazuh.

El paquete instala el agente en **`/opt/ossec`** en lugar de `/var/ossec`, aislando la instalación de Wazuh del componente `ossec` que ya utiliza el software de seguridad existente.

Esto es especialmente útil en servidores con cPanel/CloudLinux y otras plataformas donde Imunify u otra solución de seguridad ya administra su propio entorno `ossec`. La separación de rutas evita que ambos productos intenten administrar los mismos archivos y directorios.

> **Importante:** el conflicto concreto depende del software y de su configuración. Antes de instalar, revise qué servicio utiliza `/var/ossec` y valide el despliegue en un servidor de prueba.

## Importante

El RPM sale del empaquetado oficial de Wazuh. Así mantenemos los scripts del servicio, dependencias, SELinux y estructura del agente alineados con la versión de Wazuh que estamos construyendo.

Primero se prueba. Después se manda a producción. No al revés. 😈
