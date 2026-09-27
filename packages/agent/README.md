# RPM del agente Wazuh para `/opt/ossec`

Este directorio contiene un RPM precompilado y el procedimiento reproducible para generar el agente Wazuh con su árbol de instalación bajo **`/opt/ossec`**.

La finalidad principal es evitar conflictos en servidores donde **Imunify** u otro software de seguridad ya utiliza **`/var/ossec`**.

## Paquete disponible

Actualmente se publica:

```text
wazuh-agent_4.14.7-0_x86_64_OPT.rpm
```

- Wazuh: **4.14.7**
- Arquitectura: **x86_64 / amd64**
- Ruta de instalación del agente: **`/opt/ossec`**
- Formato: **RPM**
- Paquete generado mediante el procedimiento oficial de empaquetado de Wazuh, cambiando la ruta de instalación a `/opt/ossec`.

El RPM publicado está pensado para facilitar el despliegue. El script `build.sh` permite reconstruir el paquete desde el código fuente oficial de la misma versión.

## ¿Cuándo usar este RPM?

Este paquete está orientado a servidores que ya tienen:

- **Imunify**
- otro producto de seguridad que utilice `/var/ossec`
- una instalación existente que no deba compartir el árbol de archivos con el agente Wazuh

El objetivo es que el agente Wazuh utilice:

```text
/opt/ossec
```

mientras el software existente mantiene su propio:

```text
/var/ossec
```

No se utilizan symlinks para hacer pasar una ruta por la otra.

> **Importante:** que dos productos utilicen nombres o servicios relacionados con `ossec` no garantiza por sí solo que sean compatibles. Antes de instalar, revise qué rutas, servicios, usuarios, permisos, módulos y políticas SELinux administra el software existente.

## Escenario típico: Imunify / cPanel / CloudLinux

Un caso habitual es un servidor donde Imunify ya administra su propio entorno bajo `/var/ossec`. Una instalación estándar de Wazuh que también utilice esa ruta puede producir conflictos de archivos, servicios o componentes.

Este paquete separa las rutas:

```text
Imunify / otro producto
└── /var/ossec

Wazuh Agent
└── /opt/ossec
```

La separación reduce el riesgo de que ambos productos intenten administrar el mismo árbol de instalación.

## Instalación

Primero valide el paquete y el entorno:

```bash
rpm -qpl wazuh-agent_4.14.7-0_x86_64_OPT.rpm
```

Compruebe especialmente que los archivos del agente estén bajo `/opt/ossec`.

Después puede instalarlo con:

```bash
dnf install ./wazuh-agent_4.14.7-0_x86_64_OPT.rpm
```

Antes de iniciar el servicio, configure el agente según el entorno y revise la configuración resultante.

> **No instale este RPM encima de una instalación Wazuh existente sin revisar previamente sus rutas y estado.** El objetivo de este paquete es precisamente mantener separada la instalación de `/var/ossec`.

## Comprobar la instalación

Después de instalar:

```bash
rpm -q wazuh-agent
rpm -ql wazuh-agent | grep '^/opt/ossec'
```

También puede revisar el estado del servicio con el mecanismo de administración de servicios disponible en la distribución.

## Construir el RPM

Requisitos:

- Git
- Docker **o** Podman
- acceso a Internet para clonar el código fuente oficial de Wazuh

Ejecuta:

```bash
./build.sh
```

Por defecto:

- Wazuh: `4.14.7`
- trabajos de compilación: `2`
- arquitectura: `amd64`
- instalación: `/opt/ossec`
- salida: `output/`

También puedes cambiar la versión y la cantidad de trabajos:

```bash
WAZUH_VERSION=4.14.7 JOBS=4 ./build.sh
```

El script clona la etiqueta correspondiente de Wazuh y ejecuta el `generate_package.sh` oficial sin modificar el código fuente de Wazuh ni su entorno de compilación. Si solamente está disponible Podman, el script proporciona un wrapper temporal compatible con la invocación `docker` utilizada por el generador.

## Verificación del RPM generado

Si tienes `rpm` instalado:

```bash
rpm -qpl output/*.rpm | grep '^/opt/ossec'
```

El builder también comprueba que se haya generado exactamente un RPM de agente y que contenga la ruta `/opt/ossec`.

## ¿Por qué /opt/ossec?

El objetivo no es crear una variante funcionalmente distinta del agente, sino **separar su árbol de instalación** del `/var/ossec` utilizado por otras soluciones.

No se hace esto:

```text
/var/ossec -> /opt/ossec
```

El paquete se genera para instalar directamente bajo:

```text
/opt/ossec
```

## Consideraciones antes de producción

Revise como mínimo:

1. qué producto de seguridad ya utiliza `/var/ossec`;
2. qué servicios y procesos relacionados mantiene;
3. usuarios y grupos utilizados por ambos productos;
4. políticas SELinux y permisos;
5. rutas de logs y configuración;
6. reglas de firewall y conectividad hacia Wazuh Manager;
7. comportamiento después de reiniciar el servidor.

Pruebe primero en un servidor representativo. La separación de rutas evita un conflicto concreto de instalación, pero **no garantiza compatibilidad absoluta entre dos productos de seguridad ejecutándose simultáneamente**.

## Relación con el empaquetado oficial

El RPM se genera mediante el mecanismo oficial de empaquetado de Wazuh. Este proyecto no pretende reemplazar el generador de Wazuh: lo utiliza para producir el paquete con la ruta `/opt/ossec`.

La versión del RPM publicado debe mantenerse alineada con la versión indicada en su nombre. Para otra versión, reconstruya el paquete con `WAZUH_VERSION` y valide nuevamente el resultado.

## Licenciamiento y procedencia

Este repositorio publica un paquete construido a partir del proyecto Wazuh. Wazuh y sus componentes mantienen sus propias licencias y condiciones de distribución.

Antes de redistribuir, modificar o incorporar el paquete en productos o servicios comerciales, revise las licencias aplicables del proyecto Wazuh y de los componentes incluidos.

## Estructura

```text
packages/agent/
├── .gitignore
├── README.md
├── build.sh
└── wazuh-agent_4.14.7-0_x86_64_OPT.rpm
```

Primero se prueba. Después se manda a producción. No al revés. 😈
