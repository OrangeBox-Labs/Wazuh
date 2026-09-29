# OrangeBox · Wazuh

> Reglas, configuración y herramientas Wazuh para seguridad, FIM, YARA, Active Response y monitoreo de servidores Linux.

[![OrangeBox IT Services](https://img.shields.io/badge/OrangeBox-IT%20Services-ff6a00?style=for-the-badge)](https://TU_HOSTNAME/)
[![Wazuh](https://img.shields.io/badge/Wazuh-security-0073c6?style=for-the-badge)](https://wazuh.com/)
[![Bash](https://img.shields.io/badge/Bash-tooling-121011?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)

## Seguridad Linux con Wazuh

Repositorio técnico de **OrangeBox IT Services** para desplegar y mantener **Wazuh Manager, Wazuh Agent, File Integrity Monitoring (FIM), YARA, Active Response, reglas de detección y automatizaciones de seguridad** en infraestructura Linux Enterprise.

El proyecto está orientado a operaciones reales de seguridad: detección de malware y webshells, cambios de archivos, accesos SSH, escalamiento de privilegios, brute force, indicadores de compromiso (IOC), respuesta automática y reportes de seguridad.

## Estructura

```text
configuration/
└── manager/            # Configuración del Wazuh Manager

packages/
└── agent/              # Herramientas para construir el RPM OPT

tools/
├── agent/              # Instalador unificado del agente
└── ...                 # Herramientas operativas
```

Los árboles `configuration/` mantienen la estructura de instalación de Wazuh para facilitar despliegues mediante `rsync`.

## FIM y detección

La política de **File Integrity Monitoring** se distribuye por perfiles:

```text
configuration/manager/etc/shared/
├── default/
├── cpanel/
├── zimbra/
└── webserver/
```

El perfil común cubre mecanismos generales de compromiso, persistencia, credenciales y escalamiento. Los perfiles específicos agregan solamente las rutas y controles propios de cada plataforma.

## Instalador unificado del agente

El despliegue del agente se realiza con un único instalador:

```bash
cd tools/agent
./install.sh
```

El instalador pregunta si el servidor es **Linux normal** o **cPanel/CSF** y configura de forma idempotente el agente, firewall OrangeBox, auditd, YARA, ruleset oficial Yara-Rules y las validaciones finales.

**No hay que ejecutar instaladores secundarios.**

El RPM OPT para cPanel se distribuye junto al instalador:

```text
tools/agent/
├── install.sh
├── README.md
├── INSTALL.md
└── wazuh-agent_4.14.7-0_x86_64_OPT.rpm
```

## YARA + Wazuh

La integración **FIM → YARA** permite analizar archivos detectados por Wazuh usando reglas oficiales de Yara-Rules.

El instalador unificado genera directamente en el cliente:

```text
<WAZUH_HOME>/active-response/bin/orangebox-yara.sh
```

No se mantiene un instalador YARA separado en el repositorio. El ruleset oficial se valida antes de activarse y se registra el commit utilizado para facilitar auditoría y trazabilidad.

## Active Response

El repositorio incluye herramientas y configuración para respuestas automáticas frente a eventos de seguridad, incluyendo escenarios de:

- bloqueo de IP mediante firewall-drop
- indicadores de compromiso
- brute force
- detección de malware y webshell
- eventos de autenticación
- cambios de archivos críticos

## Plataformas

La configuración contempla perfiles para servidores Linux Enterprise y cargas como:

- RHEL, AlmaLinux y Rocky Linux
- Zimbra / Carbonio
- servidores web
- cPanel
- servicios Linux críticos

## Deploy

Wazuh Manager:

```bash
rsync -a configuration/manager/ /var/ossec/
```

Para endpoints, utilizar el instalador unificado de `tools/agent/` en lugar de copiar configuraciones de agente manualmente.

## Filosofía OrangeBox

**Seguridad operable y auditable.**

Las reglas y scripts deben poder revisarse, probarse y desplegarse sin depender de una caja negra.

## OrangeBox IT Services

Enterprise Linux · Wazuh · Security · Monitoring · Zimbra · VMware · Infrastructure

https://TU_HOSTNAME/

### Keywords

Wazuh, Wazuh Manager, Wazuh Agent, Wazuh rules, Wazuh FIM, File Integrity Monitoring, YARA, Active Response, malware detection, webshell detection, IOC, threat detection, Linux security, Linux monitoring, SSH security, brute force detection, RHEL, AlmaLinux, Rocky Linux, Zimbra security, Carbonio security, enterprise security, SIEM, XDR, OrangeBox.

## Documentación

La documentación técnica se mantiene junto al componente que documenta, usando el mismo nombre base con extensión `.md`. Para el agente, la documentación principal es `tools/agent/README.md` y `tools/agent/INSTALL.md`.
