# OrangeBox · Wazuh

> Reglas, configuración y herramientas Wazuh para seguridad, FIM, YARA, Active Response y monitoreo de servidores Linux.

[![OrangeBox IT Services](https://img.shields.io/badge/OrangeBox-IT%20Services-ff6a00?style=for-the-badge)](https://www.example.com/)
[![Wazuh](https://img.shields.io/badge/Wazuh-security-0073c6?style=for-the-badge)](https://wazuh.com/)
[![Bash](https://img.shields.io/badge/Bash-tooling-121011?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)

## Seguridad Linux con Wazuh

Repositorio técnico de **OrangeBox IT Services** para desplegar y mantener **Wazuh Manager, Wazuh Agent, File Integrity Monitoring (FIM), YARA, Active Response, reglas de detección y automatizaciones de seguridad** en infraestructura Linux Enterprise.

El proyecto está orientado a operaciones reales de seguridad: detección de malware y webshells, cambios de archivos, accesos SSH, escalamiento de privilegios, brute force, indicadores de compromiso (IOC), respuesta automática y reportes de seguridad.

## Estructura

```text
configuration/
├── manager/            # Configuración del Wazuh Manager
└── agents/common/      # Configuración común de agentes

tools/                  # Instaladores y herramientas auxiliares
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

## YARA + Wazuh

La integración **FIM → YARA** permite analizar archivos detectados por Wazuh usando reglas oficiales de Yara-Rules.

La integración del Agent se instala mediante:

```text
tools/agent/install.sh
```

El instalador genera directamente en el cliente el runtime YARA y la cuarentena Active Response. No hay instaladores YARA secundarios.

El proyecto registra la versión/commit del ruleset descargado para facilitar auditoría y trazabilidad.

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

Wazuh Agent:

```bash
cd tools/agent
./install.sh
```

El instalador adapta automáticamente la ruta del Agent entre `/var/ossec` y `/opt/ossec` según el tipo de instalación.

## Filosofía OrangeBox

**Seguridad operable y auditable.**

Las reglas y scripts deben poder revisarse, probarse y desplegarse sin depender de una caja negra.

## OrangeBox IT Services

Enterprise Linux · Wazuh · Security · Monitoring · Zimbra · VMware · Infrastructure

https://www.example.com/

### Keywords

Wazuh, Wazuh Manager, Wazuh Agent, Wazuh rules, Wazuh FIM, File Integrity Monitoring, YARA, Active Response, malware detection, webshell detection, IOC, threat detection, Linux security, Linux monitoring, SSH security, brute force detection, RHEL, AlmaLinux, Rocky Linux, Zimbra security, Carbonio security, enterprise security, SIEM, XDR, OrangeBox.

## Documentación

La documentación técnica se mantiene junto al componente que documenta, usando el mismo nombre base con extensión `.md`. Por ejemplo: `orangebox-auth.xml` + `orangebox-auth.md`, `agent.conf` + `agent.md` y `custom-orangebox-email.py` + `custom-orangebox-email.md`.

Los reportes de seguridad usan un único motor v4. El reporte ejecutivo y el detallado se generan en la misma ejecución; el detallado se entrega como ZIP. La implementación está en `configuration/manager/reports/orangebox-security-report.py` y la documentación en los archivos `.md` del mismo directorio.
