# OrangeBox · Wazuh

> Reglas de seguridad, detección de amenazas, IOC, YARA, respuestas activas, automatización y reportes para Wazuh, desarrollados a partir de implementaciones reales.

[![OrangeBox IT Services](https://img.shields.io/badge/OrangeBox-IT%20Services-ff6a00?style=for-the-badge)](https://www.orangebox.cl/)
[![Wazuh](https://img.shields.io/badge/Wazuh-security-0073c6?style=for-the-badge)](https://wazuh.com/)
[![Bash](https://img.shields.io/badge/Bash-tooling-121011?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)

## Descripción

**OrangeBox Wazuh** es una colección de reglas, configuraciones, herramientas y automatizaciones para Wazuh orientadas a detección de amenazas, respuesta ante incidentes, monitoreo y operación de seguridad.

El proyecto reúne trabajo desarrollado a partir de implementaciones reales, incluyendo:

- reglas personalizadas de detección
- indicadores de compromiso (IOC)
- detección de malware y webshells
- File Integrity Monitoring (FIM)
- integración con YARA
- Active Response y firewall-drop
- detección de autenticación SSH y escalamiento de privilegios
- controles de hardening
- automatización de seguridad
- generación de reportes
- perfiles para servidores Linux, Zimbra, cPanel y servidores web

Todo el contenido publicado ha sido **sanitizado para uso público**. Las direcciones IP, dominios, nombres de servidores, correos y otros valores específicos de infraestructura se reemplazan por valores de ejemplo y deben adaptarse al entorno de cada organización.

## Arquitectura de referencia

Los valores como `IP_DE_WAZUH`, `IP_DE_PROXY`, `IP_DE_BACKEND`, `IP_DE_AGENTE`, `TU_DOMINIO` y `TU_EMAIL` representan componentes reales de una arquitectura de seguridad, no valores que deban copiarse literalmente.

La explicación completa está en [ARCHITECTURE.md](ARCHITECTURE.md).

## Estructura

```text
configuration/
├── manager/
│   ├── etc/
│   │   ├── decoders/
│   │   ├── lists/
│   │   ├── rules/
│   │   └── shared/
│   ├── integrations/
│   └── reports/
packages/agent/                   # RPM y builder del agente Wazuh
tools/                            # Instaladores y herramientas auxiliares
```

La estructura de `configuration/manager/` está pensada para facilitar el despliegue sobre el directorio de configuración de Wazuh Manager.

## Detección y respuesta

El proyecto cubre escenarios como:

- autenticación y accesos SSH
- brute force
- escalamiento de privilegios
- ejecución sospechosa
- cambios de archivos
- malware y webshells
- IOC
- detección mediante YARA
- respuestas activas
- bloqueo de IP mediante firewall-drop

Las reglas se encuentran principalmente en:

```text
configuration/manager/etc/rules/
```

## FIM + YARA

La integración entre **File Integrity Monitoring y YARA** permite analizar archivos detectados por Wazuh y generar eventos de seguridad asociados.

Componentes principales:

```text
configuration/manager/etc/rules/orangebox-yara.xml
tools/orangebox-yara/

```

## Perfiles de agentes

Los perfiles compartidos se organizan por tipo de carga:

```text
configuration/manager/etc/shared/
├── default/
├── cpanel/
├── webserver/
└── zimbra/
```

Cada perfil puede adaptarse a las rutas y servicios propios de la organización.

## Reportes e integraciones

La configuración incluye:

- integración de correo para alertas
- reportes detallados de seguridad
- reportes periódicos
- documentación de despliegue y operación

Los componentes se encuentran en:

```text
configuration/manager/integrations/
configuration/manager/reports/
```

## Despliegue

Antes de desplegar, revise y adapte los valores de infraestructura documentados en [SANITIZATION.md](SANITIZATION.md).

Ejemplo para un Wazuh Manager:

```bash
rsync -a configuration/manager/ /var/ossec/
```

Valide siempre la configuración y pruebe las reglas en un entorno controlado antes de aplicarlas en producción.

## Filosofía OrangeBox

**Seguridad operable y auditable.**

Las reglas y herramientas deben poder revisarse, probarse y desplegarse sin depender de una caja negra.

## OrangeBox IT Services

Enterprise Linux · Wazuh · Security · Monitoring · Zimbra · VMware · Infrastructure

### Keywords

Wazuh, Wazuh Manager, Wazuh Agent, Wazuh rules, Wazuh FIM, File Integrity Monitoring, YARA, Active Response, malware detection, webshell detection, IOC, threat detection, Linux security, Linux monitoring, SSH security, brute force detection, RHEL, AlmaLinux, Rocky Linux, Zimbra security, Carbonio security, enterprise security, SIEM, XDR, OrangeBox.

## Documentación

La documentación técnica se mantiene junto al componente que documenta, usando el mismo nombre base con extensión `.md`. Por ejemplo: `orangebox-auth.xml` + `orangebox-auth.md`, `agent.conf` + `agent.md` y `custom-orangebox-email.py` + `custom-orangebox-email.md`.
