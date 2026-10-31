# OrangeBox Wazuh — estado del repositorio público

> Revisión de `main` realizada el 31 de octubre de 2026. Este documento describe lo versionado; **no demuestra por sí solo que un Manager o Agent tenga desplegado el mismo commit**.

## Resumen de estado

| Subsistema | Estado en el repo | Fuente de configuración / documentación |
|---|---|---|
| Wazuh Manager | Activo | `configuration/manager/etc/ossec.conf`, `configuration/manager/ossec.md` |
| Reglas OrangeBox | Activas y documentadas | `configuration/manager/etc/rules/*.xml` + `*.md` |
| Decoders | Activos | `configuration/manager/etc/decoders/` + documentación junto a cada XML |
| FIM por perfil | Activo | `configuration/manager/etc/shared/{default,cpanel,zimbra,webserver}/agent.conf` |
| CDB / allowlists | Activas y con datos de ejemplo | `configuration/manager/etc/lists/` |
| Active Response | Activo y explícito en ossec.conf | Bloques `firewall-drop`, `orangebox-yara` y `orangebox-quarantine` |
| Email SOC | Activo, con destinatarios de ejemplo | `configuration/manager/integrations/custom-orangebox-email.py` |
| IOC updater | Activo | `configuration/manager/bin/update-orangebox-ioc-lists.sh` |
| Vulnerability alerts | Activo | `configuration/manager/vulnerability-alerts/`, reglas 100321–100323 y cron |
| GeoIP | Activo | `configuration/manager/bin/update-orangebox-geoip.sh` |
| Agent installer | Activo, Manager configurable | `tools/agent/install.sh` |
| RPM OPT builder | Activo | `packages/agent/build.sh` |
| Reporte ejecutivo/detallado | Activo | `configuration/manager/reports/orangebox-security-report.py` |
| Pruebas de regresión | Activas para desarrollo | `tests/` y workflow `.github/workflows/vulnerability-alerts-tests.yml` |

## Reglas de seguridad

Los archivos XML de reglas tienen documentación Markdown adyacente. Los principales son:

- `orangebox-auth.xml`: autenticación, SUDO, SSH y excepciones por perfil.
- `orangebox-hardening.xml`: modificaciones/eliminaciones FIM, persistencia y excepciones operacionales.
- `orangebox-ioc.xml`: coincidencias de IOC confirmadas.
- `orangebox-web.xml`: reconocimiento y explotación web.
- `orangebox-incident-webdos.xml`: correlaciones de disponibilidad/DoS derivadas de incidentes.
- `orangebox-php2shell.xml`: comportamiento PHP2Shell/PEAR.
- `orangebox-vulnerability-alerts.xml`: eventos JSON consolidados de vulnerabilidades.

### FIM y excepciones cPanel/CloudLinux

- `10035` detecta cambios de contenido en CRON/ANACRON.
- `10045` detecta eliminaciones de CRON/ANACRON.
- `20032` cubre la regeneración exacta de `cpanel_ssl_reissue`.
- `20059` conserva en nivel 3 la eliminación exacta de `cpanel_php_sessions_cron` en agentes cPanel.
- `20060` conserva en nivel 3 las modificaciones de `lvemanager-cron`, `lvemanager-selector` y `cloudlinux-cron`; no exceptúa sus eliminaciones.

Las excepciones requieren la CDB dinámica `orangebox-cpanel-agents`. No se ignora todo `/etc/cron.d`.

## Active Response

La política vigente en `ossec.conf` separa las duraciones según la confianza del evento:

| Selector | Timeout | Comportamiento |
|---|---:|---|
| IOC de IP de origen confirmadas y reglas nativas relacionadas | 604800 s (7 días) | `firewall-drop` |
| Explotación web de alta confianza con IOC/PHP2Shell (99906, 10053) | 2592000 s (30 días) | `firewall-drop` |
| Grupo `orangebox_web_auto_block` | 86400 s (24 horas) | Bloqueo de origen de reconocimiento web validado |
| Grupo `orangebox_syn_flood_block` | 3600 s (1 hora) | Bloqueo ante presión SYN-RECV persistente de una sola IP |

El DoS distribuido sin una única IP responsable se detecta, pero no se bloquea de forma indiscriminada. `orangebox-yara` analiza candidatos FIM; `orangebox-quarantine` se reserva para hashes confirmados. El integrador de correo lee la política real de `ossec.conf`; no debe inferir acciones a partir del nivel de alerta.

## CDB y actualización de datos

- Los sincronizadores cPanel/DNS/Zimbra convierten los grupos Wazuh en CDB dinámicas.
- BackupPC mantiene separadas la lista estática y la resolución DNS dinámica; los valores públicos usan rangos TEST-NET.
- GeoIP valida las bases MMDB antes de reemplazarlas.
- El actualizador IOC separa IP de origen, IP de hosting, dominios y hashes; valida cada fuente antes de reemplazar CDB.
- La lista pública de IP de origen confirmadas está vacía por diseño. Los IOC confirmados reales se agregan localmente en el Manager. Emerging Threats sigue alimentando el feed automático.
- Las credenciales abuse.ch se mantienen en un archivo root-only fuera de Git.

## Alertas complementarias de vulnerabilidades

`vulnerability-alerts.py` consulta `wazuh-states-vulnerabilities-*`, agrupa por CVE y agente, deduplica en SQLite y publica un evento JSON compacto en:

```text
/var/ossec/logs/vulnerability-alerts/events.jsonl
```

Las reglas 100321/100322/100323 cubren Medium/High/Critical. Critical es obligatoria; High y Medium son configurables. El cron de ejemplo ejecuta el detector cada 8 horas. `--status` es de solo lectura; `--dry-run` no publica eventos; `--force` sin dry-run puede generar una alerta/correo real.

## Agent y telemetría

`tools/agent/install.sh` es el instalador único. Detecta Enterprise Linux, reconcilia el paquete, almacenamiento, firewall/logging, auditd, telemetría local, YARA y el Active Response de cuarentena. SYN-RECV, ksoftirqd, carga y PHP-FPM se crean localmente; no se duplican en los grupos compartidos. El instalador mantiene `logcollector.remote_commands=0`.

Este repo distribuye el RPM OPT 4.14.8. El builder y el instalador públicos se mantienen alineados con esa versión; el hostname de Manager es un placeholder que se debe configurar al desplegar.

## Reportes

`orangebox-security-report.py` utiliza un motor unificado: produce el resumen ejecutivo y el detalle ZIP en la misma ejecución. El motor público conserva el nivel más completo de detalle para MITRE, FIM, autenticación, IOC/bloqueos, vulnerabilidades y GeoIP.

## Pruebas

El directorio `tests/` es **desarrollo**, no configuración de Manager. Contiene pruebas unitarias/contractuales para Active Response, IOC updater y PHP2Shell, además de fixtures sanitizados. La CI ejecuta:

```bash
python -m unittest discover -s configuration/manager/vulnerability-alerts -p 'test_*.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

La integración `sudo bash tests/test-ioc-active-response.sh` requiere un Manager real y `wazuh-logtest`; se ejecuta manualmente y no bloquea IPs.

## Limpieza y privacidad

- Se eliminaron los fragments XML redundantes que duplicaban Active Response de `ossec.conf` o telemetría del instalador.
- Se eliminó la CDB `orangebox-private-networks` porque ninguna regla la consultaba.
- La antigua workflow IOC fue retirada; la suite útil se conserva dentro de `tests/` y el CI actual.
- La lista IOC curada pública no publica indicadores reales; las CDB SFTP y BackupPC contienen identificadores/valores de ejemplo.
- Las direcciones, hosts y correos públicos son valores TEST-NET o `.example.invalid` / `example.com`. No incluir secretos, inventarios de clientes, JSONL, SQLite ni resultados de producción.

## Diferencias intencionales frente al repositorio privado

El repositorio público conserva las mismas capacidades, pero usa CDB SFTP genérica, cron de reporte de ejemplo, lista curada IOC vacía, emails de ejemplo, hostname de Manager configurable y RPM OPT 4.14.8. No incluye los crons de clientes, CDB SFTP de cliente, IOC reales ni RPM privado 4.14.9.

## Validación del código versionado

- Los 15 XML de reglas contienen 143 bloques `<rule>`; todos incluyen `<description>` y un comentario explicativo.
- Los XML de reglas y decoders tienen documentación Markdown adyacente.
- El workflow `OrangeBox regression tests` compila todos los Python, valida la sintaxis Bash, parsea los XML y ejecuta las dos suites unitarias.
- La prueba de integración con `wazuh-logtest` queda manual porque requiere un Manager real.
