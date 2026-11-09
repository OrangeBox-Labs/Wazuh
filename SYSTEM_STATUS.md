# OrangeBox Wazuh — estado del repositorio

> Revisión de `main` realizada el 31 de octubre de 2026. Este documento describe lo versionado en Git; **no demuestra por sí solo que un Manager o Agent de producción tenga desplegado el mismo commit**.

## Resumen de estado

| Subsistema | Estado en el repo | Fuente de configuración / documentación |
|---|---|---|
| Wazuh Manager | Activo | `configuration/manager/etc/ossec.conf`, `configuration/manager/ossec.md` |
| Reglas OrangeBox | Activas y documentadas | `configuration/manager/etc/rules/*.xml` + `*.md` |
| Decoders | Activos | `configuration/manager/etc/decoders/` + documentación junto a cada XML |
| FIM por perfil | Activo | `configuration/manager/etc/shared/{default,cpanel,zimbra,webserver}/agent.conf` |
| CDB / allowlists | Activas | `configuration/manager/etc/lists/` y actualizadores de `configuration/manager/bin/` |
| Active Response | Activo y explícito en ossec.conf | Bloques `firewall-drop`, `orangebox-yara` y `orangebox-quarantine` |
| Email SOC | Activo | `configuration/manager/integrations/custom-orangebox-email.py` |
| IOC updater | Activo | `configuration/manager/bin/update-orangebox-ioc-lists.sh` |
| Vulnerability alerts | Activo | `configuration/manager/vulnerability-alerts/`, reglas 100321–100323 y cron |
| GeoIP | Activo | `configuration/manager/bin/update-orangebox-geoip.sh` |
| Agent installer | Activo | `tools/agent/install.sh` |
| RPM OPT builder | Activo | `packages/agent/build.sh` |
| Reporte ejecutivo/detallado | Activo | `configuration/manager/reports/orangebox-security-report.py` |
| Pruebas de regresión | Activas para desarrollo | `tests/` y workflow `.github/workflows/vulnerability-alerts-tests.yml` |

## Reglas de seguridad

Los rulesets tienen documentación adyacente. Los principales son:

- `orangebox-auth.xml`: autenticación, SUDO, SSH y excepciones por perfil.
- `orangebox-hardening.xml`: modificaciones/eliminaciones FIM, persistencia y excepciones operacionales.
- `orangebox-ioc.xml`: coincidencias de IOC confirmadas.
- `orangebox-web.xml`: reconocimiento y explotación web.
- `orangebox-incident-webdos.xml`: correlaciones de disponibilidad/DoS derivadas de incidentes.
- `orangebox-php2shell.xml`: comportamiento PHP2Shell/PEAR.
- `orangebox-vulnerability-alerts.xml`: eventos JSON consolidados de vulnerabilidades.

Las reglas detectoras siguen siendo la fuente de decisión. Las listas, perfiles y eventos FIM proporcionan contexto; no se deben sustituir por whitelists globales.

### FIM y excepciones cPanel/CloudLinux

- `10035` detecta cambios de contenido en CRON/ANACRON.
- `10045` detecta eliminaciones de CRON/ANACRON.
- `20032` cubre la regeneración exacta de `cpanel_ssl_reissue`.
- `20059` conserva en nivel 3 la eliminación exacta de `cpanel_php_sessions_cron` en agentes cPanel.
- `20060` conserva en nivel 3 las modificaciones de `lvemanager-cron`, `lvemanager-selector` y `cloudlinux-cron`; **no** exceptúa sus eliminaciones.
- `20062`, `20064`, `20080` y `20082` son las excepciones GCP de `/etc/hosts`. Son hijas inmediatas de `10036` y se limitan al diff exacto, al modo FIM y, cuando existe Who-Data, al proceso y usuario observados. No dependen de CDB/hostname.
- `20011` conserva en nivel 3 el SSH local de `zimbra` desde la propia IP de `mail.example.invalid`.
- `10710` rebaja a nivel 5 únicamente `Heuristics.Encrypted.PDF FOUND`; las firmas ClamAV restantes y Amavis `INFECTED` mantienen su severidad.
- `20066` conserva en nivel 5 únicamente el bloque programado exacto que vincula `bitninja.service` con `nftables.service`; otras modificaciones SYSTEMD siguen críticas.

Las excepciones de `/etc/hosts` son globales, pero siguen limitadas por ruta exacta y diff GCP completo; las variantes Who-Data exigen además proceso reconocido, `root` y UID efectivo 0. Como segunda barrera de notificación, `custom-orangebox-email.py` contiene la validación inline para silenciar únicamente el correo de los diffs GCP idempotentes exactos que todavía lleguen como `10036`; no depende de un helper externo. La alerta original permanece en Wazuh, y todo dato incompleto o cambio funcional sigue enviando correo. No se desactiva FIM ni se ignora globalmente `/etc/hosts`.

## Active Response

La política vigente en `ossec.conf` separa las duraciones según la confianza del evento:

| Selector | Timeout | Comportamiento |
|---|---:|---|
| IOC de IP de origen confirmadas y reglas nativas relacionadas | 604800 s (7 días) | `firewall-drop` |
| Explotación web de alta confianza con IOC/PHP2Shell (99906, 10053) | 2592000 s (30 días) | `firewall-drop` |
| Grupo `orangebox_web_auto_block` | 86400 s (24 horas) | Bloqueo local de reconocimiento web de alta confianza; incluye la regla 10051 para escaneo PHP2Shell repetido tras excluir proxies autorizados |
| Grupo `orangebox_syn_flood_block` | 3600 s (1 hora) | Bloqueo ante presión SYN-RECV persistente de una sola IP |

El DoS distribuido sin una única IP responsable se detecta, pero no se bloquea de forma indiscriminada. `orangebox-yara` analiza archivos candidatos; `orangebox-quarantine` se reserva para el hash de malware confirmado. La integración de correo lee la política real de `ossec.conf`; no debe inferir una acción a partir del nivel de la alerta.

## CDB y actualización de datos

- `update-orangebox-cpanel-agents.sh`, `update-orangebox-dns-agents.sh` y `update-orangebox-zimbra-agents.sh` sincronizan grupos Wazuh a CDB.
- `update-orangebox-backuppc.sh` resuelve los destinos dinámicos de BackupPC; la lista estática se administra separadamente.
- `update-orangebox-geoip.sh` valida las bases MMDB antes de reemplazarlas.
- `update-orangebox-ioc-lists.sh` separa IP de origen, IP de hosting, dominios y hashes; valida cada fuente antes de reemplazar CDB.
- La primera reclasificación de IOC requiere DRY_RUN y aprobación explícita. La Auth-Key abuse.ch se mantiene en un archivo root-only fuera de Git.

## Alertas complementarias de vulnerabilidades

`vulnerability-alerts.py` consulta `wazuh-states-vulnerabilities-*`, agrupa por CVE y agente, deduplica en SQLite y publica un evento JSON compacto en:

```text
/var/ossec/logs/vulnerability-alerts/events.jsonl
```

Las reglas 100321/100322/100323 cubren Medium/High/Critical. Critical es obligatoria; High y Medium son configurables. El cron de ejemplo ejecuta el detector cada 8 horas. `--status` es de solo lectura; `--dry-run` no publica eventos; `--force` sin dry-run puede generar una alerta/correo real.

## Agent y telemetría

`tools/agent/install.sh` es el instalador único. Detecta Enterprise Linux, reconcilia el paquete, almacenamiento, firewall/logging, auditd, telemetría local, YARA y el Active Response de cuarentena. Las métricas SYN-RECV, ksoftirqd, carga y PHP-FPM se crean localmente; no se duplican en los grupos compartidos. El instalador conserva `logcollector.remote_commands=0`.

El builder privado genera por defecto el Agent OPT 4.14.9, y existe un RPM privado 4.14.9. El instalador `tools/agent/install.sh` todavía mantiene `WAZUH_VERSION='4.14.8'`; por tanto, 4.14.9 debe tratarse como candidato de build y no como versión desplegada por defecto hasta validar el RPM, actualizar el instalador y aprobar el cambio de despliegue. Se conserva también el RPM OPT 4.14.8 como versión de compatibilidad/rollback.

## Hardening web/DoS derivado de incidentes

La guía [`docs/incident-derived-webdos-hardening.md`](docs/incident-derived-webdos-hardening.md) documenta la matriz de detección 10820–10834, el origen de las señales, los umbrales, las decisiones de Active Response y las validaciones requeridas. La guía es común a ambos repositorios y no contiene datos de clientes.

## Reportes

`orangebox-security-report.py` utiliza un motor de reporte unificado: produce el resumen ejecutivo y el detalle ZIP en la misma ejecución. El detalle incluye MITRE, FIM, autenticación, IOC/bloqueos, vulnerabilidades y GeoIP. El motor detallado del privado se sincronizó con la implementación más completa del repositorio público, conservando los remitentes y recursos propios del privado.

## Pruebas

El directorio `tests/` es **desarrollo**, no configuración de Manager. Contiene pruebas unitarias/contractuales para Active Response, IOC updater, detector de vulnerabilidades, PHP2Shell y los límites de las excepciones FIM CRON, además de fixtures de prueba controlados. La fixture de IOC confirmada se conserva solo en este repositorio privado; el repositorio público usa una dirección TEST-NET. La CI ejecuta:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

La suite `test_vulnerability_alerts.py` también vive en `tests/`. El directorio `configuration/manager/vulnerability-alerts/` contiene el servicio y su configuración de runtime, no una suite separada; no se ejecuta un descubrimiento de pruebas vacío allí.

El test `test_vulnerability_alerts.py` vive en `tests/`, no en `configuration/manager/`, para que no se copie al Manager durante el despliegue.

La integración `sudo bash tests/test-ioc-active-response.sh` requiere un Manager real y `wazuh-logtest`; se ejecuta manualmente y no bloquea IPs.

## Limpieza aplicada

- Eliminado `.github/workflows/ioc-active-response-tests.yml`; la suite útil se conserva y se ejecuta desde el workflow de regresión actual.
- Eliminado `configuration/manager/reports/reporte-test.py`, copia de prueba obsoleta no referenciada por cron.
- Eliminado `configuration/manager/reports/world-map.min.svg`, asset legado sin referencias en los motores de reportes.
- Eliminada la nota histórica de wrapping del correo que referenciaba un patch inexistente y ya aplicado en el código.
- Las fragmentaciones XML de prueba no forman parte del despliegue; la configuración efectiva vive en `ossec.conf` y en los perfiles compartidos.

## Diferencias privadas intencionales

Este repositorio conserva la CDB SFTP de cliente, crons de reportes por cliente, IOC confirmadas y datos de operación privados. No copiar esas listas ni destinatarios al repositorio público. Las credenciales, inventarios, SQLite, JSONL de producción y resultados de reportes permanecen fuera de Git.

## Validación del código versionado

- Los 15 XML de reglas contienen 143 bloques `<rule>`; todos incluyen `<description>` y un comentario explicativo.
- Los XML de reglas y decoders tienen documentación Markdown adyacente.
- El workflow `OrangeBox regression tests` compila todos los Python, valida scripts Bash (incluido `orangebox-log-rotation`, que no usa extensión `.sh`), parsea reglas/decoders XML, `ossec.conf` y perfiles `agent.conf`, y ejecuta la suite Python de `tests/`.
- La prueba de integración con `wazuh-logtest` queda manual porque requiere un Manager real.
