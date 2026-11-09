# OrangeBox Wazuh — pruebas de regresión

Este directorio contiene pruebas de desarrollo. **No forma parte de la configuración que se despliega en `/var/ossec`** y no debe copiarse al Manager durante una instalación normal.

Las pruebas protegen contratos funcionales que han causado regresiones antes: política real de Active Response, actualización de CDB IOC y detección PHP2Shell. Se ejecutan desde la raíz del repositorio.

## Qué prueba cada archivo

| Archivo | Tipo | Cobertura |
|---|---|---|
| `test_orangebox_active_response.py` | Unitarias | Interpretación de los bloques `active-response`, selectores por SID/grupo/nivel, timeouts, reglas deshabilitadas y parcheo idempotente de `ossec.conf`. |
| `test_ioc_updater_contract.py` | Contrato | Parser de fuentes IOC, validación de listas, combinación de IP confirmadas, protección de secretos y autorización de la migración inicial. |
| `test_vulnerability_alerts.py` | Unitarias | Normalización y consolidación CVE/agente, consulta de IP por API, deduplicación, outbox SQLite, `--status` de solo lectura y configuración de severidades. |
| `test_orangebox_php2shell.py` | Unitarias | Patrones positivos y negativos de PHP2Shell, límites de detección, relación con reglas IOC y política de respuesta. |
| `test_orangebox_hardening.py` | Regresión estructural | Comprueba las excepciones FIM Snap `20058`/`20061`, CloudLinux `20059`/`20060` y BitNinja `20066`/`20069`, además de los niveles, reglas padre y alcances exactos. |
| `test_operational_noise_exceptions.py` | Regresión estructural | Valida las excepciones Google Cloud `20062`–`20065` y `20080`–`20083` (CDB, diffs GCP, Who-Data y eventos scheduled/realtime), el SSH local Zimbra `20011`, la supresión de PDF cifrado (`10710`/`20067`), la excepción del temporal ClamAV (`20068`), la conservación de reglas críticas y el umbral de correo. |
| `test_agent_audit_rotation.sh` | Funcional y contrato | Agrupa las pruebas del helper de rotación auditd y del instalador: sintaxis, preflight de `crond`, rotación simulada, gzip, retención selectiva, archivos externos y propagación de errores. |
| `test_orangebox_yara_scope.py` | Regresión estructural | Confirma que 10420/10421 solo seleccionan `/tmp`, `/var/tmp` y `/dev/shm`, que el perfil Zimbra/Carbonio excluye sus temporales internos y que el Active Response YARA sigue conectado. |
| `test_zimbra_mail_log_sources.py` | Regresión estructural y de patrones | Comprueba fuentes MTA/ClamAV/Freshclam, filtros contra volcados DKIM/TLS, exclusión de mailbox/temporales, intentos SMTP con payload shell y veredictos Amavis/ClamAV. |
| `test-ioc-active-response.sh` | Integración | Ejecuta la suite Python, consulta la política configurada en el Manager y utiliza `wazuh-logtest` para validar muestras reales de reglas. |
| `fixtures/web-ioc-99906.log` | Fixture | Muestras de access log con la IOC de origen confirmada que necesita la prueba de reglas reales. Esta fixture se conserva solo en el repositorio privado; la versión pública usa una dirección TEST-NET. |

## Pruebas del instalador del agente

`test_agent_audit_rotation.sh` contiene funciones independientes para validar el contrato del helper, las precondiciones del instalador y el comportamiento de rotación. La prueba funcional utiliza un directorio temporal y un comando `service` simulado: **no ejecuta auditd real, no modifica `/var/log/audit` y no requiere root**.

La prueba estructural verifica el contenido del instalador, incluida la condición de que `crond` esté activo y habilitado antes de instalar la tarea y cambiar `max_log_file_action`. La validación final en un agente real de AlmaLinux/RHEL sigue siendo necesaria antes de desplegar cambios en producción.

## Requisitos

Para ejecutar las pruebas unitarias se necesita Python 3 y la biblioteca estándar. No requieren conexión al Indexer ni envían correos.

La prueba de rotación auditd requiere Bash, gzip, find y utilidades GNU disponibles en las distribuciones Enterprise Linux soportadas. No requiere un servicio auditd real.

La prueba de integración requiere ejecutarse en un Wazuh Manager con:

- `/var/ossec/bin/wazuh-logtest`;
- configuración instalada en `/var/ossec/etc/ossec.conf`;
- reglas, decoders y CDB IOC correspondientes;
- permisos para leer los archivos de configuración.

La prueba de integración es de solo lectura: no ejecuta Active Response ni bloquea la IP de las muestras. `wazuh-logtest` evalúa decoders y reglas en sandbox; comprobar una regla coincidente no demuestra que el agente haya aplicado un bloqueo. La ejecución real se valida por separado con el evento 651/10458, `active-responses.log` y el firewall del agente.

## Ejecución

Desde la raíz del checkout:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
bash tests/test_agent_audit_rotation.sh
```

Para validar además la configuración efectiva del Manager:

```bash
sudo bash tests/test-ioc-active-response.sh
```

Una ejecución en un equipo sin Wazuh Manager debe limitarse a las pruebas Python y a `test_agent_audit_rotation.sh`; el script de integración termina con error si no encuentra `wazuh-logtest`.

## Cómo agregar una prueba

1. Reproducir primero el problema con un caso mínimo.
2. Agregar un caso positivo y, cuando corresponda, uno negativo para comprobar que no se amplió la detección.
3. Usar fixtures sintéticos o anonimizados: no incorporar dominios, correos, nombres de host, logs ni datos de clientes reales. Si una prueba necesita una IOC real confirmada para reproducir la política privada, mantenerla únicamente en el repositorio privado y documentar su propósito. La versión pública debe usar direcciones TEST-NET (RFC 5737) y datos ficticios.
4. Ejecutar la suite completa y documentar cualquier requisito de integración.
5. No cambiar una regla ni suprimir una alerta solo para hacer pasar una prueba; el resultado esperado debe reflejar la política de seguridad aprobada.

## Automatización CI

`.github/workflows/vulnerability-alerts-tests.yml` compila las fuentes Python, valida la sintaxis de los scripts Bash, comprueba la estructura XML, ejecuta las pruebas Python y ejecuta explícitamente `test_agent_audit_rotation.sh`. La integración que requiere un Manager real se ejecuta manualmente con `test-ioc-active-response.sh`; no debe simular un Manager ni aplicar bloqueos dentro de CI.

- **SYSTEMD/dpkg:** `20070` valida las cuatro rutas temporales `.dpkg-new` observadas y exige Who-Data, `dpkg`, padre `apt-get`, root y alcance local/allowlist BitNinja.
