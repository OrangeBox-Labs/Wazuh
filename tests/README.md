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
| `test_orangebox_hardening.py` | Regresión estructural | Comprueba perfil CDB, nivel, regla padre y rutas exactas de las excepciones FIM `20059`/`20060`. |
| `test-ioc-active-response.sh` | Integración | Ejecuta la suite Python, consulta la política configurada en el Manager y utiliza `wazuh-logtest` para validar muestras reales de reglas. |
| `fixtures/web-ioc-99906.log` | Fixture | Muestras de access log anonimizadas para reproducir una detección HTTP IOC/PHP2Shell. |

## Contrato del instalador del agente

`test_agent_audit_rotation_contract.sh` valida que el instalador integre la política diaria de auditd y compruebe conflictos antes de escribir. `test_agent_audit_rotation.sh` ejecuta el helper con un servicio simulado y archivos temporales para validar gzip y retención selectiva de siete días. Estas pruebas no requieren un Manager real.

## Requisitos

Para ejecutar las pruebas unitarias se necesita Python 3 y la biblioteca estándar. No requieren conexión al Indexer ni envían correos.

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
```

Para validar además la configuración efectiva del Manager:

```bash
sudo bash tests/test-ioc-active-response.sh
```

Una ejecución en un equipo sin Wazuh Manager debe limitarse a la suite Python; el script de integración termina con error si no encuentra `wazuh-logtest`.

## Cómo agregar una prueba

1. Reproducir primero el problema con un caso mínimo.
2. Agregar un caso positivo y, cuando corresponda, uno negativo para comprobar que no se amplió la detección.
3. Usar fixtures sintéticos o anonimizados: no incorporar dominios, correos, nombres de host, logs ni datos de clientes reales. Si una prueba necesita una IOC real confirmada para reproducir la política privada, mantenerla únicamente en el repositorio privado y documentar su propósito. La versión pública debe usar direcciones TEST-NET (RFC 5737) y datos ficticios.
4. Ejecutar la suite completa y documentar cualquier requisito de integración.
5. No cambiar una regla ni suprimir una alerta solo para hacer pasar una prueba; el resultado esperado debe reflejar la política de seguridad aprobada.

## Automatización CI

`.github/workflows/vulnerability-alerts-tests.yml` valida la compilación de Python, la sintaxis de todos los scripts Bash, la estructura de los XML, las pruebas del detector de vulnerabilidades y esta suite `tests/`. Las pruebas que requieren un Manager real se ejecutan manualmente con `test-ioc-active-response.sh`; no deben simular un Manager ni aplicar bloqueos dentro de CI.
