# Prueba y depuración de reglas Wazuh

## 1. Validar sintaxis

Después de modificar XML, decoders, listas CDB o `ossec.conf`:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

Resolver los errores antes de reiniciar el servicio. Un aviso sobre una CDB inexistente suele indicar una ruta incorrecta o una lista no declarada en el bloque `<ruleset>`.

## 2. Probar una muestra

```bash
/var/ossec/bin/wazuh-logtest
```

Pegar una línea de log representativa y revisar el decoder, los campos extraídos, el SID final, nivel, grupos y descripción. La muestra debe corresponder al formato original del log; un JSON de alerta ya procesado no siempre sirve como entrada para `wazuh-logtest`.

## 3. Revisar alertas

En esta implementación, la fuente principal de alertas es `/var/ossec/logs/alerts/alerts.json`; `alerts.log` puede estar desactivado.

```bash
jq 'select(.rule.id == "SID") | {timestamp, rule: .rule, agent: .agent, data: .data, location}' /var/ossec/logs/alerts/alerts.json
```

Reemplazar `SID` por el identificador probado. Confirmar timestamp, agente, regla, nivel, grupos, IP de origen y ubicación del log. Los campos disponibles dependen del decoder.

## 4. Comprobar Active Response

Una alerta de detección no demuestra por sí sola que se ejecutó un bloqueo.

```bash
grep -F 'firewall-drop' /var/ossec/logs/active-responses.log
```

Confirmar además que `ossec.conf` tenga un bloque `<active-response>` habilitado para el SID correcto, con `<location>local</location>`, timeout definido y una IP de origen válida. El bloqueo se aplica en el agente indicado por la ubicación; no asumir que ocurrió en el Manager.

## 5. Criterio de aceptación

- La validación de sintaxis termina sin errores.
- La muestra selecciona el decoder y SID esperados.
- Los campos requeridos están presentes.
- No aparecen falsos positivos con tráfico legítimo.
- Si hay respuesta automática, se confirma tanto el registro de ejecución como el bloqueo real.
- Las pruebas no incorporan datos de clientes al repositorio público.

No bajar niveles ni ampliar excepciones solo para ocultar alertas. Limitar las excepciones al endpoint, origen, usuario o comando estrictamente necesario.
