# Lector de política Active Response

Archivo: `orangebox_active_response.py`.

Este módulo es una biblioteca de solo lectura que utiliza la integración `custom-orangebox-email.py`. Lee la configuración efectiva de `ossec.conf` y determina si una alerta coincide con un bloque de `active-response` configurado para `firewall-drop`.

## Funciones

- `_normalise_groups()`: normaliza los grupos entregados por la alerta para compararlos sin depender de mayúsculas/minúsculas.
- `_matches_group_selector()`: evalúa selectores de grupo separados por `|`; una coma final solicita coincidencia exacta del grupo, según la semántica utilizada por Wazuh.
- `firewall_drop_policy_for_alert()`: analiza los bloques habilitados, resuelve selectores por SID, grupo y nivel, y devuelve estado, ubicación y timeout efectivo cuando la alerta coincide.

## Decisión de diseño

En Wazuh, los selectores `rules_id`, `rules_group` y `level` de un mismo bloque Active Response funcionan como alternativas. El módulo replica esa evaluación para que el correo no suponga un bloqueo a partir del nivel o del grupo solamente.

El módulo **no ejecuta** `firewall-drop`, no añade reglas de firewall y no bloquea IPs. Determina qué política está configurada. Para confirmar una ejecución real se debe revisar el evento 651 y los logs/firewall del agente.

## Validación

Las pruebas de regresión están en `tests/test_orangebox_active_response.py`. Incluyen coincidencia exacta de grupos, alternativas OR, reglas deshabilitadas, configuración inválida, timeout y parcheo idempotente.
