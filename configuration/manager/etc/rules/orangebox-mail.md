# Detección de fuerza bruta de correo

Este componente agrega una capa OrangeBox sobre las reglas nativas de Wazuh para detectar múltiples fallos de autenticación contra servicios de correo.

## Detecciones

- `10700`: Postfix detectó múltiples fallos de autenticación SASL. Se basa en la regla nativa `3357`.
- `10701`: Exim/Dovecot detectó múltiples fallos de autenticación. Se basa en la regla nativa `87507`.

Las dos reglas quedan en nivel 13 y disparan `firewall-drop` durante 24 horas. La integración OrangeBox NO envía correo individual para estos eventos porque son recurrentes.

## Contención

`firewall-drop` se aplica automáticamente en el mismo servidor que generó el evento, con un bloqueo de 24 horas. La alerta sigue quedando en Wazuh; solo se suprime el correo individual para evitar ruido.

## Dependencias

La detección depende de que el servidor genere logs compatibles con las reglas nativas de Wazuh y de que esas reglas estén activas.

Postfix usa la regla nativa `3332` para un fallo individual y `3357` para múltiples fallos SASL. La capa OrangeBox usa `3357` para elevar el evento correlacionado a nivel 13.

## Prueba

Antes de desplegar a todos los servidores de correo:

1. Validar la regla con `wazuh-logtest`.
2. Generar varios fallos controlados.
3. Confirmar `10700` o `10701` en `alerts.json`.
4. Confirmar la ejecución de `firewall-drop` mediante la regla `651`.
5. Confirmar que NO llega correo individual por la integración OrangeBox.

Si un formato real de Dovecot o Exim no entrega correctamente `srcip`, se debe corregir primero la extracción antes de automatizar contención.