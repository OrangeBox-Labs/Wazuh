# Detección de fuerza bruta de correo

Este componente agrega una capa OrangeBox sobre las reglas nativas de Wazuh para detectar múltiples fallos de autenticación contra servicios de correo.

## Detecciones

- `10700`: Postfix detectó múltiples fallos de autenticación SASL. Se basa en la regla nativa `3357`.
- `10701`: Exim/Dovecot detectó múltiples fallos de autenticación. Se basa en la regla nativa `87507`.

Las dos reglas quedan en nivel 13 y se envían inmediatamente por la integración OrangeBox.

## Contención

No se aplica `firewall-drop` automáticamente.

La razón es simple: una IP puede representar una red corporativa, NAT, cliente legítimo o servicio compartido. Primero se registra y alerta la actividad; la contención queda para una fase posterior basada en pruebas reales.

## Dependencias

La detección depende de que el servidor genere logs compatibles con las reglas nativas de Wazuh y de que esas reglas estén activas.

Postfix usa la regla nativa `3332` para un fallo individual y `3357` para múltiples fallos SASL. La capa OrangeBox usa `3357` para elevar el evento correlacionado a nivel 13.

## Prueba

Antes de desplegar a todos los servidores de correo:

1. Validar la regla con `wazuh-logtest`.
2. Generar varios fallos controlados.
3. Confirmar `10700` o `10701` en `alerts.json`.
4. Confirmar que llega un único correo inmediato.
5. Verificar que no existe `firewall-drop`.

Si un formato real de Dovecot o Exim no entrega correctamente `srcip`, se debe corregir primero la extracción antes de automatizar contención.