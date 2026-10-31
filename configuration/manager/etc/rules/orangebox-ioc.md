# Reglas IOC OrangeBox

## Objetivo

Agregar contexto OrangeBox a los indicadores de compromiso que Wazuh ya detecta.

La fuente de los IOC sigue siendo la CDB oficial de Wazuh: IP maliciosas, dominios maliciosos y hashes de malware.

Para SYN flood, la regla IOC 10463 hereda directamente de 10454, que es la detección final del flood. No depende de una regla intermedia eliminada.

## Respuesta

Los IOC de origen conocidos activan `firewall-drop` en el primer evento que coincide con una regla de detección que contiene `srcip`:

- `10460`-`10463` y las reglas nativas Wazuh `99903`, `99904`, `99905`, `99907`, `99908`, `99911`, `99912`, `99913` y `99914`: bloqueo inmediato durante 7 días (`604800` segundos), siempre que el evento exponga la IP de origen en `srcip`.
- `99906`: ataque web desde IOC conocido que devolvió HTTP 200; bloqueo inmediato durante 30 días (`2592000` segundos).

Las reglas `10460`-`10463` se notifican inmediatamente mediante `orangebox_immediate`. La regla nativa `99906` se fuerza a envío inmediato por ID en el integrador.

No se asocian automáticamente a `firewall-drop` reglas cuyo IOC aparece en campos distintos de `srcip`: por ejemplo `ClientIP`, `ip_address`, `src_ip`, `dest_ip` o campos Windows. El comando estándar `firewall-drop` requiere `srcip`; además, `dest_ip` es una IP destino y no debe bloquearse como atacante.

Las detecciones de dominio por HTTP o DNS (`10464`/`10465`) solo elevan la alerta. No se bloquean automáticamente porque el destino no es una IP de origen segura para `firewall-drop`.

## Regla de diseño

La respuesta automática debe coincidir con el tipo de IOC. No se debe bloquear una IP de origen cuando el IOC detectado es un dominio de destino.

## Validación

Comprobar con `wazuh-logtest` que el ataque conserva su regla base, que el IOC agrega la regla hija y que solo los IOC de origen activan `firewall-drop`. La configuración se prueba separadamente: `wazuh-logtest` no ejecuta Active Response.
