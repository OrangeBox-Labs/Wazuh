# Reglas IOC OrangeBox

## Objetivo

Agregar contexto OrangeBox a los indicadores de compromiso que Wazuh ya detecta.

La fuente de los IOC sigue siendo la CDB oficial de Wazuh: IP maliciosas, dominios maliciosos y hashes de malware.

Para SYN flood, la regla IOC 10463 hereda directamente de 10454, que es la detección final del flood. No depende de una regla intermedia eliminada.

## Respuesta

Los IOC de origen conocido pueden activar firewall-drop cuando la alerta contiene una IP de origen.

Las detecciones de dominio por HTTP o DNS solo elevan la alerta. No se bloquean automáticamente porque el destino no es una IP de origen segura para firewall-drop.

## Regla de diseño

La respuesta automática debe coincidir con el tipo de IOC. No se debe bloquear una IP de origen cuando el IOC detectado es un dominio de destino.

## Validación

Comprobar con wazuh-logtest que el ataque conserva su regla base, que el IOC agrega la regla hija y que solo los IOC de origen activan firewall-drop.
