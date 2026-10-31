# Patcher de Active Response IOC

Script: `tools/patch-ioc-active-response-conf.py`.

Este programa modifica exclusivamente los bloques `firewall-drop` de IOC definidos por OrangeBox dentro de un `ossec.conf`. Está diseñado para conservar el resto de la configuración local del Manager.

## Funciones

- `_rules_ids()`: obtiene los IDs incluidos en un bloque Active Response.
- `_firewall_blocks()`: enumera únicamente los bloques asociados a `firewall-drop`.
- `_find_target_block()`: localiza el bloque que corresponde a la política IOC que se va a migrar.
- `_already_applied()`: reconoce el estado deseado y evita reescribir el archivo si ya está aplicado.
- `_migrate_current_policy()`: sustituye la política IOC antigua por los dos grupos de timeout acordados.
- `_write_atomic()`: escribe en un archivo temporal y reemplaza el destino de forma atómica.
- `patch_config()`: valida, aplica el cambio y devuelve si el archivo fue modificado.
- `main()`: procesa argumentos, informa el resultado y devuelve el código de salida.

## Política escrita

- IOC con IP de origen: bloqueo de 7 días.
- Explotación web de alta confianza con IOC: bloqueo de 30 días.

El patcher no descarga listas, no crea IPs de origen y no ejecuta bloqueos. La configuración resultante debe validarse con `wazuh-analysisd -t` antes de reiniciar el Manager.

## Pruebas

`tests/test_orangebox_active_response.py` verifica timeout, selectores OR, migración de la política anterior, idempotencia y rechazo de cambios inesperados en la estructura.
