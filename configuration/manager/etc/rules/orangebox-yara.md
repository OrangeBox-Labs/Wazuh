# Integración FIM → YARA

## Qué hace

YARA analiza los archivos nuevos o modificados que Wazuh FIM identifica dentro de las zonas delicadas de OrangeBox.

En estas zonas no se exige:

- una extensión determinada;
- permiso de ejecución;
- que el archivo sea un script.

Esto evita perder un payload que todavía no tenga chmod +x, use un nombre inesperado o no tenga extensión.

## Zonas analizadas

- /tmp
- /var/tmp
- /dev/shm
- /opt/zimbra/data/tmp
- /opt/zextras/data/tmp

## Flujo

```text
FIM 554/550
   ↓
10420/10421
   ↓
Active Response local
   ↓
orangebox-yara.sh
   ↓
YARA
   ↓
10501 si existe coincidencia
```

El runtime de YARA mantiene un límite de tamaño de archivo para evitar escaneos descontrolados.

## Importante

`10420` y `10421` son señales auxiliares. Pueden mantenerse en nivel 3 porque sirven para activar YARA aunque no se persistan con `log_alert_level=5`.

Una coincidencia real llega a `10501` (nivel 3), que clasifica el resultado sin elevar por sí sola la severidad. La categoría y la correlación determinan la prioridad final: `10502` webshell (nivel 14), `10503` malware (nivel 10), `10504` correo (nivel 5), `10505` documento sospechoso (nivel 8), `10510` múltiples firmas webshell distintas (nivel 15) y `10511` múltiples firmas malware distintas (nivel 13).

## Motivo del cambio

La versión anterior asociaba la selección a extensiones de script/webshell. La nueva política da prioridad a las zonas delicadas: cualquier archivo nuevo o modificado allí se analiza, independientemente de sus permisos.

YARA sigue siendo solo detección. No elimina ni mueve archivos.

Las reglas `10502`, `10510` y `10511` incluyen el grupo `orangebox_immediate`, por lo que sus correos no esperan la ventana de agrupación de 10 minutos. La regla base `10501` y las demás categorías conservan el tratamiento definido por sus niveles y grupos.