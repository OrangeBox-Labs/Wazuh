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

Una coincidencia real de YARA llega a `10501`, nivel 14, y queda persistida en `alerts.json`.

## Motivo del cambio

La versión anterior asociaba la selección a extensiones de script/webshell. La nueva política da prioridad a las zonas delicadas: cualquier archivo nuevo o modificado allí se analiza, independientemente de sus permisos.

YARA sigue siendo solo detección. No elimina ni mueve archivos.