# Integración FIM → YARA (temporales generales)

## Qué hace

YARA analiza archivos nuevos o modificados que Wazuh FIM identifica en las zonas temporales generales del sistema. No inspecciona los temporales internos de Zimbra/Carbonio.

En estas zonas no se exige:

- una extensión determinada;
- permiso de ejecución;
- que el archivo sea un script.

Esto evita perder un payload que todavía no tenga chmod +x, use un nombre inesperado o no tenga extensión.

## Zonas analizadas

- /tmp
- /var/tmp
- /dev/shm

Quedan expresamente excluidos:

- /opt/zimbra/data/tmp
- /opt/zextras/data/tmp

Estos árboles contienen archivos de procesamiento, cachés y blobs transitorios. Sus eventos FIM no ofrecen una correlación fiable con un mensaje, remitente o conexión SMTP; por eso no deben disparar el análisis YARA genérico.

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

La selección se limita deliberadamente a las zonas temporales generales del sistema. Los directorios temporales internos de Zimbra/Carbonio se excluyen tanto del perfil FIM compartido como de las reglas 10420/10421 para evitar analizar archivos efímeros que no pueden atribuirse a un correo.

YARA sigue siendo solo detección. No elimina ni mueve archivos.

Las reglas `10502`, `10510` y `10511` incluyen el grupo `orangebox_immediate`, por lo que sus correos no esperan la ventana de agrupación de 10 minutos. La regla base `10501` y las demás categorías conservan el tratamiento definido por sus niveles y grupos.