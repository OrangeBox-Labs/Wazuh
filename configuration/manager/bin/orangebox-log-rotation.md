# Rotación de logs internos OrangeBox

El script `orangebox-log-rotation` comprime y retiene los logs internos auxiliares del Manager. Se ejecuta una vez al día desde `etc/cron.d/orangebox-log-rotation`.

## Alcance

Solo procesa estos árboles:

```text
/var/ossec/logs/wazuh
/var/ossec/logs/firewall
```

Los archivos `.json` y `.log` se comprimen con gzip cuando tienen más de 24 horas. Si `lsof` está instalado, un archivo que sigue abierto se deja intacto. Los archivos comprimidos que superan siete días se eliminan; luego se retiran únicamente los directorios que quedaron vacíos.

## Protección operativa

- El lock `/run/orangebox-log-rotation.lock` evita ejecuciones simultáneas cuando `flock` está disponible.
- `gzip -n` evita incluir el nombre y timestamp originales dentro del encabezado gzip.
- Los errores individuales de compresión o purga no detienen la limpieza de los demás archivos.
- Si falta `find` o `gzip`, el script termina sin modificar los logs.

## Exclusiones

El script no toca `alerts/`, `active-responses.log` ni `ossec.log`. Tampoco reinicia servicios ni purga otros logs de Wazuh.

## Validación

Ejecutar en un Manager de laboratorio o con datos de prueba y comprobar que:

1. un `.log` antiguo se convierte en `.log.gz`;
2. un archivo modificado durante las últimas 24 horas permanece sin comprimir;
3. un `.gz` con más de siete días se elimina;
4. los logs de alertas, Active Response y `ossec.log` permanecen intactos.

El cron productivo corre como `root`; ejecutar pruebas manuales con precaución y nunca usar `touch` para envejecer logs reales.
