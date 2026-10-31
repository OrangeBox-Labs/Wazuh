# Decoder de métricas de incidentes

Archivo: `orangebox-incident-metrics.xml`.

Este decoder interpreta mensajes sintéticos emitidos por telemetría local del Agent. Su trabajo es convertir una línea de texto con prefijo OrangeBox en campos que las reglas puedan evaluar; no calcula métricas ni ejecuta comandos.

## Eventos reconocidos

Los prefijos `ORANGEBOX_*` identifican mediciones del endpoint, por ejemplo presión de conexiones SYN-RECV, carga del sistema, uso de CPU por `ksoftirqd` o carga de pools PHP-FPM cuando el perfil cPanel los instala.

El decoder conserva el nombre del evento y los valores como campos de datos. Las reglas de los archivos `orangebox-incident-webdos.xml` y `orangebox-behavior.xml` aplican después los umbrales y correlaciones.

## Flujo

1. La telemetría local del Agent escribe una línea estructurada con el prefijo de evento.
2. Logcollector recoge la salida configurada.
3. El decoder extrae los campos.
4. Las reglas comparan esos campos con sus umbrales y ventanas de tiempo.
5. Solo las reglas con una política Active Response explícita pueden disparar una acción.

La presencia de una medición no equivale por sí sola a un incidente ni a un bloqueo.

## Mantenimiento

Cuando se agregue un nuevo prefijo, documentar el nombre, los campos extraídos, la unidad y qué regla consume esos campos. Validar el XML con `wazuh-analysisd -t` y probar una muestra de log con `wazuh-logtest`.
