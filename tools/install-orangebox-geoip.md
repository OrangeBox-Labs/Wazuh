# Instalador GeoIP OrangeBox

## Objetivo

Instalar el actualizador de bases DB-IP Lite usado por los reportes de seguridad.

## Qué hace

Verifica root y las herramientas necesarias, instala el updater en /usr/local/sbin, crea el cron diario, prepara /var/lib/orangebox/geoip y ejecuta una primera actualización.

## Horario

La tarea se ejecuta todos los días a las 03:20.

## Motivo

Los reportes necesitan resolver IP públicas a país y ASN sin depender de consultas externas durante cada ejecución.

## Validación

Comprobar el updater, /etc/cron.d/orangebox-geoip y los archivos bajo /var/lib/orangebox/geoip.

El updater registra su ejecución en /var/log/orangebox-geoip-update.log.
