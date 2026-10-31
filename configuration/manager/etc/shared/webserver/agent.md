# Perfil FIM para servidores web

## Objetivo

Vigilar las rutas donde un cambio puede indicar compromiso, persistencia, alteración de controles del sistema o modificación de la aplicación. Este perfil hereda la política `default` y agrega controles propios de un servidor web.

La etiqueta `orangebox.profile=webserver` identifica el propósito del agente; el alcance efectivo se entrega mediante los grupos Wazuh asignados al agente.

## Alcance heredado

El perfil base mantiene el control de:

- directorios temporales `/tmp`, `/var/tmp` y `/dev/shm`, en tiempo real y con profundidad limitada;
- SSH, SUDO, PAM, Polkit, identidad, SYSTEMD, CRON y persistencia de credenciales;
- configuración de red, DNS, auditoría, certificados y firewall;
- binarios privilegiados seleccionados.

Los archivos sensibles como `shadow`, `gshadow` y claves privadas se monitorizan sin almacenar diffs de contenido cuando estos podrían exponer secretos.

## Webroots y archivos ejecutables

Se vigilan `/var/www`, `/srv/www` y `/usr/share/nginx/html` en tiempo real, filtrando por extensiones ejecutables o archivos de control:

- PHP y variantes: `.php`, `.phtml`, `.phar` e `.inc`;
- scripts: `.cgi`, `.pl`, `.py`, `.rb`, `.sh`, `.bash` y `.zsh`;
- archivos de comportamiento web: `.htaccess`, `.user.ini` y `web.config`.

No se recorre indiscriminadamente cada archivo estático del webroot. Se priorizan cambios que pueden introducir ejecución o alterar el comportamiento de la aplicación, sin convertir cada despliegue de imágenes, CSS o contenido en ruido FIM.

## Apache, Nginx y PHP

Las configuraciones de Apache se vigilan bajo `/etc/httpd/conf`, `/etc/httpd/conf.d` y `/etc/httpd/conf.modules.d`. Nginx se vigila bajo `/etc/nginx`. PHP y PHP-FPM se vigilan bajo `/etc/php.d`, `/etc/php-fpm.d`, `/etc/php.ini` y `/etc/php-fpm.conf`.

Estas rutas usan `realtime`, `report_changes` y `whodata` donde están definidos en `agent.conf`: se conserva el diff del cambio y la identidad del proceso que lo realizó. La configuración efectiva del agente es la fuente de verdad del alcance.

Los certificados de Let's Encrypt se vigilan para conservar trazabilidad de renovaciones y cambios. Una renovación por sí sola no se interpreta como intrusión.

## Who-Data y diffs

Who-Data se habilita donde saber quién o qué proceso cambió un archivo ayuda a investigar. `report_changes` se reserva para configuraciones cuyo contenido permite explicar el cambio.

No se habilita indiscriminadamente sobre todo el webroot ni sobre archivos que puedan contener secretos. La ausencia de un diff no significa que FIM no haya detectado el evento: la integridad y la atribución siguen disponibles en las rutas configuradas.

## Relación con las reglas OrangeBox

El agente recopila evidencia FIM; las reglas del Manager deciden si produce una alerta. Las familias relacionadas son:

- `orangebox-hardening.xml`: configuración crítica, persistencia y eliminaciones;
- `orangebox-temporary-executable.xml`: ejecutables nuevos en ubicaciones temporales;
- `orangebox-yara.xml`: envío de candidatos FIM de temporales a YARA;
- `orangebox-php2shell.xml`: detección conductual desde access logs y auditd; no depende de monitorizar masivamente `public_html`.

El FIM de webroots no reemplaza el análisis de logs web ni YARA. Cada mecanismo cubre una señal distinta.

## Validación

1. Confirmar que el agente esté en el grupo `webserver` y que la etiqueta del perfil esté presente.
2. Revisar el alcance recibido por el agente y el estado de `syscheck`.
3. Crear un archivo PHP inocuo de prueba en un webroot de laboratorio y comprobar la alerta de archivo nuevo.
4. Modificar en laboratorio un archivo de configuración de Nginx o Apache y comprobar el diff y los datos Who-Data.
5. Verificar que archivos estáticos no incluidos en el filtro no generen eventos por cambios rutinarios.

No realizar estas pruebas creando scripts ejecutables en un webroot de producción.
