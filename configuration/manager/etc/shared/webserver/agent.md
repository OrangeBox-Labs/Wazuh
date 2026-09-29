# Perfil FIM para servidores web

## Objetivo

Vigilar los puntos donde un cambio puede indicar compromiso, persistencia o alteración de la aplicación.

## Alcance

El perfil controla temporales, SSH, sudo, PAM, persistencia, red, firewall, binarios relacionados con privilegios y configuraciones de Apache, Nginx y PHP.

También controla archivos ejecutables dentro de los webroots.

## Por qué no se vigila todo /var/www

Vigilar cada archivo genera ruido y consumo. El perfil se concentra en extensiones y archivos que pueden ejecutar o alterar código.

## Who-Data

Se usa donde conocer usuario y proceso aporta valor durante una investigación. No se activa indiscriminadamente porque aumenta el costo de monitoreo.

## Archivos sensibles

Archivos como claves SSH, shadow y gshadow se controlan, pero no se almacenan diferencias de contenido. La integridad importa; el contenido secreto no debe aparecer en alertas.

## Validación

Comprobar la etiqueta orangebox.profile=webserver, crear un archivo de prueba en un webroot, modificar una configuración de Nginx o Apache y verificar la alerta FIM.
