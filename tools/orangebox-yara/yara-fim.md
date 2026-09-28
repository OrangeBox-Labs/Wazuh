# Integración FIM -> YARA OrangeBox

## Política

La integración FIM -> YARA utiliza exclusivamente el proyecto oficial:

https://github.com/Yara-Rules/rules

No se mantienen reglas YARA propias de OrangeBox.

El proyecto oficial publica índices como:

- webshells_index.yar
- malware_index.yar

y mantiene categorías separadas para webshells y malware.

Referencia:
- https://github.com/Yara-Rules/rules

## Arquitectura

FIM 554 / 550
      |
      v
10420 / 10421
      |
      v
Active Response local
      |
      v
orangebox-yara.sh
      |
      +--> webshells_index.yar
      |
      +--> malware_index.yar
      |
      v
WAZUH_HOME/logs/active-responses.log
      |
      v
decoder orangebox-yara
      |
      v
10501 level 14
      |
      v
integración de correo / dashboard

El script nunca ejecuta YARA sobre todo el filesystem. Recibe el path del evento FIM y analiza solamente ese archivo.

## Alcance del disparador

El Manager considera candidatos para YARA únicamente en zonas temporales de ejecución crítica:

- /tmp
- /var/tmp
- /dev/shm
- /opt/zimbra/data/tmp
- /opt/zextras/data/tmp

El alcance se limita además a extensiones que razonablemente pueden contener código ejecutable o payloads.

No se dispara YARA sobre /home/*/public_html, /var/www, /srv/www, /usr/share/nginx/html ni sobre webapps permanentes. Es una decisión deliberada de rendimiento y relación señal/ruido, no una afirmación de que esos archivos sean seguros.

## Instalación

El instalador se encuentra en:

tools/orangebox-yara/install-orangebox-yara.sh

Ejecutar como root desde el checkout:

chmod +x tools/orangebox-yara/install-orangebox-yara.sh
tools/orangebox-yara/install-orangebox-yara.sh

El instalador comprueba e instala automáticamente, cuando faltan:

- YARA
- jq
- git

Soporta gestores de paquetes dnf, yum y apt-get. Si los paquetes no están disponibles en los repositorios configurados, la instalación falla de forma explícita.

Para impedir cualquier instalación automática de paquetes:

ORANGEBOX_YARA_NO_PACKAGE_INSTALL=yes tools/orangebox-yara/install-orangebox-yara.sh

El instalador detecta automáticamente:

- /opt/ossec para la instalación OrangeBox/cPanel;
- /var/ossec para un agente Wazuh estándar.

No modifica ossec.conf del agente ni la configuración del Manager.

## Qué instala

El runtime queda en:

WAZUH_HOME/active-response/bin/orangebox-yara.sh

Las firmas oficiales quedan en:

WAZUH_HOME/active-response/bin/yara/rules/yara-rules/

El instalador valida los índices oficiales antes de reemplazar el ruleset, exige un commit inmutable aprobado y registra:

YARA-RULES-COMMIT
YARA-RULES-REPOSITORY
YARA-RULES-BRANCH

El .git del checkout no se conserva en el agente.

También elimina restos de los archivos históricos de reglas propias que ya no forman parte del despliegue:

orangebox-webshell-core.yar
orangebox-webshell-extended.yar

El runtime actual utiliza únicamente los índices oficiales de Yara-Rules/rules: `webshells_index.yar` y `malware_index.yar`.

## Formato del resultado

Para mantener el decoder estable, el runtime emite:

wazuh-yara: ALERT - Match: category=webshells rule=<RULE> path=/ruta/al/archivo

o:

wazuh-yara: ALERT - Match: category=malware rule=<RULE> path=/ruta/al/archivo

El Manager decodifica:

- yara_category
- yara_rule
- yara_scanned_file

y la regla 10501 genera una alerta de nivel 14 ante una coincidencia oficial.

## Seguridad del runtime

El Active Response es solamente de detección.

No:

- elimina archivos;
- mueve archivos;
- cambia permisos;
- pone archivos en cuarentena;
- descarga muestras de malware para analizarlas.

Además:

- ignora symlinks;
- limita por defecto los archivos a 5 MiB;
- espera brevemente a que el tamaño se estabilice después de un evento FIM;
- utiliza rutas conocidas para encontrar el binario YARA;
- registra errores de ejecución en active-responses.log.

## Alcance de FIM y YARA

El perfil cPanel no monitoriza masivamente /home/*/public_html con FIM. Se mantiene FIM quirúrgico para /home/*/.ssh y archivos de inicio de shell de los usuarios, mientras que el código web queda fuera del índice FIM.

Esto evita convertir el contenido normal de los sitios cPanel en millones de entradas FIM. La detección YARA queda concentrada en temporales de ejecución crítica, donde una aparición de código ejecutable tiene mayor valor como señal.

## Prueba controlada

Primero comprobar:

YARA_HOME=/opt/ossec/active-response/bin/yara
test -s "$YARA_HOME/rules/yara-rules/webshells_index.yar"
test -s "$YARA_HOME/rules/yara-rules/malware_index.yar"

yara -w "$YARA_HOME/rules/yara-rules/webshells_index.yar" /ruta/de/prueba

Para probar la cadena FIM -> YARA, crear un fixture de laboratorio que reproduzca una firma oficial ya conocida. No usar malware operativo real en un servidor de producción.

Después revisar:

grep 'wazuh-yara: ALERT - Match' /opt/ossec/logs/active-responses.log | tail -20

En el Manager:

grep '"10501"' /var/ossec/logs/alerts/alerts.json | tail

## Importante: latencia

El runtime espera como máximo unos segundos para que termine una escritura antes de ejecutar YARA. Esa espera no explica retrasos de minutos en la posterior integración de alertas.

Durante la validación de srv27 se confirmó que una coincidencia oficial puede llegar a la alerta 10501. Si se observa un retraso posterior entre el timestamp del evento y la creación/entrega del buffer de correo, ese tramo debe investigarse de forma independiente del escaneo YARA.

## Actualización de firmas

Para actualizar las firmas:

tools/orangebox-yara/install-orangebox-yara.sh

No editar ni agregar archivos .yar propios dentro del árbol del repositorio OrangeBox.

Para verificar exactamente qué versión quedó instalada:

cat /opt/ossec/active-response/bin/yara/rules/YARA-RULES-COMMIT
cat /opt/ossec/active-response/bin/yara/rules/YARA-RULES-REPOSITORY
cat /opt/ossec/active-response/bin/yara/rules/YARA-RULES-BRANCH

En agentes estándar, sustituir /opt/ossec por /var/ossec.

## Reinicio del agente

El instalador no reinicia Wazuh automáticamente.

Después de instalar o reemplazar el runtime:

systemctl restart wazuh-agent

Esto es especialmente importante cuando se modifica el Active Response: el proceso wazuh-execd debe recargar el comando instalado.


El runtime tiene una sola fuente de código: `tools/orangebox-yara/orangebox-yara.sh`. El instalador copia ese archivo y no mantiene otra implementación embebida.