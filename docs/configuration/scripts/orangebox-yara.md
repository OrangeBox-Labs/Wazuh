# Integracion OrangeBox FIM -> YARA

## Objetivo

Conectar el FIM de Wazuh con las firmas YARA de OrangeBox sin ejecutar un scan completo del filesystem.

El flujo es:

```text
FIM 554/550
   ↓
10420/10421
   ↓
Active Response local
   ↓
orangebox-yara.sh
   ↓
YARA oficial
   ↓
/logs/active-responses.log
   ↓
decoder OrangeBox
   ↓
10501 Core / no existe en el despliegue actual Extended
```

Wazuh documenta este patrón: FIM detecta archivos nuevos/modificados, Active Response ejecuta YARA sobre el archivo afectado y el resultado vuelve al Manager mediante el log de Active Response. citeturn986130view0

## Alcance inicial

El disparador YARA está deliberadamente acotado a archivos con extensiones habituales de scripts/webshell y solo en las zonas que OrangeBox ya monitoriza en tiempo real:

- `/tmp`
- `/var/tmp`
- `/dev/shm`
- `/opt/zimbra/data/tmp`
- `/opt/zextras/data/tmp`

Esto evita disparar YARA sobre todos los eventos FIM.

Las firmas actuales del repositorio son principalmente de webshell JSP. La capa YARA se considera de mayor confianza y la YARA se considera heurística.

## Instalacion en agentes

El instalador soporta automáticamente:

- Wazuh estándar: `/var/ossec`
- RPM OrangeBox/cPanel: `/opt/ossec`

Desde el checkout del repositorio:

```bash
chmod +x configuration/scripts/install-orangebox-yara.sh
configuration/scripts/install-orangebox-yara.sh
```

Requisitos en el endpoint:

```bash
command -v jq
command -v yara
```

El script no instala paquetes ni modifica `ossec.conf`.

## Configuracion del Manager

El Manager declara el comando `orangebox-yara` y lo ejecuta localmente en el agente que generó el evento. El Active Response es stateless porque no hay una accion que revertir.

No se elimina ni pone en cuarentena ningun archivo.

## Prueba controlada

Primero validar la presencia de YARA y las reglas:

```bash
yara --version
yara -r /var/ossec/active-response/bin/yara/rules/orangebox-webshell-core.yar /ruta/de/prueba.jsp
```

En cPanel sustituir `/var/ossec` por `/opt/ossec`.

Para probar el trigger FIM sin utilizar malware real, crear un archivo de laboratorio con contenido que reproduzca una firma YARA conocida y usar una extension monitorizada.

No descargar muestras de malware reales en un servidor de produccion.

## Evidencia esperada

En el agente:

```bash
grep 'wazuh-yara' /var/ossec/logs/active-responses.log | tail
```

En el Manager:

```bash
grep '"10501"\|"no existe en el despliegue actual"' /var/ossec/logs/alerts/alerts.json | tail
```

Un match YARA debe producir una alerta `10501` y llegar al flujo de correo actual por ser nivel 14. Un match YARA debe producir `no existe en el despliegue actual`, pero no supera el umbral actual de la integración de correo (12).

## Seguridad

La primera fase es solamente deteccion. No hay Active Response destructivo asociado a `10501` ni `no existe en el despliegue actual`.

La contencion automatica se evaluara despues de medir falsos positivos sobre servidores cPanel, Zimbra/Carbonio y Linux generales.

## Compatibilidad con cPanel

El agente RPM OrangeBox utiliza `/opt/ossec`. El script deriva su Wazuh home desde su propia ubicacion, por lo que la misma implementacion funciona sin hard-codear `/var/ossec`.

## Mantenimiento

Las reglas YARA YARA oficial se mantienen bajo:

```text
configuration/rules/
```

No agregar reglas heuristicas directamente al indice sin decidir primero si son YARA o YARA.
