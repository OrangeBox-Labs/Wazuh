# Actualizador de listas IOC

El actualizador operativo es **un solo script**:

- Repositorio: `configuration/manager/bin/update-orangebox-ioc-lists.sh`
- Producción: `/var/ossec/bin/update-orangebox-ioc-lists.sh`

No hay wrapper, V2 ni parser Python externo. La descarga autenticada de URLhaus, el análisis de su CSV, las validaciones, la actualización de CDB y la configuración de la Auth-Key están dentro del mismo script.

## Configurar la Auth-Key abuse.ch

URLhaus y MalwareBazaar utilizan la Auth-Key personal de abuse.ch. No guardar la clave en Git ni en comandos que queden en el historial.

Con el script desplegado, ejecutar como root:

```bash
/var/ossec/bin/update-orangebox-ioc-lists.sh --configure-key
```

La entrada se solicita dos veces sin eco. La clave se guarda en `/etc/orangebox-ioc-secrets`, propietario `root:root`, modo `0600`. El archivo contiene las variables `URLHAUS_AUTH_KEY` y `MB_AUTH_KEY`. El modo de configuración no descarga datos, no modifica listas ni reinicia Wazuh.

El script desactiva xtrace al inicio, antes de leer credenciales. **No ejecutar con `bash -x`**.

## Fuentes y semántica

Las listas tienen funciones distintas y no se deben mezclar:

- **`malicious-ip`**: CDB activa de IOC de **IP de origen**, construida como unión de Emerging Threats y la lista curada `orangebox-confirmed-source-ip`. Las reglas nativas Wazuh `99905/99906` y las reglas OrangeBox existentes siguen consultando esta misma CDB.
- **`orangebox-confirmed-source-ip`**: lista de IP de origen confirmadas por OrangeBox. Se mantiene separada del feed automático y no la modifica el actualizador. El despliegue combina la semilla versionada con las entradas locales existentes, sin eliminar entradas locales.
- **`malware-host-ip`**: IP extraídas de URLs recientes de URLhaus. Identifican infraestructura que aloja malware; no prueban que esa IP sea atacante de origen. Se conservan separadas y no se usan para bloquear `srcip`.
- **`malicious-domains`**: dominios de URLhaus.
- **`malware-hashes`**: SHA-256 recientes de MalwareBazaar.

URLhaus se descarga desde sus exportaciones V2 autenticadas `recent.csv` y `hostfile.txt`. El encabezado `id,dateadded,url,...` del CSV puede venir como línea comentada después de un preámbulo; el parser identifica y conserva esa cabecera antes de procesar la columna `url`. Si no encuentra una cabecera reconocible, aborta sin modificar CDB. Solo extrae hosts IPv4 globales. Las IP de hosting URLhaus no se mezclan con IOC de IP de origen.

### IOC de origen confirmados OrangeBox

La lista fuente se mantiene en:

- Repositorio: `configuration/manager/etc/lists/malicious-ioc/orangebox-confirmed-source-ip`
- Manager: `/var/ossec/etc/lists/malicious-ioc/orangebox-confirmed-source-ip`

El repositorio público no incluye IOC de origen reales. La lista comienza vacía y el operador agrega localmente solo direcciones confirmadas. Una lista comentada o sin direcciones es válida; Emerging Threats continúa aportando IOC de origen. La lista acepta una IPv4 por línea en formato CDB `IP:`; admite líneas vacías y comentarios. El actualizador valida el archivo y genera `malicious-ip` como unión de Emerging Threats + OrangeBox confirmadas. De esta forma se conserva la correlación nativa `99905/99906` y su Active Response de 7/30 días, sin mezclar las IP de hosting de URLhaus. El archivo debe pertenecer a `root` y no ser escribible por grupo u otros; el despliegue lo instala como `root:<grupo-del-manager>` con modo `0640`.

Agregar o retirar IOC confirmados requiere editar la lista curada y ejecutar el actualizador para reconstruir `malicious-ip`. Los cambios locales existentes se preservan durante despliegues. En el repositorio público la semilla está vacía. Las IOC confirmadas del entorno se administran únicamente en el servidor y no se publican. Las entradas no expiran automáticamente; requieren revisión y retirada explícita.

## Política de contención

La política del Manager aplica al origen de los eventos:

- reglas IOC de origen OrangeBox `10460`–`10463` y regla nativa web `99905`: bloqueo inmediato durante 7 días;
- regla nativa web `99906` (ataque desde IOC que obtuvo HTTP 200): bloqueo durante 30 días.

Las detecciones de dominio (IOC de destino) no deben disparar `firewall-drop` sobre `srcip`.

## Seguridad y validación

El script descarga las fuentes a un directorio temporal privado, valida formatos, compara conteos y cambios, rechaza caídas inesperadas y solo instala listas distintas.

### Revisar sin modificar listas

La primera separación de IP de hosting URLhaus de IOC de origen puede reducir considerablemente `malicious-ip`. Requiere revisión y aprobación manual una sola vez. El marcador persistente es:

```text
/var/ossec/var/.orangebox-ioc-source-ip-separated
```

Primero ejecutar:

```bash
ORANGEBOX_IOC_DRY_RUN=1 /var/ossec/bin/update-orangebox-ioc-lists.sh
```

El modo `DRY_RUN` descarga y valida las fuentes, muestra `previous/new/added/removed`, pero no modifica CDB, no crea el marcador ni reinicia Wazuh.

Solo después de revisar los conteos y aprobar explícitamente la reclasificación, ejecutar una vez:

```bash
ORANGEBOX_IOC_ALLOW_SOURCE_RECLASSIFICATION=1 /var/ossec/bin/update-orangebox-ioc-lists.sh
```

La aprobación solo se acepta mientras el marcador no exista y la ejecución haya superado todas las validaciones. El marcador se crea tras la actualización exitosa. No utilizar esa variable en cron ni en ejecuciones periódicas.

## Reinicio de Wazuh

- Si ninguna lista cambia, no se reinicia `wazuh-manager`.
- Si cambia una o más listas, se instalan y se reinicia `wazuh-manager` para recargar las CDB.

## Despliegue

`tools/deploy-ioc-active-response.sh` instala un único updater en `/var/ossec/bin/update-orangebox-ioc-lists.sh`. También elimina del destino los restos de despliegues anteriores (`update-orangebox-ioc-lists-v2.sh` y `parse_urlhaus_recent.py`), guardándolos en el backup del despliegue para permitir rollback.

El despliegue no actualiza las listas IOC. La primera reclasificación sigue siendo una operación independiente, con DRY_RUN y aprobación revisada.
