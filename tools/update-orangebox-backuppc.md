# Actualizacion dinamica de la whitelist BackupPC

El script `update-orangebox-backuppc.sh` mantiene exclusivamente la CDB dinamica utilizada por la excepcion BackupPC.

## Listas

### Lista estatica

`/var/ossec/etc/lists/orangebox-backuppc-static`

Contiene las IP autorizadas manualmente. **El updater nunca modifica esta lista.**

### Lista dinamica

`/var/ossec/etc/lists/orangebox-backuppc-dynamic`

Contiene la IP actual obtenida desde DNS para `vizcachas.orangebox.cl`.

Cuando DNS cambia, el script reemplaza completamente esta lista por la nueva IP. No conserva IPs dinamicas historicas.

## Comportamiento

- Resuelve IPv4 mediante `getent ahostsv4`.
- Exige exactamente una IPv4.
- Si DNS no responde o devuelve mas de una IP, termina con error y no modifica la lista dinamica.
- Si la IP no cambio, no hace nada.
- Si la IP cambio, reemplaza atomicamente la lista dinamica y reinicia `wazuh-manager`.
- La lista estatica permanece intacta en todos los casos.
- Usa `flock` para evitar ejecuciones simultaneas.

## Instalacion

Copiar como:

```
/usr/local/sbin/update-orangebox-backuppc.sh
```

y dejarlo ejecutable:

```
chmod 0750 /usr/local/sbin/update-orangebox-backuppc.sh
```

## Cron

Cada 5 minutos:

```
*/5 * * * * /usr/local/sbin/update-orangebox-backuppc.sh >/dev/null 2>&1
```

Ambas CDB deben estar declaradas en `ossec.conf`.


El repositorio privado mantiene la entrada dinámica actualmente conocida; el updater puede reemplazarla cuando DNS cambie. La lista estática permanece administrada manualmente.