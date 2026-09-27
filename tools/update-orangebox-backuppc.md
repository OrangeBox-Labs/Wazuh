# Actualizacion dinamica de whitelist BackupPC

Mantiene la CDB `/var/ossec/etc/lists/orangebox-backuppc` sincronizada con la IP
actual de `vizcachas.orangebox.cl`.

La regla `20001` de `orangebox-auth.xml` utiliza esta CDB para exceptuar
los logins SSH legitimos del servidor BackupPC sin depender de una IP fija.

## Comportamiento

- Resuelve IPv4 mediante `getent ahostsv4`.
- Si DNS no responde, termina con error y **no modifica la CDB**.
- Si la IP no cambió, no hace nada.
- Si cambió, actualiza la CDB y reinicia `wazuh-manager` para que Wazuh
  vuelva a compilar/cargar la CDB.
- Usa `flock` para evitar ejecuciones simultaneas.
- Soporta multiples registros IPv4 si DNS los entrega.

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

La CDB debe estar declarada en `ossec.conf` y referenciada por la regla
de BackupPC.
