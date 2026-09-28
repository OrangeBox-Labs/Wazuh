# Actualizacion dinamica de la whitelist BackupPC

El script `update-orangebox-backuppc.sh` mantiene la CDB utilizada por la regla `20001`.

## Comportamiento

- Resuelve el FQDN configurado.
- Exige que exista **exactamente una IPv4**.
- Reemplaza completamente la CDB con la IP actual.
- No conserva IPs historicas.
- Si DNS devuelve cero o mas de una IP, aborta sin modificar la whitelist.
- Reinicia Wazuh solo cuando la whitelist cambia.

Configure el FQDN real en:

```bash
HOSTNAME="TU_HOSTNAME"
```

En una implementacion real, reemplace `TU_HOSTNAME` por el FQDN del servidor BackupPC autorizado.
