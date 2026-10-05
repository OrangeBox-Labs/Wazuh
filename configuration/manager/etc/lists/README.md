# CDB y sincronización de agentes OrangeBox

Este directorio contiene listas CDB utilizadas directamente por las reglas del Wazuh Manager.

Las CDB se dividen en dos tipos:

- **estáticas**: se mantienen en el repositorio y se despliegan sin cambios;
- **dinámicas**: se generan desde grupos Wazuh y no deben editarse manualmente.

## CDB estáticas

### `orangebox-network-recon-programs`

Define los comandos que cuentan como reconocimiento de red para las correlaciones `10612` y `10614`.

Formato:

```text
comando:network_recon
```

Incluye solamente utilidades de consulta de red como `ip`, `ss`, `netstat`, `lsof`, `route`, `arp`, `ifconfig` y `nmcli`.

La lista debe estar declarada en el bloque `<ruleset>` de `manager/etc/ossec.conf`.

### `orangebox-sftp-authorized`

Contiene los orígenes autorizados para el SFTP del usuario `sftp-service`. La regla `20004` combina esta lista con la condición de usuario.

Formato:

```text
<IP>:
```

Agregar una IP nueva significa agregar una línea y recargar o reiniciar el Manager según el método de carga utilizado.

### `orangebox-web-auth-proxies`

Contiene los reverse proxies autorizados para la correlación `10025` de brute force web.

### `orangebox-web-discovery-proxies`

Contiene los reverse proxies autorizados para la correlación `10026` de reconocimiento de archivos sensibles.

Estas dos listas se mantienen separadas porque su alcance puede ser diferente.

### `orangebox-backuppc-static`

Contiene las IP de BackupPC autorizadas manualmente para la excepción SSH `20001`.

El updater dinámico de BackupPC no modifica esta lista.

### `orangebox-backuppc-dynamic`

Contiene la IP actual obtenida por el updater dinámico de BackupPC.

No editar esta lista manualmente salvo para recuperación controlada.

## CDB dinámicas por grupo Wazuh

La fuente de verdad es la pertenencia del agente al grupo Wazuh. El hostname no se mantiene manualmente en una segunda lista.

### `orangebox-cpanel-agents`

Representa el grupo Wazuh `cpanel`.

El sincronizador es:

```text
configuration/manager/bin/update-orangebox-cpanel-agents.sh
```

y su cron:

```text
configuration/manager/etc/cron.d/orangebox-cpanel-agents
```

Consulta `agent_groups -l -g cpanel`, genera hostname FQDN y hostname corto, normaliza FQDN sin punto final y actualiza la CDB solo cuando cambia.

### `orangebox-zimbra-agents`

Representa el grupo Wazuh `zimbra`.

Este perfil funcional cubre Zimbra y Carbonio CE:

```text
/opt/zimbra
/opt/zextras
```

El sincronizador es:

```text
configuration/manager/bin/update-orangebox-zimbra-agents.sh
```

y su cron:

```text
configuration/manager/etc/cron.d/orangebox-zimbra-agents
```

Consulta `agent_groups -l -g zimbra` y genera hostname FQDN y hostname corto.

Las reglas de autenticación usan esta CDB para reconocer el contexto Zimbra/Carbonio, pero el grupo por sí solo nunca autoriza `sudo -> root`: la regla también exige el comando operacional validado.

Las CDB dinámicas no deben editarse manualmente.

## Declaración en `ossec.conf`

Toda CDB usada por una regla debe estar declarada en el bloque `<ruleset>` de `/var/ossec/etc/ossec.conf`.

Ejemplos:

```xml
<list>etc/lists/orangebox-network-recon-programs</list>
<list>etc/lists/orangebox-cpanel-agents</list>
<list>etc/lists/orangebox-zimbra-agents</list>
```

Si una regla referencia una CDB no declarada o inexistente, `wazuh-analysisd -t` puede ignorar la regla y registrar el warning `(7616)`.

## Regla de seguridad

Una excepción operacional debe combinar contexto del endpoint con identidad y/o comando o condición exacta:

```text
grupo / contexto del endpoint
        +
usuario o identidad cuando corresponda
        +
comando o condición exacta
        =
excepción
```

No convertir una excepción puntual en una whitelist global de usuario, directorio o shell.

## Validación

Después de modificar reglas o CDB:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

Para validar la sincronización:

```bash
/var/ossec/bin/update-orangebox-cpanel-agents.sh
/var/ossec/bin/update-orangebox-zimbra-agents.sh
```

El verificador `tools/verify-deployed-config.sh` también compara las CDB dinámicas con la pertenencia real a los grupos Wazuh.

## IDs de reglas

Agregar una IP o agente a una CDB existente no requiere un nuevo SID. Cuando realmente haga falta una regla nueva, usar un ID libre del rango `20000-29999` y comprobar que no exista en otro XML.
