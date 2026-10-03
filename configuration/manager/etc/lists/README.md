# CDB de perfiles de agentes OrangeBox

Este directorio contiene listas CDB utilizadas directamente por las reglas del Wazuh Manager.

## CDB dinámicas por grupo Wazuh

Las excepciones de aplicaciones usan grupos Wazuh como fuente de verdad. No se mantiene una lista manual global de hostnames.

### `orangebox-cpanel-agents`

Representa el grupo Wazuh `cpanel`.

El sincronizador:

```text
configuration/manager/bin/update-orangebox-cpanel-agents.sh
```

genera la CDB a partir de:

```bash
/var/ossec/bin/agent_groups -l -g cpanel
```

Incluye hostname FQDN y hostname corto. No se edita manualmente.

### `orangebox-zimbra-agents`

Representa el grupo Wazuh `zimbra`.

El mismo perfil funcional se utiliza para Zimbra y Carbonio CE.

El sincronizador:

```text
configuration/manager/bin/update-orangebox-zimbra-agents.sh
```

genera la CDB a partir de:

```bash
/var/ossec/bin/agent_groups -l -g zimbra
```

Incluye hostname FQDN y hostname corto. No se edita manualmente.

Las reglas de autenticación exigen además el comando o contexto operacional validado; pertenecer al grupo por sí solo no autoriza `sudo -> root`.

### `orangebox-network-recon-programs`

CDB estática utilizada por las correlaciones `10612` y `10614`.

Formato:

```text
comando:network_recon
```

Incluye únicamente comandos de consulta de red definidos por OrangeBox.

La CDB debe estar declarada en el bloque `<ruleset>` de `configuration/manager/etc/ossec.conf`.

## Declaración y carga

Toda CDB usada por una regla debe estar declarada en `ossec.conf`.

Si una regla apunta a una CDB que no existe o no está declarada, `wazuh-analysisd -t` puede registrar el warning `(7616)` y omitir la regla.

Las CDB dinámicas son generadas por sus sincronizadores y no deben editarse manualmente.

## `orangebox-backuppc-static`

Contiene las IP de BackupPC autorizadas manualmente para la excepción SSH `20001`.

Formato:

```text
<IP>:
```

El updater dinámico no modifica esta lista.

## `orangebox-backuppc-dynamic`

Contiene la IP actual del hostname BackupPC administrado por `update-orangebox-backuppc.sh`. La lista se reemplaza completamente cuando cambia DNS.

Formato:

```text
<IP>:
```

No editar esta lista manualmente salvo para recuperación controlada.

## `orangebox-sftp-certcoopeuch`

Contiene los orígenes autorizados para el SFTP del usuario `certcoopeuch`. La regla `20004` combina esta lista con la condición de usuario.

Agregar una IP nueva significa agregar una línea `<IP>:` y reiniciar el Manager.

## `orangebox-web-auth-proxies`

Contiene los reverse proxies autorizados para la correlación `10025` de brute force web. La regla `20024` consulta esta lista.

## `orangebox-web-discovery-proxies`

Contiene los reverse proxies autorizados para la correlación `10026` de reconocimiento de archivos sensibles. La regla `20026` consulta esta lista.

Estas dos listas se mantienen separadas porque su alcance puede ser diferente. No se debe asumir que todos los proxies necesitan ambas excepciones.

## IDs de reglas

Agregar una IP a una CDB existente no requiere un nuevo SID. Cuando realmente haga falta una regla nueva, utilizar un ID libre del rango `20000-29999` y verificar que no exista en ningún otro archivo del ruleset.

## Sincronización

El grupo Wazuh distribuye `agent.conf` y etiquetas. La CDB es la condición evaluable por las reglas.

Por lo tanto, para un nuevo perfil se deben mantener sincronizados:

- grupo Wazuh;
- `agent.conf` del perfil;
- etiqueta `orangebox.profile`;
- entrada hostname -> perfil en esta CDB.

## Carga

La lista se declara en `manager/ossec.conf` como:

```xml
<list>etc/lists/orangebox-agent-profiles</list>
```

Wazuh compila y carga las CDB al iniciar el motor de análisis. Al modificar la lista hay que reiniciar el Manager.

## Validación

Con `wazuh-logtest` verificar como mínimo:

1. perfil correcto + comando permitido -> `level 0`;
2. hostname sin perfil + mismo comando -> `10005`;
3. perfil correcto + comando no permitido -> `10005`;
4. wrapper permitido + comando extra -> `10005`.