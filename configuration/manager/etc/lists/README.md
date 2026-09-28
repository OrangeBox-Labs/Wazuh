# CDB de perfiles de agentes OrangeBox

Este directorio contiene listas CDB utilizadas directamente por las reglas del Wazuh Manager.

## `orangebox-agent-profiles`

Relaciona el hostname predecodificado del evento con el perfil funcional del agente.

Formato:

```text
hostname_del_evento:perfil
```

La clave debe corresponder al valor que Wazuh muestra en Phase 1 de `wazuh-logtest` como `hostname`.

Una misma máquina puede necesitar hostname corto y FQDN cuando ambas representaciones aparecen en producción.

## Perfiles actuales

### `cpanel`

cPanel / WHM / WP Toolkit.

```text
servidor-cpanel:cpanel
servidor-cpanel.example.com:cpanel
```

Se utiliza para las excepciones de WP Toolkit y para `cpanel_ssl_reissue`.

### `zimbra`

Perfil funcional compartido por Zimbra y Carbonio CE.

```text
/opt/zimbra
/opt/zextras
```

La CDB utiliza entradas `hostname:perfil`; la versión pública mantiene un ejemplo genérico y la implementación privada registra los hostnames reales.

Un servidor Carbonio nuevo debe registrarse como `<hostname-observado>:zimbra` después de validar sus eventos reales.

## Formato del archivo CDB

`orangebox-agent-profiles` se mantiene como un archivo de datos puro con líneas `key:value`. La documentación, comentarios y justificación de cada perfil permanecen en este `README.md` para no introducir sintaxis ajena al formato de la CDB.

## Regla de seguridad

El perfil nunca debe ser la única condición de autorización. La arquitectura debe ser:

```text
perfil
+
usuario/identidad cuando corresponda
+
comando o condición exacta
=
excepción
```

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