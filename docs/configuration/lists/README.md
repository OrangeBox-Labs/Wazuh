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
srv27:cpanel
TU_HOSTNAME:cpanel
```

Se utiliza para las excepciones de WP Toolkit y para `cpanel_ssl_reissue`.

### `zimbra`

Perfil funcional compartido por Zimbra y Carbonio CE.

```text
/opt/zimbra
/opt/zextras
```

Hosts registrados actualmente para el perfil `zimbra`: ninguno en la CDB por ahora.

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