# Perfil Zimbra / Carbonio CE

Este perfil agrupa funcionalmente los servidores **Zimbra** y **Carbonio CE** que comparten la politica OrangeBox de `sudo -> root`.

## Objetivo

La etiqueta:

```text
orangebox.profile=zimbra
```

permite identificar el perfil funcional del agente.

La whitelist de `sudo` no depende solamente de esta etiqueta. Las reglas del Manager utilizan la CDB:

```text
configuration/lists/orangebox-agent-profiles
```

con el formato:

```text
hostname:perfil
```

## Por qué el perfil se llama `zimbra`

OrangeBox trata Zimbra y Carbonio CE como una **familia operacional de servidor de correo** para esta politica concreta.

Los árboles de instalación son distintos:

```text
Zimbra     -> /opt/zimbra
Carbonio   -> /opt/zextras
```

La regla `110100 reconoce ambas rutas, pero solamente cuando el hostname pertenece al perfil `zimbra`.

## Comandos autorizados

La politica se basa en la allowlist historicamente validada en `orangebox-auth.xml`.

- `zmstat-fd`, con argumentos;
- `postfix`;
- `postalias`;
- `qshape.pl`;
- `postconf`, con argumentos;
- `postsuper`;
- `postcat`;
- `zmqstat`;
- `zmmtastatus`;
- `zmmailboxdmgr status`.

No se autoriza todo `/opt/zimbra` ni todo `/opt/zextras`.

## Seguridad

El mecanismo tiene tres capas:

```text
sudo -> root
   |
   v
10005
   |
   +-- hostname con perfil zimbra
   |       +
   |      comando autorizado
   |          |
   |          v
   |       20110 / level 0
   |
   +-- cualquier otra combinacion
           |
           v
        alerta 10005
```

La ventaja es que un comando que puede ser legítimo en un servidor Zimbra/Carbonio no queda globalmente autorizado en los demás agentes.

## Asignación

1. Agregar el hostname real del evento a `orangebox-agent-profiles`.
2. Asignar el agente al grupo Wazuh `zimbra`.
3. Distribuir este `agent.conf`.
4. Reiniciar el Manager despues de modificar la CDB.

Ejemplo:

```text
zimbra03.example.invalid:zimbra
zimbra05.example.invalid:zimbra
mail2.CLIENTE_05.cl:zimbra
mail.appCLIENTE_04.cl:zimbra
```

## Carbonio CE

Para un servidor Carbonio, registrar el hostname observado en los eventos y utilizar el mismo perfil:

```text
<hostname>:zimbra
```

Esto permite reutilizar la misma regla `110100 sin duplicar una segunda familia de reglas.

## Validacion

Antes de usar el perfil en producción, probar como minimo:

- un comando autorizado en un hostname con perfil `zimbra` -> `110100, nivel 0;
- el mismo comando en un hostname sin perfil -> `10005`, nivel 13;
- un comando no autorizado en un hostname con perfil -> `10005`, nivel 13.