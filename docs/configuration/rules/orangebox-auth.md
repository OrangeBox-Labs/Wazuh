# OrangeBox Auth

Documentación de `orangebox-auth.xml`.

## Propósito

Este archivo contiene las detecciones OrangeBox relacionadas con autenticación y escalamiento:

- login SSH exitoso;
- `su` a `root`;
- `sudo` hacia `root`;
- brute force SSH seguido de login exitoso;
- ráfagas de fallos SSH desde redes internas.

La regla de `sudo -> root` es el punto de entrada común para las whitelists funcionales.

## Arquitectura de SUDO

```text
evento sudo
    |
    v
5400 / sudo
    |
    +--> 10005 / USER=root
              |
              +--> perfil cPanel + comando WP Toolkit
              |        |
              |        +--> 20031, 20035..20052 / level 0
              |
              +--> perfil Zimbra + comando Zimbra/Carbonio
              |        |
              |        +--> 20110 / level 0
              |
              +--> sin excepción válida
                       |
                       +--> 10005 / level 13
```

### Por qué 10005 depende de 5400

Las reglas nativas `5402` y `5403` son ramas hermanas bajo `5400`. La rama `5403` puede aparecer en el primer uso de sudo por FTS.

Por eso `10005` se engancha a `5400` y exige `USER=root`.

### Cambio respecto de la política anterior

Antes, `10005` contenía directamente la whitelist de Zimbra/Carbonio mediante una expresión negativa.

Ahora `10005` es solamente el detector común. Las excepciones operacionales son reglas hijas de nivel 0 condicionadas por perfil CDB.

Esto impide que una operación legítima de una aplicación quede globalmente autorizada en otros tipos de servidores.

## 10001 — Login SSH exitoso

Parte de `5715` y eleva a nivel 13 los logins SSH exitosos.

La excepción `20010` es hija directa de `10001` y silencia únicamente el evento local:

```text
Accepted publickey for root from IP_DE_SERVIDOR
```

No modifica `10001` ni afecta logins exitosos desde otras IP, otros usuarios o otros métodos de autenticación.

La excepción `20008` se mantiene para el mensaje auxiliar `Accepted key ... found at ...`, que no representa una sesión autenticada completa.

## 10004 — SU a root

Detecta apertura de sesión `su` o `su-l` hacia `root` cuando el UID iniciador no es 0.

Un `su -> root` iniciado por UID 0 no se considera escalamiento porque el proceso ya era root. Esta condición evita falsos positivos de servicios automáticos observados en producción.

## 10005 — SUDO hacia root

`10005` detecta cualquier `sudo` con destino `root` que no termine en una excepción posterior válida.

Condiciones:

```text
sudo
+
USER=root
+
sin excepción de perfil/comando
=
alerta 10005
```

No se utiliza UID o proceso como único mecanismo de confianza.

## Perfil cPanel — WP Toolkit

El perfil se resuelve mediante `configuration/lists/orangebox-agent-profiles`.

Ejemplo:

```text
srv27:cpanel
TU_HOSTNAME:cpanel
```

`20031` contiene comandos directos conocidos de WP Toolkit/cPanel.

Los wrappers `/bin/sh -c` se separan en reglas independientes para que cada operación tenga alcance exacto y no se pueda esconder un segundo comando dentro de un wrapper genérico.

### Wrappers cPanel validados

| Regla | Operación |
|---|---|
| 20035 | `cat >` para temporal de logrotate |
| 20036 | `mv` para reemplazo de logrotate |
| 20037 | `readlink /usr/local/cpanel/server.type` |
| 20038 | `cagefsctl --cagefs-status` |
| 20039 | POST local a `check-plesk.php` |
| 20044 | `package_manager_get_package_info` |
| 20045 | `get_domain_info` |
| 20046 | `listaccts` |
| 20047 | `get_users_features_settings` |
| 20048 | UAPI `DomainInfo single_domain_data` |
| 20049 | UAPI `Mime list_redirects` |
| 20050 | `get_shared_ip` |
| 20051 | `get_public_ip` |
| 20052 | `get_tweaksetting key=server_locale` |
| 20053 | cPanel API 2 `Locale get_user_locale` |

Todos requieren perfil `cpanel` y usuario `wp-toolkit`.

Los argumentos variables solo se aceptan cuando son necesarios para la operación observada y se restringen mediante expresiones concretas.

### Por qué no existe un wrapper cPanel genérico

No se acepta simplemente `perfil cpanel + wp-toolkit + /bin/sh -c`.

Un wrapper genérico convertiría la whitelist en una puerta para ejecutar comandos arbitrarios.

## Perfil Zimbra / Carbonio CE

Zimbra y Carbonio CE utilizan un único perfil funcional: `zimbra`.

Los árboles reconocidos son:

```text
/opt/zimbra
/opt/zextras
```

Hosts actualmente registrados en la CDB:

```text
TU_HOSTNAME:zimbra
TU_HOSTNAME:zimbra
TU_HOSTNAME:zimbra
mail.appnexit.cl:zimbra
```

### 20110 — Comandos Zimbra/Carbonio autorizados

`20110` es hija de `10005` y exige:

1. hostname incluido en la CDB con perfil `zimbra`;
2. comando perteneciente a la allowlist histórica.

Los comandos cubiertos son `zmstat-fd` con argumentos, `postfix`, `postalias`, `qshape.pl`, `postconf` con argumentos, `postsuper`, `postcat`, `zmqstat`, `zmmtastatus` y `zmmailboxdmgr status`.

No se autoriza todo `/opt/zimbra` ni todo `/opt/zextras`.

### Por qué no usamos UID como whitelist de Zimbra

Los eventos reales mostraron que una sesión puede aparecer con identidades como `zimbra(uid=995)` y `soporte(uid=995)`.

El perfil identifica al endpoint y el comando identifica la operación. Esto es más robusto que confiar solo en UID o nombre de usuario.

## Excepciones que no requieren perfil

### BackupPC

`20001`, `20002`, `20003` y `20006` dependen de `srcip` porque identifican al sistema autorizado como origen del SSH.

### SFTP certcoopeuch

`20004` y `20005` dependen de IP de origen + usuario. Tampoco representan un perfil del agente receptor.

### Reverse proxies

`20024` a `20028` dependen de IP de origen porque el backend puede registrar la IP del proxy.

### systemd-user

`20007` es una excepción de comportamiento genérico para sesiones PAM creadas por `systemd-user`.

### mysql

`20009` es una excepción específica para la sesión automática hacia `mysql` iniciada por UID 0.

## Convención de IDs

```text
10000-19999 = detecciones y correlaciones
20000-29999 = excepciones y whitelists
```

Dentro de este archivo:

```text
20001-20009 = excepciones genéricas de autenticación
20031-20053 = perfil cPanel / WP Toolkit
20110       = perfil Zimbra / Carbonio
```

Los huecos numéricos corresponden a IDs utilizados por otros archivos del ruleset.

## Matriz de pruebas obligatoria

```text
perfil + comando permitido
    -> regla level 0

otro hostname + mismo comando
    -> 10005 / level 13

perfil + comando no permitido
    -> 10005 / level 13

perfil + wrapper permitido + comando extra
    -> 10005 / level 13
```

Cada nuevo wrapper debe probarse también con una variante que agregue `;`, `&&`, un segundo comando o una shell posterior.

## Dependencias

- reglas nativas de Wazuh para SSH, PAM y sudo;
- CDB `etc/lists/orangebox-agent-profiles`;
- entrada de la CDB declarada en `manager/ossec.conf`;
- grupos Wazuh para distribuir configuración y etiquetas;
- integración `custom-orangebox-email.py` para el tratamiento posterior de las alertas.

Cuando se modifica una CDB, el Manager debe reiniciarse para cargar la lista actualizada.