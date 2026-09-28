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
              |        +--> 20031, 20035 / level 0
              |
              +--> perfil Zimbra + comando Zimbra/Carbonio
              |        |
              |        +--> 110100 / level 0
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
Accepted publickey for root from 127.0.0.1
```

No modifica `10001` ni afecta logins exitosos desde otras IP, otros usuarios o otros métodos de autenticación.

La excepción `20008` se mantiene para el mensaje auxiliar `Accepted key ... found at ...`, que no representa una sesión autenticada completa.


## 10006 — Fuerza bruta SSH seguida de login exitoso

`10006` correlaciona un login SSH exitoso (`10001`) con la detección nativa `5763` de fuerza bruta, exigiendo la misma IP de origen y una ventana de 5 minutos. Es una detección de alta relevancia y puede activar `firewall-drop` según la configuración del Manager.

## 10008 — Movimiento lateral SSH

`10008` detecta tres logins SSH exitosos desde la misma IP de origen hacia ubicaciones/agentes diferentes dentro de 5 minutos.

Condiciones:

```text
10001
  + misma IP de origen
  + ubicación diferente
  + correlación global entre agentes
  + 3 eventos / 300 segundos
  = 10008
```

No tiene `firewall-drop`: una misma IP puede corresponder a un bastión, sistema administrativo u otra fuente legítima y la correlación requiere investigación.


## 10004 — SU a root

Detecta apertura de sesión `su` o `su-l` hacia `root` cuando el UID iniciador no es 0.

Un `su -> root` iniciado por UID 0 no se considera escalamiento porque el proceso ya era root. Esta condición evita falsos positivos de servicios automáticos observados en producción.

### 10613 — Reconocimiento seguido de sudo → root

`10613` requiere el evento actual `10005` y una coincidencia previa de `orangebox_recon` dentro de 600 segundos y en el mismo `location`. La frecuencia es `1`: no exige dos eventos de reconocimiento; exige un único reconocimiento previo y el `sudo → root` actual.

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

El perfil se resuelve mediante `configuration/manager/etc/lists/orangebox-agent-profiles`.

Ejemplo:

```text
servidor-cpanel:cpanel
servidor-cpanel.<grupo_cliente>.cl:cpanel
```

`20031` contiene comandos directos conocidos de WP Toolkit/cPanel.

Los wrappers `/bin/sh -c` se separan en reglas independientes para que cada operación tenga alcance exacto y no se pueda esconder un segundo comando dentro de un wrapper genérico.

### Contexto cPanel validado

Actualmente `20031` cubre los comandos directos conocidos de WP Toolkit y `20035` cubre únicamente wrappers `/bin/sh -c` con operaciones previamente validadas. No se acepta `COMMAND=.+` de forma genérica y se rechazan metacaracteres de shell.

Ambas excepciones requieren perfil `cpanel` y usuario `wp-toolkit`.

El ruleset debe documentar solamente los SIDs que existen realmente. Cuando una variante nueva de WP Toolkit sea validada, se agrega su regla correspondiente y se actualiza esta documentación.

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
mail.example.com:zimbra
zimbra.example.com:zimbra
mail2.example.com:zimbra
mail.example.com:zimbra
```

### 110100 — Comandos Zimbra/Carbonio autorizados

`110100` es hija de `10005` y exige:

1. hostname incluido en la CDB con perfil `zimbra`;
2. comando perteneciente a la allowlist histórica.

Los comandos cubiertos son `zmstat-fd` con argumentos, `postfix`, `postalias`, `qshape.pl`, `postconf` con argumentos, `postsuper`, `postcat`, `zmqstat`, `zmmtastatus` y `zmmailboxdmgr status`.

No se autoriza todo `/opt/zimbra` ni todo `/opt/zextras`.

### Por qué no usamos UID como whitelist de Zimbra

Los eventos reales mostraron que una sesión puede aparecer con identidades como `zimbra(uid=995)` y `soporte(uid=995)`.

El perfil identifica al endpoint y el comando identifica la operación. Esto es más robusto que confiar solo en UID o nombre de usuario.

## Excepciones que no requieren perfil

### BackupPC

`20001` consulta `etc/lists/orangebox-backuppc-static` y `20002` consulta `etc/lists/orangebox-backuppc-dynamic`. La lista estática contiene las IP autorizadas manualmente; la dinámica contiene la IP actual obtenida desde DNS.

Para agregar otro BackupPC estático, agregar una línea `<IP>:` a la CDB estática. La lista dinámica no se edita manualmente: la mantiene `update-orangebox-backuppc.sh`.

Ambas excepciones producen `level 0` y no alteran la alerta base `10001`.

### SFTP cliente-sftp

`20004` valida el usuario `cliente-sftp` y consulta las IP de origen en `etc/lists/orangebox-sftp-cliente-sftp`.

Para agregar otro origen autorizado, agregar una nueva línea `<IP>:` a la CDB y reiniciar el Manager. No se crea una regla adicional por cada IP.

### Reverse proxies

Las excepciones se separan por tipo de detección:

- `20024` + `etc/lists/orangebox-web-auth-proxies` para `10025`;
- `20026` + `etc/lists/orangebox-web-discovery-proxies` para `10026`.

Las listas son independientes porque el alcance validado puede ser distinto para cada detección.

Para agregar otro proxy, agregar su IP a la lista correspondiente y reiniciar el Manager. No crear una regla por cada proxy.

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
20031, 20035 = perfil cPanel / WP Toolkit
110100      = perfil Zimbra / Carbonio
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
- CDB `etc/lists/orangebox-backuppc-static`;
- CDB `etc/lists/orangebox-backuppc-dynamic`;
- CDB `etc/lists/orangebox-sftp-cliente-sftp`;
- CDB `etc/lists/orangebox-web-auth-proxies`;
- CDB `etc/lists/orangebox-web-discovery-proxies`;
- entrada de las CDB declarada en `manager/ossec.conf`;
- grupos Wazuh para distribuir configuración y etiquetas;
- integración `custom-orangebox-email.py` para el tratamiento posterior de las alertas.

Cuando se modifica una CDB, el Manager debe reiniciarse para cargar la lista actualizada.

### Convención al crear una excepción

Una IP adicional dentro de una excepción existente se agrega a la CDB correspondiente; no requiere un nuevo SID.

Cuando realmente se necesita una regla nueva, utilizar un ID libre dentro de `20000-29999` y comprobar que no exista en ningún otro archivo del ruleset. Nunca reutilizar ni duplicar un ID.