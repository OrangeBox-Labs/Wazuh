# Perfil cPanel

Este perfil identifica agentes que ejecutan cPanel/WHM.

## Objetivo

La etiqueta `orangebox.profile=cpanel` permite reconocer el perfil funcional del agente en las alertas.

La supresión de falsos positivos del SUDO de WP Toolkit no depende únicamente de esta etiqueta: las reglas del Manager utilizan la CDB `orangebox-agent-profiles`, porque las reglas deben disponer de una condición evaluable durante el análisis del evento.

## Asignación

El agente debe pertenecer al grupo Wazuh `cpanel` y su hostname debe estar registrado en:

```text
configuration/lists/orangebox-agent-profiles
```

Ejemplo:

```text
TU_HOSTNAME:cpanel
```

La pertenencia al grupo y la entrada CDB deben mantenerse sincronizadas.


## Reglas asociadas

El perfil `cpanel` se consume desde las reglas del Manager mediante la CDB `orangebox-agent-profiles`.

Actualmente condiciona:

- `20031`: comandos directos de WP Toolkit;
- `20035`: contexto operacional validado de WP Toolkit;
- `20032`: regeneración esperada de `cpanel_ssl_reissue` en hardening.

No existe una whitelist genérica de `/bin/sh -c`. Cada wrapper se valida por operación completa para impedir que una excepción legítima sea reutilizada para ejecutar un segundo comando.

## Validación del perfil

```text
cpanel + comando permitido       -> level 0
otro perfil + mismo comando      -> 10005
cpanel + comando no permitido    -> 10005
cpanel + wrapper + comando extra -> 10005
```