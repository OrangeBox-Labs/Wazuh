# `verify-deployed-config.sh`

## Objetivo

Compara los archivos funcionales del repositorio OrangeBox con la configuración realmente desplegada bajo `/var/ossec` en el Wazuh Manager.

El script es de solo lectura: **no modifica configuración**.

## Problema que resuelve

Permite detectar inmediatamente una divergencia entre:

```text
Git / repo
   vs
/var/ossec
```

Esto es especialmente importante después de modificar reglas, CDB lists o grupos de agentes.

## Archivos comprobados

- `configuration/manager/etc/ossec.conf` -> `/var/ossec/etc/ossec.conf`
- `configuration/manager/etc/shared/agent-template.conf` -> `/var/ossec/etc/shared/agent-template.conf`
- `configuration/manager/etc/shared/default/agent.conf` -> `/var/ossec/etc/shared/default/agent.conf`
- `configuration/manager/etc/shared/cpanel/agent.conf` -> `/var/ossec/etc/shared/cpanel/agent.conf`
- `configuration/manager/etc/shared/zimbra/agent.conf` -> `/var/ossec/etc/shared/zimbra/agent.conf`
- `configuration/manager/etc/lists/orangebox-agent-profiles` -> `/var/ossec/etc/lists/orangebox-agent-profiles`
- `configuration/manager/integrations/custom-orangebox-email.py` -> `/var/ossec/integrations/custom-orangebox-email.py`
- reglas `.xml` y `.yar` -> `/var/ossec/etc/rules/`

## Validaciones adicionales

Además de la comparación byte a byte, verifica:

- que `20100` exista exactamente una vez en el ruleset desplegado;
- que `10005` exista exactamente una vez;
- que estén presentes las entradas de perfil cPanel y Zimbra conocidas.

## Uso

Desde el checkout del repositorio en el Manager:

```bash
chmod +x tools/verify-deployed-config.sh
./tools/verify-deployed-config.sh
```

Un resultado `FAIL` muestra automáticamente el `diff -u` del archivo divergente.

## Regla operativa

Antes de reiniciar Wazuh después de un cambio importante:

```text
git pull
  ↓
verify-deployed-config.sh
  ↓
wazuh-logtest
  ↓
systemctl restart wazuh-manager
```

Después del reinicio, volver a ejecutar el script para confirmar que el Manager está ejecutando exactamente lo versionado.