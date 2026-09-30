# Verificacion y reparacion de permisos de Wazuh

`verify-ossec-permissions.sh` revisa los dueños, grupos y permisos de las rutas operativas bajo `/var/ossec`.

Por defecto solo informa diferencias. No cambia nada.

## Uso

Revisión:

```bash
sudo ./tools/verify-ossec-permissions.sh
```

Reparación:

```bash
sudo ./tools/verify-ossec-permissions.sh --fix
```

También se puede indicar otra raíz:

```bash
sudo ./tools/verify-ossec-permissions.sh --path /var/ossec
```

## Criterios

- `etc/`: `root:wazuh`, directorios `0750` y archivos `0640`.
- `active-response/bin/`: `root:wazuh`, scripts `0750`.
- `integrations/`: `root:wazuh`, scripts `0750`.
- `logs/`, `queue/`, `stats/` y `var/`: `wazuh:wazuh`, directorios `0750` y archivos `0640`.
- `client.keys`, `authd.pass` y `sslmanager.key` se mantienen como archivos protegidos `0640`.
- `etc/orangebox-indexer.conf` debe quedar como `root:root` y `0600`; el reporte lo usa para consultar el indexador y puede contener credenciales.

El script no modifica `/var/lib/wazuh-indexer`. El indexador tiene su propio árbol, usuario y permisos y debe revisarse por separado.

## Por qué existe

Un `rsync` copia contenido y metadatos según sus opciones, pero no reemplaza una comprobación explícita de permisos. Esta herramienta permite detectar una desviación y, cuando corresponde, corregirla de forma controlada.

La idea es que la estructura del repositorio represente la estructura de `/var/ossec` y que los permisos esperados queden documentados y comprobables.
