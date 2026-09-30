# Active Response del Manager

El Manager define **cuándo** se ejecuta cada Active Response mediante sus reglas y comandos.

Los ejecutables pertenecen al agente y están versionados en:

```text
configuration/agent/active-response/bin/
-> /var/ossec/active-response/bin/
```

El instalador del agente genera directamente:

- `orangebox-yara.sh`
- `orangebox-quarantine.py`

No se deben copiar desde el Manager ni hacer rsync como parte de la instalación.

Si el mismo host del Manager también tiene un Wazuh Agent instalado y recibe Active Response con `location=local`, ese agente usa los mismos scripts que cualquier otro endpoint.

Los scripts personalizados deben quedar como `root:wazuh` y `0750`.
