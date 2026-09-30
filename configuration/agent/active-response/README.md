# Active Response del agente

Los archivos de este directorio forman parte del runtime del agente Wazuh.

La ruta relativa replica directamente `/var/ossec`:

```text
configuration/agent/active-response/bin/
-> /var/ossec/active-response/bin/
```

El instalador del agente **genera estos archivos directamente en el servidor**. No es necesario copiarlos ni hacer rsync después de instalar. La copia versionada aquí sirve para mantener la estructura del runtime, revisar cambios y documentar exactamente qué debe existir.

Los scripts personalizados deben quedar como `root:wazuh` y `0750`.

## Archivos

- `bin/orangebox-yara.sh`: analiza con YARA los archivos señalados por FIM.
- `bin/orangebox-quarantine.py`: pone en cuarentena archivos confirmados por la regla 99901.
