# Active Response

Los scripts de este directorio forman parte del runtime de Wazuh.

Al desplegar el árbol correspondiente, deben terminar en:

```text
/var/ossec/active-response/bin/
```

Los scripts personalizados deben quedar como `root:wazuh` y `0750`.

## Archivos

- `bin/orangebox-yara.sh`: detecta coincidencias YARA sobre archivos señalados por FIM.
- `bin/orangebox-quarantine.py`: pone en cuarentena archivos confirmados por la regla 99901.

`tools/` no contiene estos ejecutables. Allí quedan solo herramientas de instalación, revisión y mantenimiento.
