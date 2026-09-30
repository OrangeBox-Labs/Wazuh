# Active Response

La configuracion del Manager define cuando se ejecuta cada Active Response. El runtime de los scripts vive en `configuration/agent/active-response/`.

Al desplegar el árbol correspondiente, deben terminar en:

```text
/var/ossec/active-response/bin/
```

Los scripts personalizados se despliegan en los agentes y deben quedar como `root:wazuh` y `0750`.

`tools/` no contiene estos ejecutables. Allí quedan solo herramientas de instalación, revisión y mantenimiento.
