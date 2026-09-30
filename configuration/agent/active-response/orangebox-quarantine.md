# Cuarentena OrangeBox

`bin/orangebox-quarantine.py` es un Active Response del agente.

Se ejecuta para la regla `99901`, conserva el archivo, valida el SHA-256 de origen y de la copia y elimina el original solo después de comprobar que la cuarentena es correcta.

Runtime:

```text
configuration/agent/active-response/bin/orangebox-quarantine.py
-> /var/ossec/active-response/bin/orangebox-quarantine.py
```

Permisos esperados: `root:wazuh`, `0750`.
