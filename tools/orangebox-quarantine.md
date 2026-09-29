# Cuarentena OrangeBox

## Objetivo

Mover a cuarentena un archivo que Wazuh confirmó como malware mediante la regla 99901.

## Seguridad

El script solo acepta la regla 99901, exige ruta y SHA-256, rechaza enlaces simbólicos, vuelve a calcular el hash antes de copiar y verifica el hash de la copia.

La copia queda bajo /var/ossec/quarantine/<sha256>/ con metadatos. El original se elimina solo después de validar la copia y la identidad del archivo.

Si una comprobación falla, el archivo original se conserva.

## Motivo

La cuarentena debe priorizar la conservación de evidencia. No basta con copiar el archivo: hay que demostrar que la copia es exactamente la que disparó la alerta.

## Prueba

Usar un archivo de laboratorio asociado a la regla 99901. Nunca probar sobre un archivo real sin autorización.
