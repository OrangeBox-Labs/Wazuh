# Decoder YARA OrangeBox

## Objetivo

Convierte la salida de orangebox-yara.sh en campos que Wazuh puede usar en reglas.

## Formato esperado

El script genera una línea con esta estructura:

    wazuh-yara: ALERT - Match: category=<categoria> rule=<regla> path=<ruta>

El decoder extrae yara_category, yara_rule y yara_scanned_file.

## Motivo

Separar el texto de YARA en campos permite que las reglas trabajen con cada dato sin depender de una cadena completa.

## Validación

Probar con wazuh-logtest usando una línea real generada por el script y comprobar que los tres campos aparecen en Phase 2.
