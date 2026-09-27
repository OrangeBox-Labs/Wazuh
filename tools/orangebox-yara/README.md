# Instalador OrangeBox FIM -> YARA

Este directorio contiene únicamente el instalador de la integración.

Las firmas YARA no se almacenan aquí ni en configuration/. El instalador descarga exclusivamente el ruleset oficial de:

https://github.com/Yara-Rules/rules

Uso:

chmod +x tools/orangebox-yara/install-orangebox-yara.sh
tools/orangebox-yara/install-orangebox-yara.sh

El instalador detecta /opt/ossec y /var/ossec, valida los índices oficiales antes de instalarlos y registra el commit del ruleset.

La arquitectura y el procedimiento de prueba están documentados en docs/yara-fim.md.
