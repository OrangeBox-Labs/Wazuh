# OrangeBox Behavior

Documentación de `orangebox-behavior.xml`.

## 10610 — Escáner
Detecta mediante auditd herramientas clasificadas como `scanner`. Es nivel 14 e inmediata y no aplica `firewall-drop` por sí sola.

## 10611 — Reconocimiento
Detecta mediante auditd comandos clasificados como `recon`. Es la señal base de las correlaciones 10612 y 10613.

## 10612 — Reconocimiento repetido
Requiere tres eventos 10611, comandos auditados diferentes y la misma `location` dentro de 5 minutos.

## 10613 — Reconocimiento seguido de sudo → root
Requiere dos coincidencias previas de 10611 dentro de 10 minutos y que el evento actual sea 10005. No usa `same_location`: auditd y journald pueden entregar ubicaciones diferentes. La correlación usa directamente el SID 10611. Al disparar, 10613 es la alerta final del evento sudo y escala a nivel 15.

## 10614 — Cadena de comportamiento
Correlaciona tres eventos del grupo `orangebox_behavior` dentro de 10 minutos y en la misma `location`. Es una correlación amplia y también pertenece al mismo grupo, por lo que puede participar en correlaciones posteriores. Cualquier cambio requiere probar posibles cascadas.

## Pruebas
Validar 10610, 10611, 10612, 10613 y 10614 por separado y comprobar que 10001/10005 conserven su comportamiento cuando no corresponde una correlación.
