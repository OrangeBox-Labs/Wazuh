# OrangeBox Behavior

Documentación de `orangebox-behavior.xml`.

## 10610 — Escáner

Detecta mediante auditd herramientas clasificadas como `scanner`. Es nivel 14 e inmediata y no aplica `firewall-drop` por sí sola.

## 10611 — Reconocimiento

Detecta mediante auditd comandos clasificados como `recon`. Es la señal base de las correlaciones 10612 y 10613.

## 10612 — Reconocimiento repetido

Requiere tres eventos 10611, comandos auditados diferentes y la misma `location` dentro de 5 minutos.

## 10613 — Reconocimiento seguido de sudo → root

Se activa cuando el evento actual es `10005` y existe una coincidencia previa de `10611` dentro de 10 minutos. No debe asumirse que auditd y journald entreguen la misma `location`; la correlación se apoya directamente en el SID `10611`.

## 10614 — Cadena de comportamiento

Correlaciona tres eventos del grupo `orangebox_behavior` dentro de 10 minutos y en la misma `location`. Es una correlación amplia y puede participar en correlaciones posteriores, por lo que cualquier cambio debe probar posibles cascadas.

## Relación con el alertamiento

Las reglas que deben generar correo inmediato utilizan la marca funcional `orangebox_immediate`. No se deben convertir estas correlaciones en reglas hijas directas de `10001`, `10004` o `10005` sin comprobar que los IDs base sigan llegando intactos a la integración de correo.

## Pruebas

Validar 10610, 10611, 10612, 10613 y 10614 por separado y comprobar que 10001/10005 conserven su comportamiento cuando no corresponde una correlación.


## 20055 — Excepción de Zimbra

Silencia la alerta `10610` solamente cuando el agente pertenece al grupo Wazuh `zimbra` y el evento auditd corresponde exactamente al chequeo interno de Zimbra:

```text
/usr/bin/nc -w 15 localhost 7171
CWD=/opt/zimbra
AUID/UID/GID=zimbra
```

La excepción está respaldada por la CDB dinámica `orangebox-zimbra-agents`. No se excluye `nc` de forma global: cualquier otro uso de `nc` mantiene la detección `10610`.
