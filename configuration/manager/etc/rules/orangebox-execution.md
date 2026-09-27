# Ejecución desde directorios temporales delicados

Esta detección usa auditd para identificar ejecuciones reales desde `/tmp`, `/var/tmp` y `/dev/shm`.

## Reglas

- `10600`: ejecución desde una zona temporal delicada.
- `10601`: ejecución de un intérprete desde una zona temporal delicada.

## Instalación

El agente debe tener auditd instalado y el script `install-orangebox-exec-audit.sh` debe cargar las reglas de auditd y configurar la lectura de `/var/log/audit/audit.log` por Wazuh.

Wazuh documenta el uso de `<log_format>audit</log_format>` para procesar `audit.log` y el uso de claves en las reglas de auditd para identificar eventos. citeturn876646search1turn876646search0

## Prueba controlada

En el agente:

```bash
systemctl is-active auditd
auditctl -l | grep orangebox_exec
cat > /tmp/orangebox-audit-test <<'EOF'
#!/bin/sh
echo 'orangebox audit test'
EOF
chmod 700 /tmp/orangebox-audit-test
/tmp/orangebox-audit-test
ausearch -k orangebox_exec -ts recent -i | tail -40
rm -f /tmp/orangebox-audit-test
```

En el Manager, después de la ejecución:

```bash
grep -a '"id":"10600"\|"id":"10601"' /var/ossec/logs/alerts/alerts.json | tail -5
```

El resultado esperado es una alerta `10600`; si el campo decodificado permite identificar el intérprete, también debe aparecer `10601`.

## Política

La detección no bloquea ni elimina nada. Primero identifica la ejecución y registra evidencia. La contención se mantiene separada para evitar acciones destructivas por un evento que puede ser legítimo.

## Motivo

FIM permite detectar que apareció o cambió un archivo. auditd agrega una pieza distinta: confirma que ese archivo fue ejecutado. Las dos señales se complementan.