# Chequeo simple de salud OrangeBox

`check-orangebox-wazuh.sh` revisa el estado básico del stack sin modificar nada.

## Qué revisa

- `wazuh-manager`
- `wazuh-integratord`
- `postfix`
- `wazuh-indexer`, si está instalado localmente
- existencia de `alerts.json`
- existencia y método de entrega de `custom-orangebox-email.py`
- `jsonout_output=yes`
- `alerts_log=no`
- `log_alert_level=5`
- `email_log_source=alerts.json`
- espacio usado en `/var`
- tamaño básico de la cola de Postfix

## Códigos de salida

```text
0 = OK
1 = advertencia
2 = problema crítico
```

## Instalación

Copiar el script como `/usr/local/sbin/check-orangebox-wazuh.sh` y dejarlo ejecutable:

```bash
chmod 0750 /usr/local/sbin/check-orangebox-wazuh.sh
```

## Uso

```bash
/usr/local/sbin/check-orangebox-wazuh.sh
```

El script no reinicia servicios, no cambia reglas y no corrige automáticamente problemas. Está pensado para ejecutarse manualmente, desde cron o desde una herramienta de monitoreo.

## Motivo

La plataforma de seguridad también necesita una comprobación sencilla de salud. El objetivo es detectar rápidamente un Manager detenido, un integrador caído, Postfix inactivo, configuración crítica desviada o falta de espacio, sin convertir el monitor en otro sistema complejo.
