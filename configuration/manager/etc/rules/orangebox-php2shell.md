# OrangeBox PHP2Shell Detection

## Objetivo

Detectar indicadores PHP2Shell (CVE-2026-109618 / CVE-2026-109619) y el patrón conductual PEAR observado en el incidente, sin confundir un intento con ejecución confirmada.

## Reglas

| Regla | Nivel | Función |
|---|---:|---|
| 10050 | 8, atributo noalert="1" | Clasificador intermedio: marcador PHP2Shell/CVE o combinación PEAR pearcmd + config-create + destino bajo /tmp/, /var/tmp/ o /dev/shm/. Permite que Wazuh continúe evaluando el árbol de reglas. |
| 10051 | 12 | Tres o más eventos 10054 de la misma IP no IOC en 300 segundos. Vuelve a excluir la CDB de proxies web autorizados y entra en `orangebox_web_auto_block`: `firewall-drop` local durante 24 horas. Confirma escaneo repetido, no RCE. |
| 10052 | 12 | Señales de ejecución post-explotación observadas por auditd. Puede haber usos administrativos legítimos. |
| 10053 | 14 | Evento 10050 cuyo srcip aparece en la CDB malicious-ip. Alerta IOC dedicada y firewall-drop durante 30 días. |
| 10054 | 8 | Evento 10050 cuyo srcip no aparece en la CDB malicious-ip. Genera alerta de sondeo y no bloquea automáticamente. |

La regla 10050 exige los tres indicadores PEAR en el mismo registro para la detección conductual; no basta con pearcmd, config-create o una ruta temporal de forma aislada.

## Active Response

- 10053 comparte la política de contención de 30 días con 99906.
- 10051 hereda la política existente del grupo exacto `orangebox_web_auto_block`: `firewall-drop` durante 24 horas en el agente que generó el evento. La regla exige tres coincidencias 10054 de la misma IP en 300 segundos, que no esté en la CDB IOC y que tampoco pertenezca a la CDB de proxies web autorizados.
- 10054 registra cada sondeo no IOC, pero no bloquea por sí solo. 10050 es un clasificador silencioso y 10052 es una señal auditd que permanece sin respuesta automática.
- Un origen no presente en la CDB IOC no se considera benigno; simplemente no está clasificado actualmente como IOC de origen.
- El evento HTTP no prueba que PHP haya ejecutado el exploit. La respuesta HTTP 200 tampoco demuestra ejecución de código.
- Un comando auditd sospechoso no identifica por sí solo la IP HTTP que lo originó.

## Cobertura y límites

No se vuelve a incorporar FIM masivo a /home/*/public_html. La regla 10052 depende de los eventos execve auditd que realmente recoge el agente; no detecta webshells que operan dentro del proceso PHP sin crear procesos hijos.

## Validación en Manager

```bash
/var/ossec/bin/wazuh-analysisd -t
bash /root/Wazuh-OrangeBox/tests/test-ioc-active-response.sh
```

La regresión usa dos líneas del incidente:
- Solicitud PEAR config-create que escribe /tmp/index1.php: debe recorrer 10050 y finalizar en 10053 para la IP IOC confirmada. Se consulta la política de 30 días.
- Lectura LFI /tmp/index1: no debe activar 10050; debe seguir llegando a la regla IOC web 99906.

wazuh-logtest no ejecuta Active Response. Para confirmar el bloqueo real hay que revisar el evento 651/10458, el log Active Response del agente y el firewall del agente.
