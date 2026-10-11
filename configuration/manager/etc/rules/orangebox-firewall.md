# OrangeBox Firewall

Documentación de `orangebox-firewall.xml`.

## Para qué sirve

Convierte los eventos TCP SYN registrados por el firewall en detecciones mediante correlación Wazuh, sin generar una alerta por cada paquete.

## Flujo

```text
iptables / Shorewall
        ↓
evento ORANGEBOX-FW
        ↓
regla nativa Wazuh 4100
        ↓
10450 (señal de soporte, nivel 1 + no_log)
        ├── 10453 (port scan)
        │      └── 10456 (disparador de Active Response)
        ├── 10454 (SYN flood)
        └── 10455 (posible DoS distribuido)
```

## Reglas

### 10450 — TCP SYN de entrada

Parte de la regla nativa `4100` y busca `RES=0x00 SYN URGP=0`. La regla tiene nivel 1 y `no_log`: alimenta las correlaciones sin guardar una alerta individual por cada SYN.

### 10453 — Posible escaneo TCP de puertos

Requiere **4 eventos en 5 segundos**, con la misma IP de origen, la misma IP de destino, el mismo puerto de origen y diversidad de puertos de destino. La regla detecta el comportamiento; no es el ID configurado directamente para `firewall-drop`.

La regla hija `10456` activa `firewall-drop` en el agente que genera la alerta durante **3600 segundos (1 hora)**.

### 10454 — Posible SYN flood desde una IP

Requiere **1000 TCP SYN en 10 segundos**, desde la misma IP de origen hacia el mismo destino y el mismo puerto de destino. El puerto de origen no participa porque puede variar durante un flood.

La propia regla `10454` activa `firewall-drop` durante **3600 segundos (1 hora)**.

### 10455 — Posible DoS distribuido

Requiere **200 IPs de origen diferentes en 10 segundos** hacia el mismo puerto de destino. No ejecuta `firewall-drop` por sí sola, porque una detección distribuida no identifica una única IP responsable del conjunto del tráfico.

## Severidad y correo

El nivel de severidad y la política de correo son independientes. Las reglas de soporte y detección de port scan operan a nivel 11 y quedan bajo el umbral de correo configurado en la integración. La regla `10455` se excluye explícitamente del correo individual. La acción de `firewall-drop` se configura en `ossec.conf` mediante los IDs `10456` y `10454`.

No se deben cambiar los niveles solamente para controlar el ruido del correo.

## Falsos positivos

Los umbrales deben validarse contra el comportamiento real de cada servidor antes de cambiarlos. Considerar:

- balanceadores y reverse proxies;
- monitoreo y scanners autorizados;
- servicios expuestos públicamente;
- NAT y otras fuentes que concentren tráfico.

No agregar una respuesta automática global para un patrón que no identifica una sola IP bloqueable.

## Active Response y auditoría de bloqueos

La regla nativa Wazuh `651` (`Host Blocked by firewall-drop Active Response`) tiene nivel 3. `log_alert_level` debe ser al menos 3 para conservar esa evidencia en `alerts.json`. No se eleva artificialmente el nivel de la regla nativa.

La regla OrangeBox `10458` agrega una señal para los reportes. Con `email_alert_level=16`, ese evento se conserva para auditoría sin generar un correo individual por cada IP bloqueada.

Distinguir siempre entre una acción configurada y una acción ejecutada: para confirmar el bloqueo real, revisar los eventos de Active Response `651` y su correlación OrangeBox `10458`.
