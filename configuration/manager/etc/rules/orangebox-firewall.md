# OrangeBox Firewall

Documentación de `orangebox-firewall.xml`.

## Para qué sirve

Convierte los eventos TCP SYN registrados por el firewall en detecciones de comportamiento de red mediante correlación Wazuh.

El flujo es:

```text
iptables / Shorewall
        ↓
evento ORANGEBOX-FW
        ↓
regla nativa Wazuh 4100
        ↓
10450 (señal de soporte, no visible)
        ↓
10453 / 10454 / 10455
```

La regla `10450` usa nivel 1 + `no_log` para alimentar correlaciones sin generar una alerta individual por cada SYN.

## Reglas

### 10450 — TCP SYN de entrada

Parte de la regla nativa `4100` y busca:

```text
RES=0x00 SYN URGP=0
```

La condición evita contar variantes que no correspondan al nuevo intento TCP que queremos correlacionar.

No genera alertas visibles.

### 10453 — Posible escaneo TCP de puertos

Requiere:

- 12 TCP SYN;
- 90 segundos;
- misma IP origen;
- diferentes puertos destino.

Esto busca diferenciar un escaneo de puertos de un cliente que insiste sobre un único servicio.

La respuesta automática configurada para esta regla es `firewall-drop` durante 1 hora.

### 10454 — Posible SYN flood desde una IP

Requiere:

- 60 TCP SYN;
- 10 segundos;
- misma IP origen;
- mismo puerto destino.

La respuesta automática configurada es `firewall-drop` durante 1 hora.

### 10455 — Posible DoS distribuido

Requiere:

- 200 IPs origen diferentes;
- 10 segundos;
- mismo puerto destino.

Esta regla no ejecuta `firewall-drop` porque una detección distribuida no identifica una sola IP que represente al conjunto completo del tráfico.

## Severidad y correo

La severidad de las reglas representa la importancia de la detección.

La política de correo se decide por separado en `custom-orangebox-email.py`. No se deben cambiar los niveles solamente para controlar el ruido del correo.

## Falsos positivos

Los umbrales son una política inicial. Deben validarse contra el comportamiento real de cada servidor antes de aumentar frecuencia, reducir ventanas o automatizar nuevas acciones.

Es especialmente importante considerar:

- balanceadores y reverse proxies;
- monitoreo;
- scanners autorizados;
- servicios expuestos públicamente;
- NAT y otras fuentes que puedan concentrar tráfico.

## Dependencias

- Regla nativa Wazuh `4100`.
- Logging de firewall OrangeBox.
- `same_srcip`, `different_srcip` y `different_dstport` para las correlaciones correspondientes.
- Active Response `firewall-drop` para `10453` y `10454`.

La protección debe probarse en un servidor antes de aplicar cambios de umbral de manera general.


## Active Response firewall-drop: persistencia sin ruido de correo

La regla nativa Wazuh 651 (Host Blocked by firewall-drop Active Response) es de nivel 3. OrangeBox necesita conservar estos eventos porque los reportes de seguridad los utilizan para contabilizar y auditar los bloqueos ejecutados automáticamente. Wazuh define log_alert_level como el nivel mínimo que se almacena en alerts.json y alerts.log; con el valor anterior de 5, la regla 651 quedaba fuera de la persistencia. citeturn0search5

Por ese motivo, log_alert_level se establece en 3. No se modifica artificialmente la severidad de la regla nativa 651.

La regla hija OrangeBox 10458 utiliza nivel 15 para identificar explícitamente estos eventos en los reportes. email_alert_level permanece en 16, de modo que 10458 se registra pero no genera un correo individual por cada IP bloqueada. Wazuh documenta que email_alert_level es el umbral mínimo para generar correo. citeturn0search5

La separación buscada es:

- nivel 3: persistencia de la señal nativa 651;
- nivel 15: señal OrangeBox 10458 para reportería;
- nivel 16: umbral de correo, sin notificación por cada firewall-drop.

La regla 651 sigue siendo la señal nativa de Wazuh y 10458 agrega únicamente una capa OrangeBox para reportería.
