# Prueba real de movimiento lateral SSH — regla 10008

## Objetivo

Validar en producción la correlación de movimiento lateral basada en tres logins SSH exitosos:

- misma IP de origen;
- tres agentes/servidores distintos;
- dentro de una ventana máxima de 5 minutos;
- correlación global entre agentes;
- generación de la regla OrangeBox `10008`;
- envío inmediato de la alerta por correo.

La prueba valida específicamente la regla `10008`. No requiere Active Response.

## Regla validada

La regla desplegada es:

```xml
<rule id="10008" level="13" frequency="3" timeframe="300">
    <if_matched_sid>10001</if_matched_sid>
    <same_srcip />
    <different_location />
    <global_frequency />
    <description>ALERTA: Posible movimiento lateral SSH. La misma IP obtuvo multiples logins exitosos en diferentes servidores dentro de 5 minutos.</description>
    <mitre>
        <id>T1021.004</id>
    </mitre>
    <group>authentication_success,lateral_movement,attack,orangebox_ssh,orangebox_auth,orangebox_behavior,orangebox_immediate,</group>
</rule>
```

### Cómo funciona

```text
SSH exitoso
   |
   +--> 10001
          |
          +--> misma srcip
          +--> diferente location
          +--> global_frequency
          +--> 3 eventos dentro de 300 s
                         |
                         v
                       10008
                         |
                         +--> alerta inmediata
                         +--> correo
```

Puntos importantes:

- `10001` es la detección base de SSH exitoso.
- `frequency="3"` exige tres eventos.
- `timeframe="300"` limita la correlación a 300 segundos.
- `same_srcip` exige la misma IP origen.
- `different_location` exige que los eventos correspondan a ubicaciones/agentes distintos.
- `global_frequency` permite correlacionar eventos recibidos desde distintos agentes.
- No se bloquea automáticamente la IP: el patrón puede corresponder a una actividad administrativa legítima y se genera alerta para investigación.

## Prueba real validada

La validación exitosa se realizó con la IP origen:

```text
203.0.113.10
```

y tres destinos diferentes:

```text
ssh-server-a.example.com
ssh-server-b.example.com
ssh-server-c.example.com
```

Los tres eventos fueron logins SSH exitosos de `root`:

| Orden | Destino | Hora | Evento |
|---|---|---|---|
| 1 | `ssh-server-a.example.com` | 09:04:40 | `Accepted publickey for root from 203.0.113.10` |
| 2 | `ssh-server-b.example.com` | 09:05:10 | `Accepted publickey for root from 203.0.113.10` |
| 3 | `ssh-server-c.example.com` | 09:05:38 | `Accepted publickey for root from 203.0.113.10` |

El tercer evento completó la correlación y produjo la alerta:

```text
Regla: 10008
Mensaje: ALERTA: Posible movimiento lateral SSH
```

La alerta también fue procesada por la integración de correo y llegó con el asunto:

```text
ALERTA: Posible movimiento lateral SSH
```

Los eventos observados provinieron de ubicaciones distintas, incluyendo `journald` y `/var/log/secure`, demostrando que la correlación no depende de que todos los eventos tengan exactamente el mismo `location`.

## Procedimiento reproducible

La forma correcta de reproducir la prueba es generar tres autenticaciones SSH exitosas desde **la misma máquina/IP origen**, contra tres agentes Wazuh diferentes.

Ejemplo:

```bash
ssh root@ssh-server-a.example.com
ssh root@ssh-server-b.example.com
ssh root@ssh-server-c.example.com
```

Las tres conexiones deben completarse dentro de 300 segundos.

No sirve cambiar solamente el hostname dentro de un evento inyectado por STDIN: el correlador `different_location` necesita que Wazuh reciba eventos asociados a ubicaciones/agentes distintos. La prueba real con SSH contra tres agentes evita esa falsa validación.

## Validación en el Manager

Después de ejecutar las tres conexiones, validar las alertas:

```bash
grep -F '"rule":{"id":"10008"' /var/ossec/logs/alerts/alerts.json | tail -20
```

o:

```bash
grep -F '10008' /var/ossec/logs/alerts/alerts.json | tail -20
```

También se puede revisar el correo generado por la integración OrangeBox.

Para comprobar la correlación en el indexer:

```bash
curl -sk -u admin \
  'https://127.0.0.1:9200/_cat/indices/wazuh-*?v&s=store.size:desc'
```

Este comando consulta directamente el catálogo de índices Wazuh y fue validado como operativo.

## Criterios de éxito

La prueba se considera exitosa cuando se cumplen todos estos puntos:

1. Existen tres logins SSH exitosos.
2. Los tres tienen la misma `srcip`.
3. Los tres corresponden a agentes/locations diferentes.
4. Los tres ocurren dentro de 300 segundos.
5. Los eventos base son detectados por `10001`.
6. El tercer evento dispara `10008`.
7. La alerta contiene la descripción de movimiento lateral SSH.
8. La integración de correo recibe/procesa la alerta inmediata.

## Qué NO modificar durante esta prueba

La regla `10008` ya está validada y no debe modificarse para repetir la prueba.

En particular, mantener:

```text
frequency=3
timeframe=300
if_matched_sid=10001
same_srcip
different_location
global_frequency
```

La prueba debe adaptarse al mecanismo de generación de eventos, no alterar la correlación para hacer que un test sintético pase.

## Relación con 10007

`10007` y `10008` cubren escenarios diferentes:

- `10007`: ráfaga de fallos SSH desde redes internas.
- `10008`: múltiples logins SSH exitosos desde la misma IP hacia diferentes servidores.

Por lo tanto, una prueba de `10008` debe utilizar autenticaciones exitosas reales.

## Nota de operación

La detección está diseñada como alerta para investigación. No tiene Active Response asociado porque una misma IP puede representar un jump host, BackupPC u otra fuente administrativa legítima.

La contención automática debe mantenerse separada de esta correlación.

## Evidencia de la prueba

La validación de producción quedó confirmada con tres conexiones SSH exitosas desde `203.0.113.10`:

```text
09:04:40  ssh-server-a.example.com
09:05:10  ssh-server-b.example.com
09:05:38  ssh-server-c.example.com
```

Resultado:

```text
10001 -> 10001 -> 10008
                  |
                  +--> correo: "ALERTA: Posible movimiento lateral SSH"
```

Esta prueba constituye la referencia para futuras modificaciones de la correlación de movimiento lateral SSH.
