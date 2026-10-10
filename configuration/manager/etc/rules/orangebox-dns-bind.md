# OrangeBox DNS / BIND

Detecciones para servidores DNS que utilizan BIND/named.

## Flujo de deteccion

```text
iptables / CSF / Shorewall
        ↓
ORANGEBOX-FW
        ↓
decoder kernel / regla 4100
        ↓
10800 = UDP/53
10801 = TCP SYN/53
        ↓
10802 = UDP flood por IP
10803 = senal de observacion de flood distribuido
10811 = correlacion fuerte de flood distribuido persistente
10804..10805 = SYN flood
```

Para eventos propios de BIND:

```text
BIND / named
   ↓
decoder nativo named
   ↓
12102 / 12103 / 12149 / 12101 / 12109
   ↓
10806..10810 = prioridad OrangeBox
```

El decoder nativo de Wazuh para named extrae la IP de origen de los eventos de cliente y dispone de un decoder especifico para consultas DNS. Las reglas nativas incluyen detecciones para AXFR denegado, update denegado, fallos de cache, paquetes DNS invalidos y errores fatales de named.

## Reglas

| ID | Deteccion | Condicion |
|---|---|---|
| 10800 | Base UDP/53 | Trafico entrante UDP hacia puerto 53. No genera alerta visible. |
| 10801 | Base TCP/53 | SYN TCP entrante hacia puerto 53. No genera alerta visible. |
| 10802 | UDP flood por IP | 1000 paquetes en 10 s, misma IP/servidor/puerto. |
| 10803 | Observacion UDP distribuida | 200 IPs distintas en 10 s hacia el mismo servidor/puerto. Nivel 5; sirve como senal de correlacion. |
| 10811 | UDP distribuido persistente | 3 eventos 10803 en 5 min hacia el mismo servidor/puerto. Nivel 14. |
| 10804 | SYN flood TCP/53 por IP | 1000 SYN en 10 s, misma IP/servidor/puerto. |
| 10805 | SYN flood TCP/53 distribuido | 200 IPs distintas en 10 s hacia el mismo servidor/puerto. |
| 10806 | Reconocimiento AXFR | 3 AXFR denegados desde la misma IP en 5 min. |
| 10807 | Update DNS no autorizado | 3 updates denegados desde la misma IP en 5 min. |
| 10808 | Consultas de cache denegadas | Escala la correlacion nativa 12149 a nivel 8. Se registra, pero no envia correo; no activa firewall-drop. |
| 10809 | Paquete DNS invalido | Escala la regla nativa 12101. |
| 10810 | Caida de BIND | Escala la regla nativa 12109. |

Wazuh permite correlacionar por srcip, dstip y dstport, incluyendo same_srcip, different_srcip, same_dstip y same_dstport, para reglas basadas en frecuencia.

## Umbrales

Los umbrales de flood son una politica inicial y deben validarse con trafico real.

La regla 10802 busca una fuente individual con volumen muy alto. La regla 10803 no se trata como ataque por si sola: en DNS publico es normal recibir trafico de muchas IPs distintas en ventanas cortas, por lo que se mantiene como senal de observacion de nivel 5.

La alerta 10811 exige que la condicion distribuida de 10803 ocurra 3 veces dentro de 5 minutos sobre el mismo servidor DNS. La idea es distinguir un pico normal o puntual de un comportamiento distribuido y sostenido. Esta regla es la que debe entrar a los reportes de seguridad como alerta relevante.

Las reglas 10804 y 10805 mantienen la deteccion inicial de SYN floods TCP/53. Sus umbrales tambien deben validarse con trafico real.

No se agrega Active Response en este archivo. Un servidor DNS puede recibir trafico legitimo de muchos resolvers y un AXFR/update denegado tambien puede deberse a una configuracion operacional. Primero se valida el comportamiento real y despues se decide si alguna deteccion debe bloquear automaticamente.

La deteccion de DNS amplification/reflection no se infiere solamente a partir de estos eventos entrantes: requiere visibilidad adicional del trafico de respuesta o de consultas/respuestas para diferenciar una amplificacion real de trafico DNS normal.

## Dependencias

- Logging de firewall OrangeBox para las reglas 10800-10805.
- Decoder/ruleset nativo kernel.
- Decoder/ruleset nativo named para las reglas 10806-10810.
- Puerto DNS 53.


### 10808 — Consultas de caché denegadas

La regla nativa `12149` identifica una ráfaga de consultas de caché denegadas por BIND. OrangeBox la conserva como observación de nivel 8: queda registrada en Wazuh para investigación y reportes, pero está por debajo del umbral 12 de `HOST_DE_EJEMPLO`, por lo que no genera correo. No se configura `firewall-drop` para esta regla. Que BIND las rechace no demuestra acceso exitoso a la caché.
