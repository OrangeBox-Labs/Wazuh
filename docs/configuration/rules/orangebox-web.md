# OrangeBox Web

Documentación de `orangebox-web.xml`.

## Para qué sirve

Estas reglas agregan contexto a los errores HTTP 4xx para distinguir tres cosas que a primera vista se parecen bastante:

1. autenticación web fallida;
2. fuerza bruta sobre autenticación;
3. reconocimiento de archivos sensibles.

La gracia está en no tratar todo 404 como ataque ni todo 401 como brute force. Porque ahí terminamos alertando hasta al navegador, po.

## Flujo de detección

```text
31101 HTTP 4xx
   ├── 10024 → 401/403
   │             └── 10025 → múltiples 401/403 desde la misma IP
   │
   └── 10023 → URL sensible con 401/403/404
                 └── 10026 → múltiples intentos desde la misma IP
```

### 10024 — HTTP 401/403

Es la regla base. Parte de `31101` y conserva solo respuestas `401` y `403`.

No intenta determinar todavía si hay ataque. Solo deja identificado el evento de autenticación web fallida.

### 10023 — URL sensible

También parte directamente de `31101`, pero busca rutas que suelen interesar durante reconocimiento:

- `.env`;
- `.aws`;
- configuración de Google Cloud;
- OCI;
- OpenAI;
- `wp-config.php`;
- variantes bajo `@fs`.

Incluye `404` a propósito. Que el archivo no exista no cambia el hecho de que alguien está preguntando específicamente por una ruta sensible.

### 10025 — Fuerza bruta web

Correlaciona `10` eventos `10024` en `15` segundos desde la misma IP.

Las URLs sensibles se excluyen porque ya tienen su propio camino (`10023` → `10026`). Así evitamos que el mismo scanner termine clasificado simultáneamente como brute force y reconocimiento de secretos.

**MITRE:** `T1110`.

### 10026 — Reconocimiento automatizado

Correlaciona `2` eventos `10023` en `30` segundos desde la misma IP.

Es nivel 11 y activa `firewall-drop` durante 24 horas. La severidad se mantiene separada de la política de correo.

**MITRE:** `T1083` y `T1552`.

## Whitelist

`20024` y `20025` corresponden a reverse proxies legítimos.

Esto es necesario porque el backend puede recibir múltiples solicitudes desde el proxy y, si no se identifica correctamente la IP de origen, Wazuh podría pensar que el proxy es el atacante.

La whitelist se limita a las IP conocidas de los proxies. No se hace una excepción global para todo el tráfico web.

## Decisiones importantes

### Separar brute force de reconocimiento

Un `401` repetido contra `/login` no es lo mismo que probar `.env`, `.aws` o `wp-config.php`.

Separar ambos caminos permite aplicar una respuesta distinta y entender mejor qué estaba intentando hacer el origen.

### Incluir 404 en URLs sensibles

El objetivo es detectar el intento de descubrimiento, no solamente una descarga exitosa. Por eso `10023` trabaja sobre cualquier 4xx.

### Usar la misma IP como correlación

Las reglas de ráfaga usan `same_srcip`. Sin eso, varios clientes legítimos podrían terminar sumándose en una sola detección.

## Dependencias

- Regla nativa `31101` para HTTP 4xx.
- `same_srcip` para correlación por origen.
- Active Response `firewall-drop` para la respuesta asociada a `10026`.

Las rutas sensibles y las IP de reverse proxy deben revisarse cuando cambie la arquitectura web.
