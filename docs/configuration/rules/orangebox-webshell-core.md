# OrangeBox WebShell Core

Documentación de `orangebox-webshell-core.yar`.

## Para qué sirve

Este archivo contiene firmas YARA de **investigación** para familias JSP observadas en compromisos reales de Zimbra/Carbonio.

Estas firmas forman la capa **CORE** del pipeline FIM → YARA → alerta Wazuh de OrangeBox. El Active Response ejecuta YARA sobre archivos candidatos seleccionados por FIM (`10420/10421`) y una coincidencia CORE genera la alerta Wazuh `10501` de nivel 14.

No busca palabras sueltas. Las condiciones combinan varias piezas que, juntas, forman un patrón de webshell.

## Qué detecta

| Regla | Técnica |
|---|---|
| `OrangeBox_JSP_Runtime_Command_Execution` | `Runtime.exec()` usando parámetros HTTP |
| `OrangeBox_JSP_ProcessBuilder_Shell` | `ProcessBuilder` ejecutando shell |
| `OrangeBox_JSP_Dynamic_ClassLoader` | carga dinámica mediante `ClassLoader`/`defineClass` |
| `OrangeBox_JSP_ClassLoader_Base64` | carga dinámica con decodificación Base64 |
| `OrangeBox_JSP_Encrypted_ClassLoader_AES` | payload cifrado con AES/Cipher |
| `OrangeBox_JSP_Obfuscated_Dynamic_ClassLoader` | reconstrucción/ocultamiento mediante XOR |

En general se exige que exista código JSP, entrada desde HTTP y una técnica de ejecución o carga dinámica. La intención es bajar falsos positivos frente a buscar simplemente `Runtime`, `Base64` o `ClassLoader` por separado.

## Core vs Extended

Este archivo representa la capa **Core**. Una coincidencia se considera de alta confianza y está separada de las heurísticas de `orangebox-webshell-extended.yar`.

Un match de YARA nunca debe interpretarse como la única evidencia necesaria para declarar comprometido un servidor. El pipeline también puede aportar FIM, logs y otras detecciones Wazuh.

## Compatibilidad

Las reglas están escritas manteniendo compatibilidad con **YARA 3.11** y no dependen intencionalmente de módulos o funciones más nuevas.

## Decisiones de diseño

### Combinaciones, no palabras mágicas

Buscar solo `Runtime.exec` sería demasiado amplio. Lo mismo ocurre con `Base64` o `ClassLoader`.

La detección combina señales para que el resultado sea más útil y menos ruidoso.

### Familias separadas

Cada técnica tiene una regla propia. Esto permite saber qué comportamiento produjo el match y evita convertir todo en una mega-regla imposible de mantener.

### No confundir ausencia con inocencia

Si YARA no encuentra nada, eso solo significa que **estas firmas no encontraron lo que buscan**. Un webshell nuevo, ofuscado o de otra familia puede pasar tranquilamente por debajo del radar.
