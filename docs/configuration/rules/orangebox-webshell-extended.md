# OrangeBox WebShell Extended

Documentación de `orangebox-webshell-extended.yar`.

## Para qué sirve

Esta capa contiene detecciones YARA **heurísticas y experimentales** para técnicas JSP sospechosas.

Esta capa está conectada al pipeline FIM → YARA → alerta Wazuh de OrangeBox como detección heurística. El Active Response ejecuta estas firmas sobre los mismos candidatos seleccionados por FIM; una coincidencia genera `10502` de nivel 10 para hunting y revisión, sin correo crítico.

Está separada de Core a propósito: un match aquí significa **sospechoso**, no malware confirmado.

## Qué detecta

| Regla | Qué busca |
|---|---|
| `OrangeBox_JSP_Base64_Command_Execution` | ejecución de comandos con Base64 |
| `OrangeBox_JSP_Dynamic_Loading_Reflection` | carga dinámica y reflection de Java |
| `OrangeBox_JSP_Encoded_String_Reconstruction` | reconstrucción de strings con arrays/XOR |
| `OrangeBox_JSP_ClassLoader_Bytecode_Heuristic` | carga dinámica de bytecode |

Las condiciones combinan varias señales para que una coincidencia tenga valor durante hunting.

## Por qué está separado de Core

Core apunta a patrones que tenemos bastante claros. Extended apunta a técnicas que pueden aparecer en código legítimo, herramientas de administración o variantes de webshell.

Separarlas permite decidir en Wazuh qué hacer con cada nivel de confianza sin convertir cualquier JSP raro en una alarma roja de incendio.

## Cómo interpretar un match

Un match Extended debería provocar revisión del archivo y del contexto:

- quién lo creó o modificó;
- cuándo apareció;
- qué proceso lo generó;
- dónde está ubicado;
- qué otras detecciones FIM o Wazuh existen.

No se debe eliminar automáticamente un archivo solo porque una regla Extended hizo match.

## Compatibilidad

Las reglas mantienen compatibilidad con **YARA 3.11**.

## Decisión de diseño

La separación Core/Extended es más importante que tener muchas firmas mezcladas en un único archivo. Permite aumentar cobertura sin bajar silenciosamente el nivel de confianza de las detecciones críticas.
