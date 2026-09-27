# WebShells Index

Documentación de `webshells_index.yar`.

## Para qué sirve

Este archivo es el **punto de entrada** de las reglas YARA de webshell.

No contiene detecciones propias. El índice pertenece al ruleset oficial de Yara-Rules/rules y agrupa las firmas de webshell distribuidas por ese proyecto.

OrangeBox no mantiene copias locales de `orangebox-webshell-core.yar` ni `orangebox-webshell-extended.yar`; el instalador las elimina si quedaron de una implementación anterior.

## Por qué existe

Mantener un archivo índice evita tener que cargar cada conjunto de reglas por separado y, al mismo tiempo, conserva la separación entre:

- las firmas oficiales de webshell; la coincidencia es procesada por la regla Wazuh `10501`.

Así la política de producción puede decidir qué grupo genera alertas críticas o correo sin mezclar las firmas.

## Regla de mantenimiento

Si se agrega otro conjunto de firmas, debe decidirse primero si pertenece a Core o Extended. No conviene meter reglas nuevas directamente aquí: este archivo debe seguir siendo un índice y nada más.

## Dependencias

Los archivos incluidos deben existir en el mismo directorio y ser compatibles con la versión de YARA utilizada por el pipeline.
