---
title: "Wazuh: crear reglas es fácil... hasta que no funciona"
description: "Cómo construimos, probamos y afinamos reglas Wazuh en entornos reales, desde el evento bruto hasta la respuesta automática."
date: 2026-09-17
tags: ["wazuh", "seguridad", "linux", "deteccion", "regex", "monitoring"]
categories: ["seguridad", "monitoreo"]
---

# Wazuh: crear reglas es fácil... hasta que no funciona

Una de las partes más entretenidas de trabajar con Wazuh es esa que en la documentación parece trivial:

> "Crea una regla y listo."

Sí, claro. 😂

En la práctica, crear una regla que **realmente detecte lo que queremos, sin llenar el SOC de falsos positivos**, puede convertirse rápidamente en una pequeña guerra contra el XML, el orden de evaluación y los regex.

## Primero: encontrar el evento real

No partimos escribiendo XML a lo loco. Primero generamos o capturamos **el evento real que queremos detectar**.

Por ejemplo: un intento SSH fallido, una creación de archivo sospechoso, una petición HTTP extraña o un intento de reconocimiento de puertos.

Con el evento completo delante es mucho más fácil decidir qué parte es estable y qué parte cambia.

Y acá aparece el primer clásico:

```text
"Mi regex funciona perfecto..."

Wazuh:
"No."
```

## El orden importa más de lo que parece

Una regla puede parecer correcta y aun así no disparar porque depende de otra regla, de un `if_sid`, de un `if_matched_sid` o de una condición de correlación.

También importa **qué regla procesa primero**.

Una detección simple puede convertirse en una detección útil cuando empezamos a encadenar condiciones:

```text
evento base
   ↓
regla hija
   ↓
varios eventos relacionados
   ↓
misma IP / mismo origen
   ↓
regla de correlación
   ↓
alerta relevante
```

Eso es lo que permite pasar de "hubo un intento" a cosas como "esta misma IP está probando múltiples puertos" o "hubo una ráfaga de fallos SSH desde la red interna".

## Y después vienen los regex

Esta parte merece respeto. 😅

Wazuh no acepta cualquier regex que uno copiaría alegremente desde otro proyecto. Hay que tener claro **qué motor de expresión regular estamos usando** y, cuando corresponde, indicar explícitamente `pcre2`.

También hay diferencias entre una expresión que parece correcta y una expresión que realmente coincide con el evento que entrega Wazuh.

Por eso el proceso normalmente termina siendo:

```text
evento real
   ↓
regex inicial
   ↓
prueba
   ↓
"¿por qué no disparó?"
   ↓
revisar el log completo
   ↓
ajustar regex / condición / orden
   ↓
probar de nuevo
```

Y sí: a veces una línea de XML te roba una cantidad absolutamente ridícula de tiempo.

## Las reglas se prueban provocando el evento

No nos interesa únicamente que el XML pase la validación.

Nos interesa que la regla funcione **contra tráfico, logs o cambios reales**.

Por ejemplo, durante las pruebas hemos generado eventos controlados para verificar cadenas completas como:

```text
FIM detecta creación
        ↓
regla OrangeBox identifica el archivo
        ↓
alerta Wazuh
        ↓
correlación, cuando corresponde
        ↓
Active Response
        ↓
firewall-drop
```

Lo mismo con autenticación, web, reconocimiento y otras detecciones.

Porque una regla que "no da error al reiniciar Wazuh" no necesariamente está funcionando. Eso solo significa que Wazuh todavía no se enojó con el XML. 😈

## Cuando ya funciona, recién ahí automatizamos

Nuestra lógica es bastante simple:

**detectar primero, probar después y contener al final.**

Primero hacemos que la detección sea confiable.

Después la sometemos a pruebas controladas y revisamos exactamente qué evento generó, qué regla disparó y qué información terminó en Wazuh.

Y solo cuando esa parte está clara, agregamos respuesta automática, correo, reportes y dashboards.

Eso evita el clásico desastre de seguridad donde una regla mal ajustada termina bloqueando medio Internet porque alguien escribió un regex con fe y sin café.

## Y ahí aparecen los reportes

Una vez que las reglas producen datos confiables, podemos hacer algo mucho más útil que una pantalla llena de alertas: **resumir lo que realmente ocurrió**.

Nuestro reporte clásico y el nuevo dashboard utilizan la misma extracción de datos y la misma clasificación. El dashboard simplemente cambia la presentación para que la información sea más fácil de leer para alguien que no quiere pasar la tarde mirando JSON.

Así podemos mostrar, por ejemplo:

- eventos relevantes;
- categorías de detección;
- reglas más activas;
- sistemas afectados;
- IPs observadas;
- técnicas MITRE asociadas;
- bloqueos automáticos realizados por `firewall-drop`.

La gracia no está en hacer una pantalla bonita.

La gracia está en que **los números que aparecen sean los mismos que estamos detectando realmente**.

## La parte que nadie te cuenta

Crear una regla de Wazuh no es solamente escribir un XML.

Es entender el evento, conocer el motor de reglas, respetar el orden de evaluación, elegir bien la condición, afinar el regex, probarlo contra eventos reales y volver a ajustar cuando algo no coincide como esperabas.

Y cuando finalmente funciona y ves en los logs exactamente la alerta que querías...

bueno, ahí sí que da gusto. 😎

Porque en seguridad, **detectar bonito no sirve de mucho. Detectar bien, sí.**
