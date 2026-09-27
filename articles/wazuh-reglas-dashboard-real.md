---
title: "Wazuh: de una regla que funciona a un dashboard que sirve"
description: "Cómo construimos y probamos reglas Wazuh en OrangeBox, afinando regex, orden de evaluación, correlación y respuesta automática."
date: 2026-09-17
tags: ["wazuh", "seguridad", "linux", "deteccion", "regex", "monitoring"]
categories: ["seguridad", "monitoreo"]
---

# Wazuh: de una regla que funciona a un dashboard que sirve

En seguridad hay una frase que parece sencilla:

> "Haz una regla para detectar esto."

Perfecto. Cinco minutos, un XML y a tomar café.

Bueno... no. 😂

En la práctica, crear una regla Wazuh que **detecte exactamente lo que queremos** puede ser bastante más entretenido.

## Primero hay que encontrar el evento real

No partimos escribiendo reglas a ciegas.

Primero generamos o capturamos el evento real: un login fallido, una creación de archivo, una petición web sospechosa, un escaneo de puertos, etc.

Con el evento completo delante podemos decidir qué parte es estable, qué parte cambia y qué queremos usar realmente para identificarlo.

Y ahí normalmente aparece el primer clásico:

```text
"Mi regex funciona perfecto."

Wazuh:
"No."
```

## El orden de evaluación importa

Una regla puede estar perfectamente escrita y aun así no disparar.

Puede depender de otra regla mediante `if_sid`, de una correlación con `if_matched_sid`, de la misma IP de origen, de varios eventos en una ventana de tiempo o de una combinación de condiciones.

La idea termina siendo algo así:

```text
evento base
   ↓
regla hija
   ↓
varios eventos relacionados
   ↓
misma IP / mismo origen
   ↓
correlación
   ↓
alerta útil
```

Ahí es cuando una detección pasa de "hubo un intento" a algo realmente accionable.

## Y sí, los regex nos hacen sufrir

Esta es probablemente la parte más mañosa.

No todos los regex que uno copiaría desde otro proyecto funcionan igual en Wazuh. Hay que conocer el motor que está usando la regla y, cuando corresponde, declarar explícitamente `pcre2`.

Además, hay diferencias entre:

- el log que creemos que recibimos;
- el evento que realmente entrega Wazuh;
- y la expresión que finalmente coincide.

Así que el proceso suele parecerse bastante a esto:

```text
evento real
   ↓
regex
   ↓
prueba
   ↓
"¿por qué mierda no disparó?"
   ↓
revisar evento completo
   ↓
ajustar regex / condición / orden
   ↓
probar otra vez
```

Una línea de XML puede consumir una cantidad completamente desproporcionada de tiempo. 😅

## Validar el XML no significa que la regla funcione

Que Wazuh acepte la configuración solo significa que la configuración es válida.

Después hay que **provocar el evento** y comprobar:

- qué regla disparó;
- qué nivel obtuvo;
- qué datos llegaron;
- si la correlación funciona;
- y, cuando corresponde, si se ejecutó Active Response.

En nuestras pruebas hemos seguido cadenas como:

```text
evento real
   ↓
regla OrangeBox
   ↓
alerta Wazuh
   ↓
correlación
   ↓
Active Response
   ↓
firewall-drop
```

Ahí recién sabemos que la regla está haciendo su pega.

## Después viene la parte bonita

Cuando las detecciones ya son confiables, recién ahí tiene sentido automatizar reportes y dashboards.

Nuestro reporte clásico y el dashboard utilizan **la misma extracción y clasificación de datos**. El dashboard no inventa otra fuente: cambia la presentación para que la información sea entendible sin tener que leer miles de líneas de JSON.

Así podemos mostrar eventos relevantes, categorías, reglas activas, sistemas afectados, IPs observadas, técnicas MITRE y bloqueos automáticos.

Porque una pantalla bonita con números inventados es decoración.

Una pantalla bonita con **los mismos datos que realmente detectó Wazuh**, ya es otra cosa.

## La parte más difícil

Crear una regla Wazuh no es solamente escribir XML.

Es entender el evento, conocer el motor de reglas, encontrar el orden correcto, usar la condición correcta, afinar el regex y probar todo contra eventos reales.

Y a veces toca repetir el proceso varias veces.

Pero cuando finalmente aparece en Wazuh exactamente la alerta que querías...

ahí uno se toma el café. ☕😎

**En seguridad, detectar bonito sirve poco. Detectar bien sirve mucho.**
