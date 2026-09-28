# OrangeBox Inventory Rules — Load Order

## Problema de orden de carga

Las reglas personalizadas de OrangeBox se cargan desde:

`/var/ossec/etc/rules/`

mediante:

`<rule_dir>etc/rules</rule_dir>`

Wazuh procesa los archivos de reglas en el orden de sus nombres. Esto es relevante cuando una regla utiliza `<if_sid>` para referenciar otra regla definida en un archivo diferente.

### Caso corregido

`orangebox-00-inventory.xml` define la cadena:

```text
100317
  └── 100318
```

La regla `100318` detecta modificaciones de los grupos privilegiados `wheel` y `sudo`.

El archivo `orangebox-behavior.xml` ya no contiene la cadena experimental `10615`-`10618` que dependía de `10001`, `10004` y `10005`. Esas reglas fueron retiradas porque podían reemplazar la identidad de las alertas base de autenticación antes de que llegaran a la integración de correo.

## Solución

El archivo fue renombrado a:

```text
orangebox-00-inventory.xml
```

El prefijo `00-` mantiene el inventario cargado antes que `orangebox-behavior.xml`. Esto preserva la posibilidad de crear futuras dependencias de reglas sin reintroducir el problema de orden de carga.

La dependencia actualmente relevante dentro del inventario es:

```text
orangebox-00-inventory.xml
        │
        ├── 100317
        │    ├── 100318
        │    └── 100319
        │
        └── 100314
             ├── 100315
             ├── 100316
             └── 100320
```

## Verificación

Después del cambio:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

debe finalizar sin el warning sobre la firma `100318`.

En el incidente original, el mismo comando quedó limpio inmediatamente después de renombrar el archivo.

## ⚠️ ADVERTENCIA — NO CAMBIAR LOS NOMBRES DE LOS ARCHIVOS DE REGLAS

**Los nombres de los archivos bajo `configuration/manager/etc/rules/` son parte de la configuración funcional. No deben renombrarse, eliminarse ni reorganizarse arbitrariamente.**

El orden alfabético de los archivos puede determinar el orden en que Wazuh registra las reglas. Una regla que utiliza:

- `<if_sid>`
- `<if_matched_sid>`
- otras dependencias entre reglas

puede depender de que la regla referenciada haya sido cargada previamente.

Por lo tanto:

1. **No quitar el prefijo `00-` de `orangebox-00-inventory.xml`.**
2. **No volver a llamarlo `orangebox-inventory.xml`.**
3. **No renombrar otros archivos de reglas sin revisar primero sus dependencias.**
4. Si se crea una nueva dependencia entre archivos, comprobar el orden de carga antes de desplegar.
5. Validar siempre la configuración con:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

Un warning de tipo `Signature ID 'XXXXX' was not found` en un `if_sid` puede indicar precisamente que una dependencia está siendo cargada después de la regla que la necesita.

## Regla práctica

Cuando una regla de un archivo A depende mediante `if_sid` de una regla definida en un archivo B:

```text
B debe cargarse antes que A
```

Si el orden alfabético natural no lo garantiza, utilizar un prefijo de orden explícito en el nombre del archivo, como se hizo con:

```text
orangebox-00-inventory.xml
```

No cambiar los IDs de las reglas para solucionar un problema de orden de carga: el ID identifica la regla; el nombre del archivo controla su posición dentro del conjunto de archivos cargados.
