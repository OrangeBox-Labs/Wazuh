# OrangeBox Temporary Executable

Documentación de `orangebox-temporary-executable.xml`.

## Para qué sirve

Detecta ejecutables que aparecen o pasan a ser ejecutables dentro de:

- `/tmp/`
- `/var/tmp/`
- `/dev/shm/`

La regla no pregunta quién creó el archivo ni cómo se llama. Le interesa una sola cosa: **un archivo ejecutable apareció en un lugar donde no debería ser una forma normal de persistencia o ejecución**.

Por política FIM de OrangeBox, las modificaciones de archivos existentes basadas solo en permisos, mtime, inode u otros metadatos no generan alertas personalizadas. En este archivo la detección FIM se limita a archivos nuevos mediante `554`.

## Reglas

### 10410 — Archivo creado ya ejecutable

Parte de FIM `554` (archivo agregado).

Busca un archivo nuevo en los tres directorios temporales y verifica que sus permisos incluyan ejecución.

Ejemplo típico:

```bash
install -m 755 /dev/null /dev/shm/test
```

No se filtra por extensión porque un atacante puede llamar al ejecutable como quiera. Tampoco se inspecciona contenido: esa evaluación queda para una capa posterior de análisis de contenido. Las firmas YARA versionadas en este repositorio son actualmente experimentales y no están conectadas de forma automática a esta regla.

**Nivel 15:** un ejecutable nuevo en un directorio temporal merece atención inmediata.

## Por qué no se filtra por nombre o extensión

Porque sería muy fácil de esquivar. `malware.sh` es sospechoso, pero `update` también puede serlo si aparece ejecutable en `/dev/shm`.

La detección busca la propiedad que realmente interesa: **ejecución + directorio temporal**.

## Excepciones / whitelist

Las excepciones son deliberadamente específicas y siempre parten de la regla de detección correspondiente.

### 20040 — Dracut

Silencia `10410` exclusivamente para:

```text
/var/tmp/dracut.*
```

`dracut` puede crear árboles temporales durante la construcción de initramfs. No se excluye `/var/tmp` completo.

### 20042 — ClamAV

Silencia `10410` para archivos bajo el patrón:

```text
/var/tmp/clamav-<32 hex>.tmp/...
```

La excepción se limita al árbol temporal con nombre característico de ClamAV.
No se excluye `/var/tmp` completo.

Se eliminó la condición anterior basada en `uname_after` porque los datos del
propietario forman parte del objeto FIM/syscheck; la excepción debe basarse en
el patrón de ruta validado del temporal de ClamAV.

### 20043 — Socket MySQL

Silencia `10410` exclusivamente para:

```text
/var/tmp/mysql.sock
```

Motivo: un socket Unix puede aparecer con permisos `rwxrwxrwx`; la regla `10410` actualmente identifica la ejecución a partir del campo de permisos y, por ello, puede confundir un socket con un archivo ejecutable.

La excepción no se amplía a otros `*.sock`: se limita al socket MySQL validado.

Este caso demuestra una limitación importante del criterio de `10410`: **permiso de ejecución no equivale necesariamente a archivo regular ejecutable**.

Las excepciones no reemplazan la detección general. Un archivo distinto que aparezca ejecutable bajo `/tmp`, `/var/tmp` o `/dev/shm` continúa generando `10410`.

## Dependencias

- Wazuh FIM/syscheck.
- `554`: archivo agregado.
- `550`: archivo modificado.

Esta capa detecta el comportamiento. No pretende decidir si el archivo es malware; para eso podrá complementarse posteriormente con una capa de análisis de contenido y otras evidencias.
