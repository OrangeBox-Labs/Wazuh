# Perfil FIM Zimbra / Carbonio CE

Este perfil agrupa Zimbra y Carbonio CE como una misma familia operacional para FIM y para la política validada de `sudo -> root`. Carbonio utiliza `/opt/zextras`; Zimbra utiliza `/opt/zimbra`.

## Identificación del perfil

La etiqueta `orangebox.profile=zimbra` identifica el perfil en los eventos. La regla `110100` consulta la CDB dinámica `orangebox-zimbra-agents`, generada desde la pertenencia al grupo Wazuh `zimbra` mediante `update-orangebox-zimbra-agents.sh`.

## Alcance FIM

El archivo `agent.conf` incluye el conjunto de controles base que se necesita en este perfil y agrega las rutas específicas del servicio. El límite de FIM es de 175000 entradas y `alert_new_files` permanece activo.

### Temporales

Se vigilan en tiempo real, con profundidad recursiva limitada:

```text
/opt/zimbra/data/tmp
/opt/zextras/data/tmp
```

No se guarda diff de todos los archivos temporales. Los eventos sirven para que las reglas OrangeBox y la integración YARA puedan analizar candidatos sin almacenar contenido de forma indiscriminada.

### Jetty / webapps

En los árboles de aplicaciones Jetty se vigilan en tiempo real únicamente extensiones de interés para ejecución o despliegue:

```text
/opt/zimbra/jetty/webapps
/opt/zextras/jetty/webapps
```

El filtro se limita a `jsp`, `jspx`, `war` y `class`. No se recorre indiscriminadamente cada archivo del producto.

### Configuración y certificados

Se vigilan en tiempo real con Who-Data:

```text
/opt/zimbra/conf
/opt/zextras/conf
/opt/zimbra/ssl
/opt/zextras/ssl
```

Los árboles SSL usan `nodiff`: se registra que hubo un cambio y quién/proceso lo realizó, pero no se copia el contenido de certificados o claves a las alertas.

### Binarios privilegiados

El perfil limita la vigilancia de binarios a los comandos que forman parte de la allowlist `sudo -> root` de `orangebox-auth.xml`:

- `zmstat-fd`, `zmqstat`, `zmmtastatus` y `zmmailboxdmgr` bajo `libexec`;
- `postfix`, `postalias`, `qshape.pl`, `postconf`, `postsuper` y `postcat` bajo `common/sbin`.

Se vigilan en tiempo real con Who-Data y con filtros `restrict`. No se monitoriza completo `/opt/zimbra` ni `/opt/zextras`.

## Política SUDO

La regla `10005` es el detector general de `sudo -> root`. La regla `110100` solo la lleva a nivel 0 cuando se cumplen simultáneamente:

el hostname está registrado en la CDB `orangebox-zimbra-agents` (generada desde el grupo Wazuh `zimbra`);
2. el ejecutable y sus argumentos pertenecen a la allowlist de operaciones conocidas.

Cualquier otro comando o servidor sigue generando `10005`. El perfil por sí solo no autoriza comandos.

## Dependencias

- Grupo Wazuh `zimbra` y CDB `orangebox-zimbra-agents` sincronizada.
- CDB `orangebox-zimbra-agents` sincronizada con el grupo Wazuh `zimbra`.
- Wazuh Agent / Syscheck.
- Who-Data/Audit habilitado para las rutas donde se requiere atribución.
- Reglas `orangebox-auth.xml` y `orangebox-hardening.xml` en el Manager.

## Validación

1. Confirmar el grupo `zimbra`, la etiqueta del perfil y ambas CDB.
2. Comprobar la configuración efectiva con `wazuh-analysisd -t` en el Manager y revisar el grupo compartido recibido por el agente.
3. En laboratorio, crear un archivo temporal y una muestra JSP inocua bajo webapps; verificar eventos FIM.
4. Modificar una configuración no sensible en `/opt/zimbra/conf` o `/opt/zextras/conf` y verificar Who-Data.
5. Probar `110100` con un comando permitido, el mismo comando fuera del perfil y un comando no permitido.

No realizar estas pruebas con comandos ejecutables ni archivos de aplicación reales en producción.
