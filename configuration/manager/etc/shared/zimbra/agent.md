# Perfil FIM Zimbra / Carbonio CE

Este perfil agrupa Zimbra y Carbonio CE como una misma familia operacional para FIM y para la política validada de `sudo -> root`. Zimbra utiliza `/opt/zimbra`; Carbonio CE utiliza `/opt/zextras`.

## Identificación y fuente de verdad

La pertenencia al grupo Wazuh `zimbra` es la fuente de verdad. `update-orangebox-zimbra-agents.sh` consulta ese grupo y genera la CDB dinámica `orangebox-zimbra-agents` con FQDN y hostname corto. El archivo se mantiene en `/var/ossec/etc/lists/` del Manager y no se versiona porque se genera localmente.

La etiqueta `orangebox.profile=zimbra` identifica el perfil en los eventos. La regla `110100` consulta `orangebox-zimbra-agents`; el perfil por sí solo no autoriza comandos SUDO.

## Alcance FIM base

El `agent.conf` incluye controles base para temporales, SSH, identidad, SUDO, PAM, SYSTEMD, CRON, persistencia, red, certificados y firewall. El límite FIM es 175000 entradas y `alert_new_files` permanece activo.

Los archivos sensibles como `shadow`, `gshadow` y claves privadas se monitorizan sin almacenar diffs cuando el contenido podría exponer secretos.

## Rutas específicas del producto

### Temporales

Se vigilan en tiempo real con profundidad limitada:

```text
/opt/zimbra/data/tmp
/opt/zextras/data/tmp
```

No se guarda diff de todos los temporales. Los eventos permiten que las reglas OrangeBox y la integración YARA analicen candidatos sin almacenar contenido indiscriminadamente.

### Jetty / webapps

Se vigilan en tiempo real únicamente extensiones relacionadas con ejecución y despliegue:

```text
/opt/zimbra/jetty/webapps
/opt/zextras/jetty/webapps
```

El filtro se limita a `jsp`, `jspx`, `war` y `class`; no se recorre todo el árbol del producto.

### Configuración y certificados

Se vigilan en tiempo real con Who-Data:

```text
/opt/zimbra/conf
/opt/zextras/conf
/opt/zimbra/ssl
/opt/zextras/ssl
```

Los árboles SSL usan `nodiff`: el evento y su atribución se conservan, pero no se copia el contenido de certificados o claves a las alertas.

### Binarios privilegiados

El perfil limita la vigilancia de binarios a los comandos utilizados por la allowlist `sudo -> root`:

- `zmstat-fd`, `zmqstat`, `zmmtastatus` y `zmmailboxdmgr` bajo `libexec`;
- `postfix`, `postalias`, `qshape.pl`, `postconf`, `postsuper` y `postcat` bajo `common/sbin`.

Se vigilan en tiempo real con Who-Data y filtros `restrict`. No se monitoriza completo `/opt/zimbra` ni `/opt/zextras`.

## Política SUDO

La regla `10005` es el detector general de `sudo -> root`. La regla `110100` solo lleva el evento a nivel 0 cuando se cumplen simultáneamente:

1. el hostname pertenece al grupo Wazuh `zimbra` y está presente en la CDB `orangebox-zimbra-agents`;
2. el ejecutable y sus argumentos pertenecen a la allowlist operacional de Zimbra/Carbonio.

Cualquier otro comando o servidor sigue generando `10005`. La pertenencia al grupo por sí sola no autoriza comandos.

## Dependencias

- Grupo Wazuh `zimbra` y CDB dinámica `orangebox-zimbra-agents` sincronizada.
- Wazuh Agent / Syscheck.
- Who-Data/Audit habilitado para las rutas donde se requiere atribución.
- Reglas `orangebox-auth.xml` y `orangebox-hardening.xml` en el Manager.

## Validación

1. Confirmar la pertenencia al grupo `zimbra`, la etiqueta del perfil y la CDB `orangebox-zimbra-agents`.
2. Ejecutar `update-orangebox-zimbra-agents.sh` y validar la configuración del Manager con `wazuh-analysisd -t`.
3. En laboratorio, crear un archivo temporal y una muestra JSP inocua bajo webapps; verificar los eventos FIM.
4. Modificar una configuración no sensible en `/opt/zimbra/conf` o `/opt/zextras/conf` y revisar Who-Data.
5. Probar `110100` con un comando permitido, el mismo comando fuera del perfil y un comando no permitido.

No realizar estas pruebas con comandos ejecutables ni archivos de aplicación reales en producción.
