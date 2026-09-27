# Configuration

Los árboles desplegables reproducen directamente la raíz de instalación de Wazuh.

```text
configuration/manager/       -> /var/ossec
configuration/agents/common/ -> /var/ossec o /opt/ossec
```

## Árbol

```text
configuration/
├── manager/
│   ├── etc/
│   │   ├── ossec.conf
│   │   ├── decoders/
│   │   ├── lists/
│   │   ├── rules/
│   │   └── shared/
│   │       ├── default/agent.conf
│   │       ├── cpanel/agent.conf
│   │       └── zimbra/agent.conf
│       └── webserver/agent.conf
│   ├── integrations/
│   └── reports/
└── agents/
    └── common/
        └── active-response/
            └── bin/
                └── orangebox-yara.sh
```

Las firmas YARA no se versionan dentro de este repositorio. Los agentes las obtienen exclusivamente desde:

```text
https://github.com/Yara-Rules/rules
```

El instalador deja las firmas bajo:

```text
< WAZUH_HOME >/active-response/bin/yara/rules/yara-rules/
```

y registra el repositorio, branch y commit en `YARA-RULES-*`.

## Perfiles FIM

### default

Politica base Linux. Se centra en:

- temporales: `/tmp`, `/var/tmp`, `/dev/shm`;
- SSH, sudoers, PAM, Polkit e identidad;
- systemd, cron, shell startup y loader;
- firewall, DNS, montajes, sysctl y CA anchors;
- un conjunto reducido de binarios de autenticación y privilegios.

No incluye por defecto los árboles completos de Zimbra/Carbonio, `/root`, `/var`, `/etc/sysconfig` ni librerías completas.

### cpanel

Hereda la política base y agrega:

- código ejecutable/configurable en `/home/*/public_html`;
- EasyApache y Apache;
- cPanel y su configuración de control;
- Exim ACLs y configuración persistente;
- CSF e Imunify360.

### zimbra

Hereda la política base y es el único perfil que incorpora:

- `/opt/zimbra`;
- `/opt/zextras`;
- temporales;
- webapps Jetty;
- configuración y SSL sin diffs de secretos;
- binarios privilegiados utilizados por la política de sudo.

Zimbra/Carbonio no deben aparecer en `default/agent.conf`.

## Modos de FIM

```text
realtime
    Detección continua en directorios donde el tiempo de respuesta importa.

report_changes
    Guarda evidencia del contenido modificado. Se reserva para
    configuraciones y artefactos donde el diff tiene valor forense.

whodata
    Registra el usuario/proceso asociado al cambio.

scheduled
    Sin realtime: el elemento se revisa durante los scans periódicos de FIM.
```

La frecuencia base de FIM sigue siendo 12 horas en el `ossec.conf` del Manager. No se aumenta `file_limit` por ahora: primero se reduce el alcance y se mide nuevamente el tamaño de la base FIM.

## YARA

Los eventos FIM `554`/`550` que coinciden con el alcance definido por `10420`/`10421` activan `orangebox-yara.sh`.

El script analiza solo el archivo afectado contra:

```text
webshells_index.yar
malware_index.yar
```

del repositorio oficial Yara-Rules.

Una coincidencia se registra como:

```text
wazuh-yara: ALERT - Match: category=webshells rule=<RULE> path=/ruta/archivo
```

El Manager decodifica esa línea y genera la alerta `10501` nivel 14.

El Active Response es exclusivamente de detección: no elimina, mueve ni pone en cuarentena archivos.

## Documentación

La documentación técnica se mantiene junto al archivo que documenta, con el mismo nombre base y extensión `.md`. Esto permite revisar configuración y explicación en el mismo directorio, sin mantener un árbol documental separado.

Ejemplos: `ossec.conf` + `ossec.md`, `orangebox-auth.xml` + `orangebox-auth.md` y `agent.conf` + `agent.md`.
