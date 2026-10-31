# Scripts auxiliares del Wazuh Manager

Estos scripts mantienen listas CDB y datos locales consumidos por reglas, reportes o respuestas de OrangeBox. Se instalan bajo `/var/ossec/bin/` y se ejecutan normalmente mediante los cron del directorio `configuration/manager/etc/cron.d/`.

## Inventario

| Script | Función | Actualiza | Comportamiento seguro |
|---|---|---|---|
| `update-orangebox-backuppc.sh` | Resuelve las direcciones IPv4 de BackupPC mediante DNS. | CDB dinámica `orangebox-backuppc-dynamic`. | No toca la CDB estática; omite la ejecución si no obtiene direcciones. |
| `update-orangebox-cpanel-agents.sh` | Consulta la pertenencia al grupo Wazuh `cpanel` y genera los nombres admitidos. | CDB `orangebox-cpanel-agents`. | No vacía la lista si falla la consulta; reemplaza el archivo atómicamente cuando cambia. |
| `update-orangebox-dns-agents.sh` | Consulta la pertenencia al grupo Wazuh `dns`. | CDB `orangebox-dns-agents`. | Conserva la lista anterior ante errores o una respuesta vacía no válida. |
| `update-orangebox-zimbra-agents.sh` | Consulta la pertenencia al grupo Wazuh `zimbra`. | CDB `orangebox-zimbra-agents`. | Genera FQDN y nombre corto; evita mantener una whitelist manual de agentes. |
| `update-orangebox-geoip.sh` | Descarga y valida las bases DB-IP City Lite y ASN Lite. | Archivos MMDB de GeoIP. | Valida gzip y lectura MMDB antes de reemplazar; usa reemplazo atómico y no reinicia Wazuh. |
| `update-orangebox-ioc-lists.sh` | Descarga, normaliza y valida fuentes IOC de Emerging Threats, URLhaus y MalwareBazaar. | CDB de IP maliciosas, dominios, IPs que alojan malware y hashes. | Separa IP atacante de IP de hosting, protege la Auth-Key, rechaza entradas inválidas y exige aprobación única para la primera reclasificación de IP de origen. |

## Ciclo común de los sincronizadores de agentes

Los sincronizadores de perfiles siguen este flujo:

1. Adquieren un lock para impedir ejecuciones simultáneas.
2. Consultan los miembros del grupo Wazuh que actúa como fuente de verdad.
3. Normalizan FQDN y nombre corto, sin duplicados.
4. Construyen una CDB temporal y verifican que la salida sea válida.
5. Comparan el resultado con la lista instalada; si no hay cambios, terminan sin reiniciar.
6. Si cambió, reemplazan la CDB atómicamente y recargan el Manager cuando corresponde.
7. Limpian archivos temporales al terminar o ante una interrupción.

Los comentarios junto a las funciones y bucles del código explican el paso concreto que implementan. No se debe transformar un error de consulta en una CDB vacía: eso podría desactivar excepciones de seguridad o dejar reglas sin contexto.

## Actualizador IOC: separación de fuentes

`malicious-ip` contiene IP de origen utilizadas como indicadores de ataque. `malware-host-ip` contiene IP de infraestructura que aloja malware y debe tratarse como IOC de destino. No se mezclan.

La primera separación de datos existentes requiere una revisión explícita:

```bash
ORANGEBOX_IOC_DRY_RUN=1 /var/ossec/bin/update-orangebox-ioc-lists.sh
```

Revisar los conteos `previous/new/added/removed`. Solo después de aprobar la reclasificación inicial se utiliza una vez:

```bash
ORANGEBOX_IOC_ALLOW_SOURCE_RECLASSIFICATION=1 /var/ossec/bin/update-orangebox-ioc-lists.sh
```

El script crea un marcador persistente tras completar correctamente esa migración. Las ejecuciones cron posteriores no necesitan la variable de aprobación.

La Auth-Key de abuse.ch se configura con:

```bash
/var/ossec/bin/update-orangebox-ioc-lists.sh --configure-key
```

Se guarda fuera de Git en un archivo root-only. Nunca se debe pegar una API key en el comando, en un cron o en el repositorio.

## Instalación y validación

Copiar los scripts al Manager conservando permisos y propietario. Antes de habilitar un cron:

- revisar el script y su documentación;
- comprobar que la CDB está declarada en `ossec.conf`;
- ejecutar el script manualmente en modo seguro cuando exista;
- validar con `/var/ossec/bin/wazuh-analysisd -t`;
- confirmar que el cron invoca la ruta instalada real.

Los cron del Manager se encuentran en `configuration/manager/etc/cron.d/`. Los cron individuales de clientes son configuración de producción y no se publican en este repositorio.
