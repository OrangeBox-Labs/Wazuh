# Sanitización para publicación

Este repositorio deriva de una implementación real de Wazuh. La versión pública conserva la lógica técnica, pero reemplaza valores específicos de infraestructura.

## Placeholders

| Valor | Representa | Reemplazar por |
|---|---|---|
| `IP_DE_WAZUH` | Wazuh Manager | IP o nombre del Manager |
| `IP_DE_INDEXER` | Wazuh Indexer | IP o nombre del Indexer |
| `IP_DE_PROXY` | Reverse proxy | IP del proxy que recibe conexiones externas y las reenvía al backend |
| `IP_DE_MONITOREO` | Servidor de monitoreo (ej. Zabbix Server) | IP del sistema de monitoreo |
| `IP_DE_ZABBIX_PROXY` | Zabbix Proxy | IP del Zabbix Proxy correspondiente |
| `IP_DE_BACKEND` | Servidor backend | IP del servicio protegido |
| `IP_DE_AGENTE` | Host monitorizado | IP del servidor con Wazuh Agent |
| `IP_DE_SERVIDOR` | Servidor genérico | IP correspondiente al entorno |
| `TU_HOSTNAME` | Nombre DNS de un host | FQDN del entorno |
| `TU_DOMINIO` | Dominio de la organización | Dominio real |
| `TU_EMAIL` | Correo de ejemplo | Dirección de correo real |

## Separación de roles de infraestructura

Los placeholders representan roles distintos y no deben intercambiarse. `IP_DE_WAZUH` identifica exclusivamente al Wazuh Manager; `IP_DE_INDEXER` al Wazuh Indexer; `IP_DE_PROXY` a un reverse proxy; `IP_DE_BACKEND` al backend protegido; `IP_DE_MONITOREO` al servidor de monitoreo; y `IP_DE_ZABBIX_PROXY` a un Zabbix Proxy.

Una etiqueta debe conservar el significado del valor que reemplaza. No se debe usar `IP_DE_PROXY` para representar al Wazuh Manager, al Indexer, a Zabbix ni a un servidor genérico.

## Por qué existen IP_DE_PROXY e IP_DE_BACKEND

Cuando un servicio está publicado detrás de un reverse proxy, el backend puede registrar la dirección del proxy como origen de la conexión. Las reglas de autenticación, abuso y respuesta deben considerar esa topología para no interpretar automáticamente la IP del proxy como el atacante.

`IP_DE_PROXY` representa la dirección del componente que recibe la conexión externa y la reenvía al backend.

`IP_DE_BACKEND` representa el servidor que recibe finalmente la conexión.

Estas excepciones deben adaptarse a la arquitectura real y no deben copiarse sin revisión.

## Valores múltiples y excepciones

Cuando la implementación privada contiene varias IPs con la misma función, la versión pública no debe duplicar la misma etiqueta de placeholder en varias reglas. En su lugar, la excepción se consolida en una CDB y la regla consulta esa lista.

Ejemplo:

```text
etc/lists/orangebox-backuppc-static y etc/lists/orangebox-backuppc-dynamic
```

Las CDB públicas `orangebox-backuppc-static` y `orangebox-backuppc-dynamic` contienen únicamente direcciones de documentación (rangos TEST-NET). En una implementación real se reemplaza por una entrada por cada servidor autorizado.

Esta estrategia evita que la sanitización convierta varios servidores reales en reglas idénticas con el mismo placeholder y deja claro cómo ampliar la configuración sin duplicar SIDs.

Para una IP adicional de una excepción ya existente, agregue la IP a la CDB correspondiente y reinicie el Manager. No cree otra regla solo por la nueva IP.

Si una nueva condición requiere realmente una regla adicional, utilice un ID libre del rango OrangeBox correspondiente y verifique que no exista en ningún otro archivo del ruleset.

## Grupos de clientes

Los grupos específicos de la implementación privada también se anonimizaron en la versión pública. Valores como `CLIENTE_01`, `CLIENTE_02` y `CLIENTE_03` son identificadores genéricos y deben reemplazarse por los grupos que utilice cada organización.

## Archivos excluidos de la réplica pública

No sincronizar automáticamente todo el árbol privado. Algunos archivos son específicos de clientes o sirven solo para pruebas:

- Cron individuales de reportes por cliente bajo `configuration/manager/etc/cron.d/`. En público se mantiene únicamente el ejemplo genérico.
- Listas CDB de clientes o proveedores con IPs autorizadas, como `orangebox-sftp-client-specific`. Esta versión pública conserva únicamente la CDB genérica `orangebox-sftp-authorized` y datos de documentación.
- Reportes temporales/de prueba, como `configuration/manager/reports/reporte-test.py`.
- Artículos y capturas de pruebas que contengan nombres de hosts, dominios, alertas o detalles operacionales de clientes.
- Archivos de estado, caches, logs, volcados, datos exportados o artefactos generados en producción.

Antes de publicar una nueva ruta, comprobar sus referencias desde los scripts, la configuración y la documentación. La ausencia de credenciales no significa que los datos operacionales sean aptos para publicación.

## Regla de publicación

Nunca agregue al repositorio público:

- direcciones IP reales de clientes o infraestructura privada;
- credenciales, contraseñas, tokens o API keys;
- certificados o claves privadas;
- destinatarios reales de alertas;
- nombres internos de servidores;
- información de clientes;
- logs de producción.

El repositorio privado **Wazuh-OrangeBox** permanece como fuente de la implementación real. Este repositorio público es su versión sanitizada.


## CDB de agentes BitNinja

La versión pública incluye la lista genérica orangebox-bitninja-agents para limitar la excepción Who-Data/dpkg 20069. Su entrada example.invalid es solo documentación y debe reemplazarse localmente. Nunca copie al repositorio público el contenido real de esta CDB ni un inventario de hostnames.

## Checklist previo a cada publicación

Antes de sincronizar cambios desde el repositorio privado:

1. Comparar ambos árboles y clasificar cada diferencia como código genérico, configuración parametrizable, dato operacional o artefacto de producción.
2. Revisar IPs públicas y privadas, dominios/FQDN, correos, nombres de grupos/clientes, IDs de agentes, rutas con nombres propios y datos de inventario.
3. Buscar credenciales, tokens, claves privadas, certificados, URLs firmadas y valores de autenticación tanto en archivos como en ejemplos, fixtures y documentación.
4. Mantener la configuración pública existente cuando contenga placeholders o listas genéricas que sustituyen valores reales; no sobrescribirla con la copia privada.
5. Excluir cron y reportes por cliente, CDB operacionales, logs, capturas de alertas reales, bases de datos, exportaciones, paquetes candidatos no aprobados y pruebas que contengan datos identificables.
6. Revisar referencias de los archivos nuevos para detectar dependencias a nombres o rutas excluidos.
7. Ejecutar los tests y validaciones XML/Bash/Python del repositorio público. Para cambios de reglas/CDB, complementar con wazuh-analysisd -t y pruebas positivas/negativas con wazuh-logtest en una instalación compatible.

Una búsqueda automática ayuda, pero no sustituye la revisión contextual. No se deben publicar commits del repositorio privado como un mirror Git ni fusionar su historial: se publican blobs sanitizados y cambios explícitos sobre la rama pública main. Si una credencial real se hubiera publicado previamente, eliminar el archivo en un commit nuevo no invalida la exposición histórica; el secreto debe revocarse/rotarse y, si corresponde, sanearse el historial con un procedimiento separado.
