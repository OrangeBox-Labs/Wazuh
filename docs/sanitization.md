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
etc/lists/orangebox-backuppc
```

La CDB pública contiene una IP de documentación como ejemplo. En una implementación real se reemplaza por una entrada por cada servidor autorizado.

Esta estrategia evita que la sanitización convierta varios servidores reales en reglas idénticas con el mismo placeholder y deja claro cómo ampliar la configuración sin duplicar SIDs.

Para una IP adicional de una excepción ya existente, agregue la IP a la CDB correspondiente y reinicie el Manager. No cree otra regla solo por la nueva IP.

Si una nueva condición requiere realmente una regla adicional, utilice un ID libre del rango OrangeBox correspondiente y verifique que no exista en ningún otro archivo del ruleset.

## Grupos de clientes

Los grupos específicos de la implementación privada también se anonimizaron en la versión pública. Valores como `CLIENTE_01`, `CLIENTE_02` y `CLIENTE_03` son identificadores genéricos y deben reemplazarse por los grupos que utilice cada organización.

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
