# Sanitización para publicación

Este repositorio deriva de una implementación real de Wazuh. La versión pública conserva la lógica técnica, pero reemplaza valores específicos de infraestructura.

## Placeholders

| Valor | Representa | Reemplazar por |
|---|---|---|
| `IP_DE_WAZUH` | Wazuh Manager | IP o nombre del Manager |
| `IP_DE_INDEXER` | Wazuh Indexer | IP o nombre del Indexer |
| `IP_DE_PROXY` | Reverse proxy | IP del proxy que origina conexiones hacia el backend |
| `IP_DE_BACKEND` | Servidor backend | IP del servicio protegido |
| `IP_DE_AGENTE` | Host monitorizado | IP del servidor con Wazuh Agent |
| `IP_DE_SERVIDOR` | Servidor genérico | IP correspondiente al entorno |
| `TU_HOSTNAME` | Nombre DNS de un host | FQDN del entorno |
| `TU_DOMINIO` | Dominio de la organización | Dominio real |
| `TU_EMAIL` | Correo de ejemplo | Dirección de correo real |

## Por qué existen IP_DE_PROXY e IP_DE_BACKEND

Cuando un servicio está publicado detrás de un reverse proxy, el backend puede registrar la dirección del proxy como origen de la conexión. Las reglas de autenticación, abuso y respuesta deben considerar esa topología para no interpretar automáticamente la IP del proxy como el atacante.

`IP_DE_PROXY` representa la dirección del componente que recibe la conexión externa y la reenvía al backend.

`IP_DE_BACKEND` representa el servidor que recibe finalmente la conexión.

Estas excepciones deben adaptarse a la arquitectura real y no deben copiarse sin revisión.

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
