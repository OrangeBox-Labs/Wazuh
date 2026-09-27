# Arquitectura de referencia

La configuración publicada utiliza placeholders para representar una arquitectura Wazuh completa.

```text
                         INTERNET
                             |
                             v
                    +------------------+
                    |  REVERSE PROXY   |
                    |   IP_DE_PROXY    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |     BACKEND      |
                    |  IP_DE_BACKEND   |
                    +------------------+

              +--------------------------+
              |      WAZUH MANAGER       |
              |       IP_DE_WAZUH        |
              +------------+-------------+
                           |
              +------------+------------+
              |                         |
              v                         v
       +-------------+           +-------------+
       |   AGENTE 1  |           |   AGENTE 2  |
       |IP_DE_AGENTE |           |IP_DE_AGENTE |
       +-------------+           +-------------+
                           |
                           v
                  +------------------+
                  |  WAZUH INDEXER   |
                  |  IP_DE_INDEXER   |
                  +------------------+
```

## Componentes

### Wazuh Manager

Centraliza la recepción y procesamiento de eventos, reglas, decoders y respuestas activas.

### Wazuh Indexer

Almacena los datos utilizados para búsqueda, análisis y visualización.

### Agentes

Los agentes recopilan eventos desde los servidores monitorizados y los envían al Manager.

### Reverse proxy

Puede existir delante de aplicaciones web y servicios publicados. Cuando el backend ve al proxy como origen, las reglas deben considerar esa topología.

### Backend

Es el servicio o servidor protegido detrás del reverse proxy.

## Adaptación

Los placeholders deben reemplazarse según la topología de cada organización. La presencia de un proxy, backend o componente adicional depende del despliegue; no es obligatorio implementar todos los componentes.

Consulte también [sanitization.md](sanitization.md).
