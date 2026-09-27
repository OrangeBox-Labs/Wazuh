# Actualizador de listas IOC

El script `update-orangebox-ioc-lists.sh` descarga y valida las listas de indicadores de compromiso utilizadas por OrangeBox.

## Fuentes

- URLhaus: IP y dominios asociados a URLs recientes.
- Emerging Threats: IPs comprometidas.
- MalwareBazaar: hashes SHA-256 recientes, cuando se configura la clave de acceso.

## Seguridad

El script:

1. descarga las fuentes a un directorio temporal;
2. valida el formato;
3. compara el tamaño y los cambios con las listas actuales;
4. rechaza una caída grande e inesperada de indicadores;
5. instala las listas solo cuando son distintas.

## Reinicio de Wazuh

Wazuh necesita recargar las CDB cuando cambian sus listas. Por eso:

- **si no cambió ninguna lista:** no se reinicia `wazuh-manager`;
- **si cambió una o más listas:** se instalan y se reinicia `wazuh-manager`.

Esto evita reinicios innecesarios cada vez que se ejecuta el actualizador.

## MalwareBazaar

La lista de hashes solo se reemplaza cuando:

- existe una clave válida;
- la API responde correctamente;
- se obtienen hashes SHA-256 válidos.

Ante un error, la lista existente se conserva.

## Operación

El actualizador está pensado para ejecutarse periódicamente mediante cron o systemd timer.

No se debe ejecutar con una clave de MalwareBazaar escrita en el repositorio público. La clave debe entregarse mediante la instalación o una variable de entorno segura.
