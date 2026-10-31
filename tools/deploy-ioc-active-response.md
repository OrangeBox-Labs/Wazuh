# Deploy de Active Response IOC

Script: `tools/deploy-ioc-active-response.sh`.

Este instalador aplica correcciones conocidas de respuesta IOC, detección web y PHP2Shell sobre una instalación ya existente del Wazuh Manager. No descarga ni actualiza feeds IOC.

## Ciclo de ejecución

1. Comprueba root, el Wazuh Manager y el grupo propietario de `ossec.conf`.
2. Crea una copia de seguridad de todos los archivos que va a tocar.
3. Conserva los parámetros propios del Manager y modifica únicamente los bloques Active Response definidos por OrangeBox.
4. Instala o preserva la lista de fuentes IOC confirmadas si forma parte del despliegue.
5. Valida los archivos y la configuración.
6. Ejecuta las pruebas disponibles.
7. Reinicia `wazuh-manager` solo después de validar.
8. Si falla un paso protegido, restaura los archivos respaldados y registra el error.

La limpieza temporal se realiza mediante `cleanup()`; el bloque de rollback restaura el estado anterior y evita dejar una configuración parcialmente aplicada.

## Diferencia con el actualizador IOC

- Este script despliega configuración y reglas Active Response.
- `update-orangebox-ioc-lists.sh` descarga, valida y actualiza las CDB.

No mezclar ambas operaciones: la primera reclasificación de IOC requiere revisión manual y no debe ocurrir como efecto lateral de un deploy.

## Uso

Ejecutar desde el checkout y como root:

```bash
sudo bash tools/deploy-ioc-active-response.sh
```

Revisar el resumen y la copia creada bajo `/var/backups/orangebox-wazuh-ioc-deploy/`. No ejecutar desde una copia de trabajo que contenga modificaciones no revisadas.
