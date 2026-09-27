# wazuh.install.cpanel.sh

Instalador OrangeBox para **Wazuh Agent 4.14.7 OPT** en servidores cPanel con CSF/LFD.

## Características

- Utiliza `packages/agent/wazuh-agent_4.14.7-0_x86_64_OPT.rpm`.
- El RPM especial instala Wazuh bajo `/opt/ossec`.
- No crea ni utiliza `/var/ossec`.
- Pregunta y confirma:
  - nombre/hostname del agente;
  - Wazuh Manager;
  - grupo;
  - password de enrolamiento.
- La password nunca se muestra.
- El `agent.conf` no se instala localmente: el agente hereda la configuración centralizada desde el Manager.

## CSF

Agrega, de forma idempotente, los puertos Wazuh al `TCP_OUT`:

```text
1514,1515
```

También instala:

```text
/usr/local/sbin/orangebox-firewall
```

El helper crea la cadena:

```text
ORANGEBOX-FW
```

Registra únicamente TCP SYN externos antes de continuar con `RETURN`. Si el servidor está detrás de un NAT completo (por ejemplo GCP), el instalador detecta el par IP pública/IP privada y excluye únicamente el hairpin `IP_PUBLICA -> IP_PRIVADA`, para evitar que el propio servidor genere falsos intentos desde su IP pública.

La persistencia se realiza mediante el hook real utilizado por CSF en estos servidores:

```text
/usr/local/csf/bin/csfpost.sh
```

El instalador no reemplaza el contenido existente del hook: agrega la llamada al helper OrangeBox.

Después ejecuta:

```text
csf -r
```

y valida:

- cadena `ORANGEBOX-FW`;
- conexión desde `INPUT`;
- `TCP_OUT` con 1514 y 1515.

## RPM local

Por defecto busca el RPM relativo al instalador:

```text
../packages/agent/wazuh-agent_4.14.7-0_x86_64_OPT.rpm
```

También puede indicarse otra ruta:

```bash
WAZUH_AGENT_RPM=/ruta/al/wazuh-agent_4.14.7-0_x86_64_OPT.rpm ./wazuh.install.cpanel.sh
```

## Ejecución

Desde el checkout del repositorio:

```bash
cd tools
./wazuh.install.cpanel.sh
```

Debe ejecutarse como `root`.

## Principio

El instalador modifica solamente lo necesario para este perfil:

```text
Wazuh Agent OPT
        |
        +-- /opt/ossec
        |
        +-- CSF TCP_OUT 1514,1515
        |
        +-- ORANGEBOX-FW
        |
        +-- /usr/local/csf/bin/csfpost.sh
```

La configuración de logs cPanel, Apache, Exim, Imunify360 y demás fuentes queda centralizada en el grupo Wazuh correspondiente.
