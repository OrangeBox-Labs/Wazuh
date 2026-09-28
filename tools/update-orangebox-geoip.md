# GeoIP local DB-IP Lite

El manager de Wazuh utiliza una base GeoIP local para enriquecer los reportes con país, región y ciudad, sin consultar una API por cada IP.

## Bases instaladas

`/var/lib/orangebox/geoip/dbip-city-lite.mmdb`

Contiene país, región/estado, ciudad y coordenadas aproximadas.

`/var/lib/orangebox/geoip/dbip-asn-lite.mmdb`

Contiene número y organización ASN.

DB-IP Lite publica las bases en formato MMDB y las actualiza mensualmente. La release de septiembre de 2026 de City Lite tiene 7.748.998 registros y un tamaño de 121,4 MB; ASN Lite tiene 473.272 registros y 9,1 MB.

## Actualizador

Script:

```text
tools/update-orangebox-geoip.sh
```

El updater:

1. determina la release del mes actual y, si todavía no está publicada, prueba la del mes anterior;
2. evita descargar nuevamente una release que ya está instalada;
3. descarga el MMDB solo cuando hay una release nueva disponible;
4. verifica la integridad gzip;
5. consulta `mmdblookup` para confirmar que la base funciona;
6. reemplaza el MMDB de forma atómica;
7. conserva la base actual ante cualquier error;
8. no reinicia `wazuh-manager`.

Se usa `mmdblookup` porque el manager ya dispone de `libmaxminddb` y de esa utilidad.

## Instalación

Después de actualizar el repositorio:

```bash
install -o root -g root -m 0750 \
  tools/update-orangebox-geoip.sh \
  /usr/local/sbin/update-orangebox-geoip.sh

/usr/local/sbin/update-orangebox-geoip.sh
```

La primera ejecución descargará aproximadamente 130 MB entre City Lite y ASN Lite.

## Actualización periódica

Como DB-IP Lite es mensual, conviene ejecutar el updater diariamente. El coste normal es mínimo porque la versión instalada queda registrada y el updater solo intenta la descarga cuando aparece una release mensual nueva.

Bloque para `/etc/cron.d/orangebox-geoip`:

```cron
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
20 3 * * * root /usr/local/sbin/update-orangebox-geoip.sh >> /var/log/orangebox-geoip-update.log 2>&1
```

La ejecución queda programada todos los días a las 03:20. El usuario es `root` porque el updater debe escribir en `/var/lib/orangebox/geoip` y reemplazar las bases de forma atómica.

Para instalarlo manualmente:

```bash
cat > /etc/cron.d/orangebox-geoip <<'EOF'
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
20 3 * * * root /usr/local/sbin/update-orangebox-geoip.sh >> /var/log/orangebox-geoip-update.log 2>&1
EOF

chown root:root /etc/cron.d/orangebox-geoip
chmod 0644 /etc/cron.d/orangebox-geoip
```

Verificación:

```bash
cat /etc/cron.d/orangebox-geoip
ls -l /etc/cron.d/orangebox-geoip
```

Cuando aparece una release nueva, se descarga y valida automáticamente.

### Rutas usadas por el reporte

La base de producción se instala en:

```text
/var/lib/orangebox/geoip/dbip-city-lite.mmdb
```

El reporte puede recibir una ruta alternativa mediante:

```text
ORANGEBOX_GEOIP_CITY_DB
```

La configuración por defecto del reporte apunta a `/var/lib/orangebox/geoip/dbip-city-lite.mmdb`. El script de prueba GeoIP puede probar además rutas alternativas antes de recurrir a su mecanismo de respaldo.

El updater instala siempre las bases en `/var/lib/orangebox/geoip`, por lo que no requiere modificar Wazuh ni `ossec.conf`.

## Licencia y atribución

DB-IP Lite se distribuye bajo CC BY 4.0 y requiere atribución a DB-IP. El reporte ya incluye la atribución correspondiente.

## Instalación automática

Desde la raíz del repositorio, como root:

```bash
install -o root -g root -m 0750 \
  tools/install-orangebox-geoip.sh \
  /usr/local/sbin/install-orangebox-geoip.sh

/usr/local/sbin/install-orangebox-geoip.sh
```

El instalador copia el updater a `/usr/local/sbin`, crea `/etc/cron.d/orangebox-geoip`, prepara `/var/lib/orangebox/geoip` y ejecuta la primera actualización.
