# Reporte detallado Wazuh + GeoIP (TEST)

Archivo de prueba:

`orangebox-detailed-security-report-geoip-test.py`

Este reporte **no modifica**:

- `orangebox-security-report.py`
- `orangebox-detailed-security-report.py`
- `custom-orangebox-email.py`
- `/var/ossec/etc/ossec.conf`

## Qué agrega

Al reporte detallado existente añade dos secciones:

1. **Geolocalización de IPs de origen**
   - IP pública observada
   - país
   - región/estado
   - ciudad
   - cantidad de servidores donde fue observada

2. **IPs bloqueadas automáticamente · GeoIP**
   - IP
   - país
   - región/estado
   - ciudad
   - motivo
   - cantidad de bloqueos

Las IP privadas/reservadas se excluyen del lookup GeoIP.

## Fuente para la prueba

El script intenta primero una base MMDB local de DB-IP Lite si existe:

- `/var/ossec/reports/geoip/dbip-city-lite.mmdb`
- `/var/ossec/reports/geoip/dbip-asn-lite.mmdb`

Si no existe una base local operativa, usa como fallback la **DB-IP Free API** y guarda los resultados en:

`/var/ossec/reports/geoip-cache.json`

La ejecución limita las consultas nuevas a 450 por defecto y reutiliza la caché. Para producción conviene utilizar una base MMDB local, evitando depender de una API externa para cada reporte.

## Ejecución de prueba

Instala el script de prueba junto al reporte detallado, por ejemplo:

`/var/ossec/reports/orangebox-detailed-security-report-geoip-test.py`

Prueba sin enviar correo:

```bash
python3 /var/ossec/reports/orangebox-detailed-security-report-geoip-test.py \
  --today \
  --group CTS \
  --email soporte@example.com \
  --dry-run
```

Para una prueba real de correo:

```bash
python3 /var/ossec/reports/orangebox-detailed-security-report-geoip-test.py \
  --today \
  --group CTS \
  --email soporte@example.com
```

El archivo genera el HTML mediante el mismo motor del reporte detallado y conserva el reporte de producción sin modificaciones.

## Variables opcionales

```text
ORANGEBOX_GEOIP_CITY_DB
ORANGEBOX_GEOIP_ASN_DB
ORANGEBOX_GEOIP_CACHE
ORANGEBOX_GEOIP_CACHE_DAYS
ORANGEBOX_GEOIP_MAX_IPS
ORANGEBOX_GEOIP_MAX_NEW_LOOKUPS
ORANGEBOX_GEOIP_API_URL
```

## Producción

Para producción recomiendo DB-IP Lite MMDB local. La geolocalización por IP es aproximada y no representa necesariamente la ubicación física real del origen.

Fuentes:

- DB-IP Lite: https://db-ip.com/db/lite.php
- DB-IP City Lite MMDB: https://db-ip.com/db/format/ip-to-city-lite/mmdb.html
- DB-IP Free API: https://db-ip.com/api/free
