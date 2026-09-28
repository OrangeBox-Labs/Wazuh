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

La API gratuita de DB-IP tiene un límite de 500 consultas diarias; el script limita las consultas nuevas por ejecución a 450 por defecto y reutiliza la caché. Para producción conviene utilizar la base MMDB local, no depender de la API.

## Ejecución de prueba

El formato de argumentos es el mismo que el reporte detallado actual:

```bash
python3 /var/ossec/reports/orangebox-detailed-security-report-geoip-test.py \
  --today \
  --group CTS \
  --email soporte@orangebox.cl \
  --dry-run
```

El `--dry-run` genera el HTML pero no envía correo.

Para una prueba real de correo:

```bash
python3 /var/ossec/etc/reports/orangebox-detailed-security-report-geoip-test.py \
  --today \
  --group CTS \
  --email soporte@orangebox.cl
```

Ajustar la ruta al directorio real donde estén instalados los reportes.

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

Para producción recomiendo DB-IP Lite MMDB local. La versión Lite se actualiza mensualmente y está licenciada bajo CC BY 4.0; requiere atribución a DB-IP.

La ubicación por IP es aproximada y no representa necesariamente la ubicación física real del atacante.

Fuentes:

- DB-IP Lite: https://db-ip.com/db/lite.php
- DB-IP City Lite MMDB: https://db-ip.com/db/format/ip-to-city-lite/mmdb.html
- DB-IP Free API: https://db-ip.com/api/free
