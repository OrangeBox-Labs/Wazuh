#!/usr/bin/env python3
"""OrangeBox - Reporte detallado Wazuh con GeoIP (TEST).

No modifica el reporte de producción ni la configuración de Wazuh.

El motor de agregación/renderizado reutiliza:
  configuration/manager/reports/orangebox-detailed-security-report.py

GeoIP:
  1) Preferencia: DB-IP City Lite MMDB (+ ASN Lite MMDB opcional).
  2) Fallback para pruebas: DB-IP Free API.
  3) Resultados cacheados en /var/ossec/reports/geoip-cache.json.

Variables opcionales:
  ORANGEBOX_GEOIP_CITY_DB
  ORANGEBOX_GEOIP_ASN_DB
  ORANGEBOX_GEOIP_CACHE
  ORANGEBOX_GEOIP_CACHE_DAYS
  ORANGEBOX_GEOIP_MAX_IPS
  ORANGEBOX_GEOIP_MAX_NEW_LOOKUPS
  ORANGEBOX_GEOIP_API_URL

La geolocalización es aproximada y no debe interpretarse como ubicación
física exacta. El informe incluye atribución a DB-IP.
"""

import html
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROD_REPORT = BASE_DIR / "orangebox-detailed-security-report.py"

DEFAULT_CACHE = Path("/var/ossec/reports/geoip-cache.json")
DEFAULT_API = "http://api.db-ip.com/v2/free/{ip}"
DEFAULT_MAX_IPS = 100
DEFAULT_MAX_NEW_LOOKUPS = 450
DEFAULT_CACHE_DAYS = 30


def esc(value):
    return html.escape(str(value), quote=True)


def load_prod_module():
    spec = importlib.util.spec_from_file_location(
        "orangebox_detailed_security_report_prod",
        PROD_REPORT,
    )
    if spec is None or spec.loader is None:
        raise SystemExit(f"No se pudo cargar {PROD_REPORT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def now_utc():
    return datetime.now(timezone.utc)


class GeoIPResolver:
    def __init__(self):
        self.cache_path = Path(os.environ.get("ORANGEBOX_GEOIP_CACHE", str(DEFAULT_CACHE)))
        self.cache_days = int(os.environ.get("ORANGEBOX_GEOIP_CACHE_DAYS", str(DEFAULT_CACHE_DAYS)))
        self.max_new_lookups = int(
            os.environ.get(
                "ORANGEBOX_GEOIP_MAX_NEW_LOOKUPS",
                str(DEFAULT_MAX_NEW_LOOKUPS),
            )
        )
        self.api_url = os.environ.get("ORANGEBOX_GEOIP_API_URL", DEFAULT_API)
        self.city_db = self._first_existing(
            os.environ.get("ORANGEBOX_GEOIP_CITY_DB", ""),
            "/var/ossec/reports/geoip/dbip-city-lite.mmdb",
            "/var/ossec/etc/geoip/dbip-city-lite.mmdb",
            "/var/lib/orangebox/geoip/dbip-city-lite.mmdb",
        )
        self.asn_db = self._first_existing(
            os.environ.get("ORANGEBOX_GEOIP_ASN_DB", ""),
            "/var/ossec/reports/geoip/dbip-asn-lite.mmdb",
            "/var/ossec/etc/geoip/dbip-asn-lite.mmdb",
            "/var/lib/orangebox/geoip/dbip-asn-lite.mmdb",
        )
        self._city_reader = None
        self._asn_reader = None
        self._city_import_error = None
        self.new_queries = 0
        self.api_exhausted = False
        self.errors = []
        self.cache = self._load_cache()

    @staticmethod
    def _first_existing(*paths):
        for value in paths:
            if value and Path(value).is_file():
                return Path(value)
        return None

    def _load_cache(self):
        if not self.cache_path.is_file():
            return {}
        try:
            with self.cache_path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
            return payload if isinstance(payload, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _save_cache(self):
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump(self.cache, fh, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, self.cache_path)
        except OSError as exc:
            self.errors.append(f"No se pudo guardar la caché GeoIP: {exc}")

    def _get_readers(self):
        if not self.city_db:
            return None, None
        if self._city_reader is not None:
            return self._city_reader, self._asn_reader
        try:
            import maxminddb
            self._city_reader = maxminddb.open_database(str(self.city_db))
            if self.asn_db:
                self._asn_reader = maxminddb.open_database(str(self.asn_db))
        except Exception as exc:
            self._city_import_error = str(exc)
            self._city_reader = None
            self._asn_reader = None
        return self._city_reader, self._asn_reader

    @staticmethod
    def _localize_name(value, preferred=("es", "en")):
        if isinstance(value, dict):
            for lang in preferred:
                if value.get(lang):
                    return str(value[lang])
            for item in value.values():
                if item:
                    return str(item)
        return str(value) if value else ""

    @staticmethod
    def _mmdblookup_text(db, ip, *path):
        if shutil.which("mmdblookup") is None:
            return ""
        try:
            result = subprocess.run(
                ["mmdblookup", "--file", str(db), "--ip", str(ip), *path],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if result.returncode != 0:
            return ""
        for line in result.stdout.splitlines():
            match = re.match(r'^\s*"((?:\\.|[^"])*)"\s*<utf8_string>', line)
            if match:
                try:
                    return json.loads(f'"{match.group(1)}"')
                except json.JSONDecodeError:
                    return match.group(1)
        return ""

    @staticmethod
    def _mmdblookup_uint32(db, ip, *path):
        if shutil.which("mmdblookup") is None:
            return ""
        try:
            result = subprocess.run(
                ["mmdblookup", "--file", str(db), "--ip", str(ip), *path],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if result.returncode != 0:
            return ""
        match = re.search(r'(?m)^\s*(\d+)\s*<uint32>', result.stdout)
        return match.group(1) if match else ""

    def _lookup_mmdblookup(self, ip):
        if not self.city_db:
            return None

        country_code = self._mmdblookup_text(self.city_db, ip, "country", "iso_code")
        country = (
            self._mmdblookup_text(self.city_db, ip, "country", "names", "es")
            or self._mmdblookup_text(self.city_db, ip, "country", "names", "en")
        )
        region = (
            self._mmdblookup_text(self.city_db, ip, "subdivisions", "0", "names", "es")
            or self._mmdblookup_text(self.city_db, ip, "subdivisions", "0", "names", "en")
        )
        city = (
            self._mmdblookup_text(self.city_db, ip, "city", "names", "es")
            or self._mmdblookup_text(self.city_db, ip, "city", "names", "en")
        )

        if not any((country_code, country, region, city)):
            return None

        result = {
            "country_code": country_code.upper(),
            "country": country,
            "region": region,
            "city": city,
            "asn": "",
            "asn_org": "",
            "source": "DB-IP City Lite MMDB (mmdblookup)",
        }

        if self.asn_db:
            result["asn"] = self._mmdblookup_uint32(
                self.asn_db, ip, "autonomous_system_number"
            )
            result["asn_org"] = (
                self._mmdblookup_text(
                    self.asn_db, ip, "autonomous_system_organization"
                )
                or ""
            )
            if result["asn"] or result["asn_org"]:
                result["source"] = "DB-IP City Lite + ASN Lite MMDB (mmdblookup)"

        return result

    def _lookup_mmdb(self, ip):
        city_reader, asn_reader = self._get_readers()

        if city_reader is not None:
            city_record = city_reader.get(ip) or {}
            country = city_record.get("country") or {}
            city = city_record.get("city") or {}
            subdivisions = city_record.get("subdivisions") or []
            subdivision = subdivisions[0] if subdivisions else {}

            result = {
                "country_code": str(country.get("iso_code") or "").upper(),
                "country": self._localize_name(country.get("names")),
                "region": self._localize_name(subdivision.get("names")),
                "city": self._localize_name(city.get("names")),
                "asn": "",
                "asn_org": "",
                "source": "DB-IP City Lite MMDB",
            }

            if asn_reader is not None:
                asn_record = asn_reader.get(ip) or {}
                result["asn"] = str(asn_record.get("autonomous_system_number") or "")
                result["asn_org"] = str(
                    asn_record.get("autonomous_system_organization") or ""
                )
                result["source"] = "DB-IP City Lite + ASN Lite MMDB"

            return result

        return self._lookup_mmdblookup(ip)

    def _cache_valid(self, entry):
        if not isinstance(entry, dict):
            return False
        value = entry.get("data")
        cached_at = entry.get("cached_at")
        if not isinstance(value, dict) or not cached_at:
            return False
        try:
            ts = datetime.fromisoformat(cached_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return now_utc() - ts <= timedelta(days=self.cache_days)

    def _lookup_api(self, ip):
        if self.api_exhausted:
            return None

        if self.new_queries >= self.max_new_lookups:
            self.api_exhausted = True
            return None

        url = self.api_url.format(ip=ip)
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "Accept-Language": "es,en;q=0.8",
                "User-Agent": "OrangeBox-Wazuh-GeoIP-Test/1.0",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = response.read().decode("utf-8")
            data = json.loads(payload)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                self.api_exhausted = True
                self.errors.append(
                    f"DB-IP API limit/restricción al consultar {ip}: HTTP {exc.code}"
                )
            else:
                self.errors.append(f"DB-IP API error para {ip}: HTTP {exc.code}")
            return None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            self.errors.append(f"DB-IP API error para {ip}: {exc}")
            return None

        result = {
            "country_code": str(data.get("countryCode") or "").upper(),
            "country": str(data.get("countryName") or ""),
            "region": str(data.get("stateProv") or ""),
            "city": str(data.get("city") or ""),
            "asn": str(data.get("asNumber") or data.get("asn") or ""),
            "asn_org": str(
                data.get("organization")
                or data.get("org")
                or data.get("isp")
                or ""
            ),
            "source": "DB-IP Free API",
        }
        self.new_queries += 1
        return result

    def lookup(self, ip):
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return {
                "country_code": "",
                "country": "",
                "region": "",
                "city": "",
                "asn": "",
                "asn_org": "",
                "source": "IP inválida",
            }

        if not parsed.is_global:
            return {
                "country_code": "",
                "country": "Red privada/reservada",
                "region": "",
                "city": "",
                "asn": "",
                "asn_org": "",
                "source": "IP local",
            }

        local = self._lookup_mmdb(ip)
        if local:
            self.cache[ip] = {
                "cached_at": now_utc().isoformat().replace("+00:00", "Z"),
                "data": local,
            }
            self._save_cache()
            return dict(local)

        cached = self.cache.get(ip)
        if self._cache_valid(cached):
            data = dict(cached["data"])
            data["cached"] = True
            return data

        remote = self._lookup_api(ip)
        if remote:
            self.cache[ip] = {
                "cached_at": now_utc().isoformat().replace("+00:00", "Z"),
                "data": remote,
            }
            self._save_cache()
            return dict(remote)

        return {
            "country_code": "",
            "country": "No disponible",
            "region": "",
            "city": "",
            "asn": "",
            "asn_org": "",
            "source": "Sin datos",
        }

    def close(self):
        for reader in (self._city_reader, self._asn_reader):
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass


def collect_source_ips(group_sections):
    """Recolecta IPs públicas y servidores donde fueron observadas.

    Se deduplica por agente aunque el mismo servidor pertenezca a varios grupos.
    """
    source_agents = defaultdict(set)
    blocked = defaultdict(
        lambda: {
            "servers": set(),
            "count": 0,
            "reasons": defaultdict(int),
        }
    )

    for _, stats in group_sections:
        for agent_id, stat in stats.items():
            for ip in stat.get("ips", set()):
                try:
                    if ipaddress.ip_address(ip).is_global:
                        source_agents[ip].add(str(agent_id))
                except ValueError:
                    continue

            for ip, data in stat.get("blocked", {}).items():
                try:
                    if not ipaddress.ip_address(ip).is_global:
                        continue
                except ValueError:
                    continue

                entry = blocked[ip]
                if str(agent_id) in entry["servers"]:
                    continue

                entry["servers"].add(str(agent_id))
                entry["count"] += int(data.get("count", 0) or 0)
                reasons = data.get("reasons") or {}
                for reason, count in reasons.items():
                    entry["reasons"][str(reason)] += int(count or 0)

    return source_agents, blocked


def render_geoip_section(group_sections):
    max_ips = int(os.environ.get("ORANGEBOX_GEOIP_MAX_IPS", str(DEFAULT_MAX_IPS)))
    resolver = GeoIPResolver()
    source_agents, blocked = collect_source_ips(group_sections)

    ranked_sources = sorted(
        source_agents,
        key=lambda ip: (
            -len(source_agents[ip]),
            ipaddress.ip_address(ip).version,
            int(ipaddress.ip_address(ip)),
        ),
    )[:max_ips]

    ranked_blocked = sorted(
        blocked,
        key=lambda ip: (
            -blocked[ip]["count"],
            ipaddress.ip_address(ip).version,
            int(ipaddress.ip_address(ip)),
        ),
    )[:max_ips]

    geo = {ip: resolver.lookup(ip) for ip in sorted(set(ranked_sources) | set(ranked_blocked))}
    api_limit_note = resolver.api_exhausted

    parts = [
        "<tr><td style='padding:14px 20px 8px;'>",
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
        "style='border-bottom:1px solid #e1e5e4;'><tr>",
        "<td style='padding:12px 6px 14px;color:#19333e;font-size:22px;font-weight:800;'>"
        "Geolocalización de IPs de origen</td>",
        "</tr></table></td></tr>",
        "<tr><td style='padding:0 20px 24px;'>",
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>",
        "<tr>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>IP</td>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>PAÍS</td>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>REGIÓN</td>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>CIUDAD</td>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>SERVIDORES</td>",
        "</tr>",
    ]

    if ranked_sources:
        for ip in ranked_sources:
            item = geo[ip]
            country = (
                f"{item.get('country_code')} — {item.get('country')}"
                if item.get("country_code") and item.get("country")
                else item.get("country") or "No disponible"
            )
            parts.append(
                "<tr>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-family:monospace;font-size:11px;color:#19333e;'>{esc(ip)}</td>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-size:11px;color:#19333e;'>{esc(country)}</td>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-size:11px;color:#19333e;'>{esc(item.get('region') or '-')}</td>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-size:11px;color:#19333e;'>{esc(item.get('city') or '-')}</td>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;text-align:right;font-weight:800;font-size:11px;color:#19333e;'>{len(source_agents[ip])}</td>"
                "</tr>"
            )
    else:
        parts.append(
            "<tr><td colspan='5' style='padding:8px 5px;color:#78909c;font-size:11px;'>"
            "No hubo IPs públicas de origen durante el período.</td></tr>"
        )

    parts.extend([
        "</table></td></tr>",
        "<tr><td style='padding:0 20px 24px;'>",
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>",
        "<tr><td colspan='6' style='padding:7px 0 8px;border-bottom:2px solid #ff5a2f;"
        "font-size:14px;font-weight:800;color:#19333e;'>IPs bloqueadas automáticamente · GeoIP</td></tr>",
        "<tr>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>IP</td>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>PAÍS</td>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>REGIÓN</td>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>CIUDAD</td>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;'>MOTIVO</td>",
        "<td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:800;text-align:right;'>BLOQUEOS</td>",
        "</tr>",
    ])

    if ranked_blocked:
        for ip in ranked_blocked:
            item = geo[ip]
            entry = blocked[ip]
            country = (
                f"{item.get('country_code')} — {item.get('country')}"
                if item.get("country_code") and item.get("country")
                else item.get("country") or "No disponible"
            )
            reason = "; ".join(
                f"{reason} ({count})"
                for reason, count in sorted(
                    entry["reasons"].items(),
                    key=lambda kv: (-kv[1], kv[0]),
                )[:3]
            ) or "Firewall Drop"
            parts.append(
                "<tr>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-family:monospace;font-size:11px;color:#19333e;'>{esc(ip)}</td>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-size:11px;color:#19333e;'>{esc(country)}</td>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-size:11px;color:#19333e;'>{esc(item.get('region') or '-')}</td>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-size:11px;color:#19333e;'>{esc(item.get('city') or '-')}</td>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-size:11px;line-height:1.35;color:#19333e;'>{esc(reason)}</td>"
                f"<td style='padding:7px;border-bottom:1px solid #edf1f3;text-align:right;font-weight:800;font-size:11px;color:#19333e;'>{entry['count']}</td>"
                "</tr>"
            )
    else:
        parts.append(
            "<tr><td colspan='6' style='padding:8px 5px;color:#78909c;font-size:11px;'>"
            "No hubo bloqueos automáticos registrados.</td></tr>"
        )

    parts.extend([
        "</table></td></tr>",
        "<tr><td style='padding:0 20px 28px;'>",
        "<div style='font-size:10px;line-height:1.5;color:#667b84;'>"
        "<b>Fuente GeoIP:</b> DB-IP. La geolocalización de una IP es aproximada y puede no "
        "representar la ubicación física real del atacante.",
        "</div>",
        "</td></tr>",
    ])

    if api_limit_note:
        parts.extend([
            "<tr><td style='padding:0 20px 20px;'>",
            "<div style='background:#fff7f2;border:1px solid #f2c8b9;border-left:4px solid #ff5a2f;"
            "padding:12px 14px;font-size:11px;line-height:1.5;color:#8a3d2d;'>"
            "<b>GeoIP:</b> se alcanzó el límite de consultas nuevas configurado para esta "
            "ejecución. Las IPs sin caché quedaron como 'No disponible'."
            "</div></td></tr>",
        ])

    if resolver.errors:
        parts.extend([
            "<tr><td style='padding:0 20px 20px;'>",
            "<div style='background:#fff7f2;border:1px solid #f2c8b9;padding:10px 12px;"
            "font-size:10px;line-height:1.45;color:#8a3d2d;'>"
            "<b>Detalles GeoIP:</b> "
            + esc(" | ".join(resolver.errors[:3]))
            + "</div></td></tr>",
        ])

    resolver.close()
    return "".join(parts)


def render_geoip_plain(group_sections):
    resolver = GeoIPResolver()
    source_agents, blocked = collect_source_ips(group_sections)
    max_ips = int(os.environ.get("ORANGEBOX_GEOIP_MAX_IPS", str(DEFAULT_MAX_IPS)))

    sources = sorted(
        source_agents,
        key=lambda ip: (
            -len(source_agents[ip]),
            ipaddress.ip_address(ip).version,
            int(ipaddress.ip_address(ip)),
        ),
    )[:max_ips]
    blocked_ips = sorted(
        blocked,
        key=lambda ip: (
            -blocked[ip]["count"],
            ipaddress.ip_address(ip).version,
            int(ipaddress.ip_address(ip)),
        ),
    )[:max_ips]

    lines = [
        "",
        "GEOIP - IPS DE ORIGEN",
        "=====================",
    ]
    for ip in sources:
        item = resolver.lookup(ip)
        country = (
            f"{item.get('country_code')} - {item.get('country')}"
            if item.get("country_code") and item.get("country")
            else item.get("country") or "No disponible"
        )
        lines.append(
            f"  {ip} | {country} | {item.get('region') or '-'} | "
            f"{item.get('city') or '-'} | servidores={len(source_agents[ip])}"
        )

    lines.extend([
        "",
        "GEOIP - IPS BLOQUEADAS",
        "======================",
    ])
    for ip in blocked_ips:
        item = resolver.lookup(ip)
        country = (
            f"{item.get('country_code')} - {item.get('country')}"
            if item.get("country_code") and item.get("country")
            else item.get("country") or "No disponible"
        )
        lines.append(
            f"  {ip} | {country} | {item.get('region') or '-'} | "
            f"{item.get('city') or '-'} | bloqueos={blocked[ip]['count']}"
        )

    lines.append("Fuente GeoIP: DB-IP. La geolocalización es aproximada.")
    if resolver.api_exhausted:
        lines.append("ADVERTENCIA: se alcanzó el límite de consultas GeoIP nuevas.")
    resolver.close()
    return "\n".join(lines)


def geoip_generate_html(
    prod_module,
    group_sections,
    title,
    subtitle,
    period,
    total_agents,
    total_events,
    total_high,
    total_critical,
    total_attacks,
    vuln_error=None,
    mitre_descriptions=None,
):
    body = prod_module.generate_html(
        group_sections,
        title,
        subtitle,
        period,
        total_agents,
        total_events,
        total_high,
        total_critical,
        total_attacks,
        vuln_error=vuln_error,
        mitre_descriptions=mitre_descriptions,
    )
    geo_section = render_geoip_section(group_sections)
    marker = "</body>"
    if marker in body:
        body = body.replace(marker, geo_section + marker, 1)
    else:
        body += geo_section
    return body


def geoip_generate_plain(
    prod_module,
    group_sections,
    period,
    total_agents,
    total_events,
    total_high,
    total_critical,
    total_attacks,
    vuln_error=None,
):
    base = prod_module.generate_plain(
        group_sections,
        period,
        total_agents,
        total_events,
        total_high,
        total_critical,
        total_attacks,
        vuln_error=vuln_error,
    )
    return base + render_geoip_plain(group_sections)


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description="OrangeBox Wazuh detailed report with GeoIP (TEST)"
    )
    modes = parser.add_mutually_exclusive_group(required=True)
    for name in (
        "today",
        "yesterday",
        "thisweek",
        "lastweek",
        "thismonth",
        "lastmonth",
        "thisyear",
        "lastyear",
    ):
        modes.add_argument("--" + name, action="store_true")
    modes.add_argument("--date", help="Día específico YYYY-MM-DD")
    parser.add_argument("--group", required=True, help="Grupos Wazuh separados por comas")
    parser.add_argument(
        "--email",
        action="append",
        required=True,
        help="Destinatario; se puede repetir",
    )
    parser.add_argument("--lang", choices=("es", "en"), default="es")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("Este reporte debe ejecutarse como root.")

    mode = args.date and f"date:{args.date}" or next(
        name
        for name in (
            "today",
            "yesterday",
            "thisweek",
            "lastweek",
            "thismonth",
            "lastmonth",
            "thisyear",
            "lastyear",
        )
        if getattr(args, name)
    )

    prod = load_prod_module()
    engine = prod.load_report_module()
    now = datetime.now().astimezone()
    start, end, label = engine.period_bounds(mode, now)
    agent_info = prod.parse_agent_control()

    groups = (
        prod.all_groups()
        if args.group.lower() == "all"
        else [value.strip() for value in args.group.split(",") if value.strip()]
    )

    group_memberships = {}
    all_agent_ids = set()

    for group in groups:
        ids = prod.group_members(group)
        if not ids:
            print(f"Grupo omitido: {group} no tiene servidores asignados.")
            continue
        group_memberships[group] = ids
        all_agent_ids.update(ids)

    if not group_memberships:
        raise SystemExit("No hay grupos con servidores asignados para generar el reporte.")

    agent_stats = prod.init_agent_stats(all_agent_ids, agent_info)
    prod.aggregate_events(engine, start, end, all_agent_ids, agent_stats)

    cves, vuln_error = prod.fetch_critical_cves(engine, all_agent_ids)
    cloudlinux_agents = prod.fetch_cloudlinux_agents(engine, all_agent_ids)
    for agent_id, stat in agent_stats.items():
        stat["cves"] = cves.get(agent_id, [])
        stat["vd_unsupported"] = agent_id in cloudlinux_agents

    rendered_sections = []
    total_agents = 0
    total_events = 0
    total_high = 0
    total_critical = 0
    total_attacks = 0

    for group, ids in group_memberships.items():
        stats = {agent_id: agent_stats[agent_id] for agent_id in ids}
        total_agents += len(ids)
        total_events += sum(stat["events"] for stat in stats.values())
        total_high += sum(stat["high"] for stat in stats.values())
        total_critical += sum(stat["critical"] for stat in stats.values())
        total_attacks += sum(stat["attacks"] for stat in stats.values())
        rendered_sections.append((group, stats))

    title = (
        f"CLIENTE — Reporte detallado + GeoIP (TEST): {args.group}"
        if len(groups) == 1
        else "CLIENTE — Reporte detallado + GeoIP (TEST)"
    )
    subtitle = "Prueba de geolocalización de IPs de origen"
    period = f"{start.strftime('%d/%m/%Y %H:%M')} — {end.strftime('%d/%m/%Y %H:%M')}"

    body = geoip_generate_html(
        prod,
        rendered_sections,
        title,
        subtitle,
        period,
        total_agents,
        total_events,
        total_high,
        total_critical,
        total_attacks,
        vuln_error=vuln_error,
        mitre_descriptions=getattr(prod, "MITRE_DESCRIPTIONS", {}),
    )

    archive = prod.archive_html(
        body,
        f"geoip-test-{args.group}-{mode.replace(':', '-')}-{start:%Y%m%d}-{end:%Y%m%d}",
    )

    text_body = geoip_generate_plain(
        prod,
        rendered_sections,
        period,
        total_agents,
        total_events,
        total_high,
        total_critical,
        total_attacks,
        vuln_error=vuln_error,
    )

    subject = (
        f"[ORANGEBOX][TEST GEOIP] {prod.period_label(mode)} - Informe de Seguridad Detallado - {args.group}"
        if len(groups) == 1
        else f"[ORANGEBOX][TEST GEOIP] {prod.period_label(mode)} - Informe de Seguridad Detallado"
    )

    print(f"Grupo: {args.group}")
    print(f"Período: {period}")
    print(f"Servidores: {total_agents}")
    print(f"Eventos: {total_events}")
    print(f"Alta severidad: {total_high}")
    print(f"Críticas: {total_critical}")
    print(f"Ataques: {total_attacks}")
    print(f"Archivo: {archive}")

    if args.dry_run:
        print("Dry-run: no se envió correo.")
        return 0

    sent = 0
    for recipient in args.email:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+", recipient):
            print(f"ERROR: correo inválido: {recipient}", flush=True)
            continue

        from_addr = getattr(prod, "DEFAULT_FROM", "wazuh@example.com")
        msg_lines = [
            f"From: Wazuh SOC <{from_addr}>",
            f"To: {recipient}",
            f"Subject: {subject}",
            "MIME-Version: 1.0",
            "Content-Type: multipart/alternative; boundary=\"ORANGEBOX_GEOIP_TEST\"",
            "",
            "--ORANGEBOX_GEOIP_TEST",
            "Content-Type: text/plain; charset=UTF-8",
            "Content-Transfer-Encoding: 8bit",
            "",
            text_body,
            "",
            "--ORANGEBOX_GEOIP_TEST",
            "Content-Type: text/html; charset=UTF-8",
            "Content-Transfer-Encoding: 8bit",
            "",
            body,
            "",
            "--ORANGEBOX_GEOIP_TEST--",
            "",
        ]
        raw = "\n".join(msg_lines)

        import subprocess

        try:
            result = subprocess.run(
                ["/usr/sbin/sendmail", "-t", "-i"],
                input=raw,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                detail = (
                    result.stderr
                    or result.stdout
                    or f"sendmail exit={result.returncode}"
                ).strip()
                raise RuntimeError(detail)
            sent += 1
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            print(f"ERROR enviando a {recipient}: {exc}", flush=True)

    if sent == 0:
        raise SystemExit("No se pudo enviar el reporte a ningún destinatario.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
