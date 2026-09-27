#!/usr/bin/env python3
"""OrangeBox Wazuh Security Activity Report.

Genera reportes HTML portables a partir de las alertas JSON de Wazuh.
El HTML usa tablas e estilos inline para funcionar en Thunderbird, webmail y móvil.
"""
import argparse
import base64
import gzip
import html
import ssl
import urllib.error
import urllib.request
try:
    import orjson
except ImportError:
    orjson = None
import ipaddress
import json
import os
import re
import smtplib
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

ALERTS_ROOT = "/var/ossec/logs/alerts"
ALERTS_FILE = f"{ALERTS_ROOT}/alerts.json"
ARCHIVE_DIR = "/var/ossec/reports/archive"
DEFAULT_FROM = "TU_EMAIL"
SMTP_HOST = "localhost"
SMTP_PORT = 25
AGENT_GROUPS_BIN = "/var/ossec/bin/agent_groups"
INDEXER_CONFIG = "/var/ossec/etc/orangebox-indexer.conf"
FIREWALL_RULE = "651"
FIREWALL_RE = re.compile(r"active-response/bin/firewall-drop:\s*(\{.*\})$")
WAZUH_OSSEC_CONF = "/var/ossec/etc/ossec.conf"
LOGO_URL = "https://TU_HOSTNAME/obox/img/logo-dark.png"

AUTH_RULES = {"5710", "5712", "5715", "5716", "5720", "5760", "5763", "10001", "10006", "10007", "10008", "10009", "40101"}
WEB_RULES = {"31101", "10023", "10024", "10025", "10026"}
FIM_RULES = {"550", "553", "554", "10060", "10062", "10063", "10410", "10432"}
MALWARE_RULES = {"10060", "10062", "10063", "10410", "10432"}
PRIV_RULES = {"10004", "10005", "5402", "5403", "10032"}
AUTH_GROUPS = {"authentication", "authentication_success", "authentication_failed"}
WEB_GROUPS = {"web", "orangebox_web"}
FIM_GROUPS = {"syscheck", "syscheck_entry_added", "syscheck_entry_modified", "syscheck_entry_deleted", "orangebox_temporary_executable"}
MALWARE_GROUPS = {"malware", "webshell", "orangebox_malware", "orangebox_webshell"}
ATTACK_GROUPS = {"attack", "brute_force", "reconnaissance", "credential_discovery", "sensitive_file", "lateral_movement"}
REPORT_EXCLUDED_GROUPS = {"orangebox_exception", "orangebox_whitelist"}
REPORT_EXCLUDED_RULES = {"5402"}

RULE_CANONICAL_DESCRIPTIONS = {
    "5710": "SSH: Intento de acceso con usuario inexistente.",
    "5712": "SSH: Fuerza bruta intentando acceder al sistema con usuario inexistente.",
    "5715": "SSH: Inicio de sesión exitoso.",
    "5760": "SSH: Autenticación fallida.",
    "5763": "SSH: Fuerza bruta intentando acceder al sistema con autenticación fallida.",
    "5758": "SSH: Se superó el máximo de intentos de autenticación.",
    "10001": "SSH: Inicio de sesión SSH exitoso.",
    "10006": "SSH: Fuerza bruta completada con éxito.",
    "10007": "SSH: Posible movimiento lateral desde la red interna.",
    "40101": "ACCESO: Sesión de usuario iniciada.",
    "5501": "ACCESO: Sesión PAM de usuario abierta.",
    "5503": "ACCESO: Fallo de autenticación de usuario PAM.",
    "2501": "ACCESO: Fallo de autenticación de usuario.",
    "2502": "ACCESO: Contraseña incorrecta en múltiples intentos.",
    "3332": "ACCESO: Fallo de autenticación SASL de Postfix.",
    "10004": "PRIVILEGIOS: Usuario cambió de sesión a ROOT mediante comando SU.",
    "10005": "PRIVILEGIOS: SUDO hacia ROOT con comando no autorizado por la whitelist OrangeBox.",
    "5402": "PRIVILEGIOS: SUDO hacia ROOT ejecutado.",
    "5403": "PRIVILEGIOS: Primera ejecución de SUDO por el usuario.",
    "10032": "PRIVILEGIOS: Configuración de SUDO modificada.",
    "550": "ARCHIVOS: Integridad de archivo modificada.",
    "553": "ARCHIVOS: Archivo eliminado.",
    "554": "ARCHIVOS: Archivo agregado al sistema.",
    "517": "ARCHIVOS: Directorio monitorizado eliminado.",
    "560": "ARCHIVOS: Cola de FIM en tiempo real llena.",
    "231": "ARCHIVOS: Límite de archivos monitorizados próximo a alcanzarse.",
    "10060": "MALWARE: Script SHELL creado en directorio temporal.",
    "10062": "MALWARE: Posible WebShell PHP creado.",
    "10063": "MALWARE: Posible WebShell PHP modificado.",
    "10410": "MALWARE: Archivo ejecutable creado en directorio temporal.",
    "10432": "MALWARE: Permiso de ejecución agregado a archivo en directorio temporal.",
    "10023": "WEB: Reconocimiento o acceso a recurso sensible detectado.",
    "10024": "WEB: HTTP 401/403 detectado contra servidor web.",
    "10025": "WEB: Posible fuerza bruta web.",
    "10026": "WEB: Posible reconocimiento automatizado de archivos sensibles o credenciales web.",
    "31101": "WEB: Código de error 400 del servidor web.",
    "31516": "WEB: Acceso a URL sospechosa.",
    "31533": "WEB: Alta cantidad de solicitudes POST en un período corto.",
    "31509": "WEB: Intento de acceso de login de CMS.",
    "31151": "WEB: Múltiples errores 400 desde la misma IP de origen.",
    "30306": "WEB: Intento de acceso a índice de directorio prohibido.",
    "30318": "WEB: Aviso PHP detectado en log de Apache.",
    "31515": "WEB: Escaneo de PHPMyAdmin detectado.",
    "31104": "WEB: Ataque web común detectado.",
    "30305": "WEB: Intento de acceso a archivo o directorio prohibido.",
    "31510": "WEB: Fuerza bruta contra CMS detectada.",
    "31106": "WEB: Ataque web que devolvió código HTTP 200.",
    "10453": "RED: Posible escaneo de puertos TCP desde la misma IP de origen.",
    "10454": "RED: Posible inundación TCP SYN desde la misma IP de origen.",
    "10455": "RED: Posible ataque de denegación de servicio distribuido.",
    "10034": "CONFIGURACIÓN: Unidad o configuración persistente de SYSTEMD modificada.",
    "10035": "CONFIGURACIÓN: Configuración de CRON o ANACRON modificada.",
    "10036": "RED: Configuración crítica de red, DNS o montaje modificada.",
    "10037": "CONFIGURACIÓN: Configuración de FIREWALL modificada.",
    "10044": "CONFIGURACIÓN: Unidad o configuración persistente de SYSTEMD eliminada.",
    "100311": "ENDPOINT: Nuevo puerto de red detectado en el endpoint.",
    "100313": "ENDPOINT: Nuevo servicio detectado en el endpoint.",
}

MITRE_DESCRIPTIONS = {
    "T1110": "Fuerza bruta: intentos repetidos para obtener acceso mediante credenciales.",
    "T1110.001": "Intentos repetidos de acceso probando contraseñas.",
    "T1021": "Acceso remoto a otro sistema mediante un servicio de red.",
    "T1021.004": "Acceso remoto a sistemas mediante SSH.",
    "T1078": "Uso de una cuenta o credencial válida para intentar acceder.",
    "T1565.001": "Modificación de información almacenada para alterar su contenido o comportamiento.",
    "T1070.004": "Eliminación de archivos para borrar rastros de actividad.",
    "T1485": "Destrucción de datos para provocar pérdida o interrupción de información.",
    "T1548.003": "Uso de sudo para ejecutar acciones con privilegios elevados.",
    "T1055": "Intento de ejecutar código dentro de otro proceso para evadir controles.",
    "T1190": "Intento de aprovechar una aplicación o servicio expuesto a Internet.",
    "T1498": "Intento de saturar un servicio mediante un volumen elevado de tráfico.",
    "T1595.002": "Reconocimiento activo para identificar servicios o sistemas accesibles.",
    "T1083": "Búsqueda de archivos y directorios para conocer qué existe en el sistema.",
    "T1552": "Búsqueda de información sensible almacenada de forma insegura.",
    "T1098": "Modificación de cuentas para mantener o ampliar el acceso.",
    "T1059": "Uso de una consola o intérprete para ejecutar comandos.",
    "T1059.004": "Ejecución de comandos mediante una consola Unix o Linux.",
    "T1105": "Descarga o transferencia de archivos desde una ubicación remota.",
    "T1505.003": "Intento de instalar o utilizar un componente web malicioso, como un webshell.",
}

LABELS_ES = {
    "report": "Informe de Actividad de Seguridad", "subtitle": "Actividad de seguridad, detecciones y acciones automatizadas de Wazuh", "security_events": "Eventos de seguridad", "high_alerts": "Alertas de alta severidad", "source_ips": "IPs de origen observadas", "systems": "Servidores afectados", "firewall": "Respuesta automática · Bloqueo de IPs", "firewall_sub": "Intentos detectados y direcciones IP bloqueadas automáticamente.", "agent": "Sistema", "reason": "Motivo", "rule": "Regla", "blocked_ips": "IPs bloqueadas", "attempts": "Intentos detectados", "access": "Intentos de acceso", "web": "Intentos de acceso y exploración web", "fim": "Cambios detectados en archivos", "malware": "Detecciones de malware y archivos sospechosos", "priv": "Escalamiento de privilegios", "attack": "Detecciones clasificadas como intentos de ataque", "mitre": "Técnicas MITRE observadas en las alertas", "technique": "Técnica", "meaning": "Qué significa", "detections": "Alertas asociadas", "agents": "Servidores afectados", "no_firewall": "No se registraron bloqueos automáticos con una IP de origen válida.", "no_activity": "No se registraron detecciones de esta categoría durante el período.", "attack_note": "Esta sección incluye únicamente alertas que el informe clasificó explícitamente como actividad de ataque. Que una técnica MITRE aparezca más abajo no significa por sí sola que exista un ataque confirmado.", "mitre_note": "El contador indica cuántas alertas de Wazuh fueron asociadas a cada técnica MITRE durante el período. No representa necesariamente accesos exitosos, conexiones individuales ni compromisos confirmados.", "firewall_note": "Los intentos detectados son detecciones Wazuh asociadas a las IP que fueron bloqueadas; no equivalen necesariamente a la cantidad bruta de conexiones o solicitudes originales.", "recidivist": "IPs reincidentes en bloqueos automáticos", "recidivist_sub": "IPs que fueron bloqueadas automáticamente más de una vez durante el período.", "block_count": "Bloqueos", "trigger_rules": "Reglas que activaron el bloqueo", "ban_duration": "Tiempo de baneo configurado", "servers": "Servidores más afectados", "servers_sub": "Resumen de actividad por servidor durante el período.", "events": "Eventos", "high": "Alta severidad", "source_ips_col": "IPs origen", "attack_alerts": "Alertas de ataque", "no_servers": "No se registraron eventos para los servidores durante el período.", "cve": "Vulnerabilidades críticas (CVE)", "cve_sub": "Resumen del inventario actual de vulnerabilidades críticas del Wazuh Indexer.", "cve_total": "Hallazgos CVE críticos", "cve_systems": "Sistemas con CVE críticos", "cve_agent": "Servidor", "cve_count": "CVE críticos", "cve_error": "No fue posible consultar el inventario de vulnerabilidades del Wazuh Indexer.", "cve_none": "No se registran CVE críticos en el inventario consultado.", "cve_unsupported": "CloudLinux detectado: Wazuh no realiza actualmente evaluación nativa de vulnerabilidades para esta distribución; no corresponde interpretar el resultado como ausencia de CVE.", "technical_note": "Los identificadores y descripciones de las reglas corresponden al motor de detección Wazuh. La detección de un intento no implica por sí sola que el sistema haya sido comprometido.",
}
LABELS_EN = {
    "report": "Security Activity Report", "subtitle": "Security activity, detections and automated Wazuh responses", "security_events": "Security events", "high_alerts": "High-severity alerts", "source_ips": "Observed source IPs", "systems": "Affected servers", "firewall": "Automated response · IP blocking", "firewall_sub": "Detected attempts and IP addresses blocked automatically.", "agent": "System", "reason": "Reason", "rule": "Rule", "blocked_ips": "Blocked IPs", "attempts": "Detected attempts", "access": "Access attempts", "web": "Web access and reconnaissance attempts", "fim": "Detected file changes", "malware": "Malware and suspicious file detections", "priv": "Privilege escalation", "attack": "Detections classified as attack attempts", "mitre": "MITRE techniques observed in alerts", "technique": "Technique", "meaning": "What it means", "detections": "Associated alerts", "agents": "Most affected systems", "no_firewall": "No automatic blocks with a valid source IP were recorded.", "no_activity": "No detections were recorded for this category during the period.", "attack_note": "This section includes only alerts explicitly classified by the report as attack activity. The appearance of a MITRE technique below does not by itself mean that a confirmed attack occurred.", "mitre_note": "The counter shows how many Wazuh alerts were associated with each MITRE technique during the period. It does not necessarily represent successful logins, individual connections, or confirmed compromises.", "firewall_note": "Detected attempts are Wazuh detections associated with the IPs that were blocked; they do not necessarily equal the raw number of original connections or requests.", "recidivist": "IPs with repeated automatic blocks", "recidivist_sub": "IPs that were automatically blocked more than once during the period.", "block_count": "Blocks", "trigger_rules": "Rules that triggered the block", "ban_duration": "Configured ban time", "servers": "Most affected servers", "servers_sub": "Activity summary by server during the period.", "events": "Events", "high": "High severity", "source_ips_col": "Source IPs", "attack_alerts": "Attack alerts", "no_servers": "No server events were recorded during the period.", "cve": "Critical vulnerabilities (CVE)", "cve_sub": "Summary of the current critical vulnerability inventory from the Wazuh Indexer.", "cve_total": "Critical CVE findings", "cve_systems": "Systems with critical CVEs", "cve_agent": "Server", "cve_count": "Critical CVEs", "cve_error": "The Wazuh Indexer vulnerability inventory could not be queried.", "cve_none": "No critical CVEs are recorded in the queried inventory.", "cve_unsupported": "CloudLinux detected: Wazuh does not currently provide native vulnerability assessment for this distribution; the result must not be interpreted as absence of CVEs.", "technical_note": "Rule identifiers and descriptions come from the Wazuh detection engine. Detecting an attempt does not by itself mean that the system was compromised.",
}

def labels(lang): return LABELS_EN if lang == "en" else LABELS_ES
def esc(value): return html.escape(str(value), quote=True)


def standardize_rule_description(rule_id, description, groups=None):
    """Normaliza los nombres de reglas para el reporte sin modificar Wazuh."""
    rid = str(rule_id)
    if rid in RULE_CANONICAL_DESCRIPTIONS:
        return RULE_CANONICAL_DESCRIPTIONS[rid]

    text = str(description or "Sin descripción").strip()
    text = re.sub(
        r"^(?:ALERTA(?:\s+CRITICA)?|ORANGEBOX(?:\s+TEST)?)\s*:\s*",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\s+", " ", text).strip()

    group_set = {str(value).lower() for value in (groups or [])}
    if rid in MALWARE_RULES or group_set & MALWARE_GROUPS:
        prefix = "MALWARE"
    elif rid in PRIV_RULES or group_set & {"privilege_escalation", "privilege_escalation_root", "sudo"}:
        prefix = "PRIVILEGIOS"
    elif rid in WEB_RULES or group_set & WEB_GROUPS:
        prefix = "WEB"
    elif rid in FIM_RULES or group_set & FIM_GROUPS:
        prefix = "ARCHIVOS"
    elif rid in AUTH_RULES or group_set & AUTH_GROUPS:
        prefix = "SSH" if "ssh" in group_set else "ACCESO"
    elif group_set & ATTACK_GROUPS:
        prefix = "ATAQUE"
    else:
        return text or "Sin descripción"

    return text if re.match(rf"^{re.escape(prefix)}\s*:", text, flags=re.IGNORECASE) else f"{prefix}: {text}"


def report_event_exempt(event):
    group_set = {str(value).lower() for value in (event.get("groups") or [])}
    rule_id = str(event.get("rule_id", "")).strip()
    try:
        level = int(event.get("level", 0) or 0)
    except (TypeError, ValueError):
        level = 0
    return (
        level <= 0
        or rule_id in REPORT_EXCLUDED_RULES
        or bool(group_set & REPORT_EXCLUDED_GROUPS)
    )


def read_secure_kv(path):
    values = {}
    path = Path(path)
    if not path.exists():
        return values
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = 0
    if mode & 0o077:
        raise RuntimeError(f"{path} debe tener permisos 0600 o más restrictivos.")
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"No se pudo leer {path}: {exc}") from exc
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'").strip('"')
    return values


def indexer_settings():
    config = read_secure_kv(INDEXER_CONFIG)
    user = os.environ.get("WAZUH_INDEXER_USER") or config.get("WAZUH_INDEXER_USER") or "admin"
    password = os.environ.get("WAZUH_INDEXER_PASS") or config.get("WAZUH_INDEXER_PASS")
    if not password:
        raise RuntimeError(
            f"No existe WAZUH_INDEXER_PASS en {INDEXER_CONFIG}. "
            "El password del Indexer no debe quedar dentro del repositorio."
        )
    return {
        "url": (os.environ.get("WAZUH_INDEXER_URL") or config.get("WAZUH_INDEXER_URL") or "https://IP_DE_INDEXER:9200").rstrip("/"),
        "user": user,
        "password": password,
    }


def indexer_request(settings, path, payload):
    body = json.dumps(payload).encode("utf-8")
    token = base64.b64encode(
        f"{settings['user']}:{settings['password']}".encode("utf-8")
    ).decode("ascii")
    request = urllib.request.Request(
        f"{settings['url']}{path}",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {token}",
        },
    )
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            return json.loads(response.read().decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except OSError:
            detail = ""
        return None, f"Indexer HTTP {exc.code}: {detail[:300]}"
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return None, f"Consulta al Indexer falló: {exc}"


def fetch_critical_cves(allowed):
    try:
        settings = indexer_settings()
    except RuntimeError as exc:
        return {"total": 0, "agents": {}, "unsupported_agents": {}}, str(exc)

    filters = [{"term": {"vulnerability.severity": "Critical"}}]
    if allowed is not None:
        if not allowed:
            return {"total": 0, "agents": {}, "unsupported_agents": {}}, None
        filters.append({"terms": {"agent.id": sorted(allowed)}})

    results = {}
    total_reported = None
    search_after = None

    while True:
        payload = {
            "size": 1000,
            "track_total_hits": True,
            "_source": [
                "agent.id",
                "agent.name",
            ],
            "query": {
                "bool": {
                    "filter": filters,
                }
            },
            "sort": [
                {"_index": {"order": "asc"}},
                {"_id": {"order": "asc"}},
            ],
        }
        if search_after is not None:
            payload["search_after"] = search_after

        data, error = indexer_request(
            settings,
            "/wazuh-states-vulnerabilities-*/_search",
            payload,
        )
        if error:
            return {"total": 0, "agents": {}, "unsupported_agents": {}}, error

        hits_root = data.get("hits") or {}
        if total_reported is None:
            total = hits_root.get("total") or 0
            total_reported = int(total.get("value", total) if isinstance(total, dict) else total)

        hits = hits_root.get("hits") or []
        if not hits:
            break

        for hit in hits:
            source = hit.get("_source") or {}
            agent = source.get("agent") or {}
            agent_id = str(agent.get("id", "")).strip()
            if not agent_id:
                continue
            agent_name = str(agent.get("name") or f"Agente {agent_id}")
            record = results.setdefault(agent_id, {"name": agent_name, "count": 0})
            record["count"] += 1

        next_sort = hits[-1].get("sort")
        if not next_sort:
            break
        if next_sort == search_after:
            return {"total": 0, "agents": {}, "unsupported_agents": {}}, "La paginación del inventario CVE quedó sin avance."
        search_after = next_sort
        if len(hits) < 1000:
            break

    unsupported_agents = {}
    if allowed:
        os_filters = [{"terms": {"agent.id": sorted(allowed)}}]
        os_payload = {
            "size": max(1000, len(allowed)),
            "track_total_hits": False,
            "_source": ["agent.id", "agent.name", "host.os.name", "host.os.platform"],
            "query": {"bool": {"filter": os_filters}},
        }
        os_data, os_error = indexer_request(
            settings,
            "/wazuh-states-inventory-system-*/_search",
            os_payload,
        )
        if not os_error:
            for hit in (os_data.get("hits") or {}).get("hits", []):
                source = hit.get("_source") or {}
                agent = source.get("agent") or {}
                agent_id = str(agent.get("id", "")).strip()
                host_os = source.get("host") or {}
                os_data_block = host_os.get("os") or {}
                os_name = str(os_data_block.get("name") or "").strip()
                os_platform = str(os_data_block.get("platform") or "").strip()
                os_name_l = os_name.lower()
                os_platform_l = os_platform.lower()
                is_almalinux = "almalinux" in os_name_l or "almalinux" in os_platform_l
                is_cloudlinux = (
                    os_platform_l == "cloudlinux"
                    or os_name_l == "cloudlinux"
                )
                # AlmaLinux usa el ecosistema de CVE/RHEL y no debe quedar
                # marcado como distro sin soporte aunque conserve un label
                # de plataforma heredado.
                if agent_id and is_cloudlinux and not is_almalinux:
                    unsupported_agents[agent_id] = {
                        "name": str(agent.get("name") or f"Agente {agent_id}")
                    }

    total = total_reported if total_reported is not None else sum(item["count"] for item in results.values())
    return {"total": total, "agents": results, "unsupported_agents": unsupported_agents}, None

def valid_ip(value):
    try: ipaddress.ip_address(value); return True
    except (ValueError, TypeError): return False

def parse_timestamp(value):
    if not value: return None
    try:
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", str(value)); return datetime.fromisoformat(value)
    except (TypeError, ValueError): return None

def extract_firewall_payload(full_log):
    if not isinstance(full_log, str): return None
    match = FIREWALL_RE.search(full_log.strip())
    if not match: return None
    try: return json.loads(match.group(1))
    except json.JSONDecodeError: return None

def load_firewall_timeouts():
    """Lee desde ossec.conf los timeout de cada active-response firewall-drop.
    Se procesa por bloques de texto porque ossec.conf puede contener varios
    bloques <ossec_config>, que no forman un XML único estándar.
    """
    timeouts = {}
    try:
        with open(WAZUH_OSSEC_CONF, "r", encoding="utf-8", errors="ignore") as handle:
            config = handle.read()
    except OSError:
        return timeouts

    for block in re.findall(r"<active-response>\s*(.*?)\s*</active-response>", config, flags=re.DOTALL):
        command = re.search(r"<command>\s*([^<]+?)\s*</command>", block)
        rules_id = re.search(r"<rules_id>\s*([^<]+?)\s*</rules_id>", block)
        timeout = re.search(r"<timeout>\s*(\d+)\s*</timeout>", block)
        if not command or not rules_id or not timeout:
            continue
        if command.group(1).strip() != "firewall-drop":
            continue
        seconds = int(timeout.group(1))
        for rule_id in re.split(r"\s*,\s*", rules_id.group(1).strip()):
            if rule_id:
                timeouts[rule_id] = seconds
    return timeouts

def format_duration(seconds):
    if seconds is None:
        return "No disponible"
    if seconds < 60:
        return f"{seconds}s"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    if seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds}s"

def period_bounds(mode, now):
    today = now.date()
    if mode == "today": return datetime.combine(today, datetime.min.time(), now.tzinfo), now, "Hoy"
    if mode == "yesterday":
        day = today - timedelta(days=1); return datetime.combine(day, datetime.min.time(), now.tzinfo), datetime.combine(today, datetime.min.time(), now.tzinfo), "Ayer"
    monday = today - timedelta(days=today.weekday())
    if mode == "thisweek": return datetime.combine(monday, datetime.min.time(), now.tzinfo), now, "Semana actual"
    if mode == "lastweek":
        start = monday - timedelta(days=7); return datetime.combine(start, datetime.min.time(), now.tzinfo), datetime.combine(monday, datetime.min.time(), now.tzinfo), "Semana anterior"
    first = today.replace(day=1)
    if mode == "thismonth": return datetime.combine(first, datetime.min.time(), now.tzinfo), now, "Mes actual"
    if mode == "lastmonth":
        previous = first - timedelta(days=1); start = previous.replace(day=1); return datetime.combine(start, datetime.min.time(), now.tzinfo), datetime.combine(first, datetime.min.time(), now.tzinfo), "Mes anterior"
    year = today.replace(month=1, day=1)
    if mode == "thisyear": return datetime.combine(year, datetime.min.time(), now.tzinfo), now, "Año actual"
    if mode == "lastyear":
        start = year.replace(year=year.year - 1); return datetime.combine(start, datetime.min.time(), now.tzinfo), datetime.combine(year, datetime.min.time(), now.tzinfo), "Año anterior"
    if mode.startswith("date:"):
        day = datetime.strptime(mode[5:], "%Y-%m-%d").date(); return datetime.combine(day, datetime.min.time(), now.tzinfo), datetime.combine(day + timedelta(days=1), datetime.min.time(), now.tzinfo), day.strftime("%Y-%m-%d")
    raise SystemExit("Período no válido")

def iter_log_files(start, end):
    paths=[]; day=start.date(); last=(end-timedelta(microseconds=1)).date()
    while day <= last:
        base=Path(ALERTS_ROOT)/f"{day.year:04d}"/day.strftime("%b"); paths += [base/f"ossec-alerts-{day.day:02d}.json.gz", base/f"ossec-alerts-{day.day:02d}.json"]; day += timedelta(days=1)
    if start.date() <= datetime.now().date() <= last: paths.append(Path(ALERTS_FILE))
    seen=set()
    for path in paths:
        if path.exists() and str(path) not in seen: seen.add(str(path)); yield path

def iter_json(path):
    opener=gzip.open if str(path).endswith(".gz") else open
    with opener(path,"rb") as handle:
        for line in handle:
            try:
                obj=orjson.loads(line) if orjson is not None else json.loads(line)
                if isinstance(obj,dict): yield obj
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError): continue

def group_members(group):
    groups = [value.strip() for value in str(group).split(",") if value.strip()]
    if not groups:
        raise SystemExit("Debe especificar al menos un grupo Wazuh")
    if not os.path.exists(AGENT_GROUPS_BIN): raise SystemExit(f"No existe {AGENT_GROUPS_BIN}")

    all_ids = set()
    for group_name in groups:
        try: process=subprocess.run([AGENT_GROUPS_BIN,"-l","-g",group_name],capture_output=True,text=True,timeout=15)
        except (OSError,subprocess.SubprocessError) as exc: raise SystemExit(f"No se pudo consultar el grupo {group_name}: {exc}") from exc
        output=process.stdout+"\n"+process.stderr
        if process.returncode!=0: raise SystemExit(f"Grupo Wazuh inválido o no disponible: {group_name}\n{output.strip()}")
        ids=set(re.findall(r"\bID:\s*([0-9]+)\b",output))
        if ids:
            all_ids.update(ids)
        elif not re.search(r"0\s+agent\(s\)",output,re.I):
            raise SystemExit(f"No se pudieron obtener agentes del grupo {group_name}")
    return all_ids

def classify(rule_id, groups, level):
    rid=str(rule_id); group_set={str(value).lower() for value in (groups or [])}
    if rid==FIREWALL_RULE: return "active_response"
    if rid in MALWARE_RULES or group_set & MALWARE_GROUPS: return "malware"
    if rid in PRIV_RULES or group_set & {"privilege_escalation","privilege_escalation_root","sudo"}: return "privilege"
    if rid in WEB_RULES or group_set & WEB_GROUPS: return "web"
    if rid in FIM_RULES or group_set & FIM_GROUPS: return "fim"
    if rid in AUTH_RULES or group_set & AUTH_GROUPS: return "authentication"
    if group_set & ATTACK_GROUPS or int(level or 0)>=12: return "attack"
    return "other"

def parse_event(outer):
    rule=outer.get("rule") or {}; rule_id=str(rule.get("id","")); timestamp=parse_timestamp(outer.get("timestamp"))
    if not timestamp: return None
    if rule_id==FIREWALL_RULE:
        # Wazuh 4.x decodes active-responses.log into data.command +
        # data.parameters. The previous parser expected the raw JSON payload
        # in full_log, which made valid firewall-drop executions invisible.
        data=outer.get("data") or {}
        command=data.get("command")
        params=data.get("parameters") or {}

        # En Wazuh 4.x, el evento 651 mezcla dos representaciones:
        # command/parameters vienen estructurados en data, mientras que
        # "program" y el payload completo de firewall-drop pueden permanecer
        # únicamente dentro de full_log. Por eso no debemos exigir program
        # dentro de data.parameters.
        payload=extract_firewall_payload(outer.get("full_log",""))
        if isinstance(payload,dict):
            if command not in {"add","delete"}:
                command=payload.get("command")
            raw_params=payload.get("parameters") or {}
            if raw_params:
                merged_params=dict(raw_params)
                merged_params.update(params)
                params=merged_params
            elif payload.get("program") and "program" not in params:
                params=dict(params)
                params["program"]=payload.get("program")

        if command not in {"add","delete"}:
            return None

        # La propia regla 651 identifica la ejecución de firewall-drop.
        # En Wazuh 4.x "program" puede venir en full_log o en data.parameters;
        # no lo usamos como condición de descarte porque la estructura puede
        # variar entre versiones/decoders.
        program=params.get("program")
        if not program and isinstance(payload,dict):
            program=payload.get("program")

        alert=params.get("alert") or {}
        if not alert and isinstance(payload,dict):
            alert=(payload.get("parameters") or {}).get("alert") or {}
        alert_rule=alert.get("rule") or {}
        agent=alert.get("agent") or {}
        alert_data=alert.get("data") or {}
        # En los eventos 651 de Wazuh 4.x, la IP bloqueada está
        # normalmente en data.parameters.alert.data.srcip.
        src=alert_data.get("srcip") or data.get("srcip") or alert.get("srcip")
        if not src and isinstance(payload,dict):
            payload_params=payload.get("parameters") or {}
            payload_alert=payload_params.get("alert") or {}
            payload_alert_data=payload_alert.get("data") or {}
            src=payload_alert_data.get("srcip") or src
        mitre=alert_rule.get("mitre") or {}
        return {
            "timestamp":parse_timestamp(alert.get("timestamp")) or timestamp,
            "outer_rule":rule_id,
            "rule_id":str(alert_rule.get("id","unknown")),
            "description":standardize_rule_description(str(alert_rule.get("id","unknown")),alert_rule.get("description","Firewall Drop"),alert_rule.get("groups") or []),
            "level":int(alert_rule.get("level",0) or 0),
            "groups":alert_rule.get("groups") or [],
            "agent_id":str(agent.get("id","000")),
            "agent_name":agent.get("name","unknown"),
            "srcip":str(src) if valid_ip(src) else None,
            "command":command,
            "alert_id":str(alert.get("id",outer.get("id",""))),
            "mitre":mitre.get("id",[]),
            "techniques":mitre.get("technique",[]),
            "url":alert_data.get("url"),
        }
    agent=outer.get("agent") or {}; data=outer.get("data") or {}; mitre=rule.get("mitre") or {}
    return {
        "timestamp":timestamp,
        "outer_rule":rule_id,
        "rule_id":rule_id,
        "description":standardize_rule_description(rule_id,rule.get("description","Sin descripción"),rule.get("groups") or []),
        "level":int(rule.get("level",0) or 0),
        "groups":rule.get("groups") or [],
        "agent_id":str(agent.get("id","000")),
        "agent_name":agent.get("name","unknown"),
        "srcip":str(data.get("srcip")) if valid_ip(data.get("srcip")) else None,
        "command":None,
        "alert_id":str(outer.get("id","")),
        "mitre":mitre.get("id",[]),
        "techniques":mitre.get("technique",[]),
        "url":data.get("url"),
    }

def load_events(start,end,allowed):
    files=list(iter_log_files(start,end))
    if not files: raise SystemExit("No se encontraron logs JSON para el período solicitado")
    security_count=0; critical_count=0; source_ips=set(); agents=Counter()
    agent_stats=defaultdict(lambda: {"events":0, "high":0, "ips":set(), "attacks":0})
    categories={name:{"count":0,"ips":set(),"agents":set(),"rules":Counter(),"rule_agents":defaultdict(set)} for name in ("authentication","web","fim","malware","privilege","attack")}
    mitre_counts=Counter(); mitre_names={}; firewall_ips=set(); firewall_rows=defaultdict(set); firewall_attempts=Counter(); firewall_recurrence=Counter(); firewall_rules_by_ip=defaultdict(set); firewall_timeouts=load_firewall_timeouts(); timeline=Counter()
    seen_day=None; seen=set(); today=datetime.now().date()
    for path in files:
        if path == Path(ALERTS_FILE): file_day=today
        else:
            try: file_day=datetime.strptime(f"{path.name[13:15]} {path.parent.name} {path.parent.parent.name}","%d %b %Y").date()
            except (ValueError, IndexError): file_day=None
        if file_day != seen_day: seen_day=file_day; seen=set()
        for outer in iter_json(path):
            rule=outer.get("rule") or {}; outer_rule=str(rule.get("id",""))
            if outer_rule == FIREWALL_RULE:
                # Los eventos 651 son el registro de la ejecución real de
                # firewall-drop. Se procesan de forma independiente para no
                # depender del decoder ni del deduplicado de alertas normales.
                outer_ts=parse_timestamp(outer.get("timestamp"))
                data=outer.get("data") or {}
                params=data.get("parameters") or {}
                alert=params.get("alert") or {}
                command=data.get("command") or params.get("command")
                payload=extract_firewall_payload(outer.get("full_log",""))
                if isinstance(payload,dict):
                    if command not in {"add","delete"}:
                        command=payload.get("command")
                    payload_params=payload.get("parameters") or {}
                    if not alert and isinstance(payload_params,dict):
                        alert=payload_params.get("alert") or {}
                alert_rule=alert.get("rule") or {}
                alert_agent=alert.get("agent") or {}
                alert_data=alert.get("data") or {}
                src=alert_data.get("srcip")
                if not src and isinstance(payload,dict):
                    payload_alert=payload.get("parameters",{}).get("alert") or {}
                    src=(payload_alert.get("data") or {}).get("srcip")
                    if not alert_rule: alert_rule=payload_alert.get("rule") or {}
                    if not alert_agent: alert_agent=payload_alert.get("agent") or {}
                event_ts=parse_timestamp(alert.get("timestamp")) or outer_ts
                agent_id=str(alert_agent.get("id","000"))
                agent_name=alert_agent.get("name","unknown")
                if (command=="add" and valid_ip(src) and event_ts and start<=event_ts<end
                        and (allowed is None or agent_id in allowed)):
                    rule_id=str(alert_rule.get("id","unknown"))
                    alert_groups=alert_rule.get("groups") or []
                    alert_level=int(alert_rule.get("level",0) or 0)
                    if alert_level <= 0 or ({str(value).lower() for value in alert_groups} & REPORT_EXCLUDED_GROUPS):
                        continue
                    description=standardize_rule_description(rule_id,alert_rule.get("description","Firewall Drop"),alert_groups)
                    row_key=(agent_id,agent_name,rule_id,description)
                    src_str=str(src)
                    firewall_rows[row_key].add(src_str)
                    firewall_ips.add(src_str)
                    firewall_recurrence[src_str] += 1
                    firewall_rules_by_ip[src_str].add((rule_id,description))
                continue
            outer_ts=parse_timestamp(outer.get("timestamp"))
            if not outer_ts or outer_ts<start or outer_ts>=end: continue
            event=parse_event(outer)
            if not event or event["timestamp"]<start or event["timestamp"]>=end: continue
            if allowed is not None and event["agent_id"] not in allowed: continue
            if report_event_exempt(event): continue
            # Replica en el reporte de la excepción 20007: las sesiones
            # systemd-user de usuarios como apache no son accesos interactivos.
            if (
                event["rule_id"] == "40101"
                and re.search(
                    r"pam_unix\(systemd-user:session\):\s+session\s+opened",
                    str(outer.get("full_log", "")),
                    flags=re.IGNORECASE,
                )
            ):
                continue
            key=event["alert_id"]
            if key:
                if key in seen: continue
                seen.add(key)
            category=classify(event["rule_id"],event["groups"],event["level"]); event_agent=(event["agent_id"],event["agent_name"])
            if event["srcip"]: firewall_attempts[(event["agent_id"],event["rule_id"],event["srcip"])] += 1
            if category=="other": continue
            security_count += 1
            timeline[event["timestamp"].date()] += 1
            if event["level"]>=13: critical_count += 1
            if event["srcip"]: source_ips.add(event["srcip"])
            agents[event_agent] += 1
            agent_info=agent_stats[event_agent]
            agent_info["events"] += 1
            if event["level"] >= 13: agent_info["high"] += 1
            if event["srcip"]: agent_info["ips"].add(event["srcip"])
            if category == "attack": agent_info["attacks"] += 1
            info=categories[category]; info["count"] += 1
            if event["srcip"]: info["ips"].add(event["srcip"])
            info["agents"].add(event["agent_id"])
            rule_key=(event["rule_id"],event["description"]); info["rules"][rule_key] += 1; info["rule_agents"][rule_key].add(event["agent_name"])
            techniques=event.get("techniques") or []
            for index,mitre_id in enumerate(event.get("mitre") or []):
                mitre_counts[mitre_id] += 1
                if index<len(techniques) and techniques[index]: mitre_names[mitre_id]=techniques[index]
    firewall_result=[]
    for key,ips in firewall_rows.items():
        agent_id,agent_name,rule_id,description=key; attempts=sum(firewall_attempts[(agent_id,rule_id,ip)] for ip in ips)
        if attempts==0: attempts=len(ips)
        firewall_result.append({"agent_id":agent_id,"agent_name":agent_name,"rule_id":rule_id,"description":description,"ips":sorted(ips,key=lambda v:(ipaddress.ip_address(v).version,ipaddress.ip_address(v))),"attempts":attempts})
    return {"security_count":security_count,"critical_count":critical_count,"source_ips":source_ips,"agents":agents,"agent_stats":agent_stats,"categories":categories,"mitre_counts":mitre_counts,"mitre_names":mitre_names,"firewall_ips":firewall_ips,"firewall_rows":sorted(firewall_result,key=lambda r:r["agent_name"].lower()),"firewall_recurrence":firewall_recurrence,"firewall_rules_by_ip":firewall_rules_by_ip,"firewall_timeouts":firewall_timeouts,"timeline":timeline}

def section_rows(info):
    merged = {}
    for (rule_id, description), count in info["rules"].most_common():
        entry = merged.setdefault(
            rule_id,
            {"description": description, "count": 0, "agents": set()},
        )
        entry["count"] += count
        entry["agents"].update(info["rule_agents"][(rule_id, description)])
    rows = [
        (rule_id, entry["description"], entry["count"], sorted(entry["agents"]))
        for rule_id, entry in merged.items()
    ]
    rows.sort(key=lambda row: (-row[2], row[0]))
    return rows[:12]

def mitre_rows(summary):
    counts=summary["mitre_counts"]; names=summary["mitre_names"]
    return [(mid,names.get(mid,"Técnica MITRE ATT&CK"),MITRE_DESCRIPTIONS.get(mid,"Comportamiento asociado a una técnica de ataque o intrusión; Wazuh la vinculó con esta detección."),count) for mid,count in counts.most_common()]

def generate_html(summary,title,subtitle,period,group,lang="es"):
    L=labels(lang); security_count=summary["security_count"]; critical_count=summary["critical_count"]; all_ips=summary["source_ips"]; agents=summary["agents"]; agent_stats=summary["agent_stats"]; categories=summary["categories"]; firewall_rows=summary["firewall_rows"]; firewall_ips=summary["firewall_ips"]; cve_summary=summary.get("cve_summary") or {}
    bg="#f4f5f3"; dark="#102d38"; orange="#ff5a2f"; coral="#ff6b4a"; text="#19333e"; muted="#667b84"; border="#e1e5e4"; page=[f"<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'></head><body style='margin:0;padding:0;background:{bg};font-family:Arial,Helvetica,sans-serif;color:{text};'>"]
    page.append("<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='width:100%;background:#f4f5f3;'>")
    page.append(f"<tr><td style='height:6px;background:{orange};font-size:0;line-height:0;'>&nbsp;</td></tr>")
    page.append("<tr><td align='center' style='padding:18px 10px 34px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='width:100%;max-width:1120px;background:#ffffff;border:1px solid #e1e5e4;'>")
    page.append("<tr><td style='padding:0;background:#06141d;'>"
                 "<img src='https://TU_HOSTNAME/obox/img/banner-reporte-wazuh.png' alt='OrangeBox - Reporte de Seguridad Wazuh' width='1120' style='display:block;width:100%;max-width:1120px;height:auto;border:0;'>"
                 "</td></tr>")
    page.append(f"<tr><td style='padding:26px 26px 16px;'><div style='color:{orange};font-size:10px;font-weight:800;letter-spacing:1.8px;'>ORANGEBOX SECURITY · WAZUH</div><div style='font-size:30px;line-height:1.12;font-weight:800;margin-top:6px;color:{text};'>{esc(title)}</div><div style='font-size:14px;line-height:1.5;color:{muted};padding-top:7px;'>{esc(subtitle)}</div><table role='presentation' cellpadding='0' cellspacing='0' border='0' style='margin-top:16px;'><tr><td style='background:#f3f5f4;border:0;border-radius:20px;padding:9px 14px;font-size:11px;color:#526873;'><b>CLIENTE</b>&nbsp; {esc(group)}</td><td width='8'></td><td style='background:{orange};border-radius:20px;padding:9px 14px;font-size:11px;color:#ffffff;'><b>PERÍODO</b>&nbsp; {esc(period)}</td></tr></table></td></tr>")
    page.append("<tr><td style='padding:0 22px 24px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='8' border='0'><tr>")
    metrics=[(security_count,L["security_events"],"#eef4f6"),(critical_count,L["high_alerts"],"#fff0eb"),(len(all_ips),L["source_ips"],"#eef6f5"),(len(agents),L["systems"],"#f2f5f4"),(len(firewall_ips),L["blocked_ips"],"#fff1ec")]
    card_width=f"{100/len(metrics):.2f}%";
    for value,label,tint in metrics:
        page.append(
            f"<td width='{card_width}' valign='top' style='padding:0;'>"
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='background:{tint};border:1px solid #e0e6e4;border-radius:12px;'>"
            f"<tr><td style='padding:18px 12px 17px;'>"
            f"<div style='font-size:30px;line-height:1;font-weight:800;color:{dark};'>{value:,}</div>"
            f"<div style='font-size:9px;line-height:1.35;font-weight:800;letter-spacing:.7px;text-transform:uppercase;color:{muted};margin-top:9px;'>{esc(label)}</div>"
            f"<div style='width:34px;height:4px;background:{orange};margin-top:13px;font-size:1px;line-height:4px;'>&nbsp;</div>"
            f"</td></tr>"
            f"</table></td>"
        )
    page.append("</tr></table></td></tr>")
    def section_open(icon,heading,sub=None):
        section=f"<tr><td style='padding:0 22px 20px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='border:1px solid {border};border-radius:12px;background:#ffffff;'><tr><td style='background:#ffffff;border-bottom:1px solid {border};padding:15px 16px;font-size:17px;font-weight:800;color:{text};'><span style='color:{orange};font-size:13px;'>{icon}</span>&nbsp; {esc(heading)}</td></tr>"
        if sub: section+=f"<tr><td style='padding:8px 14px 5px;color:#78909c;font-size:12px;'>{esc(sub)}</td></tr>"
        return section
    def section_close(): return "</table></td></tr>"
    page.append(section_open("🛡",L["firewall"],L["firewall_sub"]))
    if firewall_rows:
        # Agrupa las ejecuciones reales de firewall-drop por motivo de bloqueo.
        # Una IP cuenta una sola vez dentro de cada motivo, aunque haya más de
        # una ejecución/alerta asociada al mismo bloqueo.
        firewall_by_reason=defaultdict(lambda: {"ips":set(), "attempts":0, "rules":set()})
        for row in firewall_rows:
            reason_key=(row["rule_id"],row["description"])
            firewall_by_reason[reason_key]["ips"].update(row["ips"])
            firewall_by_reason[reason_key]["attempts"] += row["attempts"]
            firewall_by_reason[reason_key]["rules"].add(row["rule_id"])
        firewall_reasons=sorted(firewall_by_reason.items(), key=lambda item:(-len(item[1]["ips"]), -item[1]["attempts"], item[0][0]))

        page.append("<tr><td style='padding:0 8px 8px;overflow-wrap:anywhere;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
        page.append(f"<tr><td style='background:#102d38;color:#fff;padding:10px;font-size:10px;font-weight:800;letter-spacing:.35px;'>{esc(L['reason'])}</td><td style='background:#102d38;color:#fff;padding:10px;font-size:10px;font-weight:800;letter-spacing:.35px;'>{esc(L['rule'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['blocked_ips'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['attempts'])}</td></tr>")
        for (rule_id,description),data in firewall_reasons:
            page.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:12px;overflow-wrap:anywhere;'>{esc(description)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:12px;'>{esc(rule_id)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{len(data['ips']):,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{data['attempts']:,}</td></tr>")
        page.append("</table></td></tr>")
    else: page.append(f"<tr><td style='padding:10px 14px;color:#147a4a;font-size:12px;'>{esc(L['no_firewall'])}</td></tr>")
    page.append(f"<tr><td style='background:#f7f9f8;border:0;border-left:4px solid {orange};border-radius:0 8px 8px 0;padding:11px 14px;color:#49616b;font-size:12px;'><b>{len(firewall_ips):,}</b> {esc(L['blocked_ips'].lower())} automáticamente · <b>{sum(row['attempts'] for row in firewall_rows):,}</b> {esc(L['attempts'].lower())} asociados a estos bloqueos.</td></tr><tr><td style='padding:0 14px 12px;color:#78909c;font-size:11px;'>{esc(L['firewall_note'])}</td></tr>")
    page.append(section_close())

    # IPs con más de una ejecución real de firewall-drop durante el período.
    firewall_recurrence=summary["firewall_recurrence"]
    firewall_rules_by_ip=summary["firewall_rules_by_ip"]
    firewall_timeouts=summary["firewall_timeouts"]
    recidivists=[ip for ip,count in firewall_recurrence.items() if count > 1]
    page.append(section_open("🔁",L["recidivist"],L["recidivist_sub"]))
    if recidivists:
        recidivists.sort(key=lambda ip:(-firewall_recurrence[ip], ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip))))
        page.append("<tr><td style='padding:0 8px 8px;overflow-wrap:anywhere;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
        page.append(f"<tr><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>IP</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['block_count'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['trigger_rules'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['ban_duration'])}</td></tr>")
        for src in recidivists:
            rules=sorted(firewall_rules_by_ip[src], key=lambda item:item[0])
            rule_text="<br>".join(f"<span style='font-family:monospace;color:#d65d00;font-weight:bold;'>{esc(rule_id)}</span> — {esc(description)}" for rule_id,description in rules)
            durations=sorted({format_duration(firewall_timeouts.get(rule_id)) for rule_id,_ in rules})
            duration_text=", ".join(durations)
            page.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-size:12px;font-weight:bold;'>{esc(src)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{firewall_recurrence[src]:,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;line-height:1.4;overflow-wrap:anywhere;'>{rule_text}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;white-space:nowrap;'>{esc(duration_text)}</td></tr>")
        page.append("</table></td></tr>")
        page.append(f"<tr><td style='padding:0 14px 12px;color:#78909c;font-size:11px;'>El tiempo mostrado corresponde al <b>tiempo de bloqueo configurado en Wazuh</b> para cada regla de respuesta automática; no representa necesariamente el tiempo restante de un bloqueo histórico.</td></tr>")
    else:
        page.append("<tr><td style='padding:10px 14px;color:#78909c;font-size:12px;'>No hubo IPs con más de una ejecución de firewall-drop durante el período.</td></tr>")
    page.append(section_close())

    # Resumen de vulnerabilidades críticas actuales del Wazuh Indexer.
    page.append(section_open("🛡",L["cve"],L["cve_sub"]))
    if cve_summary.get("error"):
        page.append(
            f"<tr><td style='padding:10px 14px;color:#8a3d2d;font-size:12px;'>{esc(L['cve_error'])} {esc(cve_summary['error'])}</td></tr>"
        )
    else:
        cve_total=int(cve_summary.get("total",0) or 0)
        cve_agents=cve_summary.get("agents") or {}
        page.append(
            f"<tr><td style='padding:0 8px 8px;color:#78909c;font-size:11px;'>"
            f"<b>{cve_total:,}</b> {esc(L['cve_total'].lower())} · "
            f"<b>{len(cve_agents):,}</b> {esc(L['cve_systems'].lower())}</td></tr>"
        )
        unsupported_agents=cve_summary.get("unsupported_agents") or {}
        if cve_agents:
            page.append("<tr><td style='padding:0 8px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
            page.append(
                f"<tr><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['cve_agent'])}</td>"
                f"<td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;text-align:center;'>{esc(L['cve_count'])}</td></tr>"
            )
            cve_rows=sorted(
                cve_agents.values(),
                key=lambda item:(-int(item.get("count",0)), str(item.get("name","")).lower()),
            )
            for item in cve_rows:
                page.append(
                    f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;overflow-wrap:anywhere;'>{esc(item.get('name') or 'Agente desconocido')}</td>"
                    f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{int(item.get('count',0)):,}</td></tr>"
                )
            page.append("</table></td></tr>")
        elif not unsupported_agents:
            page.append(f"<tr><td style='padding:10px 14px;color:#147a4a;font-size:12px;'>{esc(L['cve_none'])}</td></tr>")

        if unsupported_agents:
            names=", ".join(
                str(item.get("name") or f"Agente {agent_id}")
                for agent_id,item in sorted(
                    unsupported_agents.items(),
                    key=lambda item:str(item[1].get("name","")).lower(),
                )
            )
            page.append(
                f"<tr><td style='padding:10px 14px;color:#8a5a20;font-size:12px;'>{esc(L['cve_unsupported'])}<br><b>Agentes:</b> {esc(names)}</td></tr>"
            )
    page.append(section_close())

    # Resumen de servidores: métricas derivadas de las alertas procesadas.
    page.append(section_open("🖥",L["servers"],L["servers_sub"]))
    server_rows=sorted(agent_stats.items(), key=lambda item:(-item[1]["events"], item[0][1].lower()))
    if server_rows:
        page.append("<tr><td style='padding:0 8px 8px;overflow-wrap:anywhere;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
        page.append(f"<tr><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Servidor</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['events'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['high'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['source_ips_col'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['attack_alerts'])}</td></tr>")
        for (agent_id,agent_name),data in server_rows[:15]:
            page.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:12px;font-weight:bold;overflow-wrap:anywhere;'>{esc(agent_name)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{data['events']:,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{data['high']:,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{len(data['ips']):,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{data['attacks']:,}</td></tr>")
        page.append("</table></td></tr>")
        if len(server_rows)>15:
            page.append(f"<tr><td style='padding:0 14px 12px;color:#78909c;font-size:11px;'>Mostrando los 15 servidores con más eventos de un total de {len(server_rows):,}.</td></tr>")
    else:
        page.append(f"<tr><td style='padding:10px 14px;color:#147a4a;font-size:12px;'>{esc(L['no_servers'])}</td></tr>")
    page.append(section_close())
    section_labels=[("🔐",L["access"],"authentication"),("🌐",L["web"],"web"),("📁",L["fim"],"fim"),("🦠",L["malware"],"malware"),("🔑",L["priv"],"privilege"),("🎯",L["attack"],"attack")]
    for icon,label,category in section_labels:
        info=categories[category]; page.append(section_open(icon,label))
        if not info["count"]: page.append(f"<tr><td style='padding:10px 14px;color:#147a4a;font-size:12px;'>{esc(L['attack_note'] if category=='attack' else L['no_activity'])}</td></tr>")
        else:
            page.append(f"<tr><td style='padding:0 8px 8px;color:#78909c;font-size:11px;'><b>{info['count']:,}</b> detecciones · <b>{len(info['ips']):,}</b> IPs · <b>{len(info['agents']):,}</b> sistemas</td></tr><tr><td style='padding:0 8px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Regla</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Descripción</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Detecciones</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Sistemas</td></tr>")
            for rule_id,description,count,names in section_rows(info):
                shown=", ".join(names[:5])+(" …" if len(names)>5 else ""); page.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:11px;'>{esc(rule_id)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;overflow-wrap:anywhere;'>{esc(description)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:11px;'>{count:,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;overflow-wrap:anywhere;'>{esc(shown)}</td></tr>")
            page.append("</table></td></tr>")
        if category=="attack": page.append(f"<tr><td style='padding:0 14px 10px;color:#78909c;font-size:11px;'>{esc(L['attack_note'])}</td></tr>")
        page.append(section_close())
    page.append(section_open("🧭",L["mitre"],"MITRE ATT&CK")); page.append(f"<tr><td style='padding:8px 14px 5px;color:#78909c;font-size:11px;'>{esc(L['mitre_note'])}</td></tr>"); mitre=mitre_rows(summary)
    if mitre:
        page.append("<tr><td style='padding:0 8px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"); page.append(f"<tr><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['technique'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Nombre</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['meaning'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['detections'])}</td></tr>")
        for mitre_id,name,meaning,count in mitre: page.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:11px;'>{esc(mitre_id)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;'>{esc(name)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;line-height:1.35;'>{esc(meaning)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:11px;'>{count:,}</td></tr>")
        page.append("</table></td></tr>")
    else: page.append("<tr><td style='padding:10px 14px;color:#78909c;font-size:12px;'>No se encontraron técnicas MITRE ATT&CK en las alertas del período.</td></tr>")
    page.append(f"<tr><td style='padding:10px 14px 18px;'><div style='background:#f7f9fa;border:1px solid #dce5e9;border-left:4px solid {orange};padding:10px 12px;font-size:11px;line-height:1.5;color:#526873;'>{esc(L['technical_note'])}</div></td></tr><tr><td style='background:{dark};border-top:4px solid {orange};padding:14px 20px;color:#c7d2d7;font-size:10px;'><b style='color:#fff;'>ORANGEBOX IT SERVICES</b><br>Monitoreo y seguridad de infraestructura</td></tr></table></td></tr></table></body></html>")
    return "".join(page)

def send_email(subject,body,recipient):
    msg=MIMEMultipart("alternative"); msg["Subject"]=subject; msg["From"]=f"Wazuh SOC <{DEFAULT_FROM}>"; msg["To"]=recipient; msg.attach(MIMEText("OrangeBox Wazuh Security Activity Report.","plain","utf-8")); msg.attach(MIMEText(body,"html","utf-8"))
    with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=30) as smtp: smtp.sendmail(DEFAULT_FROM,[recipient],msg.as_string())

def archive_html(body,label):
    os.makedirs(ARCHIVE_DIR,mode=0o750,exist_ok=True); safe=re.sub(r"[^A-Za-z0-9_.-]+","_",label); path=f"{ARCHIVE_DIR}/security-report-{safe}.html"
    with open(path,"w",encoding="utf-8") as handle: handle.write(body)
    return path

def main():
    parser=argparse.ArgumentParser(description="OrangeBox Wazuh Security Activity Report"); modes=parser.add_mutually_exclusive_group(required=True)
    for name in ("today","yesterday","thisweek","lastweek","thismonth","lastmonth","thisyear","lastyear"): modes.add_argument("--"+name,action="store_true")
    modes.add_argument("--date",help="Día específico YYYY-MM-DD"); parser.add_argument("--group",required=True,help="Grupos Wazuh separados por comas")
    parser.add_argument("--email",action="append",required=True,help="Destinatario. Puede repetirse o contener varias direcciones separadas por comas."); parser.add_argument("--lang",choices=("es","en"),default="es",help="Idioma del informe: es o en"); args=parser.parse_args()
    recipients=[]
    for value in args.email: recipients.extend(r.strip() for r in value.split(",") if r.strip())
    if not recipients: raise SystemExit("Debe especificar al menos un destinatario")
    for recipient in recipients:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+",recipient): raise SystemExit(f"Dirección de correo inválida: {recipient}")
    mode=args.date and f"date:{args.date}" or next(name for name in ("today","yesterday","thisweek","lastweek","thismonth","lastmonth","thisyear","lastyear") if getattr(args,name))
    now=datetime.now().astimezone(); start,end,label=period_bounds(mode,now); allowed=group_members(args.group); summary=load_events(start,end,allowed)
    cve_summary, cve_error = fetch_critical_cves(allowed)
    summary["cve_summary"] = cve_summary
    if cve_error:
        summary["cve_summary"]["error"] = cve_error
    period=f"{start.strftime('%d/%m/%Y %H:%M')} — {end.strftime('%d/%m/%Y %H:%M') if end < now else 'ahora'}"; L=labels(args.lang); body=generate_html(summary,L["report"],L["subtitle"],period,args.group,args.lang); archive=archive_html(body,f"{args.group}-{mode.replace(':','-')}-{start:%Y%m%d}-{end:%Y%m%d}")
    subject_prefix={
        "today": "Reporte Diario de Seguridad",
        "yesterday": "Reporte Diario de Seguridad",
        "thisweek": "Reporte Semanal de Seguridad",
        "lastweek": "Reporte Semanal de Seguridad",
        "thismonth": "Reporte Mensual de Seguridad",
        "lastmonth": "Reporte Mensual de Seguridad",
        "thisyear": "Reporte Anual de Seguridad",
        "lastyear": "Reporte Anual de Seguridad",
    }
    subject=f"📊 [ORANGEBOX] {subject_prefix.get(mode, 'Reporte de Seguridad')} — {args.group}"; sent=[]; failed=[]
    for recipient in recipients:
        try: send_email(subject,body,recipient); sent.append(recipient)
        except Exception as exc: failed.append((recipient,exc))
    security=summary["security_count"]; print(f"Destinatarios enviados: {', '.join(sent) if sent else 'ninguno'}")
    if cve_error:
        print(f"CVE críticos: NO CONSULTADO — {cve_error}")
    else:
        print(f"CVE críticos: {summary['cve_summary']['total']:,} en {len(summary['cve_summary']['agents']):,} sistemas")
    for recipient,exc in failed: print(f"ERROR enviando a {recipient}: {exc}")
    print(f"Grupo: {args.group}"); print(f"Periodo: {period}"); print(f"Eventos de seguridad: {security}"); print(f"Archivo: {archive}")
    if failed: raise SystemExit(1)

if __name__=="__main__": main()
