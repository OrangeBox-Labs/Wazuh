#!/usr/bin/env python3
"""OrangeBox Wazuh - Resumen detallado por grupo.

Reporte operativo orientado al cliente. Reutiliza el motor de extracción,
clasificación y períodos de orangebox-security-report.py, pero presenta el
detalle completo por agente.

Incluye por agente:
- estado e IP del agente;
- eventos de seguridad;
- severidad alta (12-14) y crítica (15-16);
- detecciones clasificadas como ataque;
- IPs de origen observadas;
- distribución por categoría;
- top de reglas por nombre/descripción, sin mostrar IDs;
- IPs bloqueadas por firewall-drop y motivo;
- técnicas MITRE observadas;
- CVE críticos presentes en wazuh-states-vulnerabilities-*.

El reporte no modifica Wazuh ni sus configuraciones. Solo lee información.

Credenciales del indexer para CVE:
1) Variables de entorno WAZUH_INDEXER_USER / WAZUH_INDEXER_PASS, o
2) Wazuh keystore del manager; opcionalmente variables de entorno para pruebas/override.
"""

import argparse
import base64
import html
import importlib.util
import ipaddress
import os
import re
import socket
import ssl
import struct
import subprocess
import urllib.error
import urllib.request
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from xml.etree import ElementTree

BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "orangebox-security-report.py"
INDEXER_CONFIG = Path("/var/ossec/etc/orangebox-indexer.conf")
AGENT_CONTROL = "/var/ossec/bin/agent_control"
AGENT_GROUPS = "/var/ossec/bin/agent_groups"
OSSEC_CONF = Path("/var/ossec/etc/ossec.conf")
ARCHIVE_DIR = Path("/var/ossec/reports/archive")
DEFAULT_FROM = "wazuh@example.com"

LEVEL_HIGH_MIN = 12
LEVEL_CRITICAL_MIN = 15
TOP_RULES = 8
TOP_MITRE = 8

# Grupos funcionales/tecnicos que NO representan clientes.
#
# Cuando el reporte detallado se ejecuta con --group all, estos grupos
# se excluyen para evitar que una funcion del endpoint (por ejemplo
# cPanel o Zimbra) aparezca como si fuera un cliente.
#
# IMPORTANTE:
#   Estos grupos SI pueden consultarse explicitamente con
#   --group <grupo> para generar un reporte operacional interno.
#
# Un nuevo grupo funcional debe agregarse aqui antes de entrar en
# produccion. Los grupos de clientes no necesitan registrarse aqui:
# al solicitar --group <cliente> se consulta directamente el grupo Wazuh.
REPORT_NON_CLIENT_GROUPS = {
    "default",
    "cpanel",
    "zimbra",
}

CATEGORY_LABELS = {
    "authentication": "Autenticación y accesos",
    "web": "Actividad web",
    "fim": "Integridad de archivos",
    "malware": "Malware / archivos sospechosos",
    "privilege": "Escalamiento de privilegios",
    "attack": "Detecciones de ataque",
    "active_response": "Respuestas automáticas",
    "other": "Otros",
}


def esc(value):
    return html.escape(str(value), quote=True)


def num(value):
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return esc(value)


def load_report_module():
    spec = importlib.util.spec_from_file_location("orangebox_security_report", REPORT_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"No se pudo cargar {REPORT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_cmd(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"No se pudo ejecutar {' '.join(args)}: {exc}") from exc
    return p.returncode, p.stdout, p.stderr


def parse_agent_control():
    code, out, err = run_cmd([AGENT_CONTROL, "-l"])
    if code != 0:
        raise SystemExit(f"agent_control -l falló: {err.strip()}")
    agents = {}
    pattern = re.compile(
        r"^\s*ID:\s*(\d+),\s*Name:\s*(.*?),\s*IP:\s*([^,]+),\s*(.+?)\s*$"
    )
    for line in out.splitlines():
        m = pattern.match(line)
        if not m:
            continue
        agent_id, name, ip, status = m.groups()
        agents[agent_id] = {
            "id": agent_id,
            "name": name.strip(),
            "ip": ip.strip(),
            "status": status.strip(),
        }
    return agents


def group_members(group):
    groups = [value.strip() for value in str(group).split(",") if value.strip()]
    if not groups:
        raise SystemExit("Debe especificar al menos un grupo Wazuh")

    all_ids = set()
    for group_name in groups:
        code, out, err = run_cmd([AGENT_GROUPS, "-l", "-g", group_name])
        if code != 0:
            raise SystemExit(f"No se pudo consultar grupo {group_name}: {err.strip()}")

        ids = set(re.findall(r"\bID:\s*(\d+)\b", out))
        if ids:
            all_ids.update(ids)
        elif not re.search(r"0\s+agent\(s\)", out, re.I):
            raise SystemExit(f"No se pudieron obtener agentes del grupo {group_name}")

    return all_ids


def all_groups():
    """Obtiene grupos con agentes, excluyendo grupos tecnicos al usar --group all."""
    try:
        process=subprocess.run([AGENT_GROUPS, "-l"], capture_output=True, text=True, timeout=15)
    except (OSError,subprocess.SubprocessError) as exc:
        raise SystemExit(f"No se pudieron obtener los grupos Wazuh: {exc}") from exc
    output=process.stdout+"\n"+process.stderr
    if process.returncode != 0:
        raise SystemExit(f"agent_groups -l fallo: {output.strip()}")
    groups=[]
    for line in output.splitlines():
        match=re.match(r"^\s{2}(.+?)\s+\((\d+)\)\s*$", line)
        if not match:
            continue
        group_name=match.group(1).strip()
        count=int(match.group(2))
        if count <= 0 or group_name.lower() in REPORT_NON_CLIENT_GROUPS:
            continue
        groups.append(group_name)
    return groups

def fetch_critical_cves(module, agent_ids):
    """Consulta CVE críticos actuales usando el mismo acceso al Indexer del reporte ejecutivo.

    El índice de vulnerabilidades de esta instalación no expone
    vulnerability.status, por lo que la consulta se limita a severity=Critical.
    """
    if not agent_ids:
        return {}, None

    try:
        settings = module.indexer_settings()
    except RuntimeError as exc:
        return {}, str(exc)

    filters = [
        {"term": {"vulnerability.severity": "Critical"}},
        {"terms": {"agent.id": sorted(agent_ids)}},
    ]
    results = defaultdict(dict)
    search_after = None

    while True:
        payload = {
            "size": 1000,
            "track_total_hits": False,
            "_source": [
                "agent.id",
                "agent.name",
                "package.name",
                "package.version",
                "vulnerability.id",
                "vulnerability.severity",
                "vulnerability.score.base",
                "vulnerability.description",
                "vulnerability.reference",
                "vulnerability.detected_at",
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

        data, error = module.indexer_request(
            settings,
            "/wazuh-states-vulnerabilities-*/_search",
            payload,
        )
        if error:
            return {}, error

        hits = ((data.get("hits") or {}).get("hits") or [])
        if not hits:
            break

        for hit in hits:
            source = hit.get("_source") or {}
            agent = source.get("agent") or {}
            vulnerability = source.get("vulnerability") or {}
            package = source.get("package") or {}
            agent_id = str(agent.get("id", "")).strip()
            if agent_id not in agent_ids:
                continue
            if str(vulnerability.get("severity", "")).lower() != "critical":
                continue

            score = (vulnerability.get("score") or {}).get("base")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None

            cve = {
                "id": str(vulnerability.get("id", "") or ""),
                "severity": str(vulnerability.get("severity", "") or ""),
                "score": score,
                "description": str(vulnerability.get("description", "") or ""),
                "package": str(package.get("name", "") or ""),
                "version": str(package.get("version", "") or ""),
                "reference": str(vulnerability.get("reference", "") or ""),
                "detected_at": str(vulnerability.get("detected_at", "") or ""),
            }
            if not cve["id"]:
                continue

            dedupe_key = (cve["id"], cve["package"], cve["version"])
            results[agent_id][dedupe_key] = cve

        next_sort = hits[-1].get("sort")
        if not next_sort:
            break
        if next_sort == search_after:
            return {}, "La paginación del inventario CVE quedó sin avance."
        search_after = next_sort
        if len(hits) < 1000:
            break

    ordered = {}
    for agent_id, values in results.items():
        ordered[agent_id] = sorted(
            values.values(),
            key=lambda item: (
                -(item["score"] or 0),
                item["id"],
                item["package"],
                item["version"],
            ),
        )
    return ordered, None

def fetch_cloudlinux_agents(module, agent_ids):
    """Identifica agentes CloudLinux desde el inventario de sistema."""
    if not agent_ids:
        return set()

    try:
        settings = module.indexer_settings()
    except RuntimeError:
        return set()

    payload = {
        "size": max(1000, len(agent_ids)),
        "track_total_hits": False,
        "_source": [
            "agent.id",
            "host.os.name",
            "host.os.platform",
        ],
        "query": {
            "bool": {
                "filter": [
                    {"terms": {"agent.id": sorted(agent_ids)}},
                ]
            }
        },
    }

    data, error = module.indexer_request(
        settings,
        "/wazuh-states-inventory-system-*/_search",
        payload,
    )
    if error:
        return set()

    cloudlinux = set()
    for hit in (data.get("hits") or {}).get("hits", []):
        source = hit.get("_source") or {}
        agent = source.get("agent") or {}
        host = source.get("host") or {}
        os_info = host.get("os") or {}
        agent_id = str(agent.get("id", "")).strip()
        os_name = str(os_info.get("name") or "").strip().lower()
        os_platform = str(os_info.get("platform") or "").strip().lower()
        # Algunos hosts derivados de AlmaLinux pueden conservar un
        # valor de plataforma heredado. Si el nombre/plataforma identifica
        # AlmaLinux, se considera soportado para el inventario CVE de RHEL/AlmaLinux.
        is_almalinux = "almalinux" in os_name or "almalinux" in os_platform
        is_cloudlinux = (
            os_name == "cloudlinux"
            or os_platform == "cloudlinux"
        )
        if agent_id and is_cloudlinux and not is_almalinux:
            cloudlinux.add(agent_id)

    return cloudlinux


def source_ips(events):
    return {e["srcip"] for e in events if e.get("srcip")}


def parse_events_for_agents(module, start, end, allowed):
    files = list(module.iter_log_files(start, end))
    if not files:
        raise SystemExit("No se encontraron logs JSON para el período solicitado.")

    events = []
    today = datetime.now().date()
    seen_day = None
    seen = set()

    for path in files:
        if path == Path(module.ALERTS_FILE):
            file_day = today
        else:
            try:
                file_day = datetime.strptime(
                    f"{path.name[13:15]} {path.parent.name} {path.parent.parent.name}",
                    "%d %b %Y",
                ).date()
            except (ValueError, IndexError):
                file_day = None

        if file_day != seen_day:
            seen_day = file_day
            seen = set()

        for outer in module.iter_json(path):
            outer_rule = str((outer.get("rule") or {}).get("id", ""))
            if outer_rule != module.FIREWALL_RULE:
                ts = module.parse_timestamp(outer.get("timestamp"))
                if not ts or ts < start or ts >= end:
                    continue

            event = module.parse_event(outer)
            if not event or event["timestamp"] < start or event["timestamp"] >= end:
                continue

            if allowed is not None and event["agent_id"] not in allowed:
                continue

            alert_id = event.get("alert_id", "")
            if alert_id:
                if alert_id in seen:
                    continue
                seen.add(alert_id)

            if event["outer_rule"] == module.FIREWALL_RULE:
                # Active response 10458 is included only once and is treated
                # as a response, not as a normal security detection.
                if event.get("command") != "add":
                    continue

            events.append(event)

    return events


def build_agent_stats(events, agent_info, cves):
    by_agent = defaultdict(list)
    for event in events:
        by_agent[event["agent_id"]].append(event)

    stats = {}
    all_ids = sorted(set(agent_info) | set(by_agent))
    for agent_id in all_ids:
        ev = by_agent.get(agent_id, [])
        normal = [e for e in ev if e.get("outer_rule") != module.FIREWALL_RULE]

        high = sum(LEVEL_HIGH_MIN <= int(e.get("level", 0)) < LEVEL_CRITICAL_MIN for e in normal)
        critical = sum(int(e.get("level", 0)) >= LEVEL_CRITICAL_MIN for e in normal)
        attacks = sum(e.get("category") == "attack" for e in normal)

        rule_counts = Counter(
            e.get("description", "Detección sin descripción")
            for e in normal
        )

        cats = Counter(e.get("category", "other") for e in normal)
        ips = source_ips(normal)

        ip_rules = defaultdict(Counter)
        for e in normal:
            srcip = e.get("srcip")
            if not srcip:
                continue
            rule_key = (
                str(e.get("rule_id", "unknown")),
                e.get("description", "Detección sin descripción"),
            )
            ip_rules[srcip][rule_key] += 1

        blocked = defaultdict(lambda: {"count": 0, "reasons": Counter(), "rules": Counter()})
        for e in ev:
            if e.get("outer_rule") != module.FIREWALL_RULE or not e.get("srcip"):
                continue
            blocked[e["srcip"]]["count"] += 1
            blocked[e["srcip"]]["reasons"][e.get("description", "Firewall Drop")] += 1
            blocked[e["srcip"]]["rules"][str(e.get("rule_id", "unknown"))] += 1
            rule_key = (
                str(e.get("rule_id", "unknown")),
                e.get("description", "Firewall Drop"),
            )
            ip_rules[e["srcip"]][rule_key] += 1

        mitre = Counter()
        for e in normal:
            values = e.get("mitre") or []
            if isinstance(values, str):
                values = [values]
            for m in values:
                if m:
                    mitre[str(m)] += 1

        info = agent_info.get(
            agent_id,
            {
                "id": agent_id,
                "name": f"Servidor {agent_id}",
                "ip": "unknown",
                "status": "Desconocido",
            },
        )

        stats[agent_id] = {
            "id": agent_id,
            "name": info["name"],
            "ip": info["ip"],
            "status": info["status"],
            "events": len(normal),
            "high": high,
            "critical": critical,
            "attacks": attacks,
            "ips": ips,
            "ip_rules": ip_rules,
            "rules": rule_counts,
            "categories": cats,
            "blocked": blocked,
            "mitre": mitre,
            "cves": cves.get(agent_id, []),
        }
    return stats


def empty_agent_stat(agent_id, info):
    return {
        "id": agent_id,
        "name": info.get("name", f"Servidor {agent_id}"),
        "ip": info.get("ip", "unknown"),
        "status": info.get("status", "Desconocido"),
        "events": 0,
        "high": 0,
        "critical": 0,
        "attacks": 0,
        "ips": set(),
        "ip_rules": defaultdict(Counter),
        "rules": Counter(),
        "categories": Counter(),
        "blocked": defaultdict(lambda: {"count": 0, "reasons": Counter(), "rules": Counter()}),
        "mitre": Counter(),
        "cves": [],
        "vd_unsupported": False,
    }


def init_agent_stats(agent_ids, agent_info):
    stats = {}
    for agent_id in sorted(agent_ids):
        info = agent_info.get(
            agent_id,
            {"id": agent_id, "name": f"Servidor {agent_id}", "ip": "unknown", "status": "Desconocido"},
        )
        stats[agent_id] = empty_agent_stat(agent_id, info)
    return stats


def accumulate_event(agent_stats, event, module):
    agent_id = event["agent_id"]
    stat = agent_stats.get(agent_id)
    if stat is None:
        return

    if event.get("outer_rule") == module.FIREWALL_RULE:
        srcip = event.get("srcip")
        if event.get("command") != "add" or not srcip:
            return
        blocked = stat["blocked"][srcip]
        blocked["count"] += 1
        blocked["reasons"][event.get("description", "Firewall Drop")] += 1
        blocked["rules"][str(event.get("rule_id", "unknown"))] += 1
        return

    category = module.classify(
        event["rule_id"],
        event.get("groups", []),
        event.get("level", 0),
    )

    # No descartar eventos que el motor no pudo categorizar.
    # Se conservan en "other" para que el informe detallado no pierda
    # actividad real de los agentes.
    event["category"] = category
    level = int(event.get("level", 0) or 0)
    stat["events"] += 1

    if LEVEL_HIGH_MIN <= level < LEVEL_CRITICAL_MIN:
        stat["high"] += 1
    elif level >= LEVEL_CRITICAL_MIN:
        stat["critical"] += 1

    if category == "attack":
        stat["attacks"] += 1

    stat["rules"][event.get("description", "Detección sin descripción")] += 1
    stat["categories"][category] += 1

    srcip = event.get("srcip")
    if srcip:
        stat["ips"].add(srcip)
        # El ranking GeoIP representa las mismas detecciones que el reporte
        # ejecutivo: se excluyen eventos sin categoría ("other").
        if category != "other":
            stat["ip_rules"][srcip][
                (str(event.get("rule_id", "unknown")), event.get("description", "Detección sin descripción"))
            ] += 1

    values = event.get("mitre") or []
    if isinstance(values, str):
        values = [values]
    for technique in values:
        if technique:
            stat["mitre"][str(technique)] += 1


def aggregate_events(module, start, end, allowed, agent_stats):
    """Agrega eventos usando la misma mecánica de extracción del reporte ejecutivo.

    Se mantienen los límites de período, la exclusión de eventos no reportables,
    la excepción systemd-user y la deduplicación diaria. Los 10458 de
    firewall-drop se procesan como Active Response reales.
    """
    files = list(module.iter_log_files(start, end))
    if not files:
        raise SystemExit("No se encontraron logs JSON para el período solicitado.")

    today = datetime.now().date()
    seen_day = None
    seen = set()

    for path in files:
        if path == Path(module.ALERTS_FILE):
            file_day = today
        else:
            try:
                file_day = datetime.strptime(
                    f"{path.name[13:15]} {path.parent.name} {path.parent.parent.name}",
                    "%d %b %Y",
                ).date()
            except (ValueError, IndexError):
                file_day = None

        if file_day != seen_day:
            seen_day = file_day
            seen = set()

        for outer in module.iter_json(path):
            rule = outer.get("rule") or {}
            outer_rule = str(rule.get("id", ""))

            if outer_rule == module.FIREWALL_RULE:
                event = module.parse_event(outer)
                if not event or event.get("command") != "add":
                    continue
                if event["timestamp"] < start or event["timestamp"] >= end:
                    continue
                if allowed is not None and event["agent_id"] not in allowed:
                    continue
                accumulate_event(agent_stats, event, module)
                continue

            outer_timestamp = module.parse_timestamp(outer.get("timestamp"))
            if not outer_timestamp or outer_timestamp < start or outer_timestamp >= end:
                continue

            event = module.parse_event(outer)
            if not event or event["timestamp"] < start or event["timestamp"] >= end:
                continue

            if allowed is not None and event["agent_id"] not in allowed:
                continue

            if module.report_event_exempt(event):
                continue

            if (
                event["rule_id"] == "40101"
                and re.search(
                    r"pam_unix\(systemd-user:session\):\s+session\s+opened",
                    str(outer.get("full_log", "")),
                    flags=re.IGNORECASE,
                )
            ):
                continue

            alert_id = event["alert_id"]
            if alert_id:
                if alert_id in seen:
                    continue
                seen.add(alert_id)

            accumulate_event(agent_stats, event, module)


def period_label(mode):
    return {
        "today": "Diario",
        "yesterday": "Diario",
        "thisweek": "Semanal",
        "lastweek": "Semanal",
        "thismonth": "Mensual",
        "lastmonth": "Mensual",
        "thisyear": "Anual",
        "lastyear": "Anual",
    }.get(mode, "Seguridad")


def generate_html(group_sections, title, subtitle, period, total_agents, total_events, total_high, total_critical, total_attacks, vuln_error=None, mitre_descriptions=None):
    logo_url = "https://www.orangebox.cl/obox/img/logo-dark.png"
    dark = "#102d38"
    orange = "#ff5a2f"
    coral = "#ff6b4a"
    text = "#19333e"
    muted = "#667b84"
    soft = "#f4f5f3"
    panel = "#f7f9f8"
    border = "#e1e5e4"
    header_light = "#29414c"

    page = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>{esc(title)}</title>",
        "</head><body style='margin:0;padding:0;background:{soft};color:{text};font-family:Arial,Helvetica,sans-serif;-webkit-text-size-adjust:100%;'>",
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='width:100%;background:#f4f5f3;'>",
        f"<tr><td style='height:6px;background:{orange};font-size:0;line-height:0;'>&nbsp;</td></tr>",
        "<tr><td align='center' style='padding:18px 10px 34px;'>",
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='width:100%;max-width:1120px;background:#ffffff;border:1px solid {border};'>",

        # Header corporativo alojado como imagen para máxima compatibilidad con clientes de correo.
        "<tr><td style='padding:0;background:#06141d;'>",
        "<img src='https://www.orangebox.cl/obox/img/banner-reporte-wazuh.png' alt='OrangeBox - Reporte de Seguridad Wazuh' width='1120' style='display:block;width:100%;max-width:1120px;height:auto;border:0;'>",
        "</td></tr>",

        # Report heading
        "<tr><td style='padding:26px 28px 12px;'>",
        f"<div style='color:{orange};font-size:10px;font-weight:800;letter-spacing:2px;'>ORANGEBOX SECURITY · WAZUH</div>",
        f"<div style='font-size:30px;line-height:1.12;font-weight:800;color:{text};margin-top:7px;'>{esc(title)}</div>",
        "<table role='presentation' cellpadding='0' cellspacing='0' border='0' style='margin-top:16px;'><tr>",
        f"<td style='background:{panel};border:1px solid {border};border-radius:18px;padding:8px 13px;font-size:11px;color:#526873;'><b>PERÍODO</b>&nbsp; {esc(period)}</td>",
        "<td width='8'></td>",
        f"<td style='background:{orange};border-radius:18px;padding:8px 13px;font-size:11px;color:#ffffff;'><b>SERVIDORES</b>&nbsp; {num(total_agents)}</td>",
        "<td width='8'></td>" if len(group_sections) > 1 else "",
        "".join(
            f"<td style='background:{panel};border:1px solid {border};border-radius:18px;padding:8px 12px;font-size:10px;color:#526873;text-align:center;'><b>GRUPO</b>&nbsp; {esc(group_name)}</td><td width='6'></td>"
            for group_name, _ in group_sections
        ) if len(group_sections) > 1 else "",
        "</tr></table></td></tr>",

        # Executive metric strip
        "<tr><td style='padding:4px 20px 22px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>",
        "<tr>",
        f"<td style='padding:6px;'><div style='background:{panel};border:1px solid {border};border-radius:10px;text-align:center;padding:13px 8px;'><div style='font-size:24px;font-weight:800;color:{text};'>{num(total_agents)}</div><div style='font-size:9px;font-weight:800;letter-spacing:.9px;color:{muted};margin-top:3px;'>SERVIDORES</div></div></td>",
        f"<td style='padding:6px;'><div style='background:{panel};border:1px solid {border};border-radius:10px;text-align:center;padding:13px 8px;'><div style='font-size:24px;font-weight:800;color:{text};'>{num(total_events)}</div><div style='font-size:9px;font-weight:800;letter-spacing:.9px;color:{muted};margin-top:3px;'>EVENTOS</div></div></td>",
        f"<td style='padding:6px;'><div style='background:#fff7f2;border:1px solid #f5d7ca;border-radius:10px;text-align:center;padding:13px 8px;'><div style='font-size:24px;font-weight:800;color:{coral};'>{num(total_high)}</div><div style='font-size:9px;font-weight:800;letter-spacing:.9px;color:{muted};margin-top:3px;'>ALERTAS ALTA SEVERIDAD (12–14)</div></div></td>",
        f"<td style='padding:6px;'><div style='background:#fff4ef;border:1px solid #f2c8b9;border-radius:10px;text-align:center;padding:13px 8px;'><div style='font-size:24px;font-weight:800;color:{orange};'>{num(total_critical)}</div><div style='font-size:9px;font-weight:800;letter-spacing:.9px;color:{muted};margin-top:3px;'>ALERTAS CRÍTICAS (15–16)</div></div></td>",
        f"<td style='padding:6px;'><div style='background:{panel};border:1px solid {border};border-radius:10px;text-align:center;padding:13px 8px;'><div style='font-size:24px;font-weight:800;color:{text};'>{num(total_attacks)}</div><div style='font-size:9px;font-weight:800;letter-spacing:.9px;color:{muted};margin-top:3px;'>DETECCIONES DE ATAQUE</div></div></td>",
        "</tr></table></td></tr>",
    ]


    # CVE summary: unique CVE IDs and unique package/version combinations
    # across the selected agents. Repeated group membership is de-duplicated.
    cve_ids = set()
    cve_packages = set()
    cve_agents = set()
    blocked_ips = set()
    for _, stats in group_sections:
        for agent_id, stat in stats.items():
            blocked_ips.update(stat["blocked"].keys())
            for cve in stat["cves"]:
                if cve.get("id"):
                    cve_ids.add(str(cve["id"]))
                    cve_agents.add(agent_id)
                package = str(cve.get("package", "") or "")
                version = str(cve.get("version", "") or "")
                if package:
                    cve_packages.add((package, version))

    page.append(
        "<tr><td style='padding:0 22px 20px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='8' border='0'>"
        "<tr>"
        f"<td valign='top' style='padding:14px;background:#fff1ec;border:1px solid #f0ddd7;border-radius:12px;text-align:center;'><div style='font-size:26px;font-weight:800;color:#19333e;'>{num(len(cve_ids))}</div><div style='font-size:9px;font-weight:800;letter-spacing:.7px;text-transform:uppercase;color:#667b84;margin-top:6px;'>CVE críticos únicos</div></td>"
        f"<td valign='top' style='padding:14px;background:#fff4ef;border:1px solid #f0ddd7;border-radius:12px;text-align:center;'><div style='font-size:26px;font-weight:800;color:#19333e;'>{num(len(blocked_ips))}</div><div style='font-size:9px;font-weight:800;letter-spacing:.7px;text-transform:uppercase;color:#667b84;margin-top:6px;'>IPS BLOQUEADAS</div></td>"
        f"<td valign='top' style='padding:14px;background:#eef4f6;border:1px solid #dde6e8;border-radius:12px;text-align:center;'><div style='font-size:26px;font-weight:800;color:#19333e;'>{num(len(cve_packages))}</div><div style='font-size:9px;font-weight:800;letter-spacing:.7px;text-transform:uppercase;color:#667b84;margin-top:6px;'>Paquetes/versiones afectados</div></td>"
        f"<td valign='top' style='padding:14px;background:#f2f5f4;border:1px solid #e0e6e4;border-radius:12px;text-align:center;'><div style='font-size:26px;font-weight:800;color:#19333e;'>{num(len(cve_agents))}</div><div style='font-size:9px;font-weight:800;letter-spacing:.7px;text-transform:uppercase;color:#667b84;margin-top:6px;'>Servidores con CVE crítico</div></td>"
        "</tr></table></td></tr>",
    )

    if vuln_error:
        page.append(
            "<tr><td style='padding:0 28px 18px;'><div style='background:#fff7f2;border:1px solid #f2c8b9;border-left:4px solid "
            f"{orange};padding:13px 14px;font-size:12px;line-height:1.5;color:#8a3d2d;'>"
            f"<b>Vulnerabilidades:</b> no fue posible consultar el inventario CVE del Wazuh indexer en esta ejecución. {esc(vuln_error)}"
            "</div></td></tr>"
        )

    # GeoIP consolidado: las IPs de origen representan detecciones de seguridad
    # clasificadas por el reporte; las IPs bloqueadas se mantienen como ranking separado.
    all_ip_rules = defaultdict(lambda: {"rules": Counter(), "servers": set()})
    geo_blocked_ips = set()
    for _, stats in group_sections:
        for _, stat in stats.items():
            geo_blocked_ips.update(stat.get("blocked", {}).keys())
            for ip, rules in stat.get("ip_rules", {}).items():
                for rule_key, count in rules.items():
                    all_ip_rules[ip]["rules"][rule_key] += count
                all_ip_rules[ip]["servers"].add(stat["name"])

    geo_module = load_report_module()
    geo = geo_module.geoip_country_map(set(all_ip_rules.keys()) | geo_blocked_ips)
    source_country_rank = geo_module.geoip_country_ranking(all_ip_rules.keys(), geo)
    blocked_country_rank = geo_module.geoip_country_ranking(geo_blocked_ips, geo)

    source_rows = "".join(
        f"<tr><td style='border-top:1px solid #e3e9ec;padding:7px;text-align:center;color:#78909c;font-size:11px;'>{i}</td>"
        f"<td style='border-top:1px solid #e3e9ec;padding:6px;text-align:center;font-size:18px;'>{esc(geo_module.country_flag(code))}</td>"
        f"<td style='border-top:1px solid #e3e9ec;padding:7px;font-size:11px;font-weight:bold;'>{esc(name)}</td>"
        f"<td style='border-top:1px solid #e3e9ec;padding:7px;text-align:right;font-size:12px;font-weight:bold;'>{count:,}</td></tr>"
        for i, ((code, name), count) in enumerate(source_country_rank, 1)
    ) or "<tr><td colspan='4' style='padding:8px;color:#78909c;font-size:10px;'>Sin IPs públicas.</td></tr>"

    blocked_rows = "".join(
        f"<tr><td style='border-top:1px solid #e3e9ec;padding:7px;text-align:center;color:#78909c;font-size:11px;'>{i}</td>"
        f"<td style='border-top:1px solid #e3e9ec;padding:6px;text-align:center;font-size:18px;'>{esc(geo_module.country_flag(code))}</td>"
        f"<td style='border-top:1px solid #e3e9ec;padding:7px;font-size:11px;font-weight:bold;'>{esc(name)}</td>"
        f"<td style='border-top:1px solid #e3e9ec;padding:7px;text-align:right;font-size:12px;font-weight:bold;'>{count:,}</td></tr>"
        for i, ((code, name), count) in enumerate(blocked_country_rank, 1)
    ) or "<tr><td colspan='4' style='padding:8px;color:#78909c;font-size:10px;'>No hubo IPs bloqueadas.</td></tr>"

    page.append(
        f"<tr><td style='padding:0 22px 20px;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='border:1px solid {border};border-radius:12px;background:#ffffff;'>"
        f"<tr><td style='background:#ffffff;border-bottom:1px solid {border};padding:15px 16px;font-size:17px;font-weight:800;color:{text};'><span style='color:{orange};font-size:13px;'>🌍</span>&nbsp; Top países · eventos de seguridad</td></tr>"
        f"<tr><td style='padding:8px 14px 5px;color:#78909c;font-size:11px;'>IPs públicas únicas asociadas a detecciones de seguridad; no implica por sí solo un ataque confirmado.</td></tr>"
        "<tr><td style='padding:0 8px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
        "<tr><td colspan='4' style='background:#102d38;color:#fff;padding:9px;font-size:11px;font-weight:800;'>Top países · eventos de seguridad</td></tr>"
        "<tr><td style='background:#29414c;color:#fff;padding:6px;font-size:10px;font-weight:bold;width:28px;'>#</td>"
        "<td style='background:#29414c;color:#fff;padding:6px;font-size:10px;font-weight:bold;width:34px;text-align:center;'>FLAG</td>"
        "<td style='background:#29414c;color:#fff;padding:6px;font-size:10px;font-weight:bold;'>PAÍS</td>"
        "<td style='background:#29414c;color:#fff;padding:6px;font-size:10px;font-weight:bold;text-align:right;'>IPS</td></tr>"
        f"{source_rows}"
        "</table></td></tr>"
        "<tr><td style='padding:0 14px 10px;color:#78909c;font-size:10px;'>"
        "El ranking cuenta IPs públicas únicas asociadas a detecciones de seguridad clasificadas por el reporte."
        "</td></tr></table></td></tr>"
    )

    blocked_detail = defaultdict(lambda: {"reasons": Counter(), "rules": Counter(), "servers": set(), "count": 0})
    for _, stats in group_sections:
        for _, stat in stats.items():
            for ip, data in stat.get("blocked", {}).items():
                blocked_detail[ip]["count"] += int(data.get("count", 0) or 0)
                blocked_detail[ip]["servers"].add(stat["name"])
                for reason, count in data.get("reasons", {}).items():
                    normalized_reason = re.sub(
                        r"\s+DESDE IP (?:PUBLICA|MALICIOSA CONOCIDA)\s+\S+\.?$",
                        "",
                        str(reason or "").strip(),
                        flags=re.IGNORECASE,
                    ).strip()
                    blocked_detail[ip]["reasons"][normalized_reason] += count
                for rule_id, count in data.get("rules", {}).items():
                    blocked_detail[ip]["rules"][str(rule_id)] += count

    blocked_ips_ranked = sorted(
        blocked_detail,
        key=lambda ip: (-blocked_detail[ip]["count"], ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip))),
    )

    page.append(
        f"<tr><td style='padding:0 22px 20px;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='border:1px solid {border};border-radius:12px;background:#ffffff;'>"
        f"<tr><td style='background:#ffffff;border-bottom:1px solid {border};padding:15px 16px;font-size:17px;font-weight:800;color:{text};'><span style='color:{orange};font-size:13px;'>🛡</span>&nbsp; IPs bloqueadas automáticamente</td></tr>"
        f"<tr><td style='padding:8px 14px 5px;color:#78909c;font-size:11px;'>Cada IP aparece una sola vez, mostrando bandera, país, servidores que ejecutaron el bloqueo, tipo de regla y cantidad de bloqueos registrados.</td></tr>"
    )
    if blocked_ips_ranked:
        page.append("<tr><td style='padding:0 8px 8px;overflow-wrap:anywhere;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
        page.append(
            f"<tr><td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;width:110px;white-space:nowrap;'>IP</td>"
            f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;width:18%;'>PAÍS</td>"
            f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;width:21%;'>SERVIDORES</td>"
            f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;'>TIPO DE REGLA</td>"
            f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;text-align:right;width:90px;'>BLOQUEOS</td></tr>"
        )
        for ip in blocked_ips_ranked:
            item = geo.get(ip) or {}
            country = f"{item.get('flag', '🌐')} {item.get('country', 'No disponible')}" if item.get("country") and item.get("country") != "No disponible" else "🌐 No disponible"
            servers = "<br>".join(f"→ {esc(name)}" for name in sorted(blocked_detail[ip]["servers"], key=str.lower))
            rules = ", ".join(sorted(blocked_detail[ip]["rules"].keys()))
            reasons = "<br>".join(
                f"<span style='font-family:monospace;color:#d65d00;font-weight:800;'>{esc(rules)}</span> — {esc(reason)}"
                for reason in list(blocked_detail[ip]["reasons"].keys())[:6]
            )
            page.append(
                f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-size:11px;font-weight:bold;white-space:nowrap;width:110px;'>{esc(ip)}</td>"
                f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;font-weight:bold;'>{esc(country)}</td>"
                f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:10px;line-height:1.45;overflow-wrap:anywhere;'>{servers}</td>"
                f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:10px;line-height:1.45;'>{reasons}</td>"
                f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:right;font-weight:800;font-size:11px;color:{text};'>{num(blocked_detail[ip]['count'])}</td></tr>"
            )
        page.append("</table></td></tr>")
    else:
        page.append("<tr><td style='padding:10px 14px;color:#78909c;font-size:12px;'>No se registraron bloqueos automáticos durante el período.</td></tr>")
    page.append(
        "<tr><td style='padding:0 14px 18px;color:#78909c;font-size:10px;'>"
        "La columna BLOQUEOS indica cuántas ejecuciones de bloqueo se registraron para cada IP durante el período."
        "</td></tr></table></td></tr>"
    )

    page.append(
        f"<tr><td style='padding:0 22px 20px;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='border:1px solid {border};border-radius:12px;background:#ffffff;'>"
        f"<tr><td style='background:#ffffff;border-bottom:1px solid {border};padding:15px 16px;font-size:17px;font-weight:800;color:{text};'><span style='color:{orange};font-size:13px;'>🔎</span>&nbsp; IPs de origen · reglas detectadas</td></tr>"
        f"<tr><td style='padding:8px 14px 5px;color:#78909c;font-size:11px;'>Cada IP aparece una sola vez, agrupando las reglas, tipos de detección y servidores que registraron esa IP durante el período.</td></tr>"
    )

    ranked_ips = sorted(
        all_ip_rules,
        key=lambda ip: (
            -sum(all_ip_rules[ip]["rules"].values()),
            -len(all_ip_rules[ip]["servers"]),
            ipaddress.ip_address(ip).version,
            int(ipaddress.ip_address(ip)),
        ),
    )
    max_detail_ips = int(os.environ.get("ORANGEBOX_DETAILED_GEOIP_MAX_IPS", "200"))
    ranked_ips = ranked_ips[:max_detail_ips]

    if ranked_ips:
        page.append("<tr><td style='padding:0 8px 8px;overflow-wrap:anywhere;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
        page.append(
            f"<tr><td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;width:110px;white-space:nowrap;'>IP</td>"
            f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;width:19%;'>PAÍS</td>"
            f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;width:21%;'>SERVIDORES</td>"
            f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;'>TIPOS / REGLAS DETECTADAS</td></tr>"
        )
        for ip in ranked_ips:
            item = geo.get(ip) or {}
            country = (
                f"{item.get('flag', '🌐')} {item.get('country', 'No disponible')}"
                if item.get("country") and item.get("country") != "No disponible"
                else "🌐 No disponible"
            )
            rule_items = []
            for (rule_id, description), count in all_ip_rules[ip]["rules"].most_common(6):
                rule_items.append(
                    f"<div style='margin-bottom:3px;'><span style='font-family:monospace;color:#d65d00;font-weight:800;'>{esc(rule_id)}</span>"
                    f" — {esc(description)} <span style='color:#78909c;'>({num(count)})</span></div>"
                )
            if len(all_ip_rules[ip]["rules"]) > 6:
                rule_items.append(
                    f"<div style='color:#78909c;font-size:10px;'>+ {len(all_ip_rules[ip]['rules']) - 6} reglas adicionales</div>"
                )
            agent_items = "<br>".join(f"→ {esc(name)}" for name in sorted(all_ip_rules[ip]["servers"], key=str.lower))
            page.append(
                f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-size:11px;font-weight:bold;white-space:nowrap;width:110px;'>{esc(ip)}</td>"
                f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;font-weight:bold;'>{esc(country)}</td>"
                f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:10px;line-height:1.45;overflow-wrap:anywhere;'>{agent_items}</td>"
                f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:10px;line-height:1.45;'>{''.join(rule_items)}</td></tr>"
            )
        page.append("</table></td></tr>")
        if len(all_ip_rules) > max_detail_ips:
            page.append(
                f"<tr><td style='padding:0 14px 12px;color:#78909c;font-size:11px;'>"
                f"Mostrando las {max_detail_ips} IPs con más detecciones de un total de {len(all_ip_rules):,} IPs de origen.</td></tr>"
            )
    else:
        page.append("<tr><td style='padding:10px 14px;color:#78909c;font-size:12px;'>No se encontraron IPs públicas de origen durante el período.</td></tr>")

    page.append(
        "<tr><td style='padding:0 14px 18px;color:#78909c;font-size:10px;'>"
        "<b>GeoIP:</b> DB-IP. La geolocalización es aproximada y no representa necesariamente la ubicación física real del origen."
        "</td></tr></table></td></tr>"
    )

    for group_name, stats in group_sections:
        page.append(
            "<tr><td style='padding:14px 20px 8px;'>"
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='border-bottom:1px solid {border};'><tr>"
            f"<td style='padding:12px 6px 14px;color:{text};font-size:22px;font-weight:800;'>{esc(group_name)}</td>"
            "</tr></table></td></tr>"
        )

        if not stats:
            page.append(
                "<tr><td style='padding:8px 26px 24px;color:#78909c;font-size:12px;'>Grupo sin servidores asignados.</td></tr>"
            )
            continue

        for agent_id in sorted(stats, key=lambda k: stats[k]["name"].lower()):
            s = stats[agent_id]
            page.extend([
                "<tr><td style='padding:0 20px 24px;'>"
                f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='background:#ffffff;border:1px solid {border};border-radius:12px;'>"
                f"<tr><td style='background:{dark};padding:15px 16px;border-left:5px solid {orange};'>"
                f"<div style='font-size:17px;line-height:1.25;font-weight:800;color:#ffffff;'>{esc(s['name'])}</div>"
                f"<div style='font-size:10px;color:#b8c5cb;margin-top:4px;'>ID {esc(s['id'])} &nbsp;·&nbsp; {esc(s['ip'])}</div>"
                f"<div style='display:inline-block;background:#1d414e;color:#d8e1e4;border:1px solid #3c5963;border-radius:14px;padding:4px 9px;margin-top:8px;font-size:9px;font-weight:800;letter-spacing:.5px;'>ESTADO: {esc(s['status'])}</div>"
                "</td></tr>",

                # Agent metric cards
                "<tr><td style='padding:12px 12px 4px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>",
                f"<td style='padding:4px;'><div style='background:{panel};border-radius:9px;text-align:center;padding:10px 5px;'><div style='font-size:19px;font-weight:800;color:{text};'>{num(s['events'])}</div><div style='font-size:8px;color:{muted};font-weight:800;letter-spacing:.7px;'>EVENTOS</div></div></td>",
                f"<td style='padding:4px;'><div style='background:#fff7f2;border-radius:9px;text-align:center;padding:10px 5px;'><div style='font-size:19px;font-weight:800;color:{coral};'>{num(s['high'])}</div><div style='font-size:8px;color:{muted};font-weight:800;letter-spacing:.7px;'>ALERTAS ALTA SEVERIDAD (12–14)</div></div></td>",
                f"<td style='padding:4px;'><div style='background:#fff4ef;border-radius:9px;text-align:center;padding:10px 5px;'><div style='font-size:19px;font-weight:800;color:{orange};'>{num(s['critical'])}</div><div style='font-size:8px;color:{muted};font-weight:800;letter-spacing:.7px;'>ALERTAS CRÍTICAS (15–16)</div></div></td>",
                f"<td style='padding:4px;'><div style='background:{panel};border-radius:9px;text-align:center;padding:10px 5px;'><div style='font-size:19px;font-weight:800;color:{text};'>{num(s['attacks'])}</div><div style='font-size:8px;color:{muted};font-weight:800;letter-spacing:.7px;'>DETECCIONES DE ATAQUE</div></div></td>",
                f"<td style='padding:4px;'><div style='background:{panel};border-radius:9px;text-align:center;padding:10px 5px;'><div style='font-size:19px;font-weight:800;color:{text};'>{num(len(s['ips']))}</div><div style='font-size:8px;color:{muted};font-weight:800;letter-spacing:.7px;'>IPS ORIGEN</div></div></td>",
                f"<td style='padding:4px;'><div style='background:{panel};border-radius:9px;text-align:center;padding:10px 5px;'><div style='font-size:19px;font-weight:800;color:{text};'>{num(len(s['blocked']))}</div><div style='font-size:8px;color:{muted};font-weight:800;letter-spacing:.7px;'>IPS BLOQUEADAS</div></div></td>",
                "</tr></table></td></tr>",

                # Category summary
                "<tr><td style='padding:10px 16px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>",
                f"<tr><td colspan='2' style='padding:7px 0 8px;border-bottom:2px solid {orange};font-size:14px;font-weight:800;color:{text};'>Actividad detectada por categoría</td></tr>",
            ])

            cat_order = ["authentication", "web", "fim", "malware", "privilege", "attack", "active_response", "other"]
            any_cat = False
            for cat in cat_order:
                count = s["categories"].get(cat, 0)
                if count:
                    any_cat = True
                    page.append(
                        f"<tr><td style='padding:7px 5px;border-bottom:1px solid #edf1f3;font-size:11px;color:{text};'>{esc(CATEGORY_LABELS.get(cat, cat))}</td>"
                        f"<td style='padding:7px 5px;border-bottom:1px solid #edf1f3;text-align:right;font-size:11px;font-weight:800;color:{text};'>{num(count)}</td></tr>"
                    )
            if not any_cat:
                page.append(
                    "<tr><td colspan='2' style='padding:8px 5px;color:#78909c;font-size:11px;'>Sin detecciones categorizadas.</td></tr>"
                )
            page.append("</table></td></tr>")

            # Top rules by human-readable description
            page.append(
                "<tr><td style='padding:10px 16px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
                f"<tr><td colspan='2' style='padding:7px 0 8px;border-bottom:2px solid {orange};font-size:14px;font-weight:800;color:{text};'>Principales detecciones</td></tr>"
            )
            for description, count in s["rules"].most_common(TOP_RULES):
                page.append(
                    f"<tr><td style='padding:7px 5px;border-bottom:1px solid #edf1f3;font-size:11px;line-height:1.4;color:{text};'>{esc(description)}</td>"
                    f"<td style='padding:7px 5px;border-bottom:1px solid #edf1f3;text-align:right;font-weight:800;font-size:11px;color:{text};'>{num(count)}</td></tr>"
                )
            if not s["rules"]:
                page.append(
                    "<tr><td colspan='2' style='padding:8px 5px;color:#78909c;font-size:11px;'>Sin reglas de detección durante el período.</td></tr>"
                )
            page.append("</table></td></tr>")

            # MITRE
            page.append(
                "<tr><td style='padding:10px 16px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
                f"<tr><td colspan='2' style='padding:7px 0 8px;border-bottom:2px solid {orange};font-size:14px;font-weight:800;color:{text};'>Técnicas MITRE observadas</td></tr>"
            )
            if s["mitre"]:
                page.append(
                    f"<tr><td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;'>TÉCNICA</td>"
                    f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;'>DESCRIPCIÓN</td>"
                    f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;text-align:right;'>ALERTAS</td></tr>"
                )
                for technique, count in s["mitre"].most_common(TOP_MITRE):
                    description = (mitre_descriptions or {}).get(
                        str(technique),
                        "Descripción no disponible en el catálogo MITRE del reporte.",
                    )
                    page.append(
                        f"<tr><td style='padding:7px 5px;border-bottom:1px solid #edf1f3;font-family:monospace;font-size:11px;color:{text};vertical-align:top;'>{esc(technique)}</td>"
                        f"<td style='padding:7px 5px;border-bottom:1px solid #edf1f3;font-size:11px;line-height:1.35;color:{text};vertical-align:top;'>{esc(description)}</td>"
                        f"<td style='padding:7px 5px;border-bottom:1px solid #edf1f3;text-align:right;font-weight:800;font-size:11px;color:{text};vertical-align:top;'>{num(count)}</td></tr>"
                    )
            else:
                page.append(
                    "<tr><td colspan='2' style='padding:8px 5px;color:#78909c;font-size:11px;'>Sin técnicas MITRE observadas durante el período.</td></tr>"
                )
            page.append("</table></td></tr>")

            # Critical CVEs
            page.append(
                "<tr><td style='padding:10px 16px 18px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
                f"<tr><td colspan='4' style='padding:7px 0 8px;border-bottom:2px solid {orange};font-size:14px;font-weight:800;color:{text};'>CVE críticos en inventario</td></tr>"
                f"<tr><td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;'>CVE</td>"
                f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;'>Software</td>"
                f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;'>CVSS</td>"
                f"<td style='background:{header_light};color:#fff;padding:8px;font-size:10px;font-weight:800;'>Descripción</td></tr>"
            )
            if vuln_error:
                page.append(
                    "<tr><td colspan='4' style='padding:8px 5px;color:#8a3d2d;font-size:11px;line-height:1.4;'>"
                    f"No fue posible consultar los CVE de este servidor: {esc(vuln_error)}"
                    "</td></tr>"
                )
            elif s.get("vd_unsupported"):
                page.append(
                    f"<tr><td colspan='4' style='padding:8px 5px;color:#8a5a20;font-size:11px;line-height:1.4;'><b>CloudLinux:</b> Wazuh no realiza actualmente evaluación nativa de vulnerabilidades para esta distribución; el resultado no corresponde interpretarlo como ausencia de CVE.</td></tr>"
                )
            elif s["cves"]:
                for cve in s["cves"]:
                    desc = cve["description"] or "Sin descripción disponible."
                    if len(desc) > 260:
                        desc = desc[:257] + "..."
                    package = cve["package"]
                    if cve["version"]:
                        package = f"{package} {cve['version']}"
                    score = "-" if cve["score"] is None else f"{cve['score']:.1f}"
                    page.append(
                        f"<tr><td style='padding:7px;border-bottom:1px solid #edf1f3;font-family:monospace;font-size:11px;font-weight:800;color:{text};'>{esc(cve['id'])}</td>"
                        f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-size:10px;color:{text};'>{esc(package)}</td>"
                        f"<td style='padding:7px;border-bottom:1px solid #edf1f3;text-align:center;font-weight:800;font-size:11px;color:{orange};'>{esc(score)}</td>"
                        f"<td style='padding:7px;border-bottom:1px solid #edf1f3;font-size:10px;line-height:1.4;color:{text};'>{esc(desc)}</td></tr>"
                    )
            elif not vuln_error:
                page.append(
                    "<tr><td colspan='4' style='padding:8px 5px;color:#147a4a;font-size:11px;'>No se registran CVE críticos en el inventario consultado.</td></tr>"
                )
            page.append("</table></td></tr></table></td></tr>")

    page.extend([
        f"<tr><td style='background:{dark};border-top:4px solid {orange};padding:18px 22px;color:#c7d2d7;font-size:10px;line-height:1.5;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>",
        "<td valign='middle' style='width:60%;'><b style='color:#ffffff;font-size:11px;'>ORANGEBOX IT SERVICES</b><br>Monitoreo y seguridad de infraestructura</td>",
        "<td valign='middle' align='right' style='font-size:9px;color:#93aab3;letter-spacing:.7px;'>LINUX · INFRA · SECURITY</td>",
        "</tr></table></td></tr>",
        "</table></td></tr></table></body></html>"
    ])
    return "".join(page)


def generate_plain(group_sections, period, total_agents, total_events, total_high, total_critical, total_attacks, vuln_error=None):
    lines = [
        "OrangeBox — Resumen de Seguridad por Grupo",
        f"Período: {period}",
        f"Servidores: {total_agents} | Eventos de seguridad: {total_events} | Alertas alta severidad (12–14): {total_high} | Alertas críticas (15–16): {total_critical} | Detecciones de ataque: {total_attacks}",
        "",
    ]

    # CVE summary uses unique CVE IDs and unique package/version pairs.
    cve_ids = set()
    cve_packages = set()
    cve_agents = set()
    for _, stats in group_sections:
        for agent_id, stat in stats.items():
            for cve in stat["cves"]:
                if cve.get("id"):
                    cve_ids.add(str(cve["id"]))
                    cve_agents.add(agent_id)
                package = str(cve.get("package", "") or "")
                version = str(cve.get("version", "") or "")
                if package:
                    cve_packages.add((package, version))

    lines.insert(
        4,
        f"CVE críticos únicos: {len(cve_ids)} | Paquetes/versiones afectados: {len(cve_packages)} | Servidores con CVE crítico: {len(cve_agents)}",
    )

    for group_name, stats in group_sections:
        lines += [f"GRUPO: {group_name}", "-" * 72]
        if not stats:
            lines.append("Grupo sin servidores asignados.")
            lines.append("")
            continue
        for agent_id in sorted(stats, key=lambda k: stats[k]["name"].lower()):
            s = stats[agent_id]
            lines += [
                f"{s['name']} (ID {agent_id}) | {s['status']} | IP {s['ip']}",
                f"  Eventos: {s['events']} | Alta: {s['high']} | Críticas: {s['critical']} | Ataques: {s['attacks']} | IPs: {len(s['ips'])} | Bloqueadas: {len(s['blocked'])}",
                "  Top detecciones:",
            ]
            for desc, count in s["rules"].most_common(TOP_RULES):
                lines.append(f"    - {desc}: {count}")
            if s["blocked"]:
                lines.append("  IPs bloqueadas:")
                for ip, data in s["blocked"].items():
                    reason = "; ".join(r for r, _ in data["reasons"].most_common(3))
                    lines.append(f"    - {ip}: {reason}")
            if vuln_error:
                lines.append(f"  CVE críticos en inventario: NO CONSULTADO — {vuln_error}")
            elif s.get("vd_unsupported"):
                lines.append("  Vulnerabilidades: CloudLinux — Wazuh no realiza actualmente evaluación nativa de vulnerabilidades para esta distribución.")
            else:
                lines.append(f"  CVE críticos del inventario: {len(s['cves'])}")
            for cve in s["cves"] if not vuln_error else []:
                lines.append(f"    - {cve['id']} | {cve['package']} {cve['version']} | CVSS {cve['score'] or '-'}")
            lines.append("")
    return "\n".join(lines)


def archive_html(body, filename):
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    path = ARCHIVE_DIR / f"{filename}.html"
    tmp = path.with_suffix(".html.tmp")
    tmp.write_text(body, encoding="utf-8")
    os.replace(tmp, path)
    return path


def main():
    parser = argparse.ArgumentParser(description="OrangeBox Wazuh Group Security Report")
    modes = parser.add_mutually_exclusive_group(required=True)
    for name in ("today", "yesterday", "thisweek", "lastweek", "thismonth", "lastmonth", "thisyear", "lastyear"):
        modes.add_argument("--" + name, action="store_true")
    modes.add_argument("--date", help="Día específico YYYY-MM-DD")
    parser.add_argument("--group", required=True, help="Grupos Wazuh separados por comas")
    parser.add_argument("--email", action="append", required=True, help="Destinatario; se puede repetir")
    parser.add_argument("--lang", choices=("es", "en"), default="es")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("Este reporte debe ejecutarse como root.")

    mode = args.date and f"date:{args.date}" or next(
        name
        for name in ("today", "yesterday", "thisweek", "lastweek", "thismonth", "lastmonth", "thisyear", "lastyear")
        if getattr(args, name)
    )

    module = load_report_module()
    now = datetime.now().astimezone()
    start, end, label = module.period_bounds(mode, now)
    agent_info = parse_agent_control()

    groups = (
        all_groups()
        if args.group.lower() == "all"
        else [value.strip() for value in args.group.split(",") if value.strip()]
    )
    group_memberships = {}
    all_agent_ids = set()

    for group in groups:
        ids = group_members(group)
        if not ids:
            print(f"Grupo omitido: {group} no tiene servidores asignados.")
            continue
        group_memberships[group] = ids
        all_agent_ids.update(ids)

    if not group_memberships:
        raise SystemExit("No hay grupos con servidores asignados para generar el reporte.")

    # Una sola pasada por los logs del período para TODOS los grupos.
    # Se conservan solamente agregados por agente, no la lista completa
    # de eventos, evitando consumir varios GB de RAM en períodos grandes.
    agent_stats = init_agent_stats(all_agent_ids, agent_info)
    aggregate_events(module, start, end, all_agent_ids, agent_stats)

    cves, vuln_error = fetch_critical_cves(module, all_agent_ids)
    cloudlinux_agents = fetch_cloudlinux_agents(module, all_agent_ids)
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
        # Un agente puede pertenecer a más de un grupo; en ese caso se
        # muestra en cada grupo correspondiente, sin volver a leer logs.
        stats = {agent_id: agent_stats[agent_id] for agent_id in ids}

        total_agents += len(ids)
        total_events += sum(stat["events"] for stat in stats.values())
        total_high += sum(stat["high"] for stat in stats.values())
        total_critical += sum(stat["critical"] for stat in stats.values())
        total_attacks += sum(stat["attacks"] for stat in stats.values())
        rendered_sections.append((group, stats))

    # Mostrar siempre los grupos efectivos. Con --group all se usan los
    # grupos funcionales realmente resueltos, no la etiqueta literal "all".
    client_name = ", ".join(group_memberships.keys())
    title = f"OrangeBox — Reporte detallado: {client_name}"
    subtitle = ""
    period = f"{start.strftime('%d/%m/%Y %H:%M')} — {end.strftime('%d/%m/%Y %H:%M')}"
    body = generate_html(
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
        mitre_descriptions=getattr(module, "MITRE_DESCRIPTIONS", {}),
    )
    archive = archive_html(
        body,
        f"group-{args.group}-{mode.replace(':', '-')}-{start:%Y%m%d}-{end:%Y%m%d}",
    )

    text_body = generate_plain(
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
        f"[ORANGEBOX] {period_label(mode)} - Informe de Seguridad Detallado - {args.group}"
        if len(groups) == 1
        else f"[ORANGEBOX] {period_label(mode)} - Informe de Seguridad Detallado"
    )

    print(f"Grupo: {args.group}")
    print(f"Período: {period}")
    print(f"Servidores: {total_agents}")
    print(f"Eventos: {total_events}")
    print(f"Alta severidad: {total_high}")
    print(f"Críticas: {total_critical}")
    print(f"Ataques: {total_attacks}")
    if vuln_error:
        print(f"CVE críticos en inventario: NO CONSULTADO — {vuln_error}")
    else:
        print(
            "CVE críticos en inventario consultados: "
            f"{sum(len(stat['cves']) for _, stats in rendered_sections for stat in stats.values())}"
        )
    print(f"Archivo: {archive}")

    if args.dry_run:
        print("Dry-run: no se envió correo.")
        return 0

    sent = 0
    for recipient in args.email:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+", recipient):
            print(f"ERROR: correo inválido: {recipient}", flush=True)
            continue

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"Wazuh SOC <{DEFAULT_FROM}>"
        msg["To"] = recipient
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(body, "html", "utf-8"))

        try:
            result = subprocess.run(
                ["/usr/sbin/sendmail", "-t", "-i"],
                input=msg.as_string(),
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or f"sendmail exit={result.returncode}").strip()
                raise RuntimeError(f"Postfix maildrop: {detail}")
            sent += 1
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            print(f"ERROR enviando a {recipient}: {exc}", flush=True)

    if sent == 0:
        raise SystemExit("No se pudo enviar el reporte a ningún destinatario.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())