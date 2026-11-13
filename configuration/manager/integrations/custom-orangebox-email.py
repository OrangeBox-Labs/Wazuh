#!/usr/bin/env python3

import sys
import json
import os
import time
import fcntl
import html
import textwrap
import hashlib
import subprocess

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from orangebox_active_response import (
    firewall_drop_policy_for_alert,
    should_render_firewall_drop_status,
)

import re


def _is_expected_google_hosts_rewrite(alert_json):
    """Identifica una reescritura GCP idempotente; solo suprime este correo.

    Se exige regla 10036, /etc/hosts y un diff completo con una única
    eliminación/adición de la misma entrada administrada por Google.
    En Who-Data también se valida root, UID efectivo 0 y el ejecutable.
    Cualquier dato incompleto o transformación distinta opera fail-open.
    """
    if not isinstance(alert_json, dict):
        return False

    rule = alert_json.get("rule", {})
    if not isinstance(rule, dict) or str(rule.get("id", "")) != "10036":
        return False

    syscheck = alert_json.get("syscheck", {})
    if not isinstance(syscheck, dict) or syscheck.get("path") != "/etc/hosts":
        return False

    diff = syscheck.get("diff")
    if not isinstance(diff, str) or not diff:
        return False
    diff = diff.rstrip("\r\n")

    match = re.fullmatch(
        r"(?:\d+(?:,\d+)?d\d+(?:,\d+)?)\n"
        r"<[ \t]*(?P<old>[^\r\n]+)\n"
        r"\d+(?:,\d+)?a\d+(?:,\d+)?\n"
        r">[ \t]*(?P<new>[^\r\n]+)",
        diff,
    )
    if not match:
        return False

    def google_line_identity(line):
        line = line.strip()
        if re.fullmatch(
            r"169\.254\.169\.254[ \t]+metadata\.google\.internal"
            r"[ \t]+# Added by Google(?: - MDS)?",
            line,
        ):
            return ("mds", "169.254.169.254", "metadata.google.internal")

        hostname = re.fullmatch(
            r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})[ \t]+"
            r"(?P<hostname>[A-Za-z0-9][A-Za-z0-9.-]*)[ \t]+"
            r"(?P<alias>[A-Za-z0-9][A-Za-z0-9._-]*)[ \t]+"
            r"# Added by Google(?: - Hostname)?",
            line,
        )
        if hostname:
            return (
                "hostname",
                hostname.group("ip"),
                hostname.group("hostname"),
                hostname.group("alias"),
            )
        return None

    old_identity = google_line_identity(match.group("old"))
    new_identity = google_line_identity(match.group("new"))
    if old_identity is None or old_identity != new_identity:
        return False

    mode = str(syscheck.get("mode", "")).lower()
    if mode in ("scheduled", "realtime"):
        return True
    if mode != "whodata":
        return False

    audit = syscheck.get("audit", {})
    if not isinstance(audit, dict):
        return False
    user = audit.get("user", {})
    process = audit.get("process", {})
    effective_user = audit.get("effective_user", {})
    if not all(isinstance(item, dict) for item in (user, process, effective_user)):
        return False
    if user.get("name") != "root" or str(effective_user.get("id", "")) != "0":
        return False

    process_name = str(process.get("name", ""))
    return (
        process_name == "/usr/bin/sed"
        or process_name in (
            "/var/ossec/bin/wazuh-syscheckd",
            "/opt/ossec/bin/wazuh-syscheckd",
        )
    )


def _is_expected_lvestats_enablement_link_deletion(alert_json):
    """Identifica exclusivamente la baja FIM del enlace de habilitacion lvestats.

    En CloudLinux, lvestats.service es el servicio de estadisticas LVE y
    multi-user.target.wants/lvestats.service es su enlace de habilitacion
    dentro del target multi-user. Las operaciones de mantenimiento/paquetes
    pueden retirar y recrear este enlace.

    La excepcion es deliberadamente estrecha: exige la regla OrangeBox 10044,
    la ruta exacta, evento deleted y modo scheduled. No excluye el archivo
    unitario lvestats.service, otros enlaces systemd, modificaciones,
    eliminaciones detectadas en realtime/whodata ni otras reglas.

    El evento original permanece en Wazuh (alerts.json e indexer); solo se
    suprime el correo. Si falta cualquier dato de identificacion, opera
    fail-open y el correo se envia normalmente.
    """
    if not isinstance(alert_json, dict):
        return False

    rule = alert_json.get("rule", {})
    syscheck = alert_json.get("syscheck", {})
    if not isinstance(rule, dict) or not isinstance(syscheck, dict):
        return False

    return (
        str(rule.get("id", "")) == "10044"
        and syscheck.get("path") == (
            "/etc/systemd/system/multi-user.target.wants/lvestats.service"
        )
        and str(syscheck.get("event", "")).lower() == "deleted"
        and str(syscheck.get("mode", "")).lower() == "scheduled"
    )


def _is_expected_dpkg_bitninja_tempfile_cleanup(alert_json):
    """Identifica la limpieza de temporales dpkg durante una actualizacion BitNinja.

    Solo suprime correo para la regla 10044 cuando se elimina uno de los dos
    temporales exactos de bitninja-policier.service (.dpkg-new/.dpkg-tmp),
    bajo /etc/systemd/system, mediante FIM whodata y con auditoria que confirma
    root -> /usr/bin/apt-get -> /usr/bin/dpkg.

    No excluye bitninja-policier.service, otros archivos .dpkg-*, otros
    ejecutables, otros procesos padre, eventos scheduled/realtime ni cambios
    de contenido. Ante cualquier dato ausente o distinto, opera fail-open.
    El evento permanece en Wazuh; solo se suprime el correo.
    """
    if not isinstance(alert_json, dict):
        return False

    rule = alert_json.get("rule", {})
    syscheck = alert_json.get("syscheck", {})
    if not isinstance(rule, dict) or not isinstance(syscheck, dict):
        return False

    expected_paths = {
        "/etc/systemd/system/bitninja-policier.service.dpkg-new",
        "/etc/systemd/system/bitninja-policier.service.dpkg-tmp",
    }
    if (
        str(rule.get("id", "")) != "10044"
        or syscheck.get("path") not in expected_paths
        or str(syscheck.get("event", "")).lower() != "deleted"
        or str(syscheck.get("mode", "")).lower() != "whodata"
    ):
        return False

    audit = syscheck.get("audit", {})
    if not isinstance(audit, dict):
        return False

    user = audit.get("user", {})
    process = audit.get("process", {})
    effective_user = audit.get("effective_user", {})
    if not all(isinstance(item, dict) for item in (user, process, effective_user)):
        return False

    return (
        user.get("name") == "root"
        and str(user.get("id", "")) == "0"
        and effective_user.get("name") == "root"
        and str(effective_user.get("id", "")) == "0"
        and process.get("name") == "/usr/bin/dpkg"
        and process.get("parent_name") == "/usr/bin/apt-get"
    )


# ============================================================
# CONFIGURACION
# ============================================================

# Ventana de agrupacion para alertas no inmediatas.
# 600 segundos = 10 minutos.
WINDOW_SECONDS = 600

# Directorio donde se almacenan temporalmente las alertas agrupadas.
BUFFER_DIR = "/tmp/wazuh_email_buffer"

# Estado persistente para controlar deduplicacion diaria de SSH.
STATE_DIR = "/var/ossec/logs/orangebox_email_state"
SSH_STATE_FILE = os.path.join(STATE_DIR, "ssh_notifications.json")

# Destinatario obligatorio de todas las alertas.
DEFAULT_ALERT_RECIPIENT = "soporte@example.com"

# Identifica el evento sintético y la ruta donde el detector guarda su detalle completo.
VULNERABILITY_EVENT_TYPE = "orangebox_vulnerability_alert"
VULNERABILITY_DETAILS_DIR = "/var/ossec/logs/vulnerability-alerts/details"


# ============================================================
# ALERTAS POR GRUPO / CLIENTE
# ============================================================
#
# soporte@example.com SIEMPRE recibe las alertas.
# Estas opciones solamente controlan destinatarios adicionales.
#
# La comparacion de grupos es CASE-INSENSITIVE:
#   CLIENTE_01 == CLIENTE_01 == cliente_01
#
# Para agregar un cliente nuevo solamente hay que agregar una entrada
# aqui. No es necesario modificar ninguna otra parte del script.
#
# 1 = enviar al responsable del grupo
# 0 = NO enviar al responsable del grupo.
# ============================================================

CLIENT_GROUPS = {
    "CLIENTE_01": {"enabled": 0, "emails": ["cliente01@example.com"]},
    "CLIENTE_02": {"enabled": 0, "emails": ["cliente02@example.com"]},
    "CLIENTE_03": {"enabled": 0, "emails": ["cliente03@example.com"]},
    "CLIENTE_04": {"enabled": 0, "emails": ["cliente04@example.com"]},
    "CLIENTE_05": {"enabled": 0, "emails": ["cliente05@example.com"]},
    "CLIENTE_06": {"enabled": 0, "emails": ["cliente06@example.com"]},
    "ORANGEBOX": {"enabled": 0, "emails": []},
}



# ============================================================
# POLITICA DE ENVIO INMEDIATO
# ============================================================
#
# La politica tiene DOS capas:
#
# 1) Compatibilidad explicita por ID para reglas historicas/nativas.
# 2) Marca funcional "orangebox_immediate" en rule.groups.
#
# La segunda es la politica preferida: una regla nueva de alta
# prioridad se marca en el XML y automaticamente queda fuera del
# buffer, sin tener que editar este script.
#
# IMPORTANTE:
#   El tratamiento de firewall-drop se determina leyendo los selectores
#   reales (rules_id, rules_group y level) de ossec.conf mediante el modulo
#   orangebox_active_response. No se mantiene una lista paralela de IDs.
#
IMMEDIATE_RULES = {
    # Reglas historicas / nativas que no podemos marcar todas desde
    # OrangeBox (por ejemplo 5715).
    "5715",

    # Compatibilidad con reglas OrangeBox existentes.
    "10001",
    "10004",
    "10005",
    "10008",
    "10009",

    # IOC nativos de autenticación exitosa y ataque web crítico.
    # Deben notificarse inmediatamente, aunque tengan firewall-drop configurado.
    "99903",
    "99906",
    "99910",
    "99912",
    "99913",
    "99920",
}

IMMEDIATE_RULE_GROUP = "ORANGEBOX_IMMEDIATE"


# ============================================================
# FIREWALL-DROP: DETECCION DINAMICA, SIN LISTA DE IDS
# ============================================================
#
# El integrador no mantiene una lista paralela de rule IDs.
# Para cada alerta usa rule.id del JSON y consulta los bloques
# active-response habilitados en /var/ossec/etc/ossec.conf.
# Si firewall-drop está asociado a esa regla, obtiene el timeout
# configurado y suprime el correo individual.
#
# La ejecución real se audita mediante el evento nativo 651 que
# Wazuh genera al ejecutar firewall-drop. Tenerlo configurado no
# es, por sí solo, prueba de que el bloqueo se ejecutó.
#
# ============================================================
# REGLAS SIN CORREO
# ============================================================
#
# Estas reglas siguen generando la alerta Wazuh.
# Solamente se evita el correo de la integracion.
#
# 10455 = posible DDoS distribuido.
#
NO_EMAIL_RULES = {
    "10455",
}


# ============================================================
# FUNCIONES AUXILIARES
# ============================================================

def ensure_directories():
    """
    Crea los directorios necesarios si no existen.
    """

    os.makedirs(BUFFER_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)


def safe_int(value, default=0):
    """
    Convierte un valor a entero sin provocar excepciones.
    """

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def esc(value):
    """
    Escapa contenido para HTML.

    Esto es importante porque full_log, diff, rutas, etc.
    pueden contener caracteres especiales.
    """

    if value is None:
        return ""

    return html.escape(str(value))



def format_log_for_html(value):
    """Escapa el log para HTML sin insertar saltos de linea artificiales.

    Conserva los saltos originales. El wrapping visual depende del cliente
    de correo y del ancho disponible; no se cortan tokens por bloques fijos.
    """
    return html.escape(str(value or ""))


def load_json_file(path):
    """
    Carga un JSON desde disco.
    """

    with open(path, "r") as f:
        return json.load(f)


def save_json_file(path, data):
    """
    Guarda un JSON de forma segura.
    """

    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def normalize_group_name(value):
    """Normaliza grupos sin depender de mayusculas/minusculas."""
    return str(value or "").strip().upper()


def normalize_group_list(raw_groups):
    """Normaliza una lista de grupos y elimina DEFAULT/duplicados."""
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]
    elif not isinstance(raw_groups, list):
        raw_groups = []

    result = []
    seen = set()

    # Normaliza cada nombre recibido y conserva solo grupos válidos, sin DEFAULT ni duplicados.
    for group in raw_groups:
        key = normalize_group_name(group)

        if not key or key == "DEFAULT":
            continue

        if key not in seen:
            seen.add(key)
            result.append(key)

    return result


def get_agent_groups_from_manager(agent_id):
    """
    Recupera los grupos efectivos del agente directamente desde el
    manager cuando el alerta no los incluye.

    Wazuh expone esta informacion mediante agent_groups -s -i.
    """
    agent_id = str(agent_id or "").strip()

    if not agent_id or agent_id == "000":
        return []

    try:
        result = subprocess.run(
            ["/var/ossec/bin/agent_groups", "-s", "-i", agent_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    output = result.stdout or ""

    # Formato habitual:
    #   has the group: '[u'CLIENTE_04', u'default']'
    # y versiones:
    #   belongs to groups: default, CLIENTE_04
    import re

    match = re.search(r"\[([^\]]*)\]", output)

    if match:
        raw_groups = re.findall(
            r'''(?:u)?['"]([^'"]+)['"]''',
            match.group(1)
        )
        # Algunas versiones muestran el nombre del grupo con puntuación
        # de cierre (por ejemplo, "CLIENTE_05." o "default.").
        return normalize_group_list(
            [group.strip().rstrip(".,;:") for group in raw_groups]
        )

    match = re.search(
        r"belongs to groups?:\s*(.+)$",
        output,
        flags=re.IGNORECASE | re.MULTILINE,
    )

    if match:
        return normalize_group_list(
            [group.strip().rstrip(".,;:") for group in match.group(1).split(",")]
        )

    return []


def get_agent_ip_from_manager(agent_id):
    """Fallback para agentes cuyo documento de vulnerabilidad no incluye agent.ip."""
    agent_id = str(agent_id or "").strip()
    if not agent_id or agent_id == "000":
        return ""
    try:
        result = subprocess.run(
            ["/var/ossec/bin/agent_control", "-i", agent_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    import re
    match = re.search(r"\bIP(?:\s+address)?:\s*([^\s,]+)", result.stdout or "", flags=re.IGNORECASE)
    if not match:
        return ""
    address = match.group(1).strip()
    if address.lower() in {"any", "unknown", "n/a", "not", "none"}:
        return ""
    return address



def extract_agent_groups(alert_json):
    """
    Obtiene los grupos del agente real de la alerta.

    En eventos de vulnerabilidad, la alerta se origina en el manager (agente
    000), pero data.affected_agent.id identifica al endpoint afectado.
    """
    event_data = alert_json.get("data", {})
    if isinstance(event_data, dict) and event_data.get("event_type") == VULNERABILITY_EVENT_TYPE:
        affected_agent = event_data.get("affected_agent", {})
        if isinstance(affected_agent, dict):
            result = normalize_group_list(affected_agent.get("groups", []))
            if result:
                return result
            return get_agent_groups_from_manager(affected_agent.get("id", ""))
        return []

    agent = alert_json.get("agent", {})
    if not isinstance(agent, dict):
        return []

    raw_groups = agent.get("groups", [])
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]
    elif not isinstance(raw_groups, list):
        raw_groups = []

    singular = agent.get("group", "")
    if singular:
        raw_groups.append(singular)

    result = normalize_group_list(raw_groups)
    if result:
        return result
    return get_agent_groups_from_manager(agent.get("id", ""))


def build_recipients(default_recipient, agent_groups):
    """
    Soporte OrangeBox siempre recibe el correo.
    Los destinatarios de cliente dependen del grupo y su switch.
    """
    recipients = []
    seen = set()

    def add_recipient(address):
        """Agrega una dirección válida una sola vez al conjunto de destinatarios."""
        address = str(address or "").strip()

        if not address:
            return

        key = address.lower()

        if key not in seen:
            seen.add(key)
            recipients.append(address)

    # Soporte OrangeBox es SIEMPRE destinatario.
    add_recipient(DEFAULT_ALERT_RECIPIENT)

    # Conservamos tambien el recipient entregado por Wazuh si difiere,
    # para no romper una configuracion externa existente.
    add_recipient(default_recipient)

    # Busca el perfil de cada grupo para agregar los destinatarios autorizados.
    for group in agent_groups:
        config = CLIENT_GROUPS.get(normalize_group_name(group))

        if not config or not config.get("enabled"):
            continue

        # Incorpora las direcciones configuradas para ese grupo sin repetir destinatarios.
        for address in config.get("emails", []):
            add_recipient(address)

    return recipients





def restore_vulnerability_event_details(alert_json):
    """Rehidrata los paquetes completos guardados fuera del JSONL de Logcollector."""
    if not isinstance(alert_json, dict):
        return alert_json

    data = alert_json.get("data", {})
    if not isinstance(data, dict) or data.get("event_type") != VULNERABILITY_EVENT_TYPE:
        return alert_json

    event_key = str(data.get("event_key") or "").strip()
    if not event_key:
        return alert_json

    filename = hashlib.sha256(event_key.encode("utf-8")).hexdigest() + ".json"
    detail_path = os.path.join(VULNERABILITY_DETAILS_DIR, filename)
    try:
        with open(detail_path, "r", encoding="utf-8") as stream:
            details = json.load(stream)
    except (OSError, ValueError) as exc:
        try:
            with open("/var/ossec/logs/integrations.log", "a", encoding="utf-8") as logf:
                logf.write(
                    f"WARN vulnerability email: detalle auxiliar no disponible "
                    f"para {event_key}: {type(exc).__name__}: {exc}\\n"
                )
        except OSError:
            pass
        return alert_json

    if (
        not isinstance(details, dict)
        or details.get("event_type") != VULNERABILITY_EVENT_TYPE
        or str(details.get("event_key") or "") != event_key
        or not isinstance(details.get("affected_agents"), list)
        or not isinstance(details.get("vulnerability"), dict)
    ):
        try:
            with open("/var/ossec/logs/integrations.log", "a", encoding="utf-8") as logf:
                logf.write(
                    f"WARN vulnerability email: detalle auxiliar inválido para {event_key}\\n"
                )
        except OSError:
            pass
        return alert_json

    restored = dict(alert_json)
    restored["data"] = details
    return restored

def send_aggregated_vulnerability_emails(alert_json, default_recipient):
    """Envía una copia global y copias filtradas por grupo para un único evento CVE."""
    alert_json = restore_vulnerability_event_details(alert_json)
    data = alert_json.get("data", {})
    vulnerability = data.get("vulnerability", {})
    raw_agents = data.get("affected_agents", [])
    if not isinstance(vulnerability, dict) or not isinstance(raw_agents, list):
        return

    cve = str(vulnerability.get("cve") or vulnerability.get("id") or "N/A")
    severity = str(vulnerability.get("severity") or "N/A").strip().title()
    description = str(vulnerability.get("description") or "Descripción no disponible en el inventario.")
    published_at = str(vulnerability.get("published_at") or "No informada por el inventario.")
    status = str(vulnerability.get("status") or "Active")

    agents = []
    seen_ids = set()
    # Convierte los agentes afectados a registros válidos y evita duplicar agent.id.
    for raw in raw_agents:
        if not isinstance(raw, dict):
            continue
        agent_id = str(raw.get("id") or "").strip()
        if not agent_id or agent_id in seen_ids:
            continue
        seen_ids.add(agent_id)
        groups = normalize_group_list(raw.get("groups", []))
        if not groups:
            groups = get_agent_groups_from_manager(agent_id)
        packages = raw.get("packages", [])
        if not isinstance(packages, list):
            packages = []
        agents.append({
            "id": agent_id,
            "name": str(raw.get("name") or agent_id),
            "ip": str(raw.get("ip") or get_agent_ip_from_manager(agent_id) or "IP no disponible"),
            "groups": groups,
            "packages": [p for p in packages if isinstance(p, dict)],
        })

    if not agents:
        try:
            with open("/var/ossec/logs/integrations.log", "a") as logf:
                logf.write(f"WARN vulnerability email: {cve} sin agentes afectados en el evento.\n")
        except OSError:
            pass
        return

    def unique_addresses(addresses):
        """Normaliza y deduplica direcciones de correo."""
        result = []
        seen = set()
        # Normaliza direcciones y elimina duplicados sin distinguir mayúsculas.
        for address in addresses:
            address = str(address or "").strip()
            if address and address.lower() not in seen:
                seen.add(address.lower())
                result.append(address)
        return result

    def mail_for_audience(addresses, subset, audience):
        """Construye y envía el correo para el subconjunto de agentes de una audiencia."""
        addresses = unique_addresses(addresses)
        if not addresses or not subset:
            return
        rows = []
        desktop_rows = []
        # Construye las filas HTML y texto con cada agente de la audiencia.
        for agent in subset:
            pkg_details = []
            desktop_pkg_details = []
            # Añade al detalle los paquetes informados para este agente y CVE.
            for package in agent["packages"]:
                name = esc(package.get("name") or "Paquete no informado")
                version = esc(package.get("version") or "Versión no informada")
                arch = esc(package.get("architecture") or "arquitectura no informada")
                condition = esc(package.get("condition") or "")
                detected_at = esc(package.get("detected_at") or "")
                desktop_extra = []
                if condition:
                    desktop_extra.append("Condición: " + condition)
                if detected_at:
                    desktop_extra.append("Detectado: " + detected_at)
                desktop_pkg_details.append(
                    "<div style='margin:3px 0;line-height:1.35;overflow-wrap:anywhere'>"
                    "<strong>" + name + "</strong> — " + version + " (" + arch + ")"
                    + (("<br><small style='font-size:11px'>" +
                        " · ".join(desktop_extra) + "</small>") if desktop_extra else "")
                    + "</div>"
                )
                pkg_details.append(
                    "<div style='margin:9px 0 0;padding:10px 12px;"
                    "border:1px solid #e2e8f0;border-radius:6px;background:#ffffff;"
                    "line-height:1.5;overflow-wrap:anywhere'>"
                    "<div style='font-weight:700;font-size:13px;line-height:1.45;"
                    "margin-bottom:7px;color:#0f172a;overflow-wrap:anywhere'>" + name + "</div>"
                    "<div style='margin:4px 0;font-size:12px;line-height:1.5'>"
                    "<strong style='color:#475569'>Versión:</strong> " + version + "</div>"
                    "<div style='margin:4px 0;font-size:12px;line-height:1.5'>"
                    "<strong style='color:#475569'>Arquitectura:</strong> " + arch + "</div>"
                    + (("<div style='margin:6px 0 0;font-size:12px;line-height:1.55;"
                        "overflow-wrap:anywhere'><strong style='color:#475569'>Condición:</strong> " +
                        condition + "</div>") if condition else "")
                    + (("<div style='margin:5px 0 0;font-size:11px;line-height:1.5;"
                        "color:#64748b;overflow-wrap:anywhere'><strong>Detectado:</strong> " +
                        detected_at + "</div>") if detected_at else "")
                    + "</div>"
                )
            if not pkg_details:
                pkg_details = ["Paquete no informado"]
            if not desktop_pkg_details:
                desktop_pkg_details = ["Paquete no informado"]
            groups_text = ", ".join(agent["groups"]) or "Sin grupo identificado"
            desktop_rows.append(
                "<tr>"
                "<td style='padding:9px;border-bottom:1px solid #e2e8f0;vertical-align:top;"
                "overflow-wrap:anywhere'>" + esc(agent["name"]) + "<br><small>ID " +
                esc(agent["id"]) + "</small></td>"
                "<td style='padding:9px;border-bottom:1px solid #e2e8f0;vertical-align:top;"
                "overflow-wrap:anywhere'>" + esc(agent["ip"]) + "</td>"
                "<td style='padding:9px;border-bottom:1px solid #e2e8f0;vertical-align:top;"
                "overflow-wrap:anywhere'>" + esc(groups_text) + "</td>"
                "<td style='padding:9px;border-bottom:1px solid #e2e8f0;vertical-align:top;"
                "font-size:12px;overflow-wrap:anywhere'>" + "".join(desktop_pkg_details) + "</td>"
                "</tr>"
            )
            rows.append(
                "<tr><td style='padding:12px 10px;border-bottom:1px solid #dbe3ec;"
                "vertical-align:top;overflow-wrap:anywhere'>"
                "<div style='padding:14px 14px;background:#f8fafc;border:1px solid #dbe3ec;"
                "border-radius:8px;overflow-wrap:anywhere'>"
                "<div style='margin:0 0 12px;padding:0 0 9px;border-bottom:1px solid #dbe3ec;"
                "font-size:13px;line-height:1.5;overflow-wrap:anywhere'>"
                "<strong style='display:inline-block;width:150px;max-width:40%;box-sizing:border-box;"
                "vertical-align:top;padding-right:10px;color:#475569'>Servidor:</strong>"
                "<span style='display:inline-block;width:58%;vertical-align:top;font-weight:700;"
                "overflow-wrap:anywhere'>" + esc(agent["name"]) +
                "<br><small style='font-weight:400;color:#64748b'>ID " + esc(agent["id"]) + "</small></span></div>"
                "<div style='margin:9px 0;font-size:13px;line-height:1.6;overflow-wrap:anywhere'>"
                "<strong style='display:inline-block;width:150px;max-width:40%;box-sizing:border-box;"
                "vertical-align:top;padding-right:10px;color:#475569'>IP:</strong>"
                "<span style='display:inline-block;width:58%;vertical-align:top;overflow-wrap:anywhere'>" +
                esc(agent["ip"]) + "</span></div>"
                "<div style='margin:9px 0 13px;font-size:13px;line-height:1.6;overflow-wrap:anywhere'>"
                "<strong style='display:inline-block;width:150px;max-width:40%;box-sizing:border-box;"
                "vertical-align:top;padding-right:10px;color:#475569'>Grupo:</strong>"
                "<span style='display:inline-block;width:58%;vertical-align:top;overflow-wrap:anywhere'>" +
                esc(groups_text) + "</span></div>"
                "<div style='margin-top:14px;padding-top:12px;border-top:1px solid #dbe3ec'>"
                "<div style='font-size:13px;line-height:1.5;font-weight:700;color:#334155;"
                "margin-bottom:8px'>Paquetes y versiones</div>"
                "<div style='overflow-wrap:anywhere'>" +
                "".join(pkg_details) +
                "</div></div></div></td></tr>"
            )

        severity_color = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
        }.get(severity.upper(), "#475569")
        html_body = (
            "<!doctype html><html><head><meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1.0'>"
            "<style type='text/css'>"
            ".ob-cve-desktop-table{display:none!important}"
            ".ob-cve-mobile-cards{display:table!important}"
            "@media screen and (min-width:600px){"
            ".ob-cve-desktop-table{display:table!important}"
            ".ob-cve-mobile-cards{display:none!important}"
            "}"
            "</style></head>"
            "<body style='margin:0;padding:12px;background:#f1f5f9;font-family:Arial,sans-serif;color:#0f172a'>"
            "<div style='max-width:1000px;margin:auto;background:#fff;border:1px solid #cbd5e1;border-radius:12px;overflow:hidden'>"
            "<div style='padding:22px;background:#1e293b;color:#fff;text-align:center'>"
            "<img src='https://www.orangebox.cl/obox/img/logo-dark.png' "
            "alt='OrangeBox' border='0' width='220' "
            "style='display:block;width:220px;max-width:75%;height:auto;margin:0 auto 12px'>"
            "<div style='font-size:20px;font-weight:700'>OrangeBox · Alerta de vulnerabilidad</div>"
            "<div style='margin-top:12px;display:inline-block;background:" + severity_color +
            ";padding:6px 12px;border-radius:6px;font-weight:700'>" + esc(severity.upper()) +
            "</div><h2 style='margin:14px 0 4px'>" + esc(cve) + "</h2>"
            "<div>" + str(len(subset)) + " servidores afectados" +
            (" · " + esc(audience) if audience else "") + "</div></div>"
            "<div style='padding:12px 16px'><table role='presentation' style='width:100%;max-width:100%;border-collapse:collapse;margin-bottom:18px'>"
            "<tr><td style='padding:8px 0;border-bottom:1px solid #e2e8f0;font-size:13px;line-height:1.45;overflow-wrap:anywhere'>"
            "<strong style='display:inline-block;width:150px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:10px;color:#475569'>Estado:</strong>"
            "<span style='display:inline-block;width:58%;vertical-align:top;overflow-wrap:anywhere'>" +
            esc(status) + "</span></td></tr>"
            "<tr><td style='padding:8px 0;border-bottom:1px solid #e2e8f0;font-size:13px;line-height:1.45;overflow-wrap:anywhere'>"
            "<strong style='display:inline-block;width:150px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:10px;color:#475569'>Publicación CVE:</strong>"
            "<span style='display:inline-block;width:58%;vertical-align:top;overflow-wrap:anywhere'>" +
            esc(published_at) + "</span></td></tr>"
            "<tr><td style='padding:8px 0;border-bottom:1px solid #e2e8f0;font-size:13px;line-height:1.45;overflow-wrap:anywhere'>"
            "<strong style='display:inline-block;width:150px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:10px;color:#475569'>Descripción:</strong>"
            "<span style='display:inline-block;width:58%;vertical-align:top;overflow-wrap:anywhere'>" +
            esc(description) + "</span></td></tr></table>"
            "<h3 style='margin:18px 0 8px'>Servidores y paquetes afectados (" + str(len(subset)) + ")</h3>"
            "<table class='ob-cve-desktop-table' role='presentation' style='display:none;width:100%;max-width:100%;"
            "table-layout:fixed;border-collapse:collapse;font-size:13px'><thead><tr style='background:#e2e8f0;text-align:left'>"
            "<th style='padding:9px;width:26%'>Servidor</th><th style='padding:9px;width:15%'>IP</th>"
            "<th style='padding:9px;width:18%'>Grupo</th><th style='padding:9px;width:41%'>Paquete / versión</th>"
            "</tr></thead><tbody>" + "".join(desktop_rows) + "</tbody></table>"
            "<table class='ob-cve-mobile-cards' role='presentation' style='display:table;width:100%;max-width:100%;"
            "border-collapse:collapse;font-size:13px'><tbody>" +
            "".join(rows) +
            "</tbody></table></div><div style='padding:14px 20px;background:#f8fafc;color:#64748b;font-size:12px'>"
            "Mensaje automatizado de OrangeBox SOC &amp; CyberSecurity · Wazuh SIEM</div></div></body></html>"
        )
        message = MIMEMultipart("alternative")
        message["Subject"] = (
            f"[VULNERABILIDAD {severity.upper()}] {cve} - {len(subset)} servidores afectados"
            + (f" ({audience})" if audience else "")
        )
        message["From"] = "Wazuh SOC <wazuh@example.com>"
        message["To"] = ", ".join(addresses)
        message.attach(MIMEText(html_body, "html", "utf-8"))
        try:
            result = subprocess.run(
                ["/usr/sbin/sendmail", "-t", "-i"],
                input=message.as_string(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
                check=False,
            )
            if result.returncode != 0:
                detail = result.stderr.strip() or result.stdout.strip() or f"sendmail exit={result.returncode}"
                with open("/var/ossec/logs/integrations.log", "a") as logf:
                    logf.write(f"ERROR vulnerability email {cve} {audience}: {detail}\n")
        except Exception as exc:
            try:
                with open("/var/ossec/logs/integrations.log", "a") as logf:
                    logf.write(f"ERROR vulnerability email {cve} {audience}: {type(exc).__name__}: {exc}\n")
            except OSError:
                pass

    # OrangeBox recibe siempre el conjunto completo de agentes.
    global_recipients = unique_addresses([DEFAULT_ALERT_RECIPIENT, default_recipient])
    mail_for_audience(global_recipients, agents, "OrangeBox - Todos los afectados")

    # Cada contacto recibe solamente los agentes que pertenecen a su grupo.
    for group_name, config in CLIENT_GROUPS.items():
        if not config.get("enabled"):
            continue
        subset = [
            agent for agent in agents
            if normalize_group_name(group_name) in agent["groups"]
        ]
        if subset:
            mail_for_audience(config.get("emails", []), subset, group_name)




# ============================================================
# DEDUPLICACION SSH
# ============================================================

# !!! LOCKED - CONTRATO DE PRODUCCION !!!
#
# NO MODIFICAR LA LOGICA DE ESTA SECCION SIN UNA PETICION EXPLICITA
# DEL USUARIO Y PRUEBAS DE REGRESION COMPLETAS.
#
# Politica bloqueada:
#   - SSH exitoso: maximo 1 correo por AGENTE + IP DE ORIGEN + DIA.
#   - La misma IP puede generar una alerta diaria independiente
#     en cada agente.
#   - 5715 y 10001 comparten la misma deduplicacion dentro de cada
#     agente + IP + dia.
#   - La deduplicacion debe ser atomica para conexiones simultaneas.
#   - No cambiar a deduplicacion global por IP.
#
# !!! FIN CONTRATO LOCKED !!!
#
def extract_ssh_source_ip(full_log):
    """
    Extrae la IP origen directamente del log SSH cuando journald
    no entrega data.srcip al decoder.

    Ejemplo esperado:
        Accepted password for root from 192.0.2.22 port 60943 ssh2

    Esta ruta de respaldo es necesaria porque algunos eventos
    provenientes de journald llegan al integrador sin srcip aunque
    la IP exista claramente en full_log.
    """

    if not full_log:
        return ""

    import re

    match = re.search(
        r"Accepted\s+(?:password|publickey|keyboard-interactive(?:/pam)?)"
        r"\s+for\s+\S+\s+from\s+(\S+)\s+port\s+\d+",
        str(full_log)
    )

    if not match:
        return ""

    return match.group(1)


def ssh_already_notified(agent_id, srcip, event_timestamp, ssh_identity="", full_log=""):
    """
    Deduplicacion SSH por marcadores atomicos.

    Politica OrangeBox:
        - maximo un correo SSH por agente + IP origen + dia;
        - 5715 y 10001 comparten el mismo estado;
        - si journald no entrega data.srcip, el caller intenta
          recuperar la IP desde full_log;
        - SU y SUDO no pasan por esta funcion.

    Se utilizan archivos marcador creados con O_CREAT|O_EXCL para que
    dos ejecuciones simultaneas del Integrator no puedan ganar ambas
    la carrera del "primer correo".

    El JSON historico ssh_notifications.json se conserva como fuente
    de compatibilidad para no perder el estado acumulado por versiones
    anteriores del integrador.
    """

    event_timestamp = str(event_timestamp)
    event_timestamp_second = event_timestamp[:19]
    event_date = event_timestamp[:10]

    if len(event_date) != 10:
        return False

    if not srcip and not ssh_identity and not full_log:
        return False

    try:
        marker_dir = os.path.join(STATE_DIR, "ssh_seen")
        os.makedirs(marker_dir, mode=0o750, exist_ok=True)

        def marker_path(kind, value):
            """Genera la ruta persistente del marcador de deduplicación para un evento."""
            material = f"{agent_id}|{kind}|{value}|{event_date}"
            digest = hashlib.sha256(
                material.encode("utf-8", errors="replace")
            ).hexdigest()

            return os.path.join(
                marker_dir,
                f"{agent_id}-{event_date}-{kind}-{digest}.seen"
            )

        def marker_exists_or_create(path, metadata):
            """
            Devuelve True si el marcador ya existia.
            Devuelve False y lo crea de forma atomica si es nuevo.
            """
            try:
                fd = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600
                )
            except FileExistsError:
                return True

            try:
                with os.fdopen(fd, "w") as marker:
                    json.dump(metadata, marker)
                    marker.flush()
                    os.fsync(marker.fileno())
                return False
            except Exception:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
                raise

        # ----------------------------------------------------
        # Estado legacy
        # ----------------------------------------------------
        #
        # Si una IP ya genero correo con una version anterior,
        # respetamos ese estado y no volvemos a notificar.
        #
        legacy_seen = set()

        if os.path.exists(SSH_STATE_FILE):
            try:
                with open(SSH_STATE_FILE, "r") as state_file:
                    legacy_state = json.load(state_file)

                if isinstance(legacy_state, dict):
                    legacy_seen = set(legacy_state.keys())

            except (OSError, json.JSONDecodeError, ValueError):
                # El JSON legacy no debe impedir el funcionamiento
                # del mecanismo atomico actual.
                legacy_seen = set()

        ip_key = (
            f"{agent_id}|ip|{srcip}|{event_date}"
            if srcip else ""
        )

        legacy_ip_key = (
            f"{agent_id}|{srcip}|{event_date}"
            if srcip else ""
        )

        # Compatibilidad transitoria con el cambio incorrecto que
        # genero marcadores globales por IP durante esta fecha.
        # Solo se respeta un marcador global si pertenece al mismo
        # agente + IP + dia; otro agente debe conservar su propia
        # primera alerta diaria.
        global_marker_seen = False
        if srcip:
            broken_material = f"ip|{srcip}|{event_date}"
            broken_digest = hashlib.sha256(
                broken_material.encode("utf-8", errors="replace")
            ).hexdigest()
            broken_marker = os.path.join(
                marker_dir,
                f"ssh-{event_date}-ip-{broken_digest}.seen"
            )
            if os.path.exists(broken_marker):
                try:
                    with open(broken_marker, "r") as marker_file:
                        marker_data = json.load(marker_file)
                    global_marker_seen = (
                        isinstance(marker_data, dict)
                        and str(marker_data.get("agent_id", "")) == str(agent_id)
                        and str(marker_data.get("srcip", "")) == str(srcip)
                        and str(marker_data.get("date", "")) == event_date
                    )
                except (OSError, json.JSONDecodeError, ValueError):
                    global_marker_seen = False

        # ----------------------------------------------------
        # 1. Una notificacion diaria por agente + IP de origen.
        # ----------------------------------------------------
        #
        # Esta es la politica principal. Es la que debe resolver
        # exactamente el caso:
        #
        #   Accepted password ... from 192.0.2.22
        #
        # cinco veces durante el dia en el mismo agente -> un solo correo.
        #
        if srcip:
            if ip_key in legacy_seen or legacy_ip_key in legacy_seen or global_marker_seen:
                return True

            if marker_exists_or_create(
                marker_path("ip", srcip),
                {
                    "agent_id": agent_id,
                    "srcip": srcip,
                    "date": event_date,
                    "timestamp": event_timestamp,
                    "event": "ssh-login",
                },
            ):
                return True

        # ----------------------------------------------------
        # 2. Fingerprint/identidad cuando NO tenemos IP.
        # ----------------------------------------------------
        #
        # Solo se utiliza si el decoder no aporto srcip y el evento
        # dispone de una identidad secundaria confiable.
        #
        if not srcip and ssh_identity:
            identity_key = (
                f"{agent_id}|identity|{ssh_identity}|{event_date}"
            )

            if identity_key in legacy_seen:
                return True

            if marker_exists_or_create(
                marker_path("identity", ssh_identity),
                {
                    "agent_id": agent_id,
                    "identity": ssh_identity,
                    "date": event_date,
                    "timestamp": event_timestamp,
                    "event": "ssh-login",
                },
            ):
                return True

        # ----------------------------------------------------
        # 3. Duplicado exacto del mismo evento.
        # ----------------------------------------------------
        #
        # Esto cubre dos invocaciones del Integrator para exactamente
        # el mismo log, aunque el alert.id de Wazuh sea diferente.
        #
        if full_log:
            exact_material = (
                f"{agent_id}|{event_timestamp_second}|{full_log}"
            )

            exact_hash = hashlib.sha256(
                exact_material.encode("utf-8", errors="replace")
            ).hexdigest()

            if marker_exists_or_create(
                marker_path("event", exact_hash),
                {
                    "agent_id": agent_id,
                    "date": event_date,
                    "timestamp": event_timestamp,
                    "event_hash": exact_hash,
                    "event": "ssh-login",
                },
            ):
                return True

        # Limpieza simple de marcadores antiguos. Se conserva una
        # ventana de 7 dias para no permitir crecimiento indefinido.
        cutoff = time.time() - (7 * 86400)

        try:
            # Retira solo los marcadores SSH cuya fecha supera la ventana de siete días.
            for name in os.listdir(marker_dir):
                path = os.path.join(marker_dir, name)

                try:
                    if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                        os.unlink(path)
                except (OSError, FileNotFoundError):
                    pass
        except OSError:
            pass

        return False

    except Exception as exc:
        # Fail-open: un fallo de deduplicacion no debe bloquear una
        # alerta de seguridad. Registramos el error para diagnostico.
        try:
            with open(
                "/var/ossec/logs/integrations.log",
                "a"
            ) as logf:
                logf.write(
                    "ERROR custom-orangebox-email SSH dedup: "
                    f"{type(exc).__name__}: {exc}\n"
                )
        except Exception:
            pass

        return False


# ============================================================
# BUFFER AGRUPADO
# ============================================================

def append_event_to_buffer(buffer_path, current_event,
                           agent_name, agent_ip, agent_id,
                           rule_id, description, location,
                           groups, rule_level):
    """
    Agrega un evento a un buffer existente utilizando bloqueo
    exclusivo para evitar corrupcion cuando llegan eventos
    simultaneos.
    """

    with open(buffer_path, "r+") as f:

        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

        try:
            data = json.load(f)

        except (json.JSONDecodeError, ValueError):

            # Si el buffer esta corrupto, reconstruimos el buffer
            # usando el evento actual.
            data = {
                "first_seen": time.time(),
                "agent_groups": agent_groups,
                "recipients": recipients,
                "agent_name": agent_name,
                "agent_ip": agent_ip,
                "agent_id": agent_id,
                "rule_id": rule_id,
                "description": description,
                "location": location,
                "groups": groups,
                "max_level": rule_level,
                "events": []
            }

        data.setdefault("events", [])

        # ----------------------------------------------------
        # EVITAR DUPLICADOS
        # ----------------------------------------------------
        #
        # Cada alerta de Wazuh tiene un ID unico.
        # Si la misma alerta vuelve a ser procesada por la
        # integracion, no la agregamos nuevamente.
        #
        # No usamos file_path porque el mismo archivo puede
        # generar eventos legitimos diferentes.
        # ----------------------------------------------------

        current_alert_id = current_event.get("alert_id", "")

        if current_alert_id:

            already_exists = any(
                str(event.get("alert_id", "")) == current_alert_id
                # Compara los eventos agrupados para no volver a incluir el mismo ID de alerta en el buffer.
                for event in data["events"]
            )

            if already_exists:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                return

        data["events"].append(current_event)

        if rule_level > safe_int(data.get("max_level", 0)):
            data["max_level"] = rule_level

        f.seek(0)
        json.dump(data, f, indent=2)
        f.truncate()

        f.flush()
        os.fsync(f.fileno())

        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


# ============================================================
# CREACION ATOMICA DEL BUFFER
# ============================================================

def create_first_buffer(buffer_path, buffer_data):
    """
    Intenta convertirse en el proceso propietario del buffer.

    O_CREAT | O_EXCL garantiza que solamente UN proceso puede
    crear el archivo.

    Esto elimina el problema anterior donde 25 alertas
    simultaneas podian generar 25 procesos que creian ser
    el primer proceso y terminaban enviando 25 correos.
    """

    fd = os.open(
        buffer_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600
    )

    try:

        with os.fdopen(fd, "w") as f:
            json.dump(buffer_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

    except Exception:

        try:
            os.unlink(buffer_path)
        except FileNotFoundError:
            pass

        raise


# ============================================================
# LECTURA DE ARGUMENTOS WAZUH
# ============================================================

if len(sys.argv) < 4:

    with open(
        "/var/ossec/logs/integrations.log",
        "a"
    ) as logf:

        logf.write(
            "ERROR custom-orangebox-email: "
            "argumentos insuficientes.\n"
        )

    sys.exit(1)


alert_file = sys.argv[1]
recipient = sys.argv[3]


# ============================================================
# CARGAR ALERTA
# ============================================================

try:

    with open(alert_file, "r") as f:
        alert_json = json.load(f)

except Exception as e:

    with open(
        "/var/ossec/logs/integrations.log",
        "a"
    ) as logf:

        logf.write(
            "ERROR custom-orangebox-email leyendo alerta: "
            f"{str(e)}\n"
        )

    sys.exit(1)


# Los eventos consolidados de vulnerabilidad tienen su propio envío:
# un correo global completo y una copia filtrada por cada grupo habilitado.
_early_data = alert_json.get("data", {})
if isinstance(_early_data, dict) and _early_data.get("event_type") == VULNERABILITY_EVENT_TYPE:
    _early_agents = _early_data.get("affected_agents")
    if isinstance(_early_agents, list):
        send_aggregated_vulnerability_emails(alert_json, recipient)
        sys.exit(0)


# ============================================================
# DATOS PRINCIPALES
# ============================================================

rule_id = str(
    alert_json.get("rule", {}).get("id", "N/A")
)

rule_level = safe_int(
    alert_json.get("rule", {}).get("level", 0)
)

# Barrera de correo independiente de la prioridad de las reglas:
# solo suprime reescrituras GCP de /etc/hosts con diff completo e identidad
# semantica intacta. La alerta sigue en alerts.json y en el indexer.
# Los datos incompletos o cualquier cambio real operan fail-open.
if _is_expected_google_hosts_rewrite(alert_json):
    _syscheck = alert_json.get("syscheck", {})
    _audit = _syscheck.get("audit", {}) if isinstance(_syscheck, dict) else {}
    _process = _audit.get("process", {}) if isinstance(_audit, dict) else {}
    _agent = alert_json.get("agent", {})
    try:
        with open("/var/ossec/logs/integrations.log", "a", encoding="utf-8") as logf:
            logf.write(
                "INFO custom-orangebox-email: GCP /etc/hosts rewrite; "
                "mail suppressed, Wazuh alert retained "
                f"agent={_agent.get('name', 'unknown')} "
                f"process={_process.get('name', 'unknown')}\n"
            )
    except OSError:
        pass
    sys.exit(0)

# EXCEPCION FIM: enlace de habilitacion de lvestats en CloudLinux.
# Solo coincide con 10044 + ruta exacta + deleted + scheduled.
# Se conserva el evento en Wazuh; esta excepcion afecta unicamente al correo.
if _is_expected_lvestats_enablement_link_deletion(alert_json):
    _agent = alert_json.get("agent", {})
    _syscheck = alert_json.get("syscheck", {})
    try:
        with open("/var/ossec/logs/integrations.log", "a", encoding="utf-8") as logf:
            logf.write(
                "INFO custom-orangebox-email: CloudLinux lvestats enablement "
                "symlink deletion; mail suppressed, Wazuh alert retained "
                f"agent={_agent.get('name', 'unknown')} "
                f"path={_syscheck.get('path', 'unknown')} "
                f"mode={_syscheck.get('mode', 'unknown')}\n"
            )
    except OSError:
        pass
    sys.exit(0)

# EXCEPCION FIM: limpieza de temporales dpkg de BitNinja.
# Requiere regla/ruta/evento/modo y cadena auditada root -> apt-get -> dpkg.
# Solo suprime el correo; la alerta original permanece en Wazuh.
if _is_expected_dpkg_bitninja_tempfile_cleanup(alert_json):
    _agent = alert_json.get("agent", {})
    _syscheck = alert_json.get("syscheck", {})
    _audit = _syscheck.get("audit", {})
    _process = _audit.get("process", {}) if isinstance(_audit, dict) else {}
    try:
        with open("/var/ossec/logs/integrations.log", "a", encoding="utf-8") as logf:
            logf.write(
                "INFO custom-orangebox-email: BitNinja dpkg temporary-file "
                "cleanup; mail suppressed, Wazuh alert retained "
                f"agent={_agent.get('name', 'unknown')} "
                f"path={_syscheck.get('path', 'unknown')} "
                f"process={_process.get('name', 'unknown')} "
                f"parent={_process.get('parent_name', 'unknown')}\\n"
            )
    except OSError:
        pass
    sys.exit(0)

description = alert_json.get(
    "rule", {}
).get(
    "description",
    "Sin descripcion"
)

event_data = alert_json.get("data", {})
if not isinstance(event_data, dict):
    event_data = {}

vulnerability_event = event_data.get("event_type") == VULNERABILITY_EVENT_TYPE
vulnerability_data = event_data.get("vulnerability", {})
if not isinstance(vulnerability_data, dict):
    vulnerability_data = {}

affected_agent = event_data.get("affected_agent", {})
if not isinstance(affected_agent, dict):
    affected_agent = {}

display_agent = alert_json.get("agent", {})
if not isinstance(display_agent, dict):
    display_agent = {}
if vulnerability_event:
    display_agent = affected_agent

if vulnerability_event:
    # En eventos sintéticos, usar el endpoint real para buffer y destinatarios.
    agent_id = str(display_agent.get("id") or "000")
    agent_name = str(display_agent.get("name") or "Wazuh Manager")
    agent_ip = str(display_agent.get("ip") or "N/A")
else:
    # Mantener exactamente los valores por defecto de las alertas normales.
    agent_id = str(display_agent.get("id", "000"))
    agent_name = display_agent.get("name", "Wazuh Manager")
    agent_ip = display_agent.get("ip", "Local")

vulnerability_cve = str(
    vulnerability_data.get("cve") or vulnerability_data.get("id") or "N/A"
)
vulnerability_severity = str(
    vulnerability_data.get("severity") or "N/A"
).strip().title()

location = alert_json.get(
    "location",
    "N/A"
)

timestamp = alert_json.get(
    "timestamp",
    "N/A"
)

full_log = alert_json.get(
    "full_log",
    "No log fragment attached."
)

if vulnerability_event:
    vulnerability_status = str(vulnerability_data.get("status") or "Active")
    description = (
        f"Vulnerabilidad {vulnerability_severity}: {vulnerability_cve} "
        f"detectada en {agent_name}"
    )
    location = "wazuh-states-vulnerabilities-*"
    full_log = (
        "[ORANGEBOX VULNERABILITY ALERT]\n"
        f"CVE: {vulnerability_cve}\n"
        f"Severidad: {vulnerability_severity}\n"
        f"Estado: {vulnerability_status}\n"
        f"Agente afectado: {agent_name} ({agent_id})\n"
        f"IP del agente: {agent_ip}"
    )

# Vulnerability Detection genera eventos estructurados sin log crudo.
# En ese caso construimos un resumen tecnico para que el correo no
# muestre un "No log fragment attached." vacio.
if not full_log or full_log == "No log fragment attached.":
    vulnerability = alert_json.get("data", {}).get("vulnerability", {})

    if isinstance(vulnerability, dict) and vulnerability:
        package = vulnerability.get("package", {})
        if not isinstance(package, dict):
            package = {}

        scanner = vulnerability.get("scanner", {})
        if not isinstance(scanner, dict):
            scanner = {}

        cve = vulnerability.get(
            "cve",
            vulnerability.get("id", "N/A")
        )

        severity = vulnerability.get("severity", "N/A")
        status = vulnerability.get("status", "N/A")
        package_name = package.get("name", "N/A")
        package_version = package.get("version", "N/A")
        package_arch = package.get("architecture", "N/A")
        condition = (
            package.get("condition")
            or scanner.get("condition")
            or "N/A"
        )
        vuln_description = vulnerability.get(
            "description",
            "N/A"
        )

        full_log = (
            "[VULNERABILITY DETECTION]\n"
            f"CVE: {cve}\n"
            f"Severidad: {severity}\n"
            f"Estado: {status}\n"
            f"Paquete: {package_name}\n"
            f"Version: {package_version}\n"
            f"Arquitectura: {package_arch}\n"
            f"Condicion: {condition}\n"
            f"Descripcion: {vuln_description}"
        )

rule_groups = alert_json.get("rule", {}).get("groups", [])
if not isinstance(rule_groups, list):
    rule_groups = []

groups = ", ".join(
    str(group)
    # Revisa los grupos de la regla y busca cuáles identifican un perfil operativo del agente.
    for group in rule_groups
)

# Detecta la política efectiva de firewall-drop usando la semántica Wazuh:
# rules_id, rules_group y level son selectores alternativos (OR).
OSSEC_CONF = "/var/ossec/etc/ossec.conf"

firewall_drop_policy = firewall_drop_policy_for_alert(
    rule_id,
    rule_level,
    rule_groups,
    OSSEC_CONF,
)
firewall_drop_configured = firewall_drop_policy.get("status") == "configured"
firewall_drop_unknown = firewall_drop_policy.get("status") == "unknown"
firewall_drop_timeout = firewall_drop_policy.get("timeout_seconds")

if firewall_drop_unknown:
    try:
        with open("/var/ossec/logs/integrations.log", "a", encoding="utf-8") as logf:
            logf.write(
                "WARN custom-orangebox-email: Active Response no verificable "
                f"para regla {rule_id}: {firewall_drop_policy.get('error', 'error desconocido')}\\n"
            )
    except OSError:
        pass

normalized_rule_groups = {
    normalize_group_name(group)
    # Revisa los grupos de la regla y busca cuáles identifican un perfil operativo del agente.
    for group in rule_groups
}
send_immediately = (
    rule_id in IMMEDIATE_RULES
    or IMMEDIATE_RULE_GROUP in normalized_rule_groups
)


event_data = alert_json.get("data", {})
if not isinstance(event_data, dict):
    event_data = {}

win_data = event_data.get("win", {})
if not isinstance(win_data, dict):
    win_data = {}
win_event_data = win_data.get("eventdata", {})
if not isinstance(win_event_data, dict):
    win_event_data = {}

source_ip = (
    event_data.get("srcip", "")
    or event_data.get("src_ip", "")
    or event_data.get("ip_address", "")
    or win_event_data.get("ipAddress", "")
)
if not source_ip:
    import re
    source_match = re.search(
        r'^\S+\s+((?:\d{1,3}\.){3}\d{1,3})\s+-\s+-\s+\[',
        str(full_log),
    )
    if source_match:
        source_ip = source_match.group(1)

# Solo mostramos el estado firewall-drop si existe una política,
# la configuración no se puede verificar o el evento crítico requiere
# revisión de contención. Un login SSH exitoso no se etiqueta como ataque
# por el simple hecho de contener una IP de origen.
is_blocked_alert = should_render_firewall_drop_status(
    rule_id,
    rule_level,
    source_ip,
    firewall_drop_policy.get("status"),
)

# rule.groups pertenece a la REGLA. El routing usa grupos del AGENTE.
agent_groups = extract_agent_groups(alert_json)
if vulnerability_event:
    groups = ", ".join(agent_groups) or "Sin grupo de cliente asignado"
recipients = build_recipients(recipient, agent_groups)

# Identidad secundaria del login SSH.
# journald puede generar eventos derivados sin data.srcip.
# El fingerprint permite reconocer que pertenecen a la misma
# autenticacion aunque el evento no conserve la IP origen.
ssh_identity = ""
if rule_id in {"5715", "10001"}:
    import re

    ssh_user = (
        alert_json.get("data", {}).get("srcuser", "")
        or alert_json.get("data", {}).get("dstuser", "")
        or ""
    )

    fingerprint_match = re.search(
        r"SHA256:[A-Za-z0-9+/=]+",
        full_log
    )

    fingerprint = (
        fingerprint_match.group(0)
        if fingerprint_match
        else ""
    )

    if fingerprint:
        ssh_identity = f"{ssh_user}|{fingerprint}"
    elif ssh_user:
        ssh_identity = f"{ssh_user}|ssh-login"



# ============================================================
# SUPRESION DE CORREO PARA FIREWALL-DROP
# ============================================================
#
# La alerta permanece completamente en Wazuh y Active Response
# no se modifica. Solamente evitamos enviar el correo individual
# porque el dashboard PDF consolida:
#
#   - regla que disparo el bloqueo
#   - IPs atacantes
#   - ejecuciones reales de firewall-drop (regla 651)
#   - sistemas afectados
#   - volumen de intentos
#
# La regla 651 que Wazuh genera al ejecutar firewall-drop tiene
# nivel bajo y no cruza nuestro umbral de integracion, por lo
# que tampoco genera un correo individual.
#
if (
    rule_id in NO_EMAIL_RULES
    or (firewall_drop_configured and not send_immediately)
):
    sys.exit(0)


# ============================================================
# DATOS FIM / SYSCHECK
# ============================================================

# IMPORTANTE:
#
# Antes solamente guardabamos:
#
#   path
#   diff
#   size_after
#   uname_after
#
# Eso podia perder informacion importante entregada por Wazuh.
#
# Ahora conservamos TODO el objeto syscheck.

syscheck_data = alert_json.get(
    "syscheck",
    {}
)

if not isinstance(syscheck_data, dict):
    syscheck_data = {}


# ============================================================
# EVENTO COMPLETO PARA EL BUFFER
# ============================================================

alert_id = str(
    alert_json.get("id", "")
)

current_event = {
    "agent_groups": agent_groups,
    "recipients": recipients,
    "alert_id": alert_id,
    "timestamp": timestamp,
    "level": rule_level,
    "full_log": full_log,

    # Conservamos el objeto FIM COMPLETO.
    "syscheck": syscheck_data,

    # Estos campos adicionales mantienen compatibilidad con
    # cualquier procesamiento existente.
    "file_path": syscheck_data.get("path", ""),
    "file_diff": syscheck_data.get("diff", ""),
    "file_size": syscheck_data.get("size_after", "N/A"),
    "file_uname": syscheck_data.get("uname_after", "N/A"),

    # Conservamos tambien el JSON original del evento.
    # Esto permite recuperar informacion futura sin tener
    # que modificar nuevamente la estructura del buffer.
    "alert": alert_json,
}


# ============================================================
# ENVIO INMEDIATO
# ============================================================

# !!! LOCKED - ALERTAS INMEDIATAS DE SEGURIDAD !!!
#
# NO MODIFICAR LA LOGICA DE ENVIO INMEDIATO SIN UNA PETICION
# EXPLICITA DEL USUARIO Y PRUEBAS DE REGRESION COMPLETAS.
#
# Quedan congeladas las reglas de escalamiento/privilegios que
# requieren envio inmediato, incluyendo:
#   - 10004 = su -> root
#   - 10005 = SUDO -> root sin excepcion validada
#   - 10008 = sudo -i / escalamiento equivalente
#   - 10009 = otros escalamientos SUDO definidos por OrangeBox
#   - 5715 / 10001 = SSH exitoso (con su deduplicacion bloqueada arriba)
#
# No mover estas reglas al buffer ni cambiar su tratamiento sin
# autorizacion explicita y pruebas de regresion.
#
# !!! FIN CONTRATO LOCKED !!!
#
# ------------------------------------------------------------
# DEDUPLICACION PARA SSH
# ------------------------------------------------------------
#
# 5715 = regla nativa de SSH exitoso.
# 10001 = regla OrangeBox hija de 5715.
#
# Ambas representan el mismo evento de autenticacion SSH.
#
# La deduplicacion se realiza, en este orden, por:
#     1. agente + segundo + huella exacta del log
#     2. agente + IP origen + dia calendario
#     3. agente + fingerprint/identidad SSH + dia
#
# Esto NO afecta:
#     10004 = SU
#     10008 = SUDO
#     10009 = SUDO
#
# Esas reglas siguen enviandose siempre.
# ------------------------------------------------------------

if rule_id in {"5715", "10001"}:

    srcip = (
        alert_json
        .get("data", {})
        .get("srcip", "")
    )

    if not srcip:
        srcip = extract_ssh_source_ip(full_log)

    # El log bruto de sshd es el fallback normal para journald.
    # Si tampoco existe una IP, conservamos el comportamiento fail-open.
    # journald puede omitir data.srcip. La funcion de dedup
    # recupera la IP desde full_log cuando sea necesario.
    if ssh_already_notified(
        agent_id,
        srcip,
        timestamp,
        ssh_identity,
        full_log
    ):

        # SSH repetido desde la misma IP durante el mismo dia.
        #
        # La alerta SI queda registrada en Wazuh.
        # Simplemente no enviamos otro correo.
        try:
            with open("/var/ossec/logs/integrations.log", "a") as logf:
                logf.write(
                    "INFO custom-orangebox-email SSH dedup: "
                    f"rule={rule_id} agent={agent_id} "
                    f"srcip={srcip or 'unknown'} date={str(timestamp)[:10]}\\n"
                )
        except Exception:
            pass

        sys.exit(0)


# ============================================================
# PREPARAR DATOS FINALES
# ============================================================

if send_immediately:

    total_alerts = 1

    highest_level = rule_level

    final_data = {
        "agent_groups": agent_groups,
        "recipients": recipients,
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "agent_id": agent_id,
        "rule_id": rule_id,
        "description": description,
        "location": location,
        "groups": groups,
        "events": [
            current_event
        ]
    }

else:

    # ========================================================
    # AGRUPACION
    # ========================================================
    #
    # La clave sigue siendo:
    #
    #       agent_id + rule_id
    #
    # Nunca se mezclan:
    #
    #   agente A + regla 10410
    #   agente B + regla 10410
    #
    # ni:
    #
    #   agente A + regla 10410
    #   agente A + regla 10030
    #
    # ========================================================

    buffer_key = (
        f"buffer_{agent_id}_{rule_id}.json"
    )

    buffer_path = os.path.join(
        BUFFER_DIR,
        buffer_key
    )

    os.makedirs(
        BUFFER_DIR,
        exist_ok=True
    )

    buffer_data = {
        "first_seen": time.time(),
        "agent_groups": agent_groups,
        "recipients": recipients,
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "agent_id": agent_id,
        "rule_id": rule_id,
        "description": description,
        "location": location,
        "groups": groups,
        "max_level": rule_level,
        "events": [
            current_event
        ]
    }

    # --------------------------------------------------------
    # Intentamos crear el buffer de forma atomica.
    #
    # Si tenemos exito:
    #   somos el primer evento
    #   esperamos 10 minutos
    #   enviamos el correo.
    #
    # Si falla porque ya existe:
    #   otro proceso ya es propietario
    #   simplemente agregamos el evento.
    # --------------------------------------------------------

    try:

        create_first_buffer(
            buffer_path,
            buffer_data
        )

        # ----------------------------------------------------
        # SOMOS EL PRIMER EVENTO.
        #
        # Creamos un proceso hijo que esperara la ventana
        # de agrupacion mientras este proceso padre termina.
        # ----------------------------------------------------

        pid = os.fork()

        if pid > 0:
            sys.exit(0)

        # ----------------------------------------------------
        # PROCESO HIJO
        # ----------------------------------------------------
        #
        # Wazuh wazuh-integratord ejecuta las integraciones con
        # stdout/stderr conectados a un pipe y espera EOF antes
        # de continuar con la siguiente alerta.
        #
        # Este hijo debe desprenderse inmediatamente de esos
        # descriptores. Si conserva fd 1/2 abiertos mientras
        # duerme los 10 minutos, integratord queda bloqueado
        # durante toda la ventana de agrupacion y las alertas
        # posteriores (incluidas las inmediatas SSH/SU/SUDO)
        # se retrasan artificialmente.
        #
        # Reemplazamos stdin/stdout/stderr por /dev/null para
        # que el proceso hijo quede completamente desacoplado
        # del pipe del integrador.
        # ----------------------------------------------------

        os.setsid()

        devnull_fd = os.open(os.devnull, os.O_RDWR)

        try:
            os.dup2(devnull_fd, sys.stdin.fileno())
            os.dup2(devnull_fd, sys.stdout.fileno())
            os.dup2(devnull_fd, sys.stderr.fileno())
        finally:
            os.close(devnull_fd)

        time.sleep(WINDOW_SECONDS)

        # ----------------------------------------------------
        # Leer el buffer completo.
        # ----------------------------------------------------

        try:

            with open(
                buffer_path,
                "r"
            ) as f:

                final_data = json.load(f)

        except Exception as e:

            with open(
                "/var/ossec/logs/integrations.log",
                "a"
            ) as logf:

                logf.write(
                    "ERROR leyendo buffer "
                    f"{buffer_path}: {str(e)}\n"
                )

            try:
                os.remove(buffer_path)
            except FileNotFoundError:
                pass

            sys.exit(1)

        # ----------------------------------------------------
        # Eliminar buffer.
        # ----------------------------------------------------

        try:
            os.remove(buffer_path)
        except FileNotFoundError:
            pass

    except FileExistsError:

        # ----------------------------------------------------
        # Otro proceso ya creo el buffer.
        #
        # Simplemente agregamos el evento actual.
        # ----------------------------------------------------

        try:

            append_event_to_buffer(
                buffer_path,
                current_event,
                agent_name,
                agent_ip,
                agent_id,
                rule_id,
                description,
                location,
                groups,
                rule_level
            )

        except Exception as e:

            with open(
                "/var/ossec/logs/integrations.log",
                "a"
            ) as logf:

                logf.write(
                    "ERROR agregando evento al buffer "
                    f"{buffer_path}: {str(e)}\n"
                )

        # Este proceso NO envia correo.
        sys.exit(0)

    except Exception as e:

        with open(
            "/var/ossec/logs/integrations.log",
            "a"
        ) as logf:

            logf.write(
                "ERROR creando buffer "
                f"{buffer_path}: {str(e)}\n"
            )

        sys.exit(1)

    total_alerts = len(
        final_data.get("events", [])
    )

    highest_level = safe_int(
        final_data.get("max_level", 0)
    )


# ============================================================
# COLOR Y TEXTO DE CABECERA
# ============================================================

if vulnerability_event:
    severity_key = vulnerability_severity.upper()
    if severity_key == "CRITICAL":
        status_color = "#dc2626"
        status_text = "CRITICO"
    elif severity_key == "HIGH":
        status_color = "#ea580c"
        status_text = "ALTO"
    else:
        status_color = "#ca8a04"
        status_text = "MEDIO"

elif highest_level >= 12:
    status_color = "#dc2626"
    status_text = "CRITICO"

elif highest_level >= 7:
    status_color = "#f97316"
    status_text = "ADVERTENCIA"

else:
    status_color = "#4b5563"
    status_text = "INFORMACION"


# ============================================================
# ENCABEZADO
# ============================================================

if (
    send_immediately
    or total_alerts == 1
):

    if vulnerability_event:
        subtitulo_header = f"Vulnerabilidad {status_text}: {vulnerability_cve}"
        texto_contador = "1 vulnerabilidad detectada (CVE/agente)"
    else:
        subtitulo_header = (
            f"Alerta de Seguridad: Nivel "
            f"{highest_level} ({status_text})"
        )
        texto_contador = (
            "1 Alerta registrada "
            "(Evento unico)"
        )

else:

    subtitulo_header = (
        f"Maximo Nivel de Alerta en Rafaga: "
        f"{highest_level} ({status_text})"
    )

    texto_contador = (
        f"{total_alerts} Alertas registradas "
        "(Eventos consolidados)"
    )


# ============================================================
# CONSTRUCCION DEL HISTORIAL FIM
# ============================================================

log_history_html = ""
fim_details_html = ""


# ============================================================
# FIM:
#
# AHORA SE MUESTRAN TODOS LOS EVENTOS.
#
# Antes solamente:
#
#     last_event = events[-1]
#
# Por eso un correo con 25 archivos mostraba solamente
# el ultimo archivo.
#
# Ahora cada evento tiene:
#
#   archivo
#   propietario
#   tamaño
#   atributos modificados
#   hashes
#   diff si existe
#   log crudo
#
# ============================================================

fim_event_counter = 0

# Recorre los eventos FIM agrupados para construir el detalle de auditoría del correo.
for idx, ev in enumerate(
    final_data.get("events", []),
    start=1
):

    syscheck = ev.get(
        "syscheck",
        {}
    )

    if not isinstance(syscheck, dict):
        syscheck = {}

    file_path = syscheck.get(
        "path",
        ev.get("file_path", "")
    )

    if not file_path:
        continue

    fim_event_counter += 1

    file_diff = syscheck.get(
        "diff",
        ev.get("file_diff", "")
    )

    file_diff = str(
        file_diff or ""
    ).strip()

    file_size = syscheck.get(
        "size_after",
        ev.get("file_size", "N/A")
    )

    file_uname = syscheck.get(
        "uname_after",
        ev.get("file_uname", "N/A")
    )

    changed_fields = syscheck.get(
        "changed_attributes",
        syscheck.get(
            "changed_fields",
            ""
        )
    )

    # Captura el modo, tipo de evento y atribucion Who-Data entregados por FIM.
    fim_mode = syscheck.get("mode", "N/A")
    fim_event = syscheck.get("event", "N/A")
    audit_data = syscheck.get("audit", {})
    if not isinstance(audit_data, dict):
        audit_data = {}

    audit_user = audit_data.get("user", {})
    if not isinstance(audit_user, dict):
        audit_user = {}

    audit_process = audit_data.get("process", {})
    if not isinstance(audit_process, dict):
        audit_process = {}

    audit_group = audit_data.get("group", {})
    if not isinstance(audit_group, dict):
        audit_group = {}

    audit_effective_user = audit_data.get("effective_user", {})
    if not isinstance(audit_effective_user, dict):
        audit_effective_user = {}

    # --------------------------------------------------------
    # Algunos eventos FIM pueden traer informacion de hashes
    # aunque no tengan diff de contenido.
    # --------------------------------------------------------

    hash_rows = ""

    # Incluye únicamente los hashes posteriores que Wazuh entregó en el evento FIM.
    for hash_name in (
        "md5_after",
        "sha1_after",
        "sha256_after"
    ):

        if hash_name in syscheck:

            hash_rows += f"""
            <tr class="ob-detail-row">
                <td colspan="2" style="padding:7px 10px;
                    border-bottom:1px solid #e2e8f0;
                    font-size:12px;line-height:1.45;color:#0f172a;
                    overflow-wrap:anywhere;">
                    <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">{esc(hash_name)}:</strong>
                    <span style="display:inline-block;width:58%;vertical-align:top;font-family:monospace;word-break:normal;">{esc(syscheck.get(hash_name))}</span>
                </td>
            </tr>
            """

    # --------------------------------------------------------
    # Atributos modificados.
    # --------------------------------------------------------

    changed_html = ""

    if isinstance(changed_fields, list):

        changed_text = ", ".join(
            str(x)
            # Convierte la lista de atributos modificados en texto legible para el detalle FIM.
            for x in changed_fields
        )

    else:

        changed_text = str(
            changed_fields or ""
        )

    if changed_text:

        changed_html = f"""
        <tr class="ob-detail-row">
            <td colspan="2" style="padding:7px 10px;
                border-bottom:1px solid #e2e8f0;
                font-size:12px;line-height:1.45;color:#0f172a;
                overflow-wrap:anywhere;">
                <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">Atributos modificados:</strong>
                <span style="display:inline-block;width:58%;vertical-align:top;font-family:monospace;word-break:normal;">{esc(changed_text)}</span>
            </td>
        </tr>
        """

    # --------------------------------------------------------
    # Modo FIM y atribucion Who-Data.
    # Solo se muestran datos que realmente vinieron en el evento.
    # --------------------------------------------------------

    audit_rows = f"""
    <tr class="ob-detail-row">
        <td colspan="2" style="padding:7px 10px;
            border-bottom:1px solid #e2e8f0;
            font-size:12px;line-height:1.45;color:#0f172a;
            overflow-wrap:anywhere;">
            <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">Modo / evento FIM:</strong>
            <span style="display:inline-block;width:58%;vertical-align:top;font-family:monospace;">{esc(fim_mode)} / {esc(fim_event)}</span>
        </td>
    </tr>
    """

    audit_process_name = audit_process.get("name")
    audit_process_id = audit_process.get("id")
    audit_process_cwd = audit_process.get("cwd")
    audit_parent_name = audit_process.get("parent_name")
    audit_parent_pid = audit_process.get("ppid")
    audit_user_name = audit_user.get("name")
    audit_user_id = audit_user.get("id")
    audit_group_name = audit_group.get("name")
    audit_effective_user_name = audit_effective_user.get("name")

    if audit_user_name or audit_user_id:
        audit_rows += f"""
        <tr class="ob-detail-row">
            <td colspan="2" style="padding:7px 10px;
                border-bottom:1px solid #e2e8f0;
                font-size:12px;line-height:1.45;color:#0f172a;
                overflow-wrap:anywhere;">
                <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">Usuario / UID:</strong>
                <span style="display:inline-block;width:58%;vertical-align:top;">{esc(audit_user_name or "N/A")} ({esc(audit_user_id or "N/A")})</span>
            </td>
        </tr>
        """

    if audit_group_name or audit_effective_user_name:
        audit_rows += f"""
        <tr class="ob-detail-row">
            <td colspan="2" style="padding:7px 10px;
                border-bottom:1px solid #e2e8f0;
                font-size:12px;line-height:1.45;color:#0f172a;
                overflow-wrap:anywhere;">
                <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">Grupo / usuario efectivo:</strong>
                <span style="display:inline-block;width:58%;vertical-align:top;">{esc(audit_group_name or "N/A")} / {esc(audit_effective_user_name or "N/A")}</span>
            </td>
        </tr>
        """

    if audit_process_name or audit_process_id:
        audit_rows += f"""
        <tr class="ob-detail-row">
            <td colspan="2" style="padding:7px 10px;
                border-bottom:1px solid #e2e8f0;
                font-size:12px;line-height:1.45;color:#0f172a;
                overflow-wrap:anywhere;">
                <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">Proceso / PID:</strong>
                <span style="display:inline-block;width:58%;vertical-align:top;font-family:monospace;word-break:break-all;">{esc(audit_process_name or "N/A")} ({esc(audit_process_id or "N/A")})</span>
            </td>
        </tr>
        """

    if audit_parent_name or audit_parent_pid:
        audit_rows += f"""
        <tr class="ob-detail-row">
            <td colspan="2" style="padding:7px 10px;
                border-bottom:1px solid #e2e8f0;
                font-size:12px;line-height:1.45;color:#0f172a;
                overflow-wrap:anywhere;">
                <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">Proceso padre / PPID:</strong>
                <span style="display:inline-block;width:58%;vertical-align:top;font-family:monospace;word-break:break-all;">{esc(audit_parent_name or "N/A")} ({esc(audit_parent_pid or "N/A")})</span>
            </td>
        </tr>
        """

    if audit_process_cwd:
        audit_rows += f"""
        <tr class="ob-detail-row">
            <td colspan="2" style="padding:7px 10px;
                border-bottom:1px solid #e2e8f0;
                font-size:12px;line-height:1.45;color:#0f172a;
                overflow-wrap:anywhere;">
                <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">Directorio de trabajo:</strong>
                <span style="display:inline-block;width:58%;vertical-align:top;font-family:monospace;">{esc(audit_process_cwd)}</span>
            </td>
        </tr>
        """

    # --------------------------------------------------------
    # Diff.
    #
    # Si existe, se muestra exactamente.
    #
    # Si no existe, NO decimos que Wazuh "no adjunto"
    # diferencias. Indicamos que el evento no contiene
    # diff de contenido.
    # --------------------------------------------------------

    if file_diff:

        diff_html = f"""
        <pre style="margin: 0; color: #38bdf8;
            font-family: monospace;
            white-space: pre-wrap;
            font-size: 12px;
            line-height: 1.5;
            text-align: left;">{esc(file_diff)}</pre>
        """

    else:

        diff_html = """
        <div style="color: #94a3b8;
            font-family: monospace;
            font-size: 12px;">
            Este evento FIM no contiene un diff de contenido.
            Se muestran los atributos y hashes disponibles.
        </div>
        """

    fim_details_html += f"""
    <tr>
        <td colspan="2"
            style="padding: 12px 16px;
            background-color: #f1f5f9;
            font-size: 13px;
            font-weight: 700;
            color: #1e293b;
            border-bottom: 1px solid #cbd5e1;">

            Auditoria de Integridad (FIM)
            - Evento {idx}/{total_alerts}

        </td>
    </tr>

    <tr class="ob-detail-row">
        <td colspan="2" style="padding:8px 10px;
            border-bottom:1px solid #e2e8f0;
            font-size:12px;line-height:1.45;color:#0f172a;
            overflow-wrap:anywhere;">
            <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">Ruta del archivo:</strong>
            <span style="display:inline-block;width:58%;vertical-align:top;font-family:monospace;font-weight:bold;word-break:normal;">{esc(file_path)}</span>
        </td>
    </tr>

    <tr class="ob-detail-row">
        <td colspan="2" style="padding:8px 10px;
            border-bottom:1px solid #e2e8f0;
            font-size:12px;line-height:1.45;color:#0f172a;
            overflow-wrap:anywhere;">
            <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#475569;">Propietario / tamaño:</strong>
            <span style="display:inline-block;width:58%;vertical-align:top;">{esc(file_uname)} ({esc(file_size)} bytes)</span>
        </td>
    </tr>

    {audit_rows}

    {changed_html}

    {hash_rows}

    <tr>
        <td colspan="2"
            style="padding: 12px 16px;
            background-color: #f8fafc;
            font-size: 13px;
            font-weight: 700;
            color: #334155;
            border-bottom: 1px solid #cbd5e1;">

            Modificaciones Exactas en el Contenido (Diff):

        </td>
    </tr>

    <tr>
        <td colspan="2"
            style="padding: 14px;
            background-color: #1e293b;">

            {diff_html}

        </td>
    </tr>
    """


# ============================================================
# HISTORIAL DE LOGS CRUDOS
# ============================================================

# Recorre los eventos FIM agrupados para construir el detalle de auditoría del correo.
for idx, ev in enumerate(
    final_data.get("events", []),
    start=1
):

    log_history_html += f"""
    <div style="
        margin-bottom: 12px;
        border-bottom: 1px dashed #cbd5e1;
        padding-bottom: 10px;
    ">

        <span style="
            color: #475569;
            font-weight: bold;
        ">
            [{idx}/{total_alerts}]
            ({esc(ev.get('timestamp', 'N/A'))}):
        </span>

        <br/>

        <pre style="
            margin: 5px 0 0 0;
            color: #b91c1c;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-wrap: break-word;
            word-break: normal;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
            overflow: hidden;
            font-size: 13px;
            line-height: 1.4;
        ">{format_log_for_html(ev.get('full_log', ''))}</pre>

    </div>
    """


# ============================================================
# URL DINAMICA WAZUH
# ============================================================

wazuh_url = (
    "https://wazuh.example.invalid/app/threat-hunting"
    "#/overview/?tab=general&tabView=events"
    f"&agentId={final_data['agent_id']}"
    "&_a=(filters:!(('$state':(store:appState),"
    "meta:(alias:'-%20Level%2012%20or%20above%20alerts',"
    "disabled:!f,index:'wazuh-alerts-*',key:query,"
    "negate:!f,type:custom,value:"
    "'%7B%22bool%22:%7B%22must%22:%5B%5D,"
    "%22filter%22:%5B%7B%22bool%22:%7B"
    "%22should%22:%5B%7B%22range%22:%7B"
    "%22rule.level%22:%7B%22gte%22:12%7D%7D%7D%5D,"
    "%22minimum_should_match%22:1%7D%7D%5D,"
    "%22should%22:%5B%5D,%22must_not%22:%5B%5D%7D%7D'),"
    "query:(bool:(filter:!((bool:"
    "(minimum_should_match:1,should:!((range:"
    "(rule.level:(gte:12))))))),must:!(),"
    "must_not:!(),should:!())))),"
    "query:(language:kuery,query:''))"
    "&_g=(filters:!(),refreshInterval:"
    "(pause:!t,value:0),time:(from:now-24h,to:now))"
)


# Fila de datos normal para alertas con respuesta activa configurada.
def format_timeout(seconds):
    """Convierte el timeout de Active Response a una duración legible para el correo."""
    if seconds is None:
        return "no especificado"
    if seconds <= 0:
        return "sin timeout definido"
    if seconds % 86400 == 0:
        days = seconds // 86400
        return f"{days} día" if days == 1 else f"{days} días"
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hora" if hours == 1 else f"{hours} horas"
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minuto" if minutes == 1 else f"{minutes} minutos"
    return f"{seconds} segundos"


blocked_ip_html = ""
if is_blocked_alert:
    timeout_label = format_timeout(firewall_drop_timeout)
    if firewall_drop_configured:
        status_detail = "firewall-drop configurado; ejecución pendiente de confirmar"
        location_detail = firewall_drop_policy.get("location", "no especificado")
        selector_detail = ", ".join(firewall_drop_policy.get("matched_by", []))
    elif firewall_drop_unknown:
        status_detail = "No fue posible verificar la configuración de Active Response"
        location_detail = "no verificado"
        selector_detail = firewall_drop_policy.get("error", "error desconocido")
    else:
        status_detail = "NO BLOQUEADA: no hay firewall-drop configurado para esta regla"
        location_detail = "no aplica"
        selector_detail = "No coincide con ningún selector rules_id, rules_group o level"

    blocked_ip_html = f"""
                            <tr class="ob-detail-row">
                                <td colspan="2" style="padding:8px 10px;
                                    border-bottom:1px solid #cbd5e1;
                                    color:#0f172a;font-size:12px;line-height:1.45;
                                    overflow-wrap:anywhere;">
                                    <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#334155;">Active Response:</strong>
                                    <span style="display:inline-block;width:58%;vertical-align:top;font-weight:700;overflow-wrap:anywhere;">{esc(source_ip or 'IP no disponible en el evento')}</span>
                                    <span style="display:inline-block;width:58%;margin-left:170px;vertical-align:top;overflow-wrap:anywhere;">{esc(status_detail)}</span>
                                    <span style="display:inline-block;width:58%;margin-left:170px;vertical-align:top;overflow-wrap:anywhere;">Acción: firewall-drop<br>Tiempo: {esc(timeout_label)}<br>Ejecución en: {esc(location_detail)}</span>
                                    <span style="display:inline-block;width:58%;margin-left:170px;vertical-align:top;font-size:11px;color:#475569;overflow-wrap:anywhere;">Selector: {esc(selector_detail)}</span>
                                </td>
                            </tr>
                            """


# ============================================================
# PLANTILLA HTML CORPORATIVA ORANGEBOX
# ============================================================

html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="x-apple-disable-message-reformatting">
    <style>
        /* ORANGEBOX RESPONSIVE EMAIL LAYOUT
           Gmail Android can retain inline-block widths from desktop layouts.
           On narrow screens, stack every label/value and remove fixed offsets. */
        .ob-card, .ob-details-table {{
            width:100% !important;
            max-width:100% !important;
        }}
        .ob-details-table {{
            table-layout:fixed !important;
        }}
        .ob-detail-row td {{
            max-width:100% !important;
            overflow-wrap:anywhere !important;
            word-wrap:break-word !important;
        }}
        @media only screen and (max-width:600px) {{
            body {{ padding:6px !important; }}
            .ob-card {{ width:100% !important; max-width:100% !important; }}
            .ob-content {{ padding-left:4px !important; padding-right:4px !important; }}
            .ob-details-table {{ width:100% !important; max-width:100% !important; table-layout:fixed !important; }}
            .ob-detail-row td {{ padding-left:9px !important; padding-right:9px !important; }}
            .ob-detail-row strong {{
                display:block !important;
                width:100% !important;
                max-width:100% !important;
                margin:0 0 3px 0 !important;
                padding-right:0 !important;
                box-sizing:border-box !important;
            }}
            .ob-detail-row span {{
                display:block !important;
                width:100% !important;
                max-width:100% !important;
                margin-left:0 !important;
                box-sizing:border-box !important;
                overflow-wrap:anywhere !important;
                word-wrap:break-word !important;
                word-break:break-word !important;
            }}
            .ob-detail-row img {{ max-width:100% !important; height:auto !important; }}
        }}
    </style>
    <title>Alerta Wazuh: Nivel {highest_level} en {esc(final_data['agent_name'])}</title>
</head>

<body style="
    margin:0;
    padding:12px;
    background-color:#1e2a3e;
    font-family:Arial,Helvetica,sans-serif;
">

<!-- CONTENEDOR PRINCIPAL -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
       style="width:100%;background-color:#1e2a3e;">
    <tr>
        <td align="center" style="padding:10px 0;">

            <!-- TARJETA ORANGEBOX -->
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                   align="center"
                   class="ob-card"
                   style="
                       width:100%;
                       max-width:720px;
                       width:100%;
                       table-layout:fixed;
                       background-color:#2d3a4e;
                       border:1px solid #42516a;
                       border-radius:20px;
                   ">

                <!-- HEADER -->
                <tr>
                    <td align="center"
                        style="
                            padding:28px 24px 22px;
                            background-color:#2d3a4e;
                            border-radius:20px 20px 0 0;
                        ">

                        <img src="https://www.orangebox.cl/obox/img/logo-dark.png"
                             alt="OrangeBox"
                             border="0"
                             width="220"
                             style="
                                 display:block;
                                 width:220px;
                                 max-width:75%;
                                 height:auto;
                                 margin:0 auto 12px;
                             ">

                        <div style="
                            color:#ffffff;
                            font-size:22px;
                            line-height:28px;
                            font-weight:700;
                            letter-spacing:-0.3px;
                        ">
                            OrangeBox
                            <span style="color:#f97316;">Seguridad</span>
                        </div>

                        <div style="
                            display:inline-block;
                            margin-top:12px;
                            padding:6px 16px;
                            background-color:#45556c;
                            color:#e2e8f0;
                            border-radius:999px;
                            font-size:13px;
                            line-height:18px;
                            font-weight:700;
                        ">
                            {subtitulo_header}
                        </div>

                    </td>
                </tr>

                <!-- CONTENIDO -->
                <tr>
                    <td class="ob-content" style="padding:0 8px 4px;">

                        <!-- TABLA PRINCIPAL -->
                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                               class="ob-details-table"
                               style="
                                   width:100%;
                                   background-color:#eef2ff;
                                   max-width:100%;
                                   table-layout:fixed;
                                   box-sizing:border-box;
                                   border:1px solid #cbd5e1;
                                   border-collapse:separate;
                                   border-radius:14px;
                               ">

                            <!-- CABECERA DE ALERTA -->
                            <tr>
                                <td colspan="2"
                                    style="
                                        padding:16px 18px;
                                        background-color:{status_color};
                                        border-radius:13px 13px 0 0;
                                        text-align:center;
                                    ">

                                    <div style="
                                        color:#ffffff;
                                        font-size:16px;
                                        line-height:22px;
                                        font-weight:800;
                                    ">
                                        ID Regla {esc(final_data['rule_id'])}
                                    </div>

                                    <div style="
                                        margin-top:4px;
                                        color:#ffffff;
                                        font-size:15px;
                                        line-height:21px;
                                        font-weight:700;
                                    ">
                                        {esc(final_data['description'])}
                                    </div>

                                </td>
                            </tr>

                            <!-- DATOS EN FORMATO TABLA -->
                            <tr class="ob-detail-row">
                                <td colspan="2" style="padding:8px 10px;
                                    border-bottom:1px solid #cbd5e1;
                                    color:#0f172a;font-size:13px;line-height:1.45;
                                    overflow-wrap:anywhere;">
                                    <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#334155;font-size:12px;">Agente afectado:</strong>
                                    <span style="display:inline-block;width:58%;vertical-align:top;font-weight:700;word-break:normal;">{esc(final_data['agent_name'])} ({esc(final_data['agent_ip'])})</span>
                                </td>
                            </tr>

                            {blocked_ip_html}

                            <tr class="ob-detail-row">
                                <td colspan="2" style="padding:8px 10px;
                                    border-bottom:1px solid #cbd5e1;
                                    color:#0f172a;font-size:13px;line-height:1.45;
                                    overflow-wrap:anywhere;">
                                    <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#334155;font-size:12px;">Origen / ubicación:</strong>
                                    <span style="display:inline-block;width:58%;vertical-align:top;font-family:monospace;word-break:normal;">{esc(final_data['location'])}</span>
                                </td>
                            </tr>

                            <tr class="ob-detail-row">
                                <td colspan="2" style="padding:8px 10px;
                                    border-bottom:1px solid #cbd5e1;
                                    color:#0f172a;font-size:12px;line-height:1.45;
                                    overflow-wrap:anywhere;">
                                    <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#334155;">Categoría / grupo:</strong>
                                    <span style="display:inline-block;width:58%;vertical-align:top;word-break:normal;">{esc(final_data['groups'])}</span>
                                </td>
                            </tr>

                            <tr class="ob-detail-row">
                                <td colspan="2" style="padding:8px 10px;
                                    color:#0f172a;font-size:13px;line-height:1.45;
                                    overflow-wrap:anywhere;">
                                    <strong style="display:inline-block;width:170px;max-width:40%;box-sizing:border-box;vertical-align:top;padding-right:12px;color:#334155;font-size:12px;">Estado del evento:</strong>
                                    <span style="display:inline-block;width:58%;vertical-align:top;font-weight:700;">{texto_contador}</span>
                                </td>
                            </tr>

                            <!-- FIM -->
                            {fim_details_html}

                            <!-- LOGS CRUDOS -->
                            <tr>
                                <td colspan="2"
                                    style="
                                        padding:12px 16px;
                                        background-color:#f8fafc;
                                        border-top:1px solid #cbd5e1;
                                        color:#334155;
                                        font-size:13px;
                                        line-height:18px;
                                        font-weight:700;
                                    ">
                                    Historial de Logs Crudos de Wazuh
                                </td>
                            </tr>

                            <tr>
                                <td colspan="2"
                                    style="
                                        padding:16px;
                                        background-color:#ffffff;
                                        border-radius:0 0 13px 13px;
                                    ">
                                    {log_history_html}
                                </td>
                            </tr>

                        </table>
                    </td>
                </tr>

                <!-- BOTON -->
                <tr>
                    <td align="center" style="padding:20px 20px 22px;">

                        <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center"
                               style="border-collapse:separate;">
                            <tr>
                                <td align="center"
                                    bgcolor="#f97316"
                                    style="
                                        background-color:#f97316;
                                        border-radius:999px;
                                        padding:12px 28px;
                                    ">
                                    <a href="{wazuh_url}"
                                       style="
                                           display:block;
                                           color:#ffffff;
                                           text-decoration:none;
                                           font-size:15px;
                                           line-height:20px;
                                           font-weight:700;
                                       ">
                                        Investigar Agente en Wazuh Dashboard
                                    </a>
                                </td>
                            </tr>
                        </table>

                    </td>
                </tr>

                <!-- FOOTER -->
                <tr>
                    <td align="center"
                        style="
                            padding:16px 20px 18px;
                            background-color:#2d3a4e;
                            border-top:1px solid #42516a;
                            border-radius:0 0 20px 20px;
                        ">

                        <div style="
                            color:#cbd5e1;
                            font-size:12px;
                            line-height:18px;
                        ">
                            Mensaje automatizado de
                            <strong>OrangeBox SOC &amp; CyberSecurity</strong>
                        </div>

                        <div style="
                            margin-top:2px;
                            color:#cbd5e1;
                            font-size:12px;
                            line-height:18px;
                        ">
                            Por favor, no responda a este correo de alerta.
                        </div>

                        <div style="
                            margin-top:7px;
                            color:#94a3b8;
                            font-size:11px;
                            line-height:16px;
                        ">
                            Alertas procesadas por Wazuh SIEM.
                        </div>

                    </td>
                </tr>

            </table>
        </td>
    </tr>
</table>

</body>
</html>
"""


# ============================================================
# PREPARAR CORREO
# ============================================================

msg = MIMEMultipart("alternative")

if vulnerability_event:
    subject_prefix = f"[VULNERABILIDAD {vulnerability_severity.upper()}] "
else:
    subject_prefix = (
        f"[{total_alerts} EVENTOS] "
        if total_alerts > 1
        else ""
    )

msg["Subject"] = (
    f"{subject_prefix}"
    f"Wazuh Alert Lvl {highest_level} - "
    f"{final_data['agent_name']} "
    f"({final_data['description'][:35]})"
)

msg["From"] = (
    "Wazuh SOC <wazuh@example.com>"
)

final_recipients = final_data.get("recipients", recipients)

if not isinstance(final_recipients, list) or not final_recipients:
    final_recipients = [DEFAULT_ALERT_RECIPIENT]

msg["To"] = ", ".join(final_recipients)

msg.attach(
    MIMEText(
        html_template,
        "html"
    )
)


# ============================================================
# ENTREGA LOCAL RESILIENTE MEDIANTE POSTFIX MAILDROP
# ============================================================
#
# No usamos SMTP TCP contra localhost:25.
#
# /usr/sbin/sendmail entrega el mensaje al maildrop local de
# Postfix mediante postdrop. Esto permite aceptar el mensaje
# incluso cuando el daemon Postfix esta temporalmente detenido.
#
# Si Postfix esta abajo:
#     custom integration -> maildrop -> mensaje persistente
#
# Cuando Postfix vuelve:
#     pickup -> queue -> entrega SMTP
#
# IMPORTANTE:
#     - No tocar la logica de alertas inmediatas.
#     - No tocar la deduplicacion SSH.
#     - No tocar el buffer de 10 minutos.
#
try:

    sendmail = subprocess.run(
        ["/usr/sbin/sendmail", "-t", "-i"],
        input=msg.as_string(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
    )

    if sendmail.returncode != 0:

        detail = (
            sendmail.stderr.strip()
            or sendmail.stdout.strip()
            or f"sendmail exit={sendmail.returncode}"
        )

        with open(
            "/var/ossec/logs/integrations.log",
            "a"
        ) as logf:

            logf.write(
                "ERROR entregando correo al maildrop Postfix "
                "en custom-orangebox-email: "
                f"{detail}\n"
            )

except Exception as e:

    try:

        with open(
            "/var/ossec/logs/integrations.log",
            "a"
        ) as logf:

            logf.write(
                "ERROR entregando correo al maildrop Postfix "
                "en custom-orangebox-email: "
                f"{type(e).__name__}: {e}\n"
            )

    except Exception:
        pass