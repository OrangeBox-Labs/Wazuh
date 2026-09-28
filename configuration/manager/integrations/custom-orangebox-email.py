#!/usr/bin/env python3

import sys
import json
import os
import time
import fcntl
import html
import hashlib
import subprocess

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


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


# ============================================================
# ALERTAS POR GRUPO / CLIENTE
# ============================================================
#
# soporte@example.com SIEMPRE recibe las alertas.
# Estas opciones solamente controlan destinatarios adicionales.
#
# La comparacion de grupos es CASE-INSENSITIVE:
#
# Para agregar un cliente nuevo solamente hay que agregar una entrada
# aqui. No es necesario modificar ninguna otra parte del script.
#
# 1 = enviar al responsable del grupo
# 0 = NO enviar al responsable del grupo.
# ============================================================

CLIENT_GROUPS = {
    "CLIENTE_01": {
        "enabled": 0,
        "emails": [
            "security@example.com",
        ],
    },

    "CLIENTE_02": {
        "enabled": 0,
        "emails": [
            "security@example.com",
        ],
    },

    "CLIENTE_03": {
        "enabled": 0,
        "emails": [
            "security@example.com",
        ],
    },

    "CLIENTE_04": {
        "enabled": 1,
        "emails": [
            "security@example.com",
        ],
    },

    "CLIENTE_05": {
        "enabled": 0,
        "emails": [
            "security@example.com",
        ],
    },

    "CLIENTE_06": {
        "enabled": 0,
        "emails": [
            "rfarias@example.com",
        ],
    },

    "ORANGEBOX": {
        "enabled": 0,
        "emails": [],
    },
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
#   FIREWALL_DROP_RULES se evalua antes que esta politica.
#   Una alerta con firewall-drop sigue sin generar correo individual.
#
IMMEDIATE_RULES = {
    # Reglas historicas / nativas que no podemos marcar todas desde
    # CLIENTE (por ejemplo 5715).
    "5715",

    # Compatibilidad con reglas CLIENTE existentes.
    "10001",
    "10004",
    "10005",
    "10008",
    "10009",
}

IMMEDIATE_RULE_GROUP = "ORANGEBOX_IMMEDIATE"


# ============================================================
# REGLAS CON FIREWALL-DROP
# ============================================================
#
# Estas reglas siguen generando la alerta Wazuh y ejecutando
# Active Response normalmente.
#
# Solamente se evita el correo individual de la integracion.
# El reporte/dashboard PDF las recoge desde alerts.json y,
# para confirmar el bloqueo real, desde la regla 651.
#
FIREWALL_DROP_RULES = {
    "5720",   # SSH brute force -> firewall-drop
    "10006",  # SSH brute force seguido de login exitoso -> firewall-drop
    "10025",  # Web brute force -> firewall-drop
    "10026",  # Descubrimiento de archivos sensibles -> firewall-drop
    "10456",  # Port scan publico -> firewall-drop
    "10457",  # SYN flood publico -> firewall-drop
    "10700",  # Mail brute force Postfix -> firewall-drop
    "10701",  # Mail brute force Exim/Dovecot -> firewall-drop
}


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
    #   has the group: '[u'CLIENTE', u'default']'
    # y versiones:
    #   belongs to groups: default, CLIENTE
    import re

    match = re.search(r"\[([^\]]*)\]", output)

    if match:
        raw_groups = re.findall(
            r'''(?:u)?['"]([^'"]+)['"]''',
            match.group(1)
        )
        return normalize_group_list(raw_groups)

    match = re.search(
        r"belongs to groups?:\s*(.+)$",
        output,
        flags=re.IGNORECASE | re.MULTILINE,
    )

    if match:
        return normalize_group_list(
            [group.strip() for group in match.group(1).split(",")]
        )

    return []


def extract_agent_groups(alert_json):
    """
    Obtiene los grupos del agente desde el evento Wazuh.

    Primero usa agent.groups / agent.group si vienen en el alerta.
    Si Wazuh no los incluye, consulta la membresia real del agente
    en el manager mediante agent_groups.

    Nunca usa rule.groups porque esos son grupos de la regla.
    """
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
    Soporte CLIENTE siempre recibe el correo.
    Los destinatarios de cliente dependen del grupo y su switch.
    """
    recipients = []
    seen = set()

    def add_recipient(address):
        address = str(address or "").strip()

        if not address:
            return

        key = address.lower()

        if key not in seen:
            seen.add(key)
            recipients.append(address)

    # Soporte CLIENTE es SIEMPRE destinatario.
    add_recipient(DEFAULT_ALERT_RECIPIENT)

    # Conservamos tambien el recipient entregado por Wazuh si difiere,
    # para no romper una configuracion externa existente.
    add_recipient(default_recipient)

    for group in agent_groups:
        config = CLIENT_GROUPS.get(normalize_group_name(group))

        if not config or not config.get("enabled"):
            continue

        for address in config.get("emails", []):
            add_recipient(address)

    return recipients


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

    Politica CLIENTE:
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


# ============================================================
# DATOS PRINCIPALES
# ============================================================

rule_id = str(
    alert_json.get("rule", {}).get("id", "N/A")
)

rule_level = safe_int(
    alert_json.get("rule", {}).get("level", 0)
)

description = alert_json.get(
    "rule", {}
).get(
    "description",
    "Sin descripcion"
)

agent_id = str(
    alert_json.get("agent", {}).get("id", "000")
)

agent_name = alert_json.get(
    "agent", {}
).get(
    "name",
    "Wazuh Manager"
)

agent_ip = alert_json.get(
    "agent", {}
).get(
    "ip",
    "Local"
)

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

if not full_log or full_log == "No log fragment attached.":
    vulnerability = alert_json.get("data", {}).get("vulnerability", {})
    if isinstance(vulnerability, dict) and vulnerability:
        full_log = json.dumps(
            vulnerability,
            ensure_ascii=False,
            indent=2
        )

rule_groups = alert_json.get("rule", {}).get("groups", [])
if not isinstance(rule_groups, list):
    rule_groups = []

groups = ", ".join(
    str(group)
    for group in rule_groups
)

# rule.groups pertenece a la REGLA. El routing usa grupos del AGENTE.
agent_groups = extract_agent_groups(alert_json)
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
if rule_id in FIREWALL_DROP_RULES or rule_id in NO_EMAIL_RULES:
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
#   - 10009 = otros escalamientos SUDO definidos por CLIENTE
#   - 5715 / 10001 = SSH exitoso (con su deduplicacion bloqueada arriba)
#
# No mover estas reglas al buffer ni cambiar su tratamiento sin
# autorizacion explicita y pruebas de regresion.
#
# !!! FIN CONTRATO LOCKED !!!
#
normalized_rule_groups = {
    normalize_group_name(group)
    for group in rule_groups
}

send_immediately = (
    rule_id in IMMEDIATE_RULES
    or IMMEDIATE_RULE_GROUP in normalized_rule_groups
)


# ------------------------------------------------------------
# DEDUPLICACION PARA SSH
# ------------------------------------------------------------
#
# 5715 = regla nativa de SSH exitoso.
# 10001 = regla CLIENTE hija de 5715.
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

if highest_level >= 12:

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

    # --------------------------------------------------------
    # Algunos eventos FIM pueden traer informacion de hashes
    # aunque no tengan diff de contenido.
    # --------------------------------------------------------

    hash_rows = ""

    for hash_name in (
        "md5_after",
        "sha1_after",
        "sha256_after"
    ):

        if hash_name in syscheck:

            hash_rows += f"""
            <tr>
                <td style="width: 35%; padding: 8px 16px;
                    border-bottom: 1px solid #e2e8f0;
                    font-size: 12px; font-weight: 700;
                    color: #475569;">
                    {esc(hash_name)}
                </td>
                <td style="width: 65%; padding: 8px 16px;
                    border-bottom: 1px solid #e2e8f0;
                    font-size: 12px; color: #0f172a;
                    font-family: monospace;
                    word-break: break-all;">
                    {esc(syscheck.get(hash_name))}
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
            for x in changed_fields
        )

    else:

        changed_text = str(
            changed_fields or ""
        )

    if changed_text:

        changed_html = f"""
        <tr>
            <td style="width: 35%; padding: 8px 16px;
                border-bottom: 1px solid #e2e8f0;
                font-size: 12px; font-weight: 700;
                color: #475569;">
                Atributos modificados
            </td>
            <td style="width: 65%; padding: 8px 16px;
                border-bottom: 1px solid #e2e8f0;
                font-size: 12px; color: #0f172a;
                font-family: monospace;">
                {esc(changed_text)}
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

    <tr>
        <td style="width: 35%;
            padding: 10px 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
            font-weight: 700;
            color: #475569;">
            Ruta del Archivo
        </td>

        <td style="width: 65%;
            padding: 10px 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
            color: #0f172a;
            font-family: monospace;
            font-weight: bold;">
            {esc(file_path)}
        </td>
    </tr>

    <tr>
        <td style="width: 35%;
            padding: 10px 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
            font-weight: 700;
            color: #475569;">
            Propietario / Tamaño
        </td>

        <td style="width: 65%;
            padding: 10px 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
            color: #0f172a;">
            {esc(file_uname)}
            ({esc(file_size)} bytes)
        </td>
    </tr>

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
            font-size: 13px;
            line-height: 1.4;
        ">{esc(ev.get('full_log', ''))}</pre>

    </div>
    """


# ============================================================
# URL DINAMICA WAZUH
# ============================================================

wazuh_url = (
    "https://wazuh.example.com/app/threat-hunting"
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


# ============================================================
# PLANTILLA HTML CORPORATIVA ORANGEBOX
# ============================================================

html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="x-apple-disable-message-reformatting">
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
            <table role="presentation" width="720" cellpadding="0" cellspacing="0" border="0"
                   align="center"
                   style="
                       width:100%;
                       max-width:720px;
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

                        <img src="https://www.example.com/obox/img/logo-dark.png"
                             alt="CLIENTE"
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
                            CLIENTE
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
                    <td style="padding:0 20px 4px;">

                        <!-- TABLA PRINCIPAL -->
                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                               style="
                                   width:100%;
                                   background-color:#eef2ff;
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
                            <tr>
                                <td width="35%"
                                    style="
                                        width:35%;
                                        padding:12px 16px;
                                        border-bottom:1px solid #cbd5e1;
                                        color:#334155;
                                        font-size:13px;
                                        line-height:18px;
                                        font-weight:700;
                                    ">
                                    Agente afectado
                                </td>

                                <td width="65%"
                                    style="
                                        width:65%;
                                        padding:12px 16px;
                                        border-bottom:1px solid #cbd5e1;
                                        color:#0f172a;
                                        font-size:14px;
                                        line-height:20px;
                                        font-weight:700;
                                        word-break:break-word;
                                        overflow-wrap:anywhere;
                                    ">
                                    {esc(final_data['agent_name'])}
                                    ({esc(final_data['agent_ip'])})
                                </td>
                            </tr>

                            <tr>
                                <td width="35%"
                                    style="
                                        width:35%;
                                        padding:12px 16px;
                                        border-bottom:1px solid #cbd5e1;
                                        color:#334155;
                                        font-size:13px;
                                        line-height:18px;
                                        font-weight:700;
                                    ">
                                    Origen / Ubicacion
                                </td>

                                <td width="65%"
                                    style="
                                        width:65%;
                                        padding:12px 16px;
                                        border-bottom:1px solid #cbd5e1;
                                        color:#0f172a;
                                        font-size:14px;
                                        line-height:20px;
                                        font-family:monospace;
                                        word-break:break-all;
                                    ">
                                    {esc(final_data['location'])}
                                </td>
                            </tr>

                            <tr>
                                <td width="35%"
                                    style="
                                        width:35%;
                                        padding:12px 16px;
                                        border-bottom:1px solid #cbd5e1;
                                        color:#334155;
                                        font-size:13px;
                                        line-height:18px;
                                        font-weight:700;
                                        vertical-align:top;
                                    ">
                                    Categoria / Grupo
                                </td>

                                <td width="65%"
                                    style="
                                        width:65%;
                                        padding:12px 16px;
                                        border-bottom:1px solid #cbd5e1;
                                        color:#0f172a;
                                        font-size:13px;
                                        line-height:20px;
                                        word-break:break-word;
                                        overflow-wrap:anywhere;
                                    ">
                                    {esc(final_data['groups'])}
                                </td>
                            </tr>

                            <tr>
                                <td width="35%"
                                    style="
                                        width:35%;
                                        padding:12px 16px;
                                        color:#334155;
                                        font-size:13px;
                                        line-height:18px;
                                        font-weight:700;
                                    ">
                                    Estado del Evento
                                </td>

                                <td width="65%"
                                    style="
                                        width:65%;
                                        padding:12px 16px;
                                        color:#0f172a;
                                        font-size:14px;
                                        line-height:20px;
                                        font-weight:700;
                                    ">
                                    {texto_contador}
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
                            <strong>CLIENTE SOC &amp; CyberSecurity</strong>
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