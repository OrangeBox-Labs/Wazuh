#!/usr/bin/env python3
"""Read-only Active Response policy matching for the OrangeBox email integration.

Wazuh 4.x treats rules_id, rules_group and level inside one active-response
block as alternative selectors (OR). This module mirrors that behavior for
firewall-drop so email text reflects the effective manager configuration.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any


# Normaliza los grupos de la alerta para compararlos sin distinguir mayúsculas.
def _normalise_groups(groups: Any) -> list[str]:
    """Normaliza los grupos recibidos desde la alerta para comparar selectores sin distinguir mayúsculas."""
    if isinstance(groups, str):
        groups = [groups]
    if not isinstance(groups, list):
        return []
    return [str(group).strip().upper() for group in groups if str(group).strip()]


# Evalúa un selector rules_group respetando alternativas y coincidencia exacta.
def _matches_group_selector(selector: str, alert_groups: list[str]) -> bool:
    """Match Wazuh rules_group semantics, including exact trailing-comma mode.

    Multiple alternatives are separated by '|'. A selector ending in ','
    requires an exact group match; without the comma it matches substrings.
    """
    # Cada alternativa separada por | se compara de forma independiente.
    for raw_part in selector.split("|"):
        part = raw_part.strip()
        if not part:
            continue
        exact = part.endswith(",")
        token = part.rstrip(",").strip().upper()
        if not token:
            continue
        if exact:
            if token in alert_groups:
                return True
        elif any(token in group for group in alert_groups):
            return True
    return False


# Resuelve qué bloques firewall-drop coinciden; no ejecuta ni altera Active Response.
def firewall_drop_policy_for_alert(
    alert_rule_id: str,
    alert_rule_level: int,
    alert_rule_groups: Any,
    config_path: str = "/var/ossec/etc/ossec.conf",
) -> dict[str, Any]:
    """Return the firewall-drop policy matching an alert.

    Result status is one of:
      - configured: one or more enabled firewall-drop blocks match;
      - not_configured: valid configuration, no block matches;
      - unknown: the configuration cannot be read or parsed safely.

    A configured response is not proof of execution. The caller must describe
    execution as pending until a corresponding Active Response event is seen.
    """
    try:
        with open(config_path, "r", encoding="utf-8") as stream:
            config_text = stream.read()
    except OSError as exc:
        return {"status": "unknown", "error": f"No se pudo leer {config_path}: {exc}", "matches": []}

    # Permit concatenated ossec_config fragments while keeping normal XML parsing.
    config_text = re.sub(r"<\?xml[^?]*\?>", "", config_text, flags=re.IGNORECASE)
    wrapped = "<orangebox-config-root>\n" + config_text + "\n</orangebox-config-root>"

    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        return {"status": "unknown", "error": f"XML no válido en {config_path}: {exc}", "matches": []}

    rule_id = str(alert_rule_id or "").strip()
    try:
        rule_level = int(alert_rule_level or 0)
    except (TypeError, ValueError):
        rule_level = 0
    groups = _normalise_groups(alert_rule_groups)
    matches: list[dict[str, Any]] = []

    # Recorre todos los bloques y descarta los deshabilitados o de otro comando.
    for response in root.iter("active-response"):
        disabled = (response.findtext("disabled") or "no").strip().lower()
        command = (response.findtext("command") or "").strip()
        if disabled == "yes" or command != "firewall-drop":
            continue

        matched_by: list[str] = []

        # Extrae los SID del bloque; rules_id, rules_group y level son selectores OR.
        configured_ids = {
            item.strip()
            for item in (response.findtext("rules_id") or "").split(",")
            if item.strip()
        }
        if rule_id and rule_id in configured_ids:
            matched_by.append(f"rules_id:{rule_id}")

        group_selector = (response.findtext("rules_group") or "").strip()
        if group_selector and _matches_group_selector(group_selector, groups):
            matched_by.append(f"rules_group:{group_selector}")

        level_text = (response.findtext("level") or "").strip()
        # El umbral de nivel se evalúa como otra alternativa, no como filtro acumulativo.
        if level_text:
            try:
                minimum_level = int(level_text)
            except ValueError:
                return {
                    "status": "unknown",
                    "error": f"Selector <level> inválido en Active Response: {level_text}",
                    "matches": [],
                }
            if rule_level >= minimum_level:
                matched_by.append(f"level:{minimum_level}")

        # Wazuh selector fields are OR alternatives, not cumulative filters.
        if not matched_by:
            continue

        timeout_text = (response.findtext("timeout") or "").strip()
        timeout_seconds: int | None
        if timeout_text:
            try:
                timeout_seconds = int(timeout_text)
                if timeout_seconds < 0:
                    raise ValueError("timeout negativo")
            except ValueError:
                return {
                    "status": "unknown",
                    "error": f"Timeout inválido para firewall-drop: {timeout_text}",
                    "matches": [],
                }
        else:
            timeout_seconds = None

        matches.append(
            {
                "command": command,
                "location": (response.findtext("location") or "no especificado").strip(),
                "timeout_seconds": timeout_seconds,
                "matched_by": matched_by,
            }
        )

    if not matches:
        return {"status": "not_configured", "error": None, "matches": []}

    return {
        "status": "configured",
        "error": None,
        "matches": matches,
        # There should normally be one match. Preserve all matched blocks;
        # the longest explicit timeout is the most conservative summary.
        "timeout_seconds": max(
            (item["timeout_seconds"] for item in matches if item["timeout_seconds"] is not None),
            default=None,
        ),
        "location": ", ".join(dict.fromkeys(item["location"] for item in matches)),
        "matched_by": sorted({selector for item in matches for selector in item["matched_by"]}),
    }
