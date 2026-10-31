#!/usr/bin/env python3
"""Safely patch only the OrangeBox IOC firewall-drop blocks in a live ossec.conf."""

from __future__ import annotations

import argparse
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


OLD_IDS = "10460,10461,10462,10463"
SEVEN_DAY_IDS = "10460,10461,10462,10463,99903,99904,99905,99907,99908,99911,99912,99913,99914"
THIRTY_DAY_IDS = "99906,10053"
SEVEN_DAYS = "604800"
THIRTY_DAYS = "2592000"

REPLACEMENT = """<!-- Source-IP IOC detections with a decoded srcip: immediate 7-day containment.
       Includes native Wazuh SSH/web/Apache/Dovecot/SQL rules and
       OrangeBox IOC correlation rules 10460-10463. -->
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>10460,10461,10462,10463,99903,99904,99905,99907,99908,99911,99912,99913,99914</rules_id>
    <timeout>604800</timeout>
  </active-response>

  <!-- High-confidence web exploitation from a known source IOC:
       native HTTP-200 rule 99906 and PEAR/PHP2Shell behavioral rule 10053.
       A 200 response is not proof of code execution. -->
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>99906,10053</rules_id>
    <timeout>2592000</timeout>
  </active-response>"""


# Extrae los SIDs definidos en rules_id y normaliza espacios.
def _rules_ids(block: ET.Element) -> set[str]:
    """Extrae y normaliza los SID declarados en un bloque Active Response."""
    raw = (block.findtext("rules_id") or "").strip()
    return {item.strip() for item in raw.split(",") if item.strip()}


# Devuelve solo bloques firewall-drop habilitados; ignora otras respuestas.
def _firewall_blocks(root: ET.Element) -> list[ET.Element]:
    """Devuelve los bloques firewall-drop habilitados y descarta otras respuestas."""
    return [
        # Filtra la configuración y conserva únicamente firewall-drop habilitados.
        block
        for block in root.iter("active-response")
        if (block.findtext("command") or "").strip() == "firewall-drop"
        and (block.findtext("disabled") or "no").strip().lower() != "yes"
    ]


# Localiza el bloque legacy exacto que esta herramienta tiene permiso de reemplazar.
def _find_target_block(root: ET.Element) -> list[ET.Element]:
    """Localiza el único bloque legacy que esta herramienta está autorizada a reemplazar."""
    return [
        block for block in _firewall_blocks(root)
        if _rules_ids(block) == set(OLD_IDS.split(","))
    ]


# Detecta el estado final esperado para que una segunda ejecución no cambie nada.
def _already_applied(root: ET.Element) -> bool:
    """Comprueba si los bloques IOC ya tienen los SID y timeouts esperados."""
    seven_ids = set(SEVEN_DAY_IDS.split(","))
    thirty_ids = set(THIRTY_DAY_IDS.split(","))
    relevant = []
    seven = []
    thirty = []

    # Revisa cada bloque firewall-drop para separar el estado actual del estado deseado.
    for block in _firewall_blocks(root):
        ids = _rules_ids(block)
        timeout = (block.findtext("timeout") or "").strip()
        if ids & (seven_ids | thirty_ids):
            relevant.append(block)
        if ids == seven_ids and timeout == SEVEN_DAYS:
            seven.append(block)
        if ids == thirty_ids and timeout == THIRTY_DAYS:
            thirty.append(block)

    return len(relevant) == 2 and len(seven) == 1 and len(thirty) == 1


def _migrate_current_policy(original: str, root: ET.Element) -> str | None:
    """Upgrade the known current 99906-only 30-day block without touching other ARs."""
    seven_ids = set(SEVEN_DAY_IDS.split(","))
    new_thirty_ids = set(THIRTY_DAY_IDS.split(","))
    legacy_thirty_ids = {"99906"}

    blocks = _firewall_blocks(root)
    relevant = [
        block for block in blocks
        if _rules_ids(block) & (seven_ids | new_thirty_ids)
    ]
    seven = [
        block for block in blocks
        if _rules_ids(block) == seven_ids
        and (block.findtext("timeout") or "").strip() == SEVEN_DAYS
    ]
    legacy_thirty = [
        block for block in blocks
        if _rules_ids(block) == legacy_thirty_ids
        and (block.findtext("timeout") or "").strip() == THIRTY_DAYS
    ]

    if len(relevant) != 2 or len(seven) != 1 or len(legacy_thirty) != 1:
        return None

    pattern = re.compile(
        r"(<active-response>(?:(?!</active-response>).)*?<rules_id>\s*)"
        r"99906"
        r"(\s*</rules_id>(?:(?!</active-response>).)*?</active-response>)",
        flags=re.DOTALL,
    )
    updated, count = pattern.subn(r"\g<1>99906,10053\g<2>", original, count=1)
    if count != 1:
        raise RuntimeError("No se pudo ampliar de forma inequívoca el bloque 30-day de 99906.")
    return updated


# Escribe un temporal en el mismo filesystem y reemplaza ossec.conf de forma atómica.
def _write_atomic(path: Path, updated: str) -> None:
    """Escribe ossec.conf actualizado en un temporal y reemplaza el original preservando permisos."""
    stat = path.stat()
    fd, temp_name = tempfile.mkstemp(prefix=".ossec.conf.orangebox.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, stat.st_mode & 0o7777)
        try:
            os.chown(temp_name, stat.st_uid, stat.st_gid)
        except PermissionError:
            pass
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def patch_config(config_path: str | os.PathLike[str]) -> bool:
    """Patch the known IOC policy; preserve unrelated blocks and be idempotent."""
    path = Path(config_path)
    original = path.read_text(encoding="utf-8")
    config_text = re.sub(r"<\?xml[^?]*\?>", "", original, flags=re.IGNORECASE)
    wrapped_config = "<orangebox-config-root>\n" + config_text + "\n</orangebox-config-root>"
    try:
        root = ET.fromstring(wrapped_config)
    except ET.ParseError as exc:
        raise RuntimeError(f"ossec.conf no es XML válido: {exc}") from exc

    if _already_applied(root):
        return False

    updated = _migrate_current_policy(original, root)

    if updated is None:
        targets = _find_target_block(root)
        if len(targets) != 1:
            raise RuntimeError(
                f"Se esperaba el bloque IOC vigente o un único bloque legacy firewall-drop con rules_id={OLD_IDS}; "
                f"encontrados={len(targets)}. No se modificó ossec.conf."
            )

        target_ids = set(SEVEN_DAY_IDS.split(","))
        protected_ids = target_ids | {"99906", "10053"}
        # Evita que los SIDs IOC queden asignados dos veces a bloques distintos.
        for block in _firewall_blocks(root):
            if block in targets:
                continue
            if _rules_ids(block) & protected_ids:
                raise RuntimeError(
                    "Uno o más SIDs IOC ya aparecen en otro bloque firewall-drop; revisar manualmente."
                )

        pattern = re.compile(
            r"<active-response>(?:(?!</active-response>).)*?<rules_id>\s*"
            + re.escape(OLD_IDS)
            + r"\s*</rules_id>(?:(?!</active-response>).)*?</active-response>",
            flags=re.DOTALL,
        )
        updated, count = pattern.subn(REPLACEMENT, original, count=1)
        if count != 1:
            raise RuntimeError("No se pudo reemplazar el bloque IOC legacy de forma inequívoca.")

        updated = updated.replace(
            "Known malicious source IP: severe alert + 720-hour / 30-day firewall block.",
            "Known malicious source IP: immediate 168-hour / 7-day firewall block.",
        )

    updated_text = re.sub(r"<\?xml[^?]*\?>", "", updated, flags=re.IGNORECASE)
    wrapped_updated = "<orangebox-config-root>\n" + updated_text + "\n</orangebox-config-root>"
    try:
        ET.fromstring(wrapped_updated)
    except ET.ParseError as exc:
        raise RuntimeError(f"El ossec.conf resultante no es XML válido: {exc}") from exc

    _write_atomic(path, updated)
    return True


# Procesa argumentos, invoca el parche y traduce el resultado a un código de salida.
def main() -> int:
    """Procesa argumentos, aplica el parche seguro y devuelve un código de salida para automatización."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/var/ossec/etc/ossec.conf")
    args = parser.parse_args()
    try:
        changed = patch_config(args.config)
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}")
        return 1
    print("Active Response IOC actualizado." if changed else "Active Response IOC ya estaba actualizado.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
