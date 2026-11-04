#!/usr/bin/env python3
"""Regresión estructural para excluir temporales internos Zimbra/Carbonio del FIM -> YARA."""

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULE_FILE = ROOT / "configuration/manager/etc/rules/orangebox-yara.xml"
PROFILE_FILE = ROOT / "configuration/manager/etc/shared/zimbra/agent.conf"
MANAGER_FILE = ROOT / "configuration/manager/etc/ossec.conf"
RULE_DOC = ROOT / "configuration/manager/etc/rules/orangebox-yara.md"


class OrangeBoxYaraScopeTests(unittest.TestCase):
    """Protege el alcance de YARA y evita reintroducir ruido de temporales de correo."""

    @classmethod
    def setUpClass(cls):
        """Carga las reglas, el perfil compartido y la configuración del Manager."""
        cls.rules_root = ET.fromstring(
            "<rules-root>" + RULE_FILE.read_text(encoding="utf-8") + "</rules-root>"
        )
        cls.rules = {rule.get("id"): rule for rule in cls.rules_root.iter("rule")}
        cls.profile_root = ET.parse(PROFILE_FILE).getroot()
        cls.manager_root = ET.parse(MANAGER_FILE).getroot()

    def test_yara_candidate_rules_are_limited_to_general_system_temp_paths(self):
        """10420/10421 solo disparan por archivos nuevos/modificados en temporales generales."""
        expected = r"^/(?:tmp|var/tmp|dev/shm)/.+$"
        for rule_id, parent_sid in (("10420", "554"), ("10421", "550")):
            with self.subTest(rule_id=rule_id):
                rule = self.rules[rule_id]
                self.assertEqual(rule.findtext("if_sid"), parent_sid)
                file_field = next(
                    node for node in rule.findall("field") if node.get("name") == "file"
                )
                self.assertEqual((file_field.text or "").strip(), expected)
                pattern = re.compile(expected)
                for allowed in ("/tmp/sample.bin", "/var/tmp/sample.bin", "/dev/shm/sample.bin"):
                    self.assertIsNotNone(pattern.fullmatch(allowed))
                for excluded in (
                    "/opt/zimbra/data/tmp/uncompressed/data/blob",
                    "/opt/zextras/data/tmp/uncompressed/data/blob",
                ):
                    self.assertIsNone(pattern.fullmatch(excluded))

    def test_zimbra_profile_does_not_monitor_product_temp_trees(self):
        """El perfil mantiene FIM general, pero excluye data/tmp de ambos productos."""
        syscheck = self.profile_root.find("syscheck")
        self.assertIsNotNone(syscheck)
        watched = [
            (node.text or "").strip()
            for node in syscheck.findall("directories")
        ]
        watched_text = "\n".join(watched)
        self.assertNotRegex(watched_text, r"/opt/(?:zimbra|zextras)/data/tmp")
        for path in ("/tmp", "/var/tmp", "/dev/shm"):
            self.assertTrue(any(path in value for value in watched))

    def test_manager_keeps_yara_active_response_for_remaining_scope(self):
        """El Active Response continúa conectado a 10420/10421 para el resto del sistema."""
        matches = []
        for node in self.manager_root.findall(".//active-response"):
            command = (node.findtext("command") or "").strip()
            rule_ids = (node.findtext("rules_id") or "").replace(" ", "").split(",")
            if command == "orangebox-yara" and {"10420", "10421"}.issubset(set(rule_ids)):
                matches.append(node)
        self.assertEqual(len(matches), 1)
        self.assertEqual((matches[0].findtext("location") or "").strip(), "local")
        self.assertEqual((matches[0].findtext("disabled") or "").strip(), "no")

    def test_yara_result_rules_remain_available(self):
        """La exclusión de temporales de correo no elimina el motor ni sus reglas de resultado."""
        for rule_id in ("10500", "10501", "10502", "10503", "10504", "10505", "10510", "10511"):
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule_id, self.rules)

    def test_documentation_states_included_and_excluded_paths(self):
        """La documentación describe el alcance desplegado y las rutas expresamente excluidas."""
        doc = RULE_DOC.read_text(encoding="utf-8")
        for included in ("/tmp", "/var/tmp", "/dev/shm"):
            self.assertIn(included, doc)
        for excluded in ("/opt/zimbra/data/tmp", "/opt/zextras/data/tmp"):
            self.assertIn(excluded, doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
