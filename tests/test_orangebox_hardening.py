#!/usr/bin/env python3
"""Regresión estructural para las excepciones FIM de cron cPanel/CloudLinux."""

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULE_FILE = ROOT / "configuration" / "manager" / "etc" / "rules" / "orangebox-hardening.xml"


class CloudLinuxCronExceptionTests(unittest.TestCase):
    """Comprueba que las excepciones CRON sigan acotadas a perfil y rutas exactas."""

    @classmethod
    def setUpClass(cls):
        """Carga una sola vez las reglas FIM para reutilizarlas en todos los casos."""
        content = RULE_FILE.read_text(encoding="utf-8")
        cls.root = ET.fromstring("<rules-root>" + content + "</rules-root>")
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}

    def assert_cpanel_profile(self, rule):
        """Comprueba que la excepción esté limitada a la CDB dinámica del perfil cPanel."""
        profile = rule.find("list")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.get("field"), "hostname")
        self.assertEqual(profile.get("lookup"), "match_key_value")
        self.assertEqual(profile.get("check_value"), "^cpanel$")
        self.assertEqual((profile.text or "").strip(), "etc/lists/orangebox-cpanel-agents")

    def test_php_session_cron_deletion_is_exact_and_level_three(self):
        """20059 solo rebaja la eliminación del cron exacto de sesiones PHP."""
        rule = self.rules["20059"]
        self.assertEqual(rule.get("level"), "3")
        self.assertEqual(rule.findtext("if_sid"), "10045")
        self.assert_cpanel_profile(rule)
        field = rule.find("field")
        self.assertIsNotNone(field)
        self.assertEqual(field.get("name"), "file")
        pattern = re.compile(field.text or "")
        self.assertIsNotNone(pattern.fullmatch("/etc/cron.d/cpanel_php_sessions_cron"))
        self.assertIsNone(pattern.fullmatch("/etc/cron.d/other_php_sessions_cron"))
        self.assertIsNone(pattern.fullmatch("/etc/cron.d/custom-admin-cron"))

    def test_cloudlinux_lve_cron_modifications_are_exact_and_level_three(self):
        """20060 solo rebaja modificaciones de los tres cron identificados de LVE Manager."""
        rule = self.rules["20060"]
        self.assertEqual(rule.get("level"), "3")
        self.assertEqual(rule.findtext("if_sid"), "10035")
        self.assert_cpanel_profile(rule)
        field = rule.find("field")
        self.assertIsNotNone(field)
        self.assertEqual(field.get("name"), "file")
        pattern = re.compile(field.text or "")
        allowed = (
            "/etc/cron.d/lvemanager-cron",
            "/etc/cron.d/lvemanager-selector",
            "/etc/cron.d/cloudlinux-cron",
        )
        for path in allowed:
            with self.subTest(path=path):
                self.assertIsNotNone(pattern.fullmatch(path))
        self.assertIsNone(pattern.fullmatch("/etc/cron.d/unknown-cloudlinux-task"))

    def test_detection_rules_remain_broad_for_every_other_cron_path(self):
        """10035/10045 mantienen cobertura general fuera de las dos excepciones."""
        modified = self.rules["10035"]
        deleted = self.rules["10045"]
        self.assertEqual(modified.findtext("if_sid"), "550")
        self.assertEqual(deleted.findtext("if_sid"), "553")
        modified_file = next(field for field in modified.findall("field") if field.get("name") == "file")
        deleted_file = next(field for field in deleted.findall("field") if field.get("name") == "file")
        self.assertRegex(modified_file.text or "", r"/etc/cron")
        self.assertRegex(deleted_file.text or "", r"/etc/cron")
        self.assertEqual(modified.get("level"), "13")
        self.assertEqual(deleted.get("level"), "15")

    def test_exception_rule_ids_are_unique(self):
        """Evita que los SID de excepción entren en colisión dentro del ruleset."""
        for rule_id in ("20059", "20060"):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(
                    sum(1 for rule in self.root.iter("rule") if rule.get("id") == rule_id),
                    1,
                )




class DNSOnlySocialBeeXoviExceptionTests(unittest.TestCase):
    """La limpieza conocida de plugins DNSOnly no debe alertar por el sufijo FIM observado."""

    @classmethod
    def setUpClass(cls):
        cls.root = ET.fromstring(
            "<rules-root>" + RULE_FILE.read_text(encoding="utf-8") + "</rules-root>"
        )
        cls.rule = next(
            rule for rule in cls.root.iter("rule") if rule.get("id") == "20057"
        )
        cls.updater = (
            ROOT / "configuration" / "manager" / "bin" / "update-orangebox-dns-agents.sh"
        ).read_text(encoding="utf-8")
        cls.manager = (
            ROOT / "configuration" / "manager" / "etc" / "ossec.conf"
        ).read_text(encoding="utf-8")

    def test_20057_accepts_only_the_four_plugin_units_with_optional_hex_suffix(self):
        self.assertEqual(self.rule.get("level"), "0")
        self.assertEqual(self.rule.findtext("if_sid"), "10044")
        field = next(
            node for node in self.rule.findall("field") if node.get("name") == "file"
        )
        pattern = re.compile(field.text or "")
        paths = (
            "/etc/systemd/system/initialize_socialbee_plugin.service",
            "/etc/systemd/system/initialize_socialbee_plugin.timer",
            "/etc/systemd/system/initialize_xovi_plugin.service",
            "/etc/systemd/system/initialize_xovi_plugin.timer",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertIsNotNone(pattern.fullmatch(path))
                self.assertIsNotNone(pattern.fullmatch(path + ";6aebbc7e"))
        rejected = (
            "/etc/systemd/system/initialize_socialbee_plugin.service;xyz",
            "/etc/systemd/system/initialize_socialbee_plugin.service;6aebbc7",
            "/etc/systemd/system/initialize_socialbee_plugin.service;6aebbc7e.extra",
            "/etc/systemd/system/initialize_other_plugin.service;6aebbc7e",
            "/etc/systemd/system/sshd.service;6aebbc7e",
            "/usr/lib/systemd/system/initialize_socialbee_plugin.service;6aebbc7e",
        )
        for path in rejected:
            with self.subTest(path=path):
                self.assertIsNone(pattern.fullmatch(path))

    def test_20057_keeps_dns_group_cdb_scope_and_manager_declaration(self):
        profile = self.rule.find("list")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.get("field"), "hostname")
        self.assertEqual(profile.get("lookup"), "match_key_value")
        self.assertEqual(profile.get("check_value"), "^dns$")
        self.assertEqual(
            (profile.text or "").strip(), "etc/lists/orangebox-dns-agents"
        )
        self.assertIn(
            "<list>etc/lists/orangebox-dns-agents</list>", self.manager
        )

    def test_dns_updater_queries_lowercase_group_and_generates_lowercase_profile(self):
        self.assertIn('GROUP="dns"', self.updater)
        self.assertIn("printf '%s:dns\\n' \"$hostname\"", self.updater)
        self.assertNotIn('GROUP="DNS"', self.updater)
        self.assertNotIn("printf '%s:DNS\\n'", self.updater)

    def test_20057_rule_id_is_unique(self):
        self.assertEqual(
            sum(
                1 for rule in self.root.iter("rule")
                if rule.get("id") == "20057"
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
