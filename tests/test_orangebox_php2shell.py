#!/usr/bin/env python3
import re
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RULE_FILE = REPO_ROOT / "configuration" / "manager" / "etc" / "rules" / "orangebox-php2shell.xml"
INCIDENT_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "web-ioc-99906.log"
MANAGER_CONF = REPO_ROOT / "configuration" / "manager" / "etc" / "ossec.conf"


class PHP2ShellRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Carga las reglas y prepara los patrones que se reutilizan en todos los casos."""
        content = RULE_FILE.read_text(encoding="utf-8")
        cls.root = ET.fromstring("<rule-validation-root>" + content + "</rule-validation-root>")
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}
        cls.rule_10050 = cls.rules["10050"]
        match = cls.rule_10050.find("match")
        if match is None or match.get("type") != "pcre2" or not (match.text or "").strip():
            raise AssertionError("Rule 10050 must have a non-empty PCRE2 <match>.")
        cls.pattern_text = match.text.strip()
        cls.pattern = re.compile(cls.pattern_text)

    def test_rule_10050_uses_valid_noalert_attribute_and_is_child_of_web_accesslog(self):
        """Valida la estructura de la regla base PHP2Shell y su relación con el decoder web."""
        self.assertEqual(self.rule_10050.findtext("if_sid"), "31100")
        self.assertEqual(self.rule_10050.get("level"), "8")
        self.assertEqual(self.rule_10050.get("noalert"), "1")
        self.assertIsNone(self.rule_10050.find("noalert"))
        self.assertIsNone(self.rule_10050.find("options"))

    def test_real_incident_pear_config_create_tmp_write_matches(self):
        """Comprueba que la secuencia PEAR config-create hacia un temporal coincida con la regla."""
        lines = [line for line in INCIDENT_FIXTURE.read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual(len(lines), 2)
        self.assertRegex(lines[0], re.compile(r"(?i)pearcmd"))
        self.assertRegex(lines[0], re.compile(r"(?i)config-create"))
        self.assertRegex(lines[0], re.compile(r"(?i)/tmp/"))
        self.assertIsNotNone(self.pattern.search(lines[0]))

    def test_second_incident_lfi_request_does_not_match_php2shell_rule_alone(self):
        """Evita que una solicitud LFI aislada se confunda con PHP2Shell."""
        lines = [line for line in INCIDENT_FIXTURE.read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual(len(lines), 2)
        self.assertIn("/tmp/index1", lines[1])
        self.assertIsNone(self.pattern.search(lines[1]))

    def test_known_php2shell_markers_still_match(self):
        """Protege los indicadores de comportamiento PHP2Shell conocidos."""
        samples = (
            '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /?probe=php2shell HTTP/1.1" 404 0 "-" "scanner"',
            '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /icons/zz.php HTTP/1.1" 404 0 "-" "wide-cve-2026-109618/1.0"',
            '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /?id=CVE-2026-109619 HTTP/1.1" 404 0 "-" "scanner"',
        )
        # Prueba cada muestra de log incluida en los casos positivos/negativos.
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertIsNotNone(self.pattern.search(sample))

    def test_pearcmd_without_config_create_is_not_enough(self):
        """Comprueba que ejecutar pearcmd sin config-create no baste para alertar."""
        sample = '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /?lang=pearcmd&action=version HTTP/1.1" 200 0 "-" "browser"'
        self.assertIsNone(self.pattern.search(sample))

    def test_config_create_without_temporary_destination_is_not_enough(self):
        """Comprueba que config-create sin destino temporal no active la regla."""
        sample = '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /?pearcmd&config-create+/&/var/www/html/config.php HTTP/1.1" 200 0 "-" "browser"'
        self.assertIsNone(self.pattern.search(sample))

    def test_temporary_path_without_pearcmd_and_config_create_is_not_enough(self):
        """Evita alertas cuando solo aparece una ruta temporal sin la secuencia PEAR."""
        sample = '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /download?file=/tmp/readme.txt HTTP/1.1" 200 0 "-" "browser"'
        self.assertIsNone(self.pattern.search(sample))

    def test_all_supported_temporary_directories_are_recognized(self):
        """Verifica la cobertura de /tmp, /var/tmp y /dev/shm."""
        # Comprueba que la regla reconozca cada directorio temporal admitido.
        for target in ("/tmp/index.php", "/var/tmp/index.php", "/dev/shm/index.php"):
            sample = (
                '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] '
                f'"GET /index.php?x=pearcmd&y=config-create&z={target} HTTP/1.1" 200 0 "-" "scanner"'
            )
            with self.subTest(target=target):
                self.assertIsNotNone(self.pattern.search(sample))

    def test_ioc_and_non_ioc_routes_are_mutually_exclusive(self):
        """Asegura que la ruta IOC y la ruta de comportamiento normal no se superpongan."""
        rule_ioc = self.rules["10053"]
        rule_non_ioc = self.rules["10054"]
        self.assertEqual(rule_ioc.findtext("if_sid"), "10050")
        self.assertEqual(rule_non_ioc.findtext("if_sid"), "10050")
        list_ioc = rule_ioc.find("list")
        list_non_ioc = rule_non_ioc.find("list")
        self.assertEqual(list_ioc.get("field"), "srcip")
        self.assertEqual(list_ioc.get("lookup"), "address_match_key")
        self.assertEqual(list_non_ioc.get("field"), "srcip")
        self.assertEqual(list_non_ioc.get("lookup"), "not_match_key")
        self.assertEqual(list_ioc.text, list_non_ioc.text)
        self.assertEqual(list_ioc.text, "etc/lists/malicious-ioc/malicious-ip")

    def test_php2shell_ioc_response_is_exactly_30_days(self):
        """Comprueba que el evento PHP2Shell asociado a IOC bloquee exactamente 30 días."""
        sys.path.insert(0, str(REPO_ROOT / "configuration" / "manager" / "integrations"))
        from orangebox_active_response import firewall_drop_policy_for_alert
        result = firewall_drop_policy_for_alert("10053", 14, [], str(MANAGER_CONF))
        self.assertEqual(result["status"], "configured")
        self.assertEqual(result["timeout_seconds"], 2592000)
        self.assertEqual(result["matched_by"], ["rules_id:10053"])

    def test_repetition_rule_keeps_same_ip_correlation_and_excludes_ioc_and_trusted_proxies(self):
        """Exige correlación por origen y excluye IOC y reverse proxies autorizados."""
        rule = self.rules["10051"]
        self.assertEqual(rule.findtext("if_matched_sid"), "10054")
        ids_in_order = [node.get("id") for node in self.root.iter("rule")]
        self.assertLess(ids_in_order.index("10054"), ids_in_order.index("10051"))
        self.assertIsNotNone(rule.find("same_srcip"))
        source_lists = {
            (node.get("lookup"), (node.text or "").strip())
            for node in rule.findall("list")
            if node.get("field") == "srcip"
        }
        self.assertIn(("not_match_key", "etc/lists/malicious-ioc/malicious-ip"), source_lists)
        self.assertIn(("not_address_match_key", "etc/lists/orangebox-web-discovery-proxies"), source_lists)
        self.assertEqual(rule.get("frequency"), "3")
        self.assertEqual(rule.get("timeframe"), "300")
        self.assertIn("orangebox_immediate", rule.findtext("group", ""))
        self.assertIn("orangebox_web_auto_block", rule.findtext("group", ""))

    def test_repeated_non_ioc_php2shell_scan_uses_existing_24_hour_local_block(self):
        """Comprueba que la correlación 10051 active el bloqueo web existente por 24 horas."""
        from orangebox_active_response import firewall_drop_policy_for_alert
        rule = self.rules["10051"]
        groups = [item.strip() for item in rule.findtext("group", "").split(",") if item.strip()]
        result = firewall_drop_policy_for_alert("10051", 12, groups, str(MANAGER_CONF))
        self.assertEqual(result["status"], "configured")
        self.assertEqual(result["timeout_seconds"], 86400)
        self.assertEqual(result["location"], "local")
        self.assertEqual(result["matched_by"], ["rules_group:orangebox_web_auto_block,"])

    def test_php2shell_rules_do_not_define_embedded_active_response(self):
        """Evita duplicar Active Response dentro de las reglas PHP2Shell."""
        # Revisa que ninguna regla PHP2Shell incorpore un bloque Active Response duplicado.
        for rule_id in ("10050", "10051", "10052", "10053", "10054"):
            self.assertIsNone(self.rules[rule_id].find("active-response"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
