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
        self.assertEqual(self.rule_10050.findtext("if_sid"), "31100")
        self.assertEqual(self.rule_10050.get("level"), "8")
        self.assertEqual(self.rule_10050.get("noalert"), "1")
        self.assertIsNone(self.rule_10050.find("noalert"))
        self.assertIsNone(self.rule_10050.find("options"))

    def test_real_incident_pear_config_create_tmp_write_matches(self):
        lines = [line for line in INCIDENT_FIXTURE.read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual(len(lines), 2)
        self.assertRegex(lines[0], re.compile(r"(?i)pearcmd"))
        self.assertRegex(lines[0], re.compile(r"(?i)config-create"))
        self.assertRegex(lines[0], re.compile(r"(?i)/tmp/"))
        self.assertIsNotNone(self.pattern.search(lines[0]))

    def test_second_incident_lfi_request_does_not_match_php2shell_rule_alone(self):
        lines = [line for line in INCIDENT_FIXTURE.read_text(encoding="utf-8").splitlines() if line]
        self.assertEqual(len(lines), 2)
        self.assertIn("/tmp/index1", lines[1])
        self.assertIsNone(self.pattern.search(lines[1]))

    def test_known_php2shell_markers_still_match(self):
        samples = (
            '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /?probe=php2shell HTTP/1.1" 404 0 "-" "scanner"',
            '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /icons/zz.php HTTP/1.1" 404 0 "-" "wide-cve-2026-109618/1.0"',
            '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /?id=CVE-2026-109619 HTTP/1.1" 404 0 "-" "scanner"',
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertIsNotNone(self.pattern.search(sample))

    def test_pearcmd_without_config_create_is_not_enough(self):
        sample = '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /?lang=pearcmd&action=version HTTP/1.1" 200 0 "-" "browser"'
        self.assertIsNone(self.pattern.search(sample))

    def test_config_create_without_temporary_destination_is_not_enough(self):
        sample = '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /?pearcmd&config-create+/&/var/www/html/config.php HTTP/1.1" 200 0 "-" "browser"'
        self.assertIsNone(self.pattern.search(sample))

    def test_temporary_path_without_pearcmd_and_config_create_is_not_enough(self):
        sample = '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] "GET /download?file=/tmp/readme.txt HTTP/1.1" 200 0 "-" "browser"'
        self.assertIsNone(self.pattern.search(sample))

    def test_all_supported_temporary_directories_are_recognized(self):
        for target in ("/tmp/index.php", "/var/tmp/index.php", "/dev/shm/index.php"):
            sample = (
                '192.0.2.10 - - [30/Oct/2026:10:00:00 -0300] '
                f'"GET /index.php?x=pearcmd&y=config-create&z={target} HTTP/1.1" 200 0 "-" "scanner"'
            )
            with self.subTest(target=target):
                self.assertIsNotNone(self.pattern.search(sample))

    def test_ioc_and_non_ioc_routes_are_mutually_exclusive(self):
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
        sys.path.insert(0, str(REPO_ROOT / "configuration" / "manager" / "integrations"))
        from orangebox_active_response import firewall_drop_policy_for_alert
        result = firewall_drop_policy_for_alert("10053", 14, [], str(MANAGER_CONF))
        self.assertEqual(result["status"], "configured")
        self.assertEqual(result["timeout_seconds"], 2592000)
        self.assertEqual(result["matched_by"], ["rules_id:10053"])

    def test_repetition_rule_keeps_same_ip_correlation(self):
        rule = self.rules["10051"]
        self.assertEqual(rule.findtext("if_matched_sid"), "10054")
        ids_in_order = [node.get("id") for node in self.root.iter("rule")]
        self.assertLess(ids_in_order.index("10054"), ids_in_order.index("10051"))
        self.assertIsNotNone(rule.find("same_srcip"))
        source_lookup = rule.find("list")
        self.assertIsNotNone(source_lookup)
        self.assertEqual(source_lookup.get("field"), "srcip")
        self.assertEqual(source_lookup.get("lookup"), "not_match_key")
        self.assertEqual(source_lookup.text, "etc/lists/malicious-ioc/malicious-ip")
        self.assertEqual(rule.get("frequency"), "3")
        self.assertEqual(rule.get("timeframe"), "300")
        self.assertIn("orangebox_immediate", rule.findtext("group", ""))

    def test_php2shell_rules_do_not_define_embedded_active_response(self):
        for rule_id in ("10050", "10051", "10052", "10053", "10054"):
            self.assertIsNone(self.rules[rule_id].find("active-response"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
