from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "configuration" / "manager" / "etc" / "rules"

def load_rules(filename):
    source = (RULES / filename).read_text(encoding="utf-8")
    return ET.fromstring("<rules-root>" + source + "</rules-root>")

def get_rule(root, rule_id):
    for rule in root.iter("rule"):
        if rule.get("id") == str(rule_id):
            return rule
    raise AssertionError(f"Rule {rule_id} not found")

class PublicRuleExceptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mail = load_rules("orangebox-mail.xml")
        cls.ioc = load_rules("orangebox-ioc.xml")
        cls.hardening = load_rules("orangebox-hardening.xml")

    def test_encrypted_pdf_amavis_exception_is_exact_and_does_not_weaken_parent(self):
        parent = get_rule(self.mail, 10704)
        exception = get_rule(self.mail, 20067)
        self.assertEqual(parent.get("level"), "14")
        self.assertEqual(exception.get("level"), "0")
        self.assertEqual(exception.findtext("if_sid"), "10704")
        self.assertIn(r"Blocked\s+INFECTED\s+\(Heuristics\.Encrypted\.PDF\)",
                      exception.findtext("match", ""))

    def test_encrypted_pdf_clamav_heuristic_is_suppressed_only_by_exact_child(self):
        parent = get_rule(self.mail, 10707)
        exception = get_rule(self.mail, 10710)
        self.assertEqual(parent.get("level"), "13")
        self.assertEqual(exception.get("level"), "0")
        self.assertEqual(exception.findtext("if_sid"), "10707")
        self.assertIn(r"Heuristics\.Encrypted\.PDF\s+FOUND",
                      exception.findtext("match", ""))

    def test_other_amavis_infected_and_clamav_signatures_remain_detectable(self):
        self.assertEqual(get_rule(self.mail, 10704).get("level"), "14")
        self.assertEqual(get_rule(self.mail, 10707).get("level"), "13")
        self.assertNotEqual(get_rule(self.mail, 10704).get("level"), "0")
        self.assertNotEqual(get_rule(self.mail, 10707).get("level"), "0")

    def test_clamav_scan_temp_hash_exception_is_path_scoped(self):
        exception = get_rule(self.ioc, 20068)
        self.assertEqual(exception.get("level"), "0")
        self.assertEqual(exception.findtext("if_sid"), "99901")
        field = exception.find("field[@name='file']")
        self.assertIsNotNone(field)
        pattern = re.compile(field.text)
        allowed = "/tmp/20261104_155422-scantem.f25651388c/clamav-" + ("a" * 32) + ".tmp"
        self.assertRegex(allowed, pattern)
        self.assertNotRegex("/var/www/html/clamav-" + ("a" * 32) + ".tmp", pattern)
        self.assertNotRegex("/tmp/20261104_155422-scantem.f25651388c/suspicious.php", pattern)

    def test_snap_scheduled_symlink_exception_is_narrow(self):
        exception = get_rule(self.hardening, 20061)
        self.assertEqual(exception.get("level"), "3")
        self.assertEqual(exception.findtext("if_sid"), "10044")
        self.assertEqual(exception.findtext("field[@name='mode']"), "scheduled")
        file_field = exception.find("field[@name='file']")
        self.assertIsNotNone(file_field)
        pattern = re.compile(file_field.text)
        self.assertRegex(
            "/etc/systemd/system/multi-user.target.wants/snap-demo-123.mount",
            pattern,
        )
        self.assertRegex(
            r"/etc/systemd/system/snapd.mounts.target.wants/snap-google\x2dcloud-123.mount",
            pattern,
        )
        self.assertNotRegex(
            "/etc/systemd/system/multi-user.target.wants/other.service",
            pattern,
        )

    def test_bitninja_scheduled_exception_keeps_critical_parent(self):
        parent = get_rule(self.hardening, 10034)
        exception = get_rule(self.hardening, 20066)
        self.assertEqual(parent.get("level"), "13")
        self.assertEqual(exception.get("level"), "5")
        self.assertEqual(exception.findtext("if_sid"), "10034")
        self.assertEqual(exception.findtext("field[@name='mode']"), "scheduled")
        self.assertEqual(
            exception.findtext("field[@name='file']"),
            r"^/etc/systemd/system/bitninja\.service$",
        )

    def test_bitninja_whodata_exception_requires_authorized_cdb_and_exact_actor(self):
        exception = get_rule(self.hardening, 20069)
        self.assertEqual(exception.get("level"), "0")
        self.assertEqual(exception.findtext("if_sid"), "10034")
        self.assertEqual(exception.findtext("field[@name='mode']"), "whodata")
        self.assertEqual(
            exception.findtext("list[@field='hostname']"),
            "etc/lists/orangebox-bitninja-agents",
        )
        self.assertEqual(
            exception.findtext("field[@name='file']"),
            r"^/etc/systemd/system/bitninja\.service$",
        )
        self.assertEqual(exception.findtext("field[@name='process_name']"), "^/usr/bin/dpkg$")
        self.assertEqual(exception.findtext("field[@name='user_name']"), "^root$")
        self.assertEqual(exception.findtext("field[@name='effective_uid']"), "^0$")
        cdb = ROOT / "configuration" / "manager" / "etc" / "lists" / "orangebox-bitninja-agents"
        self.assertIn("bitninja01.example.invalid:", cdb.read_text(encoding="utf-8"))

    def test_exception_rule_ids_are_unique(self):
        all_ids = []
        for root in (self.mail, self.ioc, self.hardening):
            all_ids.extend(rule.get("id") for rule in root.iter("rule"))
        self.assertEqual(len(all_ids), len(set(all_ids)))

if __name__ == "__main__":
    unittest.main()
