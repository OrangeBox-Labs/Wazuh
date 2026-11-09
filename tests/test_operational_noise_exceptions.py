#!/usr/bin/env python3
"""Regresión estructural para las excepciones operacionales de alertas OrangeBox."""

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "configuration" / "manager" / "etc" / "rules"
AUTH_FILE = RULES_DIR / "orangebox-auth.xml"
HARDENING_FILE = RULES_DIR / "orangebox-hardening.xml"
MAIL_FILE = RULES_DIR / "orangebox-mail.xml"
IOC_FILE = RULES_DIR / "orangebox-ioc.xml"
MANAGER_CONF = ROOT / "configuration" / "manager" / "etc" / "ossec.conf"


def load_rules(path):
    """Carga un archivo de reglas con varios grupos XML en una raíz de prueba."""
    return ET.fromstring("<rules-root>" + path.read_text(encoding="utf-8") + "</rules-root>")


def fields_by_name(rule):
    """Devuelve los campos de una regla agrupados por su nombre de decoder."""
    return {field.get("name"): field for field in rule.findall("field")}


class GoogleCloudHostsExceptionsTests(unittest.TestCase):
    """Regresión de excepciones GCP: el diff FIM exacto determina la clasificación."""

    @classmethod
    def setUpClass(cls):
        cls.root = load_rules(HARDENING_FILE)
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}

    def test_dns_updater_and_dns_only_exception_use_real_uppercase_group(self):
        updater = (
            ROOT / "configuration" / "manager" / "bin" / "update-orangebox-dns-agents.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('GROUP="DNS"', updater)
        self.assertIn("printf '%s:DNS\\n' \"$hostname\"", updater)
        self.assertNotIn('GROUP="dns"', updater)
        self.assertNotIn("printf '%s:dns\\n'", updater)

        rule_20057 = self.rules["20057"]
        self.assertEqual(rule_20057.find("list").get("check_value"), "^DNS$")
        self.assertEqual(
            rule_20057.find("list").text,
            "etc/lists/orangebox-dns-agents",
        )

        manager = ET.parse(MANAGER_CONF).getroot()
        declared = {
            (node.text or "").strip()
            for node in manager.findall("./ruleset/list")
        }
        self.assertIn("etc/lists/orangebox-dns-agents", declared)
        self.assertIn("etc/lists/orangebox-cpanel-agents", declared)

    def test_gcp_rules_do_not_depend_on_profile_hostname_cdb(self):
        expected = ("20062", "20064", "20080", "20082")
        for rule_id in expected:
            with self.subTest(rule_id=rule_id):
                rule = self.rules[rule_id]
                self.assertEqual(rule.findtext("if_sid"), "10036")
                self.assertIsNone(rule.find("list"))
                self.assertIsNone(rule.find("hostname"))

        for removed_id in ("20063", "20065", "20081", "20083"):
            with self.subTest(removed_id=removed_id):
                self.assertNotIn(removed_id, self.rules)

        for old_id in ("20078", "20079"):
            self.assertNotIn(old_id, self.rules)

    def test_sed_exception_accepts_observed_gcp_diffs_and_rejects_mapping_changes(self):
        rule = self.rules["20062"]
        fields = fields_by_name(rule)
        self.assertEqual(rule.get("level"), "3")
        self.assertEqual(fields["mode"].text, "whodata")
        self.assertEqual(fields["file"].text, r"^/etc/hosts$")
        self.assertEqual(fields["process_name"].text, r"^/usr/bin/sed$")
        self.assertEqual(fields["user_name"].text, "^root$")
        self.assertEqual(fields["effective_uid"].text, "^0$")
        self.assertNotIn("parent_name", fields)
        pattern = re.compile(fields["changed_content"].text or "")

        samples = (
            # MDS d/a diff observed on ns1.
            "8d7\n< 169.254.169.254 metadata.google.internal # Added by Google - MDS\n"
            "9a9\n> 169.254.169.254 metadata.google.internal # Added by Google - MDS\n",
            # Hostname d/a diff observed on ns1.
            "8d7\n< 192.0.2.3 ns1.example.invalid ns1 # Added by Google - Hostname\n"
            "9a9\n> 192.0.2.3 ns1.example.invalid ns1 # Added by Google - Hostname\n",
            # MDS c diff.
            "4c4\n< 169.254.169.254 metadata.google.internal # Added by Google\n"
            "---\n> 169.254.169.254 metadata.google.internal # Added by Google - MDS\n",
            # Hostname c diff.
            "4c4\n< 192.0.2.3 ns1.example.invalid ns1 # Added by Google\n"
            "---\n> 192.0.2.3 ns1.example.invalid ns1 # Added by Google - Hostname\n",
            # Combined reorder of the two Google-managed entries.
            "8,9c8,9\n< 192.0.2.3 ns1.example.invalid ns1 # Added by Google\n"
            "< 169.254.169.254 metadata.google.internal # Added by Google\n"
            "---\n> 169.254.169.254 metadata.google.internal # Added by Google - MDS\n"
            "> 192.0.2.3 ns1.example.invalid ns1 # Added by Google - Hostname\n",
        )
        for sample in samples:
            with self.subTest(sample=sample[:45]):
                self.assertRegex(sample, pattern)

        changed_ip = samples[1].replace("192.0.2.3", "192.0.2.4", 1)
        self.assertNotRegex(changed_ip, pattern)
        self.assertNotRegex(
            samples[1].replace("ns1.example.invalid", "attacker.example.test", 1),
            pattern,
        )
        self.assertNotRegex(
            samples[1].replace(" ns1 #", " attacker #", 1),
            pattern,
        )
        self.assertNotRegex(
            samples[1] + "> 192.0.2.10 attacker.example.test\n",
            pattern,
        )
        self.assertNotRegex(
            "9a9\n> 192.0.2.3 ns1.example.invalid ns1 # Added by Google - Hostname\n",
            pattern,
        )

    def test_syscheckd_and_scheduled_rules_use_same_exact_gcp_diff(self):
        base = fields_by_name(self.rules["20062"])["changed_content"].text
        for rule_id, expected_level in (("20064", "5"), ("20082", "3")):
            with self.subTest(rule_id=rule_id):
                rule = self.rules[rule_id]
                self.assertEqual(rule.get("level"), expected_level)
                self.assertEqual(rule.findtext("if_sid"), "10036")
                fields = fields_by_name(rule)
                self.assertEqual(fields["file"].text, r"^/etc/hosts$")
                self.assertEqual(fields["changed_content"].text, base)

        syscheckd = self.rules["20064"]
        sys_fields = fields_by_name(syscheckd)
        self.assertEqual(sys_fields["mode"].text, "whodata")
        self.assertRegex(
            "/var/ossec/bin/wazuh-syscheckd",
            re.compile(sys_fields["process_name"].text or ""),
        )
        self.assertRegex(
            "/opt/ossec/bin/wazuh-syscheckd",
            re.compile(sys_fields["process_name"].text or ""),
        )
        self.assertEqual(sys_fields["user_name"].text, "^root$")
        self.assertEqual(sys_fields["effective_uid"].text, "^0$")

        scheduled = fields_by_name(self.rules["20082"])
        mode = re.compile(scheduled["mode"].text or "")
        self.assertRegex("scheduled", mode)
        self.assertRegex("realtime", mode)
        self.assertNotRegex("whodata", mode)
        self.assertNotIn("process_name", scheduled)
        self.assertNotIn("user_name", scheduled)

    def test_no_content_events_are_scoped_to_root_processes_and_exact_file(self):
        rule = self.rules["20080"]
        self.assertEqual(rule.get("level"), "3")
        self.assertEqual(rule.findtext("if_sid"), "10036")
        fields = fields_by_name(rule)
        self.assertEqual(fields["mode"].text, "whodata")
        self.assertEqual(fields["file"].text, r"^/etc/hosts$")
        self.assertEqual(
            fields["changed_content"].text,
            r"^No content changes were found for this file\.$",
        )
        process = re.compile(fields["process_name"].text or "")
        for executable in (
            "/usr/bin/sed",
            "/var/ossec/bin/wazuh-syscheckd",
            "/opt/ossec/bin/wazuh-syscheckd",
        ):
            with self.subTest(executable=executable):
                self.assertRegex(executable, process)
        self.assertNotRegex("/usr/bin/curl", process)
        self.assertEqual(fields["user_name"].text, "^root$")
        self.assertEqual(fields["effective_uid"].text, "^0$")

    def test_base_network_detection_remains_critical_and_general(self):
        base = self.rules["10036"]
        self.assertEqual(base.get("level"), "13")
        self.assertEqual(base.findtext("if_sid"), "550")
        pattern = re.compile(next(f.text for f in base.findall("field") if f.get("name") == "file"))
        for path in ("/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/fstab"):
            with self.subTest(path=path):
                self.assertRegex(path, pattern)

    def test_google_exception_rule_ids_are_unique(self):
        expected = ("20062", "20064", "20080", "20082")
        for rule_id in expected:
            count = sum(
                1 for path in RULES_DIR.glob("*.xml")
                for rule in load_rules(path).iter("rule")
                if rule.get("id") == rule_id
            )
            self.assertEqual(count, 1)




class ZimbraSelfSshExceptionTests(unittest.TestCase):
    """La conexión SSH de Zimbra al mismo host no debe escalar a correo crítico."""

    @classmethod
    def setUpClass(cls):
        cls.root = load_rules(AUTH_FILE)
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}

    def test_exception_is_specific_to_mail_jhg_self_connection(self):
        rule = self.rules["20011"]
        self.assertEqual(rule.get("level"), "3")
        self.assertEqual(rule.findtext("if_sid"), "10001")
        self.assertEqual(rule.findtext("hostname"), r"^mail\.jhg\.cl$")
        self.assertEqual(rule.findtext("srcip"), "192.0.2.19")
        self.assertEqual(rule.findtext("user"), "^zimbra$")
        pattern = re.compile(rule.findtext("match") or "")
        sample = (
            "Nov 04 14:52:02 mail.example.invalid sshd-session[4177284]: "
            "Accepted publickey for zimbra from 192.0.2.19 port 54266 ssh2: "
            "RSA SHA256:WtdjbD7wvLYXTNAvw7ESM2xSDPpxhttFJhWNkqReWt0"
        )
        self.assertRegex(sample, pattern)
        self.assertNotRegex(sample.replace("192.0.2.19", "192.0.2.20"), pattern)
        self.assertNotRegex(sample.replace("for zimbra", "for root"), pattern)

    def test_detection_parent_remains_critical_and_sid_is_unique(self):
        self.assertEqual(self.rules["10001"].get("level"), "13")
        count = sum(
            1 for path in RULES_DIR.glob("*.xml")
            for rule in load_rules(path).iter("rule")
            if rule.get("id") == "20011"
        )
        self.assertEqual(count, 1)


class EncryptedPdfHeuristicTests(unittest.TestCase):
    """La heuristica de PDF cifrado se suprime; otros veredictos INFECTED/FOUND no."""

    @classmethod
    def setUpClass(cls):
        cls.root = load_rules(MAIL_FILE)
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}

    def test_encrypted_pdf_is_suppressed_but_other_signatures_remain_critical(self):
        clam_rule = self.rules["10710"]
        self.assertEqual(clam_rule.get("level"), "0")
        self.assertEqual(clam_rule.findtext("if_sid"), "10707")
        clam_pattern = re.compile(clam_rule.findtext("match") or "")
        self.assertRegex("clamd: Heuristics.Encrypted.PDF FOUND", clam_pattern)
        self.assertNotRegex("clamd: Eicar-Test-Signature FOUND", clam_pattern)

        amavis_rule = self.rules["20067"]
        self.assertEqual(amavis_rule.get("level"), "0")
        self.assertEqual(amavis_rule.findtext("if_sid"), "10704")
        amavis_pattern = re.compile(amavis_rule.findtext("match") or "")
        self.assertRegex(
            "Blocked INFECTED (Heuristics.Encrypted.PDF) {DiscardedInbound,Quarantined}",
            amavis_pattern,
        )
        self.assertNotRegex("Blocked INFECTED (Win.Trojan.Generic)", amavis_pattern)

        self.assertEqual(self.rules["10707"].get("level"), "13")
        self.assertEqual(self.rules["10704"].get("level"), "14")
        for rule_id in ("10710", "20067"):
            count = sum(
                1 for path in RULES_DIR.glob("*.xml")
                for rule in load_rules(path).iter("rule")
                if rule.get("id") == rule_id
            )
            self.assertEqual(count, 1)


class ClamAvScanTemporaryHashExceptionTests(unittest.TestCase):
    """Solo se suprime el IOC 99901 para temporales con el patron scantem de ClamAV."""

    @classmethod
    def setUpClass(cls):
        cls.root = load_rules(IOC_FILE)
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}

    def test_scantem_clamav_temporary_file_is_suppressed_exactly(self):
        rule = self.rules["20068"]
        self.assertEqual(rule.get("level"), "0")
        self.assertEqual(rule.findtext("if_sid"), "99901")
        pattern = re.compile(fields_by_name(rule)["file"].text or "")

        sample = (
            "/tmp/20261104_155422-scantem.f25651388c/"
            "clamav-3c549e139afa12e19be2bfca5fbaf698.tmp"
        )
        self.assertRegex(sample, pattern)

        self.assertNotRegex(
            "/tmp/20261104_155422-scantem.f25651388c/suspicious.php",
            pattern,
        )
        self.assertNotRegex(
            "/tmp/clamav-3c549e139afa12e19be2bfca5fbaf698.tmp",
            pattern,
        )
        self.assertNotRegex(
            "/var/tmp/clamav-3c549e139afa12e19be2bfca5fbaf698.tmp",
            pattern,
        )

    def test_known_hash_detection_remains_available_outside_scanner_temp_path(self):
        rule = self.rules["20068"]
        pattern = re.compile(fields_by_name(rule)["file"].text or "")
        self.assertNotRegex("/var/www/html/uploaded-malware.bin", pattern)
        self.assertNotRegex("/tmp/dropper.sh", pattern)

    def test_exception_rule_id_is_unique(self):
        count = sum(
            1 for path in RULES_DIR.glob("*.xml")
            for rule in load_rules(path).iter("rule")
            if rule.get("id") == "20068"
        )
        self.assertEqual(count, 1)


class IntegrationThresholdTests(unittest.TestCase):
    """Comprueba que los niveles operacionales quedan bajo el umbral de correo."""

    def test_operational_levels_remain_logged_but_below_email_threshold(self):
        root = ET.parse(MANAGER_CONF).getroot()
        email_levels = [
            int(node.findtext("level") or "0")
            for node in root.findall("integration")
            if node.findtext("name") == "custom-orangebox-email.py"
        ]
        self.assertEqual(email_levels, [12])
        for path, ids in (
            (HARDENING_FILE, ("20062", "20064", "20071", "20080", "20082")),
            (AUTH_FILE, ("20011",)),
            (MAIL_FILE, ("10710", "20067")),
            (IOC_FILE, ("20068",)),
        ):
            by_id = {rule.get("id"): rule for rule in load_rules(path).iter("rule")}
            for rule_id in ids:
                with self.subTest(rule_id=rule_id):
                    self.assertLess(int(by_id[rule_id].get("level")), email_levels[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
