#!/usr/bin/env python3
"""Regresión estructural para las excepciones FIM OrangeBox."""

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
        for rule_id in ("20058", "20059", "20060", "20061"):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(
                    sum(1 for rule in self.root.iter("rule") if rule.get("id") == rule_id),
                    1,
                )



class SnapMountExceptionTests(unittest.TestCase):
    """Comprueba que las excepciones Snap sean específicas y conserven evidencia."""

    @classmethod
    def setUpClass(cls):
        """Carga una sola vez las reglas FIM."""
        content = RULE_FILE.read_text(encoding="utf-8")
        cls.root = ET.fromstring("<rules-root>" + content + "</rules-root>")
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}

    def test_snapd_exception_accepts_short_and_absolute_process_names(self):
        """20058 reconoce el ejecutable Snap aunque Who-Data entregue su ruta absoluta."""
        rule = self.rules["20058"]
        self.assertEqual(rule.get("level"), "0")
        self.assertEqual(rule.findtext("if_sid"), "10044")

        process_field = next(
            field for field in rule.findall("field")
            if field.get("name") == "process_name"
        )
        process_pattern = re.compile(process_field.text or "")
        # Wazuh field patterns match within the field value; the end anchor
        # ensures the executable basename is exactly snapd.
        self.assertIsNotNone(process_pattern.search("snapd"))
        self.assertIsNotNone(
            process_pattern.search("/snap/snapd/28254/usr/lib/snapd/snapd")
        )
        self.assertIsNone(process_pattern.search("/usr/bin/systemctl"))

        file_field = next(
            field for field in rule.findall("field")
            if field.get("name") == "file"
        )
        file_pattern = re.compile(file_field.text or "")
        self.assertIsNotNone(
            file_pattern.fullmatch("/etc/systemd/system/snap-core22-2437.mount")
        )
        self.assertIsNone(
            file_pattern.fullmatch("/etc/systemd/system/sshd.service")
        )

    def test_snap_wants_link_deletion_is_narrow_and_level_three(self):
        """20061 conserva nivel 3 y solo contempla los dos directorios .wants observados."""
        rule = self.rules["20061"]
        self.assertEqual(rule.get("level"), "3")
        self.assertEqual(rule.findtext("if_sid"), "10044")
        self.assertEqual(rule.findtext("field[@name='mode']"), "scheduled")

        file_field = next(
            field for field in rule.findall("field")
            if field.get("name") == "file"
        )
        pattern = re.compile(file_field.text or "")
        escaped_dash = chr(92) + "x2d"
        escaped_snap_unit = (
            "snap-google" + escaped_dash + "cloud" + escaped_dash + "cli-513.mount"
        )
        allowed = (
            "/etc/systemd/system/multi-user.target.wants/snap-core22-2437.mount",
            "/etc/systemd/system/snapd.mounts.target.wants/snap-core22-2437.mount",
            "/etc/systemd/system/multi-user.target.wants/" + escaped_snap_unit,
            "/etc/systemd/system/snapd.mounts.target.wants/" + escaped_snap_unit,
        )
        for path in allowed:
            with self.subTest(path=path):
                self.assertIsNotNone(pattern.fullmatch(path))

        rejected = (
            "/etc/systemd/system/snap-core22-2437.mount",
            "/etc/systemd/system/graphical.target.wants/snap-core22-2437.mount",
            "/etc/systemd/system/multi-user.target.wants/sshd.service",
            "/etc/systemd/system/snapd.mounts.target.wants/snap-foo.mount",
            "/etc/systemd/system/graphical.target.wants/" + escaped_snap_unit,
            "/etc/systemd/system/multi-user.target.wants/snap-google" + (chr(92) + "x2e") + "cloud" + escaped_dash + "cli-513.mount",
            "/etc/systemd/system/multi-user.target.wants/snap-google" + escaped_dash + "cloud" + escaped_dash + "cli.mount",
        )
        for path in rejected:
            with self.subTest(path=path):
                self.assertIsNone(pattern.fullmatch(path))

    def test_snap_exception_rule_ids_are_unique(self):
        """Evita colisiones en los SIDs de las excepciones Snap."""
        for rule_id in ("20058", "20061"):
            with self.subTest(rule_id=rule_id):
                self.assertEqual(
                    sum(1 for rule in self.root.iter("rule") if rule.get("id") == rule_id),
                    1,
                )



class BitNinjaSystemdExceptionTests(unittest.TestCase):
    """La integración nftables esperada no debe generar correo; otros cambios sí."""

    @classmethod
    def setUpClass(cls):
        cls.root = ET.fromstring(
            "<rules-root>" + RULE_FILE.read_text(encoding="utf-8") + "</rules-root>"
        )
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}

    def test_exact_scheduled_bitninja_nftables_block_is_level_five(self):
        rule = self.rules["20066"]
        self.assertEqual(rule.get("level"), "5")
        self.assertEqual(rule.findtext("if_sid"), "10034")
        self.assertEqual(rule.findtext("field[@name='mode']"), "scheduled")
        fields = {field.get("name"): field.text for field in rule.findall("field")}
        self.assertEqual(fields["file"], r"^/etc/systemd/system/bitninja\.service$")

        newline = chr(10)
        diff = newline.join(
            (
                "3a4,9",
                "> # Restarting nftables.service flushes the whole nft ruleset,",
                "> # including the BitNinja tables. PartOf= propagates a restart (and stop) of",
                "> # nftables.service to BitNinja;",
                "> # Ignored when nftables.service does not exist.",
                "> After=nftables.service",
                "> PartOf=nftables.service",
            )
        )
        self.assertRegex(diff, re.compile(fields["changed_content"] or ""))

    def test_exact_whodata_dpkg_bitninja_block_is_suppressed_only_on_observed_host(self):
        rule = self.rules["20069"]
        self.assertEqual(rule.get("level"), "0")
        self.assertEqual(rule.findtext("if_sid"), "10034")
        self.assertEqual(rule.findtext("hostname"), r"^webserver\.example\.invalid$")
        fields = {field.get("name"): field.text for field in rule.findall("field")}
        self.assertEqual(fields["mode"], "whodata")
        self.assertEqual(fields["file"], r"^/etc/systemd/system/bitninja\.service$")
        self.assertEqual(fields["process_name"], r"^/usr/bin/dpkg$")
        self.assertEqual(fields["user_name"], r"^root$")
        self.assertEqual(fields["effective_uid"], r"^0$")

        newline = chr(10)
        diff = newline.join(
            (
                "3a4,9",
                "> # Restarting nftables.service flushes the whole nft ruleset,",
                "> # including the BitNinja tables. PartOf= propagates a restart (and stop) of",
                "> # nftables.service to BitNinja;",
                "> # Ignored when nftables.service does not exist.",
                "> After=nftables.service",
                "> PartOf=nftables.service",
            )
        )
        self.assertRegex(diff, re.compile(fields["changed_content"] or ""))

    def test_whodata_exception_rejects_other_processes_hosts_and_unit_changes(self):
        rule = self.rules["20069"]
        fields = {field.get("name"): field.text for field in rule.findall("field")}
        process_pattern = re.compile(fields["process_name"] or "")
        diff_pattern = re.compile(fields["changed_content"] or "")
        self.assertNotRegex("/usr/bin/curl", process_pattern)
        self.assertNotRegex("/usr/bin/apt-get", process_pattern)
        self.assertNotRegex(
            "> After=nftables.service\n> PartOf=nftables.service",
            diff_pattern,
        )
        self.assertNotRegex(
            "> # Restarting nftables.service flushes the whole nft ruleset,\n> ExecStart=/bin/bash",
            diff_pattern,
        )

    def test_whodata_exception_rule_id_is_unique(self):
        self.assertEqual(
            sum(1 for rule in self.root.iter("rule") if rule.get("id") == "20069"),
            1,
        )

    def test_partial_or_unrelated_bitninja_changes_remain_critical(self):
        rule = self.rules["20066"]
        pattern = re.compile(rule.findtext("field[@name='changed_content']") or "")
        newline = chr(10)
        rejected = (
            newline.join(("> After=nftables.service", "> PartOf=nftables.service")),
            newline.join((
                "> # Restarting nftables.service flushes the whole nft ruleset,",
                "> ExecStart=/bin/bash",
            )),
            newline.join((
                "> # Restarting nftables.service flushes the whole nft ruleset,",
                "> # including the BitNinja tables. PartOf= propagates a restart (and stop) of",
                "> # nftables.service to BitNinja;",
                "> # Ignored when nftables.service does not exist.",
                "> After=nftables.service",
                "> PartOf=nftables.service",
                "> ExecStart=/bin/bash",
            )),
        )
        for sample in rejected:
            with self.subTest(content=sample):
                self.assertNotRegex(sample, pattern)

    def test_other_systemd_unit_modifications_keep_parent_critical(self):
        self.assertEqual(self.rules["10034"].get("level"), "13")
        self.assertEqual(self.rules["10034"].findtext("if_sid"), "550")

    def test_bitninja_exception_rule_id_is_unique(self):
        count = sum(
            1
            for path in RULE_FILE.parent.glob("*.xml")
            for rule in ET.fromstring(
                "<rules-root>" + path.read_text(encoding="utf-8") + "</rules-root>"
            ).iter("rule")
            if rule.get("id") == "20066"
        )
        self.assertEqual(count, 1)




class DNSOnlySocialBeeXoviExceptionTests(unittest.TestCase):
    """La limpieza conocida de plugins DNSOnly no debe alertar por un sufijo FIM observado."""

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
        self.assertEqual(profile.get("check_value"), "^DNS$")
        self.assertEqual(
            (profile.text or "").strip(), "etc/lists/orangebox-dns-agents"
        )
        self.assertIn(
            "<list>etc/lists/orangebox-dns-agents</list>", self.manager
        )

    def test_dns_updater_queries_uppercase_group_and_generates_uppercase_profile(self):
        self.assertIn('GROUP="DNS"', self.updater)
        self.assertIn("printf '%s:DNS\\n' \"$hostname\"", self.updater)
        self.assertNotIn('GROUP="dns"', self.updater)
        self.assertNotIn("printf '%s:dns\\n'", self.updater)

    def test_20057_rule_id_is_unique(self):
        self.assertEqual(
            sum(
                1 for rule in self.root.iter("rule")
                if rule.get("id") == "20057"
            ),
            1,
        )




class DpkgSystemdTemporaryDeletionTests(unittest.TestCase):
    """La limpieza dpkg de cuatro archivos staging no debe convertirse en alerta critica."""

    @classmethod
    def setUpClass(cls):
        cls.root = ET.fromstring(
            "<rules-root>" + RULE_FILE.read_text(encoding="utf-8") + "</rules-root>"
        )
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}
        cls.rule = cls.rules["20070"]

    def test_20070_only_matches_the_four_observed_dpkg_new_paths(self):
        rule = self.rule
        self.assertEqual(rule.get("level"), "3")
        self.assertEqual(rule.findtext("if_sid"), "10044")
        self.assertEqual(rule.findtext("field[@name='mode']"), "whodata")
        fields = {field.get("name"): field.text for field in rule.findall("field")}
        self.assertEqual(
            fields["file"],
            r"^/etc/systemd/system/initialize_(?:socialbee|xovi)_plugin\.(?:service|timer)\.dpkg-new$",
        )
        pattern = re.compile(fields["file"] or "")
        allowed = (
            "/etc/systemd/system/initialize_socialbee_plugin.service.dpkg-new",
            "/etc/systemd/system/initialize_socialbee_plugin.timer.dpkg-new",
            "/etc/systemd/system/initialize_xovi_plugin.service.dpkg-new",
            "/etc/systemd/system/initialize_xovi_plugin.timer.dpkg-new",
        )
        for path in allowed:
            with self.subTest(path=path):
                self.assertIsNotNone(pattern.fullmatch(path))

        rejected = (
            "/etc/systemd/system/initialize_socialbee_plugin.service",
            "/etc/systemd/system/initialize_socialbee_plugin.service.dpkg-old",
            "/etc/systemd/system/initialize_socialbee_plugin.service.dpkg-tmp",
            "/etc/systemd/system/initialize_socialbee_plugin.service.dpkg-new.extra",
            "/etc/systemd/system/initialize_other_plugin.service.dpkg-new",
            "/etc/systemd/system/sshd.service.dpkg-new",
            "/usr/lib/systemd/system/initialize_socialbee_plugin.service.dpkg-new",
        )
        for path in rejected:
            with self.subTest(path=path):
                self.assertIsNone(pattern.fullmatch(path))

    def test_20070_requires_dpkg_parent_apt_get_and_root_context(self):
        fields = {field.get("name"): field.text for field in self.rule.findall("field")}
        self.assertEqual(fields["process_name"], r"^/usr/bin/dpkg$")
        self.assertEqual(fields["parent_name"], r"^/usr/bin/apt-get$")
        self.assertEqual(fields["user_name"], r"^root$")
        self.assertEqual(fields["effective_uid"], r"^0$")
        self.assertEqual(sum(1 for field in self.rule.findall("field")
                             if field.get("name") == "parent_name"), 1)

    def test_20070_scope_is_private_hostname_or_public_bitninja_cdb(self):
        hostname = self.rule.find("hostname")
        profile = self.rule.find("list")
        self.assertNotEqual(hostname is not None, profile is not None)
        if hostname is not None:
            self.assertEqual(hostname.get("type"), "pcre2")
            self.assertEqual(hostname.text, r"^webserver\.example\.invalid$")
        else:
            self.assertEqual(profile.get("field"), "hostname")
            self.assertEqual(profile.get("lookup"), "match_key")
            self.assertEqual((profile.text or "").strip(),
                             "etc/lists/orangebox-bitninja-agents")

    def test_10044_remains_critical_and_rule_id_is_unique(self):
        self.assertEqual(self.rules["10044"].get("level"), "15")
        self.assertEqual(self.rules["10044"].findtext("if_sid"), "553")
        self.assertEqual(
            sum(1 for rule in self.root.iter("rule")
                if rule.get("id") == "20070"),
            1,
        )


class DpkgCronTemporaryDeletionTests(unittest.TestCase):
    """La limpieza dpkg del temporal WP Toolkit no debe generar correo critico."""

    @classmethod
    def setUpClass(cls):
        cls.root = ET.fromstring(
            "<rules-root>" + RULE_FILE.read_text(encoding="utf-8") + "</rules-root>"
        )
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}
        cls.rule = cls.rules["20071"]

    def test_20071_is_level_three_and_matches_only_the_observed_temporary_file(self):
        rule = self.rule
        self.assertEqual(rule.get("level"), "3")
        self.assertEqual(rule.findtext("if_sid"), "10045")
        self.assertEqual(rule.findtext("field[@name='mode']"), "whodata")
        hostname = rule.find("hostname")
        self.assertIsNotNone(hostname)
        self.assertEqual(hostname.get("type"), "pcre2")
        self.assertEqual(hostname.text, r"^cpanel\.example\.invalid$")

        file_pattern = re.compile(rule.findtext("field[@name='file']") or "")
        self.assertIsNotNone(
            file_pattern.fullmatch("/etc/cron.d/wp-toolkit-update.dpkg-new")
        )
        rejected = (
            "/etc/cron.d/wp-toolkit-update",
            "/etc/cron.d/wp-toolkit-update.dpkg-old",
            "/etc/cron.d/wp-toolkit-update.dpkg-tmp",
            "/etc/cron.d/wp-toolkit-update.dpkg-new.extra",
            "/etc/cron.d/other-package.dpkg-new",
            "/etc/cron.daily/wp-toolkit-update.dpkg-new",
        )
        for path in rejected:
            with self.subTest(path=path):
                self.assertIsNone(file_pattern.fullmatch(path))

    def test_20071_requires_whodata_dpkg_apt_get_and_root_context(self):
        fields = {field.get("name"): field.text for field in self.rule.findall("field")}
        self.assertEqual(fields["process_name"], r"^/usr/bin/dpkg$")
        self.assertEqual(fields["parent_name"], r"^/usr/bin/apt-get$")
        self.assertEqual(fields["user_name"], r"^root$")
        self.assertEqual(fields["effective_uid"], r"^0$")

    def test_10045_stays_critical_and_20071_id_is_unique(self):
        self.assertEqual(self.rules["10045"].get("level"), "15")
        self.assertEqual(self.rules["10045"].findtext("if_sid"), "553")
        count = sum(
            1
            for path in RULE_FILE.parent.glob("*.xml")
            for rule in ET.fromstring(
                "<rules-root>" + path.read_text(encoding="utf-8") + "</rules-root>"
            ).iter("rule")
            if rule.get("id") == "20071"
        )
        self.assertEqual(count, 1)



class GoogleCloudHostsFIMExceptionTests(unittest.TestCase):
    """Las excepciones GCP se determinan por el diff funcional, no por CDB de hostname."""

    @classmethod
    def setUpClass(cls):
        content = RULE_FILE.read_text(encoding="utf-8")
        cls.root = ET.fromstring("<rules-root>" + content + "</rules-root>")
        cls.rules = {rule.get("id"): rule for rule in cls.root.iter("rule")}

    def test_gcp_rules_are_available_without_profile_cdb_lookup(self):
        expected = {"20062", "20064", "20080", "20082"}
        self.assertTrue(expected.issubset(self.rules))
        for rule_id in expected:
            with self.subTest(rule_id=rule_id):
                rule = self.rules[rule_id]
                self.assertEqual(rule.findtext("if_sid"), "10036")
                self.assertIsNone(rule.find("list"))

        for removed_id in ("20063", "20065", "20081", "20083"):
            with self.subTest(removed_id=removed_id):
                self.assertNotIn(removed_id, self.rules)

    def test_gcp_exception_children_follow_10036_and_stay_below_mail_threshold(self):
        ordered_rules = list(self.root.iter("rule"))
        positions = {rule.get("id"): index for index, rule in enumerate(ordered_rules)}
        self.assertEqual(self.rules["10036"].get("level"), "13")

        for rule_id in ("20062", "20064", "20080", "20082"):
            with self.subTest(rule_id=rule_id):
                rule = self.rules[rule_id]
                self.assertEqual(rule.findtext("if_sid"), "10036")
                self.assertLess(positions["10036"], positions[rule_id])
                self.assertLess(int(rule.get("level", "99")), 12)

    def test_gcp_exceptions_are_in_the_trailing_whitelist_section(self):
        ordered_ids = [rule.get("id") for rule in self.root.iter("rule")]
        last_detection = ordered_ids.index("10049")
        for rule_id in ("20062", "20064", "20080", "20082"):
            with self.subTest(rule_id=rule_id):
                self.assertGreater(ordered_ids.index(rule_id), last_detection)
                self.assertEqual(self.rules[rule_id].findtext("if_sid"), "10036")

    def test_exact_gcp_diffs_match_and_real_hosts_changes_do_not(self):
        pattern_text = self.rules["20062"].findtext("field[@name='changed_content']")
        self.assertIsNotNone(pattern_text)
        pattern = re.compile(pattern_text or "")

        mds = (
            "8d7\n"
            "< 169.254.169.254 metadata.google.internal # Added by Google - MDS\n"
            "9a9\n"
            "> 169.254.169.254 metadata.google.internal # Added by Google - MDS\n"
        )
        hostname = (
            "8d7\n"
            "< 192.0.2.3 ns1.example.invalid ns1 # Added by Google - Hostname\n"
            "9a9\n"
            "> 192.0.2.3 ns1.example.invalid ns1 # Added by Google - Hostname\n"
        )
        for sample in (mds, hostname):
            with self.subTest(sample=sample):
                self.assertIsNotNone(pattern.fullmatch(sample))

        changed_ip = hostname.replace("192.0.2.3", "192.0.2.4", 1)
        self.assertIsNone(pattern.fullmatch(changed_ip))
        self.assertIsNone(pattern.fullmatch(hostname + "> 192.0.2.10 malicious.example\n"))
        self.assertIsNone(
            pattern.fullmatch(
                "9a9\n> 192.0.2.3 ns1.example.invalid ns1 # Added by Google - Hostname\n"
            )
        )
        self.assertEqual(
            self.rules["20064"].findtext("field[@name='changed_content']"),
            pattern_text,
        )
        self.assertEqual(
            self.rules["20082"].findtext("field[@name='changed_content']"),
            pattern_text,
        )

    def test_whodata_gcp_rules_retain_actor_and_root_constraints(self):
        sed = self.rules["20062"]
        syscheckd = self.rules["20064"]
        for rule, process in ((sed, "^/usr/bin/sed$"), (syscheckd, "(?:^|/)wazuh-syscheckd$")):
            fields = {field.get("name"): field.text for field in rule.findall("field")}
            self.assertEqual(fields["file"], "^/etc/hosts$")
            self.assertEqual(fields["mode"], "whodata")
            self.assertEqual(fields["process_name"], process)
            self.assertEqual(fields["user_name"], "^root$")
            self.assertEqual(fields["effective_uid"], "^0$")

        no_content = self.rules["20080"]
        no_content_fields = {field.get("name"): field.text for field in no_content.findall("field")}
        self.assertEqual(no_content_fields["file"], "^/etc/hosts$")
        self.assertEqual(no_content_fields["mode"], "whodata")
        self.assertEqual(no_content_fields["user_name"], "^root$")
        self.assertEqual(no_content_fields["effective_uid"], "^0$")
        process = re.compile(no_content_fields["process_name"] or "")
        for executable in (
            "/usr/bin/sed",
            "/var/ossec/bin/wazuh-syscheckd",
            "/opt/ossec/bin/wazuh-syscheckd",
        ):
            with self.subTest(executable=executable):
                self.assertIsNotNone(process.fullmatch(executable))
        self.assertIsNone(process.fullmatch("/usr/bin/curl"))
        self.assertEqual(
            no_content_fields["changed_content"],
            r"^No content changes were found for this file\.$",
        )

    def test_scheduled_realtime_rule_accepts_only_expected_modes_and_exact_file(self):
        rule = self.rules["20082"]
        self.assertEqual(rule.get("level"), "3")
        fields = {field.get("name"): field.text for field in rule.findall("field")}
        mode = re.compile(fields["mode"] or "")
        self.assertIsNotNone(mode.fullmatch("scheduled"))
        self.assertIsNotNone(mode.fullmatch("realtime"))
        self.assertIsNone(mode.fullmatch("whodata"))
        self.assertEqual(fields["file"], "^/etc/hosts$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
