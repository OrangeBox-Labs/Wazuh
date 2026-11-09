#!/usr/bin/env python3
import sys
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_DIR = REPO_ROOT / "configuration" / "manager" / "integrations"
sys.path.insert(0, str(INTEGRATION_DIR))

from orangebox_active_response import (
    firewall_drop_policy_for_alert,
    should_render_firewall_drop_status,
)
PATCHER_PATH = REPO_ROOT / "tools" / "patch-ioc-active-response-conf.py"
PATCHER_SPEC = importlib.util.spec_from_file_location("patch_ioc_active_response_conf", PATCHER_PATH)
PATCHER_MODULE = importlib.util.module_from_spec(PATCHER_SPEC)
PATCHER_SPEC.loader.exec_module(PATCHER_MODULE)
patch_config = PATCHER_MODULE.patch_config


MANAGER_CONF = REPO_ROOT / "configuration" / "manager" / "etc" / "ossec.conf"


class FirewallDropPolicyTests(unittest.TestCase):
    def test_successful_ssh_is_not_described_as_unblocked_without_a_policy(self):
        """Un login SSH exitoso no es un ataque ni debe mostrar NO BLOQUEADA."""
        for rule_id in ("5715", "10001"):
            with self.subTest(rule_id=rule_id):
                self.assertFalse(
                    should_render_firewall_drop_status(
                        rule_id, 13, "192.0.2.19", "not_configured"
                    )
                )

    def test_explicit_or_unverifiable_firewall_policy_remains_visible(self):
        """Una política configurada o no verificable siempre se muestra."""
        for status in ("configured", "unknown"):
            with self.subTest(status=status):
                self.assertTrue(
                    should_render_firewall_drop_status(
                        "10001", 13, "192.0.2.19", status
                    )
                )

    def test_other_critical_ip_alerts_keep_the_unblocked_status(self):
        """La corrección no oculta el estado de contención de otras alertas críticas."""
        self.assertTrue(
            should_render_firewall_drop_status(
                "99906", 14, "198.51.100.23", "not_configured"
            )
        )
        self.assertFalse(
            should_render_firewall_drop_status(
                "10036", 5, "", "not_configured"
            )
        )

    def write_config(self, content):
        """Crea un ossec.conf temporal para probar la política sin tocar la configuración del Manager."""
        tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_repo_policy_firewall_drop_durations(self):
        """Comprueba las duraciones de contención IOC y de escaneo PHP2Shell repetido."""
        expected = {
            "10460": 604800, "10461": 604800, "10462": 604800, "10463": 604800,
            "99903": 604800, "99904": 604800, "99905": 604800, "99907": 604800,
            "99908": 604800, "99911": 604800, "99912": 604800, "99913": 604800,
            "99914": 604800, "99906": 2592000, "10053": 2592000, "10051": 86400, "10055": 86400,
        }
        # La regla 10051 selecciona Active Response mediante el grupo exacto de web auto-block.
        for rule_id, timeout in expected.items():
            with self.subTest(rule_id=rule_id):
                groups = ["orangebox_web_auto_block"] if rule_id in ("10051", "10055") else []
                level = 12 if rule_id == "10051" else 14
                result = firewall_drop_policy_for_alert(rule_id, level, groups, str(MANAGER_CONF))
                self.assertEqual(result["status"], "configured")
                self.assertEqual(result["timeout_seconds"], timeout)
                self.assertEqual(result["location"], "local")
                if rule_id in ("10051", "10055"):
                    self.assertEqual(result["matched_by"], ["rules_group:orangebox_web_auto_block,"])
        # Sin el grupo de contención, el SID 10051 no debe seleccionar firewall-drop.
        no_group = firewall_drop_policy_for_alert("10051", 12, [], str(MANAGER_CONF))
        self.assertEqual(no_group["status"], "not_configured")

    def test_rules_id_rules_group_and_level_are_or_selectors(self):
        """Verifica que SID, grupo y nivel se evalúen como selectores alternativos."""
        config = self.write_config("""<ossec_config>
  <active-response>
    <disabled>no</disabled><command>firewall-drop</command><location>local</location>
    <rules_id>42</rules_id><rules_group>web,|orangebox_ioc,</rules_group><level>12</level>
    <timeout>600</timeout>
  </active-response>
</ossec_config>""")
        cases = [
            ("42", 1, [], True, "rules_id"),
            ("43", 8, ["web"], True, "rules_group"),
            ("44", 14, [], True, "level"),
            ("44", 11, [], False, ""),
        ]
        # Ejecuta cada combinación de selector y resultado esperado.
        for rule_id, level, groups, expected, selector in cases:
            with self.subTest(rule_id=rule_id, level=level, groups=groups):
                result = firewall_drop_policy_for_alert(rule_id, level, groups, config)
                self.assertEqual(result["status"] == "configured", expected)
                if expected:
                    self.assertTrue(any(selector in item for item in result["matched_by"]))

    def test_rules_group_trailing_comma_requires_exact_match(self):
        """Comprueba que una coma final exija coincidencia exacta del grupo."""
        config = self.write_config("""<ossec_config>
  <active-response><disabled>no</disabled><command>firewall-drop</command>
    <location>local</location><rules_group>web,</rules_group><timeout>300</timeout>
  </active-response>
</ossec_config>""")
        exact = firewall_drop_policy_for_alert("10", 5, ["web"], config)
        partial = firewall_drop_policy_for_alert("10", 5, ["web_shell"], config)
        self.assertEqual(exact["status"], "configured")
        self.assertEqual(partial["status"], "not_configured")

    def test_group_without_trailing_comma_allows_substring_match(self):
        """Verifica la coincidencia parcial cuando el selector no exige exactitud."""
        config = self.write_config("""<ossec_config>
  <active-response><disabled>no</disabled><command>firewall-drop</command>
    <location>local</location><rules_group>web</rules_group><timeout>300</timeout>
  </active-response>
</ossec_config>""")
        result = firewall_drop_policy_for_alert("10", 5, ["web_shell"], config)
        self.assertEqual(result["status"], "configured")

    def test_disabled_response_is_not_reported_as_configured(self):
        """Asegura que un bloque deshabilitado no se reporte como política activa."""
        config = self.write_config("""<ossec_config>
  <active-response><disabled>yes</disabled><command>firewall-drop</command>
    <location>local</location><rules_id>99906</rules_id><timeout>2592000</timeout>
  </active-response>
</ossec_config>""")
        result = firewall_drop_policy_for_alert("99906", 14, [], config)
        self.assertEqual(result["status"], "not_configured")

    def test_wrong_command_is_not_reported_as_firewall_drop(self):
        """Evita atribuir un bloqueo cuando el bloque usa otro comando Active Response."""
        config = self.write_config("""<ossec_config>
  <active-response><disabled>no</disabled><command>orangebox-yara</command>
    <location>local</location><rules_id>99906</rules_id><timeout>2592000</timeout>
  </active-response>
</ossec_config>""")
        result = firewall_drop_policy_for_alert("99906", 14, [], config)
        self.assertEqual(result["status"], "not_configured")

    def test_missing_or_invalid_config_is_unknown_not_not_configured(self):
        """Distingue entre política ausente y configuración que no puede evaluarse."""
        missing = firewall_drop_policy_for_alert("99906", 14, [], "/does/not/exist")
        invalid_path = self.write_config("<ossec_config><active-response>")
        invalid = firewall_drop_policy_for_alert("99906", 14, [], invalid_path)
        self.assertEqual(missing["status"], "unknown")
        self.assertEqual(invalid["status"], "unknown")

    def test_live_config_patcher_changes_only_ioc_blocks_and_is_idempotent(self):
        """Comprueba que el patcher limite los cambios a bloques IOC y sea idempotente."""
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        target = Path(temp_dir.name) / "ossec.conf"
        target.write_text("""<ossec_config>
  <command><name>firewall-drop</name><executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed><expect>srcip</expect></command>
  <active-response><disabled>no</disabled><command>orangebox-yara</command>
    <location>local</location><rules_id>10420,10421</rules_id></active-response>
  <active-response><disabled>no</disabled><command>orangebox-quarantine</command>
    <location>local</location><rules_id>99901</rules_id></active-response>
  <active-response><disabled>no</disabled><command>firewall-drop</command>
    <location>local</location><rules_id>10460,10461,10462,10463</rules_id><timeout>2592000</timeout>
  </active-response>
  <cluster><nodes><node>NODE_IP</node></nodes></cluster>
</ossec_config>
""", encoding="utf-8")

        self.assertTrue(patch_config(target))
        first = target.read_text(encoding="utf-8")
        self.assertIn("<node>NODE_IP</node>", first)
        self.assertIn("<rules_id>10420,10421</rules_id>", first)
        self.assertIn("<rules_id>99901</rules_id>", first)
        self.assertNotIn("<rules_id>10460,10461,10462,10463</rules_id>", first)

        root = ET.parse(target).getroot()
        policies = []
        # Recorre bloques Active Response para localizar y modificar únicamente los IOC.
        for block in root.iter("active-response"):
            if (block.findtext("command") or "").strip() != "firewall-drop":
                continue
            ids = {x.strip() for x in (block.findtext("rules_id") or "").split(",") if x.strip()}
            if ids & {"99905", "99906", "10053"}:
                policies.append((ids, (block.findtext("timeout") or "").strip()))

        seven_ids = {"10460", "10461", "10462", "10463", "99903", "99904", "99905",
                     "99907", "99908", "99911", "99912", "99913", "99914"}
        self.assertIn((seven_ids, "604800"), policies)
        self.assertIn(({"99906", "10053"}, "2592000"), policies)
        self.assertFalse(patch_config(target))
        self.assertEqual(first, target.read_text(encoding="utf-8"))

    def test_patcher_migrates_the_current_deployed_99906_block(self):
        """Valida la migración del bloque de explotación web de la política anterior."""
        target = self.write_config("""<ossec_config>
  <active-response><disabled>no</disabled><command>firewall-drop</command>
    <location>local</location>
    <rules_id>10460,10461,10462,10463,99903,99904,99905,99907,99908,99911,99912,99913,99914</rules_id>
    <timeout>604800</timeout>
  </active-response>
  <active-response><disabled>no</disabled><command>firewall-drop</command>
    <location>local</location><rules_id>99906</rules_id><timeout>2592000</timeout>
  </active-response>
</ossec_config>""")
        self.assertTrue(patch_config(target))
        updated = Path(target).read_text(encoding="utf-8")
        self.assertIn("<rules_id>99906,10053</rules_id>", updated)
        self.assertFalse(patch_config(target))

    def test_live_config_patcher_aborts_on_unexpected_selector_drift(self):
        """Impide sobrescribir una política que cambió de forma inesperada."""
        config = self.write_config("""<ossec_config>
  <active-response><disabled>no</disabled><command>firewall-drop</command>
    <location>local</location><rules_id>10460,10461,10462</rules_id><timeout>2592000</timeout>
  </active-response>
</ossec_config>""")
        original = Path(config).read_text(encoding="utf-8")
        with self.assertRaises(RuntimeError):
            patch_config(config)
        self.assertEqual(original, Path(config).read_text(encoding="utf-8"))

    def test_live_config_patcher_supports_concatenated_ossec_config_fragments(self):
        """Comprueba que el patcher acepte fragmentos concatenados de ossec.conf."""
        config = self.write_config("""<ossec_config>
  <command><name>firewall-drop</name><executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed><expect>srcip</expect></command>
  <active-response><disabled>no</disabled><command>orangebox-yara</command>
    <location>local</location><rules_id>10420,10421</rules_id></active-response>
</ossec_config>
<ossec_config>
  <active-response><disabled>no</disabled><command>firewall-drop</command>
    <location>local</location><rules_id>10460,10461,10462,10463</rules_id><timeout>2592000</timeout>
  </active-response>
</ossec_config>
""")
        self.assertTrue(patch_config(config))
        patched = Path(config).read_text(encoding="utf-8")
        wrapped = ET.fromstring("<test-root>" + patched + "</test-root>")
        self.assertEqual(len(wrapped.findall("ossec_config")), 2)
        self.assertIn("<rules_id>99906,10053</rules_id>", patched)
        self.assertFalse(patch_config(config))

    def test_rule_99906_and_10053_share_exact_30_day_policy(self):
        """Garantiza que ambas reglas de explotación de alta confianza usen 30 días."""
        # Verifica por separado ambos SID que comparten el bloqueo de 30 días.
        for rule_id in ("99906", "10053"):
            result = firewall_drop_policy_for_alert(
                rule_id, 14, ["web", "accesslog"], str(MANAGER_CONF)
            )
            self.assertEqual(result["status"], "configured")
            self.assertEqual(result["timeout_seconds"], 2592000)
            self.assertEqual(result["matched_by"], [f"rules_id:{rule_id}"])



class LongUnixOastUrlDetectionTests(unittest.TestCase):
    """La regla hija de 31115 bloquea el patrón unix: + callback OAST, no URLs largas genéricas."""

    @classmethod
    def setUpClass(cls):
        path = REPO_ROOT / "configuration" / "manager" / "etc" / "rules" / "orangebox-web.xml"
        root = ET.fromstring("<rules-root>" + path.read_text(encoding="utf-8") + "</rules-root>")
        cls.rules = {rule.get("id"): rule for rule in root.iter("rule")}

    def test_rule_is_specific_child_of_native_31115(self):
        rule = self.rules["10055"]
        self.assertEqual(rule.get("level"), "14")
        self.assertEqual(rule.findtext("if_sid"), "31115")
        url = rule.find("url")
        self.assertEqual(url.get("type"), "pcre2")
        pattern = re.compile(url.text or "")
        sample = "/?unix:" + ("A" * 8000) + "|http://dbn6jkvepiejmmgatd50c11g5wc1uzxcz.oast.online/"
        self.assertRegex(sample, pattern)
        self.assertNotRegex("/?unix:" + ("A" * 8000), pattern)
        self.assertNotRegex("/?q=" + ("A" * 8000) + "|http://probe.oast.online/", pattern)
        self.assertNotRegex("/?unix:short|http://probe.oast.online/", pattern)

    def test_rule_excludes_validated_proxies_and_uses_shared_auto_block_group(self):
        rule = self.rules["10055"]
        proxy = rule.find("list")
        self.assertEqual(proxy.get("field"), "srcip")
        self.assertEqual(proxy.get("lookup"), "not_address_match_key")
        self.assertEqual(proxy.text, "etc/lists/orangebox-web-discovery-proxies")
        self.assertIn("orangebox_web_auto_block", rule.findtext("group") or "")
        self.assertIn("orangebox_immediate", rule.findtext("group") or "")

    def test_rule_id_is_unique(self):
        count = 0
        for path in (REPO_ROOT / "configuration" / "manager" / "etc" / "rules").glob("*.xml"):
            root = ET.fromstring("<rules-root>" + path.read_text(encoding="utf-8") + "</rules-root>")
            count += sum(1 for rule in root.iter("rule") if rule.get("id") == "10055")
        self.assertEqual(count, 1)




if __name__ == "__main__":
    unittest.main(verbosity=2)
