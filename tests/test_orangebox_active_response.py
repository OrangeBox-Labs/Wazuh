#!/usr/bin/env python3
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_DIR = REPO_ROOT / "configuration" / "manager" / "integrations"
sys.path.insert(0, str(INTEGRATION_DIR))

from orangebox_active_response import firewall_drop_policy_for_alert
PATCHER_PATH = REPO_ROOT / "tools" / "patch-ioc-active-response-conf.py"
PATCHER_SPEC = importlib.util.spec_from_file_location("patch_ioc_active_response_conf", PATCHER_PATH)
PATCHER_MODULE = importlib.util.module_from_spec(PATCHER_SPEC)
PATCHER_SPEC.loader.exec_module(PATCHER_MODULE)
patch_config = PATCHER_MODULE.patch_config


MANAGER_CONF = REPO_ROOT / "configuration" / "manager" / "etc" / "ossec.conf"


class FirewallDropPolicyTests(unittest.TestCase):
    def write_config(self, content):
        tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_repo_policy_ioc_durations(self):
        expected = {
            "10460": 604800, "10461": 604800, "10462": 604800, "10463": 604800,
            "99903": 604800, "99904": 604800, "99905": 604800, "99907": 604800,
            "99908": 604800, "99911": 604800, "99912": 604800, "99913": 604800,
            "99914": 604800, "99906": 2592000, "10053": 2592000,
        }
        for rule_id, timeout in expected.items():
            with self.subTest(rule_id=rule_id):
                result = firewall_drop_policy_for_alert(rule_id, 14, [], str(MANAGER_CONF))
                self.assertEqual(result["status"], "configured")
                self.assertEqual(result["timeout_seconds"], timeout)
                self.assertEqual(result["location"], "local")

    def test_rules_id_rules_group_and_level_are_or_selectors(self):
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
        for rule_id, level, groups, expected, selector in cases:
            with self.subTest(rule_id=rule_id, level=level, groups=groups):
                result = firewall_drop_policy_for_alert(rule_id, level, groups, config)
                self.assertEqual(result["status"] == "configured", expected)
                if expected:
                    self.assertTrue(any(selector in item for item in result["matched_by"]))

    def test_rules_group_trailing_comma_requires_exact_match(self):
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
        config = self.write_config("""<ossec_config>
  <active-response><disabled>no</disabled><command>firewall-drop</command>
    <location>local</location><rules_group>web</rules_group><timeout>300</timeout>
  </active-response>
</ossec_config>""")
        result = firewall_drop_policy_for_alert("10", 5, ["web_shell"], config)
        self.assertEqual(result["status"], "configured")

    def test_disabled_response_is_not_reported_as_configured(self):
        config = self.write_config("""<ossec_config>
  <active-response><disabled>yes</disabled><command>firewall-drop</command>
    <location>local</location><rules_id>99906</rules_id><timeout>2592000</timeout>
  </active-response>
</ossec_config>""")
        result = firewall_drop_policy_for_alert("99906", 14, [], config)
        self.assertEqual(result["status"], "not_configured")

    def test_wrong_command_is_not_reported_as_firewall_drop(self):
        config = self.write_config("""<ossec_config>
  <active-response><disabled>no</disabled><command>orangebox-yara</command>
    <location>local</location><rules_id>99906</rules_id><timeout>2592000</timeout>
  </active-response>
</ossec_config>""")
        result = firewall_drop_policy_for_alert("99906", 14, [], config)
        self.assertEqual(result["status"], "not_configured")

    def test_missing_or_invalid_config_is_unknown_not_not_configured(self):
        missing = firewall_drop_policy_for_alert("99906", 14, [], "/does/not/exist")
        invalid_path = self.write_config("<ossec_config><active-response>")
        invalid = firewall_drop_policy_for_alert("99906", 14, [], invalid_path)
        self.assertEqual(missing["status"], "unknown")
        self.assertEqual(invalid["status"], "unknown")

    def test_live_config_patcher_changes_only_ioc_blocks_and_is_idempotent(self):
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
        for rule_id in ("99906", "10053"):
            result = firewall_drop_policy_for_alert(
                rule_id, 14, ["web", "accesslog"], str(MANAGER_CONF)
            )
            self.assertEqual(result["status"], "configured")
            self.assertEqual(result["timeout_seconds"], 2592000)
            self.assertEqual(result["matched_by"], [f"rules_id:{rule_id}"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
