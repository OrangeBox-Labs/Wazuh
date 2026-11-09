import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "configuration" / "manager" / "etc" / "rules"


class WazuhRuleStructureTests(unittest.TestCase):
    """Reject nested rules that Wazuh's rules loader will not enumerate."""

    def test_each_rule_is_a_direct_child_of_a_named_global_group(self):
        xml_files = sorted(RULES_DIR.glob("*.xml"))
        self.assertTrue(xml_files, "No custom Wazuh rule XML files found")

        for path in xml_files:
            with self.subTest(file=path.name):
                source = path.read_text(encoding="utf-8")
                root = ET.fromstring("<rules_validation_root>" + source + "</rules_validation_root>")
                parents = {
                    child: parent
                    for parent in root.iter()
                    for child in list(parent)
                }

                for rule in root.iter("rule"):
                    parent = parents.get(rule)
                    self.assertIsNotNone(parent, f"Orphan rule in {path.name}")
                    self.assertEqual(
                        parent.tag,
                        "group",
                        f"Rule {rule.get('id')} is nested under <{parent.tag}> in {path.name}",
                    )
                    self.assertIn(
                        "name",
                        parent.attrib,
                        f"Rule {rule.get('id')} is not a direct child of a named global group in {path.name}",
                    )

    def test_web_10055_is_a_sibling_of_10039(self):
        path = RULES_DIR / "orangebox-web.xml"
        source = path.read_text(encoding="utf-8")
        root = ET.fromstring("<rules_validation_root>" + source + "</rules_validation_root>")
        parents = {
            child: parent
            for parent in root.iter()
            for child in list(parent)
        }
        rules = {rule.get("id"): rule for rule in root.iter("rule")}

        self.assertIn("10039", rules)
        self.assertIn("10055", rules)
        self.assertIs(parents[rules["10039"]], parents[rules["10055"]])
        self.assertEqual(parents[rules["10055"]].tag, "group")


if __name__ == "__main__":
    unittest.main(verbosity=2)
