import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "configuration" / "manager" / "integrations" / "custom-orangebox-email.py"


def load_integrated_filter():
    """Load the real filter function without executing the mailer entry point."""
    source = INTEGRATION.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(INTEGRATION))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_is_expected_google_hosts_rewrite"
    )
    module = ast.Module(body=[function], type_ignores=[])
    namespace = {"re": re}
    exec(compile(module, str(INTEGRATION), "exec"), namespace)
    return namespace[function.name]


is_expected_google_hosts_rewrite = load_integrated_filter()

MDS_DIFF = (
    "3d2\n"
    "< 169.254.169.254 metadata.google.internal # Added by Google - MDS\n"
    "4a4\n"
    "> 169.254.169.254 metadata.google.internal # Added by Google - MDS"
)

HOST_DIFF = (
    "3d2\n"
    "< 192.0.2.21 web01.example.invalid neo-webserver # Added by Google - Hostname\n"
    "4a4\n"
    "> 192.0.2.21 web01.example.invalid neo-webserver # Added by Google - Hostname"
)


class GoogleHostsEmailIntegrationTests(unittest.TestCase):
    def make_alert(
        self,
        diff=MDS_DIFF,
        mode="whodata",
        process="/usr/bin/sed",
        user="root",
        effective_uid="0",
        path="/etc/hosts",
        rule_id="10036",
    ):
        syscheck = {"path": path, "mode": mode, "diff": diff}
        if process is not None or user is not None or effective_uid is not None:
            syscheck["audit"] = {
                "process": {"name": process} if process is not None else {},
                "user": {"name": user} if user is not None else {},
                "effective_user": {"id": effective_uid} if effective_uid is not None else {},
            }
        return {"rule": {"id": rule_id}, "syscheck": syscheck}

    def test_actual_production_events_are_suppressed_from_email(self):
        sed_event = self.make_alert(
            diff=MDS_DIFF, process="/usr/bin/sed", user="root", effective_uid="0"
        )
        syscheckd_event = self.make_alert(
            diff=HOST_DIFF,
            process="/opt/ossec/bin/wazuh-syscheckd",
            user="root",
            effective_uid="0",
        )
        self.assertTrue(is_expected_google_hosts_rewrite(sed_event))
        self.assertTrue(is_expected_google_hosts_rewrite(syscheckd_event))

    def test_syscheckd_supports_both_deployed_paths(self):
        alert = self.make_alert(diff=HOST_DIFF, process="/opt/ossec/bin/wazuh-syscheckd")
        self.assertTrue(is_expected_google_hosts_rewrite(alert))
        alert["syscheck"]["audit"]["process"]["name"] = "/var/ossec/bin/wazuh-syscheckd"
        self.assertTrue(is_expected_google_hosts_rewrite(alert))

    def test_hostname_rewrite_allows_whitespace_and_google_suffix_normalization(self):
        diff = (
            "3d2\n"
            "< 192.0.2.5\t\tneo-webserver.us-central1-a.c.example.internal hostalias # Added by Google\n"
            "4a4\n"
            "> 192.0.2.5 neo-webserver.us-central1-a.c.example.internal hostalias # Added by Google - Hostname"
        )
        self.assertTrue(is_expected_google_hosts_rewrite(self.make_alert(diff=diff)))

    def test_scheduled_and_realtime_require_the_complete_exact_diff(self):
        for mode in ("scheduled", "realtime"):
            with self.subTest(mode=mode):
                alert = self.make_alert(
                    diff=MDS_DIFF,
                    mode=mode,
                    process=None,
                    user=None,
                    effective_uid=None,
                )
                self.assertTrue(is_expected_google_hosts_rewrite(alert))
                alert["syscheck"]["diff"] = None
                self.assertFalse(is_expected_google_hosts_rewrite(alert))

    def test_real_hosts_changes_are_not_suppressed(self):
        changed_ip = HOST_DIFF.replace("192.0.2.21", "192.0.2.99", 1)
        changed_fqdn = HOST_DIFF.replace("web01.example.invalid", "attacker.example", 1)
        changed_alias = HOST_DIFF.replace("neo-webserver #", "otheralias #", 1)
        for diff in (
            changed_ip,
            changed_fqdn,
            changed_alias,
            HOST_DIFF + "\n> 192.0.2.5 evil.example evil",
        ):
            with self.subTest(diff=diff):
                self.assertFalse(is_expected_google_hosts_rewrite(self.make_alert(diff=diff)))

    def test_unknown_actor_or_identity_is_fail_open(self):
        cases = (
            {"process": "/usr/bin/curl"},
            {"user": "nobody"},
            {"effective_uid": "1000"},
            {"process": None},
            {"user": None},
            {"effective_uid": None},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                values = {
                    "process": "/usr/bin/sed",
                    "user": "root",
                    "effective_uid": "0",
                }
                values.update(overrides)
                self.assertFalse(is_expected_google_hosts_rewrite(self.make_alert(**values)))

    def test_only_rule_10036_and_exact_hosts_path_are_eligible(self):
        self.assertFalse(is_expected_google_hosts_rewrite(self.make_alert(rule_id="10030")))
        self.assertFalse(is_expected_google_hosts_rewrite(self.make_alert(path="/etc/resolv.conf")))
        self.assertFalse(is_expected_google_hosts_rewrite(self.make_alert(mode="other")))
        self.assertFalse(is_expected_google_hosts_rewrite(None))

    def test_missing_diff_is_never_suppressed(self):
        self.assertFalse(is_expected_google_hosts_rewrite(self.make_alert(diff=None)))
        self.assertFalse(is_expected_google_hosts_rewrite(self.make_alert(diff="")))

    def test_filter_is_defined_and_called_inside_existing_integration(self):
        source = INTEGRATION.read_text(encoding="utf-8")
        self.assertIn("def _is_expected_google_hosts_rewrite(alert_json):", source)
        filter_call = source.index("if _is_expected_google_hosts_rewrite(alert_json):")
        normal_flow = source.index("description = alert_json.get(", filter_call)
        self.assertLess(filter_call, normal_flow)
        self.assertNotIn("from orangebox_fim_email_filter", source)

    def test_no_standalone_fim_email_helper_file_exists(self):
        standalone = INTEGRATION.parent / "orangebox_fim_email_filter.py"
        self.assertFalse(standalone.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
