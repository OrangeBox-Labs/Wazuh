#!/usr/bin/env python3
"""Regression tests for centrally managed Zimbra/Carbonio mail log sources."""

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "configuration/manager/etc/shared/zimbra/agent.conf"
MAIL_RULES = ROOT / "configuration/manager/etc/rules/orangebox-mail.xml"

MTA_SOURCES = {
    "/var/log/zimbra.log",
    "/var/log/carbonio.log",
    "/var/log/maillog",
}
CLAMD_SOURCES = {"/opt/z*/log/clamd.log"}
FRESHCLAM_SOURCES = {"/opt/z*/log/freshclam.log"}
EXPECTED_SOURCES = MTA_SOURCES | CLAMD_SOURCES | FRESHCLAM_SOURCES

EXPECTED_MTA_RESTRICT = (
    r"(?i)(?:^|\s)(?:postfix/(?:smtpd|smtps/smtpd|submission/smtpd|"
    r"cleanup|qmgr|smtp|lmtp|anvil|amavisd/smtpd|pickup|local|virtual|"
    r"error|bounce)|amavis(?:d)?|spamd|clamd|freshclam)(?:\[\d+\])?:"
)
EXPECTED_MTA_IGNORES = [
    r"(?i)postfix/dkimmilter/",
    r"(?i)postfix/(?:submission/|smtps/)?smtpd\[\d+\]:\s*(?:[0-9a-f]{4}\s+(?:[0-9a-f]{2}\s*){1,16}(?:\||$)|read from\b|write to\b|SSL_accept:|.*Issuing session ticket)",
]
EXPECTED_CLAMD_RESTRICT = r"(?i)\b(?:FOUND|ERROR|WARNING)\b"
EXPECTED_FRESHCLAM_RESTRICT = (
    r"(?i)(?:\bERROR:|WARNING:.*"
    r"(?:OUTDATED|update process failed|database.*(?:failed|not updated)))"
)

SMTP_SHELL_PAYLOAD = re.compile(
    r"(?i)NOQUEUE:\s*reject:\s*RCPT\b.*"
    r"(?:\$\(|\$\{IFS\}).*base64.*\|\s*(?:sh|bash)\b"
)
AMAVIS_VERDICT = re.compile(
    r"(?i)\b(?:Passed|Blocked)\s+(?:CLEAN|INFECTED|BANNED|SPAM)\b"
)
CLAMD_FOUND = re.compile(r"(?i)\bFOUND\b")
FRESHCLAM_FATAL = re.compile(
    r"(?i)(?:\bERROR:|WARNING:.*"
    r"(?:OUTDATED|update process failed|database.*(?:failed|not updated)))"
)


class ZimbraMailLogSourcesTests(unittest.TestCase):
    def _sources(self):
        root = ET.parse(PROFILE).getroot()
        sources = {}
        for localfile in root.findall("localfile"):
            location = localfile.findtext("location")
            if location:
                sources[location] = localfile
        return sources

    def _rules(self):
        xml = MAIL_RULES.read_text(encoding="utf-8")
        return ET.fromstring("<ruleset>" + xml + "</ruleset>")

    def test_expected_mta_and_antivirus_sources_are_collected(self):
        sources = self._sources()
        self.assertEqual(set(sources), EXPECTED_SOURCES)

        for location in MTA_SOURCES:
            with self.subTest(location=location):
                localfile = sources[location]
                self.assertEqual(localfile.findtext("log_format"), "syslog")
                self.assertEqual(
                    localfile.findtext("only-future-events"), "yes"
                )
                self.assertEqual(
                    localfile.findtext("restrict"), EXPECTED_MTA_RESTRICT
                )
                ignores = [node.text for node in localfile.findall("ignore")]
                self.assertEqual(ignores, EXPECTED_MTA_IGNORES)
                self.assertIsNone(localfile.find("command"))
                self.assertIsNone(localfile.find("full_command"))

        for location in CLAMD_SOURCES:
            with self.subTest(location=location):
                localfile = sources[location]
                self.assertEqual(localfile.findtext("log_format"), "syslog")
                self.assertEqual(
                    localfile.findtext("only-future-events"), "yes"
                )
                self.assertEqual(
                    localfile.findtext("restrict"), EXPECTED_CLAMD_RESTRICT
                )

        for location in FRESHCLAM_SOURCES:
            with self.subTest(location=location):
                localfile = sources[location]
                self.assertEqual(localfile.findtext("log_format"), "syslog")
                self.assertEqual(
                    localfile.findtext("only-future-events"), "yes"
                )
                self.assertEqual(
                    localfile.findtext("restrict"), EXPECTED_FRESHCLAM_RESTRICT
                )

    def test_process_filter_accepts_mail_flow_and_authentication(self):
        process_filter = re.compile(EXPECTED_MTA_RESTRICT)
        allowed = [
            "Nov  3 00:03:18 mail postfix/smtpd[318046]: NOQUEUE: filter:",
            "Nov  3 00:03:18 mail postfix/cleanup[318050]: QID: message-id=",
            "Nov  3 00:03:18 mail postfix/qmgr[2792769]: QID: from=<sender>",
            "Nov  3 00:03:20 mail postfix/smtp[318051]: QID: to=<rcpt>",
            "Nov  3 00:03:20 mail postfix/lmtp[318198]: QID: status=sent",
            "Nov  3 00:15:32 mail postfix/submission/smtpd[83176]: "
            "239DE4E55C3: client=unknown[192.0.2.160], "
            "sasl_method=PLAIN, sasl_username=user@example.test",
            "Nov  3 00:32:39 mail amavis[152808]: Passed CLEAN "
            "{RelayedInternal,RelayedOutbound}, Message-ID=<test@example.test>",
        ]
        for line in allowed:
            with self.subTest(allowed=line):
                self.assertRegex(line, process_filter)
                self.assertFalse(
                    any(re.search(pattern, line) for pattern in EXPECTED_MTA_IGNORES)
                )

    def test_dkim_and_submission_tls_debug_are_excluded(self):
        process_filter = re.compile(EXPECTED_MTA_RESTRICT)
        dkim = (
            "Nov  3 00:15:32 mail postfix/dkimmilter/smtpd[121139]: "
            "0590 46 00 48 26 d7 fa f7 37|43 6c c6 b3 bd 6b 01 04"
        )
        self.assertIsNone(process_filter.search(dkim))

        debug_lines = [
            "Nov  3 00:15:32 mail postfix/submission/smtpd[136131]: "
            "06f0 6c a3 f4 ae e4 f1 0e f8|75 4f 0b 03 cb b1 90 c4",
            "Nov  3 00:15:32 mail postfix/submission/smtpd[136131]: "
            "07d0 f9 6b",
            "Nov  3 00:15:32 mail postfix/submission/smtpd[136131]: "
            "read from 023F2B90 [023DD8E3] (5 bytes => 5 (0x5))",
            "Nov  3 00:15:32 mail postfix/submission/smtpd[136131]: "
            "SSL_accept:TLSv1.3 early data",
            "Nov  3 00:15:32 mail postfix/submission/smtpd[136131]: "
            "unknown[192.0.2.160]: Issuing session ticket",
        ]
        ignores = [re.compile(pattern) for pattern in EXPECTED_MTA_IGNORES]
        for line in debug_lines:
            with self.subTest(debug=line):
                self.assertRegex(line, process_filter)
                self.assertTrue(any(pattern.search(line) for pattern in ignores))

    def test_mailbox_logs_and_amavis_temp_trees_are_not_collected(self):
        sources = self._sources()
        forbidden = {
            "/opt/zimbra/log/mailbox.log",
            "/opt/zextras/log/mailbox.log",
            "/opt/zimbra/data/tmp",
            "/opt/zextras/data/tmp",
        }
        self.assertTrue(forbidden.isdisjoint(sources))

    def test_rejected_smtp_shell_payload_matches_but_normal_reject_does_not(self):
        malicious = (
            "Nov  3 00:32:49 mail postfix/smtps/smtpd[370309]: "
            "NOQUEUE: reject: RCPT from unknown[198.51.100.23]: "
            '554 5.7.1 <display;$(echo${IFS}PAYLOAD|base64${IFS}-d|sh)@localhost>: '
            "Recipient address rejected: Access denied"
        )
        ordinary = (
            "Nov  3 00:32:49 mail postfix/smtps/smtpd[370309]: "
            "NOQUEUE: reject: RCPT from unknown[198.51.100.23]: "
            "554 5.7.1 <user@example.test>: Recipient address rejected: Access denied"
        )
        self.assertRegex(malicious, SMTP_SHELL_PAYLOAD)
        self.assertNotRegex(ordinary, SMTP_SHELL_PAYLOAD)

    def test_amavis_verdicts_separate_clean_from_security_events(self):
        clean = "amavis[100]: (100-01) Passed CLEAN {RelayedInbound}, Queue-ID: ABC123"
        infected = "amavis[100]: (100-02) Blocked INFECTED (Eicar-Test-Signature), Queue-ID: DEF456"
        banned = "amavis[100]: (100-03) Blocked BANNED (.exe), Queue-ID: GHI789"
        spam = "amavis[100]: (100-04) Passed SPAM {RelayedInbound}, Queue-ID: JKL012"

        self.assertRegex(clean, AMAVIS_VERDICT)
        self.assertNotRegex(clean, re.compile(r"(?i)\b(?:INFECTED|BANNED|SPAM)\b"))
        self.assertRegex(infected, re.compile(r"(?i)\bINFECTED\b"))
        self.assertRegex(banned, re.compile(r"(?i)\bBANNED\b"))
        self.assertRegex(spam, re.compile(r"(?i)\bSPAM\b"))

    def test_clamd_found_and_freshclam_fatal_errors_are_separated(self):
        found = "Tue Nov 3 00:13:19 2026 -> /tmp/scan/file: Eicar-Test-Signature FOUND"
        self_check = "Tue Nov 3 00:13:19 2026 -> SelfCheck: Database status OK."
        incremental_fallback = (
            "WARNING: Incremental update failed, trying to download daily.cvd"
        )
        outdated = "WARNING: Your ClamAV installation is OUTDATED!"
        fatal = "ERROR: Database update process failed: download error"

        self.assertRegex(found, CLAMD_FOUND)
        self.assertNotRegex(self_check, CLAMD_FOUND)
        self.assertNotRegex(incremental_fallback, FRESHCLAM_FATAL)
        self.assertRegex(outdated, FRESHCLAM_FATAL)
        self.assertRegex(fatal, FRESHCLAM_FATAL)

        root = self._rules()
        rules = {
            int(rule.attrib["id"]): rule for rule in root.findall(".//rule")
        }
        self.assertEqual(
            {sid: int(rules[sid].attrib["level"]) for sid in (10702, 10703, 10704, 10705, 10706, 10707, 10708, 10709)},
            {
                10702: 14,
                10703: 0,
                10704: 14,
                10705: 11,
                10706: 8,
                10707: 13,
                10708: 9,
                10709: 9,
            },
        )
        self.assertEqual(
            rules[10702].findtext("program_name"),
            r"^postfix/(?:submission/|smtps/)?smtpd$",
        )
        self.assertEqual(rules[10703].findtext("program_name"), r"^amavis$")
        self.assertIn(
            "no_full_log",
            [x.text for x in rules[10702].findall("options")],
        )
        self.assertFalse(root.findall(".//active-response"))


if __name__ == "__main__":
    unittest.main()
