import base64
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Mock external GCP/HTTP dependencies before importing main so tests run in any local environment
sys.modules["requests"] = MagicMock()
sys.modules["google"] = MagicMock()
sys.modules["google.cloud"] = MagicMock()

sys.path.insert(0, os.path.dirname(__file__))
import main  # noqa: E402


def make_cve_payload(
    cve_id="CVE-2021-44228",
    exploitability="WIDE",
    impact="CRITICAL",
    severity="CRITICAL",
    state="ACTIVE",
    project="prod-app-01",
    observed_in_wild=False,
    zero_day=False,
    upstream_fix=True,
    cvss_score=10.0,
):
    return {
        "finding": {
            "name": f"organizations/362295884660/sources/10983767/findings/{cve_id.replace('-', '')}",
            "state": state,
            "severity": severity,
            "findingClass": "VULNERABILITY",
            "category": "SOFTWARE_VULNERABILITY",
            "createTime": "2026-09-25T10:00:00Z",
            "resourceName": f"//compute.googleapis.com/projects/{project}/zones/europe-west1-b/instances/vm-1",
            "vulnerability": {
                "cve": {
                    "id": cve_id,
                    "exploitationActivity": exploitability,
                    "impact": impact,
                    "observedInTheWild": observed_in_wild,
                    "zeroDay": zero_day,
                    "upstreamFixAvailable": upstream_fix,
                    "cvssv3": {"baseScore": cvss_score},
                },
                "offendingPackage": {
                    "packageName": "log4j-core",
                    "version": "2.14.1",
                },
                "fixedPackage": {
                    "packageName": "log4j-core",
                    "version": "2.17.1",
                },
            },
        },
        "resource": {
            "projectDisplayName": project,
            "project": f"//cloudresourcemanager.googleapis.com/projects/{project}",
        },
    }


class TestSCCAlertOptimization(unittest.TestCase):
    def setUp(self):
        # Reset deduplication cache and default rules before each test
        main._RECENT_ALERTS_CACHE.clear()
        main.ALLOWED_EXPLOITABILITY = {"WIDE", "AVAILABLE", "CONFIRMED"}
        main.ALLOWED_CVE_IMPACT = {"CRITICAL", "HIGH"}
        main.REQUIRE_UPSTREAM_FIX = False
        main.DEDUP_WINDOW_SECONDS = 3600

    def test_1_wide_and_critical_cve_alerts(self):
        """Row 1 from screenshot: CVE-2021-44228 (Exploitability=Wide, Impact=Critical) must alert."""
        payload = make_cve_payload(
            cve_id="CVE-2021-44228",
            exploitability="WIDE",
            impact="CRITICAL",
            severity="CRITICAL",
            observed_in_wild=True,
        )
        allowed, reason = main.should_alert(payload)
        self.assertTrue(allowed, f"Expected alert to be allowed, got: {reason}")
        self.assertEqual(reason, "Alert matched criteria")

    def test_2_available_and_high_cve_alerts(self):
        """Row 2 from screenshot: CVE-2025-15467 (Exploitability=Available, Impact=High) must alert."""
        payload = make_cve_payload(
            cve_id="CVE-2025-15467",
            exploitability="AVAILABLE",
            impact="HIGH",
            severity="HIGH",
        )
        allowed, reason = main.should_alert(payload)
        self.assertTrue(allowed, f"Expected alert to be allowed, got: {reason}")

    def test_3_no_known_exploitability_blocked(self):
        """Row 3 from screenshot: CVE-2026-45447 (Exploitability=No known, Impact=High, 1698 findings) must be dropped."""
        payload = make_cve_payload(
            cve_id="CVE-2026-45447",
            exploitability="NO_KNOWN",
            impact="HIGH",
            severity="HIGH",
        )
        allowed, reason = main.should_alert(payload)
        self.assertFalse(allowed)
        self.assertIn("exploitability='NO_KNOWN'", reason)

    def test_4_anticipated_exploitability_blocked(self):
        """CVEs with ANTICIPATED exploitability (not yet Available or Wide) must be dropped."""
        payload = make_cve_payload(
            cve_id="CVE-2022-23307",
            exploitability="ANTICIPATED",
            impact="CRITICAL",
            severity="CRITICAL",
        )
        allowed, reason = main.should_alert(payload)
        self.assertFalse(allowed)
        self.assertIn("exploitability='ANTICIPATED'", reason)

    def test_5_medium_or_low_impact_cve_blocked(self):
        """CVEs with WIDE/AVAILABLE exploitability but MEDIUM/LOW impact must be dropped."""
        payload = make_cve_payload(
            cve_id="CVE-2023-0001",
            exploitability="AVAILABLE",
            impact="MEDIUM",
            severity="HIGH",
        )
        allowed, reason = main.should_alert(payload)
        self.assertFalse(allowed)
        self.assertIn("impact='MEDIUM'", reason)

    def test_6_inactive_finding_blocked(self):
        """Findings with state=INACTIVE must be dropped even if severity=HIGH (fixes boolean precedence bug)."""
        payload = make_cve_payload(
            cve_id="CVE-2021-44228",
            exploitability="WIDE",
            impact="CRITICAL",
            severity="HIGH",
            state="INACTIVE",
        )
        allowed, reason = main.should_alert(payload)
        self.assertFalse(allowed)
        self.assertIn("Skipped inactive finding", reason)

    def test_7_burst_deduplication_suppresses_2085_findings_across_organization(self):
        """Simulates 2,085 findings for CVE-2025-15467 across multiple projects in the org; only 1 Slack alert should fire."""
        sent_count = 0
        suppressed_count = 0
        for i in range(2085):
            # Spread findings across 20 different projects inside the same GCP organization
            project_name = f"prod-cluster-{i % 20:02d}"
            payload = make_cve_payload(
                cve_id="CVE-2025-15467",
                exploitability="AVAILABLE",
                impact="HIGH",
                severity="HIGH",
                project=project_name,
            )
            payload["finding"]["name"] = f"organizations/362295884660/sources/109/findings/f-{i}"
            payload["finding"]["resourceName"] = f"//container.googleapis.com/projects/{project_name}/pods/pod-{i}"
            allowed, _ = main.should_alert(payload)
            if allowed:
                sent_count += 1
            else:
                suppressed_count += 1

        self.assertEqual(sent_count, 1, "Only 1 organization-wide alert should fire for CVE-2025-15467")
        self.assertEqual(suppressed_count, 2084, "Remaining 2,084 duplicate findings across all projects in the org must be suppressed")

    def test_8_require_upstream_fix_toggle(self):
        """When REQUIRE_UPSTREAM_FIX=true, unpatched CVEs are suppressed until a fix exists."""
        main.REQUIRE_UPSTREAM_FIX = True
        unpatched = make_cve_payload(
            cve_id="CVE-2026-9999",
            exploitability="WIDE",
            impact="CRITICAL",
            upstream_fix=False,
        )
        allowed, reason = main.should_alert(unpatched)
        self.assertFalse(allowed)
        self.assertIn("no upstream fix available yet", reason)

    def test_9_slack_template_rendering_for_cve_and_non_cve(self):
        """Verifies Slack Block Kit template renders all placeholders cleanly without 'null' or raw tags."""
        template_path = os.path.join(
            os.path.dirname(__file__), "block_templates", "finding-detail.json"
        )
        # 9a. CVE payload
        with open(template_path, "rt") as f:
            cve_blocks = json.load(f)
        cve_payload = make_cve_payload(
            cve_id="CVE-2021-44228",
            exploitability="WIDE",
            impact="CRITICAL",
            observed_in_wild=True,
            zero_day=True,
            upstream_fix=True,
            cvss_score=10.0,
        )
        main.merge_template(cve_blocks, cve_payload)
        serialized_cve = json.dumps(cve_blocks)
        self.assertIn("*[WIDE EXPLOIT | CRITICAL IMPACT]*", serialized_cve)
        self.assertIn("CVE-2021-44228", serialized_cve)
        self.assertIn("Observed in the Wild, Zero-Day", serialized_cve)
        self.assertIn("log4j-core", serialized_cve)
        self.assertIn("2.17.1", serialized_cve)
        self.assertNotIn("<ALERT_BADGE>", serialized_cve)
        self.assertNotIn("<CVE_CONTEXT>", serialized_cve)
        self.assertNotIn("null", serialized_cve)

        # 9b. Non-CVE misconfiguration payload (payload_test.json)
        with open(template_path, "rt") as f:
            misc_blocks = json.load(f)
        with open(os.path.join(os.path.dirname(__file__), "payload_test.json"), "rt") as f:
            misc_payload = json.load(f)
        main.merge_template(misc_blocks, misc_payload)
        serialized_misc = json.dumps(misc_blocks)
        self.assertIn("PRIVATE_GOOGLE_ACCESS_DISABLED", serialized_misc)
        self.assertNotIn("<ALERT_BADGE>", serialized_misc)
        self.assertNotIn("<CVE_CONTEXT>", serialized_misc)

    @patch("main.get_secret", return_value="xoxb-test-token")
    def test_10_end_to_end_pubsub_entrypoint(self, _mock_secret):
        """Tests send_slack_chat_notification with a base64 Pub/Sub event."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"ok": true}'
        main.requests.post.reset_mock()
        main.requests.post.return_value = mock_response

        # Send valid exploitable CVE via Pub/Sub event
        valid_payload = make_cve_payload(
            cve_id="CVE-2021-44228", exploitability="WIDE", impact="CRITICAL"
        )
        event = {
            "data": base64.b64encode(json.dumps(valid_payload).encode("utf-8"))
        }
        main.send_slack_chat_notification(event, None)
        self.assertEqual(main.requests.post.call_count, 1)

        # Send noisy NO_KNOWN CVE via Pub/Sub event -> should NOT call requests.post
        noisy_payload = make_cve_payload(
            cve_id="CVE-2026-45447", exploitability="NO_KNOWN", impact="HIGH"
        )
        noisy_event = {
            "data": base64.b64encode(json.dumps(noisy_payload).encode("utf-8"))
        }
        main.send_slack_chat_notification(noisy_event, None)
        self.assertEqual(
            main.requests.post.call_count,
            1,
            "Noisy CVE should be dropped before calling Slack API",
        )

    def test_11_non_cve_critical_and_high_findings_still_alert(self):
        """Verifies THREAT, MISCONFIGURATION, TOXIC_COMBINATION, and non-CVE VULNERABILITY findings still alert."""
        # 11a. Critical THREAT (e.g., Event Threat Detection)
        threat_payload = {
            "finding": {
                "name": "organizations/362/sources/109/findings/threat-1",
                "state": "ACTIVE",
                "severity": "CRITICAL",
                "findingClass": "THREAT",
                "category": "EXECUTION:ADDED_BINARY_EXECUTED",
            },
            "resource": {"projectDisplayName": "prod-app-01"},
        }
        allowed_threat, _ = main.should_alert(threat_payload)
        self.assertTrue(allowed_threat, "Critical THREAT finding must still alert")

        # 11b. High MISCONFIGURATION (e.g., Security Health Analytics payload_test.json)
        with open(os.path.join(os.path.dirname(__file__), "payload_test.json"), "rt") as f:
            misconfig_payload = json.load(f)
        allowed_misconfig, _ = main.should_alert(misconfig_payload)
        self.assertTrue(allowed_misconfig, "High MISCONFIGURATION finding must still alert")

        # 11c. Critical Web Security Scanner VULNERABILITY without a CVE ID (e.g., SQL_INJECTION / XSS)
        web_vuln_payload = {
            "finding": {
                "name": "organizations/362/sources/109/findings/wss-1",
                "state": "ACTIVE",
                "severity": "CRITICAL",
                "findingClass": "VULNERABILITY",
                "category": "SQL_INJECTION",
            },
            "resource": {"projectDisplayName": "prod-app-01"},
        }
        allowed_web_vuln, _ = main.should_alert(web_vuln_payload)
        self.assertTrue(allowed_web_vuln, "Non-CVE Critical VULNERABILITY (like SQLi/XSS) must still alert")


if __name__ == "__main__":
    unittest.main(verbosity=2)
