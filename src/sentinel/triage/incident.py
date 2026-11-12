from typing import List
from sentinel.core.models import Alert


class IncidentTriageReport:
    """
    Transforms raw detection alerts into actionable SOC Incident Dossiers.
    Designed for instant handoff to Tier 2/3 SOC and Incident Responders.
    """

    @staticmethod
    def generate_markdown_dossier(alert: Alert) -> str:
        data = alert.matched_event.data
        user = data.get("user") or data.get("User") or data.get("userName") or "Unknown"
        host = data.get("computer_name") or data.get("host") or data.get("recipientAccountId") or "Unknown"

        lines = [
            f"# 🚨 SOC INCIDENT REPORT: {alert.rule_title.upper()}",
            f"**Alert ID**: `{alert.alert_id}` | **Severity**: `{alert.severity}` | **Source**: `{alert.matched_event.event_source}`",
            f"**Timestamp**: `{alert.timestamp}` | **Target Host**: `{host}` | **Target User**: `{user}`",
            "",
            "## 🎯 MITRE ATT&CK Mapping",
            f"- **Techniques**: {', '.join(alert.mitre_techniques) if alert.mitre_techniques else 'None specified'}",
            "",
            "## 🔍 Extracted Indicators of Compromise (IOCs)",
        ]

        if alert.extracted_iocs.get("ips"):
            lines.append(f"- **External IP Addresses**: `{', '.join(alert.extracted_iocs['ips'])}`")
        if alert.extracted_iocs.get("hashes"):
            lines.append(f"- **Payload Hashes**: `{', '.join(alert.extracted_iocs['hashes'])}`")
        if not alert.extracted_iocs.get("ips") and not alert.extracted_iocs.get("hashes"):
            lines.append("- *No external network or file hash IOCs extracted from payload.*")

        lines.extend([
            "",
            "## 📋 Recommended Containment & IR Playbook Steps",
        ])

        if alert.containment_playbook:
            for idx, step in enumerate(alert.containment_playbook, start=1):
                lines.append(f"{idx}. {step}")
        else:
            lines.append("1. Escalate to on-call Incident Responder.")
            lines.append("2. Preserve host volatility state / volatile memory.")

        lines.extend([
            "",
            "## 📦 Raw Event Artifact Details",
            "```json",
            str(data),
            "```",
        ])

        return "\n".join(lines)
