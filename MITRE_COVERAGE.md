# 🎯 MITRE ATT&CK® Enterprise Coverage Matrix
*Generated automatically by Sentinel Detection-as-Code Engine on 2026-11-12 23:04:09 UTC*

## 📊 Executive Coverage Metrics
| Metric | Value |
| :--- | :--- |
| **Active Detection Rules** | `3` |
| **Covered MITRE Techniques** | `4` |
| **Covered Enterprise Tactics** | `5 / 12` |
| **Validation Status** | `100% CI Verified` |

## 🛡️ Tactic & Technique Breakdown
| Tactic | Techniques Covered | Rule Count | Rule IDs |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1078.004` | 1 | [aws-sec-002](rules/) |
| **Execution** | `T1059.001`, `T1105` | 1 | [win-sec-001](rules/) |
| *Persistence* | *None* | 0 | - |
| **Privilege Escalation** | `T1078.004` | 1 | [aws-sec-002](rules/) |
| *Defense Evasion* | *None* | 0 | - |
| **Credential Access** | `T1003.008` | 1 | [lnx-sec-003](rules/) |
| *Discovery* | *None* | 0 | - |
| *Lateral Movement* | *None* | 0 | - |
| *Collection* | *None* | 0 | - |
| **Command and Control** | `T1059.001`, `T1105` | 1 | [win-sec-001](rules/) |
| *Exfiltration* | *None* | 0 | - |
| *Impact* | *None* | 0 | - |

## 📝 Technique Details & Rule Mapping
| Technique | Technique Name / Rule Title | Severity | Log Source |
| :--- | :--- | :--- | :--- |
| `T1003.008` | **Unauthorized Access to Sensitive Credential File (/etc/shadow)** | `HIGH` | `linux` |
| `T1059.001` | **Suspicious PowerShell Download Cradle Execution** | `HIGH` | `windows` |
| `T1078.004` | **AWS Root Account Console Login Without MFA** | `CRITICAL` | `aws` |
| `T1105` | **Suspicious PowerShell Download Cradle Execution** | `HIGH` | `windows` |
