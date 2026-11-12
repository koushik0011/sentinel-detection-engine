import os
import re
import uuid
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import yaml
except ImportError:
    yaml = None

from sentinel.core.models import SecurityEvent, DetectionRule, Alert


def _parse_yaml_fallback(text: str) -> Dict[str, Any]:
    """Lightweight standalone fallback YAML parser for simple detection rules."""
    result = {}
    current_key = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.strip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if indent == 0 and ":" in stripped:
            k, v = stripped.split(":", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            current_key = k
            if v:
                result[k] = v
        elif indent > 0 and current_key:
            if stripped.startswith("- "):
                val = stripped[2:].strip().strip('"').strip("'")
                if current_key not in result or not isinstance(result[current_key], list):
                    result[current_key] = []
                result[current_key].append(val)
            elif ":" in stripped:
                sub_k, sub_v = stripped.split(":", 1)
                sub_k = sub_k.strip()
                sub_v = sub_v.strip().strip('"').strip("'")
                if current_key not in result or not isinstance(result[current_key], dict):
                    result[current_key] = {}
                result[current_key][sub_k] = sub_v

    return result


class RuleEngine:
    """
    Evaluates raw security telemetry events against Detection-as-Code rules.
    Performs field evaluation, substring/regex matching, and IOC extraction.
    """

    IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
    MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")

    def __init__(self):
        self.rules: Dict[str, DetectionRule] = {}

    def load_rule_from_file(self, file_path: Path) -> DetectionRule:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_text = f.read()

        if file_path.suffix.lower() == ".json":
            content = json.loads(raw_text)
        elif yaml is not None:
            content = yaml.safe_load(raw_text)
        else:
            content = _parse_yaml_fallback(raw_text)

        rule = DetectionRule(**content)
        self.rules[rule.id] = rule
        return rule

    def load_rules_from_dir(self, directory: Path) -> List[DetectionRule]:
        loaded = []
        for root, _, files in os.walk(directory):
            for file in sorted(files):
                if file.endswith((".yaml", ".yml", ".json")):
                    rule = self.load_rule_from_file(Path(root) / file)
                    loaded.append(rule)
        return loaded

    def _match_field(self, event_value: Any, expected_value: Any) -> bool:
        if event_value is None:
            return False

        if isinstance(expected_value, list):
            return any(self._match_field(event_value, item) for item in expected_value)

        # Normalize path separators for robust cross-platform path matching
        str_event = re.sub(r"[\\/]+", "/", str(event_value).lower())
        str_expected = re.sub(r"[\\/]+", "/", str(expected_value).lower())

        # Wildcard prefix/suffix handling
        if str_expected.startswith("*") and str_expected.endswith("*"):
            return str_expected[1:-1] in str_event
        elif str_expected.startswith("*"):
            return str_event.endswith(str_expected[1:])
        elif str_expected.endswith("*"):
            return str_event.startswith(str_expected[:-1])

        return str_event == str_expected

    def evaluate_rule(self, rule: DetectionRule, event: SecurityEvent) -> bool:
        # Check if event matches rule selection criteria
        for field, expected in rule.selection.items():
            event_val = event.data.get(field)
            if not self._match_field(event_val, expected):
                return False
        return True

    def extract_iocs(self, event: SecurityEvent) -> Dict[str, List[str]]:
        iocs: Dict[str, List[str]] = {"ips": [], "hashes": []}
        for val in event.data.values():
            val_str = str(val)
            ips = self.IPV4_REGEX.findall(val_str)
            for ip in ips:
                if not ip.startswith(("127.", "0.0.0.0")):
                    iocs["ips"].append(ip)

            sha256 = self.SHA256_REGEX.findall(val_str)
            md5 = self.MD5_REGEX.findall(val_str)
            iocs["hashes"].extend(sha256 + md5)

        iocs["ips"] = sorted(list(set(iocs["ips"])))
        iocs["hashes"] = sorted(list(set(iocs["hashes"])))
        return iocs

    def process_event(self, event: SecurityEvent) -> List[Alert]:
        alerts = []
        for rule in self.rules.values():
            if self.evaluate_rule(rule, event):
                iocs = self.extract_iocs(event)
                alert = Alert(
                    alert_id=f"alt-{uuid.uuid4().hex[:8]}",
                    rule_id=rule.id,
                    rule_title=rule.title,
                    severity=rule.severity,
                    mitre_techniques=rule.mitre_techniques,
                    timestamp=event.timestamp,
                    matched_event=event,
                    extracted_iocs=iocs,
                    containment_playbook=rule.containment_playbook,
                )
                alerts.append(alert)
        return alerts
