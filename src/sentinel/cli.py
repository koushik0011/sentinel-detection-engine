import argparse
import json
import sys
from pathlib import Path
from typing import List

from sentinel.core.models import SecurityEvent
from sentinel.rules.engine import RuleEngine
from sentinel.triage.incident import IncidentTriageReport
from sentinel.coverage.mitre import MitreCoverageReport


def load_events(telemetry_file: Path) -> List[SecurityEvent]:
    events = []
    with open(telemetry_file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if "event_id" not in item:
                item["event_id"] = f"evt-{idx+1}"
            events.append(SecurityEvent(**item))
    return events


def cmd_test_rules(rules_dir: Path, telemetry_dir: Path, matrix_output: Path = None):
    engine = RuleEngine()
    rules = engine.load_rules_from_dir(rules_dir)
    print(f"\n🛡️ [Sentinel] Loaded {len(rules)} Detection Rules from {rules_dir}")

    tp_file = telemetry_dir / "true_positives.jsonl"
    fp_file = telemetry_dir / "benign_baseline.jsonl"

    if not tp_file.exists():
        print(f"Error: Missing true positive telemetry dataset at {tp_file}", file=sys.stderr)
        return 1

    tp_events = load_events(tp_file)
    fp_events = load_events(fp_file) if fp_file.exists() else []

    print(f"Testing across {len(tp_events)} Attack Events and {len(fp_events)} Benign Baseline Events...\n")

    passed_rules = 0
    print("=" * 70)
    print("                 DETECTION RULE TEST REPORT")
    print("=" * 70)

    for rule in rules:
        # Check true positives (must fire at least once on intended attack telemetry)
        tp_hits = sum(1 for e in tp_events if engine.evaluate_rule(rule, e))
        # Check false positives (must NEVER fire on benign baseline telemetry)
        fp_hits = sum(1 for e in fp_events if engine.evaluate_rule(rule, e))

        passed = (tp_hits > 0) and (fp_hits == 0)
        status_icon = "✅ PASS" if passed else "❌ FAIL"
        if passed:
            passed_rules += 1

        print(f"[{status_icon}] {rule.id.ljust(24)} | TP: {tp_hits} | FP: {fp_hits} | {rule.title}")

    print("=" * 70)
    print(f"Summary: {passed_rules}/{len(rules)} Rules Passed Verification ({passed_rules/len(rules)*100:.1f}%)")

    if matrix_output:
        md = MitreCoverageReport.generate_markdown(rules)
        with open(matrix_output, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"📄 [Sentinel] Generated MITRE ATT&CK matrix: {matrix_output}")

    return 0 if passed_rules == len(rules) else 1


def cmd_matrix(rules_dir: Path, output_file: Path):
    engine = RuleEngine()
    rules = engine.load_rules_from_dir(rules_dir)
    md = MitreCoverageReport.generate_markdown(rules)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"\n🎯 [Sentinel] MITRE ATT&CK Enterprise Matrix exported to: {output_file}")
    print(f"Total Rules Mapped: {len(rules)}")
    return 0


def cmd_replay(rules_dir: Path, telemetry_file: Path):
    engine = RuleEngine()
    engine.load_rules_from_dir(rules_dir)
    events = load_events(telemetry_file)

    print(f"\n🔍 [Sentinel] Replaying {len(events)} security telemetry logs...")
    alerts = []
    for event in events:
        alerts.extend(engine.process_event(event))

    print(f"Generated {len(alerts)} high-fidelity security alerts!\n")
    for alert in alerts:
        dossier = IncidentTriageReport.generate_markdown_dossier(alert)
        print(dossier)
        print("\n" + "-" * 70 + "\n")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Sentinel Detection Engine & DaC Harness")
    subparsers = parser.add_subparsers(dest="command", required=True)

    test_parser = subparsers.add_parser("test", help="Test detection rules against telemetry")
    test_parser.add_argument("--rules", type=Path, default=Path("rules"), help="Rules directory")
    test_parser.add_argument("--telemetry", type=Path, default=Path("tests/telemetry"), help="Telemetry directory")
    test_parser.add_argument("--matrix-output", type=Path, default=None, help="Generate MITRE ATT&CK coverage markdown file")

    matrix_parser = subparsers.add_parser("matrix", help="Generate MITRE ATT&CK coverage matrix")
    matrix_parser.add_argument("--rules", type=Path, default=Path("rules"), help="Rules directory")
    matrix_parser.add_argument("--output", type=Path, default=Path("MITRE_COVERAGE.md"), help="Output markdown path")

    replay_parser = subparsers.add_parser("replay", help="Replay logs and generate triage dossiers")
    replay_parser.add_argument("--rules", type=Path, default=Path("rules"), help="Rules directory")
    replay_parser.add_argument("--telemetry", type=Path, required=True, help="Path to telemetry .jsonl")

    args = parser.parse_args()

    if args.command == "test":
        sys.exit(cmd_test_rules(args.rules, args.telemetry, args.matrix_output))
    elif args.command == "matrix":
        sys.exit(cmd_matrix(args.rules, args.output))
    elif args.command == "replay":
        sys.exit(cmd_replay(args.rules, args.telemetry))


if __name__ == "__main__":
    main()
