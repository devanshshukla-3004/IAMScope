from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from iamscope.engine import analyze_policy, diff_policies


def read_json(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Cannot read {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="iamscope", description="Offline IAM policy risk analyzer")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="Analyze one IAM policy JSON file")
    analyze.add_argument("policy")
    analyze.add_argument("--format", choices=["text", "json"], default="text")
    diff = sub.add_parser("diff", help="Compare two IAM policy JSON files")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            result = analyze_policy(read_json(args.policy), policy_name=Path(args.policy).name)
            if args.format == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"IAMScope analysis: {result['policy_name']}")
                print(f"Statements: {result['statement_count']} | Findings: {result['finding_count']}")
                for finding in result["findings"]:
                    print(f"[{finding['severity'].upper()}] {finding['rule_id']} — {finding['title']}")
                    print(f"  {finding['message']}")
                    print(f"  Fix: {finding['remediation']}")
                print("\n" + result["disclaimer"])
        else:
            result = diff_policies(read_json(args.before), read_json(args.after))
            if args.format == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"Added statements: {result['added_count']}")
                print(f"Removed statements: {result['removed_count']}")
                for statement in result["added_statements"]:
                    print("+ " + json.dumps(statement, sort_keys=True))
                for statement in result["removed_statements"]:
                    print("- " + json.dumps(statement, sort_keys=True))
        return 0
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
