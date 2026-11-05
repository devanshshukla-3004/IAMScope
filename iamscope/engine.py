from __future__ import annotations

from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from typing import Any
import json


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    evidence: dict[str, Any]
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PRIVILEGE_ACTIONS = {
    "iam:passrole", "iam:putrolepolicy", "iam:attachrolepolicy",
    "iam:createloginprofile", "iam:createaccesskey", "iam:updateassumerolepolicy",
    "sts:assumerole", "lambda:createfunction", "lambda: updatefunctioncode",
    "cloudformation:createstack", "ec2:runinstances",
}


def _items(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, str)]
    return []


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    raw = policy.get("Statement", [])
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise ValueError("'Statement' must be an object or an array")
    if not all(isinstance(item, dict) for item in raw):
        raise ValueError("Every statement must be a JSON object")
    return raw


def _principal_values(principal: Any) -> list[str]:
    if principal == "*":
        return ["*"]
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        values: list[str] = []
        for value in principal.values():
            values.extend(_items(value))
        return values
    return []


def analyze_policy(document: str | dict[str, Any], *, policy_name: str = "policy") -> dict[str, Any]:
    """Analyze a local AWS IAM policy document; no cloud calls are performed."""
    if isinstance(document, str):
        try:
            policy = json.loads(document)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    else:
        policy = document
    if not isinstance(policy, dict):
        raise ValueError("Policy document must be a JSON object")

    statements = _statements(policy)
    findings: list[Finding] = []

    def add(rule_id: str, severity: str, title: str, message: str,
            evidence: dict[str, Any], remediation: str) -> None:
        findings.append(Finding(rule_id, severity, title, message, evidence, remediation))

    for index, statement in enumerate(statements):
        effect = str(statement.get("Effect", "")).lower()
        actions = [x.lower() for x in _items(statement.get("Action"))]
        not_actions = [x.lower() for x in _items(statement.get("NotAction"))]
        resources = _items(statement.get("Resource"))
        sid = statement.get("Sid", f"statement-{index + 1}")
        evidence = {"sid": sid, "statement_index": index, "actions": actions or not_actions,
                    "resources": resources}

        if effect != "allow":
            continue

        if "*" in actions:
            add("IAM001", "critical", "Full action wildcard",
                "The statement allows every action supported by the matched resource scope.",
                evidence, "Replace Action '*' with the smallest required service actions.")
        elif any(action.endswith(":*") for action in actions):
            add("IAM002", "high", "Service-wide action wildcard",
                "The statement grants all actions within one or more services.",
                evidence, "Enumerate only the API actions the workload actually needs.")

        if "*" in resources:
            severity = "critical" if "*" in actions else "high"
            add("IAM003", severity, "Wildcard resource",
                "The statement applies to every resource in its resource scope.",
                evidence, "Scope Resource to explicit ARNs and use conditions where supported.")

        matched_privilege = sorted({action for action in actions
                                    if action in PRIVILEGE_ACTIONS or action.endswith(":*")})
        if matched_privilege:
            add("IAM004", "high", "Privilege-management or escalation-sensitive actions",
                "The policy includes actions commonly involved in changing identity permissions or obtaining powerful execution paths.",
                {**evidence, "matched_actions": matched_privilege},
                "Remove unnecessary identity-management and pass-role permissions; constrain targets and conditions.")

        if not actions and not not_actions:
            add("IAM009", "medium", "Missing action scope",
                "The statement has neither Action nor NotAction as a string or string array.",
                evidence, "Add a valid Action or NotAction field and validate the policy against the IAM policy grammar.")

    # Trust policies use Principal; resource policies may also contain it.
    for index, statement in enumerate(statements):
        if str(statement.get("Effect", "")).lower() != "allow" or "Principal" not in statement:
            continue
        principal = _principal_values(statement.get("Principal"))
        sid = statement.get("Sid", f"statement-{index + 1}")
        evidence = {"sid": sid, "statement_index": index, "principal": statement.get("Principal"),
                    "actions": _items(statement.get("Action"))}
        if "*" in principal:
            add("IAM005", "critical", "Public or unrestricted principal",
                "The statement trusts any principal unless other policy conditions restrict access.",
                evidence, "Replace the wildcard principal with specific trusted account or role ARNs and add restrictive conditions.")
        accounts = sorted({p.split(":")[4] for p in principal
                           if p.startswith("arn:") and len(p.split(":")) > 5
                           and p.split(":")[4].isdigit()})
        if accounts:
            add("IAM006", "medium", "Explicit account trust",
                "The trust statement names one or more AWS accounts. Confirm each is an approved trust boundary.",
                {**evidence, "account_ids": accounts},
                "Document and periodically review every trusted account; prefer specific role principals where possible.")

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id, f.evidence.get("statement_index", -1)))
    counts = {severity: sum(f.severity == severity for f in findings)
              for severity in SEVERITY_ORDER}
    return {
        "tool": "IAMScope",
        "version": "0.1.0",
        "policy_name": policy_name,
        "statement_count": len(statements),
        "finding_count": len(findings),
        "severity_counts": counts,
        "findings": [finding.to_dict() for finding in findings],
        "disclaimer": "Static-analysis indicators only; effective access depends on identity/resource policies, boundaries, SCPs, conditions, and runtime context."
    }


def diff_policies(before: str | dict[str, Any], after: str | dict[str, Any]) -> dict[str, Any]:
    """Compare normalized statement objects; output is deterministic."""
    def load(value: str | dict[str, Any]) -> dict[str, Any]:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON: {exc.msg}") from exc
        if not isinstance(value, dict):
            raise ValueError("Policy document must be a JSON object")
        return value

    old_statements = _statements(load(before))
    new_statements = _statements(load(after))
    def canonical(statement: dict[str, Any]) -> str:
        return json.dumps(statement, sort_keys=True, separators=(",", ":"))
    old = {canonical(item) for item in old_statements}
    new = {canonical(item) for item in new_statements}
    added = sorted(new - old)
    removed = sorted(old - new)
    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "added_statements": [json.loads(item) for item in added],
        "removed_statements": [json.loads(item) for item in removed],
    }
