from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
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
    "iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:attachuserpolicy",
    "iam:attachgrouppolicy", "iam:putuserpolicy", "iam:putgrouppolicy", "iam:createpolicy",
    "sts:assumerole", "lambda:createfunction", "lambda:updatefunctioncode",
    "cloudformation:createstack", "ec2:runinstances",
}

# These are candidate capability combinations, not proof that an escalation works.
# AWS resource scoping, trust, conditions, boundaries and service context still matter.
ESCALATION_PATTERNS = (
    {
        "id": "PASSROLE_LAMBDA",
        "title": "PassRole with Lambda execution control",
        "required": {"iam:passrole", "lambda:createfunction"},
        "supporting": {"lambda:updatefunctioncode"},
        "description": "PassRole combined with Lambda function creation can create a candidate path to execute code under a role.",
        "remediation": "Restrict PassRole to named roles using iam:PassedToService and resource constraints; limit Lambda creation and code-update permissions.",
    },
    {
        "id": "PASSROLE_COMPUTE",
        "title": "PassRole with EC2 instance launch",
        "required": {"iam:passrole", "ec2:runinstances"},
        "supporting": set(),
        "description": "PassRole combined with instance launch can create a candidate path to run workloads under a permitted instance profile.",
        "remediation": "Restrict PassRole to approved instance roles and constrain launch templates, instance profiles, images and resource conditions.",
    },
    {
        "id": "IAM_POLICY_VERSION",
        "title": "IAM policy version control",
        "required": {"iam:createpolicyversion", "iam:setdefaultpolicyversion"},
        "supporting": set(),
        "description": "Creating and selecting a policy version can allow a principal to change the permissions represented by a customer-managed policy.",
        "remediation": "Remove unnecessary policy-version management; separate policy authoring from deployment and tightly scope target policy ARNs.",
    },
    {
        "id": "ROLE_POLICY_MUTATION",
        "title": "Role policy mutation",
        "required": {"iam:putrolepolicy"},
        "supporting": {"iam:attachrolepolicy", "iam:updateassumerolepolicy"},
        "description": "Inline or attached role-policy mutation can alter permissions on roles within the granted resource scope.",
        "remediation": "Remove role-policy mutation from runtime identities or constrain it to dedicated, reviewed deployment roles.",
    },
)


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


def _candidate_attack_paths(statements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate exact Allow actions across statements; deliberately not an IAM simulator."""
    action_sources: dict[str, list[dict[str, Any]]] = {}
    for index, statement in enumerate(statements):
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        # NotAction and wildcard grants are not expanded into guessed concrete actions.
        for action in _items(statement.get("Action")):
            normalized = action.lower()
            if "*" in normalized:
                continue
            action_sources.setdefault(normalized, []).append({
                "statement_index": index,
                "sid": statement.get("Sid", f"statement-{index + 1}"),
                "resources": _items(statement.get("Resource")),
            })

    paths: list[dict[str, Any]] = []
    for pattern in ESCALATION_PATTERNS:
        required = pattern["required"]
        if not required.issubset(action_sources):
            continue
        matched = sorted(required | (pattern["supporting"] & action_sources.keys()))
        sources = []
        seen = set()
        for action in matched:
            for source in action_sources[action]:
                key = (action, source["statement_index"])
                if key not in seen:
                    sources.append({"action": action, **source})
                    seen.add(key)
        paths.append({
            "pattern_id": pattern["id"],
            "title": pattern["title"],
            "confidence": "candidate",
            "matched_actions": matched,
            "supporting_statements": sorted({s["statement_index"] for s in sources}),
            "evidence": sources,
            "description": pattern["description"],
            "remediation": pattern["remediation"],
            "limitations": "This is a permission-combination signal only. IAMScope does not resolve resource compatibility, conditions, trust, boundaries, SCPs, or runtime prerequisites.",
        })
    return paths


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

        if not_actions:
            add("IAM007", "high", "Allow with NotAction",
                "An Allow statement using NotAction can grant a broad set of actions other than the exclusions; its effective scope depends on Resource and conditions.",
                {**evidence, "excluded_actions": not_actions},
                "Prefer an explicit Action allow-list. If NotAction is required, tightly scope resources and conditions and review the resulting effective permissions.")

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
        if statement.get("Condition"):
            add("IAM008", "info", "Trust statement has conditions",
                "Conditions are present and may narrow who can assume or access the resource; IAMScope does not fully evaluate their semantics.",
                {**evidence, "condition_keys": sorted(statement.get("Condition", {}).keys()) if isinstance(statement.get("Condition"), dict) else []},
                "Manually validate every condition operator, key, value, and expected identity context.")

    attack_paths = _candidate_attack_paths(statements)
    for path in attack_paths:
        add("IAM010", "high", path["title"],
            path["description"] + " This is a candidate path, not proof of exploitability.",
            {"pattern_id": path["pattern_id"], "matched_actions": path["matched_actions"],
             "supporting_statements": path["supporting_statements"], "evidence": path["evidence"]},
            path["remediation"])

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id, f.evidence.get("statement_index", -1)))
    counts = {severity: sum(f.severity == severity for f in findings)
              for severity in SEVERITY_ORDER}
    return {
        "tool": "IAMScope",
        "version": "0.2.0",
        "policy_name": policy_name,
        "statement_count": len(statements),
        "finding_count": len(findings),
        "severity_counts": counts,
        "findings": [finding.to_dict() for finding in findings],
        "attack_paths": attack_paths,
        "disclaimer": "Static-analysis indicators only; candidate attack paths are permission combinations, not proof of exploitability. Effective access depends on identity/resource policies, boundaries, SCPs, conditions, and runtime context."
    }


def diff_policies(before: str | dict[str, Any], after: str | dict[str, Any]) -> dict[str, Any]:
    """Compare normalized statement objects; preserve duplicate statements."""
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

    old = Counter(canonical(item) for item in old_statements)
    new = Counter(canonical(item) for item in new_statements)
    added = sorted((new - old).elements())
    removed = sorted((old - new).elements())
    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "added_statements": [json.loads(item) for item in added],
        "removed_statements": [json.loads(item) for item in removed],
    }
