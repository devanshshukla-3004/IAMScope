# Detection rules (v0.2)

| Rule | Severity | Detection | Suggested response |
|---|---|---|---|
| IAM001 | Critical | Allow statement with Action `*` | Replace with explicit required actions |
| IAM002 | High | Allow statement with service wildcard such as `s3:*` | Enumerate required API actions |
| IAM003 | High / Critical | Allow statement with Resource `*` | Scope to specific resource ARNs |
| IAM004 | High | Identity-management / execution-path-sensitive actions | Remove or constrain permissions |
| IAM005 | Critical | Allow statement with Principal `*` | Restrict trusted principals and conditions |
| IAM006 | Medium | Explicit AWS account principal in a trust statement | Review and document trust boundary |
| IAM007 | High | Allow statement with NotAction | Prefer explicit Action allow-list; tightly scope exceptions |
| IAM008 | Info | Trust statement contains Condition | Manually validate condition semantics and identity context |
| IAM009 | Medium | Missing Action and NotAction | Correct the policy document |
| IAM010 | High | Correlated exact Allow actions match a known candidate escalation pattern | Review the combined permissions, resource scope and execution context |

## Candidate path patterns

- `PASSROLE_LAMBDA`: `iam:PassRole` plus `lambda:CreateFunction` (and optionally `lambda:UpdateFunctionCode`).
- `PASSROLE_COMPUTE`: `iam:PassRole` plus `ec2:RunInstances`.
- `IAM_POLICY_VERSION`: `iam:CreatePolicyVersion` plus `iam:SetDefaultPolicyVersion`.
- `ROLE_POLICY_MUTATION`: `iam:PutRolePolicy`, optionally correlated with role-policy attachment or trust-policy mutation actions.

The engine correlates exact actions across Allow statements. It deliberately does not expand wildcard or NotAction grants into guessed concrete permissions. A reported path is a **candidate capability combination**, not proof of an exploitable chain. Resource compatibility, trust, conditions, permission boundaries, SCPs, service control policies, and runtime prerequisites are not fully evaluated.

All detections are static heuristics and require contextual review.
