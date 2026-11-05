# Detection rules (v0.1)

| Rule | Severity | Detection | Suggested response |
|---|---|---|---|
| IAM001 | Critical | Allow statement with Action `*` | Replace with explicit required actions |
| IAM002 | High | Allow statement with service wildcard such as `s3:*` | Enumerate required API actions |
| IAM003 | High / Critical | Allow statement with Resource `*` | Scope to specific resource ARNs |
| IAM004 | High | Identity-management / execution-path-sensitive actions | Remove or constrain permissions |
| IAM005 | Critical | Allow statement with Principal `*` | Restrict trusted principals and conditions |
| IAM006 | Medium | Explicit AWS account principal in a trust statement | Review and document trust boundary |
| IAM009 | Medium | Missing Action and NotAction | Correct the policy document |

These are static heuristics. They do not calculate effective permissions, resolve policy variables, evaluate all condition operators, model service control policies, or prove exploitability. Findings require contextual review.
