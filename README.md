# IAMScope

**Cloud Identity & Permission Risk Analyzer**

IAMScope is an offline-first static analyzer for AWS-style IAM policy documents. It identifies risky permission patterns, trust-policy exposure, and policy changes without requiring cloud credentials or making live cloud API calls.

> Static analysis findings are risk indicators, not proof that an identity is exploitable. Validate findings against effective permissions, resource policies, service control policies, boundaries, and the deployment context.

## Initial scope

- Parse and validate IAM policy JSON.
- Detect wildcard actions/resources, administrative access, privilege-escalation-related actions, risky trust principals, and cross-account trust.
- Emit deterministic findings with severity, evidence, and remediation guidance.
- Compare two policy documents and report added/removed statements.
- Run locally with Python; no AWS credentials required.

## Development

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## CLI (planned in the initial build)

```bash
iamscope analyze examples/policies/overprivileged.json --format json
iamscope diff examples/policies/baseline.json examples/policies/overprivileged.json
```

## Safety

IAMScope only reads local JSON policy documents. It does not authenticate to AWS, enumerate accounts, assume roles, change policies, or execute cloud actions.

## License

MIT
