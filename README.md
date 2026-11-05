# IAMScope

**Cloud Identity & Permission Risk Analyzer**

IAMScope is an offline-first static analyzer for AWS IAM policy documents. It highlights risky permission patterns, trust-policy exposure, candidate privilege-escalation permission combinations, and policy drift without cloud credentials or live AWS API calls.

## Features

- Deterministic IAM policy analysis with severity-ranked findings and remediation guidance.
- Detects full-action and service wildcards, wildcard resources, privilege-management actions, unrestricted trust principals, and explicit account trust.
- Correlates selected exact Allow-action combinations into **candidate attack paths**, including PassRole with Lambda/EC2 execution, IAM policy-version control, and role-policy mutation.
- Compares policy snapshots and reports added/removed statements while preserving duplicate statement counts.
- Local CLI, FastAPI service, and browser dashboard.
- Sample policies, automated tests, and GitHub Actions CI.

> Candidate attack paths are permission-combination signals, not proof of exploitability. IAMScope does not resolve resource compatibility, conditions, trust relationships, permissions boundaries, SCPs, or runtime prerequisites. Review findings in context.

## Quick start (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m uvicorn iamscope.api:app --reload
```

Open http://127.0.0.1:8000. The dashboard supports policy analysis, candidate attack-path review, and before/after comparison. All processing is local to the running service.

## CLI

```powershell
iamscope analyze examples/policies/overprivileged.json --format text
iamscope analyze examples/policies/trust-policy.json --format json
iamscope diff examples/policies/baseline.json examples/policies/expanded.json
```

## Run tests

```powershell
py -m pip install -r requirements.txt
py -m pip install -e .
py -m pytest
```

## API

- `GET /api/health` — service health.
- `POST /api/analyze` — JSON body: `{"policy": { ... }, "policy_name": "example"}`; response includes findings and an `attack_paths` array.
- `POST /api/diff` — JSON body: `{"before": { ... }, "after": { ... }}`.
- `GET /docs` — interactive OpenAPI documentation.

## Detection scope

| Capability | Current behavior |
|---|---|
| Wildcard and broad grants | Detects `Action: "*"`, service wildcards, and `Resource: "*"` |
| Sensitive permissions | Flags selected IAM mutation, PassRole, and execution-sensitive actions |
| Trust exposure | Flags wildcard principals and reports explicit account principals |
| Candidate attack paths | Correlates exact Allow action combinations across statements; does not expand wildcards |
| Policy drift | Compares canonical statements and preserves duplicate statement multiplicity |

## Safety and limitations

IAMScope reads only the JSON documents supplied to it. It does not authenticate to AWS, enumerate accounts, assume roles, mutate IAM, or execute cloud actions. The ruleset is heuristic: it does not calculate complete effective permissions, resolve policy variables, evaluate every condition operator, model service control policies, permission boundaries, session policies, resource-based policies, or service-specific authorization behavior. Candidate attack paths may be false positives or miss paths requiring wildcard expansion or contextual evaluation. Review every finding before making access decisions.

## Project structure

```text
iamscope/       analysis engine, CLI, API
web/            local browser dashboard
examples/       safe synthetic policy fixtures
tests/          engine, CLI and API tests
docs/           detection rule reference
```

## License

MIT
