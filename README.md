# IAMScope

**Cloud Identity & Permission Risk Analyzer**

IAMScope is an offline-first static analyzer for AWS IAM policy documents. It highlights risky permission patterns, trust-policy exposure, and policy drift without cloud credentials or live AWS API calls.

## Features

- Deterministic IAM policy analysis with severity-ranked findings and remediation guidance.
- Detects full-action and service wildcards, wildcard resources, privilege-management actions, unrestricted trust principals, and explicit account trust.
- Compares policy snapshots and reports added/removed statements.
- Local CLI, FastAPI service, and browser dashboard.
- Sample policies, automated tests, and GitHub Actions CI.

> Findings are risk indicators, not proof of exploitability. Effective access depends on identity and resource policies, permission boundaries, service control policies, conditions, and runtime context. IAMScope does not currently evaluate the complete AWS authorization model.

## Quick start (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m uvicorn iamscope.api:app --reload
```

Open http://127.0.0.1:8000. The dashboard supports policy analysis and before/after comparison. All processing is local to the running service.

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
- `POST /api/analyze` — JSON body: `{"policy": { ... }, "policy_name": "example"}`.
- `POST /api/diff` — JSON body: `{"before": { ... }, "after": { ... }}`.
- `GET /docs` — interactive OpenAPI documentation.

## Safety and limitations

IAMScope reads only the JSON documents supplied to it. It does not authenticate to AWS, enumerate accounts, assume roles, mutate IAM, or execute cloud actions. This initial ruleset is heuristic: it does not fully resolve wildcards, policy variables, condition logic, SCPs, permission boundaries, session policies, or service-specific authorization behavior. Review every finding in its environment before making access decisions.

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
