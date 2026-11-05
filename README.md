<div align="center">

# IAMScope

### Cloud Identity & Permission Risk Analyzer

**Find risky AWS IAM permissions. Review candidate privilege-escalation paths. Track policy drift.**

[![CI](https://github.com/devanshshukla-3004/IAMScope/actions/workflows/tests.yml/badge.svg?branch=feat/iam-analysis-engine)](https://github.com/devanshshukla-3004/IAMScope/actions/workflows/tests.yml)
![Version](https://img.shields.io/badge/version-0.3.0-0ea5e9)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Overview

IAMScope is an **offline-first static analyzer for AWS IAM policy JSON**. It helps security engineers and cloud defenders spot broad permissions, risky trust-policy configurations, selected privilege-management actions, and permission combinations that may represent candidate escalation paths.

It provides three ways to work with the same analysis engine:

- **Web dashboard** — inspect policy findings and compare policy snapshots.
- **Command-line interface** — analyze JSON files and produce text or JSON output.
- **REST API** — integrate local policy analysis into scripts and defensive workflows.

IAMScope analyzes only the policy documents supplied by the operator. It does not connect to an AWS account, require AWS credentials, or make cloud API calls.

> **Important:** IAMScope is a heuristic static-analysis tool, not an AWS authorization simulator. A reported candidate path is not proof of exploitability. Always validate findings against the complete identity, resource, and runtime context.

## What it can do

| Capability | What IAMScope provides |
|---|---|
| Broad permission detection | Flags full-action wildcards, service-wide action wildcards, and wildcard resources in Allow statements |
| Privilege-sensitive action review | Highlights selected IAM mutation, PassRole, and execution-sensitive actions |
| Trust-policy review | Flags wildcard principals and reports explicit AWS account trust; notes the presence of trust conditions |
| Candidate escalation correlation | Correlates selected exact Allow actions into candidate permission chains |
| Policy drift comparison | Reports statements added or removed between two policy snapshots, preserving duplicate statement counts |
| Multiple interfaces | Browser dashboard, CLI, and FastAPI REST API |
| Local-first operation | No AWS credentials, account discovery, role assumption, or cloud-side changes |

### Detection rules

The current ruleset uses stable identifiers so findings can be referenced in reviews and reports.

| Rule | Severity | Summary |
|---|---|---|
| IAM001 | Critical | Full `Action: "*"` wildcard in an Allow statement |
| IAM002 | High | Service-wide action wildcard such as `s3:*` |
| IAM003 | High / Critical | Wildcard resource in an Allow statement |
| IAM004 | High | Selected privilege-management or escalation-sensitive actions |
| IAM005 | Critical | Wildcard / unrestricted trust principal |
| IAM006 | Medium | Explicit AWS account principal in a trust statement |
| IAM007 | High | Allow statement using `NotAction` |
| IAM008 | Informational | Trust statement contains conditions that need contextual review |
| IAM009 | Medium | Missing or unrecognized Action / NotAction scope |
| IAM010 | High | Exact Allow-action combination matches a candidate escalation pattern |

See [docs/rules.md](docs/rules.md) for the detailed rule reference and remediation guidance.

### Candidate permission-chain patterns

IAM010 currently correlates these selected exact-action combinations:

| Pattern | Required actions |
|---|---|
| `PASSROLE_LAMBDA` | `iam:PassRole` + `lambda:CreateFunction` |
| `PASSROLE_COMPUTE` | `iam:PassRole` + `ec2:RunInstances` |
| `IAM_POLICY_VERSION` | `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` |
| `ROLE_POLICY_MUTATION` | `iam:PutRolePolicy` |

The engine can include selected supporting actions as additional evidence. It deliberately does **not** expand wildcard actions or `NotAction` grants into guessed concrete permissions.

## Screenshots

The application includes two primary workspaces:

- **Policy Analyzer:** submit a policy JSON document and inspect severity-ranked findings, evidence, remediation, and candidate permission chains.
- **Policy Comparison:** compare a baseline policy with a current policy and review added and removed statements.

The screenshots below can be added to this section when repository-owned image assets are committed. Until then, see the running dashboard locally using the setup instructions below.

## Architecture

```text
                  AWS IAM policy JSON
                           |
             +-------------+-------------+
             |             |             |
          Web UI          CLI         REST API
             |             |             |
             +-------------+-------------+
                           |
                   Analysis Engine
                           |
          +----------------+----------------+
          |                |                |
      Rule checks    Candidate-path     Policy diff
      IAM001–009      correlation        comparison
          |                |                |
          +----------------+----------------+
                           |
               Findings / Evidence /
               Remediation / JSON
```

All interfaces use the same local Python analysis engine. The dashboard is served by the FastAPI application.

## Quick start

### Requirements

- Python **3.10 or newer**
- pip
- Git

### Windows PowerShell

Clone the feature branch:

```powershell
git clone --branch feat/iam-analysis-engine https://github.com/devanshshukla-3004/IAMScope.git
cd IAMScope
```

Create an environment, install the project, and start the dashboard:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m uvicorn iamscope.api:app --reload
```

Open:

- Dashboard: http://127.0.0.1:8000
- API documentation: http://127.0.0.1:8000/docs
- Health endpoint: http://127.0.0.1:8000/api/health

If the `iamscope` command is not available in the current shell, invoke the installed Windows entry point directly:

```powershell
.\.venv\Scripts\iamscope.exe --help
```

### macOS / Linux

```bash
git clone --branch feat/iam-analysis-engine https://github.com/devanshshukla-3004/IAMScope.git
cd IAMScope
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
uvicorn iamscope.api:app --reload
```

Open http://127.0.0.1:8000 in your browser.

## Command-line usage

After installing the package with `pip install -e .`, the `iamscope` command is available in the active virtual environment.

### Analyze a policy

Text output:

```bash
iamscope analyze examples/policies/overprivileged.json --format text
```

JSON output:

```bash
iamscope analyze examples/policies/trust-policy.json --format json
```

### Compare policy snapshots

```bash
iamscope diff examples/policies/baseline.json examples/policies/expanded.json
```

JSON diff output:

```bash
iamscope diff examples/policies/baseline.json examples/policies/expanded.json --format json
```

### Windows without shell activation

Use the virtual-environment executable explicitly:

```powershell
.\.venv\Scripts\iamscope.exe analyze examples/policies/overprivileged.json --format text
.\.venv\Scripts\iamscope.exe diff examples/policies/baseline.json examples/policies/expanded.json
```

## REST API

The local API is documented interactively at `/docs`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health, version, and analysis mode |
| POST | `/api/analyze` | Analyze one IAM policy JSON document |
| POST | `/api/diff` | Compare before and after policy documents |
| GET | `/docs` | Interactive OpenAPI documentation |

### Analyze request

```http
POST /api/analyze
Content-Type: application/json
```

```json
{
  "policy_name": "example-policy",
  "policy": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "ReadExampleBucket",
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example-bucket/*"
      }
    ]
  }
}
```

The response includes the policy name, analyzer version, statement and finding counts, severity counts, individual findings, candidate `attack_paths`, evidence, remediation guidance, and a static-analysis disclaimer.

### Compare request

```http
POST /api/diff
Content-Type: application/json
```

```json
{
  "before": {
    "Statement": []
  },
  "after": {
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:ListAllMyBuckets",
        "Resource": "*"
      }
    ]
  }
}
```

The response contains `added_count`, `removed_count`, `added_statements`, and `removed_statements`.

## Run tests

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the complete test suite:

```bash
python -m pytest -v
```

The test suite covers engine rules, candidate-path correlation, policy diff behavior, CLI behavior, API endpoints, validation, and version consistency.

The project CI workflow runs the tests across Python 3.10, 3.11, 3.12, and 3.13, and checks dashboard JavaScript syntax.

## Example policy fixtures

Synthetic example policies are provided in `examples/policies/`:

| File | Purpose |
|---|---|
| `overprivileged.json` | Demonstrates broad permissions and privilege-sensitive actions |
| `trust-policy.json` | Demonstrates trust-policy review cases |
| `baseline.json` | Starting policy for comparison |
| `expanded.json` | Updated policy containing an additional statement |

Use these fixtures to explore the CLI, dashboard, and API without connecting to an AWS account.

## Security model and limitations

IAMScope is intentionally **offline and read-only**.

It does not:

- Authenticate to AWS or request AWS credentials.
- Enumerate AWS accounts, users, roles, or resources.
- Assume roles or call AWS APIs.
- Apply, update, or delete IAM policies.
- Execute actions in a cloud environment.

The current analyzer is a heuristic static analyzer. It does not calculate complete effective AWS permissions or fully model:

- Identity-based and resource-based policy interactions.
- Service Control Policies (SCPs) and Resource Control Policies (RCPs).
- Permissions boundaries and session policies.
- Every IAM condition operator, policy variable, or context key.
- Service-specific authorization rules and runtime prerequisites.
- Full resource compatibility across correlated statements.

Candidate paths are syntactic combinations of exact Allow actions. The engine does not establish that matched statements have compatible resources, conditions, principals, or runtime context. Wildcards and `NotAction` are not expanded into inferred action lists. As a result, findings can include false positives and may miss risks that require broader policy evaluation.

**Do not use IAMScope findings as the sole basis for granting, denying, or changing production access.** Validate results with the relevant AWS documentation, policy simulator or a complete authorization review.

## Project structure

```text
IAMScope/
├── iamscope/
│   ├── __init__.py       # Package version
│   ├── engine.py         # Static analysis and policy diff engine
│   ├── cli.py            # Command-line interface
│   └── api.py            # FastAPI application
├── web/
│   ├── index.html        # Dashboard structure
│   ├── styles.css        # Dashboard styling
│   └── app.js            # Dashboard interactions
├── examples/
│   └── policies/         # Synthetic IAM policy fixtures
├── tests/
│   ├── test_engine.py
│   ├── test_cli.py
│   └── test_api.py
├── docs/
│   └── rules.md          # Detection rules and limitations
├── .github/
│   └── workflows/
│       └── tests.yml     # CI workflow
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Roadmap

Potential next engineering milestones:

- More complete effective-permission evaluation across policy types and authorization context.
- Expanded, versioned AWS action and service coverage.
- More precise resource and condition compatibility checks for candidate paths.
- Browser-level end-to-end tests for the dashboard.
- Optional AWS account integration with a separately designed, least-privilege, read-only security model.

These are future directions, not capabilities claimed by the current release.

## Contributing

Issues, bug reports, and focused pull requests are welcome. When reporting a detection issue, include a sanitized policy example, expected behavior, actual behavior, and relevant test output. Never publish AWS credentials, account secrets, or sensitive production policy documents.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
