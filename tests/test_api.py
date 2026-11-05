from fastapi.testclient import TestClient

from iamscope import __version__
from iamscope.api import app

client = TestClient(app)


def test_health_endpoint_reports_package_version():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == __version__


def test_openapi_version_matches_package_version():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["version"] == __version__


def test_analyze_endpoint_returns_findings_and_candidate_paths():
    response = client.post("/api/analyze", json={
        "policy_name": "test",
        "policy": {"Statement": [{"Effect": "Allow", "Action": [
            "iam:PassRole", "lambda:CreateFunction"
        ], "Resource": "*"}]},
    })
    assert response.status_code == 200
    payload = response.json()
    assert payload["finding_count"] >= 2
    assert payload["attack_paths"][0]["pattern_id"] == "PASSROLE_LAMBDA"


def test_invalid_policy_returns_422():
    response = client.post("/api/analyze", json={"policy": {"Statement": ["invalid"]}})
    assert response.status_code == 422


def test_policy_label_length_is_bounded():
    response = client.post("/api/analyze", json={
        "policy_name": "x" * 121,
        "policy": {"Statement": []},
    })
    assert response.status_code == 422


def test_diff_endpoint():
    response = client.post("/api/diff", json={
        "before": {"Statement": []},
        "after": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    })
    assert response.status_code == 200
    assert response.json()["added_count"] == 1
