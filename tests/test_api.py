from fastapi.testclient import TestClient

from iamscope.api import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint_returns_findings():
    response = client.post("/api/analyze", json={"policy_name": "test", "policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}})
    assert response.status_code == 200
    assert response.json()["finding_count"] >= 2


def test_invalid_policy_returns_422():
    response = client.post("/api/analyze", json={"policy": {"Statement": ["invalid"]}})
    assert response.status_code == 422


def test_diff_endpoint():
    response = client.post("/api/diff", json={"before": {"Statement": []}, "after": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}})
    assert response.status_code == 200
    assert response.json()["added_count"] == 1
