import json
from pathlib import Path

import pytest

from iamscope.engine import analyze_policy, diff_policies

ROOT = Path(__file__).parents[1]


def load_fixture(name):
    return (ROOT / "examples" / "policies" / name).read_text(encoding="utf-8")


def test_detects_wildcards_and_sensitive_actions():
    result = analyze_policy(load_fixture("overprivileged.json"))
    rule_ids = {item["rule_id"] for item in result["findings"]}
    assert {"IAM001", "IAM003", "IAM004"}.issubset(rule_ids)
    assert result["severity_counts"]["critical"] >= 1


def test_detects_unrestricted_trust_principal():
    result = analyze_policy(load_fixture("trust-policy.json"))
    assert any(item["rule_id"] == "IAM005" for item in result["findings"])


def test_deny_statement_is_not_flagged_as_allow():
    result = analyze_policy({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    assert result["finding_count"] == 0


def test_accepts_single_statement_object():
    result = analyze_policy({"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}})
    assert result["statement_count"] == 1
    assert any(item["rule_id"] == "IAM003" for item in result["findings"])


def test_invalid_json_has_readable_error():
    with pytest.raises(ValueError, match="Invalid JSON"):
        analyze_policy("{not-json")


def test_invalid_statement_shape_is_rejected():
    with pytest.raises(ValueError, match="Every statement"):
        analyze_policy({"Statement": ["not-an-object"]})


def test_diff_reports_added_and_removed_statements():
    result = diff_policies(load_fixture("baseline.json"), load_fixture("expanded.json"))
    assert result["added_count"] == 1
    assert result["removed_count"] == 0
    assert result["added_statements"][0]["Sid"] == "ListAllBuckets"


def test_diff_is_order_independent_for_statement_fields():
    before = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    after = {"Statement": [{"Resource": "*", "Action": "s3:GetObject", "Effect": "Allow"}]}
    assert diff_policies(before, after)["added_count"] == 0


def test_non_object_document_is_rejected():
    with pytest.raises(ValueError, match="JSON object"):
        analyze_policy(json.dumps([{"Effect": "Allow"}]))
