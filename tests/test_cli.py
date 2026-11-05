from iamscope.cli import main


def test_analyze_json_output(capsys):
    assert main(["analyze", "examples/policies/overprivileged.json", "--format", "json"]) == 0
    output = capsys.readouterr().out
    assert '"tool": "IAMScope"' in output
    assert '"findings"' in output


def test_diff_text_output(capsys):
    assert main(["diff", "examples/policies/baseline.json", "examples/policies/expanded.json"]) == 0
    assert "Added statements: 1" in capsys.readouterr().out
