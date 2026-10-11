"""Tests for the web backend's analysis endpoint logic (no server needed)."""

from pathlib import Path

from webapp.server import analyze_code, list_samples

SAMPLES = Path(__file__).parent / "samples"


def test_analyze_returns_findings_and_cfg():
    res = analyze_code((SAMPLES / "branch_vuln.py").read_text(), "cfg")
    assert res["ok"]
    assert [(f["category"], f["line"]) for f in res["findings"]] == [("sql_injection", 9)]
    search = [f for f in res["functions"] if f["name"] == "search"][0]
    join = [b for b in search["blocks"] if b["label"] == "join"][0]
    assert join["in"] == ["term"]
    assert search["iterations"] > 0


def test_linear_mode_has_cfg_but_no_taint_sets():
    res = analyze_code((SAMPLES / "branch_vuln.py").read_text(), "linear")
    assert res["findings"] == []                      # the known linear miss
    search = [f for f in res["functions"] if f["name"] == "search"][0]
    assert search["blocks"] and search["blocks"][0]["in"] is None


def test_syntax_error_reports_line():
    res = analyze_code("x = 1\ndef f(:\n", "cfg")
    assert not res["ok"] and res["line"] == 2


def test_samples_listed():
    names = [s["name"] for s in list_samples()]
    assert "try_vuln.py" in names and len(names) == len(list(SAMPLES.glob("*.py")))
