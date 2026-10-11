"""Tests for the CFG-based dataflow analysis (Step 7)."""

import ast
from pathlib import Path

from taint_analyzer import EMPTY_TAINT, load_config
from taint_analyzer.analysis import analyze_linear
from taint_analyzer.cfg import build_cfg
from taint_analyzer.dataflow import analyze_function, solve
from taint_analyzer.parser import extract_functions, parse_file

SAMPLES = Path(__file__).parent / "samples"
CONFIG = load_config()

# What the CFG analysis must report for every sample: (category, line).
EXPECTED = {
    "sql_concat_vuln.py": [("sql_injection", 7)],
    "cmd_fstring_vuln.py": [("command_injection", 7)],
    "eval_flask_vuln.py": [("code_injection", 8)],
    "module_level_vuln.py": [("sql_injection", 7)],
    "branch_vuln.py": [("sql_injection", 9)],
    "loop_vuln.py": [("sql_injection", 6)],
    "try_vuln.py": [("sql_injection", 9)],
    "condition_sink_vuln.py": [("code_injection", 5)],
    "sql_param_safe.py": [],
    "sanitized_int_safe.py": [],
    "overwrite_safe.py": [],
    "branch_safe.py": [],
    "infeasible_path_fp.py": [("sql_injection", 10)],   # known false positive
}


def run(path, linear=False):
    out = []
    for func in extract_functions(parse_file(path)):
        if linear:
            out += analyze_linear(func, CONFIG, str(path))
        else:
            out += analyze_function(func, CONFIG, str(path)).findings
    return [(f.category, f.line) for f in out]


def test_every_sample_has_an_expectation():
    assert sorted(p.name for p in SAMPLES.glob("*.py")) == sorted(EXPECTED)


def test_cfg_analysis_on_samples():
    for name, expected in EXPECTED.items():
        assert run(SAMPLES / name) == expected, name


def test_cfg_analysis_finds_what_linear_misses():
    for name in ("branch_vuln.py", "loop_vuln.py", "try_vuln.py"):
        assert run(SAMPLES / name, linear=True) == [], name
        assert run(SAMPLES / name) != [], name


def solve_src(src):
    cfg = build_cfg("f", ast.parse(src).body)
    return cfg, solve(cfg, CONFIG)


def test_merge_is_union():
    cfg, res = solve_src("if c:\n    x = input()\nelse:\n    x = 'a'\n")
    join = [b for b in cfg.blocks.values() if b.label == "join"][0]
    assert res.taint_in[join.id] == {"x"}


def test_sanitized_on_all_paths_is_clean():
    cfg, res = solve_src("x = input()\nif c:\n    x = int(x)\nelse:\n    x = 0\n")
    assert res.taint_out[cfg.exit] == EMPTY_TAINT
    assert res.taint_in[cfg.exit] == EMPTY_TAINT


def test_loop_reaches_fixed_point():
    # taint moves one variable per iteration: c <- b <- a <- input()
    cfg, res = solve_src("while k:\n    c = b\n    b = a\n    a = input()\n")
    head = [b for b in cfg.blocks.values() if b.label == "while-head"][0]
    assert res.taint_in[head.id] == {"a", "b", "c"}
    assert res.iterations > len(cfg.blocks)       # needed more than one pass


def test_function_with_match_falls_back_to_linear():
    import sys
    if sys.version_info < (3, 10):
        return
    from taint_analyzer.parser import parse_source
    tree = parse_source("def f(cursor, k):\n"
                        "    match k:\n"
                        "        case 1:\n"
                        "            pass\n"
                        "    cursor.execute(input())\n")
    res = analyze_function(extract_functions(tree)[1], CONFIG, "x.py")
    assert res.note and res.dataflow is None
    assert [(f.category, f.line) for f in res.findings] == [("sql_injection", 5)]
