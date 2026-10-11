"""Tests for parsing, expression taint, the linear analyzer, and the CFG."""

import ast
import sys
from pathlib import Path

import pytest

from taint_analyzer import EMPTY_TAINT, load_config
from taint_analyzer.analysis import analyze_linear
from taint_analyzer.cfg import UnsupportedSyntax, build_cfg
from taint_analyzer.expr import call_name, sink_hits, taint_origins, transfer
from taint_analyzer.parser import extract_functions, parse_file, parse_source

SAMPLES = Path(__file__).parent / "samples"
CONFIG = load_config()


def expr(src):
    return ast.parse(src, mode="eval").body


def stmt(src):
    return ast.parse(src).body[0]


def analyze_file(path):
    findings = []
    for func in extract_functions(parse_file(path)):
        findings += analyze_linear(func, CONFIG, str(path))
    return findings


# ---------------------------------------------------------------- Step 2-3
def test_extract_functions_qualified_names():
    tree = parse_source(
        "def a():\n"
        "    def inner(): pass\n"
        "class C:\n"
        "    def m(self): pass\n"
        "async def b(): pass\n")
    names = [f.name for f in extract_functions(tree)]
    assert names == ["<module>", "a", "a.<locals>.inner", "C.m", "b"]


def test_syntax_error_is_reported():
    with pytest.raises(SyntaxError):
        parse_source("def broken(:\n")


# ---------------------------------------------------------------- Step 4
def test_call_name():
    assert call_name(expr("cursor.execute")) == "cursor.execute"
    assert call_name(expr("request.args.get")) == "request.args.get"
    assert call_name(expr("get_db().execute")) is None


def test_taint_origins_rules():
    t = frozenset({"name"})
    assert taint_origins(expr("'SELECT ' + name"), t, CONFIG) == {"name"}
    assert taint_origins(expr("f'x {name}'"), t, CONFIG) == {"name"}
    assert taint_origins(expr("name.strip().lower()"), t, CONFIG) == {"name"}
    assert taint_origins(expr("','.join([name, 'a'])"), t, CONFIG) == {"name"}
    assert taint_origins(expr("input()"), EMPTY_TAINT, CONFIG) == {"input()"}
    assert taint_origins(expr("int(name)"), t, CONFIG) == EMPTY_TAINT       # sanitizer
    assert taint_origins(expr("len('abc')"), t, CONFIG) == EMPTY_TAINT
    assert taint_origins(expr("lambda: name"), t, CONFIG) == EMPTY_TAINT


def test_transfer_assignments():
    t = frozenset({"a"})
    assert transfer(stmt("b = a + '!'"), t, CONFIG) == {"a", "b"}
    assert transfer(stmt("a = 'const'"), t, CONFIG) == EMPTY_TAINT          # strong update
    assert transfer(stmt("x, y = a, 1"), t, CONFIG) == {"a", "x"}           # element-wise
    assert transfer(stmt("a, b = b, a"), t, CONFIG) == {"b"}                # swap uses old state
    assert transfer(stmt("d['k'] = a"), t, CONFIG) == {"a", "d"}            # weak update
    assert transfer(stmt("d['k'] = 1"), frozenset({"d"}), CONFIG) == {"d"}  # never removed
    assert transfer(stmt("s += a"), t, CONFIG) == {"a", "s"}
    assert transfer(stmt("for x in a: pass"), t, CONFIG) == {"a", "x"}


def test_sink_only_checks_configured_argument():
    t = frozenset({"name"})
    safe = stmt("cursor.execute('... ?', (name,))")
    bad = stmt("cursor.execute('... ' + name)")
    assert sink_hits(safe, t, CONFIG) == []
    assert [h.sink for h in sink_hits(bad, t, CONFIG)] == ["cursor.execute"]


# ---------------------------------------------------------------- Step 5
EXPECTED = {
    "sql_concat_vuln.py": [("sql_injection", 7)],
    "cmd_fstring_vuln.py": [("command_injection", 7)],
    "eval_flask_vuln.py": [("code_injection", 8)],
    "module_level_vuln.py": [("sql_injection", 7)],
    "sql_param_safe.py": [],
    "sanitized_int_safe.py": [],
    "overwrite_safe.py": [],
}


def test_linear_analyzer_on_samples():
    for name, expected in EXPECTED.items():
        got = [(f.category, f.line) for f in analyze_file(SAMPLES / name)]
        assert got == expected, name


def test_linear_analyzer_known_limitation_branch():
    # Documented limitation of Step 5; the CFG analysis (Step 7) must fix it.
    assert analyze_file(SAMPLES / "branch_vuln.py") == []


# ---------------------------------------------------------------- Step 6
def cfg_of(src):
    return build_cfg("f", ast.parse(src).body)


def succ_labels(g, bid):
    return sorted(g.blocks[s].label for s in g.blocks[bid].successors)


def test_cfg_straight_line():
    g = cfg_of("a = 1\nb = 2\n")
    first = g.blocks[g.entry].successors[0]
    assert len(g.blocks[first].statements) == 2
    assert g.blocks[first].successors == [g.exit]


def test_cfg_if_else_joins():
    g = cfg_of("if c:\n    x = 1\nelse:\n    x = 2\ny = x\n")
    head = g.blocks[g.entry].successors[0]
    assert ast.unparse(g.blocks[head].branch_node) == "c"
    assert succ_labels(g, head) == ["else", "then"]
    join = [b for b in g.blocks.values() if b.label == "join"][0]
    assert sorted(g.blocks[p].label for p in join.predecessors) == ["else", "then"]
    assert join.successors == [g.exit]


def test_cfg_if_without_else_can_skip_body():
    g = cfg_of("if c:\n    x = 1\n")
    head = g.blocks[g.entry].successors[0]
    assert succ_labels(g, head) == ["join", "then"]


def test_cfg_while_break_continue():
    g = cfg_of("while c:\n    if d:\n        break\n    continue\nz = 1\n")
    head = [b for b in g.blocks.values() if b.label == "while-head"][0]
    after = [b for b in g.blocks.values() if b.label == "after-loop"][0]
    assert after.id in head.successors                      # condition false
    brk = [b for b in g.blocks.values() if b.statements and isinstance(b.statements[-1], ast.Break)][0]
    cont = [b for b in g.blocks.values() if b.statements and isinstance(b.statements[-1], ast.Continue)][0]
    assert brk.successors == [after.id]
    assert cont.successors == [head.id]                     # back edge


def test_cfg_for_head_holds_loop_statement():
    g = cfg_of("for x in xs:\n    y = x\n")
    head = [b for b in g.blocks.values() if b.label == "for-head"][0]
    assert isinstance(head.statements[0], ast.For)
    assert any(g.blocks[p].label == "loop-body" for p in head.predecessors)


def test_cfg_return_goes_to_exit_and_rest_unreachable():
    g = cfg_of("return 1\nx = 2\n")
    dead = [b for b in g.blocks.values() if b.label == "unreachable"][0]
    assert dead.predecessors == []
    first = g.blocks[g.entry].successors[0]
    assert g.blocks[first].successors == [g.exit]


def test_cfg_try_every_statement_reaches_handler():
    g = cfg_of("try:\n    a = input()\n    a = 'x'\nexcept E:\n    run(a)\n")
    handler = [b for b in g.blocks.values() if b.label == "except"][0]
    # the state after `a = input()` (before it is overwritten) must reach the handler
    srcs = [g.blocks[p] for p in handler.predecessors]
    assert any(s.statements and ast.unparse(s.statements[0]) == "a = input()" for s in srcs)


def test_cfg_match_is_unsupported():
    if sys.version_info < (3, 10):
        return                                   # `match` syntax needs Python 3.10+
    with pytest.raises(UnsupportedSyntax):
        cfg_of("match x:\n    case 1:\n        pass\n")


def test_cfg_pretty_mentions_branch():
    text = cfg_of("if c:\n    x = 1\n").pretty()
    assert "branch on: c" in text and "L2: x = 1" in text
