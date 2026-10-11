"""Checks that the shared data structures and config loader work."""

import ast
import json

import pytest

from taint_analyzer import CFG, Finding, TaintSet, ConfigError, load_config


def test_default_config_loads():
    cfg = load_config()
    assert cfg.is_source("input")
    assert cfg.is_sanitizer("int")
    spec = cfg.sink_spec("cursor.execute")
    assert spec.category == "sql_injection"
    assert spec.args == (0,)          # only the query string, not the params
    assert cfg.sink_spec("print") is None


def test_bad_config_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"sources": [], "sinks": {}}))   # no sanitizers
    with pytest.raises(ConfigError):
        load_config(bad)


def test_cfg_edges_and_printing():
    g = CFG("demo")
    entry, body, exit_ = g.new_block("entry"), g.new_block(), g.new_block("exit")
    g.entry, g.exit = entry.id, exit_.id
    body.statements = ast.parse("q = 'SELECT ' + name").body
    g.add_edge(entry.id, body.id)
    g.add_edge(body.id, exit_.id)
    g.add_edge(body.id, exit_.id)                     # duplicate is ignored
    assert g.blocks[body.id].successors == [exit_.id]
    assert g.blocks[exit_.id].predecessors == [body.id]
    assert "L1: q = 'SELECT ' + name" in g.pretty()


def test_taint_set_is_immutable_and_comparable():
    a = TaintSet({"x"}) | TaintSet({"y"})
    assert a == TaintSet({"y", "x"})
    with pytest.raises(AttributeError):
        a.add("z")


def test_finding_format():
    f = Finding("app.py", "login", 7, "cursor.execute", "sql_injection",
                ("query",), "cursor.execute(query)")
    assert f.format().startswith("app.py:7: [sql_injection] in login()")
