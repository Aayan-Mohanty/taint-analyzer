"""Step 5: preliminary analyzer that walks statements in source order.

This is a stop-gap so the tool works end to end before the CFG-based
dataflow analysis (Step 7) is written. It visits every statement once,
top to bottom, including the bodies of if/else, loops and try blocks,
carrying one taint set along.

Known limitations, all fixed by the CFG analysis in Step 7:
  - if/else: the else-branch is analyzed AFTER the if-branch, as if both
    ran in sequence. An assignment in the else-branch can therefore wrongly
    remove taint added in the if-branch, and a vulnerability is missed.
  - loops: the body is analyzed once, so taint that only reaches a sink on
    the second iteration is missed.
  - try/except: handlers see only the state at the end of the try body.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

from .config import Config
from .expr import sink_hits, transfer
from .models import EMPTY_TAINT, Finding
from .parser import FunctionInfo


def nested_bodies(stmt: ast.stmt) -> List[List[ast.stmt]]:
    """Statement lists nested inside `stmt`, in source order."""
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return []                                # analyzed as separate units
    if isinstance(stmt, ast.Try) or (hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar)):
        bodies = [stmt.body] + [h.body for h in stmt.handlers] + [stmt.orelse, stmt.finalbody]
    elif hasattr(ast, "Match") and isinstance(stmt, ast.Match):
        bodies = [case.body for case in stmt.cases]
    else:
        bodies = [getattr(stmt, "body", []), getattr(stmt, "orelse", [])]
    return [b for b in bodies if isinstance(b, list) and b]


def analyze_linear(func: FunctionInfo, config: Config, filename: str) -> List[Finding]:
    found: Dict[Tuple[int, int, str], Finding] = {}

    def run(stmts: List[ast.stmt], taint: frozenset) -> frozenset:
        for stmt in stmts:
            for hit in sink_hits(stmt, taint, config):
                key = (hit.call.lineno, hit.call.col_offset, hit.sink)
                found.setdefault(key, Finding(
                    file=filename, function=func.name, line=hit.call.lineno,
                    sink=hit.sink, category=hit.spec.category,
                    tainted_vars=tuple(sorted(hit.origins)),
                    code=ast.unparse(hit.call)))
            taint = transfer(stmt, taint, config)
            for body in nested_bodies(stmt):
                taint = run(body, taint)
        return taint

    run(func.body, EMPTY_TAINT)                  # parameters start untainted
    return [found[k] for k in sorted(found)]
