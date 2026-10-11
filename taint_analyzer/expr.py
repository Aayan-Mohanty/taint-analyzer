"""Step 4: expression and statement helpers shared by every analysis.

Three questions are answered here:
  1. What is the dotted name of a call?          -> call_name
  2. Is an expression tainted, and by what?       -> taint_origins
  3. How does one statement change the taint set? -> transfer
plus finding sink calls inside a statement      -> sink_hits
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Set, Union

from .config import Config, SinkSpec
from .models import EMPTY_TAINT

_SCOPES = (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


# ---------------------------------------------------------------------------
# 1. Call names
# ---------------------------------------------------------------------------
def call_name(func: ast.expr) -> Optional[str]:
    """Dotted name of a call target: `cursor.execute` -> "cursor.execute".

    Returns None when the target is not a plain chain of names, e.g.
    `get_db().execute` or `handlers[0]`.
    """
    parts: List[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


# ---------------------------------------------------------------------------
# 2. Taint of an expression
# ---------------------------------------------------------------------------
def taint_origins(expr: Optional[ast.AST], taint: frozenset, config: Config) -> frozenset:
    """Return what makes `expr` tainted; an empty set means untainted.

    Elements are tainted variable names (e.g. "name") or source calls
    written as "input()". Rules:
      - a variable is tainted if it is in the current taint set
      - a call to a source is tainted; a call to a sanitizer is not
      - any other call is tainted if an argument or, for a method call,
        the object it is called on is tainted (covers "a".join(x), s.strip())
      - any other expression (+, f-strings, indexing, ...) is tainted if
        any part of it is tainted
    """
    if expr is None:
        return EMPTY_TAINT
    if isinstance(expr, ast.Name):
        return frozenset({expr.id}) if expr.id in taint else EMPTY_TAINT
    if isinstance(expr, ast.Call):
        name = call_name(expr.func)
        if config.is_source(name):
            return frozenset({f"{name}()"})
        if config.is_sanitizer(name):
            return EMPTY_TAINT
        parts: List[ast.AST] = list(expr.args) + [kw.value for kw in expr.keywords]
        if isinstance(expr.func, ast.Attribute):
            parts.append(expr.func.value)        # the receiver object
        elif not isinstance(expr.func, ast.Name):
            parts.append(expr.func)              # e.g. make_handler()(x): the callee expression
        return _union(parts, taint, config)
    if isinstance(expr, ast.Lambda):
        return EMPTY_TAINT                       # its body does not run here
    parts = []
    for child in ast.iter_child_nodes(expr):
        if isinstance(child, ast.comprehension):
            parts.append(child.iter)             # [f(x) for x in data] depends on data
        elif isinstance(child, ast.expr):
            parts.append(child)
    return _union(parts, taint, config)


def _union(exprs: Iterable[ast.AST], taint: frozenset, config: Config) -> frozenset:
    out: Set[str] = set()
    for e in exprs:
        out |= taint_origins(e, taint, config)
    return frozenset(out)


# ---------------------------------------------------------------------------
# 3. Transfer function: taint set before a statement -> taint set after it
# ---------------------------------------------------------------------------
def transfer(stmt: ast.stmt, taint: frozenset, config: Config) -> frozenset:
    """Apply one statement's assignments to the taint set.

    For compound statements (if/while/for/with/try) only the header is
    applied here (e.g. the loop variable of a `for`); their bodies are
    handled by whoever walks the program (the CFG or the linear analyzer).
    """
    t: Set[str] = set(taint)

    if isinstance(stmt, ast.Assign):
        for target in stmt.targets:
            _assign_value(target, stmt.value, taint, t, config)
    elif isinstance(stmt, ast.AnnAssign):
        if stmt.value is not None:               # `x: int` alone assigns nothing
            _assign_value(stmt.target, stmt.value, taint, t, config)
    elif isinstance(stmt, ast.AugAssign):        # x += e keeps x's old taint
        if taint_origins(stmt.value, taint, config):
            _bind(stmt.target, True, t)
    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
        _bind(stmt.target, bool(taint_origins(stmt.iter, taint, config)), t)
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            if item.optional_vars is not None:
                _bind(item.optional_vars, bool(taint_origins(item.context_expr, taint, config)), t)
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        t.discard(stmt.name)                     # the name now refers to code
    elif isinstance(stmt, ast.Delete):
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                t.discard(target.id)
    elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
        for alias in stmt.names:
            t.discard(alias.asname or alias.name.split(".")[0])
    return frozenset(t)


def _assign_value(target: ast.expr, value: ast.expr, taint: frozenset,
                  t: Set[str], config: Config) -> None:
    """`a, b = x, y` is matched element by element; anything else as a whole."""
    if (isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List))
            and len(target.elts) == len(value.elts)
            and not any(isinstance(e, ast.Starred) for e in target.elts + value.elts)):
        for tgt, val in zip(target.elts, value.elts):
            _assign_value(tgt, val, taint, t, config)   # all evaluated on the old taint set
        return
    _bind(target, bool(taint_origins(value, taint, config)), t)


def _bind(target: ast.expr, tainted: bool, t: Set[str]) -> None:
    """Record that `target` now holds a tainted or untainted value."""
    if isinstance(target, ast.Name):
        # Strong update: the old value is replaced completely.
        if tainted:
            t.add(target.id)
        else:
            t.discard(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _bind(elt, tainted, t)
    elif isinstance(target, ast.Starred):
        _bind(target.value, tainted, t)
    elif isinstance(target, (ast.Attribute, ast.Subscript)):
        # Weak update: `obj.x = v` / `d[k] = v` changes only part of the
        # object, so taint can be added to it but never removed.
        root = _root_name(target)
        if tainted and root is not None:
            t.add(root)


def _root_name(node: ast.expr) -> Optional[str]:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


# ---------------------------------------------------------------------------
# 4. Sink detection
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SinkHit:
    call: ast.Call
    sink: str
    spec: SinkSpec
    origins: frozenset


def header_exprs(stmt: ast.stmt) -> List[ast.AST]:
    """The parts of a statement that are evaluated by the statement itself.

    For compound statements this excludes the nested bodies, which are
    separate statements with their own program points.
    """
    if isinstance(stmt, (ast.If, ast.While)):
        return [stmt.test]
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return [stmt.iter]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [item.context_expr for item in stmt.items]
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Try)):
        return []
    if hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar):
        return []
    if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
        return [stmt.subject]
    return [stmt]


def iter_calls(node: ast.AST) -> Iterator[ast.Call]:
    """Every call inside `node`, not entering lambdas or nested definitions."""
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Call):
            yield n
        for child in ast.iter_child_nodes(n):
            if not isinstance(child, _SCOPES):
                stack.append(child)


def sink_hits(node: Union[ast.stmt, ast.expr], taint: frozenset, config: Config) -> List[SinkHit]:
    """Sink calls in `node` whose dangerous arguments are tainted.

    `taint` must be the taint set *before* the statement runs, because the
    call's arguments are evaluated before any assignment takes effect.
    """
    roots = header_exprs(node) if isinstance(node, ast.stmt) else [node]
    hits: List[SinkHit] = []
    for root in roots:
        for call in iter_calls(root):
            name = call_name(call.func)
            spec = config.sink_spec(name)
            if spec is None:
                continue
            if any(isinstance(a, ast.Starred) for a in call.args):
                checked = list(call.args)        # f(*args): positions unknown, check all
            else:
                checked = [call.args[i] for i in spec.args if i < len(call.args)]
            origins = _union(checked, taint, config)
            if origins:
                hits.append(SinkHit(call, name, spec, origins))
    hits.sort(key=lambda h: (h.call.lineno, h.call.col_offset))
    return hits
