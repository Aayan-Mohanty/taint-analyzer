"""Step 6: build a control-flow graph (CFG) for one function body.

Layout produced for every function:
  entry block -> first block -> ... -> exit block
Every `return` and `raise` jumps to the exit block.

Supported: sequences, if/elif/else, while (+else), for (+else), break,
continue, return, raise, with, try/except/else/finally.
Not supported: `match` (raises UnsupportedSyntax).

Approximations (each only ADDS paths, so the taint analysis may report
extra warnings but does not miss flows because of them):
  - A loop's body may run zero or more times; a `while` test is assumed
    able to go either way, even `while True`.
  - Inside `try`, every statement gets its own block, and every one of
    those blocks has an edge to every `except` handler and to `finally`,
    because an exception can occur after any statement.
  - After `finally`, control continues to the next statement even on the
    exceptional path (where Python would re-raise).
Known gap: `return`/`break`/`continue` inside a `try` that has `finally`
jump directly to their target without passing through the `finally` body.
"""

from __future__ import annotations

import ast
from typing import List, Optional, Tuple

from .models import CFG, BasicBlock


class UnsupportedSyntax(Exception):
    """Raised for statements the CFG builder does not handle."""


def build_cfg(name: str, body: List[ast.stmt]) -> CFG:
    """Build the CFG for a function (or module) body."""
    return _Builder(name).build(body)


class _Builder:
    def __init__(self, name: str) -> None:
        self.cfg = CFG(name)
        # (continue target, break target) for each enclosing loop
        self.loops: List[Tuple[int, int]] = []
        # one list per enclosing `try` body, collecting the blocks created in it
        self.try_scopes: List[List[int]] = []

    # -- helpers ------------------------------------------------------------
    def new_block(self, label: str = "") -> int:
        block = self.cfg.new_block(label)
        for scope in self.try_scopes:
            scope.append(block.id)
        return block.id

    def block(self, bid: int) -> BasicBlock:
        return self.cfg.blocks[bid]

    def edge(self, src: Optional[int], dst: int) -> None:
        if src is not None:
            self.cfg.add_edge(src, dst)

    # -- driver -------------------------------------------------------------
    def build(self, body: List[ast.stmt]) -> CFG:
        cfg = self.cfg
        cfg.entry = self.cfg.new_block("entry").id
        cfg.exit = self.cfg.new_block("exit").id
        first = self.new_block()
        self.edge(cfg.entry, first)
        end = self.visit_body(body, first)
        self.edge(end, cfg.exit)                 # falling off the end returns None
        return cfg

    def visit_body(self, stmts: List[ast.stmt], current: Optional[int]) -> Optional[int]:
        """Add statements starting in block `current`.

        Returns the block where control continues afterwards, or None if
        the body always ends in return/raise/break/continue.
        """
        for stmt in stmts:
            if current is None:                  # code after return/break: unreachable
                current = self.new_block("unreachable")
            current = self.visit_stmt(stmt, current)
            # Inside try: close the block after every statement, so that each
            # intermediate state has its own block (and edge to the handlers).
            if self.try_scopes and current is not None and self.block(current).statements:
                nxt = self.new_block()
                self.edge(current, nxt)
                current = nxt
        return current

    # -- statements ---------------------------------------------------------
    def visit_stmt(self, stmt: ast.stmt, cur: int) -> Optional[int]:
        if isinstance(stmt, ast.If):
            return self.visit_if(stmt, cur)
        if isinstance(stmt, ast.While):
            return self.visit_while(stmt, cur)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            return self.visit_for(stmt, cur)
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            # The header (binding `as` names) goes in the current block,
            # then the body simply continues; no branching is involved.
            self.block(cur).statements.append(stmt)
            return self.visit_body(stmt.body, cur)
        if isinstance(stmt, ast.Try) or (hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar)):
            return self.visit_try(stmt, cur)
        if hasattr(ast, "Match") and isinstance(stmt, ast.Match):
            raise UnsupportedSyntax(f"line {stmt.lineno}: 'match' statements are not supported")
        if isinstance(stmt, (ast.Return, ast.Raise)):
            self.block(cur).statements.append(stmt)
            self.edge(cur, self.cfg.exit)
            return None
        if isinstance(stmt, ast.Break):
            self.block(cur).statements.append(stmt)
            self._require_loop(stmt)
            self.edge(cur, self.loops[-1][1])
            return None
        if isinstance(stmt, ast.Continue):
            self.block(cur).statements.append(stmt)
            self._require_loop(stmt)
            self.edge(cur, self.loops[-1][0])
            return None
        # Simple statement (assignment, call, pass, import, nested def, ...)
        self.block(cur).statements.append(stmt)
        return cur

    def _require_loop(self, stmt: ast.stmt) -> None:
        if not self.loops:
            raise UnsupportedSyntax(f"line {stmt.lineno}: '{type(stmt).__name__.lower()}' outside a loop")

    def _join(self, ends: List[Optional[int]], label: str) -> Optional[int]:
        live = [e for e in ends if e is not None]
        if not live:
            return None
        join = self.new_block(label)
        for e in live:
            self.edge(e, join)
        return join

    def visit_if(self, stmt: ast.If, cur: int) -> Optional[int]:
        self.block(cur).branch_node = stmt.test
        self.block(cur).label = self.block(cur).label or "if"
        then_b = self.new_block("then")
        self.edge(cur, then_b)
        then_end = self.visit_body(stmt.body, then_b)
        if stmt.orelse:                          # `elif` arrives here as a nested If
            else_b = self.new_block("else")
            self.edge(cur, else_b)
            else_end = self.visit_body(stmt.orelse, else_b)
        else:
            else_end = cur                       # condition false: skip the body
        return self._join([then_end, else_end], "join")

    def visit_while(self, stmt: ast.While, cur: int) -> Optional[int]:
        head = self.new_block("while-head")
        self.edge(cur, head)
        self.block(head).branch_node = stmt.test
        after = self.new_block("after-loop")
        body_b = self.new_block("loop-body")
        self.edge(head, body_b)
        self.loops.append((head, after))
        body_end = self.visit_body(stmt.body, body_b)
        self.loops.pop()
        self.edge(body_end, head)                # back edge
        self._loop_exit(stmt.orelse, head, after)
        return after

    def visit_for(self, stmt, cur: int) -> Optional[int]:
        head = self.new_block("for-head")
        self.edge(cur, head)
        # The For node itself is the head's statement: the transfer function
        # treats it as "target = next item of iter".
        self.block(head).statements.append(stmt)
        after = self.new_block("after-loop")
        body_b = self.new_block("loop-body")
        self.edge(head, body_b)
        self.loops.append((head, after))
        body_end = self.visit_body(stmt.body, body_b)
        self.loops.pop()
        self.edge(body_end, head)
        self._loop_exit(stmt.orelse, head, after)
        return after

    def _loop_exit(self, orelse: List[ast.stmt], head: int, after: int) -> None:
        """Loop `else:` runs when the loop ends without `break`."""
        if orelse:
            else_b = self.new_block("loop-else")
            self.edge(head, else_b)
            self.edge(self.visit_body(orelse, else_b), after)
        else:
            self.edge(head, after)

    def visit_try(self, stmt, cur: int) -> Optional[int]:
        self.try_scopes.append([])
        body_b = self.new_block("try")
        self.edge(cur, body_b)
        body_end = self.visit_body(stmt.body, body_b)
        in_try = self.try_scopes.pop()
        # An exception can be raised before the first statement completes
        # (state = `cur`) or after any statement (each block in `in_try`).
        raise_points = [cur] + in_try

        ends: List[Optional[int]] = []
        if stmt.orelse:
            else_b = self.new_block("try-else")
            self.edge(body_end, else_b)
            ends.append(self.visit_body(stmt.orelse, else_b))
        else:
            ends.append(body_end)

        for handler in stmt.handlers:
            h_b = self.new_block("except")
            for src in raise_points:
                self.edge(src, h_b)
            ends.append(self.visit_body(handler.body, h_b))

        if stmt.finalbody:
            fin = self.new_block("finally")
            for e in ends:
                self.edge(e, fin)
            for src in raise_points:             # unhandled exception path
                self.edge(src, fin)
            return self.visit_body(stmt.finalbody, fin)
        return self._join(ends, "after-try")
