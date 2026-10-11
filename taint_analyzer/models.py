"""Core data structures shared by every part of the analyzer.

Both team members code against these definitions, so change them only
after agreeing together.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Taint set
# ---------------------------------------------------------------------------
# The set of variable names that MAY hold untrusted data at a program point.
# A frozenset is used because it is immutable and hashable: during the
# fixed-point iteration we compare old and new sets with ==, and an
# immutable value cannot be modified by accident after it is stored.
TaintSet = frozenset  # usage: TaintSet({"name", "query"})

EMPTY_TAINT: frozenset = frozenset()


# ---------------------------------------------------------------------------
# Control-flow graph
# ---------------------------------------------------------------------------
@dataclass
class BasicBlock:
    """A straight-line sequence of statements with one entry and one exit.

    Control enters only at the first statement and leaves only after the
    last one. Branching happens only between blocks, through the edges.
    """

    id: int
    statements: List[ast.stmt] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    # Optional human-readable tag, e.g. "entry", "exit", "if-test", "loop-head".
    label: str = ""
    # For blocks that end in a branch (if / while / for), the AST node whose
    # test decides which successor runs. The analysis does not need it for
    # taint, but it makes CFG printouts readable.
    branch_node: Optional[ast.AST] = None

    def __repr__(self) -> str:  # short form, avoids dumping whole AST nodes
        return (f"BasicBlock(id={self.id}, label={self.label!r}, "
                f"stmts={len(self.statements)}, succ={self.successors}, "
                f"pred={self.predecessors})")


@dataclass
class CFG:
    """Control-flow graph for a single function."""

    function_name: str
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    entry: int = -1
    exit: int = -1
    _next_id: int = 0

    def new_block(self, label: str = "") -> BasicBlock:
        """Create a block with a fresh id and register it in the graph."""
        block = BasicBlock(id=self._next_id, label=label)
        self.blocks[block.id] = block
        self._next_id += 1
        return block

    def add_edge(self, src: int, dst: int) -> None:
        """Add a directed edge src -> dst, ignoring duplicates."""
        if dst not in self.blocks[src].successors:
            self.blocks[src].successors.append(dst)
        if src not in self.blocks[dst].predecessors:
            self.blocks[dst].predecessors.append(src)

    def pretty(self) -> str:
        """Return a readable text dump of the graph (needs Python 3.9+)."""
        lines = [f"CFG for function '{self.function_name}' "
                 f"(entry={self.entry}, exit={self.exit})"]
        for bid in sorted(self.blocks):
            b = self.blocks[bid]
            tag = f" [{b.label}]" if b.label else ""
            lines.append(f"  Block {bid}{tag}")
            for stmt in b.statements:
                text = ast.unparse(stmt).splitlines()[0]
                lines.append(f"    L{stmt.lineno}: {text}")
            if b.branch_node is not None:
                lines.append(f"    branch on: {ast.unparse(b.branch_node)}")
            lines.append(f"    -> {b.successors if b.successors else 'none'}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Analysis output
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Finding:
    """One possible vulnerability: tainted data reaching a sink.

    Named Finding rather than Warning, because Warning is a Python builtin.
    """

    file: str
    function: str
    line: int
    sink: str                 # dotted sink name, e.g. "cursor.execute"
    category: str             # e.g. "sql_injection"
    tainted_vars: tuple       # sorted variable names that carried the taint
    code: str                 # source text of the offending statement

    def format(self) -> str:
        vars_text = ", ".join(self.tainted_vars) if self.tainted_vars else "(direct source call)"
        return (f"{self.file}:{self.line}: [{self.category}] in {self.function}(): "
                f"tainted data reaches {self.sink} via {vars_text}\n"
                f"    {self.code}")
