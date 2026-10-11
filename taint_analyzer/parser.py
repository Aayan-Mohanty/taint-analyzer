"""Step 2-3: read a Python file and collect the functions to analyze."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Union

MODULE_NAME = "<module>"


@dataclass
class FunctionInfo:
    """One unit of analysis: a function body, or the module's top-level code."""

    name: str              # qualified name, e.g. "Repo.find" or "outer.<locals>.inner"
    body: List[ast.stmt]   # the statements to analyze
    lineno: int
    node: ast.AST          # the FunctionDef / AsyncFunctionDef, or the Module


def parse_source(source: str, filename: str = "<string>") -> ast.Module:
    """Parse source text. Raises SyntaxError for invalid Python."""
    return ast.parse(source, filename=filename)


def parse_file(path: Union[str, Path]) -> ast.Module:
    """Read and parse a file. Raises OSError or SyntaxError."""
    path = Path(path)
    return parse_source(path.read_text(encoding="utf-8"), filename=str(path))


class _FunctionCollector(ast.NodeVisitor):
    """Finds every function and method, including nested ones.

    Qualified names follow Python's own __qualname__ convention.
    """

    def __init__(self) -> None:
        self.prefix: List[str] = []
        self.found: List[FunctionInfo] = []

    def _visit_function(self, node) -> None:
        qualname = ".".join(self.prefix + [node.name])
        self.found.append(FunctionInfo(qualname, node.body, node.lineno, node))
        self.prefix += [node.name, "<locals>"]
        self.generic_visit(node)
        del self.prefix[-2:]

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.prefix.append(node.name)
        self.generic_visit(node)
        self.prefix.pop()


def extract_functions(tree: ast.Module, include_module: bool = True) -> List[FunctionInfo]:
    """Return the module's top-level code (optional) followed by every function.

    Top-level code is included because small scripts often call input() and
    a sink directly, outside any function. Function and class definitions
    inside it only bind a name there; their bodies are analyzed separately.
    """
    collector = _FunctionCollector()
    collector.visit(tree)
    units: List[FunctionInfo] = []
    if include_module:
        units.append(FunctionInfo(MODULE_NAME, tree.body, 1, tree))
    units.extend(collector.found)
    return units
