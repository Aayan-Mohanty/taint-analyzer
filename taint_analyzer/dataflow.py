"""Step 7: taint analysis as a forward "may" dataflow problem over the CFG.

For every basic block B:
    IN[B]  = union of OUT[P] for every predecessor P     (empty for entry)
    OUT[B] = transfer of B's statements applied to IN[B]

The worklist algorithm recomputes blocks until no OUT set changes (a fixed
point). It terminates because:
  - the sets only contain variable names that occur in the function, so
    there are finitely many possible sets, and
  - the transfer function is monotone (a larger IN never gives a smaller
    OUT) and OUT starts empty, so each OUT set can only grow.

Union at merge points makes this a "may" analysis: a variable counts as
tainted after a merge if it is tainted on AT LEAST ONE incoming path.
The analysis is path-insensitive: it does not track which branch
conditions hold, so it can warn about paths that can never execute
(see tests/samples/infeasible_path_fp.py).
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .analysis import analyze_linear
from .cfg import CFG, UnsupportedSyntax, build_cfg
from .config import Config
from .expr import SinkHit, sink_hits, transfer
from .models import EMPTY_TAINT, Finding
from .parser import FunctionInfo


@dataclass
class DataflowResult:
    cfg: CFG
    taint_in: Dict[int, frozenset]
    taint_out: Dict[int, frozenset]
    iterations: int                   # number of block computations performed


def solve(cfg: CFG, config: Config) -> DataflowResult:
    """Run the worklist algorithm to a fixed point."""
    taint_in = {bid: EMPTY_TAINT for bid in cfg.blocks}
    taint_out = {bid: EMPTY_TAINT for bid in cfg.blocks}

    # Every block is computed at least once, in creation order (roughly
    # source order, which tends to reach the fixed point in few passes).
    worklist = deque(sorted(cfg.blocks))
    queued = set(worklist)
    iterations = 0

    while worklist:
        bid = worklist.popleft()
        queued.discard(bid)
        iterations += 1
        block = cfg.blocks[bid]

        new_in = EMPTY_TAINT
        for pred in block.predecessors:
            new_in = new_in | taint_out[pred]          # merge: union
        new_out = new_in
        for stmt in block.statements:
            new_out = transfer(stmt, new_out, config)

        taint_in[bid] = new_in
        if new_out != taint_out[bid]:
            taint_out[bid] = new_out
            for succ in block.successors:              # successors must be recomputed
                if succ not in queued:
                    worklist.append(succ)
                    queued.add(succ)

    return DataflowResult(cfg, taint_in, taint_out, iterations)


def collect_findings(result: DataflowResult, config: Config,
                     func_name: str, filename: str) -> List[Finding]:
    """Replay each block from its IN set and check every sink call."""
    found: Dict[tuple, Finding] = {}

    def record(hit: SinkHit) -> None:
        key = (hit.call.lineno, hit.call.col_offset, hit.sink)
        found.setdefault(key, Finding(
            file=filename, function=func_name, line=hit.call.lineno,
            sink=hit.sink, category=hit.spec.category,
            tainted_vars=tuple(sorted(hit.origins)),
            code=ast.unparse(hit.call)))

    for bid, block in result.cfg.blocks.items():
        state = result.taint_in[bid]
        for stmt in block.statements:
            for hit in sink_hits(stmt, state, config):  # state BEFORE the statement
                record(hit)
            state = transfer(stmt, state, config)
        if block.branch_node is not None:               # e.g. `if eval(x):`
            for hit in sink_hits(block.branch_node, state, config):
                record(hit)
    return [found[k] for k in sorted(found)]


@dataclass
class FunctionResult:
    findings: List[Finding]
    dataflow: Optional[DataflowResult] = None
    note: str = ""                    # set when the CFG could not be built


def analyze_function(func: FunctionInfo, config: Config, filename: str) -> FunctionResult:
    """CFG-based analysis; falls back to the linear analyzer for unsupported syntax."""
    try:
        cfg = build_cfg(func.name, func.body)
    except UnsupportedSyntax as e:
        return FunctionResult(analyze_linear(func, config, filename),
                              note=f"{filename}: {func.name}(): {e}; used the less precise linear analysis")
    result = solve(cfg, config)
    return FunctionResult(collect_findings(result, config, func.name, filename), result)


def format_taint_table(result: DataflowResult) -> str:
    """Per-block IN/OUT sets, for debugging and for the report."""
    def fmt(s: frozenset) -> str:
        return "{" + ", ".join(sorted(s)) + "}"
    cfg = result.cfg
    lines = [f"Taint sets for '{cfg.function_name}' "
             f"(fixed point after {result.iterations} block computations)"]
    for bid in sorted(cfg.blocks):
        label = f" [{cfg.blocks[bid].label}]" if cfg.blocks[bid].label else ""
        lines.append(f"  Block {bid}{label}: IN={fmt(result.taint_in[bid])}  "
                     f"OUT={fmt(result.taint_out[bid])}")
    return "\n".join(lines)
