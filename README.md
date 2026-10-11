# Static Taint Analyzer for Python

Finds places where untrusted input (e.g. `input()`) can reach a dangerous
call (e.g. `cursor.execute`, `os.system`, `eval`) without being sanitized.

## Usage

```
python3 -m taint_analyzer FILE [FILE ...]            # report warnings
python3 -m taint_analyzer FILE --show-cfg            # also print each function's CFG
python3 -m taint_analyzer FILE --config my.json      # custom sources/sinks/sanitizers
python3 -m pytest                                    # run the tests
```

Exit status: 0 = no warnings, 1 = warnings found, 2 = error.

## Pipeline

```
source file --(ast.parse)--> AST --(cfg.py)--> CFG per function --(analysis)--> findings --> report
```

| File | Step | Purpose |
|---|---|---|
| `models.py` | 1 | Shared data structures: `BasicBlock`, `CFG`, `TaintSet`, `Finding` |
| `config.py`, `config.json` | 1 | Sources, sinks (with dangerous argument positions), sanitizers |
| `parser.py` | 2-3 | Parse a file; collect module code and every function/method |
| `expr.py` | 4 | Call names, taint of an expression, per-statement transfer function, sink detection |
| `analysis.py` | 5 | Preliminary analyzer: walks statements in source order (replaced in Step 7) |
| `cfg.py` | 6 | Control-flow graph builder |
| `report.py`, `__main__.py` | 9 | Output and command-line interface |

## Status

- Done: Steps 1-6.
- Next: Step 7, worklist dataflow analysis over the CFG. This fixes the
  linear analyzer's known misses (see `tests/samples/branch_vuln.py`).

## Limitations (current)

- Analysis is per function; values passed into or returned from other
  functions are not tracked. Function parameters start untainted.
- Calls are recognized by their written name (`cursor.execute`), not by
  the object's real type.
- Sources are calls only; e.g. `request.args["q"]` (indexing) is not a source.
- Sink arguments are checked by position only; keyword arguments to sinks are not checked.
- Mutating methods are not modeled: `parts.append(user)` does not taint `parts`.
- Assigning into part of an object (`d[k] = v`, `obj.x = v`) taints the whole
  object, and that taint is never removed.
- Not handled: `match` statements in the CFG, walrus assignments (`:=`),
  variables captured by nested functions, dynamic code (`getattr`, `exec`-generated code).
