# Static Taint Analyzer for Python

Finds places where untrusted input (e.g. `input()`) can reach a dangerous
call (e.g. `cursor.execute`, `os.system`, `eval`) without being sanitized.

## Usage

```
python3 -m taint_analyzer FILE [FILE ...]            # report warnings
python3 -m taint_analyzer FILE --show-cfg            # also print each function's CFG
python3 -m taint_analyzer FILE --show-taint          # also print each block's IN/OUT taint sets
python3 -m taint_analyzer FILE --linear              # use the preliminary analyzer (for comparison)
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
| `analysis.py` | 5 | Preliminary analyzer: walks statements in source order (kept for comparison, `--linear`) |
| `cfg.py` | 6 | Control-flow graph builder |
| `dataflow.py` | 7 | Worklist dataflow analysis over the CFG (the default analysis) |
| `report.py`, `__main__.py` | 9 | Output and command-line interface |

## Status

- Done: Steps 1-7 (sanitizers, Step 8, are included through `config.json`).
- Next: larger labeled test suite and precision/recall evaluation; then
  string/container modeling and interprocedural analysis.

## Results on the bundled samples

13 hand-written programs in `tests/samples/`: 8 contain a real vulnerability,
5 do not (one of those, `infeasible_path_fp.py`, is built to trigger a false positive).

| Analyzer | Detected (of 8) | Missed | False positives |
|---|---|---|---|
| CFG dataflow (default) | 8 | 0 | 1 |
| Linear (`--linear`) | 5 | 3 (branch, loop, try) | 1 |

These samples were written to exercise specific features, so the numbers
show which cases each analyzer handles; they are not a measure of accuracy
on real-world code.

## Limitations (current)

- The analysis is path-insensitive: it ignores branch conditions, so it can
  warn about paths that can never run (`infeasible_path_fp.py`).
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
