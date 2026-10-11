"""Command-line entry point.

    python3 -m taint_analyzer FILE [FILE ...] [--config PATH]
                              [--show-cfg] [--show-taint] [--linear]

Exit status: 0 = no warnings, 1 = warnings found, 2 = error.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .analysis import analyze_linear
from .cfg import UnsupportedSyntax, build_cfg
from .config import ConfigError, load_config
from .dataflow import analyze_function, format_taint_table
from .parser import extract_functions, parse_file
from .report import format_report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="taint_analyzer",
                                 description="Find untrusted input reaching dangerous calls.")
    ap.add_argument("files", nargs="+", help="Python files to analyze")
    ap.add_argument("--config", help="JSON file with sources, sinks, sanitizers")
    ap.add_argument("--show-cfg", action="store_true", help="print the control-flow graph of each function")
    ap.add_argument("--show-taint", action="store_true", help="print each block's IN/OUT taint sets")
    ap.add_argument("--linear", action="store_true",
                    help="use the preliminary top-to-bottom analyzer instead of the CFG analysis (for comparison)")
    args = ap.parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    findings, units, errors = [], 0, False
    for path in args.files:
        try:
            tree = parse_file(path)
        except (OSError, SyntaxError) as e:
            print(f"error: cannot analyze {path}: {e}", file=sys.stderr)
            errors = True
            continue
        for func in extract_functions(tree):
            units += 1
            if args.linear:
                if args.show_cfg:
                    try:
                        print(build_cfg(func.name, func.body).pretty() + "\n")
                    except UnsupportedSyntax as e:
                        print(f"(no CFG for {func.name}: {e})\n")
                findings.extend(analyze_linear(func, config, path))
                continue
            res = analyze_function(func, config, path)
            if res.note:
                print(f"note: {res.note}", file=sys.stderr)
            if res.dataflow is not None:
                if args.show_cfg:
                    print(res.dataflow.cfg.pretty() + "\n")
                if args.show_taint:
                    print(format_taint_table(res.dataflow) + "\n")
            findings.extend(res.findings)

    print(format_report(findings, len(args.files), units))
    if errors:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
