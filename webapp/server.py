"""Web backend for the taint analyzer (Python standard library only).

    python3 -m webapp.server            # then open http://127.0.0.1:8000
    python3 -m webapp.server --port 9000

On a hosting platform (e.g. Render), run:
    python -m webapp.server --host 0.0.0.0
The port is then taken from the PORT environment variable the platform sets.

Endpoints:
    GET  /                 the web page (webapp/static/index.html)
    GET  /api/samples      the sample programs in tests/samples
    POST /api/analyze      body {"code": "...", "mode": "cfg" | "linear"}

The submitted code is only parsed with ast.parse, never executed.
"""

from __future__ import annotations

import argparse
import ast
import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from taint_analyzer.analysis import analyze_linear
from taint_analyzer.cfg import UnsupportedSyntax, build_cfg
from taint_analyzer.config import load_config
from taint_analyzer.dataflow import analyze_function
from taint_analyzer.parser import extract_functions, parse_source

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
SAMPLES = ROOT.parent / "tests" / "samples"
MAX_BODY = 200_000            # bytes; enough for any reasonable single file
CONFIG = load_config()


def _block_json(cfg, block, taint_in=None, taint_out=None):
    lines = []
    for stmt in block.statements:
        lines.append({"line": stmt.lineno, "text": ast.unparse(stmt).splitlines()[0]})
    return {
        "id": block.id,
        "label": block.label,
        "lines": lines,
        "branch": ast.unparse(block.branch_node) if block.branch_node is not None else None,
        "succ": list(block.successors),
        "pred": list(block.predecessors),
        "in": sorted(taint_in[block.id]) if taint_in else None,
        "out": sorted(taint_out[block.id]) if taint_out else None,
    }


def analyze_code(code: str, mode: str) -> dict:
    try:
        tree = parse_source(code, filename="<input>")
    except SyntaxError as e:
        return {"ok": False, "error": f"Syntax error on line {e.lineno}: {e.msg}", "line": e.lineno}

    findings, functions = [], []
    for func in extract_functions(tree):
        info = {"name": func.name, "lineno": func.lineno, "note": "", "iterations": None, "blocks": []}
        if mode == "linear":
            func_findings = analyze_linear(func, CONFIG, "<input>")
            try:
                cfg = build_cfg(func.name, func.body)
                info.update(entry=cfg.entry, exit=cfg.exit,
                            blocks=[_block_json(cfg, b) for b in cfg.blocks.values()])
            except UnsupportedSyntax as e:
                info["note"] = str(e)
        else:
            res = analyze_function(func, CONFIG, "<input>")
            func_findings = res.findings
            info["note"] = res.note
            if res.dataflow is not None:
                df = res.dataflow
                info.update(entry=df.cfg.entry, exit=df.cfg.exit, iterations=df.iterations,
                            blocks=[_block_json(df.cfg, b, df.taint_in, df.taint_out)
                                    for b in df.cfg.blocks.values()])
        functions.append(info)
        for f in func_findings:
            findings.append({"function": f.function, "line": f.line, "sink": f.sink,
                             "category": f.category, "via": list(f.tainted_vars), "code": f.code})
    findings.sort(key=lambda f: f["line"])
    return {"ok": True, "mode": mode, "findings": findings, "functions": functions}


def list_samples() -> list:
    out = []
    for path in sorted(SAMPLES.glob("*.py")):
        code = path.read_text(encoding="utf-8")
        first = code.splitlines()[0] if code else ""
        out.append({"name": path.name, "expect": first.lstrip("# ").strip(), "code": code})
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "TaintAnalyzer/1.0"

    def _send(self, status, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status=HTTPStatus.OK) -> None:
        self._send(status, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/samples":
            return self._json(list_samples())
        if path == "/":
            path = "/index.html"
        target = (STATIC / path.lstrip("/")).resolve()
        if STATIC not in target.parents or not target.is_file():   # blocks ../ escapes
            return self._json({"ok": False, "error": "Not found"}, HTTPStatus.NOT_FOUND)
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype == "application/javascript":
            ctype += "; charset=utf-8"
        self._send(HTTPStatus.OK, target.read_bytes(), ctype)

    def do_HEAD(self) -> None:          # some uptime/health checkers use HEAD
        self.send_response(HTTPStatus.OK if self.path.split("?", 1)[0] in ("/", "/index.html") else HTTPStatus.NOT_FOUND)
        self.end_headers()

    def do_POST(self) -> None:
        if self.path != "/api/analyze":
            return self._json({"ok": False, "error": "Not found"}, HTTPStatus.NOT_FOUND)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            return self._json({"ok": False, "error": f"Request must be under {MAX_BODY} bytes"},
                              HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
            code, mode = data.get("code", ""), data.get("mode", "cfg")
            if not isinstance(code, str) or mode not in ("cfg", "linear"):
                raise ValueError
        except (ValueError, AttributeError):
            return self._json({"ok": False, "error": 'Send JSON: {"code": "...", "mode": "cfg" or "linear"}'},
                              HTTPStatus.BAD_REQUEST)
        try:
            self._json(analyze_code(code, mode))
        except RecursionError:
            self._json({"ok": False, "error": "The code is nested too deeply to analyze."})

    def log_message(self, fmt, *args) -> None:   # one short line per request
        print(f"{self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the taint analyzer web app.")
    ap.add_argument("--host", default="127.0.0.1",
                    help="default 127.0.0.1 (this computer only); use 0.0.0.0 on a hosting platform")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")),
                    help="default: the PORT environment variable if set, otherwise 8000")
    args = ap.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Taint analyzer running at http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
