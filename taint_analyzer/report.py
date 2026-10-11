"""Step 9 (basic): turn findings into readable text."""

from __future__ import annotations

from collections import Counter
from typing import List

from .models import Finding


def format_report(findings: List[Finding], files: int, units: int) -> str:
    lines = [f.format() for f in findings]
    if findings:
        by_cat = Counter(f.category for f in findings)
        cats = ", ".join(f"{n} {c}" for c, n in sorted(by_cat.items()))
        lines.append("")
        lines.append(f"{len(findings)} possible vulnerabilit{'y' if len(findings) == 1 else 'ies'} "
                     f"({cats}) in {files} file(s), {units} function(s) analyzed.")
        lines.append("Each warning is a possible vulnerability to review, not a confirmed one.")
    else:
        lines.append(f"No tainted data reaches a sink in {files} file(s), {units} function(s) analyzed.")
    return "\n".join(lines)
