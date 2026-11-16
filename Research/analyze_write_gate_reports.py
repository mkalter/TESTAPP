#!/usr/bin/env python3
"""Summarize HermesEnabler's *read-only* write-authorization diagnostics.

Usage:
  python3 Research/analyze_write_gate_reports.py 26-gates.txt
  python3 Research/analyze_write_gate_reports.py 26-gates.txt 27-gates.txt

Inputs are text reports produced by BQRunWriteGateDiagnostics. No device
access, sandbox changes, privileged service calls, or protected writes occur.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from pathlib import Path
import re

TARGETS = (
    "Protected MG cache file",
    "Protected MG cache directory",
    "Protected SystemGroup Library",
    "Own Documents directory",
    "Own log file (control)",
    "Own App Group (control)",
)
OPERATIONS = (
    "file-read-data", "file-write-data", "file-write-create",
    "file-write-unlink", "file-write-mode", "file-write-xattr",
)

def parse_report(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    result = {"name": str(path), "os": None, "bundle": None, "entitlements": {},
              "targets": OrderedDict()}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("OS: "):
            result["os"] = line.removeprefix("OS: ")
        elif line.startswith("bundle="):
            result["bundle"] = line.removeprefix("bundle=")
        elif line.startswith("com.apple.security.") and " : " in line:
            key, value = line.split(" : ", 1)
            result["entitlements"][key] = value
        elif line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
            current = name if name in TARGETS else None
            if current:
                result["targets"][current] = {}
        elif current and "=" in line:
            key, value = line.split("=", 1)
            result["targets"][current][key] = value
    return result

def summary(report: dict) -> list[str]:
    name = report["name"]
    mg = report["targets"].get("Protected MG cache file", {})
    own = report["targets"].get("Own log file (control)", {})
    group = report["targets"].get("Own App Group (control)", {})
    private = [key for key in (
        "com.apple.security.system-group-containers",
        "com.apple.security.system-groups"
    ) if report["entitlements"].get(key, "").startswith("PRESENT")]
    write_rule = mg.get("file-write-data", "UNKNOWN")
    read_rule = mg.get("file-read-data", "UNKNOWN")
    write_open = mg.get("open(O_WRONLY|O_NOFOLLOW), NO WRITE", "UNKNOWN")
    mount = mg.get("filesystem", "UNKNOWN")
    own_write = own.get("file-write-data", "UNKNOWN")
    group_write = group.get("file-write-data", "UNKNOWN")
    lines = [
        f"Report: {name}",
        f"OS: {report['os'] or 'unavailable'}",
        f"App: {report['bundle'] or 'unavailable'}",
        f"Protected MG: read={read_rule}; write={write_rule}",
        f"Protected MG: write-open without writing={write_open}",
        f"Own log: write={own_write}; own App Group: write={group_write}",
        f"MG filesystem: {mount}",
        "Private system-group entitlement observed: " + (", ".join(private) if private else "none reported"),
    ]
    if (write_rule.startswith("DENY") and "DENIED 1 " in write_open
        and (own_write == "ALLOW" or group_write == "ALLOW")):
        lines.append("Interpretation: strong evidence of a protected SystemGroup sandbox authorization gate.")
    elif write_rule == "ALLOW" and "DENIED" in write_open:
        lines.append("Interpretation: write-open denied despite ALLOW policy; investigate other OS/file restrictions.")
    elif write_rule == "UNKNOWN" or "unavailable" in write_rule.lower():
        lines.append("Interpretation: sandbox policy evidence unavailable; do not infer ALLOW.")
    else:
        lines.append("Interpretation: incomplete or mixed signals; further verification needed.")
    return lines

def compare(before: dict, after: dict) -> list[str]:
    out = ["", "26/27 COMPARISON (observation only):"]
    for target in TARGETS:
        a = before["targets"].get(target, {})
        b = after["targets"].get(target, {})
        for key in OPERATIONS:
            va, vb = a.get(key, "NOT TESTED"), b.get(key, "NOT TESTED")
            if va != vb:
                out.append(f"  {target} / {key}: {va} -> {vb}")
    if len(out) == 2:
        out.append("  No captured policy differences, or one/both reports lack comparable fields.")
    out.append("A difference does not itself establish an exploitable or safely writable cache.")
    return out

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path, help="One or two mg-write-gates.txt reports")
    args = parser.parse_args()
    if len(args.reports) > 2:
        parser.error("Provide one or two reports.")
    results = [parse_report(path) for path in args.reports]
    for report in results:
        print("\n".join(summary(report)))
        print()
    if len(results) == 2:
        print("\n".join(compare(*results)))

if __name__ == "__main__":
    main()
