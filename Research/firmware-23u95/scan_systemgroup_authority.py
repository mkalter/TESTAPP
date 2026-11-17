#!/usr/bin/env python3
"""Exact watchOS sandbox extension-class search: issuer vs receiver.

Uses hash-tracked decompiled kernel policies, not live probing. Every result
is a *candidate condition*, NEVER evidence of a writable file descriptor.
"""
from __future__ import annotations
import argparse
import json
import re
import zipfile

TARGET = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"

def forms(source):
    depth = 0
    quoted = False
    escaped = False
    comment = False
    start = 0
    for i, ch in enumerate(source):
        if comment:
            if ch == "\n": comment = False
            continue
        if quoted:
            if escaped: escaped = False
            elif ch == "\\": escaped = True
            elif ch == '"': quoted = False
            continue
        if ch == ";" and source[i:i+2] == ";;":
            comment = True
            continue
        if ch == '"': quoted = True
        elif ch == "(":
            if depth == 0: start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0: raise ValueError("Unbalanced profile")
            if depth == 0:
                yield source.count("\n", 0, start)+1, source[start:i+1]
    if depth or quoted: raise ValueError("Unclosed profile")

def names(block, predicate):
    return sorted(set(re.findall(r'\(' + re.escape(predicate) + r'\s+"([^"]+)"\)', block)))

def relation(block):
    sub = names(block, "subpath")
    exact = names(block, "literal")
    patterns = re.findall(r'\(regex\s+#?"([^"]+)"', block)
    matched = [p for p in sub if TARGET == p or TARGET.startswith(p.rstrip("/")+"/")]
    matched += [p for p in exact if TARGET == p]
    for p in patterns:
        try:
            if re.search(p, TARGET): matched.append(p)
        except re.error: pass
    if matched: return "MATCH", matched
    # The emitter uses placeholders for some OTHER container roots.
    # Their expansion is unknown: do not assume their grants apply to MG.
    if any("$"+"{" in p or "[^" in p for p in sub+exact):
        return "UNKNOWN", []
    if not (sub or exact or patterns): return "UNRESTRICTED_BY_PATH_PREDICATE", []
    return "NO_MATCH", []

def collect(profile, action):
    result = []
    for line, block in forms(profile):
        if not block.startswith("(allow "+action): continue
        match, evidence = relation(block)
        result.append({
            "line": line, "path_match": match, "matching_path_rules": evidence,
            "extension_classes": names(block, "extension-class"),
            "extensions": names(block, "extension"),
            "entitlement_predicates": sorted(set(re.findall(
                r'\(%entitlement-[^\s]+\s+"([^"]+)"', block))),
            "profile_flags": names(block, "profile-flag")
        })
    return result

def analyze(issuer, receiver, version):
    issue = collect(issuer, "file-issue-extension")
    allow = collect(receiver, "file-write-data")
    classes = sorted(set(
        c for r in issue+allow for c in r["extension_classes"]+r["extensions"]
    ))
    results = []
    for c in classes:
        issuance = [r for r in issue if c in r["extension_classes"] and r["path_match"] != "NO_MATCH"]
        acceptance = [r for r in allow if
                      c in r["extensions"]+r["extension_classes"] and r["path_match"] != "NO_MATCH"]
        results.append({
            "class": c,
            "target_issuer_rules": issuance,
            "receiver_write_rule_candidates": acceptance,
            "explicit_target_issuer_match": any(
                r["path_match"]=="MATCH" for r in issuance),
            "receiver_private_entitlements_mentioned": sorted(set(
                e for r in acceptance for e in r["entitlement_predicates"]
                if e.startswith("com.apple.private.") or "system-group" in e
            ))
        })
    return {
        "source": version, "target": TARGET,
        "issuer_rule_count": len(issue), "receiver_rule_count": len(allow),
        "classes": results,
        "limitations": [
            "Conditional require-any/require-all branches and dynamic macros NOT fully evaluated",
            "Permission/entitlement lists are mentions, not proof every predicate is required",
            "Issuer access does not establish that an unprivileged client can obtain a token",
            "No process identity, POSIX DAC, XPC call or on-device write was evaluated"
        ]
    }

def read_zip(path, member):
    with zipfile.ZipFile(path) as z: return z.read(member).decode()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--watch26", required=True)
    p.add_argument("--watch27")
    p.add_argument("--output", required=True)
    args = p.parse_args()
    reports = [analyze(
        read_zip(args.watch26, "commands/containermanagerd.sb"),
        read_zip(args.watch26, "commands/baseline.sb"),
        "Watch6,18 / 23U95")]
    if args.watch27:
        reports.append(analyze(
            read_zip(args.watch27, "new-containermanagerd.sb"),
            read_zip(args.watch27, "new-baseline.sb"),
            "watchOS 27 comparator (another Watch model)"))
    with open(args.output, "w") as f: json.dump(reports, f, indent=2)
    for report in reports:
        print(report["source"])
        for row in report["classes"]:
            if row["explicit_target_issuer_match"]:
                print("EXPLICIT TARGET ISSUER:", row["class"],
                      "receiver candidates:", len(row["receiver_write_rule_candidates"]),
                      "private entitlement mentions:", row["receiver_private_entitlements_mentioned"])
        print("No functioning writer can be inferred from the static matrix.")

if __name__ == "__main__": main()
