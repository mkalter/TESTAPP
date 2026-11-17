#!/usr/bin/env python3
"""Read-only 23U95 libMobileGestalt writer/cache authority audit.

Must be run on the original Watch6,18 / 23U95 / ARM64_32 dyld-extracted
/usr/lib/libMobileGestalt.dylib with the known SHA-256. Distinguishes literal
strings, nlist symbols, callable C implementations, and direct call edges.
No device operations, entitlements, IPC calls, or protected-file mutations.
"""
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path
import trace_cfpreferences_authority as macho

EXPECTED_SHA256 = "a842db6add515926a9ef49da87bc7467974c8e8b52f7550e40f111c455c42bd0"
MARKERS = [
    "setCacheValue", "MGSetAnswer", "MGWrite", "MGRebuild",
    "MGServer", "MGCache", "MGCopyAnswer", "MobileGestalt",
    "CacheSentinel", "MGSetServer", "MGInvalidate", "MGGet",
]
# The original C external symbol has Mach-O's leading underscore.
# No symbol in this list is assumed exported until nlist evidence exists.
SELECTORS = [
    "_MGCopyAnswer", "_MGCopyAnswerWithError",
    "_MGServerCopyAnswerWithError", "__MGServerCopyAnswerWithError",
    "_MGRebuildCache", "__MGRebuildCache",
    "_MGWriteCache", "__MGWriteCache",
    "_MGWriteRebuildCacheSentinel", "__MGWriteRebuildCacheSentinel",
    "_MGRebuildCache4PurpleRestore", "__MGRebuildCache4PurpleRestore",
    "_MGSetAnswer", "__MGSetAnswer", "MGSetAnswer", "_MGSetServer",
]
def audit(original_binary: str, output: str):
    raw = Path(original_binary).read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != EXPECTED_SHA256:
        raise RuntimeError(
            f"STOP: wrong binary SHA256={observed}; expected 23U95 {EXPECTED_SHA256}"
        )
    table, nsyms = macho.syms(raw)
    matches = []
    for symbol, versions in sorted(table.items()):
        if not any(m.lower() in symbol.lower() for m in MARKERS):
            continue
        for record in versions:
            matches.append({
                "name": symbol, "address": hex(record["address"]),
                "nlist_type": hex(record["type"]), "nlist_section": record["section"],
                # N_EXT=0x01, N_TYPE=0x0E, N_SECT=0x0E.
                "external": bool(record["type"] & 0x01),
                "defined_in_section": (record["type"] & 0x0E) == 0x0E,
            })
    # Source strings are only *literal bytes*; not evidence of a defined API.
    string_hits = {}
    for term in MARKERS:
        locations = [m.start() for m in re.finditer(re.escape(term.encode("ascii")), raw)]
        if locations:
            string_hits[term] = {
                "count": len(locations),
                "first_file_offsets": [hex(p) for p in locations[:12]],
            }
    targets = sorted(set(
        sym for sym, records in table.items()
        if sym in SELECTORS and any(r["address"] for r in records)
    ))
    # Prevent digest or global symbol-name substitutions from becoming a
    # false positive: the shared verifier demands the actual Mach-O nlist and
    # checks each selected address is inside the original __TEXT,__text.
    macho.EXPECTED = EXPECTED_SHA256
    macho.TARGET_NAMES = targets
    decoded = macho.targeted(raw, original_binary)
    export = {
        "source": "Apple original Watch6,18 23U95 /usr/lib/libMobileGestalt.dylib",
        "sha256": observed,
        "nlist_total": nsyms,
        "name_substring_symbol_matches": matches,
        "literal_byte_string_matches": string_hits,
        "explicit_candidate_names": SELECTORS,
        "code_targets_resolved": targets,
        "verified_code": decoded["target_methods"],
        "code_candidates_missing_from_text": decoded["missing_targets"],
        "limitations": [
            "String occurrence is not evidence of a callable setter.",
            "nlist symbol is not proof of external visibility or sandbox permission.",
            "Direct BL call targets are incomplete; indirect calls and cache-state transitions remain unresolved.",
            "No actual Watch6,18 mobilegestalt data, XPC, cache file, or registered system property was changed.",
        ],
    }
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    (directory/"mobilegestalt-writer-analysis.json").write_text(
        json.dumps(export, indent=2)+"\n"
    )
    txt = [
        "Exact Watch6,18 23U95 libMobileGestalt writer and cache control-flow audit",
        "Original binary SHA256="+observed,
        "Mach-O nlist symbols="+str(nsyms),
        "Names found as actual nlist symbols:",
    ]
    for v in matches:
        txt.append(
            f"  {v['name']} @{v['address']} defined={v['defined_in_section']} "
            f"external={v['external']} type={v['nlist_type']}"
        )
    txt.append("String-only matches (must NOT be mistaken for API):")
    for name, entry in string_hits.items():
        txt.append(f"  {name}: occurrences={entry['count']}, first={entry['first_file_offsets'][:3]}")
    for v in decoded["target_methods"]:
        txt.append(f"\n=== {v['label']} @{v['method_address']} ({v['bytes']} bytes) ===")
        txt.extend(v["instructions"])
        txt.append("Immediate direct calls:")
        for edge in v["direct_calls"]:
            txt.append(f"  {edge['pc']} -> {edge['target']} {edge['names']}")
    txt.append("\nNo caller-authorized arbitrary MobileGestalt writer is established by this audit.")
    (directory/"mobilegestalt-writer-analysis.txt").write_text("\n".join(txt)+"\n")
    print("\n".join(txt[:min(60,len(txt))]))
    print("disassembled_implementations="+str(len(decoded["target_methods"])))
    if not decoded["target_methods"]:
        raise RuntimeError("No target implementation independently identified")


if __name__ == "__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: trace_mobilegestalt_authority.py <original libMobileGestalt.dylib> <output-dir>")
    audit(sys.argv[1], sys.argv[2])
