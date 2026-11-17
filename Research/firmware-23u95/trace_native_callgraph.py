#!/usr/bin/env python3
"""SHA-pinned bounded call graph for actual watchOS 26.6.1 / 23U95 nanotimekitd.

Maps only direct branch-with-link destinations within the original binary.
Objective-C stub targets are decoded via the same validated selector resolver
already used in this project. A direct graph edge is NOT a sandbox
authorization grant, and no third-party process can inherit daemon privileges.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from resolve_daemon_objc import EXPECTED, sections, sec_at
from resolve_daemon_stubs import stub

# All VAs refer to the exact original ARM64_32 nanotimekitd Mach-O SHA256.
# Listener addresses were recovered from original relative ObjC method lists.
ROOTS = {
    0x1113C: "NTKDCollectionCoordinator listener:shouldAcceptNewConnection:",
    0x2A7D4: "NTKDSyncController listener:shouldAcceptNewConnection:",
    0x315C8: "NTKDFaceSnapshotCoordinator listener:shouldAcceptNewConnection:",
    0x44218: "NTKDComplicationStoreCoordinator listener:shouldAcceptNewConnection:",
    0x45D54: "NTKDDiagnosticExtentionHelper listener:shouldAcceptNewConnection:",
    0x8134: "NTKDCollectionStore _removeUnavailableFacesFromStore:",
    0x8594: "NTKDCollectionStore _addDefaultFacesToStore:",
    0x34658: "NTKDSyncController _updatePairedSyncState",
    0x3E704: "NTKDSyncController _fromSyncResetWithFaces:orderedUUIDs:selectedUUID:",
    0x2E100: "NTKDSyncController _queue_validateLibraryFaces block capture",
    0x3E0C4: "NTKDCollectionStore resetWithFaces block capture",
}
# A known imported C symbol call: NOT an Objective-C stub.
NAMED = {
    0x6BD70: "_NTKFaceStyleIsAvailable",
}
LIMIT_BYTES = 0x580
MAX_INSTRUCTIONS = 300


def parse_target(operand: str):
    match = re.fullmatch(r"#?(?:0x)?([0-9a-fA-F]+)", operand.strip())
    if not match:
        return None
    return int(match.group(1), 16)


def main(binary: str, output_dir: str):
    data = Path(binary).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise SystemExit(f"Untrusted firmware bytes: {digest} != {EXPECTED}")
    sec = sections(data)
    text = next((s for s in sec if s["name"] == "__TEXT,__text"), None)
    if text is None:
        raise SystemExit("Original __TEXT,__text section absent")
    start = int(text["vm"])
    end = start + int(text["size"])
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.detail = False

    methods_path = Path(output_dir) / "validated-method-candidates.json"
    candidates = json.loads(methods_path.read_text())
    original_methods = {}
    for c in candidates:
        pc = int(c["address"], 16)
        original_methods[pc] = c["method"]

    table = []
    for pc, root_name in ROOTS.items():
        if not (start <= pc < end):
            raise SystemExit(f"Known root {root_name} at {pc:#x} outside __text")
        off = int(text["offset"]) + (pc - start)
        length = min(LIMIT_BYTES, end - pc)
        instructions = list(cs.disasm(data[off: off+length], pc))
        if not instructions:
            raise SystemExit(f"No real instructions at root {pc:#x}")
        edges = []
        for ins in instructions[:MAX_INSTRUCTIONS]:
            if ins.mnemonic != "bl":
                continue
            target = parse_target(ins.op_str)
            if target is None:
                continue
            if target in NAMED:
                kind, name = "imported C stub", NAMED[target]
            elif target in original_methods:
                kind, name = "validated Objective-C IMP", original_methods[target]
            else:
                try:
                    resolved = stub(data, sec, target)
                except (ValueError, KeyError, IndexError) as error:
                    resolved = f"unable to resolve: {type(error).__name__}"
                if resolved and not resolved.startswith(("unrecognized", "unresolved", "error", "unable")):
                    kind, name = "resolved Objective-C dispatch stub", resolved
                else:
                    kind, name = "unresolved direct target", resolved
            edges.append({
                "caller_pc": hex(ins.address),
                "target_pc": hex(target),
                "target_kind": kind,
                "target_name": name,
            })
        table.append({
            "root_pc": hex(pc),
            "root_name": root_name,
            "bounded_bytes": length,
            "instructions_decoded": min(len(instructions), MAX_INSTRUCTIONS),
            "direct_bl_edges": edges,
        })

    dest = Path(output_dir)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "native-callgraph-authorization.json").write_text(
        json.dumps({
            "source_sha256": digest,
            "scope": "bounded direct-call edges only; no indirect block or XPC message semantics inferred",
            "root_count": len(table),
            "roots": table
        }, indent=2) + "\n"
    )
    out = [f"original_daemon_sha256={digest}", f"roots={len(table)}"]
    out.append("LIMITATION: this is a direct BL graph, not a complete authorization or XPC contract.")
    for record in table:
        out.append(f"\n=== {record['root_name']} at {record['root_pc']} ===")
        for edge in record["direct_bl_edges"]:
            out.append(
                f"{edge['caller_pc']} -> {edge['target_pc']}: "
                f"{edge['target_kind']} :: {edge['target_name']}"
            )
        if not record["direct_bl_edges"]:
            out.append("No BL edges in bounded window")
    (dest / "native-callgraph-authorization.txt").write_text("\n".join(out) + "\n")
    print("\n".join(out[:9]))
    print(f"Detailed provenance: {dest/'native-callgraph-authorization.txt'}")
    print(f"Machine-readable edges: {dest/'native-callgraph-authorization.json'}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: trace_native_callgraph.py <hash-pinned nanotimekitd> <analysis-output-dir>")
    main(sys.argv[1], sys.argv[2])
