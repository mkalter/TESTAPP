#!/usr/bin/env python3
"""Bounded original 23U95 MobileGestalt internal call-target disassembly.

These are exact BL destinations observed in the original SHA-pinned library,
not symbol guesses. Stop at first RET to avoid crediting adjacent functions.
Read-only, no Watch/XPC/cache operations.
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from trace_cfpreferences_authority import syms
from resolve_daemon_objc import sections

SHA = "a842db6add515926a9ef49da87bc7467974c8e8b52f7550e40f111c455c42bd0"
TARGETS = {
    0x215E128C: "direct BL target at __MGWriteCache+0x30 and __MGRebuildCache+0x88; conditional gate",
    0x215B28F0: "late-binding resolver called by __MGWriteCacheOnHelper w0=0x2e w1=2",
    0x215C10D0: "internal descriptor getter called in __MGWriteCache",
    0x215B1798: "tail-branch target of __MGCacheCopyValueForKey",
    0x215CAAE0: "previously observed matching-23U95 DeviceBrand provider candidate",
}
MAX_INS = 250

def audit(path: str, destination: str):
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA:
        raise RuntimeError(f"Wrong original source sha256: {digest}")
    secs=sections(data)
    code=next((sec for sec in secs if sec["name"]=="__TEXT,__text"), None)
    if not code:
        raise RuntimeError("No valid ARM64_32 __TEXT,__text")
    symbols,_=syms(data)
    by_address={}
    for label,instances in symbols.items():
        for i in instances:
            by_address.setdefault(i["address"], []).append(label)
    md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    result={
        "original_sha256":digest,
        "scope":"Direct internal call destinations, 250 instructions maximum, bounded at first RET; branch alternatives are not a full CFG",
        "addresses":[]
    }
    for pc,why in TARGETS.items():
        if not(code["vm"]<=pc<code["vm"]+code["size"]) or pc % 4:
            raise RuntimeError(f"Target {pc:#x} not inside original __text")
        start=code["offset"]+pc-code["vm"]
        raw=data[start:start+min(MAX_INS*4,code["vm"]+code["size"]-pc)]
        instructions=[]
        edges=[]
        for ins in md.disasm(raw,pc):
            instructions.append(f"{ins.address:#010x} {ins.mnemonic:8} {ins.op_str}")
            if ins.mnemonic in ("b","bl"):
                arg=ins.op_str.lstrip("#")
                try: target=int(arg,16)
                except ValueError: target=0
                if target:
                    edges.append({
                        "from":hex(ins.address), "branch":ins.mnemonic,
                        "to":hex(target), "resolved_names":by_address.get(target,[])[:9]
                    })
            if ins.mnemonic=="ret" and len(instructions)>=5:
                break
            if len(instructions)>=MAX_INS:
                break
        result["addresses"].append({
            "address":hex(pc),
            "reason_in_original_code":why,
            "verified_nlist_symbol_if_any":by_address.get(pc,[]),
            "instructions":instructions,
            "branch_targets":edges,
            "stop_at_ret":bool(instructions and " ret " in instructions[-1]),
        })
    dest=Path(destination);dest.mkdir(exist_ok=True,parents=True)
    (dest/"mg-internal-call-targets.json").write_text(json.dumps(result,indent=2)+"\n")
    text=[f"Verified exact libMobileGestalt SHA256: {digest}"]
    for v in result["addresses"]:
        text.extend(["",f"== {v['address']} ==",
                     v["reason_in_original_code"],
                     f"nlist-at-target={v['verified_nlist_symbol_if_any']}"])
        text.extend(v["instructions"])
        text.append("Resolved direct branches:")
        text.extend(
            f"{x['from']} {x['branch']} {x['to']} {x['resolved_names']}"
            for x in v["branch_targets"]
        )
    text.extend(["","No authorized protected-write path was invoked or demonstrated."])
    (dest/"mg-internal-call-targets.txt").write_text("\n".join(text)+"\n")
    print("Original SHA256",digest)
    for v in result["addresses"]:
        print(v["address"],"instructions",len(v["instructions"]),
              "exit-ret",v["stop_at_ret"],
              "known-sym",v["verified_nlist_symbol_if_any"])
        print("\n".join(v["instructions"][:22]))


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: trace_mg_internal_targets.py <original 23U95 libMobileGestalt> <output>")
    audit(sys.argv[1],sys.argv[2])
