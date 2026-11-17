#!/usr/bin/env python3
"""Exact-hash read-only ARM64_32 MobileGestaltHelper Objective-C entry audit.

Distinguishes a selector existing as a string from an actual Objective-C
method implementation, and reports only disassembly verified by method
metadata. Does not call privileged services or mutate any Apple device.
"""
from __future__ import annotations
import hashlib
import json
import struct
import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from resolve_daemon_objc import sections, sec_at, str_at, addr_from_encoded

EXPECTED_SHA = "0e0c05244a3d35753e948783372f18e615ae2032cf7b750dd7a9cc57cfb3626e"
TARGETS = [
    "rebuildCache:",
    "setCacheSentinel:",
    "listener:shouldAcceptNewConnection:",
    "setCacheValue",
    "setCacheValue:",
    "setAnswer:",
]
MAX_INSTRUCTIONS = 120


def scan(data: bytes):
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA:
        raise ValueError(f"wrong Apple binary: {digest}")
    sec = sections(data)
    code = next((x for x in sec if x["name"] == "__TEXT,__text"), None)
    if not code:
        raise ValueError("missing original __TEXT,__text")
    selectors = {}
    for block in sec:
        if not any(tag in block["name"] for tag in ("objc_methname", "__cstring")):
            continue
        raw = data[block["offset"]:block["offset"]+block["size"]]
        for name in TARGETS:
            needle = name.encode() + b"\0"
            start = 0
            while True:
                at = raw.find(needle, start)
                if at < 0:
                    break
                selectors.setdefault(name, []).append(block["vm"] + at)
                start = at+1

    refs = {}
    for block in sec:
        if "objc_selrefs" not in block["name"]:
            continue
        raw = data[block["offset"]:block["offset"]+block["size"]]
        for index in range(0, len(raw)-3, 4):
            value = struct.unpack_from("<I", raw, index)[0]
            for name, values in selectors.items():
                if any(x in addr_from_encoded(value) for x in values):
                    refs.setdefault(name, set()).add(block["vm"] + index)

    hits = []
    for block in sec:
        if any(tag in block["name"] for tag in ("__text", "__cstring", "objc_methname", "objc_selrefs", "__LINKEDIT")):
            continue
        raw = data[block["offset"]:block["offset"]+block["size"]]
        for off in range(0, len(raw)-11, 4):
            vm = block["vm"]+off
            nrel, trel, irel = struct.unpack_from("<iii", raw, off)
            name_addr = vm+nrel
            ty_addr = vm+4+trel
            impl_addr = vm+8+irel
            if not (impl_addr % 4 == 0 and sec_at(sec,impl_addr,4) == code):
                continue
            typ = str_at(data,sec,ty_addr,80)
            if not typ or not any(c in typ for c in "@#:"):
                continue
            for name, locations in selectors.items():
                if name_addr in locations or name_addr in refs.get(name,set()):
                    hits.append({"name":name,"method_va":hex(impl_addr),"type_encoding":typ,
                                 "metadata_va":hex(vm),"section":block["name"],"encoding":"relative"})

    for block in sec:
        if not any(tag in block["name"] for tag in ("objc_const","objc_data")):
            continue
        raw=data[block["offset"]:block["offset"]+block["size"]]
        for off in range(0,len(raw)-11,4):
            m,t,im=struct.unpack_from("<III",raw,off)
            for name, locations in selectors.items():
                if not any(x in addr_from_encoded(m) for x in set(locations)|set(refs.get(name,set()))):
                    continue
                impl=next((x for x in addr_from_encoded(im) if x%4==0 and sec_at(sec,x,4)==code),None)
                ty=next((text for x in addr_from_encoded(t) if (text:=str_at(data,sec,x,80))),None)
                if impl is not None and ty and any(c in ty for c in "@#:"):
                    hits.append({"name":name,"method_va":hex(impl),"type_encoding":ty,
                                 "metadata_va":hex(block["vm"]+off),"section":block["name"],"encoding":"absolute"})

    seen=set()
    verified=[]
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    for h in hits:
        key=(h["name"],h["method_va"])
        if key in seen:
            continue
        seen.add(key)
        va=int(h["method_va"],16)
        offset=code["offset"]+(va-code["vm"])
        raw=data[offset:offset+min(0x360,code["vm"]+code["size"]-va)]
        instructions=[]
        for ins in cs.disasm(raw,va):
            if len(instructions)>=MAX_INSTRUCTIONS:
                break
            instructions.append(f"{ins.address:#010x} {ins.mnemonic:8} {ins.op_str}")
            if ins.mnemonic=="ret" and len(instructions)>=12:
                break
        h["instructions"]=instructions
        verified.append(h)
    return {"sha256":digest,"selectors_found":{k:[hex(x) for x in v] for k,v in selectors.items()},
            "relative_or_absolute_verified_methods":verified,
            "limitation":"Only the target selector list is scanned; no absence claim for dynamic IPC; no call graph completeness claim"}


def main():
    data=Path(sys.argv[1]).read_bytes()
    report=scan(data)
    out=Path(sys.argv[2])
    out.mkdir(parents=True,exist_ok=True)
    (out/"mgh-abi-report.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["SHA "+report["sha256"],"TARGET METHOD STRING COUNT: "+str(len(report["selectors_found"])) ,
           "VERIFIED IMP COUNT: "+str(len(report["relative_or_absolute_verified_methods"]))]
    for name, loc in report["selectors_found"].items():
        lines.append(f"STRING {name} {loc}")
    for h in report["relative_or_absolute_verified_methods"]:
        lines.append(f"\n=== {h['name']} : {h['type_encoding']} @ {h['method_va']} ({h['encoding']}) ===")
        lines.extend(h["instructions"])
    lines.append("\nNO ARBITRARY SETTER IS ESTABLISHED BY STRINGS OR AN EXPORTED SELECTOR ALONE.")
    (out/"mgh-abi-report.txt").write_text("\n".join(lines)+"\n")
    print("\n".join(lines[:20]))


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: audit_mobilegestalt_helper.py /path/to/MobileGestaltHelper /path/to/audit")
    main()
