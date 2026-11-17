#!/usr/bin/env python3
"""Read-only bounded ARM64_32 native ObjC method disassembler.

Consumes exact hash-checked Apple nanotimekitd, the section map and
previously recovered relative ObjC method-list name/type/IMP triplets.
It neither patches Apple binaries nor modifies an Apple Watch.
"""
import sys, json, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

exe=Path(sys.argv[1]); output=Path(sys.argv[2])
data=exe.read_bytes()
sha=hashlib.sha256(data).hexdigest()
expected="103d9ed37894bac21ff30074ab9eaea8ed0f2932245b90dc67323ad914c026a6"
if sha != expected:raise SystemExit(f"unexpected source SHA256 {sha}")
secs=json.loads((output/"section-map.json").read_text())
text=next((s for s in secs if s['name']=="__TEXT,__text"),None)
if text is None:raise SystemExit("missing __TEXT,__text in validated section map")
methods=json.loads((output/"validated-method-candidates.json").read_text())
cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
cs.detail=False
start=int(text['vm']); end=start+int(text['size'])
print("source_sha256",sha,"text_range",hex(start),hex(end),"validated_imp_count",len(methods))
for method in methods:
    va=int(method['address'],16)
    if not start<=va<end:raise SystemExit(f"Method IMP {hex(va)} outside validated __text")
    count=min(0x650,end-va)
    off=int(text["offset"])+(va-start)
    raw=data[off:off+count]
    print(f"\n=== {method['method']} @ {hex(va)} ObjC encoding {method['type']} ===")
    insts=list(cs.disasm(raw,va))
    if not insts: raise SystemExit(f"No ARM64 code at {hex(va)}; refusing a guessed conclusion")
    n=0
    for inst in insts:
        if n>=270:break
        print(f"{inst.address:#010x} {inst.mnemonic:8} {inst.op_str}")
        n+=1
        if inst.mnemonic=="ret" and n>=12:break
    print("instructions_displayed",n)
