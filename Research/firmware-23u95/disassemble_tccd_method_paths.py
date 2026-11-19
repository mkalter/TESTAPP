#!/usr/bin/env python3
"""Disassemble bounded verified ObjC IMPs in the exact original 23U95 tccd.

Outputs narrowly selected method names and instruction *addresses*, not
original Apple binaries. No exploit, payload or on-device calls are made.
"""
import argparse, hashlib, json, re
from pathlib import Path
from recover_arm64_32_objc_lists import sections, source_offset

P=re.compile(r"(?:registerNewDB|MigratedDB|PathToDatabase|_createDatabase|"
             r"setUpMigration|validateEntry|Delegate|delegat|SandboxExtension|"
             r"sandboxOperation|cleanup|DatabaseRegistry|directory|"
             r"requestor|client|_sendMessage)",re.I)

def main():
    pa=argparse.ArgumentParser()
    pa.add_argument("--input",required=True)
    pa.add_argument("--expected-sha256",required=True)
    pa.add_argument("--method-map",required=True)
    pa.add_argument("--output",required=True)
    a=pa.parse_args()
    b=Path(a.input).read_bytes()
    sha=hashlib.sha256(b).hexdigest()
    if sha!=a.expected_sha256.lower():raise ValueError("original binary mismatch")
    mapping=json.loads(Path(a.method_map).read_text())
    if mapping["sha256"]!=sha:raise ValueError("original and method-map SHA mismatch")
    allm=[m for l in mapping["all_lists"] for m in l["methods"]]
    if not allm:raise SystemExit("No verified ObjC IMP mappings: do not invent disassembly")
    try:
        from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
    except ImportError as e:raise SystemExit("Capstone not installed") from e
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    sec=sections(b)
    addrs=sorted(set(int(m["imp"],16) for m in allm))
    targets=sorted([m for m in allm if P.search(m["name"])],
                   key=lambda m:(m["name"],int(m["imp"],16)))
    report=dict(original_sha256=sha,verified_method_entries=len(allm),
                selected_methods=[],warning="Limited disassembly: no caller reachability, entitlement bypass or protected write demonstrated")
    for m in targets[:80]:
        vm=int(m["imp"],16)
        p,s=source_offset(sec,vm,4)
        if p is None or s["name"]!="__text":continue
        nxt=next((x for x in addrs if x>vm),vm+480)
        count=min(120,max(1,(nxt-vm)//4),s["size"]-(vm-s["vm"])>>2)
        code=b[p:p+4*count]
        ins=[f"0x{i.address:x}: {i.mnemonic} {i.op_str}" for i in md.disasm(code,vm)]
        report["selected_methods"].append(dict(name=m["name"],imp=m["imp"],
                                                 instruction_count=len(ins),
                                                 bounded_assembly=ins))
    Path(a.output).write_text(json.dumps(report,indent=2)+"\n")
    print("SHA",sha,"VERIFIED IMP ENTRIES",len(allm),
          "SELECTED",len(report["selected_methods"]))
    for m in report["selected_methods"][:30]:
        print("METHOD",m["name"],m["imp"],"instructions",m["instruction_count"])
if __name__=="__main__":main()
