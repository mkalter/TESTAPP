#!/usr/bin/env python3
"""Read-only signed 23U95 MobileGestaltHelper XPC implementation map.

Maps the *original* code behind listener:shouldAcceptNewConnection:,
rebuildCache: and setCacheSentinel:. Never invokes an XPC method and never
touches the on-device cache.
"""
import argparse, hashlib, json, re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from recover_arm64_32_objc_lists import sections,source_offset
from resolve_tccd_selector_stubs import selector_stub

TARGETS=("listener:shouldAcceptNewConnection:","rebuildCache:","setCacheSentinel:")
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--sha256",required=True)
    p.add_argument("--method-map",required=True)
    p.add_argument("--output",required=True)
    a=p.parse_args()
    b=Path(a.input).read_bytes()
    digest=hashlib.sha256(b).hexdigest()
    if digest!=a.sha256.lower():raise ValueError("original helper hash mismatch")
    m=json.loads(Path(a.method_map).read_text())
    if m["sha256"]!=digest:raise ValueError("method map original hash mismatch")
    allm=[row for li in m["all_lists"] for row in li["methods"]]
    addrs=sorted(set(int(x["imp"],16) for x in allm))
    sec=sections(b)
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    methods=[]
    for row in allm:
        if row["name"] not in TARGETS:continue
        vm=int(row["imp"],16)
        off,s=source_offset(sec,vm,4)
        if off is None or s["name"]!="__text":continue
        nxt=next((x for x in addrs if x>vm),vm+480)
        max_bytes=min(480, max(4,nxt-vm), s["size"]-(vm-s["vm"]))
        if max_bytes<4:continue
        code=b[off:off+(max_bytes//4)*4]
        ins=[dict(vm=hex(v.address),op=v.mnemonic,args=v.op_str)
             for v in md.disasm(code,vm)]
        calls=[]
        for i in ins:
            if i["op"]!="bl":continue
            match=re.search(r"0x([0-9a-f]+)",i["args"])
            if not match:continue
            target=int(match.group(),16)
            out=dict(from_pc=i["vm"],target=hex(target))
            try:
                stub=selector_stub(b,sec,target)
                if stub:out["objc_stub"]=stub
            except (ValueError,IndexError):
                out["objc_stub"]=dict(error="unresolved or non-objc target")
            calls.append(out)
        methods.append(dict(method=row["name"],imp=hex(vm),
                            instruction_count=len(ins),instructions=ins,
                            immediate_calls=calls))
    results=dict(original_sha256=digest,target_implementations=methods,
                 target_names=list(TARGETS),verified_total=len(methods),
                 caveats=[
                   "Objective-C method metadata and bounded disassembly only",
                   "No trusted writer or arbitrary binary plist setter established",
                   "rebuildCache: can delete and regenerate the protected cache",
                   "Do not call reboot/rebuild/set sentinel on the user's watch"])
    Path(a.output).write_text(json.dumps(results,indent=2)+"\n")
    print("EXACT HELPER SHA",digest)
    print("VERIFIED XPC-RELATED IMPS",len(methods))
    for m in methods:
        print(m["method"],m["imp"],"instructions",m["instruction_count"])
        for call in m["immediate_calls"][:24]:
            print("  call",call["target"],call.get("objc_stub",{}).get("selector","non-objc or unresolved"))
    if not methods:raise SystemExit("No reliable XPC-related method IMPs")
if __name__=="__main__":main()
