#!/usr/bin/env python3
"""Bounded offline callsite trace for genuine Watch6,18/23U95 ClockKit.

This reconstructs *only verified* ObjC method IMPs from Apple's SHA-pinned
original ClockKit image. No XPC request, face import or on-device action.
"""
import argparse,hashlib,json,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from recover_arm64_32_objc_lists import sections,source_offset
from resolve_tccd_selector_stubs import selector_stub

IMPORTANT=("setupConnectionIfNeeded","validateFaceType:faceBundleId:",
           "addWatchFaceAtURL:","openWatchFaceURLWithSecurityScopedURL:",
           "_validateWatchFaceAtURL:","_importWatchFaceAtURL:",
           "CLKWatchFaceLibrary","openWatchFaceURLWithBookmarkData:")

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--input",required=True)
    a.add_argument("--sha256",required=True)
    a.add_argument("--method-map",required=True)
    a.add_argument("--out",required=True)
    x=a.parse_args()
    b=Path(x.input).read_bytes()
    sh=hashlib.sha256(b).hexdigest()
    if sh!=x.sha256.lower():raise ValueError("original ClockKit SHA mismatch")
    methods=json.loads(Path(x.method_map).read_text())
    if methods["sha256"]!=sh:raise ValueError("ObjC IMP map SHA mismatch")
    allm=[m for l in methods["all_lists"] for m in l["methods"]]
    ordered=sorted({int(m["imp"],16) for m in allm})
    sec=sections(b)
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    selected=[]
    for m in allm:
        name=m["name"]
        if not any(k.lower() in name.lower() for k in IMPORTANT):continue
        addr=int(m["imp"],16)
        ofs,s=source_offset(sec,addr,4)
        if ofs is None or s["name"]!="__text":continue
        nxt=next((v for v in ordered if v>addr),addr+600)
        cap=min(600,nxt-addr,s["size"]-(addr-s["vm"]))
        if cap<4:continue
        instructions=[]
        calls=[]
        for ins in decoder.disasm(b[ofs:ofs+(cap//4)*4],addr):
            instructions.append(dict(pc=hex(ins.address),op=ins.mnemonic,args=ins.op_str))
            if ins.mnemonic!="bl":continue
            match=re.search(r"0x([0-9a-f]+)",ins.op_str)
            if not match:continue
            vm=int(match.group(),16)
            entry=dict(pc=hex(ins.address),branch_target=hex(vm))
            try:
                value=selector_stub(b,sec,vm)
                if value:entry["decoded_objc_selector"]=value
            except (ValueError,IndexError):
                pass
            calls.append(entry)
        selected.append(dict(name=name,imp=hex(addr),instruction_count=len(instructions),
                             bounded_instructions=instructions,calls=calls))
    report=dict(source_sha256=sh,total_validated_method_entries=len(allm),
                selected_methods=selected,selected_count=len(selected),
                caveats=[
                    "Original watchOS client methods do not prove server implementation or accepted XPC requests.",
                    "Selector names and bounded branch disassembly do not prove authentication.",
                    "No Apple binary included in report; no physical Watch modified."])
    Path(x.out).write_text(json.dumps(report,indent=2)+"\n")
    print("ORIGINAL SHA",sh,"ALL METHODS",len(allm),
          "SELECTED",len(selected))
    for m in selected:
        print("METHOD",m["name"],m["imp"],
              "instructions",m["instruction_count"])
        for c in m["calls"][:15]:
            if c.get("decoded_objc_selector",{}).get("selector"):
                print("   SELECTOR",c["decoded_objc_selector"]["selector"])
    if not selected:
        print("NO SELECTED METHODS VERIFIED — do not infer this service is absent")
if __name__=="__main__":main()
