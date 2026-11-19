#!/usr/bin/env python3
"""SHA-verified ORIGINAL Watch6,18/23U95 Hermès2025 availability predicate audit.

Read-only static inspection of the original signed Apple FaceBundle:
- restriction wrapper at 0x3b2c
- restriction helper at 0x46b8
- nearby system identity/feature checks and named Mach-O call targets.
No app runs, patching, sandbox bypass, private API invocation or native-face
state changes. A callsite name alone does not prove the complete condition.
"""
import argparse,hashlib,json,re
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from recover_arm64_32_objc_lists import sections,source_offset
from trace_clockkit_macho_symbols import macho_symbols

EXPECTED="ca8f29bd478483d5bfcd6a30cae9f324a37e2655e0515a27929596df4dc9af49"
TARGETS={
    "Hermes2025Face.isRestrictedForDevice:":(0x3b2c,0x3b64),
    "Hermes2025Face.restriction_helper":(0x46b8,0x4870),
}
INTERESTING=(
    "DeviceBrand","Hermes","hermes","isRestrictedForDevice",
    "deviceBrand","isHermes","isHermès","collectionType",
    "CLKDevice","MGCopyAnswer","isAppleWatch","WatchModel",
    "isInternalBuild","capability","screenClass",
)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--original",required=True)
    p.add_argument("--output",required=True)
    args=p.parse_args()
    data=Path(args.original).read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    if digest!=EXPECTED:raise ValueError("Different original Apple Hermès2025 executable SHA")
    sec=sections(data)
    symerr=None
    try:
        _,symbols=macho_symbols(data)
    except Exception as exc:
        symerr=str(exc);symbols=[]
    by_address={}
    for s in symbols:by_address.setdefault(s["vm"],[]).append(s["name"])
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    targets={}
    for name,(start,end) in TARGETS.items():
        o,region=source_offset(sec,start,end-start)
        if o is None or region["name"]!="__text":
            targets[name]=dict(error="No exact backed __text region")
            continue
        rows=[];calls=[]
        for ins in decoder.disasm(data[o:o+(end-start)],start):
            row=dict(address=hex(ins.address),op=ins.mnemonic,args=ins.op_str)
            rows.append(row)
            if ins.mnemonic not in ("bl","b"):continue
            found=re.search(r"0x([0-9a-f]+)",ins.op_str)
            if not found:continue
            addr=int(found.group(),16)
            call=dict(at=hex(ins.address),target=hex(addr),
                      named_symbols=by_address.get(addr,[])[:14])
            calls.append(call)
        targets[name]=dict(start=hex(start),end=hex(end),
                           instructions=rows,calls=calls)
    ascii_matches=[]
    for m in re.finditer(rb"[\x20-\x7e]{6,170}",data):
        value=m.group().decode("ascii","replace")
        if any(k.lower() in value.lower() for k in INTERESTING):
            ascii_matches.append(value)
    results=dict(source_sha256=digest,source_length=len(data),
        decoded_macho_symbols=len(symbols),symbol_error=symerr,
        relevant_original_strings=sorted(set(ascii_matches))[:220],
        exact_known_function_ranges=targets,
        limitations=[
            "Call graph and Apple selectors do not prove a particular DeviceBrand key value is sufficient",
            "Runtime device properties were not modified or spoofed",
            "No method invoked; no protected filesystem write or library operation",
            "The true predicate requires interpreting original branch and call target semantics"])
    Path(args.output).write_text(json.dumps(results,indent=2)+"\n")
    print("ORIGINAL-HERMES-SHA",digest,"MACHO-SYMBOLS",len(symbols))
    for name,item in targets.items():
        print("FUNC",name,"instructions",len(item.get("instructions",[])))
        for c in item.get("calls",[]):
            print("  CALL",c["at"],c["target"],c["named_symbols"][:8])
    print("IDENTITY STRINGS",results["relevant_original_strings"][:35])
if __name__=="__main__":main()
