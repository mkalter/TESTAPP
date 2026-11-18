#!/usr/bin/env python3
"""Resolve Objective-C selector stubs actually called by verified 23U95 methods.

Non-executable offline evidence only: an ObjC selector call is not an
authorization grant and cannot establish an exploitable path by itself.
"""
import argparse,hashlib,json,re,struct
from pathlib import Path
from recover_arm64_32_objc_lists import sections,source_offset,readname

def u32(b,o):return struct.unpack_from("<I",b,o)[0]
def raw(b,sec,vm,n=8):
    o,s=source_offset(sec,vm,n)
    if o is None:raise ValueError(f"unbacked VM {vm:#x}")
    return b[o:o+n],s

def selector_stub(b,sec,addr):
    buf,s=raw(b,sec,addr)
    if s["name"]!="__objc_stubs":return None
    i1,i2=struct.unpack("<II",buf)
    if i1&0x9f00001f!=0x90000001:return dict(error="unrecognized ADRP X1")
    if i2&0xffc003ff!=0xb9400021:return dict(error="unrecognized LDR W1")
    imm=(((i1>>5)&0x7ffff)<<2)|((i1>>29)&3)
    if imm&(1<<20):imm-=1<<21
    off=((i2>>10)&0xfff)*4
    selref=(addr&~0xfff)+(imm<<12)+off
    sb,ss=raw(b,sec,selref,4)
    if ss["name"]!="__objc_selrefs":return dict(error="unexpected selector ref section",selref=hex(selref))
    encoded=struct.unpack("<I",sb)[0]
    result=readname(b,sec,selref)
    if not result:return dict(error="unresolved selector",selref=hex(selref),encoded=hex(encoded))
    return dict(selector=result,selref=hex(selref),selector_vm=hex(encoded&0x03ffffff))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--expected-sha256",required=True)
    p.add_argument("--disassembly",required=True)
    p.add_argument("--output",required=True)
    a=p.parse_args()
    b=Path(a.input).read_bytes()
    digest=hashlib.sha256(b).hexdigest()
    if digest!=a.expected_sha256.lower():raise ValueError("source SHA mismatch")
    report=json.loads(Path(a.disassembly).read_text())
    if report["original_sha256"]!=digest:raise ValueError("disassembly SHA mismatch")
    sec=sections(b); cache={};methods=[]
    for m in report["selected_methods"]:
        calls=[]
        for line in m["bounded_assembly"]:
            match=re.match(r"0x([0-9a-f]+): bl #0x([0-9a-f]+)",line)
            if not match:continue
            pc,target=(int(v,16) for v in match.groups())
            if target not in cache:
                try:cache[target]=selector_stub(b,sec,target)
                except ValueError as e:cache[target]=dict(error=str(e))
            info=cache[target]
            if info is None:continue
            calls.append(dict(pc=hex(pc),target=hex(target),**info))
        if calls:methods.append(dict(name=m["name"],imp=m["imp"],objc_calls=calls))
    out=dict(source_sha256=digest,methods=methods,matched_methods=len(methods),
             warning="Selector resolution alone does NOT prove a client-reachable mutating TCC RPC.")
    Path(a.output).write_text(json.dumps(out,indent=2)+"\n")
    print("VERIFIED OBJC CALL SITES",sum(len(m["objc_calls"]) for m in methods),
          "METHODS",len(methods))
    for m in methods:
        if any(t in m["name"].lower() for t in
               ("registern","migrat","createdatabase","sandbox","databasepath","directory")):
            print("METHOD",m["name"],m["imp"])
            for c in m["objc_calls"][:20]:
                print(" ",c["pc"],c.get("selector",c.get("error")))
