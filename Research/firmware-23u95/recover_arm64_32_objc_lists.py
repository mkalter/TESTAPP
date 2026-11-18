#!/usr/bin/env python3
"""Read-only ARM64_32 Objective-C relative method-list recovery.

Enumerates verified method-list headers and IMPs from original SHA-pinned
Watch6,18 tccd. It does NOT invoke daemon methods or infer RPC permissions.
"""
import argparse, hashlib, json, struct, re
from pathlib import Path

def u32(b,o):return struct.unpack_from("<I",b,o)[0]
def i32(b,o):return struct.unpack_from("<i",b,o)[0]
def sections(b):
    if u32(b,0)!=0xfeedface:raise ValueError("expected thin MH_MAGIC arm64_32")
    if u32(b,4)!=0x0200000c:raise ValueError("not ARM64_32")
    pos=28; out=[]
    for _ in range(u32(b,16)):
        if pos+8>len(b):raise ValueError("bad load command")
        cmd,size=struct.unpack_from("<II",b,pos)
        if size<8 or pos+size>len(b):raise ValueError("invalid load command")
        if cmd==1:
            n=u32(b,pos+48)
            for j in range(n):
                off=pos+56+j*68
                if off+68>pos+size:raise ValueError("invalid section")
                name=b[off:off+16].split(b"\0",1)[0].decode("ascii","replace")
                segment=b[off+16:off+32].split(b"\0",1)[0].decode("ascii","replace")
                vm,sz,physical=struct.unpack_from("<III",b,off+32)
                if physical+sz<=len(b):
                    out.append(dict(name=name,segment=segment,vm=vm,size=sz,file=physical))
        pos+=size
    return out
def source_offset(sec,vm,n=1):
    for s in sec:
        if s["vm"]<=vm and vm+n<=s["vm"]+s["size"]:
            return s["file"]+vm-s["vm"],s
    return None,None
def readname(b,sec,vm,depth=0):
    p,s=source_offset(sec,vm,1)
    if p is None:return None
    if s["name"]=="__objc_selrefs" and depth<1:
        if p+4>len(b):return None
        return readname(b,sec,u32(b,p),depth+1)
    if s["name"] not in ("__objc_methname","__cstring"):return None
    end=b.find(b"\0",p,min(len(b),p+350))
    if end<0:return None
    raw=b[p:end]
    if not (1<len(raw)<250):return None
    try:s=raw.decode("utf-8")
    except UnicodeError:return None
    return s if re.fullmatch(r"[A-Za-z_.$+:][A-Za-z_0-9.$+:]*",s) else None

def extract(b):
    sec=sections(b)
    region=next((s for s in sec if s["name"]=="__objc_methlist"),None)
    if region is None:raise ValueError("no method list section")
    text=[s for s in sec if s["name"]=="__text"]
    if not text:raise ValueError("no text section")
    results=[]; pos=0; diagnostics=[]
    while pos+8<=region["size"]:
        header=region["file"]+pos
        flag=u32(b,header); count=u32(b,header+4)
        stride=(flag & 0xfffc)
        relative=(flag & 0x80000000)!=0
        if (relative and stride==12 and 1<=count<=500 and
            pos+8+count*stride<=region["size"]):
            entries=[]
            for i in range(count):
                addr=region["vm"]+pos+8+i*stride
                ofs=region["file"]+pos+8+i*stride
                namevm=addr+i32(b,ofs)
                impvm=addr+8+i32(b,ofs+8)
                name=readname(b,sec,namevm)
                ip,imps=source_offset(sec,impvm,4)
                if not name or imps is None or imps["name"]!="__text":break
                entries.append(dict(name=name,imp=hex(impvm),entry=hex(addr)))
            if len(entries)==count:
                results.append(dict(vm=hex(region["vm"]+pos),header=hex(flag),count=count,
                                    methods=entries))
                pos+=8+count*stride
                continue
        if len(diagnostics)<16 and (count>0 or flag):
            diagnostics.append(dict(pos=hex(region["vm"]+pos),header=hex(flag),count=count))
        pos+=4
    return sec,results,diagnostics

def debug_first_entries(b,sec):
    region=next((s for s in sec if s["name"]=="__objc_methlist"),None)
    if region is None:return []
    diagnostics=[]
    for pos in range(0,region["size"]-20,4):
        header=region["file"]+pos
        flags=u32(b,header);count=u32(b,header+4)
        if flags!=0x8000000c or not (1<=count<=64):continue
        e=region["file"]+pos+8
        vm=region["vm"]+pos+8
        namevm=vm+i32(b,e)
        typevm=vm+4+i32(b,e+4)
        impvm=vm+8+i32(b,e+8)
        seloff,selsec=source_offset(sec,namevm,4)
        selvalue=u32(b,seloff) if seloff is not None else None
        rows=dict(list_vm=hex(region["vm"]+pos),count=count,
            name_entry_vm=hex(namevm),name_section=selsec["name"] if selsec else None,
            raw_selref_word=hex(selvalue) if selvalue is not None else None,
            direct_name_read=readname(b,sec,namevm),
            type_vm=hex(typevm),type_section=(source_offset(sec,typevm)[1] or {}).get("name"),
            imp_vm=hex(impvm),imp_section=(source_offset(sec,impvm)[1] or {}).get("name"))
        if selvalue is not None:
            candidates=[selvalue,selvalue&0x3fffffff,selvalue&0x03ffffff,
                        selvalue+0x10000000,selvalue+0x80000000]
            rows["pointer_candidates"]=[
                dict(vm=hex(c),section=(source_offset(sec,c)[1] or {}).get("name"),
                     name=readname(b,sec,c))
                for c in candidates]
        diagnostics.append(rows)
        if len(diagnostics)>=16:break
    return diagnostics

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--expected-sha256",required=True)
    p.add_argument("--output",required=True)
    a=p.parse_args()
    b=Path(a.input).read_bytes()
    digest=hashlib.sha256(b).hexdigest()
    if digest!=a.expected_sha256.lower():raise ValueError("original SHA mismatch")
    sec,lists,debug=extract(b)
    result=dict(sha256=digest,lists=len(lists),methods=sum(x["count"] for x in lists),
                classes_not_assumed=True,
                interesting=[dict(vm=l["vm"],methods=[m for m in l["methods"] if any(
                    k in m["name"].lower() for k in
                    ("database","path","migrat","entitle","sandbox","delegat","request","access",
                     "registry","cleanup","valid","sync","listener","client","connection"))])
                    for l in lists if any(any(k in m["name"].lower() for k in
                    ("database","path","migrat","entitle","sandbox","delegat","request","access",
                     "registry","cleanup","valid","sync","listener","client","connection"))
                    for m in l["methods"])],
                all_lists=lists,initial_misalignment_candidates=debug,
                selref_pointer_diagnostics=debug_first_entries(b,sec))
    Path(a.output).write_text(json.dumps(result,indent=2)+"\n")
    print("validated SHA",digest,"validated method lists",len(lists),
          "methods",result["methods"],"interesting lists",len(result["interesting"]))
    for li in result["interesting"][:40]:
        print("LIST",li["vm"],"METHODS","; ".join(
            f"{v['name']}@{v['imp']}" for v in li["methods"][:10]))
    if not lists:
        print("No relative method lists validated; inspect first headers:",debug)
        for x in result["selref_pointer_diagnostics"][:8]:print("SELREF",json.dumps(x))
