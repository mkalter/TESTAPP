#!/usr/bin/env python3
"""Resolve class owners for verified ObjC method lists of exact 23U95 tccd.

Raw 32-bit on-disk chained rebases are decoded only when pointer targets
map to expected, backed Mach-O sections. Not a runtime authorization probe.
"""
import argparse,hashlib,json,re,struct
from pathlib import Path
from recover_arm64_32_objc_lists import sections,source_offset

def u32(b,o):return struct.unpack_from("<I",b,o)[0]
def target(raw):return raw&0x03ffffff
def getraw(b,sec,vm):
    o,s=source_offset(sec,vm,4)
    if o is None:return None
    return u32(b,o)
def stringat(b,sec,vm,kind):
    o,s=source_offset(sec,vm,1)
    if o is None or s["name"]!=kind:return None
    q=b.find(b"\0",o,min(o+128,len(b)))
    if q<=o:return None
    try:t=b[o:q].decode("ascii")
    except UnicodeError:return None
    return t if re.fullmatch(r"[A-Za-z_$][\w.$]{1,80}",t) else None
def class_t(b,sec,vm,method_map,kind):
    o,s=source_offset(sec,vm,20)
    if o is None or s["name"]!="__objc_data":return None
    roval=u32(b,o+16)
    rovm=target(roval&~7)
    ro,ros=source_offset(sec,rovm,32)
    if ro is None or ros["name"]!="__objc_const":return None
    namevm=target(u32(b,ro+16))
    name=stringat(b,sec,namevm,"__objc_classname")
    methvm=target(u32(b,ro+20))
    if not name:return None
    methods=method_map.get(methvm,[])
    return dict(class_vm=hex(vm),kind=kind,class_name=name,
                class_ro_vm=hex(rovm),base_methods_vm=hex(methvm),
                verified_method_count=len(methods),
                verified_method_names=[m["name"] for m in methods],
                is_verified_list=methvm in method_map,
                raw_class_ro=hex(roval))
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--expected-sha256",required=True)
    p.add_argument("--method-map",required=True)
    p.add_argument("--output",required=True)
    a=p.parse_args()
    b=Path(a.input).read_bytes()
    sha=hashlib.sha256(b).hexdigest()
    if sha!=a.expected_sha256.lower():raise ValueError("source mismatch")
    mapping=json.loads(Path(a.method_map).read_text())
    if mapping["sha256"]!=sha:raise ValueError("method-map mismatch")
    mm={int(l["vm"],16):l["methods"] for l in mapping["all_lists"]}
    sec=sections(b)
    region=next(s for s in sec if s["name"]=="__objc_classlist")
    classes=[];first=[]
    for i in range(region["size"]//4):
        raw=u32(b,region["file"]+i*4);vm=target(raw)
        if len(first)<10:first.append(dict(raw=hex(raw),decoded_vm=hex(vm),
             section=(source_offset(sec,vm)[1] or {}).get("name")))
        c=class_t(b,sec,vm,mm,"class")
        if c:
            classes.append(c)
            ptr=getraw(b,sec,vm)
            if ptr is not None:
                metaclass=class_t(b,sec,target(ptr),mm,"metaclass")
                if metaclass:
                    metaclass["class_name"]=c["class_name"]
                    classes.append(metaclass)
    report=dict(source_sha256=sha,
                scanned_classlist_entries=region["size"]//4,
                resolved_class_metadata=len(classes),
                classlist_samples=first,classes=classes,
                warning="Static class metadata does not prove XPC caller authority.")
    Path(a.output).write_text(json.dumps(report,indent=2)+"\n")
    print("ORIGINAL",sha,"CLASSLIST",report["scanned_classlist_entries"],
          "RESOLVED",len(classes))
    for c in classes:
        if any(any(k in m.lower() for k in
            ("registry","migrat","database","entitle","sandbox","path","client","request"))
            for m in c["verified_method_names"]):
            print(c["kind"],c["class_name"],c["base_methods_vm"],
                  "method examples",c["verified_method_names"][:12])
    if not classes:print("POINTER DIAGNOSTIC",first)
