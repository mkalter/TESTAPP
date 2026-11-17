#!/usr/bin/env python3
"""Offline class attribution of exact watchOS 23U95 nanotimekitd listener IMPs.

Uses original ARM64_32 relative objc method list headers and searches each
method list's owning class_ro metadata. Requires an exact SHA-pinned Mach-O.
No device calls, jailbreak, filesystem writes outside test output.
"""
import sys, json, struct, hashlib
from pathlib import Path
from resolve_daemon_objc import EXPECTED, sections, sec_at, str_at, addr_from_encoded

def u32(buf,off):return struct.unpack_from("<I",buf,off)[0]
def i32(buf,off):return struct.unpack_from("<i",buf,off)[0]

def read_at(buf,sec,vm,n=4):
    s=sec_at(sec,vm,n)
    if s is None:raise ValueError("address not in backed section")
    off=s["offset"]+vm-s["vm"]
    return buf[off:off+n]

def validate_name(buf,sec,vm):
    s=sec_at(sec,vm)
    if s is None:return None
    if "objc_classname" not in s["name"]:return None
    return str_at(buf,sec,vm)

def list_for_entry(buf,sec,entry):
    s=sec_at(sec,entry,12)
    if not s or "objc_methlist" not in s["name"]:return []
    starts=[]
    begin=s["vm"]
    for base in range(begin,entry-7,4):
        hdr,cnt=struct.unpack("<II",read_at(buf,sec,base,8))
        size=hdr&0xfffc
        if size!=12 or cnt<1 or cnt>4000:continue
        if not(base+8<=entry<base+8+cnt*size and (entry-base-8)%size==0):continue
        # Name field should point into a selector ref or methname section.
        try:
            raw=read_at(buf,sec,entry,12)
            namevm=entry+i32(raw,0)
            typvm=entry+4+i32(raw,4)
            impvm=entry+8+i32(raw,8)
        except Exception:continue
        name_s=sec_at(sec,namevm)
        imp_s=sec_at(sec,impvm)
        type_s=sec_at(sec,typvm)
        if not (name_s and ("objc_selrefs" in name_s["name"] or "objc_methname" in name_s["name"])):continue
        if not(imp_s and "__text" in imp_s["name"]):continue
        if not(type_s and "objc_methtype" in type_s["name"]):continue
        starts.append((base,cnt))
    # Prefer the shortest plausible list with a checked relative-method entry.
    return sorted(set(starts),key=lambda x:x[1])

def owner_at(buf,sec,listvm):
    owners=[]
    for s in sec:
        if "objc_const" not in s["name"]:continue
        raw=buf[s["offset"]:s["offset"]+s["size"]]
        for i in range(0,len(raw)-3,4):
            value=u32(raw,i)
            if listvm not in addr_from_encoded(value):continue
            fieldvm=s["vm"]+i
            # Candidate class_ro32 includes class name pointer immediately
            # before baseMethods; show a few nearby offsets to audit.
            raw_near=[]
            for diff in (-20,-16,-12,-8,-4,4,8):
                try:
                    value2=u32(read_at(buf,sec,fieldvm+diff,4),0)
                    opts=[(v,validate_name(buf,sec,v)) for v in addr_from_encoded(value2)]
                    valid=[(hex(v),name) for v,name in opts if name]
                    raw_near.append(dict(offset=diff,ptr=hex(value2),names=valid))
                except Exception:pass
            candidates=[x for x in raw_near if x["names"]]
            owners.append(dict(owner_field=hex(fieldvm),
                               raw=hex(value),
                               class_name_candidates=candidates,
                               neighbor_words=raw_near))
    return owners

def main():
    path=Path(sys.argv[1]);out=Path(sys.argv[2])
    data=path.read_bytes();sha=hashlib.sha256(data).hexdigest()
    if sha!=EXPECTED:raise SystemExit("Wrong exact Apple original")
    sec=sections(data)
    methods=json.loads((out/"validated-method-candidates.json").read_text())
    selected=[m for m in methods if m["method"]=="listener:shouldAcceptNewConnection:" or
        m["method"] in ("_resetWithFaces:orderedUUIDs:selectedUUID:","_queue_validateLibraryFaces",
                       "_queue_addFace:forUUID:")]
    entries=[]
    for m in selected:
        lists=list_for_entry(data,sec,int(m["entry"],16))
        entries.append(dict(method=m["method"],imp=m["address"],entry=m["entry"],
            method_lists=[dict(vm=hex(vm),count=count,owners=owner_at(data,sec,vm)) for vm,count in lists[:5]]))
    print(json.dumps(entries,indent=2))
    (out/"verified-class-owner-candidates.json").write_text(json.dumps(entries,indent=2))
    if not entries:raise SystemExit("no selected methods")
if __name__=="__main__":main()
