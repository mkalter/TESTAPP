#!/usr/bin/env python3
"""Find Objective-C method IMPs in exact Watch6,18/23U95 nanotimekitd.

A stripped Mach-O's objc metadata may not be decoded by llvm-objdump's
--objc-meta-data. This scanner uses relative method-list layouts and validates
the name, type and text destinations to avoid presenting random pointers as IMPs.
READ ONLY; never loads the library or touches any Watch.
"""
from __future__ import annotations
import hashlib
import json
import struct
import sys
from pathlib import Path

EXPECTED = "103d9ed37894bac21ff30074ab9eaea8ed0f2932245b90dc67323ad914c026a6"
KEYWORDS = ("removeUnavailableFacesFromStore", "migrateBundleFacesInStore",
            "migrateFacesInStore", "addDefaultFacesToStore",
            "fromSyncResetWithFaces", "faceWithJSONObjectRepresentation",
            "setFaceLibrary", "createFaceLibrary", "resetFaceLibrary",
            "faceLibrary", "pairedsync", "librarybroker",
            "resetWithFaces", "faceStyleForUUID", "removeFaceForUUID",
            "addFace", "faceForUUID", "setOrderedUUIDs", "synchronize",
            "shouldAcceptNewConnection", "listener", "xpc", "connection",
            "validate", "entitle", "authorize", "libraryBroker")

def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]

def i32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<i", buf, off)[0]

def sections(data: bytes):
    magic=u32(data,0)
    if magic not in (0xFEEDFACE,0xFEEDFACF):
        raise ValueError("expected little-endian thin Mach-O")
    if u32(data, 4) != 0x0200000c:
        raise ValueError("wrong architecture (ARM64_32 required)")
    ncmds = u32(data, 16)
    off = 32 if magic==0xFEEDFACF else 28
    result = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if size < 8 or off + size > len(data):
            raise ValueError("invalid LC")
        if magic==0xFEEDFACE and cmd==1:
            nsects = u32(data, off+48)
            if size < 56+68*nsects: raise ValueError("invalid LC_SEGMENT")
            for n in range(nsects):
                loc=off+56+n*68
                name=data[loc:loc+16].split(b"\0",1)[0].decode("ascii","replace")
                seg=data[loc+16:loc+32].split(b"\0",1)[0].decode("ascii","replace")
                addr,sz,fileoff=struct.unpack_from("<III",data,loc+32)
                if sz and fileoff + sz <= len(data):
                    result.append(dict(name=f"{seg},{name}",vm=addr,size=sz,offset=fileoff))
        if magic==0xFEEDFACF and cmd==0x19:
            nsects=u32(data,off+64)
            if size < 72+80*nsects: raise ValueError("invalid LC_SEGMENT_64")
            for n in range(nsects):
                loc=off+72+n*80
                name=data[loc:loc+16].split(b"\0",1)[0].decode("ascii","replace")
                seg=data[loc+16:loc+32].split(b"\0",1)[0].decode("ascii","replace")
                addr,sz=struct.unpack_from("<QQ",data,loc+32)
                fileoff=u32(data,loc+48)
                if sz and fileoff+sz <= len(data):
                    result.append(dict(name=f"{seg},{name}",vm=addr,size=sz,offset=fileoff))
        off += size
    return result

def sec_at(sec,addr,n=1):
    return next((s for s in sec if s["vm"]<=addr and addr+n<=s["vm"]+s["size"]),None)

def str_at(data,sec,addr,maxlen=120):
    s=sec_at(sec,addr)
    if s is None: return None
    off=s["offset"]+addr-s["vm"]
    r=data[off: min(off+maxlen,s["offset"]+s["size"])].split(b"\0",1)[0]
    if not r or any(c<32 or c>126 for c in r): return None
    return r.decode("ascii")

def addr_from_encoded(encoded):
    # 23U95 arm64_32 chained pointers may embed metadata in their top byte.
    # Report candidate only when independently section-validated.
    return [encoded,encoded & 0x00ffffff,encoded & 0x03ffffff,
            encoded & 0x0fffffff]

def main(path):
    data=Path(path).read_bytes()
    sha=hashlib.sha256(data).hexdigest()
    if sha!=EXPECTED:
        raise ValueError(f"SHA mismatch {sha}")
    sec=sections(data)
    print("SHA=",sha,"len=",len(data),"section_count=",len(sec))
    for s in sec:
        if any(t in s["name"] for t in ("objc_", "__text","cstring")):
            print("SECTION",s["name"],hex(s["vm"]),hex(s["size"]))
    textsec=next((s for s in sec if s["name"].endswith(",__text")),None)
    if textsec is None: raise ValueError("missing __text section")
    targets={}
    for s in sec:
        if not any(t in s["name"] for t in ("objc_methname", "cstring", "objc_classname")):
            continue
        raw=data[s["offset"]:s["offset"]+s["size"]]
        for string in raw.split(b"\0"):
            if not string or len(string)>180:continue
            try: name=string.decode("ascii")
            except UnicodeDecodeError: continue
            if any(k.lower() in name.lower() for k in KEYWORDS):
                start=raw.find(string+b"\0")
                if start>=0:
                    targets[name]=s["vm"]+start
    print("TARGET_SELECTOR_STRINGS",json.dumps({k:hex(v) for k,v in targets.items()},indent=2))
    if not targets: raise ValueError("no target selector strings in sections")

    # Collect selector-reference address for each target, validating chained
    # absolute pointers against actual selector VM section.
    selrefs={}
    for s in sec:
        if "objc_selrefs" not in s["name"]:
            continue
        buf=data[s["offset"]:s["offset"]+s["size"]]
        for i in range(0,len(buf)-3,4):
            raw=u32(buf,i)
            for name,addr in targets.items():
                if addr in addr_from_encoded(raw):
                    selrefs.setdefault(name,[]).append(s["vm"]+i)
    print("SELECTOR_REFS",json.dumps({k:[hex(v) for v in xs[:30]] for k,xs in selrefs.items()},indent=2))

    # Look for relative method triples: name-offset, types-offset, imp-offset.
    # The "name" field targets either the literal selector (direct method
    # selector) or a __objc_selrefs slot. Sign-aware offsets are supported.
    hits=[]
    for s in sec:
        # No need to brute-force huge __TEXT text, or string sections.
        if "__text" in s["name"] or "__cstring" in s["name"] or "objc_methname" in s["name"]:continue
        if "objc_selrefs" in s["name"] or "__LINKEDIT" in s["name"]:continue
        buf=data[s["offset"]:s["offset"]+s["size"]]
        for i in range(0,len(buf)-11,4):
            vm=s["vm"]+i
            dest_name=vm+i32(buf,i)
            for name,addr in targets.items():
                if dest_name!=addr and dest_name not in selrefs.get(name,[]):continue
                dest_type=vm+4+i32(buf,i+4)
                dest_imp=vm+8+i32(buf,i+8)
                imp_s=sec_at(sec,dest_imp,4)
                if imp_s is None or imp_s!=textsec or dest_imp%4!=0:continue
                types=str_at(data,sec,dest_type,90)
                if types is None or not any(c in types for c in "@#:"):continue
                hits.append(dict(method=name,entry=hex(vm),section=s["name"],
                                 address=hex(dest_imp),type=types,
                                 name_kind="direct" if dest_name==addr else "selref"))
    # Also look for old method triples using absolute encoded 32-bit pointers.
    for s in sec:
        if not any(t in s["name"] for t in ("objc_const","objc_data")):continue
        buf=data[s["offset"]:s["offset"]+s["size"]]
        for i in range(0,len(buf)-11,4):
            raw_name=u32(buf,i)
            raw_type=u32(buf,i+4)
            raw_imp=u32(buf,i+8)
            for name,addr in targets.items():
                if addr not in addr_from_encoded(raw_name):continue
                for imp in addr_from_encoded(raw_imp):
                    imp_s=sec_at(sec,imp,4)
                    if imp_s is None or imp_s!=textsec or imp%4:continue
                    for t in addr_from_encoded(raw_type):
                        types=str_at(data,sec,t,90)
                        if types and any(c in types for c in "@#:"):
                            hits.append(dict(method=name,entry=hex(s["vm"]+i),
                                section=s["name"],address=hex(imp),type=types,
                                name_kind="absolute"))
                            break
    hits=sorted({(h["method"],h["address"],h["entry"]):h for h in hits}.values(),
                key=lambda h:(h["method"],int(h["address"],16)))
    print("VALIDATED_METHOD_CANDIDATES",json.dumps(hits,indent=2))
    Path("analysis/validated-method-candidates.json").write_text(json.dumps(hits,indent=2))
    Path("analysis/section-map.json").write_text(json.dumps(sec,indent=2))
    if not hits:
        print("No IMPs recovered: method encoding/relocation may differ. "
              "This is NOT evidence methods are absent.")
    return 0

if __name__=="__main__":
    try: sys.exit(main(sys.argv[1]))
    except (ValueError,IndexError,struct.error,OSError) as e:
        print(f"ERROR: {e}",file=sys.stderr)
        sys.exit(1)
