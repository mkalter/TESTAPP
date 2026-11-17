#!/usr/bin/env python3
"""Read-only ARM64_32 Mach-O Objective-C metadata walker.

This deliberately checks both ILP32 class_ro layouts and the two common
method-list formats, and emits the method IMP addresses when verified.
No Apple binaries or mutating code are packaged in the report.
"""
import struct, sys, re, hashlib
from pathlib import Path
from collections import Counter

p = Path(sys.argv[1]); buf = p.read_bytes()
u32=lambda o: struct.unpack_from("<I",buf,o)[0]
u64=lambda o: struct.unpack_from("<Q",buf,o)[0]
assert u32(0)==0xfeedfacf, "not MH_MAGIC_64 arm64_32 source"
ncmds=u32(16); off=32
secs=[]; segments=[]
for i in range(ncmds):
    cmd=u32(off); size=u32(off+4)
    if cmd==0x19:
        segname=buf[off+8:off+24].split(b"\0",1)[0].decode(errors="replace")
        vm=u64(off+24); vm_size=u64(off+32); foff=u64(off+40); fsize=u64(off+48)
        segments.append((segname,vm,vm_size,foff,fsize))
        nsecs=u32(off+64)
        for k in range(nsecs):
            so=off+72+k*80
            name=buf[so:so+16].split(b"\0",1)[0].decode(errors="replace")
            segment=buf[so+16:so+32].split(b"\0",1)[0].decode(errors="replace")
            addr=u64(so+32); length=u64(so+40); physical=u32(so+48)
            secs.append((segment,name,addr,length,physical))
    off+=size
def at(vm,length=1):
    vm=vm & 0xffffffff
    for seg,name,addr,extent,physical in secs:
        if addr<=vm and vm+length<=addr+extent and physical+vm-addr+length<=len(buf):
            return int(physical+vm-addr)
    for name,addr,size,physical,psize in segments:
        if addr<=vm and vm+length<=addr+min(size,psize) and physical+vm-addr+length<=len(buf):
            return int(physical+vm-addr)
    return None
def text(vm):
    o=at(vm)
    if o is None:return ""
    b=buf[o:o+250].split(b"\0",1)[0]
    if not b or len(b)>=200:return ""
    try:
        s=b.decode("utf-8")
    except UnicodeDecodeError:return ""
    return s if s.isprintable() else ""
def P(vm):
    o=at(vm,4)
    return u32(o) if o is not None else 0
def namedlist(vm):
    o=at(vm,8)
    if o is None:return []
    e=u32(o); count=u32(o+4)
    item_size=(e&0xfffffff8) if e&0x80000000 else (e&0xffff)
    # Relative entries use 3 signed int32 offsets; absolute entries 3 ptrs
    relative=bool(e&0x80000000)
    if item_size<12 or item_size>64 or count>5000:return []
    result=[]
    for i in range(count):
        loc=o+8+i*item_size
        if loc+12>len(buf):break
        if relative:
            ro,_,io=struct.unpack_from("<iii",buf,loc)
            # relative offsets are relative to fields within each method entry
            mname_va=vm+8+i*item_size+ro
            imp_va=vm+8+i*item_size+8+io
            method_name=text(mname_va)
        else:
            method_name=text(u32(loc)); imp_va=u32(loc+8)
        if method_name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:.]+",method_name):
            result.append((method_name,imp_va))
    return result
headers=[]
for seg,name,addr,length,physical in secs:
    if any(t in name for t in ('objc','__text')):
        headers.append((seg,name,hex(addr),length))
print("SOURCE",p)
print("SHA256",hashlib.sha256(buf).hexdigest())
print("SECTIONS",*headers,sep="\n ")
classes=[]; candidates=Counter()
for seg,name,addr,length,physical in secs:
    if name not in ('__objc_classlist','__objc_nlclslist'):continue
    for pos in range(physical,physical+int(length),4):
        if pos+4>len(buf):break
        cls_ptr=u32(pos)
        co=at(cls_ptr,20)
        if co is None:continue
        ro_ptr=u32(co+16)&~7
        oo=at(ro_ptr,36)
        if oo is None:continue
        for name_offset,methods_offset in [(16,20),(20,24)]:
            classname=text(u32(oo+name_offset))
            if classname and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.$]+",classname):
                methods=namedlist(u32(oo+methods_offset))
                classes.append((classname,methods))
                candidates[(name_offset,methods_offset)]+=1
                break
print("OBJCCLASSES",len(classes),"layouts",dict(candidates))
sought=('Unavailable','Library','Face','Sync','Migrat','Store','Entitle','Validat','Carousel','Hermes','Restriction')
for classname,methods in classes:
    if any(t.lower() in classname.lower() for t in sought):
        print("CLASS",classname,"methods",len(methods))
    for method,addr in methods:
        if any(t.lower() in method.lower() for t in sought):
            print("METHOD",classname,method,hex(addr))
