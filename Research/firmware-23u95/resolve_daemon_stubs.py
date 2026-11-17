#!/usr/bin/env python3
"""Resolve Objective-C stubs called by real 23U95 nanotimekitd store methods.

SHA-guarded; offline; 32-bit selector-pointer decoding for ARM64_32.
No device or system writes.
"""
import hashlib
import struct
import sys
from pathlib import Path
from resolve_daemon_objc import EXPECTED, sections, sec_at, str_at, addr_from_encoded

CALL_STUBS = {
    0x70AA0:"store fast enumeration",
    0x6EDC0:"enumeration / count",
    0x6F640:"get face style for item",
    0x6EE60:"current device",
    0x71020:"remove unavailable record",
    0x71640:"retrieve store / metadata",
    0x6ED20:"get object count",
    0x70760:"object enumeration",
    0x71CE0:"migration update item",
    0x72720:"migration finish",
    0x6F440:"enumerate via block",
    0x6D080:"sync reset dispatch",
    0x6DB60:"sync-reset forwarding",
    0x6C860:"add default store operations",
    0x6D2E0:"validation callback: input face library",
    0x6F840:"validation callback: install internal validation block",
    0x721E0:"validation callback: fetch static value or defaults",
    0x70EE0:"validation callback: compare/apply validation outcome",
    0x6F620:"native store add: get face descriptor",
    0x6E2C0:"native store add: early create or style check",
    0x6EDE0:"native store add/reset: convert face representation",
    0x6F040:"native store add/reset: object creation",
    0x71360:"native store add: face lookup",
    0x71C80:"native store add: insert order",
    0x71E60:"native store add: assign face",
    0x710A0:"sync reset: create new store",
    0x724E0:"sync reset: compare state",
    0x70F60:"sync reset: set selected",
    0x6D380:"sync reset: write ordered UUIDs",
    0x6D8E0:"sync reset: set face array",
    0x6D900:"sync reset: set selection",
    0x6E800:"sync reset: reconcile state",
    0x6D7C0:"sync reset: process item",

}

def blob_at(buf, sections_, vm, n):
    s=sec_at(sections_,vm,n)
    if s is None:
        raise ValueError("VM not in backed section")
    off=s["offset"]+(vm-s["vm"])
    return buf[off:off+n]

def stub(buf, sec, addr):
    ins1,ins2=struct.unpack("<II",blob_at(buf,sec,addr,8))
    if ins1 & 0x9F00001F != 0x90000001:
        return f"unrecognized first instruction {ins1:#010x}"
    if ins2 & 0xFFC003FF != 0xB9400021:
        return f"unrecognized second instruction {ins2:#010x}"
    imm=(((ins1>>5)&0x7FFFF)<<2)|((ins1>>29)&3)
    if imm&(1<<20):imm-=1<<21
    offset=((ins2>>10)&0xFFF)*4
    ref=(addr&~0xFFF)+(imm<<12)+offset
    encoded=struct.unpack("<I",blob_at(buf,sec,ref,4))[0]
    values=addr_from_encoded(encoded)
    selectors=[(va,str_at(buf,sec,va)) for va in values]
    meth=next(((va,name) for va,name in selectors
       if name and sec_at(sec,va) and "objc_methname" in sec_at(sec,va)["name"]),None)
    if meth is None:
        return f"unresolved selector reference {ref:#x} encoded {encoded:#x}"
    return f"{meth[1]} (selref={ref:#x}, selector_vm={meth[0]:#x})"

def main(path):
    buf=Path(path).read_bytes()
    sha=hashlib.sha256(buf).hexdigest()
    if sha!=EXPECTED:raise ValueError("unexpected original daemon SHA")
    sec=sections(buf)
    for addr,description in CALL_STUBS.items():
        try: out=stub(buf,sec,addr)
        except Exception as e:out=f"error: {e}"
        print(f"{addr:#08x} [{description}] -> {out}")

if __name__=="__main__":
    main(sys.argv[1])
