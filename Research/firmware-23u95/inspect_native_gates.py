#!/usr/bin/env python3
"""Read-only original watchOS 23U95 ARM64_32 NanoTimeKit gate disassembly."""
import hashlib, struct, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

FILES = {
 "NanoTimeKit": (
    "bf3f7e360fe06ab7e513807bcb3b6ac695f38c6ea8cd8428b7aed579c2b58e1c",
    {
      "NTKInternalBuild": (0x54601310, 8),
      "NTKShowInternalFaces": (0x546013C4, 80),
      "NTKShowHardwareSpecificFaces": (0x546014DC, 100),
      "FaceBundleManager.enumerate": (0x544B0C4C, 80),
      "FaceBundleManager.lookup": (0x544B0DDC, 145),
      "_NTKCanAddWatchFace": (0x54602E48, 145),
    }
 ),
 "NTKZeusFaceBundle": (
    "2b34d3d411b77ee73f3892638f419eda83b7bedc4653ecf44adf7c975bbd72e4",
    {
      "NTKPoodleFace.isRestrictedForDevice": (0x13B4, 30),
      "NTKHadesFace.isRestrictedForDevice": (0x12FC, 45),
      "NTKBellonaFace.isRestrictedForDevice": (0x21E80, 40),
    }
 ),
 "NTKHermes2025FaceBundle": (
    "ca8f29bd478483d5bfcd6a30cae9f324a37e2655e0515a27929596df4dc9af49",
    {
      "Hermes2025Face.isRestrictedForDevice": (0x3B2C, 18),
      "Hermes2025Face.restriction_helper": (0x46B8, 110),
    }
 ),
}
def sections(data):
    magic, cpu, _, _, ncmds, sizecmds, _ = struct.unpack_from("<IiiIIII",data,0)
    if magic!=0xfeedface or cpu!=0x0200000c:
        raise ValueError("Not 32-bit-header ARM64_32 Mach-O")
    if ncmds>1000 or sizecmds>1000000 or sizecmds+28>len(data):
        raise ValueError("Load command bounds invalid")
    off=28
    for _ in range(ncmds):
        cmd,size=struct.unpack_from("<II",data,off)
        if size<8 or off+size>28+sizecmds:
            raise ValueError("Corrupt load command")
        if cmd==1:
            fields=struct.unpack_from("<II16sIIIIiiII",data,off)
            nsects=fields[-2]
            if 56+68*nsects>size: raise ValueError("Corrupt section count")
            for k in range(nsects):
                n,s,a,length,o,*rest=struct.unpack_from("<16s16sIIIIIIIII",data,off+56+68*k)
                if o+length<=len(data):
                    yield n.rstrip(bytes([0])).decode("ascii","replace"),a,length,o
        off+=size

def main(path):
    data=Path(path).read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    filename=Path(path).name
    if filename not in FILES:
        print("STOP: unsupported firmware component",filename); return 2
    expected,gates=FILES[filename]
    print("file",filename,"bytes",len(data),"sha256",digest,"expected",expected)
    if digest!=expected:
        print("STOP: digest mismatch, no disassembly on wrong firmware"); return 2
    sects=list(sections(data))
    disasm=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    for label,(address,count) in gates.items():
        print(chr(10)+"=== ",label,hex(address)," ===")
        found=False
        for name,addr,length,fileoff in sects:
            if addr<=address<addr+length:
                found=True
                offset=fileoff+(address-addr)
                raw=data[offset: min(fileoff+length,offset+count*4)]
                print("section",name,"fileoffset",hex(offset))
                for i in disasm.disasm(raw,address,count=count):
                    print(f"0x{i.address:08x}: {i.mnemonic:<9} {i.op_str}")
                break
        if not found:print("Target address not mapped to an on-disk section")
    return 0
if __name__=="__main__":
    try: sys.exit(main(sys.argv[1]))
    except (IndexError,ValueError,struct.error,OSError) as exc:
        print(type(exc).__name__,exc,file=sys.stderr); sys.exit(3)
