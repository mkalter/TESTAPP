#!/usr/bin/env python3
"""Independent LC_SYMTAB path to genuine Watch6,18/23U95 ClockKit client IMPs.

Does not trust/require objc method-name pointer rebasing in optimized dyld
method lists. Bounds every symbol to original Mach-O __text and checks a
fixed source SHA. Never invokes an Apple framework, XPC or face operation.
"""
import argparse,hashlib,json,re,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from recover_arm64_32_objc_lists import sections,source_offset
from resolve_tccd_selector_stubs import selector_stub

INTEREST=(
    "CLKWatchFaceLibraryServer _queue_setupConnectionIfNeeded",
    "CLKWatchFaceLibraryServer validateFaceType:",
    "CLKWatchFaceLibraryServer openWatchFaceURLWithSecurityScopedURL:",
    "CLKWatchFaceLibrary _validateWatchFaceAtURL:",
    "CLKWatchFaceLibrary _importWatchFaceAtURL:",
    "CLKWatchFaceLibrary addWatchFaceAtURL:",
)
AVAILABILITY_INTEREST=(
    "NTKGreenfieldUtilities validateFaceType:faceBundleId:",
    "NTKFaceDescriptor isAvailableForDevice:",
    "NTKFaceBundleManager faceBundleForBundleIdentifier:onDevice:",
    "NTKFaceBundleManager faceBundleForBundleIdentifier:",
    "NTKFaceStyleIsAvailable",
)
MIGRATION_INTEREST=(
    "NTKFace faceWithJSONObjectRepresentation:forDevice:forMigration:",
    "NTKFace faceWithJSONObjectRepresentation:forDevice:",
    "NTKFace _applyConfiguration:allowFailure:forMigration:",
    "NTKFace _initWithFaceStyle:forDevice:",
    "NTKFaceBundleManager faceBundleForBundleIdentifier:onDevice:forMigration:",
    "NTKFaceBundleManager faceBundleForBundleIdentifier:onDevice:",
    "NTKMigratableFaceStyles",
)
def u32(b,p):return struct.unpack_from("<I",b,p)[0]
def macho_symbols(b):
    pos=28
    ncmds=u32(b,16)
    symtab=None
    for _ in range(ncmds):
        cmd,size=struct.unpack_from("<II",b,pos)
        if cmd==2:
            if size<24:raise ValueError("bad LC_SYMTAB size")
            symtab=struct.unpack_from("<IIII",b,pos+8)
            break
        if size<8:raise ValueError("bad load command")
        pos+=size
    if symtab is None:raise ValueError("No LC_SYMTAB in original dyld export")
    symoff,nsyms,stroff,strsize=symtab
    if nsyms>1000000 or symoff+nsyms*12>len(b) or stroff+strsize>len(b):
        raise ValueError("Invalid LC_SYMTAB boundaries")
    symbols=[]
    for j in range(nsyms):
        o=symoff+j*12
        strx,stype,sect,desc,value=struct.unpack_from("<IBBHI",b,o)
        if strx==0 or strx>=strsize or value==0:continue
        q=b.find(b"\0",stroff+strx, min(stroff+strsize,stroff+strx+320))
        if q<0:continue
        try:name=b[stroff+strx:q].decode("utf-8")
        except UnicodeError:continue
        symbols.append(dict(name=name,vm=value,section_index=sect,symbol_type=stype))
    return symtab,symbols

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--sha256",required=True)
    p.add_argument("--out",required=True)
    p.add_argument("--profile",choices=("clockkit","availability","migration"),default="clockkit")
    a=p.parse_args()
    b=Path(a.input).read_bytes()
    digest=hashlib.sha256(b).hexdigest()
    if digest!=a.sha256.lower():raise ValueError("Different original Apple framework SHA")
    tab,symbols=macho_symbols(b)
    sect=sections(b)
    patterns=(INTEREST if a.profile=="clockkit" else
              AVAILABILITY_INTEREST if a.profile=="availability" else MIGRATION_INTEREST)
    target=[m for m in symbols if any(t in m["name"] for t in patterns)]
    symbol_names_by_vm={}
    for symbol in symbols:
        symbol_names_by_vm.setdefault(symbol["vm"],[]).append(symbol["name"])
    values=sorted({m["vm"] for m in symbols if (source_offset(sect,m["vm"],4)[1] or {}).get("name")=="__text"})
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    result=[]
    for m in target:
        addr=m["vm"]
        o,part=source_offset(sect,addr,4)
        if o is None or part["name"]!="__text":continue
        nxt=next((x for x in values if x>addr),addr+512)
        # A larger bounded window for the exact JSON migration constructor;
        # the usual short function scope remains unchanged.
        limit=2048 if a.profile=="migration" else 512
        maxbytes=min(limit,max(4,nxt-addr),part["size"]-(addr-part["vm"]))
        if maxbytes<4:continue
        ins=[]
        calls=[]
        for q in md.disasm(b[o:o+(maxbytes//4)*4],addr):
            ins.append(dict(pc=hex(q.address),op=q.mnemonic,args=q.op_str))
            if q.mnemonic!="bl":continue
            c=re.search(r"0x([0-9a-f]+)",q.op_str)
            if not c:continue
            targetaddr=int(c.group(),16)
            row=dict(pc=hex(q.address),target=hex(targetaddr))
            names=symbol_names_by_vm.get(targetaddr,[])
            if names:row["exact_original_target_symbols"]=sorted(set(names))[:12]
            try:
                named=selector_stub(b,sect,targetaddr)
                if named:row["objc_selector"]=named
            except (ValueError,IndexError):pass
            calls.append(row)
        result.append(dict(name=m["name"],imp=hex(addr),instruction_count=len(ins),
                           bounded_instructions=ins,calls=calls))
    out=dict(sha256=digest,profile=a.profile,symtab=dict(symoff=tab[0],nsyms=tab[1],
          stroff=tab[2],strsize=tab[3]),total_parsed_symbols=len(symbols),
          matching_target_symbol_names=len(target),
          disassembled_target_functions=len(result),functions=result,
          caveat="Symbol-code correlation only; no native Hermes unlock or accepted RPC verified")
    Path(a.out).write_text(json.dumps(out,indent=2)+"\n")
    print("ORIGINAL WATCH",a.profile,"SHA",digest,"SYMBOLS",len(symbols),
          "METHOD SYMBOLS",len(target),"VERIFIED CODE FUNCTIONS",len(result))
    for m in result:
        print("FUNCTION",m["name"],m["imp"],"instructions",m["instruction_count"])
        for c in m["calls"]:
            if "exact_original_target_symbols" in c:
                print("    EXACT CALL TARGET",c["pc"],c["target"],c["exact_original_target_symbols"])
            if "objc_selector" in c: print("    call",c["pc"],c["objc_selector"].get("selector"))
    if not result:print("NO VERIFIED METHOD SYMBOLS — check LC_SYMTAB and original dyld cache selector layout")
if __name__=="__main__":main()
