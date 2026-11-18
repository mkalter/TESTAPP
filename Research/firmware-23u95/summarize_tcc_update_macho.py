#!/usr/bin/env python3
"""Original-firmware TCC / SoftwareUpdate focused binary metadata comparator.

Input: extracted Apple Mach-O bytes; output: symbols, relative method sizes,
and strings, but no copyrighted raw binaries. Never executes code on devices.
"""
import argparse, hashlib, json, re, struct, subprocess
from pathlib import Path

MAGIC_32 = 0xfeedface
ARCH_ARM64_32 = 0x0200000c
P = re.compile(r'path|valid|authori|permission|audit|entitle|sandbox|check|write|rename|move|replace|copy|stage|install|tcc|softwareupdate|extract|destination|origin|target|cache|file|preflight|pid|uid|client',re.I)

def mach_symbols(data):
    if len(data) < 28 or struct.unpack_from("<I",data,0)[0] != MAGIC_32:
        return {"error":"not a 32-bit Mach-O header", "symbols":{}, "symbol_count":0}
    if struct.unpack_from("<I",data,4)[0] != ARCH_ARM64_32:
        return {"error":"not ARM64_32", "symbols":{}, "symbol_count":0}
    ncmds=struct.unpack_from("<I",data,16)[0]
    p=28; symtab=None; text_section=None
    for i in range(ncmds):
        if p+8>len(data):return {"error":"broken load command", "symbols":{}, "symbol_count":0}
        cmd,size=struct.unpack_from("<II",data,p)
        if size<8 or p+size>len(data):return {"error":"broken load command size", "symbols":{}, "symbol_count":0}
        if cmd==2:symtab=struct.unpack_from("<IIII",data,p+8)
        if cmd==1:
            nsects=struct.unpack_from("<I",data,p+48)[0] if size>=56 else 0
            for n in range(nsects):
                off=p+56+n*68
                if off+68>p+size:break
                sect=data[off:off+16].split(b"\0",1)[0]
                seg=data[off+16:off+32].split(b"\0",1)[0]
                addr,sz,fileoffset=struct.unpack_from("<III",data,off+32)
                if sect==b"__text" and seg==b"__TEXT":text_section=(addr,sz,fileoffset)
        p+=size
    if not symtab or not text_section:
        return {"error":"missing symtab or __TEXT,__text", "symbols":{}, "symbol_count":0}
    off,num,str_off,str_len=symtab
    if off+num*12>len(data) or str_off+str_len>len(data):
        return {"error":"out-of-bounds nlist", "symbols":{}, "symbol_count":0}
    names=data[str_off:str_off+str_len]
    codeaddr,codesize,codeoff=text_section
    found=[]
    for i in range(num):
        nameoff,stype,sect,desc,vm=struct.unpack_from("<IBBhI",data,off+i*12)
        if not codeaddr<=vm<codeaddr+codesize or nameoff>=str_len:continue
        nul=names.find(b"\0",nameoff)
        if nul<0:continue
        name=names[nameoff:nul].decode("utf-8","replace")
        if name:found.append((vm,name))
    found.sort()
    high={}
    for i,(addr,name) in enumerate(found):
        if not P.search(name):continue
        nextaddr = found[i+1][0] if i+1<len(found) else codeaddr+codesize
        length=max(0,min(nextaddr-addr,0x4000))
        offset=codeoff+(addr-codeaddr)
        if offset>=len(data):continue
        segment=data[offset:offset+length]
        high[name]={"bytes":length,"body_sha256":hashlib.sha256(segment).hexdigest(),
                    "original_vm":hex(addr)}
    return {"symbols":high,"symbol_count":num,
            "defined_code_symbols":len(found),"error":None}

def analyze(path):
    p=Path(path);d=p.read_bytes()
    result={"source":p.name,"size":len(d),"sha256":hashlib.sha256(d).hexdigest()}
    result.update(mach_symbols(d))
    try:
        s=subprocess.check_output(["strings","-a","-n","8",str(p)],text=True,errors="replace")
        relevant=[line.strip() for line in s.splitlines() if P.search(line)]
        result["relevant_strings"]=sorted(set(relevant))[:4500]
        result["relevant_strings_total"]=len(relevant)
    except Exception as e:result["strings_error"]=str(e)
    return result

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input",required=True)
    ap.add_argument("--version",required=True)
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    paths=sorted(p for p in Path(args.input).iterdir() if p.is_file())
    if not paths: raise SystemExit("missing originals")
    j={"version":args.version,
       "limitations":["Offline original-firmware symbols are not necessarily public or reachable from an app",
                      "Changes between these OS versions may be unrelated to the named CVEs",
                      "Symbol body hashes can change after relinking without behavior changing",
                      "This report neither writes system files nor establishes a working exploit"],
       "binaries":{p.name:analyze(p) for p in paths}}
    Path(args.output).write_text(json.dumps(j,indent=2)+"\n")
    for name,x in j["binaries"].items():
        print(args.version,name,"sha",x['sha256'],"nlist",x['symbol_count'],
              "interesting",len(x["symbols"]),"strings",x.get("relevant_strings_total"))
if __name__=="__main__":main()
