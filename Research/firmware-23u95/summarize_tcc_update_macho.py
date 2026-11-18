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
    def err(reason):
        return {"error":reason,"symbols":{},"symbol_count":0}
    if len(data)<32: return err("invalid Mach-O header")
    magic=struct.unpack_from("<I",data,0)[0]
    bits=32 if magic==0xfeedface else 64 if magic==0xfeedfacf else 0
    if not bits:return err("unrecognized Mach-O magic")
    cputype=struct.unpack_from("<I",data,4)[0]
    if cputype not in (0x0200000c,0x0100000c):
        return err("not an Apple ARM64/ARM64_32 image")
    ncmds=struct.unpack_from("<I",data,16)[0]
    p=28 if bits==32 else 32
    symtab=None;text_section=None
    for _ in range(ncmds):
        if p+8>len(data):return err("truncated load command")
        cmd,size=struct.unpack_from("<II",data,p)
        if size<8 or p+size>len(data):return err("broken load command")
        if cmd==2 and size>=24:symtab=struct.unpack_from("<IIII",data,p+8)
        if (cmd==1 and bits==32) or (cmd==0x19 and bits==64):
            nsects=struct.unpack_from("<I",data,p+(48 if bits==32 else 64))[0]
            step=68 if bits==32 else 80
            header=56 if bits==32 else 72
            for j in range(nsects):
                start=p+header+j*step
                if start+step>p+size:break
                sect=data[start:start+16].split(b"\0",1)[0]
                seg=data[start+16:start+32].split(b"\0",1)[0]
                if bits==32:
                    addr,sz=struct.unpack_from("<II",data,start+32)
                    offset=struct.unpack_from("<I",data,start+40)[0]
                else:
                    addr,sz=struct.unpack_from("<QQ",data,start+32)
                    offset=struct.unpack_from("<I",data,start+48)[0]
                if sect==b"__text" and seg in (b"__TEXT",b"__TEXT_EXEC"):
                    text_section=(addr,sz,offset)
        p+=size
    if not symtab or not text_section:return err("missing LC_SYMTAB or executable text")
    off,num,str_off,str_len=symtab
    stride=12 if bits==32 else 16
    if off+num*stride>len(data) or str_off+str_len>len(data):
        return err("invalid original symbol table bounds")
    names=data[str_off:str_off+str_len]
    codeaddr,codesize,codeoff=text_section
    found=[]
    for i in range(num):
        fmt="<IBBhI" if bits==32 else "<IBBHQ"
        nameoff,stype,sect,desc,vm=struct.unpack_from(fmt,data,off+i*stride)
        if not codeaddr<=vm<codeaddr+codesize or nameoff>=str_len:continue
        stop=names.find(b"\0",nameoff)
        if stop<0:continue
        label=names[nameoff:stop].decode("utf-8","replace")
        if label:found.append((vm,label))
    found.sort()
    out={}
    for i,(addr,label) in enumerate(found):
        if not P.search(label):continue
        next_pc=found[i+1][0] if i+1<len(found) else codeaddr+codesize
        length=max(0,min(next_pc-addr,0x4000))
        ofs=codeoff+(addr-codeaddr)
        if ofs>=len(data):continue
        body=data[ofs:ofs+length]
        out[label]={"bytes":length,"body_sha256":hashlib.sha256(body).hexdigest(),
                    "original_vm":hex(addr)}
    return {"symbols":out,"symbol_count":num,
            "defined_code_symbols":len(found),"macho_bits":bits,"error":None}


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
