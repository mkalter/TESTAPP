#!/usr/bin/env python3
"""Read-only original-watchOS TCC fat/thin Mach-O selector and string audit.
Symbols/strings alone never prove XPC authorization or a CVE exploit.
"""
import argparse, hashlib, json, re, struct
from pathlib import Path

ARM32=0x0200000c
ARM64=0x0100000c
PAT=re.compile(rb'(?i)(tcc|directory|legacy|database|path|validat|sandbox|entitl|audit|client|xpc|preflight|permission|container|cleanup|rename|unlink|extension|replace|migrat|authoriz|file)')

def select(data):
    if data[:4] in (bytes.fromhex('cefaedfe'), bytes.fromhex('cffaedfe')):
        if len(data)<12:raise ValueError('short thin Mach-O')
        return data,dict(format='thin',cpu_type=hex(struct.unpack_from('<I',data,4)[0]))
    fat={bytes.fromhex('cafebabe'):('>',20),bytes.fromhex('cafebabf'):('>',32),
         bytes.fromhex('bebafeca'):('<',20),bytes.fromhex('bfbafeca'):('<',32)}
    if data[:4] not in fat:raise ValueError('not a recognized Mach-O')
    end,step=fat[data[:4]]
    if len(data)<8:raise ValueError('short fat header')
    n=struct.unpack_from(end+'I',data,4)[0]
    if not 0<n<=32:raise ValueError('unreasonable arch count')
    arch=[]
    for i in range(n):
        off=8+i*step
        if off+step>len(data):raise ValueError('truncated arch header')
        cpu,sub=struct.unpack_from(end+'II',data,off)
        if step==20:start,size,_=struct.unpack_from(end+'III',data,off+8)
        else:start,size,_=struct.unpack_from(end+'QQI',data,off+8)
        if start<8+n*step or size<28 or start+size>len(data):raise ValueError('bad slice bounds')
        arch.append((cpu,sub,start,size))
    preferred=[r for cpu in (ARM32,ARM64) for r in arch if r[0]==cpu]
    if not preferred:raise ValueError('no ARM64_32/ARM64 slice')
    cpu,sub,start,size=preferred[0]
    selected=data[start:start+size]
    if selected[:4] not in (bytes.fromhex('cefaedfe'),bytes.fromhex('cffaedfe')):
        raise ValueError('non-Mach-O selected slice')
    if struct.unpack_from('<I',selected,4)[0]!=cpu:raise ValueError('cpu mismatch')
    return selected,dict(format='fat',architectures=[hex(r[0]) for r in arch],
                         selected_cpu=hex(cpu),selected_subtype=hex(sub),offset=start,size=size)

def audit(path,expected):
    original=Path(path).read_bytes()
    digest=hashlib.sha256(original).hexdigest()
    if digest!=expected.lower():raise ValueError('original SHA256 mismatch')
    selected,arch=select(original)
    matches=set()
    for match in re.finditer(rb'[\x20-\x7e]{7,200}',selected):
        raw=match.group(0).strip()
        if PAT.search(raw):matches.add(raw.decode('ascii','replace'))
    matches=sorted(matches)
    return selected,dict(original_sha256=digest,original_bytes=len(original),
        selected_sha256=hashlib.sha256(selected).hexdigest(),selected_bytes=len(selected),
        architecture=arch,matching_strings_total=len(matches),
        matching_strings=matches[:3000],limitations=[
          'Candidate strings do not establish implementations or vulnerable XPC entrypoints',
          'A TCC service port is not client authorization or a system-cache writer',
          'Binary bytes are not published in report artifact'])

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--input',required=True)
    p.add_argument('--expected-sha256',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--thin',required=True)
    a=p.parse_args()
    data,report=audit(a.input,a.expected_sha256)
    Path(a.thin).write_bytes(data)
    Path(a.output).write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print('Validated original SHA256 + selected slice:', report['architecture'])
    print('Matching candidate names:',report['matching_strings_total'])
