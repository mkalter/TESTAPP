#!/usr/bin/env python3
"""Exact watchOS 26.6.1 CoreFoundation static preference authority trace.

Reads original SHA-validated ARM64_32 CoreFoundation extracted from 23U95.
Uses Mach-O nlist (not a string-name guess) to locate concrete implementations.
Only bounded disassembly of identified symbols and immediate BL destinations.
No device, privileged IPC, or file writes.
"""
from __future__ import annotations
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from resolve_daemon_objc import sections

EXPECTED = "f08e572ddcdd26ce33704165a63992ce91fc57c4a90907432b15af7d373acb86"
TARGET_NAMES = [
    "_CFPrefsImpersonateApplicationWithIdentifierAndAuditToken",
    "_CFPrefsGetEntitlementForMessageWithLockedContext",
    "__CFPreferencesWriteDomainDictionaryToPath",
    "+[CFPrefsDaemon _copyUncanonicalizedSourcePathWithDomain:user:byHost:containerPath:managed:managedUsesContainer:]",
    "+[CFPrefsDaemon _getUncanonicalizedSourcePath:withDomain:user:byHost:containerPath:managed:managedUsesContainer:]",
    "-[CFPrefsDaemon handleMessage:fromPeer:replyHandler:]",
    "-[CFPrefsDaemon handleSourceMessage:replyHandler:]",
    "-[CFPrefsDaemon _createSourceWithDomain:user:container:byHost:managed:shmemIndex:]",
    "-[CFPrefsDaemon withSourceForDomain:inContainer:user:byHost:managed:managedUsesContainer:cloudStoreEntitlement:cloudConfigurationPath:performWithSourceLock:afterReleasingSourceLock:]",
    "-[CFPrefsPlistSource attachSandboxExtensionTokenToMessage:forWriting:]",
    "-[CFPrefsPlistSource attachAccessTokenToMessage:accessType:]",
    "-[CFPrefsSource validateValue:forKey:inDict:forWriting:]",
]
MAX_BYTES = 0x980
MAX_INS = MAX_BYTES // 4


def syms(data):
    if len(data) < 28 or struct.unpack_from("<I", data, 0)[0] != 0xfeedface:
        raise ValueError("Expected a little-endian 32-bit ARM64_32 Mach-O")
    if struct.unpack_from("<I", data, 4)[0] != 0x0200000c:
        raise ValueError("Wrong Mach-O CPU architecture")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    pos = 28
    symtab = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, pos)
        if size < 8 or pos+size > len(data):
            raise ValueError("Invalid Mach-O load command")
        if cmd == 2:
            symtab = struct.unpack_from("<IIII", data, pos+8)
        pos += size
    if not symtab:
        raise ValueError("Original Mach-O has no LC_SYMTAB")
    symoff, nsyms, stroff, strsize = symtab
    if symoff+12*nsyms > len(data) or stroff+strsize > len(data):
        raise ValueError("Mach-O symbol bounds invalid")
    names = data[stroff:stroff+strsize]
    result = {}
    for index in range(nsyms):
        nameoff, kind, sect, desc, vm = struct.unpack_from("<IBBhI", data, symoff+12*index)
        if nameoff >= strsize or vm == 0:
            continue
        zero = names.find(b"\0", nameoff)
        if zero < 0:
            continue
        label = names[nameoff:zero].decode("utf-8","replace")
        if label:
            result.setdefault(label,[]).append({"address":vm,"type":kind,"section":sect})
    return result, nsyms


def targeted(data, source_path):
    actual = hashlib.sha256(data).hexdigest()
    if actual != EXPECTED:
        raise ValueError(f"Expected exact 23U95 CoreFoundation {EXPECTED}; got {actual}")
    ss = sections(data)
    code = next((s for s in ss if s["name"]=="__TEXT,__text"), None)
    if not code:
        raise ValueError("Missing executable code section")
    sym, nsyms = syms(data)
    address_lookup = {}
    for label, instances in sym.items():
        for instance in instances:
            address_lookup.setdefault(instance["address"],[]).append(label)
    all_pcs = sorted(p for p in address_lookup if code["vm"] <= p < code["vm"]+code["size"])
    cs = Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    report = {"source":"original Apple Watch6,18 23U95 CoreFoundation",
              "sha256":actual, "original_path":source_path,
              "symbol_entries":nsyms,
              "target_methods":[],"missing_targets":[],
              "limitations":["A symbol's existence is not an authorization bypass.",
                             "Only direct BL calls are mapped; ObjC message dispatch and conditional block callbacks require separate study.",
                             "No XPC call, sandbox operation, or protected write was performed."]}
    for target in TARGET_NAMES:
        candidates = sym.get(target,[])
        candidates = [v for v in candidates if code["vm"] <= v["address"] < code["vm"]+code["size"]]
        if not candidates:
            report["missing_targets"].append(target)
            continue
        for candidate in candidates:
            pc=candidate["address"]
            next_pcs=[q for q in all_pcs if q>pc]
            nextpc=next_pcs[0] if next_pcs else code["vm"]+code["size"]
            size=max(0,min(MAX_BYTES,nextpc-pc,code["vm"]+code["size"]-pc))
            start=code["offset"]+(pc-code["vm"])
            ins=list(cs.disasm(data[start:start+size],pc))[:MAX_INS]
            instructions=[]
            direct_calls=[]
            for inst in ins:
                instructions.append(f"{inst.address:#010x} {inst.mnemonic:8} {inst.op_str}")
                if inst.mnemonic == "bl":
                    dest_string=inst.op_str.strip().lstrip("#")
                    try: target_pc=int(dest_string,16)
                    except ValueError: continue
                    direct_calls.append({
                        "pc":hex(inst.address),
                        "target":hex(target_pc),
                        "names":address_lookup.get(target_pc,[])[:12],
                    })
            report["target_methods"].append({
                "label":target,"method_address":hex(pc),"bytes":size,
                "next_symbol_va":hex(nextpc),
                "source_of_address":"validated Mach-O LC_SYMTAB nlist32",
                "instruction_count":len(ins),
                "direct_calls":direct_calls,
                "instructions":instructions})
    return report


def main(binary, out):
    buf=Path(binary).read_bytes()
    result=targeted(buf,str(binary))
    dest=Path(out)
    dest.mkdir(parents=True,exist_ok=True)
    (dest/"cfprefsd-authority-disassembly.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=[f"Exact CoreFoundation SHA256: {result['sha256']}",
           f"nlist original symbols: {result['symbol_entries']}",
           f"resolved target implementations: {len(result['target_methods'])}/{len(TARGET_NAMES)}"]
    for rec in result["target_methods"]:
        lines.append(f"\n=== {rec['label']} @ {rec['method_address']} ({rec['bytes']} bytes) ===")
        lines.extend(rec["instructions"])
        lines.append("DIRECT CALLS:")
        for edge in rec["direct_calls"]:
            lines.append("  "+edge["pc"]+" -> "+edge["target"]+" "+", ".join(edge["names"]))
    lines.append("MISSING TARGETS: "+json.dumps(result["missing_targets"]))
    lines.extend("LIMIT: "+x for x in result["limitations"])
    (dest/"cfprefsd-authority-disassembly.txt").write_text("\n".join(lines)+"\n")
    print("\n".join(lines[:3]))
    for rec in result["target_methods"]:
        print(f" {rec['method_address']} {rec['label']} ins={rec['instruction_count']} calls={len(rec['direct_calls'])}")
    if result["missing_targets"]:
        print("Non-resolved targets:",*result["missing_targets"],sep="\n - ")
    if not result["target_methods"]:
        raise SystemExit("No verified addresses; cannot infer permission semantics from strings alone")


if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: trace_cfpreferences_authority.py <CoreFoundation-original> <report-dir>")
    main(sys.argv[1], sys.argv[2])
