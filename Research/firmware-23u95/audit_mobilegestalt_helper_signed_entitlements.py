#!/usr/bin/env python3
"""Read the *actual Code Signature entitlements* of an original Apple Mach-O.

Read-only; validates exact SHA256 and parses LC_CODE_SIGNATURE's embedded
SuperBlob. Raw binary and signatures remain private to the GitHub runner.
A string found elsewhere in the Mach-O is NOT accepted as an entitlement.
"""
import argparse, hashlib, json, plistlib, struct
from pathlib import Path

LC_CODE_SIGNATURE=0x1d
CSMAGIC_EMBEDDED_SIGNATURE=0xfade0cc0
CSMAGIC_EMBEDDED_ENTITLEMENTS=0xfade7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS=0xfade7172
CSSLOT_ENTITLEMENTS=5
CSSLOT_DER_ENTITLEMENTS=7

def parse(binary):
    if len(binary)<28 or struct.unpack_from("<I",binary)[0]!=0xfeedface:
        raise ValueError("Expected 32-bit ARM64_32 Mach-O")
    if struct.unpack_from("<I",binary,4)[0]!=0x0200000c:
        raise ValueError("Wrong target CPU")
    commands=struct.unpack_from("<I",binary,16)[0]
    sizecmd=struct.unpack_from("<I",binary,20)[0]
    pos=28
    if commands<1 or commands>200 or pos+sizecmd>len(binary):
        raise ValueError("Bad Mach-O load commands")
    offsize=None
    for _ in range(commands):
        if pos+8>len(binary):raise ValueError("Truncated load command")
        cmd,size=struct.unpack_from("<II",binary,pos)
        if size<8 or pos+size>len(binary):raise ValueError("Invalid load command")
        if cmd==LC_CODE_SIGNATURE:
            if size<16:raise ValueError("Truncated code signature command")
            offsize=struct.unpack_from("<II",binary,pos+8)
        pos+=size
    if offsize is None:raise ValueError("No Mach-O LC_CODE_SIGNATURE")
    offset,size=offsize
    if offset<0 or size<12 or offset+size>len(binary):
        raise ValueError("Invalid signature range")
    cs=binary[offset:offset+size]
    magic,length,count=struct.unpack_from(">III",cs,0)
    if magic!=CSMAGIC_EMBEDDED_SIGNATURE:
        raise ValueError("Not a code-signature SuperBlob")
    if length>len(cs) or length<12 or count>128 or 12+count*8>length:
        raise ValueError("Invalid SuperBlob bounds")
    results=[]
    for i in range(count):
        kind,start=struct.unpack_from(">II",cs,12+i*8)
        if start+8>length:raise ValueError("Invalid signature slot")
        blob_magic,blob_size=struct.unpack_from(">II",cs,start)
        if blob_size<8 or start+blob_size>length:
            raise ValueError("Invalid embedded slot range")
        payload=cs[start+8:start+blob_size]
        result=dict(slot_type=hex(kind),magic=hex(blob_magic),
                    blob_sha256=hashlib.sha256(cs[start:start+blob_size]).hexdigest(),
                    payload_bytes=len(payload))
        if kind==CSSLOT_ENTITLEMENTS and blob_magic==CSMAGIC_EMBEDDED_ENTITLEMENTS:
            try:
                ent=plistlib.loads(payload)
                if not isinstance(ent,dict):raise ValueError("Entitlements not dict")
                result["xml_entitlements"]=ent
            except Exception as e:
                raise ValueError(f"Invalid XML entitlement signature: {e}") from e
        if kind==CSSLOT_DER_ENTITLEMENTS and blob_magic==CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
            result["der_present"]=True
        results.append(result)
    entitlements=[r["xml_entitlements"] for r in results if "xml_entitlements" in r]
    return dict(code_signature_offset=offset,code_signature_bytes=size,
                slots=results,
                xml_entitlements=entitlements[0] if len(entitlements)==1 else None,
                xml_entitlement_slot_count=len(entitlements),
                der_entitlement_slot_count=sum(1 for r in results if r.get("der_present")))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--sha256",required=True)
    p.add_argument("--report",required=True)
    a=p.parse_args()
    b=Path(a.input).read_bytes()
    sha=hashlib.sha256(b).hexdigest()
    if sha!=a.sha256.lower():raise ValueError("Apple original SHA256 mismatch")
    result=parse(b)
    ent=result.get("xml_entitlements")
    targets=["com.apple.private.security.storage.MobileGestaltCache",
             "com.apple.security.system-groups",
             "com.apple.security.system-group-containers"]
    result.update(source_sha256=sha,source_bytes=len(b),
                  queried_entitlements={k: ent.get(k) if ent else None for k in targets},
                  target_group_declared=bool(
                      ent and "systemgroup.com.apple.mobilegestaltcache"
                      in str(ent.get("com.apple.security.system-groups",""))),
                  limitations=[
                    "Signature entitlements evidence is not a proof of remote API authorization",
                    "No private API was invoked; no system file writes occurred",
                    "XML entitlements alone do not cryptographically validate Apple's signature chain"])
    # Keep report focused on target entitlement names; don't republish all
    # unrelated Apple entitlements or source binary.
    for item in result["slots"]:item.pop("xml_entitlements",None)
    result.pop("xml_entitlements",None)
    Path(a.report).write_text(json.dumps(result,indent=2)+"\n")
    print("Validated sha",sha,"XML slot count",result["xml_entitlement_slot_count"],
          "target group declared",result["target_group_declared"])
    print("Target entitlements",json.dumps(result["queried_entitlements"],sort_keys=True))
    if result["xml_entitlement_slot_count"]!=1:
        raise SystemExit("Cannot establish target entitlements from exactly one XML slot")

if __name__=="__main__":main()
