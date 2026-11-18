#!/usr/bin/env python3
"""Offline-only original Watch6,18 ClockKit/FaceBundle service identifier inventory.

No framework binary, source code or content file included in output artifact.
Only actual file existence, SHA256, Apple plist launch keys and bounded
XPC/selector indicator counts. This is NOT a service client or face import.
"""
import argparse,hashlib,json,plistlib,re
from pathlib import Path

KEYS=(
    b"CLKWatchFaceLibrary",b"CLKWatchFaceLibraryServer",
    b"CLKWatchFaceLibraryServerInterface",b"CLKCompanionWatchFaceLibraryService",
    b"validateFaceType:faceBundleId:completionHandler:",
    b"openWatchFaceURLWithSecurityScopedURL:",
    b"openWatchFaceURLWithBookmarkData:",b"addWatchFaceAtURL:",
    b"face.json",b"face type",b"bundle id",
    b"NTKGreenfieldUtilities",b"NTKDCollectionStore",
    b"_queue_addFace:forUUID:",b"_resetWithFaces:",
    b"isRestrictedForDevice:",b"NTKZeusFaceBundle",b"NTKHermes2025FaceBundle",
    b"com.apple.ClockKit.CLKWatchFaceLibrary",
)
def check_binary(path):
    data=path.read_bytes()
    hits={key.decode("ascii"):data.count(key) for key in KEYS}
    candidates=[]
    for match in re.finditer(rb"[\x20-\x7e]{7,160}",data):
        t=match.group()
        if any(k in t for k in (
            b"CLKWatchFaceLibrary",b"validateFaceType",
            b"openWatchFaceURL",b"faceBundleId",b"Greenfield",
            b"NTKGreenfield",b"CLKCompanion")):
            candidates.append(t.decode("ascii","replace")[:160])
    return dict(kind="binary",sha256=hashlib.sha256(data).hexdigest(),
                bytes=len(data),indicators=hits,distinct_matching_strings=sorted(set(candidates))[:100])
def check_plist(path):
    data=path.read_bytes()
    d=plistlib.loads(data)
    if not isinstance(d,dict):return dict(kind="plist",error="not dictionary")
    allowed=("CFBundleIdentifier","CFBundleExecutable","CFBundlePackageType","Label",
             "Program","ProgramArguments","MachServices","UserName","ServiceType")
    return dict(kind="plist",sha256=hashlib.sha256(data).hexdigest(),
                bytes=len(data),metadata={k:d[k] for k in allowed if k in d})
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--root",required=True)
    ap.add_argument("--output",required=True)
    a=ap.parse_args()
    root=Path(a.root)
    files=[]
    for path in sorted(root.rglob("*")):
        if not path.is_file():continue
        rel=str(path.relative_to(root))
        try:detail=check_plist(path) if path.name=="Info.plist" or path.suffix==".plist" else check_binary(path)
        except Exception as e:detail=dict(kind="inspection_error",error=str(e))
        files.append(dict(path=rel,**detail))
    report=dict(source="original matching Apple Watch6,18 watchOS26.6.1 23U95 range extraction",
                files=files,count=len(files),
                standalone_clockkit_framework_files=sum(
                    "ClockKit.framework/ClockKit" in x["path"] for x in files),
                clockkit_xpc_bundle_files=sum("ClockKit.framework/XPCServices" in x["path"] for x in files),
                limitations=[
                    "Absence of standalone ClockKit Mach-O not proof of absence from dyld shared cache",
                    "A declared Mach service or available selector does not establish a permitted XPC client",
                    "Face import and native Apple FaceBundle installation are separate operations",
                    "Original Apple binary data not published in artifact",
                    "No on-watch XPC, file edits, library state reset, or Hermès unlock performed"])
    Path(a.output).write_text(json.dumps(report,indent=2,default=str)+"\n")
    print("MATCHING ORIGINAL WATCHOS PATHS",len(files))
    for x in files:
        print(x["path"],x.get("kind"),x.get("sha256","NO_HASH"))
        if x.get("kind")=="binary":
            print("  Relevant selector evidence:",
                  {k:v for k,v in x["indicators"].items() if v})
        elif x.get("kind")=="plist":
            print("  Launch/identifier metadata:",x["metadata"])
    if not files:
        print("NOT FOUND as standalone files; inspect original dyld cache before concluding absent")
if __name__=="__main__":main()
