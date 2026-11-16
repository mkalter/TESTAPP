#!/usr/bin/env python3
"""Read-only inventory of extracted firmware for MobileGestalt authorization research.

This never interacts with a Watch or calls a system writer. It enumerates
strings and entitlement plist files, and is not an exploit finder.
"""
import argparse
import hashlib
import json
import os
import plistlib
import sys
import tempfile
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
MARKERS = {
    "write_function": b"MGWriteCache",
    "rebuild_function": b"MGRebuildCache",
    "hypothetical_setter": b"MGSetAnswer",
    "read_function": b"MGCopyAnswer",
    "helper_mach_service": b"com.apple.mobilegestalt.xpc",
    "target_system_group": b"systemgroup.com.apple.mobilegestaltcache",
    "private_cache_entitlement": b"com.apple.private.security.storage.MobileGestaltCache",
    "source_device_tree": b"marketing-software-behavior",
    "cache_sentinel": b"setCacheSentinel",
}
RIGHTS = (
    "com.apple.private.security.storage.MobileGestaltCache",
    "com.apple.security.system-groups",
    "com.apple.security.system-group-containers",
    "com.apple.security.application-groups",
)
MACHO_MAGIC = {bytes.fromhex(v) for v in
               ("feedface", "cefaedfe", "feedfacf", "cffaedfe",
                "cafebabe", "bebafeca", "cafebabf", "bfbafeca")}


def walk(root):
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
        for name in files:
            path = Path(directory) / name
            if path.is_file() and not path.is_symlink():
                yield path


def inspect(path, root):
    try:
        if not 0 < path.stat().st_size <= MAX_BYTES:
            return None
        content = path.read_bytes()
    except OSError:
        return None
    signs = [key for key, value in MARKERS.items() if value in content]
    rights = {}
    if path.suffix in (".plist", ".entitlements"):
        try:
            plist = plistlib.loads(content)
            if isinstance(plist, dict):
                claims = plist.get("Entitlements", plist)
                if isinstance(claims, dict):
                    rights = {k: claims[k] for k in RIGHTS if k in claims}
        except (ValueError, TypeError, OverflowError):
            pass
    excerpt = []
    if path.suffix in (".sb", ".txt", ".md", ".profile", ".scm"):
        try:
            if b"\x00" not in content[:8192]:
                lines = content.decode("utf-8").splitlines()
                locations = [i for i, line in enumerate(lines)
                             if "MobileGestaltCache" in line
                             or "systemgroup.com.apple.mobilegestaltcache" in line]
                selected = set()
                for i in locations[:8]:
                    selected.update(range(max(0, i - 5), min(len(lines), i + 11)))
                excerpt = [{"line": i + 1, "text": lines[i][:260]}
                           for i in sorted(selected)[:100]]
        except UnicodeError:
            pass
    if not signs and not rights and not excerpt:
        return None
    priority = (3 if "write_function" in signs and rights
                else 2 if "write_function" in signs or rights
                else 1)
    return {
        "path": str(path.relative_to(root)),
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "macho_header": content[:4] in MACHO_MAGIC,
        "matched_binary_strings": signs,
        "parsed_entitlement_claims": rights,
        "sandbox_text_excerpt": excerpt,
        "audit_priority": priority,
        "proof_of_write": False
    }


def scan(root):
    items = []
    too_large = 0
    for path in walk(root):
        try:
            if path.stat().st_size > MAX_BYTES:
                too_large += 1
                continue
        except OSError:
            continue
        row = inspect(path, root)
        if row:
            items.append(row)
    items.sort(key=lambda r: (-r["audit_priority"], r["path"]))
    return {"root": str(root.resolve()), "items": items,
            "large_files_skipped": too_large,
            "limitation": "Strings and plist claims do not imply effective rights"}


def markdown(report, build):
    lines = [
        "# Static MobileGestalt firmware inventory",
        "",
        "Target build (supplied by investigator): " + build,
        "Files with matching evidence: " + str(len(report["items"])),
        "Files larger than 64 MiB skipped: " + str(report["large_files_skipped"]),
        "",
        "This scan does NOT confirm authorization, control flow, vulnerability,",
        "or a working system-cache writer. No Watch was accessed.",
        "",
        "| Priority | File | Markers | Entitlement claims |",
        "|---|---|---|---|",
    ]
    for item in report["items"][:150]:
        markers = ", ".join(item["matched_binary_strings"][:7]) or "policy"
        entitlements = ", ".join(item["parsed_entitlement_claims"]) or "none"
        lines.append("| %s | %s | %s | %s |" % (
            item["audit_priority"], item["path"].replace("|", "/"),
            markers, entitlements))
    lines.extend(["", "## Relevant policy text", ""])
    for item in report["items"]:
        if item["sandbox_text_excerpt"]:
            lines.append("### " + item["path"])
            for line in item["sandbox_text_excerpt"]:
                lines.append("%d: %s" % (line["line"], line["text"]))
    lines.extend(["", "## Correct interpretation", "",
                  "- String matches are references, not call sites.",
                  "- Signed private entitlements must also be validated at runtime.",
                  "- Fixed-path cache rebuild is not a user-supplied value setter.",
                  "- Compare the exact hardware-specific firmware before interpreting.",
                  "- Extract individual dylibs from dyld shared cache before scanning;",
                  "  large raw shared-cache segments are intentionally skipped."])
    return "\n".join(lines) + "\n"


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "System/Library/Sandbox").mkdir(parents=True)
        (root / "Entitlements").mkdir()
        (root / "usr/libexec").mkdir(parents=True)
        (root / "System/Library/Sandbox/container.sb").write_text(
            '(allow file-write-data (require-all (storage-class "MobileGestaltCache") '
            '(extension "com.apple.sandbox.system-group") '
            '(entitlement "com.apple.security.system-groups")))',
            encoding="utf-8")
        (root / "Entitlements/MobileGestaltHelper.plist").write_bytes(
            plistlib.dumps({
                "com.apple.private.security.storage.MobileGestaltCache": True,
                "com.apple.security.system-groups":
                    ["systemgroup.com.apple.mobilegestaltcache"]
            }))
        (root / "usr/libexec/MobileGestaltHelper").write_bytes(
            bytes.fromhex("cffaedfe") + b"\0_MGWriteCache\0com.apple.mobilegestalt.xpc")
        result = scan(root)
        assert len(result["items"]) == 3, result
        assert any(x["sandbox_text_excerpt"] for x in result["items"])
        assert any(x["parsed_entitlement_claims"] for x in result["items"])
        assert any(x["macho_header"] for x in result["items"])
        assert all(not x["proof_of_write"] for x in result["items"])
        assert "MobileGestalt" in markdown(result, "23U95")
    print("Self-test PASS: binary strings / entitlement plist / policy snippets")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path)
    p.add_argument("--output", type=Path, default=Path("mg-firmware-audit"))
    p.add_argument("--build", default="23U95")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.root or not args.root.is_dir():
        p.error("--root must be an existing extracted firmware directory")
    report = scan(args.root)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "inventory.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (args.output / "report.md").write_text(
        markdown(report, args.build), encoding="utf-8")
    print("Wrote static report for", len(report["items"]), "candidate files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
