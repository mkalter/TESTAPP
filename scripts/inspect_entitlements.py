#!/usr/bin/env python3
"""Read-only audit of Watch/iPhone entitlements. Does not modify IPA or device.

Examples:
  python3 scripts/inspect_entitlements.py --source HermesEnabler2/HermesEnabler2.entitlements
  python3 scripts/inspect_entitlements.py --source HermesEnabler2/EntitlementProbe.private.entitlements
  python3 scripts/inspect_entitlements.py --ipa HermesEnabler.ipa   # macOS only
"""
import argparse
import pathlib
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

KEYS = (
    "com.apple.security.application-groups",
    "com.apple.security.system-groups",
    "com.apple.security.system-group-containers",
    "application-identifier",
    "com.apple.developer.team-identifier",
)


def run(*argv):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode:
        raise RuntimeError(
            "%s failed (%d): %s" %
            (" ".join(map(str, argv)), p.returncode,
             (p.stderr or p.stdout).decode(errors="replace").strip())
        )
    return p.stdout


def print_source(path):
    data = plistlib.loads(path.read_bytes())
    print("=== Source entitlement request: %s ===" % path)
    for key in KEYS:
        print("%s: %r" % (key, data.get(key, "<not requested>")))
    print("Source plist values are requests, NOT authorized or effective entitlements.")


def show_bundle(bundle):
    print("\n=== Bundle: %s ===" % bundle)
    try:
        signed = plistlib.loads(run("codesign", "-d", "--entitlements", ":-", str(bundle)))
    except (RuntimeError, ValueError, plistlib.InvalidFileException) as e:
        print("Cannot read signed entitlements: %s" % e)
        return

    profile = bundle / "embedded.mobileprovision"
    allowed = None
    if profile.is_file():
        try:
            allowed = plistlib.loads(
                run("security", "cms", "-D", "-i", str(profile))
            ).get("Entitlements", {})
        except (RuntimeError, ValueError, plistlib.InvalidFileException) as e:
            print("Cannot decode embedded provisioning profile: %s" % e)
    else:
        print("No embedded.mobileprovision found; entitlement authorization unverified.")

    for key in KEYS:
        claim = signed.get(key)
        grant = None if allowed is None else allowed.get(key)
        if key not in signed:
            status = "NOT IN SIGNATURE"
        elif allowed is None:
            status = "PROFILE NOT CHECKED"
        elif key not in allowed:
            status = "NOT ALLOWED BY PROFILE"
        elif isinstance(claim, list) and isinstance(grant, list):
            status = "MATCHES PROFILE" if all(x in grant for x in claim) else "PROFILE MISMATCH"
        elif claim == grant:
            status = "MATCHES PROFILE"
        else:
            # Some Apple entitlements have wildcards. For these, inspect full values.
            status = "VALUES DIFFER (inspect wildcard/profile semantics)"
        print("%s: %s" % (key, status))
        print("  signature: %r" % claim)
        print("  profile:   %r" % grant)
    print("Even a matching signature/profile does not prove access to MobileGestalt.")


def inspect_ipa(path):
    if not path.is_file() or not zipfile.is_zipfile(path):
        raise ValueError("IPA must be an existing ZIP-based .ipa file")
    if not shutil.which("codesign") or not shutil.which("security"):
        raise RuntimeError("IPA signature checks need macOS codesign and security utilities")

    with tempfile.TemporaryDirectory(prefix="ipa-entitlements-") as name:
        root = pathlib.Path(name)
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                dest = (root / item.filename).resolve()
                if not dest.is_relative_to(root.resolve()):
                    raise ValueError("Unsafe archive path detected")
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Symlink entry in IPA; refusing unsafe extraction")
            archive.extractall(root)

        hosts = sorted((root / "Payload").glob("*.app"))
        bundles = list(hosts)
        for host in hosts:
            bundles.extend(sorted((host / "Watch").glob("*.app")))
        if not bundles:
            raise ValueError("No Payload/*.app or embedded Watch/*.app found")
        for bundle in bundles:
            if bundle.is_dir():
                show_bundle(bundle)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--source", type=pathlib.Path, help="Inspect a source entitlements plist (any OS)")
    group.add_argument("--ipa", type=pathlib.Path, help="Inspect signed IPA including Watch app (macOS)")
    args = p.parse_args()
    try:
        if args.source:
            print_source(args.source)
        else:
            inspect_ipa(args.ipa)
    except (OSError, ValueError, RuntimeError, plistlib.InvalidFileException) as e:
        p.exit(1, "ERROR: %s\n" % e)


if __name__ == "__main__":
    main()
