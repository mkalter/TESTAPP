#!/usr/bin/env python3
"""Compare *decompiled text* watchOS sandbox policy issuer and receiver gates (read-only).

Inputs are pre-extracted policy text; the tool does not download/decrypt firmware,
modify devices, request entitlements, or attempt sandbox bypasses.

Example:
  python3 Research/compare_systemgroup_policy.py watch7_5_26.sb watch7_5_27.sb
  python3 Research/compare_systemgroup_policy.py watch7_5_26.sb watch7_5_27.sb --all-file-rules
"""
import argparse
import difflib
import hashlib
from pathlib import Path
import re
import sys

# The previous comparator skipped file-issue-extension entirely: the main
# iOS 26->27 policy change was therefore invisible even with both profiles.
# Also cover file-write* / file-read* shorthand.
RULE_RE = re.compile(
    r"\(\s*(allow|deny)\s+"
    r"(file-issue-extension|file-(?:read|write)(?:-[a-z0-9-]+|\*)?)"
    r"(?=[\s\)])", re.I,
)
KEYS = (
    "system-group", "systemgroup", "system-groups", "system-group-containers",
    "mobilegestaltcache", "Shared/SystemGroup", "com.apple.app-sandbox.read-write",
)


def read_text(path: Path) -> str:
    data = path.read_bytes()
    if b"\x00" in data:
        raise ValueError(f"{path}: looks like a binary file; provide a decompiled .sb text profile")
    return data.decode("utf-8")


def balanced_expression(source: str, start: int) -> str | None:
    """Capture one parenthesized rule, respecting quotes and ; comments."""
    depth = 0
    quoted = False
    escaped = False
    comment = False
    for i in range(start, len(source)):
        ch = source[i]
        if comment:
            if ch == "\n":
                comment = False
            continue
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
            continue
        if ch == ";":
            comment = True
        elif ch == '"':
            quoted = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
            if depth < 0:
                return None
    return None


def rules(source: str, all_file_rules: bool) -> list[str]:
    matches = []
    seen = set()
    for match in RULE_RE.finditer(source):
        expr = balanced_expression(source, match.start())
        if not expr:
            continue
        # Decompilation and macro expansion may change apparent rule structure.
        norm = " ".join(expr.split())
        if not all_file_rules and not any(key.lower() in norm.lower() for key in KEYS):
            continue
        if norm not in seen:
            matches.append(norm)
            seen.add(norm)
    return sorted(matches)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("profile_26", type=Path, help="Decompiled watchOS 26 sandbox profile text")
    ap.add_argument("profile_27", type=Path, help="Decompiled watchOS 27 sandbox profile text")
    ap.add_argument("--all-file-rules", action="store_true", help="Compare all read/write file rules, not just SystemGroup-related rules")
    args = ap.parse_args()
    try:
        old_source, new_source = read_text(args.profile_26), read_text(args.profile_27)
    except (OSError, UnicodeError, ValueError) as exc:
        ap.error(str(exc))
    old, new = rules(old_source, args.all_file_rules), rules(new_source, args.all_file_rules)
    print("UNVERIFIED INPUT: this utility does not independently authenticate "
          "the extracted watchOS build, device model or decompiled policy.")
    print(f"26 input: {args.profile_26} SHA256={digest(args.profile_26)}")
    print(f"27 input: {args.profile_27} SHA256={digest(args.profile_27)}")
    print(f"Rule filter: {'all file read/write rules' if args.all_file_rules else 'SystemGroup-related read/write rules'}")
    print(f"Matching rules: 26={len(old)}, 27={len(new)}")
    def phase(rule: str) -> str:
        lowered = rule.lower()
        if re.search(r"^\(\s*(?:allow|deny)\s+file-issue-extension", lowered):
            return "ISSUER"
        if re.search(r"^\(\s*(?:allow|deny)\s+file-write", lowered):
            return "RECEIVER_WRITE"
        return "RECEIVER_READ"

    print("Authorization phases (a token is not evidence of write permission):")
    for kind in ("ISSUER", "RECEIVER_WRITE", "RECEIVER_READ"):
        left = sorted(x for x in old if phase(x) == kind)
        right = sorted(x for x in new if phase(x) == kind)
        added = sorted(set(right) - set(left))
        removed = sorted(set(left) - set(right))
        print(f"  {kind}: 26={len(left)} 27={len(right)} "
              f"new={len(added)} removed={len(removed)}")
    if not any(phase(rule) == "ISSUER" for rule in old + new):
        print("WARNING: no relevant extension-issuer rules found. "
              "This is NOT evidence that issuance is permitted or identical.")
    if not any(phase(rule) == "RECEIVER_WRITE" for rule in old + new):
        print("WARNING: no relevant protected write policy rules found. "
              "Inspect inherited/include policies; absence does not mean ALLOW.")
    if not old and not new:
        print("NO RELEVANT RULES FOUND: input may be incomplete, rules may use indirect predicates,")
        print("or text may not be a suitable decompiled profile. This does NOT prove permission.")
        return 2
    diff = list(difflib.unified_diff(old, new, fromfile="watchOS26", tofile="watchOS27", lineterm=""))
    if not diff:
        print("No textual changes among captured rules. Defaults, includes, entitlement context and")
        print("runtime behavior still need independent verification.")
    else:
        print("\n".join(diff))
        print("This is a TEXT diff, not a verified effective sandbox or exploitability diff.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
