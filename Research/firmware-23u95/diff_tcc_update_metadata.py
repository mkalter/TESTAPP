#!/usr/bin/env python3
"""Report same Watch model 26 -> 27 patch changes from *source metadata*.

Does not attribute particular changes to CVEs without independent proof.
"""
import argparse,json,re
from pathlib import Path
def score(name):
    p=[("validat|canonical|normaliz|sanitiz",9),("sandbox|entitle|permiss|authoriz|audit",8),
       ("move|rename|replace|write|copy|install|stage|file|path",5),
       ("tcc|softwareupdate|client|request",2)]
    return sum(w for regex,w in p if re.search(regex,name,re.I))
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--old",required=True)
    ap.add_argument("--new",required=True);ap.add_argument("--output",required=True)
    args=ap.parse_args();a=json.loads(Path(args.old).read_text());b=json.loads(Path(args.new).read_text())
    rows=[]
    for name in sorted(set(a["binaries"])|set(b["binaries"])):
        old=a["binaries"].get(name,{});new=b["binaries"].get(name,{})
        old_syms=old.get("symbols",{}); new_syms=new.get("symbols",{})
        method_changes=[]
        for sym in sorted(set(old_syms)|set(new_syms)):
            o=old_syms.get(sym);n=new_syms.get(sym)
            if not o or not n:
                kind="new" if n else "removed"
            elif o["bytes"]!=n["bytes"]:kind="size changed"
            elif o["body_sha256"]!=n["body_sha256"]:kind="same size body changed"
            else:continue
            method_changes.append({"name":sym,"kind":kind,
                "old_size":o["bytes"] if o else None,"new_size":n["bytes"] if n else None,
                "score":score(sym)})
        method_changes.sort(key=lambda x:(-x["score"],x["kind"]=="same size body changed",x["name"]))
        oldstr=set(old.get("relevant_strings",[]));newstr=set(new.get("relevant_strings",[]))
        added=sorted(newstr-oldstr,key=lambda x:-score(x))[:120]
        removed=sorted(oldstr-newstr,key=lambda x:-score(x))[:120]
        rows.append({"binary":name,"old_sha256":old.get("sha256"),
            "new_sha256":new.get("sha256"),"old_bytes":old.get("size"),
            "new_bytes":new.get("size"),"method_changes_count":len(method_changes),
            "changed_methods_ranked":method_changes[:160],
            "new_relevant_strings":added,"removed_relevant_strings":removed,
            "old_method_count":len(old_syms),"new_method_count":len(new_syms),
            "unsupported":old.get("error") or new.get("error")})
    out={"old":a["version"],"new":b["version"],
        "same_hardware":"Apple Watch7,5",
        "warning":"Patch comparison identifies diff candidates only; does not establish which change fixes CVE-2026-86886 or CVE-2026-84609.",
        "binaries":rows}
    Path(args.output).write_text(json.dumps(out,indent=2)+"\n")
    summary=["# Same Watch7,5 watchOS 26.6 vs watchOS 27 TCC/SoftwareUpdate patch differences","",
             "The two CVE classes are known to be fixed in watchOS27, but no specific changed symbol is attributed to a CVE without evidence.",""]
    for r in rows:
        summary += [f"## {r['binary']}",
            f"26 SHA256: \`{r['old_sha256']}\`",
            f"27 SHA256: \`{r['new_sha256']}\`",
            f"Changed relevant named methods: {r['method_changes_count']}; old/new symbols: {r['old_method_count']}/{r['new_method_count']}",""]
        for entry in r["changed_methods_ranked"][:24]:
            summary.append(f"- \`{entry['name']}\` — {entry['kind']}; bytes {entry['old_size']} → {entry['new_size']}")
        summary += ["","New or modified validation-related strings (selected):"]
        for msg in r["new_relevant_strings"][:15]:summary.append("- "+msg[:250])
        summary.append("")
    Path(args.output).with_suffix(".md").write_text("\n".join(summary)+"\n")
    print("\n".join(summary[:80]))
if __name__=="__main__":main()
