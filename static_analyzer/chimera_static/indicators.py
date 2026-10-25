"""Analyst observations independent of the scored findings subset."""


def build(result: dict) -> tuple[list[dict], dict]:
    items = []
    seen = set()

    def add(key, severity, category, title, detail="", evidence="", attack=()):
        # Repeated section/import observations remain distinct through their evidence.
        identity = (key, str(evidence))
        if identity in seen or severity not in (1, 2, 3):
            return
        seen.add(identity)
        items.append({"id": key, "severity": severity, "category": category, "title": title,
                      "detail": str(detail)[:1000], "evidence": str(evidence)[:300], "attack": list(attack)})

    for kind in ("pe", "elf"):
        block = result.get(kind, {})
        for a in block.get("anomalies", []):
            add(a["id"], a["severity"], a["category"], a["title"], a["detail"], a["evidence"], a["attack"])
        imports = block.get("imports_annotated", [])
        if kind == "pe":
            for lib in imports:
                if lib["severity"]:
                    add("library_" + lib["dll"], lib["severity"], "imports",
                        "Library: " + lib["dll"], lib["description"], lib["dll"])
            functions = [(lib["dll"], fn) for lib in imports for fn in lib["functions"]]
        else:
            functions = [(fn.get("lib") or "", fn) for fn in imports]
        # One indicator per import only for APIs that are suspicious in context (severity 2+). APIs merely
        # worth noting (severity 1: GetCurrentProcess, LoadLibrary...) are everywhere in benign software, so they
        # are summed up in one line instead of flooding the list, and carry no ATT&CK mapping of their own.
        noted = {}
        for lib, fn in functions:
            name = fn["name"] or str(fn.get("ordinal"))
            if fn["severity"] >= 2:
                add(kind + "_api_" + (fn["name"] or "ordinal"), fn["severity"], "imports",
                    "Import: " + name,
                    fn["description"] + (" " + fn["attacker_use"] if fn["attacker_use"] else ""),
                    lib + "!" + name, fn["attack"])
            elif fn["severity"] == 1:
                noted.setdefault(fn.get("category") or "misc", []).append(name)
        if noted:
            count = sum(len(names) for names in noted.values())
            add(kind + "_api_noted", 1, "imports", f"{count} imports worth noting",
                "Common in ordinary software too; listed with their purpose in the imports table.",
                "; ".join(f"{cat.replace('_', ' ')}: {', '.join(sorted(set(names))[:6])}"
                          for cat, names in sorted(noted.items())))
        if kind == "pe":
            for exp in block.get("exports_annotated", []):
                if exp["flagged"]:
                    add("pe_export_" + exp["name"], 1, "exports", "Export shares a Windows API name",
                        "May be an API-compatible wrapper or proxy library.", exp["name"])
            sec = block.get("headers", {}).get("optional", {}).get("dll_characteristics", [])
            if block and not block.get("is_driver"):
                for flag, title in (("aslr", "ASLR is not enabled"), ("dep", "DEP is not enabled"),
                                    ("cfg", "Control Flow Guard is not enabled")):
                    if flag not in sec:
                        add("pe_missing_" + flag, 1, "header", title)
    # An API name in the strings only says something when the file does not import it anyway (names resolved at
    # run time); the import table's own name strings are not indicators. One indicator per string category.
    imported = set()
    for lib in result.get("pe", {}).get("imports_annotated", []):
        imported.update(fn.get("name") or "" for fn in lib.get("functions", []))
    imported.update(fn.get("name", "").split("@", 1)[0]
                    for fn in result.get("elf", {}).get("imports_annotated", []))
    imported |= {name[:-1] for name in imported if name[-1:] in ("A", "W")}
    groups = {}
    for string in result.get("universal", {}).get("strings_flagged", []):
        value = string["value"]
        if string["category"].startswith("api_") and (value in imported or value[:-1] in imported):
            continue
        group = groups.setdefault(string["category"], {"severity": 0, "values": [], "attack": set()})
        group["severity"] = max(group["severity"], string["severity"])
        group["values"].append(f'{value} @{string["offset"]}')
        group["attack"].update(string.get("attack", []))
    for category, group in groups.items():
        count = len(group["values"])
        add("string_" + category, group["severity"], "strings",
            f'String: {category.replace("_", " ")} ({count})',
            "String content is an observation; it does not establish execution or intent.",
            "; ".join(group["values"][:6]), sorted(group["attack"]))
    t = result.get("type", {})
    for flag, title, sev in (("extension_mismatch", "File format differs from its extension", 2),
                             ("double_extension", "Executable has a double extension", 2),
                             ("rtlo_in_name", "Filename contains a right-to-left override", 3)):
        if t.get(flag):
            add("file_" + flag, sev, "file", title, evidence=result.get("file", {}).get("name", ""))
    items.sort(key=lambda item: (-item["severity"], item["category"], item["id"], item["evidence"]))
    items = items[:5000]
    summary = {"high": sum(i["severity"] == 3 for i in items),
               "medium": sum(i["severity"] == 2 for i in items),
               "low": sum(i["severity"] == 1 for i in items)}
    return items, summary
