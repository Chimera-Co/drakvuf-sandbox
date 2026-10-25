#!/usr/bin/env python3
"""Build src/data/attack.json: MITRE ATT&CK technique names and tactics for the report's ATT&CK matrix.

Source: the "Tactic::Technique::Sub-technique [Txxxx.yyy]" entries of the capa rules shipped in this repository
(drakrun/data/capa-rules, static_analyzer/capa-rules), plus a short table for techniques CHIMERA's own findings
emit that no capa rule names. No network access; run again after updating the capa rules:

    python3 tools/gen_attack.py          # write src/data/attack.json
    python3 tools/gen_attack.py --check  # fail if the file is out of date
"""

import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
OUT = HERE.parent / "src" / "data" / "attack.json"
RULE_DIRS = [REPO / "drakrun" / "data" / "capa-rules", REPO / "static_analyzer" / "capa-rules"]

# Enterprise tactics in kill-chain order.
TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# ATT&CK Enterprise names and tactics for ids used by CHIMERA findings (static_analyzer, drakrun) that the capa
# rules do not mention. Parent techniques are listed so sub-techniques can show "Technique: Sub-technique".
EXTRA = {
    "T1003": ("OS Credential Dumping", ["Credential Access"]),
    "T1003.001": ("LSASS Memory", ["Credential Access"]),
    "T1005": ("Data from Local System", ["Collection"]),
    "T1014": ("Rootkit", ["Defense Evasion"]),
    "T1018": ("Remote System Discovery", ["Discovery"]),
    "T1027.006": ("HTML Smuggling", ["Defense Evasion"]),
    "T1027.009": ("Embedded Payloads", ["Defense Evasion"]),
    "T1027.013": ("Encrypted/Encoded File", ["Defense Evasion"]),
    "T1036": ("Masquerading", ["Defense Evasion"]),
    "T1036.002": ("Right-to-Left Override", ["Defense Evasion"]),
    "T1036.005": ("Match Legitimate Name or Location", ["Defense Evasion"]),
    "T1036.007": ("Double File Extension", ["Defense Evasion"]),
    "T1036.008": ("Masquerade File Type", ["Defense Evasion"]),
    "T1041": ("Exfiltration Over C2 Channel", ["Exfiltration"]),
    "T1053": ("Scheduled Task/Job", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.003": ("Cron", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1059.005": ("Visual Basic", ["Execution"]),
    "T1059.007": ("JavaScript", ["Execution"]),
    "T1090": ("Proxy", ["Command and Control"]),
    "T1090.003": ("Multi-hop Proxy", ["Command and Control"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1098.004": ("SSH Authorized Keys", ["Persistence", "Privilege Escalation"]),
    "T1203": ("Exploitation for Client Execution", ["Execution"]),
    "T1204": ("User Execution", ["Execution"]),
    "T1204.002": ("Malicious File", ["Execution"]),
    "T1218": ("System Binary Proxy Execution", ["Defense Evasion"]),
    "T1221": ("Template Injection", ["Defense Evasion"]),
    "T1222": ("File and Directory Permissions Modification", ["Defense Evasion"]),
    "T1222.002": ("Linux and Mac File and Directory Permissions Modification", ["Defense Evasion"]),
    "T1486": ("Data Encrypted for Impact", ["Impact"]),
    "T1543": ("Create or Modify System Process", ["Persistence", "Privilege Escalation"]),
    "T1543.002": ("Systemd Service", ["Persistence", "Privilege Escalation"]),
    "T1547": ("Boot or Logon Autostart Execution", ["Persistence", "Privilege Escalation"]),
    "T1547.006": ("Kernel Modules and Extensions", ["Persistence", "Privilege Escalation"]),
    "T1548": ("Abuse Elevation Control Mechanism", ["Privilege Escalation", "Defense Evasion"]),
    "T1548.001": ("Setuid and Setgid", ["Privilege Escalation", "Defense Evasion"]),
    "T1553": ("Subvert Trust Controls", ["Defense Evasion"]),
    "T1553.002": ("Code Signing", ["Defense Evasion"]),
    "T1566": ("Phishing", ["Initial Access"]),
    "T1566.001": ("Spearphishing Attachment", ["Initial Access"]),
    "T1571": ("Non-Standard Port", ["Command and Control"]),
    "T1574": ("Hijack Execution Flow", ["Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1574.006": ("Dynamic Linker Hijacking", ["Persistence", "Privilege Escalation", "Defense Evasion"]),
}

ENTRY = re.compile(r"([A-Za-z][A-Za-z &\-]+?)::([^\[\n\"']+?)\s*\[(T\d{4}(?:\.\d{3})?)\]")


def build() -> dict:
    techniques: dict = {}

    def add(tid, name, tactic, parent_name=None):
        if tactic not in TACTICS:  # e.g. "Mobile::..." entries
            return
        entry = techniques.setdefault(tid, {"name": name, "tactics": []})
        if tactic not in entry["tactics"]:
            entry["tactics"].append(tactic)
        if "." in tid:
            entry["parent"] = tid.split(".")[0]
            if parent_name:
                add(entry["parent"], parent_name, tactic)

    for rule_dir in RULE_DIRS:
        for path in sorted(rule_dir.rglob("*.yml")):
            for match in ENTRY.finditer(path.read_text(errors="ignore")):
                tactic, names, tid = match.group(1).strip(), match.group(2).strip(), match.group(3)
                parts = [p.strip() for p in names.split("::")]
                if "." in tid and len(parts) >= 2:
                    add(tid, parts[-1], tactic, parts[0])
                else:
                    add(tid, parts[0], tactic)
    for tid, (name, tactics) in EXTRA.items():
        for tactic in tactics:
            add(tid, name, tactic)
    for entry in techniques.values():
        entry["tactics"].sort(key=TACTICS.index)
    return {
        "source": "capa rules in this repository plus CHIMERA finding ids (ATT&CK Enterprise)",
        "tactics": TACTICS,
        "techniques": dict(sorted(techniques.items())),
    }


def main() -> int:
    text = json.dumps(build(), indent=1, sort_keys=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT} is out of date: run tools/gen_attack.py", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    data = json.loads(text)
    print(f"wrote {OUT} ({len(data['techniques'])} techniques)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
