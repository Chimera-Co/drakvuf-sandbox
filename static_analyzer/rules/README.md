# YARA rules baked into the static image

Each folder is one ruleset, copied **unmodified** from its source and pinned in its `SOURCE.json`
(source URL, commit, archive SHA-256, licence, SHA-256 of every rule file). The image build compiles
everything here into `/opt/chimera-static/rules.yarc` (`chimera_static.rules_build`) and **fails** on zero
rules or a compile error. `static.json` reports the rule count and pins under `universal.yara_ruleset`.

| Folder | Source | Commit | Licence | Rules |
|---|---|---|---|---|
| `reversinglabs/` | https://github.com/reversinglabs/reversinglabs-yara-rules | `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84` (3 Nov 2025) | MIT, `reversinglabs/LICENSE` | 1240 (931 certificate, 308 malware, 1 exploit) |

Severity in findings: ReversingLabs `MALWARE`/`EXPLOIT` rules with `tc_detection_factor` ≥ 4 → high,
other malware rules → medium, `INFO` certificate rules (signer seen on malware, leaked certificate) → medium.
A YARA match is evidence in the static score; it never sets a malware family on its own.

To add a ruleset: new folder with the unmodified files, its licence and a `SOURCE.json` in the same
shape; check redistribution terms first (`docs/chimera/plan/static-engine-design.md` §2.2).
