#!/usr/bin/env python3
"""
CHIMERA M5 sample shortlist and download from MalwareBazaar (abuse.ch).

  shortlist  query MalwareBazaar *metadata* for families documented to check for
             VMs/sandboxes and pick the newest Windows EXE of each, plus control
             samples; writes shortlist.csv for the team to review. Nothing is
             downloaded. About 20 small queries: abuse.ch rate-limits heavy use
             and its terms forbid high-volume harvesting, so do not loop this.
  download   operator only, after the mentor's written sign-off and the team's
             review: fetch the reviewed shortlist as MalwareBazaar's
             password-protected ZIPs into a root-only directory and write the
             private register that m5_eval.py reads.

The API needs an abuse.ch Auth-Key. Put it in a root-only file (never in the
repository or on the command line):
  sudo install -D -m 600 /dev/null /etc/chimera/abusech-auth-key   # then paste the key into it

  sudo /opt/chimera/venv/bin/python scripts/chimera/bench/m5_samples.py shortlist \
      --out /var/lib/chimera-samples
  # review /var/lib/chimera-samples/shortlist.csv; delete rows to drop them
  sudo /opt/chimera/venv/bin/python scripts/chimera/bench/m5_samples.py download \
      --out /var/lib/chimera-samples --i-have-the-mentor-signoff
"""

import argparse
import csv
import datetime
import os
import pathlib
import sys

API = "https://mb-api.abuse.ch/api/v1/"
KEY_FILE = pathlib.Path("/etc/chimera/abusech-auth-key")
ZIP_PASSWORD = "infected"  # MalwareBazaar's published password for every sample ZIP
# MalwareBazaar's evasion tags are rare (2 recent EXEs tagged anti-vm, Oct 2026), so
# samples are chosen by family; the tags only rank samples within a family.
EVASION_TAGS = ["anti-vm", "anti-sandbox", "vm-detection", "evasive", "antivm", "anti-analysis", "vmprotect"]
# Families with publicly documented VM/sandbox checks (vendor and research write-ups);
# names as MalwareBazaar's "signature" field spells them.
VM_AWARE_FAMILIES = [
    "GuLoader", "Rhadamanthys", "AgentTesla", "Formbook", "SmokeLoader", "Vidar", "LummaStealer",
    "DarkGate", "PrivateLoader", "Amadey", "Stealc", "RedLineStealer", "Latrodectus", "PureLogsStealer",
    "QuasarRAT", "SnakeKeylogger", "ValleyRAT", "XLoader", "CryptBot", "Socks5Systemz", "Pikabot",
    "WarzoneRAT", "MassLogger", "BumbleBee", "MeduzaStealer",
]
# Families that spread by themselves over networks or infect other files.
# Containment is fail-closed, but they are not needed to answer the question.
EXCLUDED_FAMILIES = {
    "wannacry", "phorpiex", "conficker", "ramnit", "sality", "virut", "neshta", "mydoom",
    "expiro", "floxif", "emotet", "qakbot", "trickbot",
}
EXCLUDED_TAGS = {"worm", "wormable", "file-infector", "infector", "ransomware"}
# Common families used as controls; samples carrying an evasion tag are skipped.
# Team to confirm each has no reported environment checks (XWorm left out: it spreads over USB).
CONTROL_FAMILIES = ["AsyncRAT", "njrat", "RemcosRAT", "DCRat", "NanoCore"]
FIELDS = ["sha256", "role", "family", "tags", "file_name", "first_seen", "source_url"]


def auth_key():
    key = os.environ.get("MB_AUTH_KEY") or (KEY_FILE.read_text().strip() if KEY_FILE.exists() else "")
    if not key:
        raise SystemExit(f"no abuse.ch Auth-Key: create {KEY_FILE} (root, mode 600)")
    return key


def query(session, key, **data):
    resp = session.post(API, data=data, headers={"Auth-Key": key}, timeout=60)
    resp.raise_for_status()
    body = resp.json()
    status = body.get("query_status")
    if status in ("no_results", "tag_not_found", "signature_not_found"):
        return []
    if status != "ok":
        raise SystemExit(f"MalwareBazaar query {data.get('query')} failed: {status}")
    return body.get("data") or []


def _tags(entry):
    return {t.lower() for t in entry.get("tags") or []}


def eligible(entry, since):
    family = (entry.get("signature") or "").strip()
    return bool(
        family
        and family.lower() not in EXCLUDED_FAMILIES
        and not _tags(entry) & EXCLUDED_TAGS
        and entry.get("file_type") == "exe"
        and (entry.get("first_seen") or "")[:10] >= since
    )


def pick(entries, count, role, taken):
    """One sample per family: the one with the most evasion tags, then the newest."""
    best = {}

    def rank(e):
        return (len(_tags(e) & set(EVASION_TAGS)), e["first_seen"])

    for entry in entries:
        family = entry["signature"].strip().lower()  # MalwareBazaar spells some families two ways (Stealc/StealC)
        if family in taken:
            continue
        if family not in best or rank(entry) > rank(best[family]):
            best[family] = entry
    ranked = sorted(best.values(), key=lambda e: e["first_seen"], reverse=True)
    ranked.sort(key=lambda e: -len(_tags(e) & set(EVASION_TAGS)))  # stable: newest first within a tag count
    rows = []
    for entry in ranked[:count]:
        taken.add(entry["signature"].strip().lower())
        rows.append(
            {
                "sha256": entry["sha256_hash"],
                "role": role,
                "family": entry["signature"].strip(),
                "tags": " ".join(entry.get("tags") or []),
                "file_name": entry.get("file_name", ""),
                "first_seen": entry["first_seen"],
                "source_url": f"https://bazaar.abuse.ch/sample/{entry['sha256_hash']}/",
            }
        )
    return rows


def shortlist(fetch_family, count, controls, since):
    vm_aware = [e for family in VM_AWARE_FAMILIES for e in fetch_family(family) if eligible(e, since)]
    taken = set()
    rows = pick(vm_aware, count, "test", taken)
    control_entries = [
        e
        for family in CONTROL_FAMILIES
        for e in fetch_family(family)
        if eligible(e, since) and not _tags(e) & set(EVASION_TAGS)
    ]
    rows += pick(control_entries, controls, "control", taken)
    return rows


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def cmd_shortlist(args):
    import requests

    key, session = auth_key(), requests.Session()
    since = (datetime.date.today() - datetime.timedelta(days=args.since_days)).isoformat()
    rows = shortlist(
        lambda family: query(session, key, query="get_siginfo", signature=family, limit="100"),
        args.count,
        args.controls,
        since,
    )
    out = private_dir(pathlib.Path(args.out))
    with (out / "shortlist.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    tests = sum(r["role"] == "test" for r in rows)
    print(f"{tests} test + {len(rows) - tests} control samples -> {out / 'shortlist.csv'} (metadata only)")


def cmd_download(args):
    import requests

    if not args.i_have_the_mentor_signoff:
        raise SystemExit("download needs --i-have-the-mentor-signoff (protocol precondition)")
    key, session = auth_key(), requests.Session()
    out = private_dir(pathlib.Path(args.out))
    zips = private_dir(out / "zips")
    with (out / "shortlist.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    register = []
    for row in rows:
        path = zips / f"{row['sha256']}.zip"
        if not path.exists():
            resp = session.post(
                API, data={"query": "get_file", "sha256_hash": row["sha256"]}, headers={"Auth-Key": key}, timeout=120
            )
            resp.raise_for_status()
            if resp.content[:2] != b"PK":
                raise SystemExit(f"{row['sha256']}: not a ZIP ({resp.content[:120]!r})")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(resp.content)
            print(f"saved {row['family']} {row['sha256'][:12]}", flush=True)
        register.append(
            {
                "sha256": row["sha256"],
                "path": str(path),
                "role": row["role"],
                "family": row["family"],
                "tags": row["tags"],
                "archive_password": ZIP_PASSWORD,
                "entry": "",
                "source_url": row["source_url"],
                "retrieved": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        )
    with (out / "register.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(register[0].keys()))
        writer.writeheader()
        writer.writerows(register)
    print(f"{len(register)} samples registered in {out / 'register.csv'}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("shortlist")
    p.add_argument("--out", default="/var/lib/chimera-samples")
    p.add_argument("--count", type=int, default=len(VM_AWARE_FAMILIES))
    p.add_argument("--controls", type=int, default=5)
    p.add_argument("--since-days", type=int, default=180)
    p.set_defaults(func=cmd_shortlist)
    p = sub.add_parser("download")
    p.add_argument("--out", default="/var/lib/chimera-samples")
    p.add_argument("--i-have-the-mentor-signoff", action="store_true")
    p.set_defaults(func=cmd_download)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
