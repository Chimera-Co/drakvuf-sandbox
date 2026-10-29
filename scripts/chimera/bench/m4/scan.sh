#!/bin/bash
# usage: [TOOLS=perdedor,alkhaser,pafish,vmaware] [TOOL_OPTIONS='{"vmaware":{...}}'] scan.sh <label> <runs>  (FIRST=<n> starts the numbering at run n, to resume)
# DRAKVUF-attached scans (default PERDEDOR + al-khaser; TOOL_OPTIONS makes it a custom-profile scan); one summary
# line + per-check JSONL per run.
API=http://127.0.0.1:5000/api/evasion
EV=${EV:-/var/lib/chimera-evidence/m4-2026-10-19}; sudo -n mkdir -p $EV
TOOL_OPTIONS=${TOOL_OPTIONS:-}; PROFILE=custom; [[ -z "$TOOL_OPTIONS" ]] && { TOOL_OPTIONS='{}'; PROFILE=full; }
TOOLS_JSON=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1].split(",")))' "${TOOLS:-perdedor,alkhaser}")
for n in $(seq ${FIRST:-1} $2); do
  ID=$(curl -s -X POST $API/scans -H 'Content-Type: application/json' \
    -d '{"sandbox_id":"default","tools":'"$TOOLS_JSON"',"profile":"'"$PROFILE"'","tool_options":'"$TOOL_OPTIONS"',"with_drakvuf":true}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])')
  start=$(date +%s); outcome=ok
  while true; do
    S=$(curl -s $API/scans/$ID/status | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))')
    [[ "$S" == finished || "$S" == failed ]] && break
    (( $(date +%s)-start > 3000 )) && { outcome=WATCH-TIMEOUT; break; }
    sleep 10
  done
  secs=$(( $(date +%s)-start ))
  sudo -n python3 -I - "$1" "$n" "$ID" "$secs" "$outcome" "$EV" <<'PY'
import json, sys
from collections import Counter
label, n, sid, secs, outcome, ev = sys.argv[1:]
e = json.load(open(f"/var/lib/drakrun/evasion/{sid}/evasion.json"))
tr = e["tool_results"]; tl = tr if isinstance(tr, list) else list(tr.values())
md = e.get("metadata") or {}
att = e.get("drakvuf_attached", md.get("drakvuf_attached")); err = e.get("drakvuf_error", md.get("drakvuf_error"))
summ = " ".join(f"{t['tool']}:{t.get('status')}:{dict(Counter(c['status'] for c in t.get('checks', [])))}" for t in tl)
line = f"{label} run{n} id={sid} secs={secs} {outcome} status={e.get('status')} attached={att} err={err} score={(e.get('score') or {}).get('chimera_score')} | {summ}"
print(line)
open(f"{ev}/summary.txt", "a").write(line + "\n")
with open(f"{ev}/checks.jsonl", "a") as f:
    for t in tl:
        for c in t.get("checks", []):
            f.write(json.dumps({"arm": label, "run": int(n), "scan": sid, "tool": t["tool"], "id": c.get("id") or c.get("check_id") or c.get("name"),
                                "status": c["status"], "attached": att, "measured": c.get("measured_value")}) + "\n")
PY
done
