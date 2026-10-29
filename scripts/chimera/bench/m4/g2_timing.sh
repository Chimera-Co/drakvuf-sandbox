#!/bin/bash
# usage (root): [REPEATS=3] g2_timing.sh
# CPUID round-trip timing (goal G2): REPEATS runs of 100,000 iterations of scripts/chimera/bench/cpuid-timing per
# configuration. The analysis guests are pinned to pCPUs 16-19 (E-cores) by the arms' install.json, so the guest
# configurations run on E-cores; dom0 is measured with its vCPU 0 moved to pCPU 16 (E-core) and on its own pCPU 0
# (P-core), to show the core-type difference. Bare metal (Debian without Xen) is a separate manual step:
#   CPUID_TIMING_CPU=<E-core> cpuid_timing 100000 bare-ecore-1.json bare-ecore-1.csv
#   dom0-pcore, dom0-ecore          the harness in dom0
#   A0-nodrakvuf                    arm A0-scan, evasion scan without DRAKVUF
#   H3-nodrakvuf                    arm H3, without DRAKVUF
#   H3-drakvuf-nocpuidmon           arm H3, DRAKVUF with the production plugins minus cpuidmon (and its -s)
#   H3-drakvuf-cpuidmon             arm H3, production (cpuidmon -s)
# Raw JSON and CSV per run land in $EV/raw/<config>-<n>.{json,csv}, one line per run in $EV/log.txt. The production
# config.toml, arm H3 and dom0's vCPU 0 pinning are restored on exit, whatever happens.
set -u
CFG=/etc/drakrun/config.toml; API=http://127.0.0.1:5000/api/evasion
HARNESS=${HARNESS:-/var/tmp/chimera-tools/cpuid-timing/cpuid_timing}; REPEATS=${REPEATS:-3}
export EV=${EV:-/var/lib/chimera-evidence/g2-$(date +%F)}
mkdir -p "$EV/raw"; cp $CFG "$EV/config.toml.production"
log() { echo "$(date -Is) $*" | tee -a "$EV/log.txt"; }
restart() { systemctl restart 'drakrun-evasion-worker@*'; sleep 10; }
restore() {
  # Stopping the workers ends a scan in flight; its domain is left behind and blocks the arm switch
  cp "$EV/config.toml.production" $CFG; systemctl stop 'drakrun-evasion-worker@*'
  xl destroy vm-1 2>/dev/null; chimera-arm use H3 >/dev/null; xl vcpu-pin Domain-0 0 0
  systemctl start drakrun-evasion-worker@1 drakrun-evasion-worker@2; sleep 10
  log "restored: config $(diff -q $CFG "$EV/config.toml.production" >/dev/null && echo identical)," \
      "arm $(cat /var/lib/chimera-arms/CURRENT), dom0 vCPU0 on pCPU $(xl vcpu-list Domain-0 | awk 'NR>1 && $3==0 {print $4}')"
}
trap restore EXIT
detected() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["alkhaser_style_detected"])' "$1"; }

dom0() {  # <label> <pcpu>
  xl vcpu-pin Domain-0 0 "$2"; sleep 2
  for n in $(seq 1 "$REPEATS"); do
    CPUID_TIMING_CPU=0 "$HARNESS" 100000 "$EV/raw/$1-$n.json" "$EV/raw/$1-$n.csv" >/dev/null
    log "$1 run$n pcpu=$(xl vcpu-list Domain-0 | awk 'NR>1 && $3==0 {print $4}') detected=$(detected "$EV/raw/$1-$n.json")"
  done
  xl vcpu-pin Domain-0 0 0
}

guest() {  # <label> <with_drakvuf: true|false>
  for n in $(seq 1 "$REPEATS"); do
    id=$(curl -s -X POST $API/scans -H 'Content-Type: application/json' \
      -d '{"sandbox_id":"default","tools":["cpuid-timing"],"profile":"full","tool_options":{},"with_drakvuf":'"$2"'}' \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])')
    start=$(date +%s); status=
    while :; do
      status=$(curl -s $API/scans/$id/status | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))')
      [[ "$status" == finished || "$status" == failed ]] && break
      (( $(date +%s) - start > 2400 )) && { status=WATCH-TIMEOUT; break; }
      sleep 10
    done
    raw=/var/lib/drakrun/evasion/$id/raw/cpuid-timing
    cp "$raw/cpuid-timing.json" "$EV/raw/$1-$n.json" 2>/dev/null; cp "$raw/cpuid-timing.csv" "$EV/raw/$1-$n.csv" 2>/dev/null
    tool=$(python3 -c 'import json,sys
e = json.load(open(sys.argv[1])); t = e["tool_results"]; t = t if isinstance(t, list) else list(t.values())
print("attached=%s tool=%s" % (e.get("drakvuf_attached"), t[0].get("status")), t[0].get("error") or "")' \
      /var/lib/drakrun/evasion/$id/evasion.json 2>/dev/null)
    log "$1 run$n scan=$id status=$status secs=$(( $(date +%s) - start )) $tool" \
        "detected=$( [[ -f "$EV/raw/$1-$n.json" ]] && detected "$EV/raw/$1-$n.json" || echo none)"
  done
}

chimera-net-check --require-inetsim || exit 1
log "harness $(sha256sum "$HARNESS" | cut -c1-16) guest $(sha256sum /var/tmp/chimera-tools/cpuid-timing/cpuid_timing.exe | cut -c1-16)"
dom0 dom0-pcore 0
dom0 dom0-ecore 16

chimera-arm use A0-scan; restart
guest A0-nodrakvuf false

chimera-arm use H3; restart
guest H3-nodrakvuf false

sed -i -e 's/"cpuidmon", //' -e '/^extra_drakvuf_args = { "-s" = true }$/d' $CFG
grep -E '^(plugins|extra_drakvuf_args)' $CFG | grep -qE 'cpuidmon|"-s"' && { log "config still has cpuidmon"; exit 1; }
grep -E '^plugins' $CFG | grep -q hidsim || { log "config lost hidsim"; exit 1; }
log "H3-drakvuf-nocpuidmon config: $(grep -E '^(plugins|extra_drakvuf_args)' $CFG | tr '\n' ' ')"
restart
guest H3-drakvuf-nocpuidmon true

cp "$EV/config.toml.production" $CFG
log "H3-drakvuf-cpuidmon config: $(grep -E '^(plugins|extra_drakvuf_args)' $CFG | tr '\n' ' ')"
restart
guest H3-drakvuf-cpuidmon true
