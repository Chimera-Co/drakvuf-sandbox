#!/bin/bash
# usage (root): VMAWARE_DISABLE=<technique,...> [RUNS=5] [ARMS="A0 A0r H3"] baseline.sh
# Hardening baseline (goal G1), DRAKVUF attached throughout. Per arm: RUNS scans of PERDEDOR + al-khaser + Pafish,
# RUNS VMAware scans with the techniques in VMAWARE_DISABLE skipped, and one VMAware scan as released. VMAware runs
# alone, so a VMAware scan that ends early cannot lose the other tools' results.
#   A0   arm A0-scan (A0 + Defender exclusion for the checker folders), production plugins minus cpuidmon/hidsim, no -s
#   A0r  arm A0-scan, production plugins (cpuidmon -s, hidsim): the Stage 1 baseline's runtime hiding
#   H3   arm H3, production plugins
#   H3r  arm H3-rebuild (H3 rebuilt from the arm scripts on a fresh A0 copy, goal G1.4), production plugins
# VMAWARE_RELEASED=0 skips the one VMAware scan as released (it is known to end the guest).
# The production config.toml and arm H3 are restored on exit, whatever happens.
set -u
: "${VMAWARE_DISABLE:?comma-separated VMAware techniques to skip in the limited scans}"
S=$(cd "$(dirname "$0")" && pwd); CFG=/etc/drakrun/config.toml
export EV=${EV:-/var/lib/chimera-evidence/g1-$(date +%F)}
mkdir -p "$EV"; cp $CFG "$EV/config.toml.production"
# By name: a glob only matches loaded units, so it skipped a worker that had been stopped (G1.4)
restart() { systemctl restart drakrun-evasion-worker@1 drakrun-evasion-worker@2; sleep 10; }
restore() {
  # Stopping the workers ends a scan in flight; its domain is left behind and blocks the arm switch
  cp "$EV/config.toml.production" $CFG; systemctl stop 'drakrun-evasion-worker@*'
  xl destroy vm-1 2>/dev/null; chimera-arm use H3 >/dev/null
  systemctl start drakrun-evasion-worker@1 drakrun-evasion-worker@2; sleep 10
  echo "restored: config $(diff -q $CFG "$EV/config.toml.production" >/dev/null && echo identical), arm $(cat /var/lib/chimera-arms/CURRENT)" | tee -a "$EV/arms-config.txt"
}
trap restore EXIT
for arm in ${ARMS:-A0 A0r H3}; do
  cp "$EV/config.toml.production" $CFG
  case $arm in
    A0)  chimera-arm use A0-scan
         sed -i -e 's/, "cpuidmon", "hidsim"\]$/]/' -e '/^extra_drakvuf_args = { "-s" = true }$/d' $CFG
         grep -E '^(plugins|extra_drakvuf_args)' $CFG | grep -qE 'cpuidmon|hidsim|"-s"' \
           && { echo "A0 config still has the runtime hiding"; exit 1; } ;;
    A0r) chimera-arm use A0-scan ;;
    H3)  chimera-arm use H3 ;;
    H3r) chimera-arm use H3-rebuild ;;
    *)   echo "unknown arm $arm"; exit 1 ;;
  esac
  chimera-net-check --require-inetsim || exit 1
  { echo "== $arm $(date -Is) arm=$(cat /var/lib/chimera-arms/CURRENT)"; grep -E '^(plugins|extra_drakvuf_args)' $CFG; } | tee -a "$EV/arms-config.txt"
  restart
  TOOLS=perdedor,alkhaser,pafish "$S/scan.sh" "$arm" "${RUNS:-5}"
  TOOLS=vmaware TOOL_OPTIONS="{\"vmaware\":{\"disable\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1].split(",")))' "$VMAWARE_DISABLE")}}" \
    "$S/scan.sh" "$arm-vmaware-limited" "${RUNS:-5}"
  [[ ${VMAWARE_RELEASED:-1} == 0 ]] || TOOLS=vmaware "$S/scan.sh" "$arm-vmaware-released" 1
done
