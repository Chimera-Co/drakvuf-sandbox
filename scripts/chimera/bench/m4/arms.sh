#!/bin/bash
# usage: RUNS=5 arms.sh <arm>...   arms: H1 (config.toml as it is), H1S (+cpuidmon -s), H1SH (+cpuidmon -s +hidsim, mouse moves only)
S=$(dirname "$0"); CFG=/etc/drakrun/config.toml; EV=${EV:-/var/lib/chimera-evidence/m4-2026-10-19}
sudo -n cp $CFG $CFG.bak.m4
restore() { sudo -n cp $CFG.bak.m4 $CFG; sudo -n systemctl restart drakrun-evasion-worker@1
  echo "config restored: $(sudo -n diff -q $CFG $CFG.bak.m4 >/dev/null && echo identical)"; }
trap restore EXIT
for arm in "$@"; do
  sudo -n cp $CFG.bak.m4 $CFG
  case $arm in
    H1) ;;
    H1S)  sudo -n sed -i 's/^plugins = \[\(.*\)\]$/plugins = [\1, "cpuidmon"]/' $CFG
          sudo -n sed -i '/^\[drakrun\]/a extra_drakvuf_args = { "-s" = true }' $CFG ;;
    H1SH) sudo -n sed -i 's/^plugins = \[\(.*\)\]$/plugins = [\1, "cpuidmon", "hidsim"]/' $CFG
          sudo -n sed -i '/^\[drakrun\]/a extra_drakvuf_args = { "-s" = true }' $CFG ;;
    *) echo "unknown arm $arm"; exit 1 ;;
  esac
  { echo "== arm $arm $(date -Is)"; sudo -n grep -E '^(plugins|extra_drakvuf_args)' $CFG; } | sudo -n tee -a $EV/arms-config.txt
  sudo -n systemctl restart drakrun-evasion-worker@1; sleep 10
  $S/scan.sh $arm ${RUNS:-5}
done
