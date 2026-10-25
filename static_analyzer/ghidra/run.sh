#!/bin/sh
# Entry point of the decompiler container:
#   run.sh /in/sample /work /out <analysis_timeout_s> <heap e.g. 1536M> [max_functions] [decompile_budget_s]
# /work (rw, noexec) holds the throwaway Ghidra project, the JVM's home and temp files and targets.json
# (addresses from capa); /out/ghidra.json is the result. Exit 0 = Ghidra ran (see the JSON for per-function
# errors); anything else = it did not, and the caller records stderr.
set -eu
sample=$1 work=$2 out=$3 timeout=${4:-180} heap=${5:-1536M} max=${6:-40} budget=${7:-120}
mkdir -p "$work/tmp" "$work/project"
[ -f "$work/targets.json" ] || echo '{"addresses": []}' > "$work/targets.json"
export HOME="$work"
# Java takes user.home from the user database (nobody: /nonexistent), not $HOME; Ghidra's launcher saves its JDK
# choice there. JAVA_TOOL_OPTIONS reaches every java the launcher starts.
export JAVA_TOOL_OPTIONS="-Duser.home=$work"
exec /opt/ghidra/support/launch.sh fg jdk Ghidra-Headless "$heap" \
    "-Djava.io.tmpdir=$work/tmp -Duser.home=$work -Djava.awt.headless=true" \
    ghidra.app.util.headless.AnalyzeHeadless \
    "$work/project" chimera -import "$sample" -overwrite -deleteProject \
    -analysisTimeoutPerFile "$timeout" -max-cpu 2 \
    -scriptPath /opt/chimera-ghidra \
    -postScript chimera_decompile.py "$work/targets.json" "$out/ghidra.json" "$max" "$budget"
