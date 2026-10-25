#!/bin/bash
# Daily offline-intel refresh on the CHIMERA host (the host has internet; guests never do): build a bundle from
# scripts/chimera/intel/feeds.toml, import it, keep two weeks of bundles. Run by chimera-intel-update.timer.
set -euo pipefail
OUT=/var/lib/chimera-intel/bundles
SRC=${CHIMERA_SRC:-/opt/chimera/src}
VENV=${CHIMERA_VENV:-/opt/chimera/venv}
install -d -m 700 "$OUT"
previous=$(ls -t "$OUT"/chimera-intel-*.tar.gz 2>/dev/null | head -1 || true)
# A feed that fails keeps its previous data (and expiry); the builder exits non-zero only if every feed failed.
"$VENV/bin/python" "$SRC/scripts/chimera/intel/build_bundle.py" \
    --feeds "$SRC/scripts/chimera/intel/feeds.toml" \
    --output "$OUT" \
    --abusech-key-file /etc/chimera/abusech-auth-key \
    ${previous:+--previous "$previous"}
latest=$(ls -t "$OUT"/chimera-intel-*.tar.gz | head -1)
"$VENV/bin/drakrun" intel import "$latest"
find "$OUT" -name 'chimera-intel-*.tar.gz*' -mtime +14 -delete
