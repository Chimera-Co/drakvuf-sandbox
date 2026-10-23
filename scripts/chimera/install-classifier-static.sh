#!/usr/bin/env bash
# Install the CHIMERA classifier (dynamic + static models) and the static-analysis worker on the
# CHIMERA host. Run from the checkout you deploy (e.g. /opt/chimera/src) after pulling this branch:
#
#   sudo scripts/chimera/install-classifier-static.sh            # classifier, image, worker, config
#   sudo scripts/chimera/install-classifier-static.sh --drakrun  # also rebuild + reinstall drakrun itself
#
# Idempotent. Backs up what it replaces (classifier folder, config.toml). Never overwrites settings
# that are already in config.toml; it only adds missing [classifier] / [static] sections.
set -euo pipefail

VENV=/opt/chimera/venv
CLASSIFIER_DIR=/etc/drakrun/classifier
CONFIG=/etc/drakrun/config.toml
IMAGE=localhost/chimera-static:0.1.0
ENGINE=podman
DRAKRUN=0
RESTART=0
CHECK=1
usage() {
  sed -n '2,10p' "$0"
  echo "options: --venv DIR  --classifier-dir DIR  --config FILE  --engine podman|docker  --drakrun  --restart  --no-check"
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --venv) VENV="$2"; shift 2 ;;
    --classifier-dir) CLASSIFIER_DIR="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --engine) ENGINE="$2"; shift 2 ;;
    --drakrun) DRAKRUN=1; shift ;;
    --restart) RESTART=1; shift ;;
    --no-check) CHECK=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option $1"; usage; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Test hook only: CHIMERA_INSTALL_ROOT=<dir> puts systemd/static paths under <dir>, skips the root
# check and replaces systemctl with a no-op, so the whole script can run on a development machine.
PREFIX="${CHIMERA_INSTALL_ROOT:-}"
SYSTEMCTL="systemctl"
[[ -n "$PREFIX" ]] && SYSTEMCTL="true"
SYSTEMD_DIR="$PREFIX/etc/systemd/system"
STATIC_DIR="$PREFIX/var/lib/drakrun/static"
STAMP="$(date +%Y%m%d-%H%M%S)"
say() { printf '\n==> %s\n' "$*"; }
[[ $EUID -eq 0 || -n "$PREFIX" ]] || { echo "run as root (sudo)"; exit 1; }
[[ -x "$VENV/bin/python" ]] || { echo "no Python venv at $VENV (use --venv)"; exit 1; }
cd "$REPO"
echo "repo $REPO @ $(git rev-parse --short HEAD 2>/dev/null || echo '?') ($(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?'))"

if [[ $DRAKRUN -eq 1 ]]; then
  say "Rebuilding drakrun from this checkout (make) and installing it into $VENV"
  make
  "$VENV/bin/pip" install --no-deps --force-reinstall dist/*.whl
fi

say "Checking the model's Python packages in $VENV"
if ! "$VENV/bin/python" -c "import lightgbm, numpy" 2>/dev/null; then
  echo "installing lightgbm==4.7.0 numpy==2.4.6 (the versions the models were trained with)"
  "$VENV/bin/pip" install "lightgbm==4.7.0" "numpy==2.4.6"
fi
"$VENV/bin/python" - <<'EOF'
import lightgbm, numpy, sys
want = {"lightgbm": "4.7.0", "numpy": "2.4.6"}
have = {"lightgbm": lightgbm.__version__, "numpy": numpy.__version__}
print(f"python {sys.version.split()[0]}, " + ", ".join(f"{k} {v}" for k, v in have.items()))
for k, v in want.items():
    if have[k] != v:
        print(f"WARNING: {k} {have[k]} differs from the training version {v}")
EOF
"$VENV/bin/python" -c "import drakrun.analyzer.static.worker" 2>/dev/null || {
  echo "WARNING: the drakrun installed in $VENV has no static-analysis code yet: rerun with --drakrun"
}

say "Installing the classifier into $CLASSIFIER_DIR"
if [[ -d "$CLASSIFIER_DIR" ]]; then
  cp -a "$CLASSIFIER_DIR" "$CLASSIFIER_DIR.bak-$STAMP"
  echo "previous version kept in $CLASSIFIER_DIR.bak-$STAMP"
fi
install -d -m 755 "$CLASSIFIER_DIR"
find "$CLASSIFIER_DIR" -maxdepth 1 -type f -delete
install -m 644 classifier/deploy/* "$CLASSIFIER_DIR"/
(cd "$CLASSIFIER_DIR" && "$VENV/bin/python" -I -c "
import json, sys; sys.path.insert(0, '.')
import model
v = model.classify(json.load(open('$REPO/classifier/fixtures/bginfo-96f7ee81-features.json')), '.')
print('model check:', v['label'], v['score'], v['model'], v['model_version'])")

say "Building the static-analysis image $IMAGE with $ENGINE"
command -v "$ENGINE" >/dev/null || { echo "$ENGINE not installed: apt install $ENGINE"; exit 1; }
# Host network for the build: a bridge network makes netavark/docker insert FORWARD rules ahead of
# CHIMERA_GUARD, and chimera-net-check then refuses to start the analysis workers. The analyzer
# containers themselves always run with --network none, which adds no rules.
"$ENGINE" build --network host -t "$IMAGE" -f static_analyzer/Containerfile static_analyzer
install -d -m 711 "$STATIC_DIR"
if [[ "$ENGINE" == "podman" ]]; then
  # Containers default to no network, so nothing started by hand opens a bridge either
  install -d "$PREFIX/etc/containers"
  [[ -e "$PREFIX/etc/containers/containers.conf" ]] || printf '[containers]\nnetns = "none"\n' \
    > "$PREFIX/etc/containers/containers.conf"
fi
if [[ -z "$PREFIX" ]] && command -v chimera-net-check >/dev/null; then
  chimera-net-check || { echo "containment check failed after the image build: fix the firewall before restarting workers"; exit 1; }
fi

say "Installing the static worker service"
install -d "$SYSTEMD_DIR"
install -m 644 scripts/chimera/systemd/drakrun-static-worker.service "$SYSTEMD_DIR"/
$SYSTEMCTL daemon-reload
$SYSTEMCTL enable drakrun-static-worker.service

say "Checking $CONFIG"
cp -a "$CONFIG" "$CONFIG.bak-$STAMP"
"$VENV/bin/python" - "$CONFIG" "$CLASSIFIER_DIR" "$ENGINE" "$IMAGE" <<'EOF'
import sys, tomllib
path, clf_dir, engine, image = sys.argv[1:]
text = open(path, encoding="utf-8").read()
cfg = tomllib.loads(text)
add = []
if "classifier" not in cfg:
    add.append(f'\n[classifier]\nenabled = true\nmodel_path = "{clf_dir}/model.py"\ntimeout_s = 60\n')
else:
    c = cfg["classifier"]
    if not c.get("enabled"):
        print("NOTE: [classifier] enabled is not true: set it to use the model")
    if c.get("model_path") != f"{clf_dir}/model.py":
        # Without model_path the runner falls back to the labelled stub, not the deployed model
        print(f"WARNING: [classifier] model_path is {c.get('model_path')!r}: analyses use the stub model "
              f"until it is set to {clf_dir}/model.py")
if "static" not in cfg:
    add.append(f'\n[static]\nenabled = true\nengine = "{engine}"\nimage = "{image}"\ntimeout_s = 90\nwait_s = 120\n')
elif not cfg["static"].get("enabled"):
    print("NOTE: [static] enabled is not true: set it to run static analysis")
if add:
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n# added by install-classifier-static.sh" + "".join(add))
    print("added:", ", ".join(s.split("]")[0].strip()[1:] for s in add))
tomllib.loads(open(path, encoding="utf-8").read())  # still valid
print("config OK (backup next to it)")
EOF

if [[ $RESTART -eq 1 ]]; then
  say "Restarting CHIMERA services (make sure no analysis is running)"
  $SYSTEMCTL restart drakrun-static-worker.service
  $SYSTEMCTL restart drakrun-web.service || true
  for unit in $(systemctl list-units --plain --no-legend 'drakrun-worker@*' 2>/dev/null | awk '{print $1}'); do $SYSTEMCTL restart "$unit"; done
else
  say "Not restarting services. When no analysis is running:"
  echo "  sudo systemctl restart drakrun-static-worker drakrun-web 'drakrun-worker@*'"
fi

if [[ $CHECK -eq 1 ]]; then
  say "End-to-end check"
  "$VENV/bin/python" scripts/chimera/e2e_classifier_static.py --engine "$ENGINE" --image "$IMAGE" \
    --model "$CLASSIFIER_DIR/model.py"
fi
