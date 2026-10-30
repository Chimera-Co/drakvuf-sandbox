---
title: 3. CHIMERA console
group: Build from scratch
---
# Build step 3: the CHIMERA package and console

The `drakrun` Python package contains the CLI, the workers, the web API and, built into it, this console.

## System packages

```bash
apt install iptables tcpdump dnsmasq qemu-utils bridge-utils libmagic1 python3-venv redis-server conntrack \
            podman nodejs npm
systemctl enable --now redis-server
```

`podman` runs the static analyzers; `nodejs` and `npm` are only needed to build the console.

## Checkout and build

Deploy from a root-owned checkout, so nothing an ordinary user can change is executed as root:

```bash
git clone --recurse-submodules <repository URL> /opt/chimera/src
cd /opt/chimera/src
make                      # builds the console (npm ci, vite build), drakshell and get-explorer-pid, then the wheel
```

The `Makefile` rebuilds the console whenever a file under `drakrun/web/frontend/src` changes, including these
documentation pages.

## Python environment

```bash
python3 -m venv /opt/chimera/venv
/opt/chimera/venv/bin/pip install wheel
/opt/chimera/venv/bin/pip install dist/*.whl
/opt/chimera/venv/bin/drakrun --help
```

To redeploy after a pull: `make` again, then
`/opt/chimera/venv/bin/pip install --no-deps --force-reinstall dist/*.whl`, then restart the services.

## Configuration

`drakrun install` (next steps) writes `/etc/drakrun/config.toml` from `drakrun/data/config.toml`. The sections
and every default are defined in `drakrun/lib/config.py`. The essentials:

```toml
[redis]
host = "localhost"
port = 6379

[network]
dns_server = "10.99.0.2"       # INetSim, see step 4
out_interface = "inetsim0"
net_enable = true

[drakrun]
default_timeout = 300          # seconds of detonation unless the upload sets a timeout
plugins = ["apimon", "clipboardmon", "exmon", "filetracer", "memdump", "procmon", "regmon",
           "socketmon", "tlsmon"]

[worker]
# vm_guest_os = {1 = "windows", 2 = "linux"}   # no binding: every worker serves both
memory_admission_timeout = 1800
memory_admission_margin_mb = 192
```

Optional features stay off until their section is enabled: `[static]`, `[classifier]`, `[intel]`, `[evasion]`
(see [workers and services](build-services.md)). Presets (`[preset.<name>]`) bundle plugin lists and timeouts
that an upload can select.

## Web service

```bash
install -m 644 scripts/chimera/systemd/drakrun-web.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now drakrun-web
```

The unit runs gunicorn bound to **127.0.0.1:5000**. The API has no login of its own, so keep it on loopback and
reach it through an SSH tunnel:

```bash
ssh -L 5000:127.0.0.1:5000 <user>@<chimera-host>    # then open http://localhost:5000
```

## Developing the console

```bash
cd drakrun/web/frontend
npm ci
PROXY_BACKEND_URL=http://127.0.0.1:5000 npm run dev     # Vite on port 3000, API proxied
npm test                                                # vitest
npm run build                                           # production bundle into dist/
```

Documentation pages are Markdown files in `src/docs/content/`. The file name `NN-slug.md` sets the order and the
URL (`/docs/slug`); the front matter sets the sidebar title and group. Links to other pages are written as
`slug.md`; diagrams are `diagram pipeline`, `diagram architecture` and `diagram containment` code fences.

Next: [network containment](build-network.md).
