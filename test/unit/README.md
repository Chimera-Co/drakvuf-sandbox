# `test/unit/` — Sandbox Evasion unit tests

This tree covers the Phase 1 Sandbox Evasion subsystem (config/registry
parsing, verifier adapters against fixture bytes, scoring, report
generation, API layer) and is independent of the legacy `test/` suite.

`test/conftest.py` targets a pre-v0.19 CLI (`draksetup`, `drak-web.service`,
port 6300) against a real provisioned Xen host, and imports `invoke` and the
local `vm_runner_client` package at module scope — neither is installed by
default, and it also shells out to `git ls-tree HEAD ../drakvuf` at import
time. None of that exists in a plain checkout, which is why CI's `build.yml`
never actually invokes pytest today.

Because `test/unit/` is nested under `test/`, pytest will still try to load
`test/conftest.py` when collecting tests here unless told not to look above
this directory. Run tests with `--confcutdir` pointed at this folder:

```bash
python -m pytest test/unit --confcutdir=test/unit -v
```

This does not modify or attempt to repair the legacy suite; it just stops
pytest's conftest search at this directory's boundary, which is what
`--confcutdir` exists for.
