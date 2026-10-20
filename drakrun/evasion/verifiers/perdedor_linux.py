"""Package the vendored Linux agent for an offline, standard-library guest."""

from __future__ import annotations

import pathlib
import zipfile

from drakrun.evasion.verifiers.base import VerifierError


def build_linux_zipapp(repo_path: pathlib.Path, output: pathlib.Path) -> None:
    """Bundle only Python sources, with the agent's own CLI as entry point.

    The optional native CPUID/RDTSC helper is deliberately absent. Upstream
    reports those checks as skipped when the helper cannot be built. No
    compiler, third-party package, or source extraction is needed in-guest.
    """
    packages = (
        repo_path / "agents/linux/perdedor_linux",
        repo_path / "common/python/perdedor_common",
    )
    for package in packages:
        if not (package / "__init__.py").is_file():
            raise VerifierError(f"PERDEDOR package missing: {package}")
    if not (packages[0] / "__main__.py").is_file():
        raise VerifierError(f"PERDEDOR Linux entry point missing under {repo_path}")

    # ZIP_STORED also works on Python installations without the optional zlib.
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for package in packages:
            for source in sorted(package.rglob("*.py")):
                archive.write(source, source.relative_to(package.parent).as_posix())
        archive.writestr(
            "__main__.py",
            "from perdedor_linux.__main__ import main\nraise SystemExit(main())\n",
        )
