#!/usr/bin/env python

import os
from setuptools import find_packages, setup

version_globals = {}
with open("drakrun/version.py") as f:
    exec(f.read(), version_globals)

version = version_globals["__version__"]
if os.getenv("DRAKRUN_VERSION_TAG"):
    version = version + "+" + os.getenv("DRAKRUN_VERSION_TAG")


def read_requirements():
    # requirements.txt also carries pip-only lines (comments, "-e ./perdedor")
    # that are not valid install_requires entries; perdedor is installed
    # separately from its submodule.
    with open("requirements.txt") as f:
        lines = (line.strip() for line in f)
        return [line for line in lines if line and not line.startswith(("#", "-e "))]

setup(
    name="drakvuf-sandbox",
    version=version,
    description="DRAKRUN",
    package_dir={"drakrun": "drakrun"},
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "drakrun = drakrun.cli:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
