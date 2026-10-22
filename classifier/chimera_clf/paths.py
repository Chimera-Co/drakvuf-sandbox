"""Where the training data lives. Only training scripts use this; the deployed model never does.

CHIMERA_DATASETS points at the folder with WinMET_volume_*.7z, the WinMET label files and
EMBER2024/data. Default: Capstone_Classifier_Datasets next to the repository checkout.
"""

import os
from pathlib import Path

CLASSIFIER_DIR = Path(__file__).resolve().parents[1]
DATASETS = Path(os.environ.get("CHIMERA_DATASETS", CLASSIFIER_DIR.parents[1] / "Capstone_Classifier_Datasets"))
EMBER_DATA = DATASETS / "EMBER2024" / "data"
