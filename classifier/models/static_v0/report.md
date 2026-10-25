# Static models (EMBER2024) — training report

2026-10-23T04:26:26+0530, 4 min. LightGBM on thrember v3 vectors (2568 features). Time-split: tested only on weeks after training. Thresholds set on validation weeks (malicious: ≤1% benign above, suspicious: ≤5%).

| model | train / val / test | ROC-AUC | PR-AUC | TPR @1% FPR | TPR @0.1% FPR | threshold | TPR | FPR | challenge detected |
|---|---|---|---|---|---|---|---|---|---|
| elf | 46000 / 6000 / 12000 | 0.9858 | 0.9881 | 0.867 | 0.629 | 0.864 | 0.899 | 0.0107 | 0.231 (n=386) |
| pdf | 92000 / 12000 / 24000 | 0.9912 | 0.9930 | 0.918 | 0.781 | 0.636 | 0.932 | 0.0177 | 0.601 (n=805) |
| pe | 142986 / 31490 / 63658 | 0.9960 | 0.9949 | 0.935 | 0.792 | 0.751 | 0.912 | 0.0056 | 0.574 (n=4868) |

PE by file type (test weeks):

| type | n | ROC-AUC | TPR | FPR |
|---|---|---|---|---|
| Dot_Net | 6602 | 0.9979 | 0.946 | 0.0084 |
| Win32 | 36364 | 0.9946 | 0.897 | 0.0063 |
| Win64 | 20692 | 0.9974 | 0.930 | 0.0038 |

Caveats: EMBER labels come from AV vendor consensus (ClarAVy); ELF/PDF vectors carry only byte/entropy/string statistics (thrember's PE-specific groups are zero for them); the challenge set is malicious-only, so it measures detection, not false positives.
