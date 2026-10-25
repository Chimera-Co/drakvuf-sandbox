# chimera-lgbm-rf 0.1 — training report

Created 2026-10-23T04:34:31+0530, 126s. Out-of-fold numbers, 5-fold, families and benign programs never split across folds.

- Malicious: 12000 WinMET reports from 1145 groups (cap 300/family)
- Benign: 38 CHIMERA runs from 23 programs (dropped 0 with < 10 hooked calls)
- Features: 1853 (api, apilog, apishare, tot, grp, file, reg, proc, ng2, ng3)
- API vocabulary: 224 hooked APIs kept, 38 dropped as sandbox blind spots (list at the end)

**Caveat:** all malicious examples come from CAPE and all benign ones from CHIMERA, so these numbers can be inflated by sandbox differences. The honest number is the frozen model on CHIMERA malware runs.

## Metrics (LightGBM)

| | threshold | TPR | FPR (runs) | FPR (programs) | precision | F1 | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|
| malicious | 0.826 | 0.615 | 0.000 | 0.000 | 1.000 | 0.761 | 0.9712 | 0.9999 |
| suspicious | 0.377 | 0.877 | 0.079 | 0.087 | 1.000 | 0.934 | 0.9712 | 0.9999 |

Confusion at the malicious threshold: {'tp': 7377, 'fp': 0, 'fn': 4623, 'tn': 38}
TPR at 1% / 5% FPR (uncalibrated): 0.61475 / 0.82125

## Baselines (same folds)

| model | ROC-AUC | PR-AUC | TPR@1%FPR | TPR@5%FPR |
|---|---|---|---|---|
| random_forest | 0.9754 | 0.9999 | 0.7984166666666667 | 0.82475 |
| logistic_regression | 0.9093 | 0.9996 | 0.3238333333333333 | 0.3254166666666667 |

## Benign programs (calibrated out-of-fold scores)

| program | runs | max score |
|---|---|---|
| AnyDesk portable | 2 | 0.000 |
| Everything 1.4.1.1028 | 2 | 0.286 |
| Greenshot 1.3.328 | 2 | 0.562 |
| IT inventory script (scheduled task, HTTP POST) unknown | 2 | 0.003 |
| KeePassXC 2.7.12 | 2 | 0.086 |
| Logon script (Run key, recon) unknown | 2 | 0.377 |
| Syncthing see file | 2 | 0.003 |
| Sysinternals Autoruns (autorunsc) latest at download | 2 | 0.000 |
| Sysinternals BGInfo latest at download | 2 | 0.359 |
| Sysinternals ProcDump latest at download | 2 | 0.000 |
| Sysinternals PsExec latest at download | 2 | 0.086 |
| TightVNC 2.8.87 | 2 | 0.003 |
| Visual C++ Redistributable x64 latest at download | 2 | 0.359 |
| WinRAR 7.13 | 2 | 0.000 |
| accesschk latest | 1 | 0.003 |
| backup-documents 1.0 | 1 | 0.003 |
| dropbox 274.4.4905 | 1 | 0.003 |
| listdlls latest | 1 | 0.377 |
| log-collector 1.0 | 1 | 0.826 |
| psinfo latest | 1 | 0.003 |
| rclone see file | 2 | 0.003 |
| security-baseline 1.0 | 1 | 0.000 |
| tailscale 1.104.2 | 1 | 0.003 |

## Recall per malware family (top 30 by size)

| family | n | recall |
|---|---|---|
| snakelogger | 236 | 0.924 |
| virlock | 236 | 0.021 |
| cosmu | 236 | 0.004 |
| redline | 232 | 0.983 |
| stop | 232 | 0.552 |
| gamarue | 230 | 0.670 |
| noon | 229 | 0.965 |
| disabler | 228 | 0.991 |
| snojan | 227 | 1.000 |
| amadey | 226 | 0.420 |
| taskun | 226 | 0.978 |
| strab | 224 | 0.732 |
| agenttesla | 224 | 0.920 |
| berbew | 222 | 0.000 |
| qbot | 222 | 0.811 |
| vbclone | 215 | 0.014 |
| mokes | 206 | 0.908 |
| equationdrug | 201 | 0.075 |
| blihan | 199 | 1.000 |
| dofoil | 184 | 0.505 |
| gcleaner | 180 | 0.089 |
| bladabindi | 178 | 0.933 |
| sload | 151 | 0.960 |
| makoob | 151 | 0.073 |
| deyma | 141 | 0.809 |
| injuke | 139 | 0.727 |
| remcos | 132 | 0.795 |
| zard | 132 | 0.909 |
| vilsel | 123 | 0.813 |
| lazy | 115 | 0.870 |

## Features that alone separate the classes (check for sandbox artefacts)

AUC far from 0.5 using one feature only. Fine for behaviour (injection, persistence); suspicious for loader/runtime noise (LdrGetDllHandle, GetSystemTimeAsFileTime, totals).

| feature | AUC |
|---|---|
| api:RegSetValueExW | 0.229 |
| apishare:RegSetValueExW | 0.234 |
| apilog:RegSetValueExW | 0.235 |
| ng3:70 | 0.235 |
| file:written_log | 0.244 |
| ng2:100 | 0.267 |
| ng2:130 | 0.268 |
| ng3:265 | 0.268 |
| apilog:RegOpenKeyExW | 0.273 |
| ng2:291 | 0.282 |
| apilog:GetSystemMetrics | 0.286 |
| reg:create_key_log | 0.292 |
| apishare:IsDebuggerPresent | 0.707 |
| ng3:501 | 0.301 |
| api:RegOpenKeyExW | 0.306 |
| api:IsDebuggerPresent | 0.689 |
| apilog:IsDebuggerPresent | 0.683 |
| grp:anti_analysis:calls_log | 0.681 |
| apishare:FindNextFileW | 0.678 |
| ng3:247 | 0.323 |
| ng3:33 | 0.324 |
| ng2:70 | 0.327 |
| apilog:RegQueryValueExA | 0.672 |
| apilog:SystemParametersInfoW | 0.328 |
| apishare:RegQueryValueExA | 0.672 |

## Top features by gain (final model)

| feature | gain |
|---|---|
| file:written_log | 413461.6 |
| apilog:GetSystemMetrics | 144951.4 |
| ng3:70 | 140773.0 |
| api:RegSetValueExW | 140094.9 |
| apilog:RegSetValueExW | 132734.4 |
| apishare:IsDebuggerPresent | 98653.8 |
| apishare:RegSetValueExW | 84919.8 |
| ng3:265 | 83471.9 |
| grp:anti_analysis:calls_log | 78652.5 |
| apilog:RegOpenKeyExW | 62712.2 |
| tot:calls_log | 59041.0 |
| reg:set_value_log | 58871.8 |
| apilog:RegOpenKeyExA | 58291.4 |
| apishare:RegOpenKeyExW | 57673.0 |
| apishare:FindNextFileW | 54555.2 |
| tot:distinct | 51323.8 |
| grp:anti_analysis:distinct | 47400.3 |
| ng2:172 | 41134.6 |
| ng2:505 | 40685.9 |
| apishare:GetSystemMetrics | 40219.6 |
| reg:create_key_log | 40088.5 |
| tot:seq_log | 38064.1 |
| ng3:205 | 34780.4 |
| apishare:RegCloseKey | 32640.6 |
| apilog:FindNextFileW | 27340.2 |

## APIs dropped from both sides (one sandbox cannot observe them)

| API | reason |
|---|---|
| CoCreateInstance | DRAKVUF blind spot (CAPE 34.3%, CHIMERA 0%) |
| CoCreateInstanceEx | DRAKVUF blind spot (CAPE 19.5%, CHIMERA 0%) |
| CreateProcessA | DRAKVUF blind spot (CAPE 30.5%, CHIMERA 0%) |
| CreateProcessInternalW | DRAKVUF blind spot (CAPE 59.2%, CHIMERA 0%) |
| CreateWindowExW | CAPE blind spot (CAPE 0.0%, CHIMERA 78.9%) |
| CryptExportKey | CAPE blind spot (CAPE 0.4%, CHIMERA 21.1%) |
| FindFirstFileExA | partly invisible to DRAKVUF: FindNextFileW is seen more often than this (CAPE 0.0%, CHIMERA 0.0%) |
| FindFirstFileExW | partly invisible to DRAKVUF: FindNextFileW is seen more often than this (CAPE 59.8%, CHIMERA 5.3%) |
| GetDiskFreeSpaceA | DRAKVUF blind spot (CAPE 20.9%, CHIMERA 0%) |
| GetSystemTime | start-up call CHIMERA mostly misses (CAPE 81.5%, CHIMERA 18.4%) |
| GetSystemTimeAsFileTime | start-up call CHIMERA mostly misses (CAPE 99.9%, CHIMERA 23.7%) |
| GetTickCount | CAPE blind spot (CAPE 0.0%, CHIMERA 36.8%) |
| GetTickCount64 | CAPE blind spot (CAPE 0.0%, CHIMERA 18.4%) |
| LdrGetDllHandle | DLL-loader internals, not mappable between sandboxes (CAPE 96.4%, CHIMERA 100.0%) |
| LdrGetProcedureAddress | DLL-loader internals, not mappable between sandboxes (CAPE 2.3%, CHIMERA 84.2%) |
| LdrLoadDll | DLL-loader internals, not mappable between sandboxes (CAPE 99.6%, CHIMERA 100.0%) |
| MsgWaitForMultipleObjectsEx | CAPE blind spot (CAPE 2.3%, CHIMERA 47.4%) |
| NSPStartup | CAPE blind spot (CAPE 2.6%, CHIMERA 39.5%) |
| RegDeleteValueW | CAPE blind spot (CAPE 0.4%, CHIMERA 18.4%) |
| RemoveDirectoryA | DRAKVUF blind spot (CAPE 22.0%, CHIMERA 0%) |
| RemoveDirectoryW | CAPE blind spot (CAPE 2.2%, CHIMERA 23.7%) |
| SHGetKnownFolderPath | CAPE blind spot (CAPE 1.0%, CHIMERA 18.4%) |
| SetErrorMode | CAPE blind spot (CAPE 0.0%, CHIMERA 34.2%) |
| SetWindowLongPtrW | CAPE blind spot (CAPE 0.0%, CHIMERA 63.2%) |
| SetWindowLongW | CAPE blind spot (CAPE 0.0%, CHIMERA 47.4%) |
| SetWindowsHookExA | DRAKVUF blind spot (CAPE 18.3%, CHIMERA 0%) |
| SetWindowsHookExW | CAPE blind spot (CAPE 1.4%, CHIMERA 31.6%) |
| SystemParametersInfoA | DRAKVUF blind spot (CAPE 18.2%, CHIMERA 0%) |
| WSARecv | CAPE blind spot (CAPE 0.1%, CHIMERA 18.4%) |
| WSASend | CAPE blind spot (CAPE 0.0%, CHIMERA 26.3%) |
| WinHttpConnect | CAPE blind spot (CAPE 1.2%, CHIMERA 18.4%) |
| WinHttpOpenRequest | CAPE blind spot (CAPE 1.2%, CHIMERA 18.4%) |
| WinHttpQueryHeaders | CAPE blind spot (CAPE 0.1%, CHIMERA 18.4%) |
| WinHttpReceiveResponse | CAPE blind spot (CAPE 0.0%, CHIMERA 18.4%) |
| WinHttpSendRequest | CAPE blind spot (CAPE 1.2%, CHIMERA 18.4%) |
| recv | CAPE blind spot (CAPE 0.1%, CHIMERA 18.4%) |
| send | CAPE blind spot (CAPE 0.2%, CHIMERA 15.8%) |
| shutdown | CAPE blind spot (CAPE 0.7%, CHIMERA 31.6%) |

## Family model

21 classes ((n/a), redline, cosmu, berbew, amadey, agenttesla, taskun, virlock, strab, blihan, vbclone, bladabindi, gcleaner, vilsel, disabler, noon, allaple, snojan, mydoom, sload, other), n=6489. 3-fold CV: {'accuracy': 0.8426568038218524, 'macro_f1': 0.8583354053863936, 'coverage_at_0.6': 0.8839574664817383, 'accuracy_at_0.6': 0.8957461645746164}
