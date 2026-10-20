# Classifier interface

Every finished analysis can be handed to a malware classifier. The sandbox extracts behaviour features, runs the
model, and stores its verdict next to the report. Code: `drakrun/analyzer/classifier/`, postprocess plugin
`classify_sample` (runs after `generate_report`).

## Turning it on

```toml
# /etc/drakrun/config.toml
[classifier]
enabled = true                                   # default false
model_path = "/etc/drakrun/classifier/model.py"  # unset or missing file: the built-in stub
timeout_s = 60
```

## The model file

One Python file with one function. It runs in its own Python process (the drakrun venv, Python 3.11), CPU only,
with no network; it may load files next to it (e.g. `model.joblib`) and import sibling modules.

Packages already installed in that venv, so a model can use them without a deploy step. Pickled models
(joblib/pickle) only load reliably with the **same versions** they were saved with, so train with these:

| Package | Version |
|---|---|
| scikit-learn | 1.9.1 |
| joblib | 1.6.0 |
| lightgbm | 4.7.0 |
| xgboost | 3.2.0 |
| numpy | 2.4.6 |
| scipy | 1.17.1 |

Anything else must be added to the deployment venv first. Check a model before handing it over with
`python -c "import model, json; print(model.classify(json.load(open('features.json')), '.'))"` from its
directory, using the deployment venv's Python.

```python
def classify(features: dict, analysis_dir: str) -> dict:
    return {
        "label": "malicious",          # "malicious" | "suspicious" | "benign" | "unknown"
        "score": 0.93,                 # 0..1
        "family": "AgentTesla",        # or None
        "model": "chimera-rf",
        "model_version": "1.0",
        "explanation": ["many registry autorun writes"],
    }
```

An exception, a timeout, or an invalid result (missing key, label outside the list, score outside 0..1 or a bool)
is recorded as `{"schema": "chimera-verdict/1", "label": "unknown", "error": "..."}`; the analysis itself never
fails because of the model. Extra keys in the result are dropped.

`stub_model.py` (`model: "chimera-stub"`) is a placeholder heuristic, not a trained model, and says so in its
explanation.

## Outputs

| Where | What |
|---|---|
| `<analysis>/features.json` | the model's input, schema `chimera-features/1` |
| `<analysis>/classification.json` | the verdict, schema `chimera-verdict/1` |
| `metadata.json` → `classification` | same verdict, also in `GET /api/status/<id>` |
| `GET /api/features/<id>`, `GET /api/classification/<id>` | the two files (404 if absent) |

## `chimera-features/1`

All behaviour is scoped to the sample's own process and its descendants (the process started by the injector,
found in `process_tree.json`); events of other processes are excluded. Lists are capped.

| Key | Content |
|---|---|
| `sample` | `sha256`, `file_name`, `file_type`, `size_bytes` |
| `run` | `guest_os`, `timeout_s`, `complete`, `vm_stalled`, `drakvuf_errors` (from the telemetry summary) |
| `processes` | `count`, `max_depth` (0 = sample only), `names` (≤50), `command_lines` (≤50), `exited_early` |
| `api_calls` | `{api_name: count}` from apimon; only the APIs in `drakrun/data/hooks.txt` can appear |
| `api_sequence` | first 2000 API names in time order |
| `files` | `created`, `written`, `deleted` counts, `paths` (≤100) |
| `registry` | `set_value`, `create_key`, `delete` counts, `keys` (≤100), `autorun_touched` |
| `network` | `dns_queries`, `connections`, `remote_endpoints` (`ip:port`, ≤100), `http_requests` |
| `ttps` | `[{name, attack: [ATT&CK IDs]}]` from capa |

`network.dns_queries` on Windows combines two sources: `DnsQueryEx` API hooks from
`socketmon.log` and query names parsed from `dump.pcap`. The capture catches resolvers that
talk to the DNS server directly, such as `nslookup`, which bypass the hooked API. The
capture also contains Windows' own background lookups (update, telemetry, Bing), so a
capture query is kept only if its server IP and guest UDP source port match a
`UdpSendMessages` event in `socketmon.log` (`RemotePort` 53, `LocalPort` set) that is
attributed to the sample's subtree. Without `socketmon.log`, or when socketmon records no
local port, no capture names are added. TCP/53 is not covered. Names are deduplicated
(case-insensitive) and capped at 100.

Counts are observed attempts, not confirmed effects. The guest network is INetSim: every name resolves and every
HTTP request gets a fake answer.

For Linux, `run.guest_os` is `"linux"`. The sample is the `InjectedPid` in `inject.log`
(`Method: "AgentExec"`); its process subtree defines the scope. `api_calls` counts syscall
`Method` names from `syscall.log` (or `syscall.log.gz`), and `api_sequence` contains the first
2000 names in timestamp order. `files.written` and `files.deleted` count attributed path
entries in the report's `modified_files` and `deleted_files`; `files.paths` combines their
filenames. These are unique paths per section, not write-event counts; `files.created` is
zero because the report does not distinguish creation. Network features use report
`connections` and `dns_queries`, filtered to subtree seqids. Registry fields stay empty/zero,
as do `http_requests` and `ttps`, which have no Linux producer.
