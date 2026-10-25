import pathlib
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from drakrun.lib.paths import CONFIG_PATH, PACKAGE_DIR

DNS_USE_GATEWAY_ADDRESS = "use-gateway-address"
OUT_INTERFACE_DEFAULT = "default"


class RedisConfigSection(BaseModel):
    host: str = "localhost"
    port: int = 6379
    username: Optional[str] = None
    password: Optional[str] = None

    def make_url(self):
        if self.username is not None and self.password is not None:
            return f"redis://{self.username}:{self.password}@{self.host}:{self.port}"
        else:
            return f"redis://{self.host}:{self.port}"


class NetworkConfigSection(BaseModel):
    dns_server: str
    out_interface: str
    net_enable: bool


WorkerGuestOS = Literal["windows", "linux", "any"]


class WorkerConfigSection(BaseModel):
    vm_guest_os: Dict[int, WorkerGuestOS] = Field(default_factory=dict)
    memory_admission_timeout: float = Field(default=1800, ge=0, allow_inf_nan=False)
    memory_admission_poll_interval: float = Field(default=5, gt=0, allow_inf_nan=False)
    # Reserve 64 MB shadow memory and 128 MB for Xen/device-model overhead.
    memory_admission_margin_mb: int = Field(default=192, ge=0)


class DrakrunConfigSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    plugins: List[str]
    default_timeout: int
    job_timeout_leeway: int = 600
    net_enable: Optional[bool] = None
    apimon_hooks_path: Optional[pathlib.Path] = None
    syscall_hooks_path: Optional[pathlib.Path] = None
    extra_drakvuf_args: Optional[Dict[str, Any]] = None
    extra_output_subdirs: Optional[List[str]] = None
    no_post_restore: bool = False
    no_screenshotter: bool = False
    result_ttl: int = -1
    gzip_syscalls: bool = False
    use_7zip: bool = False
    path_to_7zip: str = "C:/Program Files/7-Zip/7z.exe"
    # Override hostname used in worker names on this host.
    # It gets automatically detected if not set.
    worker_hostname: Optional[str] = None
    # Don't pick 'shellexec' method even if supported by Drakvuf
    no_shellexec: bool = False
    # DRAKVUF -F (Xen fast singlestep). Upstream leaves it off by default;
    # drakrun has always passed it. Switchable to test the apimon crash.
    fast_singlestep: bool = True
    # INetSim terminates TLS for both guest OSes. Unreadable logs are optional.
    inetsim_service_log: pathlib.Path = pathlib.Path("/var/log/chimera-inetsim/service.log")


class DrakrunDefaultsPresetSection(BaseModel):
    plugins: Optional[List[str]] = None
    default_timeout: Optional[int] = None
    job_timeout_leeway: Optional[int] = None
    net_enable: Optional[bool] = None
    apimon_hooks_path: Optional[pathlib.Path] = None
    syscall_hooks_path: Optional[pathlib.Path] = None
    extra_drakvuf_args: Optional[Dict[str, Any]] = None
    extra_output_subdirs: Optional[List[str]] = None
    no_post_restore: Optional[bool] = None
    no_screenshotter: Optional[bool] = None
    gzip_syscalls: Optional[bool] = None


class CapaConfigSection(BaseModel):
    rules_directory: pathlib.Path = PACKAGE_DIR / "data" / "capa-rules"
    analyze_drakmon_log: bool = True
    analyze_memdumps: bool = False
    analyze_only_malware_pids: bool = False
    worker_pool_processes: int = 4


class ClassifierConfigSection(BaseModel):
    enabled: bool = False
    model_path: Optional[pathlib.Path] = None
    timeout_s: float = Field(default=60, gt=0, allow_inf_nan=False)


class StaticConfigSection(BaseModel):
    """Static analysis of every upload, run beside the detonation in a locked-down container."""

    enabled: bool = False
    # "podman" (production) or "docker". The analyzer never runs outside a container.
    engine: Literal["podman", "docker"] = "podman"
    image: str = "localhost/chimera-static:0.1.0"
    timeout_s: float = Field(default=90, gt=0, allow_inf_nan=False)
    memory_mb: int = Field(default=2048, ge=256)
    cpus: float = Field(default=1.0, gt=0, allow_inf_nan=False)
    pids_limit: int = Field(default=32, ge=8)
    # Unprivileged uid/gid the analyzer runs as inside the container (nobody).
    container_uid: int = 65534
    container_gid: int = 65534
    # How long classify_sample waits for static.json once the detonation has finished.
    wait_s: float = Field(default=120, ge=0, allow_inf_nan=False)
    max_output_bytes: int = 32 * 1024 * 1024
    # Deep pass (capa + FLOSS) for PE and ELF files, after the fast pass, on its own queue and worker
    # (`drakrun static-worker --deep`), so it never delays the fast result or the verdict.
    deep_enabled: bool = False
    deep_timeout_s: float = Field(default=240, gt=0, allow_inf_nan=False)
    deep_memory_mb: int = Field(default=2048, ge=512)
    # Decompilation in the deep pass: Ghidra headless in its own image (a JVM cannot run inside the
    # self-limiting analyzer process), same isolation flags; capa's match addresses pick the functions.
    ghidra_enabled: bool = False
    ghidra_image: str = "localhost/chimera-ghidra:11.1.2"
    ghidra_analysis_timeout_s: int = Field(default=180, ge=10)
    ghidra_decompile_budget_s: int = Field(default=120, ge=10)
    ghidra_memory_mb: int = Field(default=2048, ge=1024)
    ghidra_max_functions: int = Field(default=40, ge=1, le=200)


class MemdumpConfigSection(BaseModel):
    # Maximum total size of collected, uncompressed dumps
    max_total_dumps_size: int = 500 * 1024 * 1024
    # Minimal accepted size of a single memory dump
    min_single_dump_size: int = 512
    # Maximal accepted size of a single memory dump
    max_single_dump_size: int = 32 * 1024 * 1024
    # Drop dumps from System process
    filter_out_system_pid: bool = True


class S3StorageConfigSection(BaseModel):
    enabled: bool = True
    bucket: str = "drakrun"
    address: str
    access_key: str
    secret_key: Optional[str]
    iam_auth: bool = False
    remove_local_after_upload: bool = True


class KartonConfigSection(BaseModel):
    enabled: bool = False
    config_path: Optional[pathlib.Path] = None
    # redis expire timeout for karton results
    redis_ttl: int = 3600
    # How often KartonState is polled to check if analysis is done
    poll_interval: int = 10


class SandboxDefinitionSection(BaseModel):
    """One entry in the sandbox registry, declared as a [sandbox.<id>] table.

    The registry is deliberately configuration-driven rather than discovered
    from the hypervisor: drakrun currently derives every vm-N from a single
    golden image, so enumerating running domains would report concurrency
    slots as if they were distinct environments.
    """

    display_name: Optional[str] = None
    platform: str = "windows"
    os_version: Optional[str] = None
    firmware: Optional[str] = None
    hypervisor: str = "xen"
    lifecycle: str = "drakrun-vm"
    # Verifier ids this sandbox opts into. The API intersects this with the
    # platforms each adapter actually supports, so declaring an unsupported
    # tool here is harmless - it simply won't be offered.
    verifiers: List[str] = Field(default_factory=lambda: ["perdedor", "alkhaser"])
    metadata: Dict[str, str] = Field(default_factory=dict)


class AlKhaserConfigSection(BaseModel):
    # Host-side path to al-khaser_x64.exe. The binary is copied into the
    # disposable overlay per scan and dies with it, so the golden image stays
    # clean and the tool can be upgraded without rebuilding the image.
    host_binary_path: Optional[pathlib.Path] = None
    # al-khaser defaults to --sleep 600 and TIMING_ATTACKS performs nine
    # separate sleeps of that duration, so an unqualified full run sleeps for
    # roughly 90 minutes. The adapter always passes an explicit value.
    default_sleep_seconds: int = 30
    timeout: int = 1800


class PerdedorConfigSection(BaseModel):
    # Checkout of the perdedor repository. The adapter needs the on-disk
    # Windows agent tree or Linux/common Python sources to stage in the guest,
    # which a wheel install would not provide.
    repo_path: Optional[pathlib.Path] = None
    timeout: int = 900


class EvasionConfigSection(BaseModel):
    alkhaser: AlKhaserConfigSection = AlKhaserConfigSection()
    perdedor: PerdedorConfigSection = PerdedorConfigSection()
    # Default wall-clock budget for a whole verification scan, in seconds.
    default_timeout: int = 2400
    # CHIMERA evasion score thresholds (0-100, higher is better).
    score_pass_threshold: float = 90.0
    score_warn_threshold: float = 70.0


class DrakrunConfig(BaseSettings):
    model_config = SettingsConfigDict(
        extra="allow",
        toml_file=CONFIG_PATH,
        env_prefix="drakrun__",
        nested_model_default_partial_update=True,
        env_nested_delimiter="__",
    )
    redis: RedisConfigSection
    worker: WorkerConfigSection = Field(default_factory=WorkerConfigSection)
    network: NetworkConfigSection
    drakrun: DrakrunConfigSection
    capa: CapaConfigSection = CapaConfigSection()
    classifier: ClassifierConfigSection = Field(default_factory=ClassifierConfigSection)
    static: StaticConfigSection = Field(default_factory=StaticConfigSection)
    memdump: MemdumpConfigSection = MemdumpConfigSection()
    karton: KartonConfigSection = KartonConfigSection()
    s3: Optional[S3StorageConfigSection] = None
    preset: Dict[str, DrakrunDefaultsPresetSection] = Field(default_factory=dict)
    sandbox: Dict[str, SandboxDefinitionSection] = Field(default_factory=dict)
    evasion: EvasionConfigSection = EvasionConfigSection()

    def get_drakrun_defaults(
        self, preset_name: Optional[str] = None
    ) -> DrakrunDefaultsPresetSection:
        if preset_name is None:
            preset = dict(DrakrunDefaultsPresetSection())
        elif preset_name not in self.preset:
            raise RuntimeError(f"Preset {preset_name} is not defined in configuration")
        else:
            preset = dict(self.preset[preset_name])
        global_defaults = dict(self.drakrun)
        return DrakrunDefaultsPresetSection(
            **{
                key: (preset[key] if preset[key] is not None else global_defaults[key])
                for key in preset.keys()
            }
        )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            env_settings,
            TomlConfigSettingsSource(settings_cls),
        )


def load_config() -> DrakrunConfig:
    return DrakrunConfig()
