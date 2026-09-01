import os
import tomllib
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict

class SandboxSettings(BaseModel):
    hypervisor: str = "QEMU"
    qemu_system_path: str = "C:\\Program Files\\qemu\\qemu-system-x86_64.exe"
    qemu_img_path: str = "C:\\Program Files\\qemu\\qemu-img.exe"
    vm_image_path: str = ""
    snapshot_name: str = "clean"
    boot_timeout_s: int = 120
    detonation_timeout_s: int = 300
    network_mode: str = "SIMULATED"
    hostfwd_port_host: int = 8443
    hostfwd_port_guest: int = 8443
    memory_mb: int = 4096
    cpu_count: int = 4
    sample_dir: str = "samples"
    manage_vm: bool = True
    use_virtio_serial: bool = True
    serial_pipe_name: str = "127.0.0.1:8444"

    @property
    def agent_base_url(self) -> str:
        return f"http://127.0.0.1:{self.hostfwd_port_host}"

class FusionSettings(BaseModel):
    window_seconds: float = 5.0
    max_window_events: int = 10000
    min_confidence_emit: float = 0.40
    process_tree_depth: int = 10

class PolicySettings(BaseModel):
    ruleset_path: str = "rules/default"
    global_confidence_gate: float = 0.60
    max_mutations_per_session: int = 15
    default_cooldown_s: int = 20
    dry_run: bool = False

class DeceptionSettings(BaseModel):
    default_causal_window_ms: int = 30000
    plausibility_warn_below: float = 0.50
    enable_clock_manipulation: bool = False

class BusSettings(BaseModel):
    default_queue_size: int = 1000
    overflow_policy: str = "DROP_OLDEST"

class DbSettings(BaseModel):
    path: str = "artifacts/adam.sqlite"
    batch_size: int = 500
    batch_interval_ms: int = 250

class LoggingSettings(BaseModel):
    level: str = "INFO"
    format: str = "json"
    directory: str = "logs"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ADAM__", env_nested_delimiter="__")

    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    fusion: FusionSettings = Field(default_factory=FusionSettings)
    policy: PolicySettings = Field(default_factory=PolicySettings)
    deception: DeceptionSettings = Field(default_factory=DeceptionSettings)
    bus: BusSettings = Field(default_factory=BusSettings)
    db: DbSettings = Field(default_factory=DbSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

CONFIG_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class HttpGuestSettings(BaseModel):
    hostfwd_port_host: int = 8443
    hostfwd_port_guest: int = 8443
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 30.0

class GuestToolsSettings(BaseModel):
    sysmon_enabled: bool = True
    procmon_enabled: bool = True
    tshark_enabled: bool = True
    tshark_path: str = "C:\\Program Files\\Wireshark\\tshark.exe"

def get_settings(config_path: Optional[str] = None) -> Settings:
    return load_settings(config_path)

def load_settings(config_path: Optional[str] = None) -> Settings:
    paths_to_try = []
    if config_path:
        paths_to_try.append(config_path)
    
    env_path = os.environ.get("ADAM_CONFIG_PATH")
    if env_path:
        paths_to_try.append(env_path)
        
    paths_to_try.extend([
        "config/development.toml",
        "config/default.toml"
    ])
    
    config_data = {}
    for p in paths_to_try:
        if os.path.exists(p):
            with open(p, "rb") as f:
                config_data = tomllib.load(f)
            break
            
    return Settings.model_validate(config_data)

