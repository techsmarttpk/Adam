"""
adam/common/config.py

Milestone 4 -- Configuration for VM execution (ARCHITECTURE.md section 12).

Scope note: this module originally implemented ONLY what SandboxController
needed -- the `sandbox` section of `Settings`. It does NOT build logging,
the event bus, the error hierarchy, or the plugin registry; those are
separate milestones and stay unbuilt until something actually needs them
(same discipline as detonate() not growing collect_artifacts() before
Collector Orchestration existed). Other developers are expected to add
their own `<section>: XSettings` fields to `Settings` in their own
milestones. Phase 5 (Guest Agent) added a second section owned by this same
developer, `guest_tools: GuestToolsSettings` -- see that model's own
docstring for why, unlike `sandbox`, every one of its fields has a default
and its absence is not a fail-fast condition. A later Phase 5 revision (the
HTTP guest agent architecture) added `guest_backend` (a `Literal["vbox",
"http"]` selector) and `http_guest: HttpGuestSettings` alongside it -- see
those two definitions' own docstrings, and adam/sandbox/guest/channel.py
for how Runner uses `guest_backend` to choose between VBoxGuestChannel and
HTTPGuestChannel without SessionOrchestrator ever depending on the choice.

Precedence (ARCHITECTURE.md section 12.1), highest to lowest:

    programmatic overrides (Settings(**kwargs), mainly for tests)
        > real environment variables (ADAM__SANDBOX__VM_NAME=...)
        > .env file (same ADAM__SANDBOX__* names -- see .env.example)
        > config/<ADAM_ENV>.toml   (per-machine, gitignored if it has secrets)
        > config/default.toml      (committed baseline)
        > pydantic field defaults  (lowest -- always valid)

CLI-flag overrides (the actual top tier in the architecture diagram) are
not implemented here -- there is no CLI entrypoint yet; that lands with
the Orchestrator milestone. The two env-var tiers (real env > .env) are a
deliberate refinement of the architecture's single "Environment variables"
tier: an explicitly exported env var should win over a stale value someone
left in .env, which is what pydantic-settings does by default when env
sources are listed in that order.

Secrets rule (ARCHITECTURE.md section 12.3): guest_username / guest_password
are required SandboxSettings fields with NO TOML representation anywhere in
this module. They resolve only from ADAM__SANDBOX__GUEST_USERNAME /
ADAM__SANDBOX__GUEST_PASSWORD. If neither is set, Settings() raises a
Pydantic ValidationError immediately -- config loading fails fast, rather
than SandboxController failing later with a confusing guest auth error.
"""

from __future__ import annotations

import os
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

# adam/common/config.py -> parents[0]=common, parents[1]=adam, parents[2]=project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"


class SandboxSettings(BaseModel):
    """
    Everything SandboxController's constructor needs, per its own
    docstring commitment: "whenever Configuration lands, it should be
    able to supply these values without this class's public interface
    changing." Field names intentionally match SandboxController's
    constructor parameter names 1:1.
    """

    vm_name: str
    snapshot_name: str = "clean"
    boot_timeout_s: float = Field(default=60.0, gt=0)
    guest_ready_timeout_s: float = Field(default=150.0, gt=0)

    # No default -- absence must fail fast at Settings() construction,
    # not surface later as a guestcontrol authentication error. Never
    # given a TOML representation; see module docstring / ARCHITECTURE.md
    # section 12.3.
    guest_username: str
    guest_password: str


class GuestToolsSettings(BaseModel):
    """
    Phase 5 (Guest Agent) addition -- ARCHITECTURE.md section 12.1's
    per-milestone extension pattern ("Other developers are expected to add
    their own `<section>: XSettings` fields to `Settings` in their own
    milestones -- this file only owns `sandbox`" no longer holds now that
    Dev A owns this section too, same file, new field).

    Every field has a default so that `Settings()` remains constructible
    with zero `[guest_tools]` configuration at all -- unlike
    `guest_username`/`guest_password`, an unconfigured guest tool is not a
    fail-fast condition (ARCHITECTURE.md section 14.2's "refuse to start"
    category does not apply here): GuestAgent treats a `None` path as "this
    telemetry source is not configured, skip it," which is exactly the
    same "support partial telemetry" guarantee that governs a tool being
    physically absent from the guest at runtime. See
    adam/sandbox/guest/agent/agent.py's module docstring.

    procmon_path / tshark_path: absolute Windows paths to the executables
    INSIDE THE GUEST (not the host) -- Procmon and tshark run inside the
    sandboxed VM, not on the host running ADAM. No universal default is
    possible (installation-specific); config/default.toml's committed
    values match the specific ADAM_WIN10_OFFICE guest image this project
    targets, same category of environment-specific-but-committed value as
    `sandbox.vm_name`.

    sysmon_log: the Windows Event Log channel Sysmon writes to. Given a
    real, universal default -- "Microsoft-Windows-Sysmon/Operational" is
    Sysmon's own fixed channel name for every standard installation, not
    environment-specific the way the two paths above are.

    tshark_interface: passed to tshark's `-i` flag. No universal default
    exists (interface names/indices are host-image-specific); "1" (tshark's
    own convention for "the first interface `tshark -D` lists") is used as
    a pragmatic, disclosed default likely to need per-image tuning, not a
    verified-correct value for every possible guest image.

    The four `*_timeout_s` fields bound the individual guestcontrol calls
    GuestAgent issues (tool verification, Procmon terminate/CSV conversion,
    tshark stop, tshark EK JSON conversion) -- see agent.py for exactly
    which call each one guards.
    """

    procmon_path: str | None = None
    tshark_path: str | None = None
    sysmon_log: str = "Microsoft-Windows-Sysmon/Operational"
    tshark_interface: str = "1"
    capture_dir: str = "C:\\ADAM\\telemetry"

    tool_verify_timeout_s: float = Field(default=15.0, gt=0)
    procmon_terminate_timeout_s: float = Field(default=15.0, gt=0)
    procmon_export_timeout_s: float = Field(default=120.0, gt=0)
    tshark_stop_timeout_s: float = Field(default=15.0, gt=0)
    tshark_export_timeout_s: float = Field(default=60.0, gt=0)
    copy_from_guest_timeout_s: float = Field(default=60.0, gt=0)


class HttpGuestSettings(BaseModel):
    """
    Phase 5 (HTTP Guest Agent architecture) addition -- settings for
    HTTPGuestChannel (adam/sandbox/guest/http_channel.py) when
    `Settings.guest_backend == "http"`. Distinct from GuestToolsSettings
    above (which the "vbox" backend's GuestAgent still owns and uses
    unchanged) because the two backends' tool-path/timeout needs
    genuinely differ in shape: the HTTP backend's tool paths live in the
    GUEST's own agent.config.json (adam/sandbox/guest/agent/AgentConfig.psm1),
    not host-side Settings, since the guest-resident PowerShell service
    reads them locally -- this section only needs to know how to REACH
    that service and, for verify_tools()'s own reporting, which paths it
    expects the guest to have configured.
    """

    host: str = "127.0.0.1"
    port: int = 8765
    request_timeout_s: float = Field(default=15.0, gt=0)

    # Mirrors of GuestToolsSettings' path/log fields, used only for
    # HTTPGuestChannel's verify_tools()/start_captures() calls (which
    # paths to ask the guest agent about) -- the guest agent's own
    # agent.config.json is the actual source of truth for what it uses
    # internally; these must be kept consistent with it by whoever
    # provisions the guest image, the same manual-sync obligation
    # config/default.toml's [guest_tools] section already carries for the
    # "vbox" backend.
    procmon_path: str | None = None
    tshark_path: str | None = None
    sysmon_log: str = "Microsoft-Windows-Sysmon/Operational"
    tshark_interface: str = "1"
    capture_dir: str = "C:\\ADAM\\telemetry"

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class DatabaseSettings(BaseModel):
    """
    Phase 1 / 2 addition — Configuration for the SQLite persistence layer.
    """
    path: str = "adam_local.db"
    batch_size: int = Field(default=100, gt=0)
    batch_timeout_s: float = Field(default=1.0, gt=0)
    queue_size: int = Field(default=10000, gt=0)


class DeceptionSettings(BaseModel):
    default_causal_window_ms: int = Field(default=30000, gt=0)
    plausibility_warn_below: float = Field(default=0.5, ge=0.0, le=1.0)
    enable_clock_manipulation: bool = False



def _deep_merge_section(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """
    One-level merge suitable for this TOML shape (top-level [section]
    tables of scalar keys): keys present in `override` win, per-section,
    without requiring the override file to repeat every key from the
    base file.
    """
    merged = dict(base)
    for section, values in override.items():
        if isinstance(values, dict) and isinstance(merged.get(section), dict):
            merged[section] = {**merged[section], **values}
        else:
            merged[section] = values
    return merged


class _TomlConfigSource(PydanticBaseSettingsSource):
    """
    Custom pydantic-settings source implementing the two TOML tiers from
    ARCHITECTURE.md section 12.1: config/default.toml (committed
    baseline), overridden by config/<ADAM_ENV>.toml if that file exists
    (ADAM_ENV defaults to "development" -- matches the config/development
    .toml / config/production.toml names already reserved in .gitignore).

    Returns the whole merged dict from __call__() rather than
    implementing per-field get_field_value(), which is the documented
    pattern in pydantic-settings for "load one file, return everything"
    sources.
    """

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        # Required by the abstract base class; unused because __call__
        # is overridden below to return the full merged dict at once.
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        merged: dict[str, Any] = {}

        default_path = CONFIG_DIR / "default.toml"
        if default_path.exists():
            merged = _deep_merge_section(merged, tomllib.loads(default_path.read_text(encoding="utf-8")))

        environment = os.environ.get("ADAM_ENV", "development")
        environment_path = CONFIG_DIR / f"{environment}.toml"
        if environment_path.exists():
            merged = _deep_merge_section(merged, tomllib.loads(environment_path.read_text(encoding="utf-8")))

        return merged


class Settings(BaseSettings):
    """
    Root config model. Resolves once at startup into a single frozen
    object, validated by Pydantic -- invalid config fails fast here,
    never as a mystery error mid-detonation (ARCHITECTURE.md section 12.1).

    Only `sandbox` is defined here; other developers add their own
    `<section>: XSettings` fields in their own milestones. This keeps
    merge conflicts in this file to "adding one more field," matching
    the project's module-ownership rules.
    """

    model_config = SettingsConfigDict(
        env_prefix="ADAM__",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    sandbox: SandboxSettings
    guest_tools: GuestToolsSettings = Field(default_factory=GuestToolsSettings)

    # Phase 5 (HTTP Guest Agent architecture) backend selector --
    # "vbox" (default): VBoxGuestChannel wrapping the existing,
    #   GuestControl-based GuestAgent -- the "compatibility backend",
    #   proven against a real VM across Bugs #1-#4 / Issues #1-#3.
    # "http": HTTPGuestChannel talking to the guest-resident PowerShell
    #   HTTP agent (adam/sandbox/guest/agent/adam_agent.ps1) -- the
    #   target architecture, NOT YET VALIDATED against a real VM (see
    #   docs/phase5-migration-guide.md's "Remaining Phase 5 gaps").
    # Runner (adam/orchestrator/runner.py) reads this to decide which
    # GuestChannel implementation to construct; SessionOrchestrator
    # itself only ever depends on the GuestChannel interface, never on
    # this setting or on which concrete class was chosen.
    guest_backend: Literal["vbox", "http"] = "vbox"
    http_guest: HttpGuestSettings = Field(default_factory=HttpGuestSettings)
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    deception: DeceptionSettings = Field(default_factory=DeceptionSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Order = priority, highest first. See module docstring for the
        # full precedence chain and why real env vars outrank .env.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            _TomlConfigSource(settings_cls),
            file_secret_settings,
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Load and cache the process-wide Settings singleton. Cached because
    config is meant to resolve once at startup (ARCHITECTURE.md section
    12.1) -- call get_settings.cache_clear() only in tests that need to
    reload with different environment variables.
    """
    return Settings()
