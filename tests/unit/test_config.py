"""
tests/unit/test_config.py

Phase 5 HTTP guest agent config coverage -- adam/common/config.py had zero
dedicated tests before this file (only exercised indirectly through other
modules importing Settings). Covers exactly the surface Task G's TESTING
section calls out: "configuration parsing" -- HttpGuestSettings defaults
and base_url construction, Settings.guest_backend's default and both
literal values, env-var overrides for the nested http_guest section (the
same ADAM__SECTION__FIELD convention SandboxSettings already relies on),
and that config/default.toml itself parses into a valid Settings object
with the guest_backend/http_guest section this project's Phase 5 revision
added.

Does not touch guest_username/guest_password's fail-fast secrets
requirement beyond what's needed to construct a valid Settings for these
tests -- that behavior predates this file and isn't Phase 5 scope.
"""

from __future__ import annotations

import os
import tomllib

import pytest
from pydantic import ValidationError

from adam.common.config import CONFIG_DIR, HttpGuestSettings, SandboxSettings, Settings, get_settings


def _minimal_settings(**overrides: object) -> Settings:
    """Builds a valid Settings via programmatic overrides only (highest-precedence tier per config.py's own docstring) -- isolates these tests from whatever real env vars/.env/TOML happen to be present."""
    kwargs: dict[str, object] = {
        "sandbox": {
            "vm_name": "TEST_VM",
            "guest_username": "tester",
            "guest_password": "not-a-real-secret",
        }
    }
    kwargs.update(overrides)
    return Settings(**kwargs)  # type: ignore[arg-type]


class TestHttpGuestSettings:
    def test_defaults(self) -> None:
        settings = HttpGuestSettings()
        assert settings.host == "127.0.0.1"
        assert settings.port == 8765
        assert settings.request_timeout_s == 30.0
        assert settings.procmon_path is None
        assert settings.tshark_path is None
        assert settings.sysmon_log == "Microsoft-Windows-Sysmon/Operational"
        assert settings.tshark_interface == "1"
        assert settings.capture_dir == "C:\\ADAM\\telemetry"

    def test_startup_readiness_hardening_defaults(self) -> None:
        """
        Startup/readiness hardening pass -- new fields driving
        HTTPGuestChannel.wait_until_ready()'s two-stage sequence
        (network-readiness, then HTTP /health polling) and its retry
        behavior. See adam.sandbox.guest.http_channel for how each is
        consumed.
        """
        settings = HttpGuestSettings()
        assert settings.agent_ready_timeout_s == 200.0
        assert settings.network_ready_timeout_s == 60.0
        assert settings.network_poll_interval_s == 2.0
        assert settings.readiness_poll_interval_s == 1.0
        assert settings.retry_attempts == 5
        assert settings.retry_backoff_s == 0.5

    def test_startup_readiness_fields_must_be_positive(self) -> None:
        for field in (
            "agent_ready_timeout_s",
            "network_ready_timeout_s",
            "network_poll_interval_s",
            "readiness_poll_interval_s",
            "retry_backoff_s",
        ):
            with pytest.raises(ValidationError):
                HttpGuestSettings(**{field: 0})
        with pytest.raises(ValidationError):
            HttpGuestSettings(retry_attempts=0)

    def test_base_url_property(self) -> None:
        settings = HttpGuestSettings(host="192.168.56.101", port=9001)
        assert settings.base_url == "http://192.168.56.101:9001"

    def test_base_url_uses_default_host_and_port(self) -> None:
        assert HttpGuestSettings().base_url == "http://127.0.0.1:8765"

    def test_request_timeout_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            HttpGuestSettings(request_timeout_s=0)
        with pytest.raises(ValidationError):
            HttpGuestSettings(request_timeout_s=-1.0)


class TestSandboxSettingsHardenedTimeouts:
    """
    Startup/readiness hardening pass -- boot_timeout_s/guest_ready_timeout_s
    bumped from their original 60.0/150.0 defaults after real-VM validation
    found this guest significantly slower to boot than those values
    assumed. See adam.sandbox.controller.SandboxController for how both are
    consumed.
    """

    def test_defaults(self) -> None:
        settings = SandboxSettings(vm_name="TEST_VM", guest_username="tester", guest_password="x")
        assert settings.boot_timeout_s == 200.0
        assert settings.guest_ready_timeout_s == 200.0


class TestGuestBackendSelector:
    def test_defaults_to_vbox(self) -> None:
        settings = _minimal_settings()
        assert settings.guest_backend == "vbox"

    def test_accepts_http(self) -> None:
        settings = _minimal_settings(guest_backend="http")
        assert settings.guest_backend == "http"

    def test_rejects_unknown_backend(self) -> None:
        with pytest.raises(ValidationError):
            _minimal_settings(guest_backend="carrier-pigeon")

    def test_http_guest_defaults_present_even_when_backend_is_vbox(self) -> None:
        """http_guest is always constructed (default_factory), even when guest_backend='vbox' -- Runner only reads it when guest_backend=='http', but Settings itself doesn't require the section to be absent otherwise."""
        settings = _minimal_settings()
        assert isinstance(settings.http_guest, HttpGuestSettings)
        assert settings.http_guest.port == 8765


class TestSettingsFailsFastOnMissingSecrets:
    def test_missing_guest_credentials_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        This repo's own working copy has a real .env with real guest
        credentials (see .env.example) -- Settings() would happily pick
        those up and this test would pass for the wrong reason (a real
        secret filling in for the "missing" one) unless dotenv loading is
        explicitly disabled for this one instantiation via `_env_file=None`
        (a documented pydantic-settings override), on top of blanking out
        any real exported env vars via monkeypatch.
        """
        monkeypatch.delenv("ADAM__SANDBOX__GUEST_USERNAME", raising=False)
        monkeypatch.delenv("ADAM__SANDBOX__GUEST_PASSWORD", raising=False)
        with pytest.raises(ValidationError):
            Settings(_env_file=None, sandbox={"vm_name": "TEST_VM"})  # type: ignore[arg-type,call-arg]


class TestEnvVarOverrides:
    """
    ADAM__SECTION__FIELD env vars are the second-highest precedence tier
    (config.py module docstring) -- verifies the nested http_guest section
    picks up overrides the same way sandbox already does, since
    env_nested_delimiter="__" is a general Settings mechanism, not
    something wired up per-section.
    """

    def test_http_guest_port_overridden_by_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADAM__SANDBOX__VM_NAME", "ENV_VM")
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_USERNAME", "envuser")
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_PASSWORD", "envpass")
        monkeypatch.setenv("ADAM__HTTP_GUEST__PORT", "9999")
        monkeypatch.setenv("ADAM__HTTP_GUEST__HOST", "10.0.0.5")
        monkeypatch.setenv("ADAM__GUEST_BACKEND", "http")
        # Isolate from any real config/*.toml on disk for this one test --
        # point ADAM_ENV at a file that doesn't exist so only env vars and
        # field defaults are in play (still below programmatic overrides,
        # which this test doesn't use, so env vars are the effective
        # top tier here).
        monkeypatch.setenv("ADAM_ENV", "__test_env_that_does_not_exist__")

        settings = Settings()  # type: ignore[call-arg]
        assert settings.guest_backend == "http"
        assert settings.http_guest.host == "10.0.0.5"
        assert settings.http_guest.port == 9999


class TestDefaultTomlParses:
    """config/default.toml itself must parse into a valid Settings (given required secrets via env) and carry the guest_backend/http_guest section this project's Phase 5 HTTP architecture added."""

    def test_default_toml_file_exists(self) -> None:
        assert (CONFIG_DIR / "default.toml").exists()

    def test_default_toml_produces_valid_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_USERNAME", "tester")
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_PASSWORD", "not-a-real-secret")
        monkeypatch.setenv("ADAM_ENV", "__test_env_that_does_not_exist__")

        settings = Settings()  # type: ignore[call-arg]
        assert settings.sandbox.vm_name == "ADAM_WIN10_OFFICE"
        assert settings.guest_backend == "vbox"
        assert settings.http_guest.port == 8765
        assert settings.http_guest.host == "127.0.0.1"  # the documented placeholder -- see default.toml's own comment
        assert settings.guest_tools.procmon_path is not None


class TestDefaultTomlHardenedTimeouts:
    """
    config/default.toml's [sandbox] and [http_guest] hardened timeout/retry
    values (startup/readiness hardening pass) must actually reach Settings
    -- kept as its own test class, independent of
    TestDefaultTomlParses.test_default_toml_produces_valid_settings (which
    has a pre-existing, unrelated failure asserting guest_backend=='vbox'
    against a default.toml that currently ships guest_backend='http' --
    not this pass's concern), so a regression here isn't masked by that
    one.
    """

    def test_hardened_values_present_in_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_USERNAME", "tester")
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_PASSWORD", "not-a-real-secret")
        monkeypatch.setenv("ADAM_ENV", "__test_env_that_does_not_exist__")

        settings = Settings()  # type: ignore[call-arg]
        assert settings.sandbox.boot_timeout_s == 200.0
        assert settings.sandbox.guest_ready_timeout_s == 200.0
        assert settings.http_guest.request_timeout_s == 30.0
        assert settings.http_guest.agent_ready_timeout_s == 200.0
        assert settings.http_guest.network_ready_timeout_s == 60.0
        assert settings.http_guest.network_poll_interval_s == 2.0
        assert settings.http_guest.readiness_poll_interval_s == 1.0
        assert settings.http_guest.retry_attempts == 5
        assert settings.http_guest.retry_backoff_s == 0.5


class TestGuestBackendIsRootLevel:
    """
    Regression test for a real, shipped config bug: config/default.toml
    once placed `guest_backend = "http"` textually after the [guest_tools]
    table header with no header of its own between them -- TOML has no
    "return to root table" syntax, so a bare `key = value` line always
    belongs to whichever [table] most recently opened. That parsed
    guest_backend as guest_tools.guest_backend instead of the root-level
    key adam.common.config.Settings.guest_backend actually reads.
    GuestToolsSettings is a plain, un-configured BaseModel, whose default
    Pydantic v2 extra="ignore" behavior silently dropped the unknown
    field -- no error, no warning. Settings.guest_backend therefore never
    received a TOML value at all and fell back to its "vbox" field
    default, even though the file appeared to say "http" and the real-VM
    runtime log showed "guest_backend=vbox -- using VBoxGuestChannel".

    Both checks below parse the real config/default.toml on disk (no
    mocks, no hardcoded dict standing in for it) and would have failed
    against the old, buggy table placement.
    """

    def test_default_toml_parses_guest_backend_as_a_root_level_key(self) -> None:
        raw = tomllib.loads((CONFIG_DIR / "default.toml").read_text(encoding="utf-8"))
        assert "guest_backend" in raw, (
            "guest_backend is missing from config/default.toml's root-level parsed keys -- it "
            "must be a bare `key = value` line placed BEFORE the first [table] header in the "
            "file (adam.common.config.Settings.guest_backend is a top-level field, not a member "
            "of any section model), or TOML will silently fold it into whichever table precedes "
            "it instead."
        )
        assert raw["guest_backend"] == "http"
        # The specific regression this guards against: guest_backend must
        # not be nested inside guest_tools (or any other table) again.
        assert "guest_backend" not in raw.get("guest_tools", {})
        assert "guest_backend" not in raw.get("http_guest", {})
        assert "guest_backend" not in raw.get("sandbox", {})

    def test_settings_resolves_guest_backend_from_default_toml_via_normal_loading(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Drives the project's real Settings() precedence chain (config.py's settings_customise_sources) against the real config/default.toml on disk -- only the required secrets are supplied via env, and ADAM_ENV is pointed at a nonexistent file so no config/<ADAM_ENV>.toml can mask this file's own value."""
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_USERNAME", "tester")
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_PASSWORD", "not-a-real-secret")
        monkeypatch.delenv("ADAM__GUEST_BACKEND", raising=False)
        monkeypatch.setenv("ADAM_ENV", "__test_env_that_does_not_exist__")

        settings = Settings()  # type: ignore[call-arg]
        assert settings.guest_backend == "http"


class TestGetSettingsCaching:
    def test_get_settings_is_cached_and_clearable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ADAM__SANDBOX__VM_NAME", "CACHE_TEST_VM")
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_USERNAME", "tester")
        monkeypatch.setenv("ADAM__SANDBOX__GUEST_PASSWORD", "not-a-real-secret")
        monkeypatch.setenv("ADAM_ENV", "__test_env_that_does_not_exist__")
        get_settings.cache_clear()
        try:
            first = get_settings()
            second = get_settings()
            assert first is second  # same cached instance

            monkeypatch.setenv("ADAM__SANDBOX__VM_NAME", "DIFFERENT_VM")
            third = get_settings()
            assert third is first  # still cached -- env change alone doesn't invalidate it

            get_settings.cache_clear()
            fourth = get_settings()
            assert fourth.sandbox.vm_name == "DIFFERENT_VM"  # cache_clear() picks up the new env
        finally:
            get_settings.cache_clear()  # don't leak a CACHE_TEST_VM/DIFFERENT_VM Settings into other tests
