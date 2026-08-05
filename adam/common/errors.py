"""
adam/common/errors.py

The AdamError exception hierarchy -- ARCHITECTURE.md section 14.1. Every
exception any ADAM module raises intentionally should ultimately derive
from AdamError, so `except AdamError` (or a specific branch, e.g.
`except SandboxError`) is a meaningful, catchable boundary anywhere in the
codebase, per section 14.2's graduated degrade-don't-abort response table.

Scope. `adam/common/` is Dev A's exclusive-write directory (ARCHITECTURE.md
section 10.1), and per docs/dev-a-environment-and-roadmap.md's Phase 1 spec:
"AdamError hierarchy -- at least the SandboxError and CollectorError
branches ... since that's what your modules will raise." The full tree from
section 14.1 is declared below regardless, since it costs nothing (these
are all plain marker classes) and section 14.1's tree is already frozen,
reviewed architecture -- there is no design decision left to make for the
Fusion/Policy/Deception branches, only a transcription one. Branches this
module does not yet raise anywhere (FusionError, PolicyError,
DeceptionError, PersistenceError, ReportingError, and several Sandbox/
Collector leaves) exist as forward declarations for Dev B/C/D's modules to
raise once those modules exist, exactly as section 14.1 specifies them.

Re-parenting existing exceptions. Three exceptions predate this file and
were explicitly, self-documented as temporary stand-ins for it:
`VBoxCommandError` (adam/sandbox/vbox/client.py), and
`SandboxStateError` / `SandboxOperationError` (adam/sandbox/state.py). Per
docs/remaining-work-plan.md's Next-bucket item 4, this is a pure
re-parenting exercise, not a rename -- every existing `except
VBoxCommandError`/`except SandboxStateError`/`except SandboxOperationError`
call site keeps working unchanged, because those class names, constructors,
and raise sites are untouched; only their base classes change, from plain
`Exception` to the appropriate node in this tree:

  - `VBoxCommandError` -> `VMOperationError` ("VBoxManage failed" is
    exactly VBoxCommandError's own description: VBoxManage itself
    unreachable, or a query method failing outright).
  - `SandboxOperationError` -> `VMOperationError` as well: its own
    docstring describes it as covering "restore_snapshot, start,
    wait_for_state, wait_for_guest_ready, or copy_to_guest reporting
    failure, or VBoxManage being unreachable entirely" during prepare()/
    arm() -- the same underlying failure mode as VBoxCommandError, just
    surfaced at the controller layer instead of the client layer. There is
    no dedicated leaf for this in section 14.1's tree; VMOperationError is
    the closest, most accurate fit, and is used for both rather than
    inventing an unspecified fourth SandboxError leaf.
  - `SandboxStateError` (adam/sandbox/state.py) -> subclasses THIS
    module's `SandboxStateError` (the frozen leaf name), under an
    identical short name in a different module -- a standard pattern (a
    generic base and a richer, module-local concrete subclass sharing a
    name) chosen specifically because adam/common/ must not import from
    adam/sandbox/ (section 5.1: "Must not import anything from any other
    ADAM module"), so the dependency can only run one way: sandbox depends
    on common, never the reverse. See adam/sandbox/state.py for the
    concrete, richly-fielded version actually raised throughout the
    codebase.
"""

from __future__ import annotations


class AdamError(Exception):
    """Base class for every exception any ADAM module raises intentionally."""


class ConfigError(AdamError):
    """Invalid or missing configuration. Section 14.2: refuse to start."""


class ContractViolationError(AdamError):
    """A message failed schema validation against its adam.contracts model."""


class SandboxError(AdamError):
    """Base for adam/sandbox/ failures (section 5.2)."""


class VMOperationError(SandboxError):
    """VBoxManage failed -- unreachable, or an operation it ran reported failure."""


class SandboxStateError(SandboxError):
    """
    Illegal FSM transition. This is the generic, frozen-tree leaf; the
    concrete, richly-fielded exception actually raised throughout this
    codebase is `adam.sandbox.state.SandboxStateError`, which subclasses
    this one under the same short name -- see this module's docstring.
    """


class GuestTimeoutError(SandboxError):
    """
    Guest unresponsive. Originally reserved for Phase 5's real agent
    channel with no raise site yet -- now that site exists:
    HTTPGuestChannel.wait_until_ready() (adam/sandbox/guest/http_channel.py)
    raises this when the guest-resident HTTP agent never answers a healthy
    GET /health within settings.sandbox.guest_ready_timeout_s, after the VM
    itself was already confirmed booted by SandboxController.prepare()'s
    existing wait_for_guest_ready() check -- the message distinguishes "VM
    never booted" (a VMOperationError, raised earlier, during prepare())
    from "VM booted but the guest's own HTTP agent never came up on top of
    that" (this class). VBoxGuestChannel does not raise this -- its own
    guest-responsiveness handling predates and is unrelated to this leaf.
    """


class SampleTransferError(SandboxError):
    """Sample delivery into the guest failed. Not yet raised anywhere -- reserved for the ISO-mount transfer path (Phase 6)."""


class GuestToolMissingError(SandboxError):
    """
    A required guest-side telemetry tool (Procmon64.exe, tshark.exe) or the
    Sysmon event log channel is not present/reachable in the guest.

    New leaf, added during Phase 5 (Guest Agent) implementation -- section
    14.1's frozen tree has no existing node for "a required guest-side tool
    is missing": SampleTransferError is specifically about sample delivery,
    GuestTimeoutError is specifically about guest unresponsiveness, neither
    fits "the file exists and the guest is responsive, but the requested
    tool isn't installed at the configured path." Raised only by
    GuestAgent.verify_tools() when explicitly asked to hard-fail (most
    callers use its returned availability report instead and degrade to
    partial telemetry per ARCHITECTURE.md section 14.2/14.4 -- see
    adam/sandbox/guest/agent/agent.py's module docstring).
    """


class GuestToolExportError(SandboxError):
    """
    A guest-side telemetry tool ran but its capture/export/conversion step
    failed (e.g. Procmon's CSV export did not produce the expected header,
    tshark's EK JSON conversion returned a non-zero exit). Same disclosed-
    addition reasoning as GuestToolMissingError -- distinct from
    VMOperationError because the underlying VBoxManage/guestcontrol call
    itself succeeded; it's the *tool's own output* that was unusable.
    """


class CollectorError(AdamError):
    """Base for adam/collectors/ failures (section 5.3). Not yet raised anywhere -- collectors don't exist yet (Phase 7)."""


class ParserError(CollectorError):
    """A collector's source-format parser hit a malformed record."""


class SourceUnavailableError(CollectorError):
    """A collector's underlying telemetry source (log file, pcap, etc.) is unavailable."""


class FusionError(AdamError):
    """Base for adam/fusion/ failures (section 5.4, Dev B's module). Not raised by any Dev A code."""


class DetectorError(FusionError):
    """A single semantic detector raised. Section 14.2: skip that detector for that event, continue."""


class PolicyError(AdamError):
    """Base for adam/policy/ failures (section 5.5, Dev C's module). Not raised by any Dev A code."""


class RuleSyntaxError(PolicyError):
    """A policy rule file failed to parse. Caught at load, not at runtime (section 14.1)."""


class RuleCompilationError(PolicyError):
    """A syntactically valid rule failed to compile into an executable predicate."""


class PredicateError(PolicyError):
    """A compiled rule predicate raised during evaluation."""


class DeceptionError(AdamError):
    """Base for adam/deception/ failures (section 5.6, Dev C's module). Not raised by any Dev A code."""


class PrimitiveError(DeceptionError):
    """A deception primitive's implementation raised."""


class MutationFailedError(DeceptionError):
    """A mutation was attempted and failed. Section 14.2: record MutationResult(status=FAILED), continue."""


class PersistenceError(AdamError):
    """Base for adam/db/ failures (section 5.7, Dev D's module). Not raised by any Dev A code."""


class ReportingError(AdamError):
    """Base for adam/reporting/ failures (section 5.9, Dev D's module). Not raised by any Dev A code."""
