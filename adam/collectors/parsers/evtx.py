"""
adam/collectors/parsers/evtx.py

Parses Sysmon Event Log (EVTX) records into adam.contracts.raw_event.RawEvent.
ARCHITECTURE.md section 5.3 / docs/dev-a-environment-and-roadmap.md Phase 7.

Two clearly separated halves, deliberately:

  1. `parse_sysmon_event_xml()` -- a pure function: Sysmon XML string in,
     RawEvent out. No file I/O, no third-party EVTX library involved. This
     is where essentially all of this module's real logic and risk of bugs
     lives (event-ID-to-Category mapping, field extraction, timestamp
     parsing), and it is exactly what this module's offline verification
     exercises, against hand-built XML fixtures matching Sysmon's real,
     stable, well-documented event schema (Event IDs 1, 3, 11, 12/13; see
     https://learn.microsoft.com/sysinternals/downloads/sysmon for the
     schema this is checked against).

  2. `iter_evtx_records()` -- a thin wrapper around the third-party
     `python-evtx` library (`Evtx.Evtx.Evtx` + `Evtx.Views.evtx_file_xml_view`)
     that reads a real, binary `.evtx` file and yields each record's raw XML
     string for (1) to parse. This half is NOT independently testable in
     this environment -- there is no real `.evtx` binary file available to
     read, and hand-constructing a valid one is a binary-format exercise
     with no verification value (the risk in this module is in the parsing
     logic, not in calling a well-established third-party library per its
     documented API). Disclosed explicitly, per this project's "not
     verifiable from current implementation" convention, rather than
     claimed as tested.

Field-completeness note: several Sysmon event types (FileCreate, Registry*,
NetworkConnect, DNS) do not populate every field `ProcessInfo`
(adam/contracts/raw_event.py) requires a non-empty string for --
`IntegrityLevel`, `User`, `CommandLine`, `ProcessGuid` are only guaranteed
present on Event ID 1 (ProcessCreate). Where Sysmon's own XML omits one of
these, this parser substitutes the literal placeholder `"-"`, matching
Sysmon's own convention for genuinely empty fields (e.g. `RuleName` is
often literally `-` in real Sysmon output) rather than fabricating a
plausible-looking value. This is a disclosed parser convention, not silent
data invention -- a consumer that cares can check for the literal `"-"`.

ID generation note: `adam/common/ids.py` (a proper `new_id(prefix)`
generator) does not exist yet (tracked in docs/remaining-work-plan.md).
`RawEvent.event_id` is generated here via `uuid.uuid4()` in the interim,
consistent with this project's established pattern of a disclosed,
temporary stand-in rather than blocking on an unrelated Phase 1 item.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from xml.etree import ElementTree

from adam.contracts.enums import Category, Source
from adam.contracts.raw_event import ProcessInfo, RawEvent

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

# Sysmon's XML namespace on every <Event> element. ElementTree requires this
# to be included in every tag lookup below (`{ns}TagName`), or the lookups
# silently return None.
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

_PLACEHOLDER = "-"
"""Sysmon's own convention for a genuinely empty field. See module docstring."""

# Sysmon's documented, stable Event ID -> RawEvent.category mapping.
# https://learn.microsoft.com/sysinternals/downloads/sysmon
_EVENT_ID_CATEGORY: dict[int, Category] = {
    1: Category.PROCESS,  # ProcessCreate
    2: Category.FILE,  # FileCreateTime (file creation time changed)
    3: Category.NETWORK,  # NetworkConnect
    5: Category.PROCESS,  # ProcessTerminate
    6: Category.MODULE,  # DriverLoad
    7: Category.MODULE,  # ImageLoad
    8: Category.PROCESS,  # CreateRemoteThread
    9: Category.FILE,  # RawAccessRead
    10: Category.PROCESS,  # ProcessAccess
    11: Category.FILE,  # FileCreate
    12: Category.REGISTRY,  # RegistryEvent (Object create/delete)
    13: Category.REGISTRY,  # RegistryEvent (Value Set)
    14: Category.REGISTRY,  # RegistryEvent (Key/Value Rename)
    15: Category.FILE,  # FileCreateStreamHash
    17: Category.SYSTEM,  # PipeEvent (Created)
    18: Category.SYSTEM,  # PipeEvent (Connected)
    19: Category.WMI,  # WmiEvent (WmiEventFilter)
    20: Category.WMI,  # WmiEvent (WmiEventConsumer)
    21: Category.WMI,  # WmiEvent (WmiEventConsumerToFilter)
    22: Category.NETWORK,  # DNSEvent
    23: Category.FILE,  # FileDelete
}
_DEFAULT_CATEGORY = Category.SYSTEM


class SysmonParseError(Exception):
    """
    Raised when a Sysmon XML record is too malformed to produce a RawEvent
    (missing <System>/<EventID>/<TimeCreated>, or the XML itself doesn't
    parse). Not yet folded into adam.common.errors' ParserError -- see that
    module's docstring; this predates ParserError actually being raised by
    any code, and folding it in is a small, separate follow-up.
    """


def _text(data_elements: dict[str, str], name: str, *, default: str | None = None) -> str | None:
    return data_elements.get(name, default)


_SYSTEMTIME_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<offset>Z|[+-]\d{2}:?\d{2})?$"
)


def _parse_system_time(raw: str) -> datetime:
    """
    Parses Sysmon's <TimeCreated SystemTime="..."/> attribute. Windows EVTX
    timestamps are frequently given with 7 fractional digits (100ns ticks)
    rather than Python's 6-digit microsecond precision, and always carry
    either a trailing 'Z' or an explicit +HH:MM offset -- neither of which
    datetime.fromisoformat() accepted directly on every Python version this
    project targets/verifies against, so this is parsed with an explicit
    regex rather than assumed to already be in a directly-parseable shape.
    Defaults to UTC if no offset is present at all (should not happen for
    real Sysmon output, but a missing offset is not itself grounds to
    reject an otherwise well-formed timestamp).
    """
    match = _SYSTEMTIME_RE.match(raw.strip())
    if match is None:
        raise SysmonParseError(f"unrecognised SystemTime format: {raw!r}")

    base = match.group("base").replace(" ", "T")
    frac = (match.group("frac") or "0").ljust(6, "0")[:6]  # pad/truncate to exactly 6 digits (microseconds)
    offset = match.group("offset")

    dt = datetime.fromisoformat(f"{base}.{frac}")
    if offset is None or offset == "Z":
        return dt.replace(tzinfo=timezone.utc)
    if ":" not in offset:
        offset = f"{offset[:3]}:{offset[3:]}"
    return datetime.fromisoformat(f"{base}.{frac}{offset}")


def parse_sysmon_event_xml(
    xml_text: str,
    *,
    session_id: str,
    raw_ref: str | None = None,
) -> RawEvent:
    """
    Parses one Sysmon <Event>...</Event> XML document (as produced by
    Windows Event Viewer's "Copy Details as XML", `wevtutil qe /f:xml`, or
    python-evtx's evtx_record_xml_view) into a RawEvent.

    Raises SysmonParseError if the XML is malformed or missing a field this
    parser cannot proceed without (EventID, TimeCreated). Missing optional
    process-detail fields are substituted with the "-" placeholder rather
    than raising -- see module docstring.
    """
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise SysmonParseError(f"malformed Sysmon event XML: {exc}") from exc

    system = root.find(f"{_NS}System")
    if system is None:
        raise SysmonParseError("Sysmon event XML missing <System> element")

    event_id_el = system.find(f"{_NS}EventID")
    if event_id_el is None or event_id_el.text is None:
        raise SysmonParseError("Sysmon event XML missing <System>/<EventID>")
    try:
        event_id = int(event_id_el.text.strip())
    except ValueError as exc:
        raise SysmonParseError(f"non-integer <EventID>: {event_id_el.text!r}") from exc

    time_created_el = system.find(f"{_NS}TimeCreated")
    if time_created_el is None or "SystemTime" not in time_created_el.attrib:
        raise SysmonParseError("Sysmon event XML missing <System>/<TimeCreated SystemTime=...>")
    occurred_at = _parse_system_time(time_created_el.attrib["SystemTime"])

    record_id_el = system.find(f"{_NS}EventRecordID")
    source_event_id = int(record_id_el.text.strip()) if record_id_el is not None and record_id_el.text else event_id

    category = _EVENT_ID_CATEGORY.get(event_id)
    if category is None:
        logger.warning("unmapped Sysmon EventID=%d, defaulting category to %s", event_id, _DEFAULT_CATEGORY.value)
        category = _DEFAULT_CATEGORY

    data_elements: dict[str, str] = {}
    event_data = root.find(f"{_NS}EventData")
    if event_data is not None:
        for data_el in event_data.findall(f"{_NS}Data"):
            name = data_el.attrib.get("Name")
            if name is not None:
                data_elements[name] = data_el.text or ""

    process: ProcessInfo | None = None
    pid_raw = _text(data_elements, "ProcessId")
    if pid_raw is not None:
        try:
            pid = int(pid_raw)
        except ValueError:
            pid = 0
        ppid_raw = _text(data_elements, "ParentProcessId")
        try:
            ppid = int(ppid_raw) if ppid_raw is not None else 0
        except ValueError:
            ppid = 0
        process = ProcessInfo(
            pid=pid,
            ppid=ppid,
            image=_text(data_elements, "Image", default=_PLACEHOLDER) or _PLACEHOLDER,
            command_line=_text(data_elements, "CommandLine", default="") or "",
            integrity_level=_text(data_elements, "IntegrityLevel", default=_PLACEHOLDER) or _PLACEHOLDER,
            user=_text(data_elements, "User", default=_PLACEHOLDER) or _PLACEHOLDER,
            guid=_text(data_elements, "ProcessGuid", default=_PLACEHOLDER) or _PLACEHOLDER,
        )

    return RawEvent(
        event_id=f"raw_{uuid.uuid4().hex}",
        session_id=session_id,
        source=Source.SYSMON,
        source_event_id=source_event_id,
        category=category,
        occurred_at=occurred_at,
        observed_at=datetime.now(timezone.utc),
        process=process,
        attributes={k: v for k, v in data_elements.items() if k not in {
            "ProcessId", "ParentProcessId", "Image", "CommandLine", "IntegrityLevel", "User", "ProcessGuid",
        }},
        raw_ref=raw_ref,
    )


def iter_evtx_records(evtx_path: str) -> "Iterator[str]":
    """
    Yields the raw XML string of each record in a real Sysmon .evtx file, in
    file order. Thin wrapper around python-evtx -- see module docstring for
    why this half is not independently unit-tested in this environment.
    Requires the `python-evtx` package (add to requirements.txt when this
    is wired into a live SysmonCollector against a real log).
    """
    # Local import: optional dependency, only needed on this path. python-evtx
    # ships no type stubs / py.typed marker, hence the ignores -- a real
    # untyped-third-party-library situation, not a shortcut around our own
    # code's typing.
    import Evtx.Evtx as evtx  # type: ignore[import-untyped]
    import Evtx.Views as e_views  # type: ignore[import-untyped]

    with evtx.Evtx(evtx_path) as log:
        for xml_str, _record in e_views.evtx_file_xml_view(log.get_file_header()):
            yield xml_str
