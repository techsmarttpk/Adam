"""
adam/collectors/parsers/pcap.py

Parses tshark's "Elasticsearch Kibana" (`-T ek`) newline-delimited JSON
output into adam.contracts.raw_event.RawEvent. ARCHITECTURE.md section 5.3
/ docs/dev-a-environment-and-roadmap.md Phase 7 (file named `pcap.py` after
the underlying capture format, per the roadmap's own naming).

Why `-T ek`, not `-T json`. tshark's plain `-T json` output is a single
JSON array wrapping every packet in the capture -- well-suited to parsing a
complete, closed `.pcap` file after the fact, but not to tailing a
still-growing capture, since a JSON array only becomes valid to parse once
its closing `]` has been written. `-T ek` (`tshark -T ek -l -r <path>` or
run live) instead emits one self-contained JSON object per line, in the
Elasticsearch bulk-index format: an "index action" line, followed by a
"document" line holding the actual packet fields nested under `"layers"`.
This line-oriented shape is exactly what a real-time collector needs, the
same reason ProcMon's CSV export (not a hypothetical single-JSON-blob
export) was chosen for `pml.py`.

No process attribution. Unlike Sysmon's own network event (Event ID 3),
raw packet capture at the tshark/libpcap layer has no OS process context --
a NetworkCollector-produced RawEvent's `process` field is always `None`.
Correlating a packet with the process that sent it is explicitly Fusion's
job (ARCHITECTURE.md section 5.3: "Must not correlate across sources" is
this collector's own boundary; combining Sysmon's process-aware Event ID 3
with this collector's packet-level detail across sources is exactly what
that boundary reserves for Fusion, not for this collector to attempt).

Field-completeness note: not every packet has every layer (a bare ARP frame
has no `tcp`/`udp` layer, an ICMP packet has no port numbers). All layer
lookups here are defensive (`.get()` with a default), not an assumption
that every field observed in one example capture is universally present.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from adam.contracts.enums import Category, Source
from adam.contracts.raw_event import RawEvent


class PcapParseError(Exception):
    """
    Raised when a tshark -T ek line is too malformed to produce a RawEvent
    (invalid JSON, or a document line missing the fields this parser
    cannot proceed without: frame.number, frame.time_epoch). Not yet folded
    into adam.common.errors' ParserError -- same disclosed, temporary
    status as evtx.py's SysmonParseError and pml.py's ProcmonParseError.
    """


def _layer(layers: dict[str, Any], layer_name: str) -> dict[str, str]:
    value = layers.get(layer_name)
    return value if isinstance(value, dict) else {}


def parse_tshark_ek_line(
    line: str,
    *,
    session_id: str,
    raw_ref: str | None = None,
) -> RawEvent | None:
    """
    Parses one line of `tshark -T ek` output. Returns None (not an error)
    for an "index action" line -- tshark's ek format alternates these with
    the actual "document" lines that carry packet data, and a caller
    iterating line-by-line is expected to skip the None results, same
    pattern as skipping a blank line. Raises PcapParseError only for lines
    that are neither a well-formed index-action line nor a well-formed,
    minimally-complete document line.
    """
    stripped = line.strip()
    if not stripped:
        return None

    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise PcapParseError(f"malformed tshark -T ek JSON line: {exc}") from exc

    if not isinstance(obj, dict):
        raise PcapParseError(f"expected a JSON object per line, got {type(obj).__name__}")

    if "index" in obj:
        return None  # index-action line, not a packet document -- see docstring

    layers = obj.get("layers")
    if not isinstance(layers, dict):
        raise PcapParseError("tshark -T ek document line missing 'layers' object")

    frame = _layer(layers, "frame")
    number_raw = frame.get("frame.number")
    epoch_raw = frame.get("frame.time_epoch")
    if number_raw is None or epoch_raw is None:
        raise PcapParseError("tshark -T ek document missing frame.number/frame.time_epoch")

    try:
        frame_number = int(number_raw)
    except ValueError as exc:
        raise PcapParseError(f"non-integer frame.number: {number_raw!r}") from exc

    try:
        occurred_at = datetime.fromtimestamp(float(epoch_raw), tz=timezone.utc)
    except ValueError as exc:
        raise PcapParseError(f"non-numeric frame.time_epoch: {epoch_raw!r}") from exc

    ip_layer = _layer(layers, "ip")
    ipv6_layer = _layer(layers, "ipv6")
    tcp_layer = _layer(layers, "tcp")
    udp_layer = _layer(layers, "udp")

    src_ip = ip_layer.get("ip.src") or ipv6_layer.get("ipv6.src")
    dst_ip = ip_layer.get("ip.dst") or ipv6_layer.get("ipv6.dst")
    src_port = tcp_layer.get("tcp.srcport") or udp_layer.get("udp.srcport")
    dst_port = tcp_layer.get("tcp.dstport") or udp_layer.get("udp.dstport")

    attributes: dict[str, Any] = {
        "protocols": frame.get("frame.protocols", ""),
        "length": frame.get("frame.len", ""),
    }
    if src_ip is not None:
        attributes["src_ip"] = src_ip
    if dst_ip is not None:
        attributes["dst_ip"] = dst_ip
    if src_port is not None:
        attributes["src_port"] = src_port
    if dst_port is not None:
        attributes["dst_port"] = dst_port

    return RawEvent(
        event_id=f"raw_network_{session_id}_{frame_number}",
        session_id=session_id,
        source=Source.WIRESHARK,
        source_event_id=frame_number,
        category=Category.NETWORK,
        occurred_at=occurred_at,
        observed_at=datetime.now(timezone.utc),
        process=None,  # no process attribution at this layer -- see module docstring
        attributes=attributes,
        raw_ref=raw_ref,
    )
