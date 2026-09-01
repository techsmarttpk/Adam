import xml.etree.ElementTree as ET
import uuid
import re
from datetime import datetime
from adam.contracts.enums import EventSource, EventCategory
from adam.contracts.raw_event import RawEvent, ProcessContext
from adam.collectors.base import BaseCollector
from adam.common.timeutil import parse_iso, now_utc


def _safe_int(val, default: int = 0) -> int:
    """Safely converts string/int to int, supporting decimal and hex ('0x123')."""
    if val is None:
        return default
    try:
        val_str = str(val).strip()
        return int(val_str, 0) if val_str.startswith(("0x", "0X")) else int(val_str)
    except (ValueError, TypeError):
        return default


def _clean_xml_str(xml_str: str) -> str:
    """Removes XML declarations with multi-byte encoding tags that crash ElementTree."""
    if isinstance(xml_str, bytes):
        xml_str = xml_str.decode('utf-8', errors='ignore')
    # Strip <?xml ...?> header if present to avoid encoding mismatches
    return re.sub(r'^\s*<\?xml[^>]*\?>', '', xml_str)


class SysmonCollector(BaseCollector):
    def parse_xml_event(self, xml_str: str, session_id: str) -> RawEvent:
        """Parses a raw Windows XML Event log string from Sysmon."""
        cleaned_xml = _clean_xml_str(xml_str)
        root = ET.fromstring(cleaned_xml)

        # Handle wildcard tag matching to ignore XML namespaces completely
        # (This avoids namespace mismatch bugs across different Windows versions)
        def find_elem(parent, tag_name):
            if parent is None:
                return None
            for child in parent:
                if child.tag.endswith(tag_name):
                    return child
            return None

        def findall_elems(parent, tag_name):
            if parent is None:
                return []
            return [c for c in parent if c.tag.endswith(tag_name)]

        # 1. Parse System tag
        system = find_elem(root, 'System')

        # 2. Extract Event ID
        event_id = 0
        event_id_elem = find_elem(system, 'EventID')
        if event_id_elem is not None and event_id_elem.text:
            event_id = _safe_int(event_id_elem.text, default=0)

        # 3. Extract TimeCreated
        occurred_at_str = None
        time_created = find_elem(system, 'TimeCreated')
        if time_created is not None:
            occurred_at_str = time_created.attrib.get('SystemTime')

        occurred_at = parse_iso(occurred_at_str) if occurred_at_str else now_utc()

        # 4. Extract EventData attributes safely
        event_data = find_elem(root, 'EventData')
        attrs = {}

        if event_data is not None:
            # Sysmon usually uses <Data Name="Key">Value</Data>
            for data in findall_elems(event_data, 'Data'):
                name = data.attrib.get('Name')
                if name:
                    attrs[name] = data.text if data.text is not None else ""
            
            # Fallback for non-standard XML elements inside EventData directly
            for child in event_data:
                tag = child.tag.split('}')[-1] # Strip namespace if any
                if tag != 'Data' and child.text and tag not in attrs:
                    attrs[tag] = child.text

        # 5. Fallback for Process ID if missing in EventData (check System/Execution)
        pid_raw = attrs.get("ProcessId")
        if not pid_raw and system is not None:
            execution = find_elem(system, 'Execution')
            if execution is not None:
                pid_raw = execution.attrib.get('ProcessID')

        pid = _safe_int(pid_raw, default=0)
        
        ppid_raw = attrs.get("ParentProcessId")
        ppid = _safe_int(ppid_raw, default=0) if ppid_raw else None

        image = attrs.get("Image")
        cmdline = attrs.get("CommandLine")
        user = attrs.get("User")
        guid = attrs.get("ProcessGuid")

        # 6. Categorize Event
        category = EventCategory.SYSTEM
        if event_id == 1:
            category = EventCategory.PROCESS
        elif event_id in (11, 23, 26):
            category = EventCategory.FILE
        elif event_id in (12, 13, 14):
            category = EventCategory.REGISTRY
        elif event_id == 3:
            category = EventCategory.NETWORK

        process = ProcessContext(
            pid=pid,
            ppid=ppid,
            image=image,
            command_line=cmdline,
            user=user,
            guid=guid
        )

        return RawEvent(
            event_id=f"raw_sys_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            source=EventSource.SYSMON,
            source_event_id=event_id,
            category=category,
            occurred_at=occurred_at,
            observed_at=now_utc(),
            process=process,
            attributes=attrs,
            raw_ref=None
        )

