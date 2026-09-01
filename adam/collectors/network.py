import uuid
from datetime import datetime
from typing import List
import scapy.all as scapy
from adam.contracts.enums import EventSource, EventCategory
from adam.contracts.raw_event import RawEvent
from adam.collectors.base import BaseCollector
from adam.common.timeutil import now_utc

class NetworkCollector(BaseCollector):
    def parse_pcap_file(self, pcap_path: str, session_id: str) -> List[RawEvent]:
        """Parses a PCAP file using scapy and returns normalized RawEvents for network packets."""
        events = []
        try:
            packets = scapy.rdpcap(pcap_path)
            for pkt in packets:
                if pkt.haslayer(scapy.IP):
                    ip = pkt[scapy.IP]
                    proto = ip.proto
                    src_ip = ip.src
                    dst_ip = ip.dst
                    
                    attrs = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": str(proto),
                        "size": len(pkt)
                    }
                    
                    if pkt.haslayer(scapy.TCP):
                        attrs["src_port"] = pkt[scapy.TCP].sport
                        attrs["dst_port"] = pkt[scapy.TCP].dport
                    elif pkt.haslayer(scapy.UDP):
                        attrs["src_port"] = pkt[scapy.UDP].sport
                        attrs["dst_port"] = pkt[scapy.UDP].dport
                        
                    occurred_at = datetime.fromtimestamp(float(pkt.time))
                    
                    events.append(RawEvent(
                        event_id=f"raw_net_{uuid.uuid4().hex[:12]}",
                        session_id=session_id,
                        source=EventSource.WIRESHARK,
                        category=EventCategory.NETWORK,
                        occurred_at=occurred_at,
                        observed_at=now_utc(),
                        process=None,
                        attributes=attrs,
                        raw_ref=None
                    ))
        except Exception:
            pass
        return events
