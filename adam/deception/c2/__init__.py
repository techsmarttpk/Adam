"""Command-and-Control (C2) Forcing, Sinkholing & Memory Key Extraction Subsystem."""

from adam.deception.c2.sinkhole import C2Sinkhole, SyntheticC2Response, C2ProtocolType
from adam.deception.c2.tls_extractor import TLSSessionKeyExtractor, DecryptedFlow
from adam.deception.c2.traffic_normalizer import TrafficNormalizer, BeaconProfile

__all__ = [
    "C2Sinkhole",
    "SyntheticC2Response",
    "C2ProtocolType",
    "TLSSessionKeyExtractor",
    "DecryptedFlow",
    "TrafficNormalizer",
    "BeaconProfile",
]
