"""Kernel Object Identity Randomizer.

Dynamically aliases and randomizes synchronization primitives, mutexes, semaphores,
and named pipes to thwart malware single-instance checks and IPC rendezvous evasion.
"""

from __future__ import annotations
import dataclasses
import hashlib
import time
from typing import Dict, Optional


@dataclasses.dataclass
class ObjectAlias:
    original_name: str
    aliased_name: str
    object_type: str  # MUTEX, SEMAPHORE, NAMED_PIPE, EVENT
    created_at_ns: int
    access_count: int = 0


class ObjectIdentityRandomizer:
    """Manages dynamic translation between malware-requested object identifiers

    and randomized kernel object namespaces.
    """

    def __init__(self, session_salt: str = "adam_salt_v1") -> None:
        self.session_salt = session_salt
        self.aliases: Dict[str, ObjectAlias] = {}

    def get_or_create_alias(self, original_name: str, object_type: str) -> str:
        """Translates a requested object name into an isolated randomized alias."""
        key = f"{object_type}:{original_name}"
        if key in self.aliases:
            alias_entry = self.aliases[key]
            alias_entry.access_count += 1
            return alias_entry.aliased_name

        hash_digest = hashlib.sha256(f"{self.session_salt}:{key}".encode()).hexdigest()[:12]
        prefix_map = {
            "MUTEX": "Global\\Mtx_",
            "SEMAPHORE": "Global\\Sem_",
            "NAMED_PIPE": "\\\\.\\pipe\\svc_",
            "EVENT": "Global\\Evt_",
        }
        prefix = prefix_map.get(object_type.upper(), "Global\\Obj_")
        aliased_name = f"{prefix}{hash_digest}"

        alias_entry = ObjectAlias(
            original_name=original_name,
            aliased_name=aliased_name,
            object_type=object_type.upper(),
            created_at_ns=time.perf_counter_ns(),
            access_count=1,
        )
        self.aliases[key] = alias_entry
        return aliased_name

    def resolve_original(self, aliased_name: str) -> Optional[str]:
        for entry in self.aliases.values():
            if entry.aliased_name == aliased_name:
                return entry.original_name
        return None
