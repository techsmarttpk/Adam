"""Attention-Based Security Event Encoder with Flood Filtering & Deduplication.

Computes contextual state embeddings:
    h_i = Attention(W_q * e_i, K, V)
Transforms streaming Sysmon/VMI telemetry into fixed-dimension state vectors for the DRL agent.
Includes anti-poisoning telemetry filtering and sliding-window event deduplication to prevent
malware event-flooding attacks.
"""

from __future__ import annotations
import dataclasses
import math
from typing import Dict, List, Optional, Tuple


@dataclasses.dataclass
class SecurityEventToken:
    event_type: str  # PROCESS_CREATE, MEM_INJECT, REG_QUERY, NET_CONNECT, etc.
    source_pid: int
    target: str
    severity: float  # 0.0 to 1.0
    repeat_count: int = 1
    timestamp_ns: int = 0


class TelemetryFilter:
    """Sliding-window event deduplication pipeline.

    Collapses repetitive API sequences (e.g. 500 RegQueryValue calls)
    into high-level token abstractions to thwart event-flooding and buffer overflow.
    """

    def __init__(self, window_size: int = 50, max_token_rate_per_sec: int = 100) -> None:
        self.window_size = window_size
        self.max_token_rate_per_sec = max_token_rate_per_sec
        self.recent_events: List[SecurityEventToken] = []

    def ingest_event(
        self, event_type: str, source_pid: int, target: str, severity: float, timestamp_ns: int
    ) -> Optional[SecurityEventToken]:
        """Deduplicate bursts of identical events within the sliding window."""
        if self.recent_events:
            last = self.recent_events[-1]
            if last.event_type == event_type and last.source_pid == source_pid and last.target == target:
                last.repeat_count += 1
                return None  # Collapsed into previous token

        token = SecurityEventToken(
            event_type=event_type,
            source_pid=source_pid,
            target=target,
            severity=severity,
            repeat_count=1,
            timestamp_ns=timestamp_ns,
        )
        self.recent_events.append(token)
        if len(self.recent_events) > self.window_size:
            self.recent_events.pop(0)
        return token

    def get_window_tokens(self) -> List[SecurityEventToken]:
        return list(self.recent_events)


class AttentionEventEncoder:
    """Attention-based encoder mapping variable-length security event streams

    into fixed-size embedding representations for the reinforcement learning policy.
    """

    EVENT_TYPES = [
        "PROCESS_CREATE",
        "PROCESS_HOLLOWING",
        "MEM_INJECT_RWX",
        "REG_QUERY",
        "REG_WRITE",
        "FILE_DROP",
        "NET_DNS_QUERY",
        "NET_CONNECT",
        "MUTEX_OPEN",
        "SYSCALL_DISPATCH",
        "EPT_TRAP",
    ]

    def __init__(self, embedding_dim: int = 16, max_sequence_len: int = 32) -> None:
        self.embedding_dim = embedding_dim
        self.max_sequence_len = max_sequence_len
        self.filter = TelemetryFilter(window_size=max_sequence_len)
        self.type_to_idx = {t: idx for idx, t in enumerate(self.EVENT_TYPES)}

    def _event_to_vector(self, token: SecurityEventToken) -> List[float]:
        """Convert a security event token into an embedding vector."""
        vec = [0.0] * self.embedding_dim
        type_idx = self.type_to_idx.get(token.event_type, len(self.EVENT_TYPES)) % (self.embedding_dim // 2)
        vec[type_idx] = 1.0
        vec[-1] = min(1.0, math.log1p(token.repeat_count) / 5.0)  # Log-normalized count
        vec[-2] = token.severity
        vec[-3] = (token.source_pid % 1000) / 1000.0
        return vec

    def compute_attention_embedding(self, raw_events: List[Dict[str, object]]) -> List[float]:
        """Process event stream through deduplication filter and compute attention vector:

        h = softmax(Q * K^T / sqrt(d)) * V
        """
        tokens = []
        for ev in raw_events:
            tok = self.filter.ingest_event(
                event_type=str(ev.get("type", "PROCESS_CREATE")),
                source_pid=int(ev.get("pid", 0)),
                target=str(ev.get("target", "")),
                severity=float(ev.get("severity", 0.5)),
                timestamp_ns=int(ev.get("timestamp_ns", 0)),
            )
            if tok:
                tokens.append(tok)

        window = self.filter.get_window_tokens()
        if not window:
            return [0.0] * self.embedding_dim

        # Compute vectors for tokens
        vectors = [self._event_to_vector(t) for t in window]

        # Scaled dot-product self-attention approximation across tokens
        dim = self.embedding_dim
        sqrt_d = math.sqrt(dim)

        # Average Query / Key projections
        query = vectors[-1]  # Latest event as query
        scores = []
        for key in vectors:
            dot = sum(q * k for q, k in zip(query, key))
            scores.append(dot / sqrt_d)

        # Softmax
        max_score = max(scores) if scores else 0.0
        exp_scores = [math.exp(s - max_score) for s in scores]
        sum_exp = sum(exp_scores)
        attn_weights = [e / sum_exp for e in exp_scores] if sum_exp > 0 else [1.0 / len(vectors)] * len(vectors)

        # Weighted value sum
        context_vector = [0.0] * dim
        for weight, val in zip(attn_weights, vectors):
            for i in range(dim):
                context_vector[i] += weight * val[i]

        return [round(v, 4) for v in context_vector]
