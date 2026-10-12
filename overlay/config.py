from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .core import MAX_FRAME_PAYLOAD


@dataclass(frozen=True, slots=True)
class OverlayConfig:
    node_id_bits: int = 256
    bucket_size: int = 3
    alpha: int = 3
    replication_factor: int = 3
    record_ttl_seconds: int = 180
    refresh_interval_seconds: int = 30
    republish_interval_seconds: int = 60
    rpc_timeout_seconds: float = 0.8
    required_relays: int = 2
    max_tunnel_hops: int = 8
    tunnel_ttl_seconds: int = 120
    max_frame_payload: int = MAX_FRAME_PAYLOAD

    def validate(self) -> None:
        if self.node_id_bits != 256:
            raise ValueError("NodeID uses SHA-256 and therefore has 256 bits")
        if self.bucket_size < 1 or self.alpha < 1 or self.replication_factor < 1:
            raise ValueError("bucket_size, alpha and replication_factor must be positive")
        if not 120 <= self.record_ttl_seconds <= 300:
            raise ValueError("record TTL must be between 120 and 300 seconds")
        if self.refresh_interval_seconds < 1 or self.republish_interval_seconds < 1:
            raise ValueError("maintenance intervals must be positive")
        if self.republish_interval_seconds > self.record_ttl_seconds / 2:
            raise ValueError("republish interval must not exceed half the record TTL")
        if self.rpc_timeout_seconds <= 0 or self.required_relays < 2:
            raise ValueError("timeout must be positive and simplified profile requires at least two relays")
        if self.max_tunnel_hops < self.required_relays or self.tunnel_ttl_seconds < 1:
            raise ValueError("invalid tunnel hop or TTL limits")
        if self.max_frame_payload != MAX_FRAME_PAYLOAD:
            raise ValueError(f"max_frame_payload is fixed at {MAX_FRAME_PAYLOAD} by the protocol")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def load(cls, path: str | Path) -> OverlayConfig:
        config = cls(**json.loads(Path(path).read_text(encoding="utf-8")))
        config.validate()
        return config


DEFAULT_CONFIG = OverlayConfig()
DEFAULT_CONFIG.validate()
