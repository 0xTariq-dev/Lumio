from __future__ import annotations

import os
import re
from dataclasses import dataclass


_IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-fA-F]{64}$")
_LOCAL_IMAGE_REFERENCE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)


def _positive_int(name: str, default: int, *, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 1 or value > maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


@dataclass(frozen=True)
class WorkerSettings:
    token: str | None
    guest_image: str | None
    guest_image_local: str | None = None
    sandbox_cpus: int = 1
    sandbox_memory_mib: int = 2048
    browser_timeout_seconds: int = 90
    sandbox_kill_seconds: int = 180
    queue_limit: int = 10
    report_ttl_seconds: int = 900
    request_body_limit_bytes: int = 15 * 1024 * 1024

    @classmethod
    def from_env(cls) -> WorkerSettings:
        return cls(
            token=os.getenv("ANALYSIS_WORKER_TOKEN"),
            guest_image=os.getenv("ANALYSIS_GUEST_IMAGE"),
            guest_image_local=os.getenv("ANALYSIS_GUEST_IMAGE_LOCAL"),
            sandbox_cpus=_positive_int("ANALYSIS_SANDBOX_CPUS", 1, maximum=8),
            sandbox_memory_mib=_positive_int(
                "ANALYSIS_SANDBOX_MEMORY_MIB", 2048, maximum=8192
            ),
        )

    @property
    def is_configured(self) -> bool:
        return bool(
            self.token
            and len(self.token) >= 32
            and self.token.isascii()
            and self.guest_image
            and _IMAGE_DIGEST.fullmatch(self.guest_image)
            and (
                self.guest_image_local is None
                or _LOCAL_IMAGE_REFERENCE.fullmatch(self.guest_image_local)
            )
        )
