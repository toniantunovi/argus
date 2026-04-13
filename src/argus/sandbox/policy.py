"""Sandbox security policy definitions."""
from __future__ import annotations

from dataclasses import dataclass

from argus.config import SandboxConfig


@dataclass
class SandboxPolicy:
    network: str = "none"
    read_only_rootfs: bool = True
    cap_drop: list[str] = None
    security_opt: list[str] = None
    pids_limit: int = 256
    mem_limit: str = "512m"
    cpu_quota: int = 200000
    tmpfs: dict[str, str] = None

    def __post_init__(self):
        if self.cap_drop is None:
            self.cap_drop = ["ALL"]
        if self.security_opt is None:
            self.security_opt = ["no-new-privileges:true"]
        if self.tmpfs is None:
            self.tmpfs = {"/tmp": "size=256m,exec", "/app/output": "size=64m"}

    @classmethod
    def from_config(cls, config: SandboxConfig) -> SandboxPolicy:
        return cls(
            network=config.network,
            mem_limit=config.mem_limit,
            cpu_quota=config.cpu_quota,
            pids_limit=config.pids_limit,
        )

    def to_docker_kwargs(self) -> dict:
        """Convert to docker.containers.run() kwargs."""
        kwargs = {
            "network_mode": "none" if self.network == "none" else self.network,
            "read_only": self.read_only_rootfs,
            "cap_drop": self.cap_drop,
            "security_opt": self.security_opt,
            "pids_limit": self.pids_limit,
            "mem_limit": self.mem_limit,
            "cpu_quota": self.cpu_quota,
            "tmpfs": self.tmpfs,
        }
        return kwargs
