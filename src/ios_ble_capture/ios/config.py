"""Explicit configuration for iPhone host adapters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class IosConfigurationError(ValueError):
    """Raised when an iPhone host-adapter configuration is unsafe or incomplete."""


class HostPlatform(StrEnum):
    """Platforms with supported iPhone host-adapter mechanisms."""

    LINUX = "linux"
    WSL = "wsl"
    WINDOWS = "windows"


@dataclass(frozen=True, slots=True)
class IosTarget:
    """A target iPhone selected explicitly by its USB device identifier."""

    udid: str

    def __post_init__(self) -> None:
        if not self.udid or self.udid != self.udid.strip():
            raise IosConfigurationError("an iPhone UDID must be supplied explicitly")
