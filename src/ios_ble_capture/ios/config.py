"""Explicit configuration for iPhone host adapters."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from enum import StrEnum


class IosConfigurationError(ValueError):
    """Raised when an iPhone host-adapter configuration is unsafe or incomplete."""


class HostPlatform(StrEnum):
    """Platforms with supported iPhone host-adapter mechanisms."""

    LINUX = "linux"
    WSL = "wsl"
    WINDOWS = "windows"


class RsdBackend(StrEnum):
    """Remote Service Discovery transports supported by pymobiledevice3."""

    TUNNELD = "tunneld"
    USERSPACE = "userspace"


@dataclass(frozen=True, slots=True)
class IosTarget:
    """A target iPhone selected explicitly by its USB device identifier."""

    udid: str

    def __post_init__(self) -> None:
        if not self.udid or self.udid != self.udid.strip():
            raise IosConfigurationError("an iPhone UDID must be supplied explicitly")


@dataclass(frozen=True, slots=True)
class UsbIpTarget:
    """The Windows hardware identity required to hand a phone to WSL."""

    hardware_id: str

    def __post_init__(self) -> None:
        if not self.hardware_id or self.hardware_id != self.hardware_id.strip():
            raise IosConfigurationError("a USB/IP hardware ID must be supplied explicitly")


def detect_host_platform(*, system: str | None = None, release: str | None = None) -> HostPlatform:
    """Identify the supported host platform without inferring an iPhone identity."""

    host_system = (system or platform.system()).casefold()
    host_release = (release or platform.release()).casefold()
    if host_system == "windows":
        return HostPlatform.WINDOWS
    if host_system == "linux" and ("microsoft" in host_release or "wsl" in host_release):
        return HostPlatform.WSL
    if host_system == "linux":
        return HostPlatform.LINUX
    raise IosConfigurationError(f"unsupported host platform: {host_system}")
