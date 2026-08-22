"""Developer Disk Image checks and safe Windows-assisted mounting."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from ios_ble_capture.ios.process import Command

if TYPE_CHECKING:
    from ios_ble_capture.ios.config import IosTarget, UsbIpTarget


class DdiError(RuntimeError):
    """Raised when Developer Disk Image ownership or mounting is unsafe."""


class DeveloperImageState(StrEnum):
    """The DDI state observable without attempting a mount."""

    MOUNTED = "mounted"
    NOT_MOUNTED = "not_mounted"
    UNKNOWN = "unknown"


def developer_image_state(listing: str, *, mount_path: str) -> DeveloperImageState:
    """Read pymobiledevice3's JSON mounter listing without assuming a device model."""

    try:
        records = json.loads(listing)
    except json.JSONDecodeError:
        return DeveloperImageState.UNKNOWN
    if not isinstance(records, list):
        return DeveloperImageState.UNKNOWN
    for record in records:
        if isinstance(record, Mapping) and record.get("MountPath") == mount_path:
            return DeveloperImageState.MOUNTED
    return DeveloperImageState.NOT_MOUNTED


@dataclass(frozen=True, slots=True)
class DeveloperImageConfiguration:
    """Commands and expected mount path for a target-supplied iPhone."""

    target: IosTarget
    mount_path: str
    pymobiledevice3: str = "pymobiledevice3"

    def __post_init__(self) -> None:
        if not self.mount_path.startswith("/"):
            raise DdiError("the expected developer image mount path must be absolute")

    def list_command(self) -> Command:
        """List mounted developer images."""

        return Command((self.pymobiledevice3, "mounter", "list", "--udid", self.target.udid))

    def auto_mount_command(self) -> Command:
        """Ask pymobiledevice3 to mount the matching developer image."""

        return Command((self.pymobiledevice3, "mounter", "auto-mount", "--udid", self.target.udid))


@dataclass(frozen=True, slots=True)
class WindowsDdiConfiguration:
    """Windows service and USB/IP identities required for native-USB DDI mounting."""

    usbip: UsbIpTarget
    apple_mobile_device_service: str
    usbipd: str = "usbipd.exe"
    powershell: str = "powershell.exe"

    def __post_init__(self) -> None:
        if (
            not self.apple_mobile_device_service
            or self.apple_mobile_device_service != self.apple_mobile_device_service.strip()
        ):
            raise DdiError("the Windows Apple mobile-device service must be supplied explicitly")

    def hand_to_windows_commands(self) -> tuple[Command, Command]:
        """Release USB/IP and start the target-supplied Windows device service."""

        return (
            Command((self.usbipd, "unbind", "--hardware-id", self.usbip.hardware_id)),
            _service_command(self.powershell, "Start-Service", self.apple_mobile_device_service),
        )

    def hand_to_wsl_commands(self) -> tuple[Command, Command]:
        """Stop the Windows device service before sharing the phone with WSL."""

        return (
            _service_command(self.powershell, "Stop-Service", self.apple_mobile_device_service),
            Command((self.usbipd, "bind", "--force", "--hardware-id", self.usbip.hardware_id)),
        )


def _service_command(powershell: str, action: str, service: str) -> Command:
    return Command(
        (
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"{action} -Name $args[0]",
            service,
        )
    )


class WindowsDdiHandoff(Protocol):
    """Moves USB ownership for one DDI mount attempt."""

    def hand_to_windows(self) -> None:
        """Give the phone to Windows."""

    def hand_to_wsl(self) -> None:
        """Return the phone to WSL."""


def mount_with_windows_handoff(
    handoff: WindowsDdiHandoff,
    *,
    wait_for_phone: Callable[[], bool],
    mount: Callable[[], bool],
) -> bool:
    """Mount through native Windows USB and always return ownership to WSL."""

    try:
        handoff.hand_to_windows()
        return wait_for_phone() and mount()
    finally:
        handoff.hand_to_wsl()
