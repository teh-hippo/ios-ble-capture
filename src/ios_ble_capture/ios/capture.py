"""Native-host Bluetooth packet-capture command specifications."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from ios_ble_capture.ios.config import HostPlatform
from ios_ble_capture.ios.process import Command

if TYPE_CHECKING:
    from pathlib import Path

    from ios_ble_capture.ios.config import IosTarget


class CaptureConfigurationError(ValueError):
    """Raised when a capture backend cannot safely run on the selected host."""


class CaptureBackend(StrEnum):
    """Supported iPhone Bluetooth logger backends."""

    IDEVICEBTLOGGER = "idevicebtlogger"
    PYMOBILEDEVICE3 = "pymobiledevice3"


@dataclass(frozen=True, slots=True)
class CapturePlan:
    """The backend, output format and command for one capture process."""

    backend: CaptureBackend
    output: Path
    command: Command

    @property
    def format(self) -> str:
        """Return the packet-capture format emitted by the selected backend."""

        return "pcap" if self.backend is CaptureBackend.IDEVICEBTLOGGER else "pcapng"


@dataclass(frozen=True, slots=True)
class CaptureTools:
    """Host commands used by the supported physical capture backends."""

    idevicebtlogger: str = "idevicebtlogger"
    pymobiledevice3: str = "pymobiledevice3"


DEFAULT_CAPTURE_TOOLS = CaptureTools()


def select_capture_backend(*, host: HostPlatform) -> CaptureBackend:
    """Select the logger which can reach the host's usbmuxd ownership domain."""

    match host:
        case HostPlatform.LINUX:
            return CaptureBackend.PYMOBILEDEVICE3
        case HostPlatform.WSL:
            return CaptureBackend.IDEVICEBTLOGGER
        case HostPlatform.WINDOWS:
            raise CaptureConfigurationError(
                "windows cannot capture Bluetooth packets. Use a native Linux or WSL capture host."
            )


def build_capture_plan(
    *,
    target: IosTarget,
    host: HostPlatform,
    output: Path,
    tools: CaptureTools = DEFAULT_CAPTURE_TOOLS,
) -> CapturePlan:
    """Build a physical-capture command without starting it."""

    backend = select_capture_backend(host=host)
    if backend is CaptureBackend.IDEVICEBTLOGGER:
        path = output.with_suffix(".pcap")
        command = Command((tools.idevicebtlogger, "-u", target.udid, "-f", "pcap", "-x", str(path)))
    else:
        path = output.with_suffix(".pcapng")
        command = Command(
            (
                tools.pymobiledevice3,
                "btlogger",
                "--format",
                "pcapng",
                "--udid",
                target.udid,
                str(path),
            )
        )
    return CapturePlan(backend=backend, output=path, command=command)
