"""Windows-side iPhone assistance command specifications."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from ios_ble_capture.ios.process import Command

if TYPE_CHECKING:
    from pathlib import Path

    from ios_ble_capture.ios.config import IosTarget


MAX_TCP_PORT = 65_535


class WindowsPhoneAction(StrEnum):
    """Persistent phone services which Windows can own."""

    TUNNELD = "tunneld"
    DISPLAY_WEB = "display_web"
    WDA_FORWARD = "wda_forward"


@dataclass(frozen=True, slots=True)
class WindowsPhoneConfiguration:
    """Commands for target-supplied Windows Python and iPhone identifiers."""

    target: IosTarget
    python: Path
    wda_port: int
    display_port: int

    def __post_init__(self) -> None:
        for name, port in (("WDA", self.wda_port), ("display", self.display_port)):
            if not 1 <= port <= MAX_TCP_PORT:
                raise ValueError(f"{name} port must be between 1 and {MAX_TCP_PORT}")

    def command(self, action: WindowsPhoneAction) -> Command:
        """Build the Windows command for one supported phone service."""

        prefix = (str(self.python), "-m", "pymobiledevice3")
        if action is WindowsPhoneAction.TUNNELD:
            return Command((*prefix, "remote", "tunneld", "--protocol", "tcp"))
        if action is WindowsPhoneAction.DISPLAY_WEB:
            return Command(
                (
                    *prefix,
                    "developer",
                    "core-device",
                    "display",
                    "serve-web",
                    "--bind",
                    "127.0.0.1",
                    "--http-port",
                    str(self.display_port),
                    "--tunnel",
                    self.target.udid,
                )
            )
        return Command(
            (
                *prefix,
                "usbmux",
                "forward",
                str(self.wda_port),
                str(self.wda_port),
                "--udid",
                self.target.udid,
            )
        )
