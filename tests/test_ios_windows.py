from __future__ import annotations

from pathlib import Path

from ios_ble_capture.ios.config import IosTarget
from ios_ble_capture.ios.windows import (
    WindowsPhoneAction,
    WindowsPhoneConfiguration,
)


def test_windows_wda_forwarding_selects_the_explicit_phone() -> None:
    target = IosTarget("00000000-0000000000000000")
    configuration = WindowsPhoneConfiguration(
        target=target,
        python=Path("python.exe"),
        wda_port=8100,
        display_port=8080,
    )

    assert configuration.command(WindowsPhoneAction.WDA_FORWARD).argv[-2:] == (
        "--udid",
        target.udid,
    )
