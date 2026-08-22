from __future__ import annotations

import pytest

from ios_ble_capture.ios.ddi import mount_with_windows_handoff


class _Handoff:
    def __init__(self, *, fail_to_windows: bool = False) -> None:
        self.events: list[str] = []
        self.fail_to_windows = fail_to_windows

    def hand_to_windows(self) -> None:
        self.events.append("windows")
        if self.fail_to_windows:
            raise RuntimeError("partial handoff")

    def hand_to_wsl(self) -> None:
        self.events.append("wsl")


def test_failed_windows_ddi_mount_returns_usb_ownership_to_wsl() -> None:
    handoff = _Handoff()

    mounted = mount_with_windows_handoff(
        handoff,
        wait_for_phone=lambda: True,
        mount=lambda: False,
    )

    assert mounted is False
    assert handoff.events == ["windows", "wsl"]


def test_partial_windows_handoff_failure_still_restores_wsl() -> None:
    handoff = _Handoff(fail_to_windows=True)

    with pytest.raises(RuntimeError, match="partial handoff"):
        mount_with_windows_handoff(
            handoff,
            wait_for_phone=lambda: True,
            mount=lambda: True,
        )

    assert handoff.events == ["windows", "wsl"]
