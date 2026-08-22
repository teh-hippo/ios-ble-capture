from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.ios.capture import (
    CaptureBackend,
    CaptureConfigurationError,
    build_capture_plan,
    select_capture_backend,
)
from ios_ble_capture.ios.config import HostPlatform, IosTarget

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("host", "backend"),
    [
        (HostPlatform.LINUX, CaptureBackend.PYMOBILEDEVICE3),
        (HostPlatform.WSL, CaptureBackend.IDEVICEBTLOGGER),
    ],
)
def test_supported_capture_hosts_have_an_explicit_backend(host: HostPlatform, backend: CaptureBackend) -> None:
    assert select_capture_backend(host=host) is backend


def test_wsl_selects_the_classic_logger_that_owns_its_usbmuxd_connection(tmp_path: Path) -> None:
    target = IosTarget("00000000-0000000000000000")

    plan = build_capture_plan(
        target=target,
        host=HostPlatform.WSL,
        output=tmp_path / "capture",
    )

    assert plan.backend is CaptureBackend.IDEVICEBTLOGGER
    assert plan.output == tmp_path / "capture.pcap"
    assert plan.command.argv == (
        "idevicebtlogger",
        "-u",
        target.udid,
        "-f",
        "pcap",
        "-x",
        str(tmp_path / "capture.pcap"),
    )


def test_native_linux_selects_pymobiledevice3_pcapng(tmp_path: Path) -> None:
    target = IosTarget("00000000-0000000000000000")
    plan = build_capture_plan(
        target=target,
        host=HostPlatform.LINUX,
        output=tmp_path / "capture.any",
    )

    assert plan.backend is CaptureBackend.PYMOBILEDEVICE3
    assert plan.command.argv == (
        "pymobiledevice3",
        "btlogger",
        "--format",
        "pcapng",
        "--udid",
        target.udid,
        str(tmp_path / "capture.pcapng"),
    )


def test_windows_is_not_mistaken_for_a_physical_capture_backend() -> None:
    with pytest.raises(CaptureConfigurationError, match="cannot capture"):
        select_capture_backend(host=HostPlatform.WINDOWS)
