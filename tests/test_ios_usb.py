from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.ios.config import IosTarget, RsdBackend, UsbIpTarget
from ios_ble_capture.ios.process import Command, CommandResult
from ios_ble_capture.ios.usb import (
    RsdConfiguration,
    UsbMuxConfiguration,
    UsbOwnershipCleanupError,
    UsbOwnershipError,
    WslUsbIpConfiguration,
    WslUsbIpManager,
    WslUsbIpPolicy,
    resolve_usbip_bus_id,
)

if TYPE_CHECKING:
    from pathlib import Path

_HARDWARE_ID = "1234:5678"
_PRIVATE_FILE_MODE = 0o600


@dataclass
class _Runner:
    listings: list[str]
    failures: set[str] = field(default_factory=set)
    commands: list[tuple[str, ...]] = field(default_factory=list)

    def run(self, command: Command, *, timeout: float | None = None) -> CommandResult:
        del timeout
        self.commands.append(command.argv)
        operation = command.argv[1]
        if operation in self.failures:
            return CommandResult(1, "", f"{operation} failed")
        if operation == "list":
            listing = self.listings.pop(0) if len(self.listings) > 1 else self.listings[0]
            return CommandResult(0, listing, "")
        return CommandResult(0, "", "")


@dataclass
class _Probe:
    values: list[bool]

    def __call__(self) -> bool:
        return self.values.pop(0) if len(self.values) > 1 else self.values[0]


def test_wsl_usbip_uses_a_fresh_bus_id_and_release_preserves_sharing() -> None:
    handoff = WslUsbIpConfiguration(UsbIpTarget(_HARDWARE_ID))

    assert handoff.attach_command(bus_id="4-1").argv == ("usbipd.exe", "attach", "--wsl", "--busid", "4-1")
    assert handoff.release_command().argv == ("usbipd.exe", "detach", "--hardware-id", _HARDWARE_ID)


def test_rsd_commands_preserve_the_selected_transport_and_usbmux_socket() -> None:
    target = IosTarget("00000000-0000000000000000")
    userspace = RsdConfiguration(target, RsdBackend.USERSPACE)
    tunneld = RsdConfiguration(target, RsdBackend.TUNNELD, usbmuxd_socket="/run/usbmuxd")

    assert userspace.developer_dvt_command("screenshot", "screen.png").argv[-3:] == (
        "--userspace",
        "--udid",
        target.udid,
    )
    assert tunneld.developer_dvt_command("screenshot", "screen.png").argv[-2:] == ("--tunnel", target.udid)
    assert tunneld.tunneld_command().environment == {"USBMUXD_SOCKET_ADDRESS": "/run/usbmuxd"}


def test_usbmux_port_forwarding_validates_both_endpoints() -> None:
    command = UsbMuxConfiguration(IosTarget("00000000-0000000000000000")).forward_command(
        local_port=8100,
        device_port=8100,
    )

    assert command.argv == (
        "pymobiledevice3",
        "usbmux",
        "forward",
        "8100",
        "8100",
        "--udid",
        "00000000-0000000000000000",
    )


def test_bus_id_resolution_requires_one_exact_hardware_match() -> None:
    listing = "BUSID  VID:PID  DEVICE\n4-1    1234:5678 Phone\n5-2    abcd:ef01 Other\n"

    assert resolve_usbip_bus_id(listing, hardware_id=_HARDWARE_ID) == "4-1"

    with pytest.raises(UsbOwnershipError, match="no USB device"):
        resolve_usbip_bus_id(listing, hardware_id="9999:0000")
    with pytest.raises(UsbOwnershipError, match="multiple"):
        resolve_usbip_bus_id(f"{listing}6-3 1234:5678 Phone\n", hardware_id=_HARDWARE_ID)


def test_manager_re_resolves_bus_id_and_records_private_ownership(tmp_path: Path) -> None:
    runner = _Runner(
        [
            "BUSID VID:PID DEVICE\n",
            "BUSID VID:PID DEVICE\n4-1 1234:5678 Phone\n",
        ]
    )
    phone = _Probe([False, False, True])
    state = tmp_path / "ownership" / "usb.json"
    manager = WslUsbIpManager(
        WslUsbIpConfiguration(UsbIpTarget(_HARDWARE_ID)),
        runner=runner,
        phone_present=phone,
        mux_ready=lambda: True,
        policy=WslUsbIpPolicy(wait_attempts=2, wait_delay=0, attach_attempts=1),
        state_path=state,
        sleeper=lambda _delay: None,
    )

    assert manager.acquire() == "4-1"
    assert [command[1] for command in runner.commands] == ["bind", "list", "list", "attach"]
    assert json.loads(state.read_text()) == {
        "bus_id": "4-1",
        "detach_required": True,
        "hardware_id": _HARDWARE_ID,
    }
    assert state.stat().st_mode & 0o777 == _PRIVATE_FILE_MODE
    manager.release()
    assert runner.commands[-1][1] == "detach"
    assert not state.exists()


def test_manager_refuses_to_claim_a_pre_existing_attachment(tmp_path: Path) -> None:
    runner = _Runner(["4-1 1234:5678 Phone\n"])
    manager = WslUsbIpManager(
        WslUsbIpConfiguration(UsbIpTarget(_HARDWARE_ID)),
        runner=runner,
        phone_present=lambda: True,
        mux_ready=lambda: True,
        state_path=tmp_path / "usb.json",
    )

    with pytest.raises(UsbOwnershipError, match="already attached"):
        manager.acquire()

    assert runner.commands == []
    assert not (tmp_path / "usb.json").exists()


def test_manager_accepts_existing_attachment_without_detaching_it(tmp_path: Path) -> None:
    runner = _Runner(["4-1 1234:5678 Phone\n"])
    state = tmp_path / "usb.json"
    manager = WslUsbIpManager(
        WslUsbIpConfiguration(UsbIpTarget(_HARDWARE_ID)),
        runner=runner,
        phone_present=lambda: True,
        mux_ready=lambda: True,
        state_path=state,
        accept_existing=True,
    )

    assert manager.acquire() == "4-1"
    assert json.loads(state.read_text())["detach_required"] is False
    manager.release()
    assert [command[1] for command in runner.commands] == ["list"]


def test_manager_recovers_owned_attachment_and_detaches_after_restart(
    tmp_path: Path,
) -> None:
    state = tmp_path / "usb.json"
    first_runner = _Runner(["4-1 1234:5678 Phone\n"])
    first = WslUsbIpManager(
        WslUsbIpConfiguration(UsbIpTarget(_HARDWARE_ID)),
        runner=first_runner,
        phone_present=_Probe([False, True]),
        mux_ready=lambda: True,
        policy=WslUsbIpPolicy(wait_attempts=1, wait_delay=0, attach_attempts=1),
        state_path=state,
    )
    assert first.acquire() == "4-1"
    assert json.loads(state.read_text())["detach_required"] is True

    resumed_runner = _Runner(["7-2 1234:5678 Phone\n"])
    resumed = WslUsbIpManager(
        WslUsbIpConfiguration(UsbIpTarget(_HARDWARE_ID)),
        runner=resumed_runner,
        phone_present=lambda: True,
        mux_ready=lambda: True,
        state_path=state,
    )
    assert resumed.acquire() == "7-2"
    resumed.release()

    assert [command[1] for command in resumed_runner.commands] == ["list", "detach"]
    assert not state.exists()


def test_manager_releases_after_an_attach_failure(tmp_path: Path) -> None:
    runner = _Runner(["4-1 1234:5678 Phone\n"], failures={"attach"})
    manager = WslUsbIpManager(
        WslUsbIpConfiguration(UsbIpTarget(_HARDWARE_ID)),
        runner=runner,
        phone_present=lambda: False,
        mux_ready=lambda: True,
        policy=WslUsbIpPolicy(wait_attempts=1, wait_delay=0, attach_attempts=1),
        state_path=tmp_path / "usb.json",
    )

    with pytest.raises(UsbOwnershipError, match="USB/IP attach"):
        manager.acquire()

    assert [command[1] for command in runner.commands] == [
        "bind",
        "list",
        "attach",
        "detach",
    ]


def test_manager_surfaces_cleanup_failure_with_primary_error(tmp_path: Path) -> None:
    runner = _Runner(
        ["4-1 1234:5678 Phone\n"],
        failures={"attach", "detach"},
    )
    manager = WslUsbIpManager(
        WslUsbIpConfiguration(UsbIpTarget(_HARDWARE_ID)),
        runner=runner,
        phone_present=lambda: False,
        mux_ready=lambda: True,
        policy=WslUsbIpPolicy(wait_attempts=1, wait_delay=0, attach_attempts=1),
        state_path=tmp_path / "usb.json",
    )

    with pytest.raises(UsbOwnershipCleanupError) as raised:
        manager.acquire()

    assert isinstance(raised.value.primary_error, UsbOwnershipError)
    assert isinstance(raised.value.cleanup_error, UsbOwnershipError)
