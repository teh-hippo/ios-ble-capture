"""usbmuxd, Remote Service Discovery and WSL USB/IP command specifications."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from ios_ble_capture.ios.config import IosTarget, RsdBackend, UsbIpTarget
from ios_ble_capture.ios.process import Command, CommandRunner

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


class UsbConfigurationError(ValueError):
    """Raised when USB hand-off configuration is incomplete."""


class UsbOwnershipError(RuntimeError):
    """Raised when USB ownership cannot be acquired or released safely."""


class UsbOwnershipCleanupError(UsbOwnershipError):
    """Raised when ownership cleanup fails while handling another failure."""

    def __init__(self, primary_error: BaseException, cleanup_error: UsbOwnershipError) -> None:
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error
        super().__init__(f"USB ownership cleanup failed while handling {type(primary_error).__name__}: {primary_error}")


MAX_TCP_PORT = 65_535
_MIN_USBIP_LIST_FIELDS = 2


@dataclass(frozen=True, slots=True)
class UsbMuxConfiguration:
    """usbmuxd commands for one explicitly selected iPhone."""

    target: IosTarget
    pymobiledevice3: str = "pymobiledevice3"

    def list_devices_command(self) -> Command:
        """List USB devices visible to the current usbmuxd daemon."""

        return Command((self.pymobiledevice3, "usbmux", "list"))

    def lockdown_info_command(self) -> Command:
        """Probe the selected phone through the current usbmuxd daemon."""

        return Command((self.pymobiledevice3, "lockdown", "info", "--udid", self.target.udid))

    def forward_command(self, *, local_port: int, device_port: int) -> Command:
        """Forward one local TCP port to a device port through usbmuxd."""

        _require_port(local_port, "local")
        _require_port(device_port, "device")
        return Command(
            (
                self.pymobiledevice3,
                "usbmux",
                "forward",
                str(local_port),
                str(device_port),
                "--udid",
                self.target.udid,
            )
        )


@dataclass(frozen=True, slots=True)
class RsdConfiguration:
    """Remote Service Discovery connection settings."""

    target: IosTarget
    backend: RsdBackend
    pymobiledevice3: str = "pymobiledevice3"
    usbmuxd_socket: str | None = None

    def tunneld_command(self) -> Command:
        """Start a TCP tunneld process with the selected usbmuxd socket, if any."""

        if self.backend is not RsdBackend.TUNNELD:
            raise UsbConfigurationError("userspace RSD does not start tunneld")
        environment = {} if self.usbmuxd_socket is None else {"USBMUXD_SOCKET_ADDRESS": self.usbmuxd_socket}
        return Command((self.pymobiledevice3, "remote", "tunneld", "--protocol", "tcp"), environment=environment)

    def developer_dvt_command(self, *arguments: str) -> Command:
        """Build a DVT command for the selected RSD backend."""

        suffix = (
            ("--userspace", "--udid", self.target.udid)
            if self.backend is RsdBackend.USERSPACE
            else ("--tunnel", self.target.udid)
        )
        return Command((self.pymobiledevice3, "developer", "dvt", *arguments, *suffix))


@dataclass(frozen=True, slots=True)
class WslUsbIpConfiguration:
    """USB/IP commands used to borrow an iPhone from Windows for WSL."""

    target: UsbIpTarget
    usbipd: str = "usbipd.exe"

    def list_command(self) -> Command:
        """List current USB/IP devices and their re-enumerated bus identities."""

        return Command((self.usbipd, "list"))

    def bind_command(self) -> Command:
        """Force-share the configured hardware identity from Windows."""

        return Command((self.usbipd, "bind", "--force", "--hardware-id", self.target.hardware_id))

    def attach_command(self, *, bus_id: str) -> Command:
        """Attach a freshly resolved USB/IP bus identity to WSL."""

        if not bus_id or bus_id != bus_id.strip():
            raise UsbConfigurationError("a current USB/IP bus ID is required for attachment")
        return Command((self.usbipd, "attach", "--wsl", "--busid", bus_id))

    def release_command(self) -> Command:
        """Detach WSL while preserving Windows' existing USB/IP sharing state."""

        return Command((self.usbipd, "detach", "--hardware-id", self.target.hardware_id))


@dataclass(frozen=True, slots=True)
class WslUsbIpPolicy:
    """Bounded retry settings for one USB/IP ownership transaction."""

    wait_attempts: int = 12
    wait_delay: float = 0.5
    attach_attempts: int = 3

    def __post_init__(self) -> None:
        if self.wait_attempts < 1 or self.attach_attempts < 1:
            raise UsbConfigurationError("USB/IP retry counts must be positive")
        if self.wait_delay < 0:
            raise UsbConfigurationError("USB/IP retry delay cannot be negative")


DEFAULT_WSL_USBIP_POLICY = WslUsbIpPolicy()


class UsbPresenceProbe(Protocol):
    """Reports whether native usbmuxd can see the selected phone."""

    def __call__(self) -> bool: ...


class WslUsbIpManager:
    """Acquire WSL USB ownership and guarantee release after partial failure."""

    def __init__(  # noqa: PLR0913
        self,
        configuration: WslUsbIpConfiguration,
        *,
        runner: CommandRunner,
        phone_present: UsbPresenceProbe,
        mux_ready: UsbPresenceProbe,
        policy: WslUsbIpPolicy | None = None,
        state_path: Path | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        accept_existing: bool = False,
    ) -> None:
        self._configuration = configuration
        self._runner = runner
        self._phone_present = phone_present
        self._mux_ready = mux_ready
        self._policy = policy or DEFAULT_WSL_USBIP_POLICY
        self._state_path = state_path
        self._sleeper = sleeper
        self._accept_existing = accept_existing
        self._bus_id: str | None = None
        self._detach_required = False

    @property
    def bus_id(self) -> str | None:
        """Return the bus identity recorded for the active hand-off."""

        return self._bus_id

    def acquire(self) -> str:
        """Attach the configured phone to WSL and verify native usbmuxd."""

        if self._bus_id is not None:
            return self._bus_id

        ownership_attempted = False
        try:
            if self._phone_present():
                state = self._load_state()
                if state is None:
                    self._require_existing_accepted()
                else:
                    self._detach_required = state["detach_required"] is True
                bus_id = self._wait_for_bus_id()
            else:
                ownership_attempted = True
                self._require_success(
                    self._configuration.bind_command(),
                    "USB/IP force-bind",
                )
                bus_id = self._attach()
            self._record(bus_id, detach_required=self._detach_required)
            self._require_mux(bus_id)
        except BaseException as primary_error:
            if (
                ownership_attempted
                or self._bus_id is not None
                or (self._state_path is not None and self._state_path.exists())
            ):
                try:
                    self.release(force=True)
                except UsbOwnershipError as cleanup_error:
                    raise UsbOwnershipCleanupError(primary_error, cleanup_error) from primary_error
            raise
        else:
            return bus_id

    def release(self, *, force: bool = False) -> None:
        """Detach the phone from WSL while preserving Windows sharing."""

        state = self._load_state()
        if not force and self._bus_id is None and state is None:
            return
        detach_required = self._detach_required or (state is not None and state["detach_required"])
        if detach_required:
            self._require_success(
                self._configuration.release_command(),
                "USB/IP detach",
            )
        self._bus_id = None
        self._detach_required = False
        if self._state_path is not None:
            self._state_path.unlink(missing_ok=True)

    def _attach(self) -> str:
        last_bus_id: str | None = None
        for attempt in range(self._policy.attach_attempts):
            last_bus_id = self._wait_for_bus_id()
            self._detach_required = True
            self._require_success(
                self._configuration.attach_command(bus_id=last_bus_id),
                "USB/IP attach",
            )
            for settle in range(self._policy.wait_attempts):
                if self._phone_present():
                    return last_bus_id
                if settle + 1 < self._policy.wait_attempts:
                    self._sleeper(self._policy.wait_delay)
            if attempt + 1 < self._policy.attach_attempts:
                self._sleeper(self._policy.wait_delay)
        raise UsbOwnershipError(
            "the phone never reached WSL's USB tree"
            + (f"; last bus ID {last_bus_id}" if last_bus_id is not None else "")
        )

    def _wait_for_bus_id(self) -> str:
        last_error: UsbOwnershipError | None = None
        for attempt in range(self._policy.wait_attempts):
            result = self._runner.run(self._configuration.list_command())
            if result.returncode == 0:
                try:
                    return resolve_usbip_bus_id(
                        result.stdout,
                        hardware_id=self._configuration.target.hardware_id,
                    )
                except UsbOwnershipError as error:
                    last_error = error
            else:
                detail = (result.stderr or result.stdout).strip()
                last_error = UsbOwnershipError(f"usbipd could not list USB devices: {detail or result.returncode}")
            if attempt + 1 < self._policy.wait_attempts:
                self._sleeper(self._policy.wait_delay)
        raise UsbOwnershipError(
            f"phone {self._configuration.target.hardware_id} did not re-enumerate for USB/IP"
        ) from last_error

    def _record(self, bus_id: str, *, detach_required: bool) -> None:
        self._bus_id = bus_id
        if self._state_path is None:
            return
        if self._state_path.is_symlink():
            raise UsbOwnershipError(
                f"refusing to write USB ownership state through a symbolic link: {self._state_path}"
            )
        self._state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._state_path.parent.chmod(0o700)
        descriptor = os.open(
            self._state_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(
                {
                    "bus_id": bus_id,
                    "detach_required": detach_required,
                    "hardware_id": self._configuration.target.hardware_id,
                },
                output,
                sort_keys=True,
            )
            output.write("\n")

    def _load_state(self) -> dict[str, bool | str] | None:
        if self._state_path is None or not self._state_path.is_file():
            return None
        if self._state_path.is_symlink():
            raise UsbOwnershipError(f"refusing to read USB ownership state through a symbolic link: {self._state_path}")
        try:
            state = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise UsbOwnershipError(f"cannot read USB ownership state: {error}") from error
        if (
            not isinstance(state, dict)
            or state.get("hardware_id") != self._configuration.target.hardware_id
            or not isinstance(state.get("bus_id"), str)
            or not isinstance(state.get("detach_required"), bool)
        ):
            raise UsbOwnershipError("USB ownership state does not match the configured phone")
        return {
            "bus_id": state["bus_id"],
            "detach_required": state["detach_required"],
            "hardware_id": state["hardware_id"],
        }

    def _require_mux(self, bus_id: str) -> None:
        if not self._mux_ready():
            raise UsbOwnershipError(f"native usbmuxd cannot serve the attached phone on bus {bus_id}")

    def _require_existing_accepted(self) -> None:
        if not self._accept_existing:
            raise UsbOwnershipError(
                "the phone is already attached to WSL; set accept_existing=True to use it without detaching it"
            )

    def _require_success(self, command: Command, operation: str) -> None:
        result = self._runner.run(command)
        if result.returncode == 0:
            return
        detail = (result.stderr or result.stdout).strip()
        raise UsbOwnershipError(f"{operation} failed: {detail or f'exit code {result.returncode}'}")


def resolve_usbip_bus_id(listing: str, *, hardware_id: str) -> str:
    """Resolve one current bus ID for an exact hardware identity."""

    target = hardware_id.casefold()
    matches = [
        fields[0]
        for line in listing.replace("\r", "").splitlines()
        if len(fields := line.split()) >= _MIN_USBIP_LIST_FIELDS and fields[1].casefold() == target
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise UsbOwnershipError(f"no USB device with hardware ID {hardware_id} is available to usbipd")
    raise UsbOwnershipError(f"usbipd found multiple devices with hardware ID {hardware_id}")


def _require_port(port: int, name: str) -> None:
    if not 1 <= port <= MAX_TCP_PORT:
        raise UsbConfigurationError(f"{name} port must be between 1 and {MAX_TCP_PORT}")
