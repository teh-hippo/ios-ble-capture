# ruff: noqa: ASYNC109

from __future__ import annotations

import asyncio
import importlib
from dataclasses import dataclass
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.ble import (
    ActiveBleBackend,
    BleConfigurationError,
    BleError,
    BleFrameSizeError,
    BleSession,
    NotificationCallback,
    connect,
    scan,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_SERVICE_UUID = "00000000-0000-0000-0000-000000000001"
_CHARACTERISTIC_UUID = "00000000-0000-0000-0000-000000000002"
_SCAN_TIMEOUT = 3
_CHARACTERISTIC = object()


class FakeBackend(ActiveBleBackend):
    def __init__(self) -> None:
        self.connected: tuple[str, float] | None = None
        self.closed = False
        self.reads: list[tuple[str, str]] = []
        self.writes: list[tuple[str, str, bytes, bool]] = []
        self.notifications: tuple[str, str, NotificationCallback] | None = None

    async def connect(self, address: str, timeout: float) -> None:
        self.connected = (address, timeout)

    async def close(self) -> None:
        self.closed = True

    async def read(self, service_uuid: str, characteristic_uuid: str) -> bytes:
        self.reads.append((service_uuid, characteristic_uuid))
        return b"\x01\x02"

    async def write(
        self,
        service_uuid: str,
        characteristic_uuid: str,
        data: bytes,
        *,
        response: bool,
    ) -> None:
        self.writes.append((service_uuid, characteristic_uuid, data, response))

    async def start_notify(
        self,
        service_uuid: str,
        characteristic_uuid: str,
        callback: NotificationCallback,
    ) -> None:
        self.notifications = (service_uuid, characteristic_uuid, callback)

    async def stop_notify(self, service_uuid: str, characteristic_uuid: str) -> None:
        assert self.notifications is not None
        assert (service_uuid, characteristic_uuid) == self.notifications[:2]

    def emit(self, payload: bytes) -> None:
        assert self.notifications is not None
        self.notifications[2](payload)


@dataclass
class FakeDevice:
    address: str
    name: str | None


@dataclass
class FakeAdvertisement:
    local_name: str | None
    rssi: int | None
    service_uuids: tuple[str, ...]


class FakeScanner:
    async def discover(self, timeout: float) -> Mapping[str, object]:
        assert timeout == _SCAN_TIMEOUT
        return {
            "BB:BB": (
                FakeDevice(address="BB:BB", name="fallback"),
                FakeAdvertisement(local_name="second", rssi=-70, service_uuids=(_SERVICE_UUID,)),
            ),
            "AA:AA": (
                FakeDevice(address="AA:AA", name="first"),
                FakeAdvertisement(local_name=None, rssi=-40, service_uuids=()),
            ),
        }


class _BleakService:
    def get_characteristic(self, characteristic_uuid: str) -> object | None:
        return _CHARACTERISTIC if characteristic_uuid == _CHARACTERISTIC_UUID else None


class _BleakServices:
    def get_service(self, service_uuid: str) -> _BleakService | None:
        return _BleakService() if service_uuid == _SERVICE_UUID else None


class _BleakClient:
    last_read: object | None = None

    def __init__(self, address: str, *, timeout: float) -> None:
        self.address = address
        self.timeout = timeout
        self.services = _BleakServices()

    async def connect(self) -> None:
        return

    async def disconnect(self) -> None:
        return

    async def read_gatt_char(self, characteristic: object) -> bytes:
        type(self).last_read = characteristic
        return b"\x01"

    async def write_gatt_char(
        self,
        characteristic: object,
        data: bytes,
        *,
        response: bool,
    ) -> None:
        del characteristic, data, response

    async def start_notify(self, characteristic: object, callback: object) -> None:
        del characteristic, callback

    async def stop_notify(self, characteristic: object) -> None:
        del characteristic


def test_connect_refuses_an_implicit_address() -> None:
    async def exercise() -> None:
        with pytest.raises(BleConfigurationError, match="address must be explicitly provided"):
            await connect(address=None, timeout=1, backend=FakeBackend())

    asyncio.run(exercise())


def test_read_and_write_propagate_explicit_uuids_and_response_mode() -> None:
    backend = FakeBackend()

    async def exercise() -> BleSession:
        session = await connect(address="AA:BB:CC:DD:EE:FF", timeout=2, backend=backend)
        await session.write(
            b"\x01\x02",
            service_uuid=_SERVICE_UUID,
            characteristic_uuid=_CHARACTERISTIC_UUID,
            response=False,
            timeout=2,
            frame_size=2,
        )
        assert (
            await session.read(
                service_uuid=_SERVICE_UUID,
                characteristic_uuid=_CHARACTERISTIC_UUID,
                timeout=2,
                frame_size=2,
            )
            == b"\x01\x02"
        )
        return session

    session = asyncio.run(exercise())

    assert backend.connected == ("AA:BB:CC:DD:EE:FF", 2)
    assert backend.writes == [(_SERVICE_UUID, _CHARACTERISTIC_UUID, b"\x01\x02", False)]
    assert backend.reads == [(_SERVICE_UUID, _CHARACTERISTIC_UUID)]
    asyncio.run(session.close())


def test_frame_size_is_checked_before_write() -> None:
    backend = FakeBackend()

    async def exercise() -> None:
        session = await connect(address="AA:BB", timeout=1, backend=backend)
        with pytest.raises(BleFrameSizeError, match="exactly 3 bytes"):
            await session.write(
                b"\x01\x02",
                service_uuid=_SERVICE_UUID,
                characteristic_uuid=_CHARACTERISTIC_UUID,
                response=True,
                timeout=1,
                frame_size=3,
            )

    asyncio.run(exercise())
    assert backend.writes == []


def test_notifications_validate_frames_and_preserve_endpoint() -> None:
    backend = FakeBackend()
    received: list[bytes] = []

    async def exercise() -> None:
        session = await connect(address="AA:BB", timeout=1, backend=backend)
        await session.notify(
            received.append,
            service_uuid=_SERVICE_UUID,
            characteristic_uuid=_CHARACTERISTIC_UUID,
            timeout=1,
            frame_size=2,
        )
        backend.emit(b"\x03\x04")
        with pytest.raises(BleFrameSizeError, match="notification frame"):
            backend.emit(b"\x05")

    asyncio.run(exercise())

    assert received == [b"\x03\x04"]
    assert backend.notifications is not None
    assert backend.notifications[:2] == (_SERVICE_UUID, _CHARACTERISTIC_UUID)


def test_scan_maps_advertisements_without_connecting() -> None:
    devices = asyncio.run(scan(timeout=_SCAN_TIMEOUT, backend=FakeScanner()))

    assert [(device.address, device.name, device.rssi, device.service_uuids) for device in devices] == [
        ("AA:AA", "first", -40, ()),
        ("BB:BB", "second", -70, (_SERVICE_UUID,)),
    ]


def test_bleak_backend_resolves_characteristic_inside_explicit_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        importlib,
        "import_module",
        lambda _name: SimpleNamespace(BleakClient=_BleakClient),
    )

    async def exercise() -> None:
        session = await connect(address="AA:BB", timeout=1)
        assert (
            await session.read(
                service_uuid=_SERVICE_UUID,
                characteristic_uuid=_CHARACTERISTIC_UUID,
                timeout=1,
                frame_size=1,
            )
            == b"\x01"
        )
        with pytest.raises(BleError, match="service is not available"):
            await session.read(
                service_uuid="00000000-0000-0000-0000-000000000099",
                characteristic_uuid=_CHARACTERISTIC_UUID,
                timeout=1,
                frame_size=1,
            )
        await session.close()

    asyncio.run(exercise())

    assert _BleakClient.last_read is _CHARACTERISTIC
