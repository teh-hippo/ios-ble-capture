"""Vendor-neutral BLE scanning and active GATT operations."""
# ruff: noqa: ASYNC109

from __future__ import annotations

import asyncio
import importlib
import math
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, Self, cast

type NotificationCallback = Callable[[bytes], None]

_DISCOVERY_ENTRY_LENGTH = 2


class BleError(RuntimeError):
    """Raised when a BLE operation cannot complete."""


class BleConfigurationError(BleError):
    """Raised when an active BLE request is incomplete or invalid."""


class BleUnavailableError(BleError):
    """Raised when the optional bleak dependency is unavailable."""


class BleFrameSizeError(BleError):
    """Raised when a frame does not match its explicit size."""


@dataclass(frozen=True, slots=True)
class BleDevice:
    """Describes one device observed during scanning."""

    address: str
    name: str | None
    rssi: int | None
    service_uuids: tuple[str, ...]


class ScannerBackend(Protocol):
    """Obtains unnormalised BLE discovery data."""

    async def discover(self, timeout: float) -> Mapping[str, object]: ...


class ActiveBleBackend(Protocol):
    """Defines the backend surface required for an active GATT session."""

    async def connect(self, address: str, timeout: float) -> None: ...

    async def close(self) -> None: ...

    async def read(self, service_uuid: str, characteristic_uuid: str) -> bytes: ...

    async def write(
        self,
        service_uuid: str,
        characteristic_uuid: str,
        data: bytes,
        *,
        response: bool,
    ) -> None: ...

    async def start_notify(
        self,
        service_uuid: str,
        characteristic_uuid: str,
        callback: NotificationCallback,
    ) -> None: ...

    async def stop_notify(self, service_uuid: str, characteristic_uuid: str) -> None: ...


async def scan(*, timeout: float, backend: ScannerBackend | None = None) -> tuple[BleDevice, ...]:
    """Scan nearby BLE devices without establishing an active connection."""
    _require_timeout(timeout)
    scanner = backend or _BleakScannerBackend.create()
    discovered = await _within_timeout(scanner.discover(timeout), timeout)
    return _map_scan_results(discovered)


async def connect(
    *,
    address: str | None,
    timeout: float,
    backend: ActiveBleBackend | None = None,
) -> BleSession:
    """Connect to one explicitly addressed device and return its GATT session."""
    explicit_address = _require_address(address)
    _require_timeout(timeout)
    active_backend = backend or _BleakBackend.create()
    try:
        await _within_timeout(active_backend.connect(explicit_address, timeout), timeout)
    except BaseException:
        await active_backend.close()
        raise
    return BleSession(address=explicit_address, _backend=active_backend)


@dataclass(slots=True)
class BleSession:
    """Owns one explicit-address active BLE connection."""

    address: str
    _backend: ActiveBleBackend
    _closed: bool = False

    async def __aenter__(self) -> Self:
        self._require_open()
        return self

    async def __aexit__(self, _exc_type: object, _exc_value: object, _traceback: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the connection.  Repeated closes are harmless."""
        if self._closed:
            return
        self._closed = True
        await self._backend.close()

    async def read(
        self,
        *,
        service_uuid: str | None,
        characteristic_uuid: str | None,
        timeout: float,
        frame_size: int | None,
    ) -> bytes:
        """Read one GATT characteristic using explicit service and size constraints."""
        service, characteristic = _require_endpoint(service_uuid, characteristic_uuid)
        _require_timeout(timeout)
        _require_frame_size(frame_size)
        self._require_open()
        payload = bytes(await _within_timeout(self._backend.read(service, characteristic), timeout))
        _validate_frame_size(payload, frame_size, "read")
        return payload

    async def write(  # noqa: PLR0913
        self,
        data: bytes | bytearray | memoryview,
        *,
        service_uuid: str | None,
        characteristic_uuid: str | None,
        response: bool,
        timeout: float,
        frame_size: int | None,
    ) -> None:
        """Write one complete frame to an explicitly selected characteristic."""
        service, characteristic = _require_endpoint(service_uuid, characteristic_uuid)
        _require_timeout(timeout)
        _require_frame_size(frame_size)
        if not isinstance(response, bool):
            raise BleConfigurationError("write response mode must be explicitly True or False")
        self._require_open()
        payload = bytes(data)
        _validate_frame_size(payload, frame_size, "write")
        await _within_timeout(
            self._backend.write(service, characteristic, payload, response=response),
            timeout,
        )

    async def notify(
        self,
        callback: NotificationCallback,
        *,
        service_uuid: str | None,
        characteristic_uuid: str | None,
        timeout: float,
        frame_size: int | None,
    ) -> None:
        """Subscribe to notifications and validate every delivered frame."""
        service, characteristic = _require_endpoint(service_uuid, characteristic_uuid)
        _require_timeout(timeout)
        _require_frame_size(frame_size)
        self._require_open()

        def validated_callback(data: bytes) -> None:
            payload = bytes(data)
            _validate_frame_size(payload, frame_size, "notification")
            callback(payload)

        await _within_timeout(self._backend.start_notify(service, characteristic, validated_callback), timeout)

    async def stop_notify(
        self,
        *,
        service_uuid: str | None,
        characteristic_uuid: str | None,
        timeout: float,
    ) -> None:
        """Unsubscribe from notifications for one explicitly selected characteristic."""
        service, characteristic = _require_endpoint(service_uuid, characteristic_uuid)
        _require_timeout(timeout)
        self._require_open()
        await _within_timeout(self._backend.stop_notify(service, characteristic), timeout)

    def _require_open(self) -> None:
        if self._closed:
            raise BleError("BLE session is closed")


class _BleakScanner(Protocol):
    @classmethod
    async def discover(cls, *, timeout: float, return_adv: bool) -> Mapping[str, object]: ...


class _BleakClient(Protocol):
    @property
    def services(self) -> _BleakServiceCollection: ...

    async def connect(self) -> None: ...

    async def disconnect(self) -> None: ...

    async def read_gatt_char(self, characteristic: object) -> bytes: ...

    async def write_gatt_char(self, characteristic: object, data: bytes, *, response: bool) -> None: ...

    async def start_notify(self, characteristic: object, callback: Callable[[object, bytearray], None]) -> None: ...

    async def stop_notify(self, characteristic: object) -> None: ...


class _BleakService(Protocol):
    def get_characteristic(self, characteristic_uuid: str) -> object | None: ...


class _BleakServiceCollection(Protocol):
    def get_service(self, service_uuid: str) -> _BleakService | None: ...


class _BleakClientFactory(Protocol):
    def __call__(self, address: str, *, timeout: float) -> _BleakClient: ...


class _BleakScannerBackend:
    def __init__(self, scanner: type[_BleakScanner]) -> None:
        self._scanner = scanner

    @classmethod
    def create(cls) -> _BleakScannerBackend:
        try:
            bleak = importlib.import_module("bleak")
        except ModuleNotFoundError as error:
            raise BleUnavailableError("bleak is required for BLE scanning") from error
        return cls(cast("type[_BleakScanner]", bleak.BleakScanner))

    async def discover(self, timeout: float) -> Mapping[str, object]:
        found = await self._scanner.discover(timeout=timeout, return_adv=True)
        if not isinstance(found, Mapping):
            raise BleError("BLE scanner returned an invalid discovery mapping")
        return found


class _BleakBackend:
    def __init__(self, client_factory: _BleakClientFactory) -> None:
        self._client_factory = client_factory
        self._client: _BleakClient | None = None

    @classmethod
    def create(cls) -> _BleakBackend:
        try:
            bleak = importlib.import_module("bleak")
        except ModuleNotFoundError as error:
            raise BleUnavailableError("bleak is required for active BLE operations") from error
        return cls(cast("_BleakClientFactory", bleak.BleakClient))

    async def connect(self, address: str, timeout: float) -> None:
        self._client = self._client_factory(address, timeout=timeout)
        await self._client.connect()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.disconnect()
            self._client = None

    async def read(self, service_uuid: str, characteristic_uuid: str) -> bytes:
        client = self._require_client()
        characteristic = self._resolve_characteristic(
            client,
            service_uuid,
            characteristic_uuid,
        )
        return bytes(await client.read_gatt_char(characteristic))

    async def write(
        self,
        service_uuid: str,
        characteristic_uuid: str,
        data: bytes,
        *,
        response: bool,
    ) -> None:
        client = self._require_client()
        characteristic = self._resolve_characteristic(
            client,
            service_uuid,
            characteristic_uuid,
        )
        await client.write_gatt_char(characteristic, data, response=response)

    async def start_notify(
        self,
        service_uuid: str,
        characteristic_uuid: str,
        callback: NotificationCallback,
    ) -> None:
        def bleak_callback(_characteristic: object, data: bytearray) -> None:
            callback(bytes(data))

        client = self._require_client()
        characteristic = self._resolve_characteristic(
            client,
            service_uuid,
            characteristic_uuid,
        )
        await client.start_notify(characteristic, bleak_callback)

    async def stop_notify(self, service_uuid: str, characteristic_uuid: str) -> None:
        client = self._require_client()
        characteristic = self._resolve_characteristic(
            client,
            service_uuid,
            characteristic_uuid,
        )
        await client.stop_notify(characteristic)

    def _require_client(self) -> _BleakClient:
        if self._client is None:
            raise BleError("BLE backend is not connected")
        return self._client

    @staticmethod
    def _resolve_characteristic(
        client: _BleakClient,
        service_uuid: str,
        characteristic_uuid: str,
    ) -> object:
        service = client.services.get_service(service_uuid)
        if service is None:
            raise BleError(f"BLE service is not available: {service_uuid}")
        characteristic = service.get_characteristic(characteristic_uuid)
        if characteristic is None:
            raise BleError(f"BLE characteristic {characteristic_uuid} is not available in service {service_uuid}")
        return characteristic


def _map_scan_results(discovered: Mapping[str, object]) -> tuple[BleDevice, ...]:
    devices: list[BleDevice] = []
    for key, item in discovered.items():
        if not isinstance(item, tuple) or len(item) != _DISCOVERY_ENTRY_LENGTH:
            raise BleError("BLE scanner returned an invalid discovery mapping")
        device, advertisement = item
        address = _optional_text(getattr(device, "address", None)) or _optional_text(key)
        if address is None:
            raise BleError("BLE scanner reported a device without an address")
        name = _optional_text(getattr(advertisement, "local_name", None)) or _optional_text(
            getattr(device, "name", None)
        )
        rssi_value = getattr(advertisement, "rssi", None)
        rssi = rssi_value if isinstance(rssi_value, int) and not isinstance(rssi_value, bool) else None
        service_values = getattr(advertisement, "service_uuids", ()) or ()
        if not isinstance(service_values, Sequence) or isinstance(service_values, (bytes, bytearray, str)):
            raise BleError("BLE scanner returned invalid service UUIDs")
        service_uuids = tuple(value for value in service_values if isinstance(value, str) and value.strip())
        devices.append(BleDevice(address=address, name=name, rssi=rssi, service_uuids=service_uuids))
    return tuple(sorted(devices, key=lambda device: (device.address.casefold(), device.name or "")))


def _require_address(address: str | None) -> str:
    if address is None or not isinstance(address, str) or not address.strip():
        raise BleConfigurationError("address must be explicitly provided")
    return address


def _require_endpoint(service_uuid: str | None, characteristic_uuid: str | None) -> tuple[str, str]:
    if service_uuid is None or not isinstance(service_uuid, str) or not service_uuid.strip():
        raise BleConfigurationError("service UUID must be explicitly provided")
    if characteristic_uuid is None or not isinstance(characteristic_uuid, str) or not characteristic_uuid.strip():
        raise BleConfigurationError("characteristic UUID must be explicitly provided")
    return service_uuid, characteristic_uuid


def _require_timeout(timeout: float) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise BleConfigurationError("timeout must be a positive finite number")


def _require_frame_size(frame_size: int | None) -> None:
    if frame_size is not None and (isinstance(frame_size, bool) or not isinstance(frame_size, int) or frame_size <= 0):
        raise BleConfigurationError("frame size must be a positive integer or None")


def _validate_frame_size(payload: bytes, frame_size: int | None, operation: str) -> None:
    if frame_size is not None and len(payload) != frame_size:
        raise BleFrameSizeError(f"{operation} frame must be exactly {frame_size} bytes; received {len(payload)}")


def _optional_text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


async def _within_timeout[Value](awaitable: Awaitable[Value], timeout: float) -> Value:
    try:
        return await asyncio.wait_for(awaitable, timeout)
    except TimeoutError as error:
        raise BleError(f"BLE operation timed out after {timeout:g} seconds") from error
