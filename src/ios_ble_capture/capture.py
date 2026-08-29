"""Import HCI H4 captures and normalise their ATT traffic."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from ios_ble_capture.errors import CaptureDataError
from ios_ble_capture.models import AttEvent, Direction
from ios_ble_capture.storage import PRIVATE_DIRECTORY_MODE, write_private_text

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from datetime import tzinfo
    from pathlib import Path

ATT_CID: Final = 0x0004
DLT_BLUETOOTH_HCI_H4: Final = 187
DLT_BLUETOOTH_HCI_H4_WITH_PHDR: Final = 201

_ATT_HEADER_LENGTH: Final = 3
_ATT_PREPARE_HEADER_LENGTH: Final = 5
_H4_ACL: Final = 0x02
_H4_EVENT: Final = 0x04
_HCI_ACL_HEADER_LENGTH: Final = 5
_HCI_DISCONNECTION_COMPLETE: Final = 0x05
_HCI_EVENT_HEADER_LENGTH: Final = 3
_HCI_LE_META_EVENT: Final = 0x3E
_LE_CONNECTION_COMPLETE_SUBEVENTS: Final = frozenset({0x01, 0x0A, 0x29})
_LE_CONNECTION_COMPLETE_MINIMUM_LENGTH: Final = 12
_L2CAP_HEADER_LENGTH: Final = 4
_PCAP_GLOBAL_HEADER_LENGTH: Final = 24
_PCAPNG_BLOCK_HEADER_LENGTH: Final = 8
_PCAPNG_ENHANCED_PACKET_HEADER_LENGTH: Final = 20
_PCAPNG_INTERFACE_DESCRIPTION_HEADER_LENGTH: Final = 8
_PCAPNG_INTERFACE_TIMESTAMP_RESOLUTION: Final = 9
_PCAPNG_MINIMUM_BLOCK_LENGTH: Final = 12
_PCAPNG_SECTION_HEADER: Final = 0x0A0D0D0A
_PCAPNG_INTERFACE_DESCRIPTION: Final = 0x00000001
_PCAPNG_ENHANCED_PACKET: Final = 0x00000006
_PCAP_MAGIC_LAYOUTS: Final = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_ATT_OPCODES_WITH_VALUE_HANDLE: Final = frozenset({0x12, 0x16, 0x17, 0x1B, 0x1D, 0x52, 0xD2})
_ATT_PREPARE_WRITE_OPCODES: Final = frozenset({0x16, 0x17})


class CaptureFormatError(CaptureDataError):
    """Raised when a capture container or packet is malformed."""


@dataclass(frozen=True, slots=True)
class ConnectionEvent:
    """A connection lifecycle event observed in an HCI capture."""

    timestamp: datetime
    connection_handle: int
    peer_address: str | None
    connected: bool
    connection_epoch: int | None


@dataclass(frozen=True, slots=True)
class CaptureTrace:
    """The connection lifecycle and normalised ATT events from one capture."""

    connections: tuple[ConnectionEvent, ...]
    events: tuple[AttEvent, ...]


@dataclass(frozen=True, slots=True)
class _CapturedH4Packet:
    timestamp: datetime
    direction: Direction
    h4: bytes


@dataclass(slots=True)
class _ActiveConnection:
    epoch: int
    peer_address: str | None


@dataclass(slots=True)
class _L2capFragment:
    epoch: int
    expected_length: int
    data: bytearray


def import_capture(
    data: bytes,
    *,
    allow_truncated: bool = False,
    classic_pcap_timezone: tzinfo | None = None,
) -> CaptureTrace:
    """Return ATT events from a classic pcap or pcapng HCI H4 capture."""

    active_connections: dict[int, _ActiveConnection] = {}
    fragments: dict[int, _L2capFragment] = {}
    connection_events: list[ConnectionEvent] = []
    att_events: list[AttEvent] = []
    next_epoch = 0

    for packet in _iter_h4_packets(
        data,
        allow_truncated=allow_truncated,
        classic_pcap_timezone=classic_pcap_timezone,
    ):
        lifecycle = _connection_lifecycle(
            packet.timestamp,
            packet.h4,
            allow_truncated=allow_truncated,
        )
        if lifecycle is not None:
            handle, address, connected = lifecycle
            if connected:
                next_epoch += 1
                active_connections[handle] = _ActiveConnection(next_epoch, address)
                fragments.pop(handle, None)
                epoch: int | None = next_epoch
            else:
                active = active_connections.pop(handle, None)
                fragments.pop(handle, None)
                epoch = active.epoch if active is not None else None
                address = active.peer_address if active is not None else address
            connection_events.append(
                ConnectionEvent(
                    timestamp=packet.timestamp,
                    connection_handle=handle,
                    peer_address=address,
                    connected=connected,
                    connection_epoch=epoch,
                )
            )
            continue

        if not packet.h4 or packet.h4[0] != _H4_ACL:
            continue
        acl = _acl_payload(packet.h4, allow_truncated=allow_truncated)
        if acl is None:
            continue
        handle, packet_boundary, payload = acl
        active = active_connections.get(handle)
        if active is None:
            next_epoch += 1
            active = _ActiveConnection(next_epoch, None)
            active_connections[handle] = active

        l2cap = _reassemble_l2cap(
            handle,
            active.epoch,
            packet_boundary,
            payload,
            fragments,
            allow_truncated=allow_truncated,
        )
        if l2cap is None:
            continue
        l2cap_length, channel_id = struct.unpack_from("<HH", l2cap)
        if channel_id != ATT_CID or l2cap_length == 0:
            continue
        att = l2cap[4:]
        opcode = att[0]
        attribute_handle, value_offset, value = _att_fields(att, opcode)
        att_events.append(
            AttEvent(
                timestamp=packet.timestamp,
                direction=packet.direction,
                connection_handle=handle,
                connection_epoch=active.epoch,
                peer_address=active.peer_address,
                opcode=opcode,
                attribute_handle=attribute_handle,
                value=value,
                value_offset=value_offset,
            )
        )

    if fragments and not allow_truncated:
        raise CaptureFormatError("capture ends with an incomplete L2CAP fragment")
    return CaptureTrace(tuple(connection_events), tuple(att_events))


def write_raw_run(
    run_directory: Path,
    events: Iterable[AttEvent],
) -> None:
    """Write unredacted JSONL event records into a private run directory."""

    if run_directory.exists() and not run_directory.is_dir():
        raise CaptureDataError(f"raw run path is not a directory: {run_directory}")
    run_directory.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIRECTORY_MODE)
    run_directory.chmod(PRIVATE_DIRECTORY_MODE)
    write_private_text(
        run_directory / "events.jsonl",
        "".join(json.dumps(event.to_record(), sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    )


def _iter_h4_packets(
    data: bytes,
    *,
    allow_truncated: bool,
    classic_pcap_timezone: tzinfo | None,
) -> Iterator[_CapturedH4Packet]:
    if data[:4] == struct.pack("<I", _PCAPNG_SECTION_HEADER):
        yield from _iter_pcapng(data, allow_truncated=allow_truncated)
        return
    yield from _iter_classic_pcap(
        data,
        allow_truncated=allow_truncated,
        wall_clock_timezone=classic_pcap_timezone,
    )


def _iter_classic_pcap(  # noqa: C901
    data: bytes,
    *,
    allow_truncated: bool,
    wall_clock_timezone: tzinfo | None,
) -> Iterator[_CapturedH4Packet]:
    if len(data) < _PCAP_GLOBAL_HEADER_LENGTH:
        raise CaptureFormatError("pcap header is truncated")
    try:
        endian, timestamp_scale = _PCAP_MAGIC_LAYOUTS[data[:4]]
    except KeyError as error:
        raise CaptureFormatError("unsupported pcap byte order or timestamp resolution") from error
    link_type = struct.unpack_from(f"{endian}I", data, 20)[0]
    if link_type not in {DLT_BLUETOOTH_HCI_H4, DLT_BLUETOOTH_HCI_H4_WITH_PHDR}:
        raise CaptureFormatError("pcap does not contain Bluetooth HCI H4 packets")

    record_header = struct.Struct(f"{endian}IIII")
    offset = _PCAP_GLOBAL_HEADER_LENGTH
    while offset < len(data):
        if offset + record_header.size > len(data):
            if allow_truncated:
                return
            raise CaptureFormatError("pcap record header is truncated")
        seconds, fraction, captured_length, original_length = record_header.unpack_from(
            data,
            offset,
        )
        offset += record_header.size
        if captured_length != original_length and not allow_truncated:
            raise CaptureFormatError("pcap record was truncated by the capture snapshot length")
        if offset + captured_length > len(data):
            if allow_truncated:
                return
            raise CaptureFormatError("pcap record payload is truncated")
        timestamp_value = seconds + fraction / timestamp_scale
        timestamp = _classic_timestamp(
            timestamp_value,
            wall_clock_timezone=wall_clock_timezone,
        )
        packet = data[offset : offset + captured_length]
        offset += captured_length
        normalised = _normalise_link_packet(timestamp, packet, link_type)
        if normalised is not None:
            yield normalised


def _iter_pcapng(  # noqa: C901, PLR0912
    data: bytes,
    *,
    allow_truncated: bool,
) -> Iterator[_CapturedH4Packet]:
    endian = "<"
    interfaces: dict[int, tuple[int, int]] = {}
    offset = 0
    while offset < len(data):
        if offset + _PCAPNG_BLOCK_HEADER_LENGTH > len(data):
            if allow_truncated:
                return
            raise CaptureFormatError("pcapng block header is truncated")

        if data[offset : offset + 4] == struct.pack("<I", _PCAPNG_SECTION_HEADER):
            endian = _pcapng_section_endian(data, offset)
            interfaces = {}
        block_type = struct.unpack_from(f"{endian}I", data, offset)[0]
        block_length = struct.unpack_from(f"{endian}I", data, offset + 4)[0]
        if block_length < _PCAPNG_MINIMUM_BLOCK_LENGTH:
            raise CaptureFormatError("pcapng block length is invalid")
        if offset + block_length > len(data):
            if allow_truncated:
                return
            raise CaptureFormatError("pcapng block is truncated")
        if struct.unpack_from(f"{endian}I", data, offset + block_length - 4)[0] != block_length:
            raise CaptureFormatError("pcapng block length footer does not match header")

        body = data[offset + _PCAPNG_BLOCK_HEADER_LENGTH : offset + block_length - _L2CAP_HEADER_LENGTH]
        if block_type == _PCAPNG_INTERFACE_DESCRIPTION:
            if len(body) < _PCAPNG_INTERFACE_DESCRIPTION_HEADER_LENGTH:
                raise CaptureFormatError("pcapng interface description is truncated")
            link_type = struct.unpack_from(f"{endian}H", body)[0]
            interfaces[len(interfaces)] = (
                link_type,
                _pcapng_timestamp_divisor(body[_PCAPNG_INTERFACE_DESCRIPTION_HEADER_LENGTH:], endian),
            )
        elif block_type == _PCAPNG_ENHANCED_PACKET:
            if len(body) < _PCAPNG_ENHANCED_PACKET_HEADER_LENGTH:
                raise CaptureFormatError("pcapng enhanced packet is truncated")
            (
                interface_id,
                timestamp_high,
                timestamp_low,
                captured_length,
                original_length,
            ) = struct.unpack_from(
                f"{endian}IIIII",
                body,
            )
            if captured_length != original_length and not allow_truncated:
                raise CaptureFormatError("pcapng packet was truncated by the capture snapshot length")
            if _PCAPNG_ENHANCED_PACKET_HEADER_LENGTH + captured_length > len(body):
                raise CaptureFormatError("pcapng enhanced packet payload is truncated")
            interface = interfaces.get(interface_id)
            if interface is None:
                raise CaptureFormatError(f"pcapng packet references unknown interface {interface_id}")
            link_type, divisor = interface
            if link_type in {DLT_BLUETOOTH_HCI_H4, DLT_BLUETOOTH_HCI_H4_WITH_PHDR}:
                timestamp_value = (timestamp_high << 32) | timestamp_low
                timestamp = datetime.fromtimestamp(timestamp_value / divisor, UTC)
                packet = body[
                    _PCAPNG_ENHANCED_PACKET_HEADER_LENGTH : _PCAPNG_ENHANCED_PACKET_HEADER_LENGTH + captured_length
                ]
                normalised = _normalise_link_packet(timestamp, packet, link_type)
                if normalised is not None:
                    yield normalised
        offset += block_length


def _pcapng_section_endian(data: bytes, offset: int) -> str:
    if offset + _PCAPNG_MINIMUM_BLOCK_LENGTH > len(data):
        raise CaptureFormatError("pcapng section header is truncated")
    byte_order_magic = data[offset + 8 : offset + 12]
    if byte_order_magic == b"\x4d\x3c\x2b\x1a":
        return "<"
    if byte_order_magic == b"\x1a\x2b\x3c\x4d":
        return ">"
    raise CaptureFormatError("pcapng section has unrecognised byte-order magic")


def _classic_timestamp(
    value: float,
    *,
    wall_clock_timezone: tzinfo | None,
) -> datetime:
    timestamp = datetime.fromtimestamp(value, UTC)
    if wall_clock_timezone is None:
        return timestamp
    wall_clock = timestamp.replace(tzinfo=None)
    return wall_clock.replace(tzinfo=wall_clock_timezone).astimezone(UTC)


def _pcapng_timestamp_divisor(options: bytes, endian: str) -> int:
    offset = 0
    while offset + 4 <= len(options):
        option_code, option_length = struct.unpack_from(f"{endian}HH", options, offset)
        value_start = offset + 4
        value_end = value_start + option_length
        padded_end = value_end + (-option_length % 4)
        if padded_end > len(options):
            raise CaptureFormatError("pcapng interface option is truncated")
        if option_code == 0:
            break
        if option_code == _PCAPNG_INTERFACE_TIMESTAMP_RESOLUTION and option_length == 1:
            resolution = int.from_bytes(options[value_start:value_end], "big")
            exponent = resolution & 0x7F
            return int(2**exponent if resolution & 0x80 else 10**exponent)
        offset = padded_end
    return 1_000_000


def _normalise_link_packet(timestamp: datetime, packet: bytes, link_type: int) -> _CapturedH4Packet | None:
    if link_type == DLT_BLUETOOTH_HCI_H4:
        if not packet:
            return None
        return _CapturedH4Packet(timestamp, Direction.UNKNOWN, packet)
    if len(packet) < _HCI_ACL_HEADER_LENGTH:
        return None
    direction = Direction.DEVICE_TO_HOST if struct.unpack_from(">I", packet)[0] & 1 else Direction.HOST_TO_DEVICE
    return _CapturedH4Packet(timestamp, direction, packet[4:])


def _connection_lifecycle(  # noqa: PLR0911
    timestamp: datetime,
    h4: bytes,
    *,
    allow_truncated: bool,
) -> tuple[int, str | None, bool] | None:
    del timestamp
    if not h4 or h4[0] != _H4_EVENT:
        return None
    if len(h4) < _HCI_EVENT_HEADER_LENGTH:
        if allow_truncated:
            return None
        raise CaptureFormatError("HCI event header is truncated")
    parameter_length = h4[2]
    if len(h4) < _HCI_EVENT_HEADER_LENGTH + parameter_length:
        if allow_truncated:
            return None
        raise CaptureFormatError("HCI event payload is truncated")
    parameters = h4[_HCI_EVENT_HEADER_LENGTH : _HCI_EVENT_HEADER_LENGTH + parameter_length]
    if (
        h4[1] == _HCI_LE_META_EVENT
        and len(parameters) >= _LE_CONNECTION_COMPLETE_MINIMUM_LENGTH
        and parameters[0] in _LE_CONNECTION_COMPLETE_SUBEVENTS
    ):
        if parameters[1] != 0:
            return None
        handle = struct.unpack_from("<H", parameters, 2)[0] & 0x0FFF
        return handle, _format_address(parameters[6:12]), True
    if h4[1] == _HCI_DISCONNECTION_COMPLETE and len(parameters) >= _L2CAP_HEADER_LENGTH and parameters[0] == 0:
        handle = struct.unpack_from("<H", parameters, 1)[0] & 0x0FFF
        return handle, None, False
    return None


def _acl_payload(
    h4: bytes,
    *,
    allow_truncated: bool,
) -> tuple[int, int, bytes] | None:
    if len(h4) < _HCI_ACL_HEADER_LENGTH:
        if allow_truncated:
            return None
        raise CaptureFormatError("HCI ACL header is truncated")
    handle_and_flags, declared_length = struct.unpack_from("<HH", h4, 1)
    if len(h4) < _HCI_ACL_HEADER_LENGTH + declared_length:
        if allow_truncated:
            return None
        raise CaptureFormatError("HCI ACL payload is truncated")
    handle = handle_and_flags & 0x0FFF
    packet_boundary = (handle_and_flags >> 12) & 0b11
    return handle, packet_boundary, h4[_HCI_ACL_HEADER_LENGTH : _HCI_ACL_HEADER_LENGTH + declared_length]


def _reassemble_l2cap(  # noqa: PLR0913
    handle: int,
    epoch: int,
    packet_boundary: int,
    payload: bytes,
    fragments: dict[int, _L2capFragment],
    *,
    allow_truncated: bool,
) -> bytes | None:
    if packet_boundary == 0b01:
        fragment = fragments.get(handle)
        if fragment is None or fragment.epoch != epoch:
            if allow_truncated:
                return None
            raise CaptureFormatError("L2CAP continuation has no matching initial fragment")
        fragment.data.extend(payload)
        if len(fragment.data) < fragment.expected_length:
            return None
        completed = bytes(fragment.data[: fragment.expected_length])
        fragments.pop(handle, None)
        return completed

    if len(payload) < _L2CAP_HEADER_LENGTH:
        if allow_truncated:
            return None
        raise CaptureFormatError("L2CAP header is truncated")
    l2cap_length = struct.unpack_from("<H", payload)[0]
    expected_length = _L2CAP_HEADER_LENGTH + l2cap_length
    if len(payload) >= expected_length:
        return payload[:expected_length]
    fragments[handle] = _L2capFragment(epoch, expected_length, bytearray(payload))
    return None


def _format_address(raw: bytes) -> str:
    return ":".join(f"{octet:02X}" for octet in reversed(raw))


def _att_fields(
    att: bytes,
    opcode: int,
) -> tuple[int | None, int | None, bytes]:
    if opcode not in _ATT_OPCODES_WITH_VALUE_HANDLE or len(att) < _ATT_HEADER_LENGTH:
        return None, None, att[1:]
    attribute_handle = int(struct.unpack_from("<H", att, 1)[0])
    if opcode not in _ATT_PREPARE_WRITE_OPCODES:
        return attribute_handle, None, att[_ATT_HEADER_LENGTH:]
    if len(att) < _ATT_PREPARE_HEADER_LENGTH:
        raise CaptureFormatError("ATT prepare-write offset is truncated")
    value_offset = int(struct.unpack_from("<H", att, 3)[0])
    return attribute_handle, value_offset, att[_ATT_PREPARE_HEADER_LENGTH:]
