from __future__ import annotations

import json
import stat
import struct
from datetime import timedelta, timezone
from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.capture import CaptureFormatError, import_capture, write_raw_run
from ios_ble_capture.models import Direction

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from ios_ble_capture.models import AttEvent

_BASE_TIMESTAMP = 1_785_302_400
_LINK_TYPE_H4_WITH_PHDR = 201
_WRITE_HANDLE = 0x0025
_NOTIFY_HANDLE = 0x0026
_PREPARE_OFFSET = 32
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600


def _pcap(packets: list[bytes]) -> bytes:
    capture = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, _LINK_TYPE_H4_WITH_PHDR))
    for index, packet in enumerate(packets):
        capture.extend(struct.pack("<IIII", _BASE_TIMESTAMP + index, 0, len(packet), len(packet)))
        capture.extend(packet)
    return bytes(capture)


def _pcapng(packets: list[bytes]) -> bytes:
    section = struct.pack("<II", 0x0A0D0D0A, 28) + b"\x4d\x3c\x2b\x1a" + struct.pack("<HHqI", 1, 0, -1, 28)
    interface = struct.pack("<IIHHII", 1, 20, _LINK_TYPE_H4_WITH_PHDR, 0, 65_535, 20)
    records = bytearray()
    for index, packet in enumerate(packets):
        padded_packet = packet + b"\x00" * (-len(packet) % 4)
        body = struct.pack("<IIIII", 0, 0, _BASE_TIMESTAMP + index, len(packet), len(packet)) + padded_packet
        block_length = len(body) + 12
        records.extend(struct.pack("<II", 6, block_length))
        records.extend(body)
        records.extend(struct.pack("<I", block_length))
    return section + interface + bytes(records)


def _with_phdr(direction_from_device: int, h4: bytes) -> bytes:
    return struct.pack(">I", direction_from_device) + h4


def _connect(handle: int, address: str, *, subevent: int = 0x01) -> bytes:
    raw_address = bytes.fromhex(address.replace(":", ""))[::-1]
    parameters = bytes([subevent, 0]) + struct.pack("<H", handle) + b"\x00\x00" + raw_address
    return _with_phdr(1, b"\x04\x3e" + bytes([len(parameters)]) + parameters)


def _disconnect(handle: int) -> bytes:
    parameters = b"\x00" + struct.pack("<H", handle) + b"\x13"
    return _with_phdr(1, b"\x04\x05" + bytes([len(parameters)]) + parameters)


def _acl(handle: int, packet_boundary: int, l2cap_fragment: bytes) -> bytes:
    handle_and_flags = handle | packet_boundary << 12
    return _with_phdr(
        0,
        b"\x02" + struct.pack("<HH", handle_and_flags, len(l2cap_fragment)) + l2cap_fragment,
    )


def _att(handle: int, value: bytes) -> bytes:
    att = b"\x52" + struct.pack("<H", 0x0025) + value
    return _acl(handle, 0b10, struct.pack("<HH", len(att), 4) + att)


def _prepare_write(handle: int, *, value_offset: int, value: bytes) -> bytes:
    att = b"\x16" + struct.pack("<H", 0x0025) + struct.pack("<H", value_offset) + value
    return _acl(handle, 0b10, struct.pack("<HH", len(att), 4) + att)


def test_imports_classic_pcap_and_tracks_reused_handle_epochs() -> None:
    trace = import_capture(
        _pcap(
            [
                _connect(0x40, "10:20:30:40:50:60"),
                _att(0x40, b"\x01"),
                _disconnect(0x40),
                _connect(0x40, "A0:B0:C0:D0:E0:F0"),
                _att(0x40, b"\x02"),
            ],
        ),
    )

    assert [(event.connection_epoch, event.peer_address, event.value) for event in trace.events] == [
        (1, "10:20:30:40:50:60", b"\x01"),
        (2, "A0:B0:C0:D0:E0:F0", b"\x02"),
    ]
    assert trace.events[0].direction is Direction.HOST_TO_DEVICE


def test_reassembles_l2cap_att_fragments_and_imports_pcapng() -> None:
    att = b"\x1b" + struct.pack("<H", 0x0026) + b"\xab\xcd"
    l2cap = struct.pack("<HH", len(att), 4) + att
    trace = import_capture(
        _pcapng(
            [
                _connect(0x41, "01:02:03:04:05:06"),
                _acl(0x41, 0b10, l2cap[:5]),
                _acl(0x41, 0b01, l2cap[5:]),
            ],
        ),
    )

    assert len(trace.events) == 1
    assert trace.events[0].attribute_handle == _NOTIFY_HANDLE
    assert trace.events[0].value == b"\xab\xcd"


def test_attributes_le_enhanced_connection_complete_v2() -> None:
    trace = import_capture(
        _pcap(
            [
                _connect(0x40, "10:20:30:40:50:60", subevent=0x29),
                _att(0x40, b"\x01"),
            ]
        )
    )

    assert trace.events[0].peer_address == "10:20:30:40:50:60"


def test_prepare_write_preserves_offset_outside_payload() -> None:
    trace = import_capture(
        _pcap(
            [
                _connect(0x40, "10:20:30:40:50:60"),
                _prepare_write(
                    0x40,
                    value_offset=_PREPARE_OFFSET,
                    value=b"\xaa\xbb",
                ),
            ]
        )
    )

    assert trace.events[0].attribute_handle == _WRITE_HANDLE
    assert trace.events[0].value_offset == _PREPARE_OFFSET
    assert trace.events[0].value == b"\xaa\xbb"


def test_rejects_truncated_pcap_unless_explicitly_allowed() -> None:
    truncated = _pcap([_att(0x40, b"\x01")])[:-1]

    with pytest.raises(CaptureFormatError, match="pcap record payload is truncated"):
        import_capture(truncated)

    assert import_capture(truncated, allow_truncated=True).events == ()


def test_rejects_snapshot_truncation_unless_explicitly_allowed() -> None:
    packet = _att(0x40, b"\x01")
    capture = bytearray(_pcap([packet]))
    struct.pack_into("<I", capture, 24 + 12, len(packet) + 1)

    with pytest.raises(CaptureFormatError, match="snapshot length"):
        import_capture(bytes(capture))

    assert import_capture(bytes(capture), allow_truncated=True).events


def test_rejects_incomplete_acl_and_l2cap_fragments() -> None:
    incomplete_acl = _with_phdr(
        0,
        b"\x02" + struct.pack("<HH", 0x2040, 8) + b"\x01",
    )
    att = b"\x52" + struct.pack("<H", 0x0025) + b"\x01"
    l2cap = struct.pack("<HH", len(att), 4) + att
    incomplete_l2cap = _acl(0x40, 0b10, l2cap[:5])

    with pytest.raises(CaptureFormatError, match="ACL payload"):
        import_capture(_pcap([incomplete_acl]))
    with pytest.raises(CaptureFormatError, match="incomplete L2CAP"):
        import_capture(_pcap([incomplete_l2cap]))

    assert import_capture(_pcap([incomplete_acl]), allow_truncated=True).events == ()
    assert import_capture(_pcap([incomplete_l2cap]), allow_truncated=True).events == ()


def test_raw_runs_are_private_and_write_events_incrementally(tmp_path: Path) -> None:
    trace = import_capture(_pcap([_connect(0x40, "10:20:30:40:50:60"), _att(0x40, b"\xde\xad")]))
    run_directory = tmp_path / "run"

    def interrupted_events() -> Iterator[AttEvent]:
        yield trace.events[0]
        raise OSError("source interrupted")

    with pytest.raises(OSError, match="source interrupted"):
        write_raw_run(run_directory, interrupted_events())

    events_path = run_directory / "events.jsonl"
    assert stat.S_IMODE(run_directory.stat().st_mode) == _PRIVATE_DIRECTORY_MODE
    assert stat.S_IMODE(events_path.stat().st_mode) == _PRIVATE_FILE_MODE
    assert json.loads(events_path.read_text(encoding="utf-8"))["value_hex"] == "dead"


def test_classic_wall_clock_timezone_normalises_to_an_instant() -> None:
    packets = [_connect(0x40, "10:20:30:40:50:60"), _att(0x40, b"\x01")]

    conventional = import_capture(_pcap(packets)).events[0].timestamp
    wall_clock = (
        import_capture(
            _pcap(packets),
            classic_pcap_timezone=timezone(timedelta(hours=10)),
        )
        .events[0]
        .timestamp
    )

    assert conventional - wall_clock == timedelta(hours=10)
