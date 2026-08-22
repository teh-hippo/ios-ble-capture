from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

_ADDRESS = "02:00:00:00:00:01"
_BASE_TIMESTAMP = 1_785_302_400
_HANDLE = 0x0040
_LINK_TYPE_H4_WITH_PHDR = 201
_MESSAGE = bytes.fromhex("10 03 32 33 34 45")


def capture_packets() -> tuple[bytes, ...]:
    return (_connect(), _write(_MESSAGE))


def classic_pcap(packets: tuple[bytes, ...]) -> bytes:
    output = bytearray(
        struct.pack(
            "<IHHiIII",
            0xA1B2C3D4,
            2,
            4,
            0,
            0,
            65_535,
            _LINK_TYPE_H4_WITH_PHDR,
        )
    )
    for index, packet in enumerate(packets):
        output.extend(
            struct.pack(
                "<IIII",
                _BASE_TIMESTAMP + index,
                0,
                len(packet),
                len(packet),
            )
        )
        output.extend(packet)
    return bytes(output)


def pcapng(packets: tuple[bytes, ...]) -> bytes:
    section = struct.pack("<II", 0x0A0D0D0A, 28) + b"\x4d\x3c\x2b\x1a" + struct.pack("<HHqI", 1, 0, -1, 28)
    interface = struct.pack(
        "<IIHHII",
        1,
        20,
        _LINK_TYPE_H4_WITH_PHDR,
        0,
        65_535,
        20,
    )
    records = bytearray()
    for index, packet in enumerate(packets):
        padded = packet + b"\x00" * (-len(packet) % 4)
        timestamp = (_BASE_TIMESTAMP + index) * 1_000_000
        body = (
            struct.pack(
                "<IIIII",
                0,
                timestamp >> 32,
                timestamp & 0xFFFFFFFF,
                len(packet),
                len(packet),
            )
            + padded
        )
        block_length = len(body) + 12
        records.extend(struct.pack("<II", 6, block_length))
        records.extend(body)
        records.extend(struct.pack("<I", block_length))
    return section + interface + bytes(records)


def generate(destination: Path) -> tuple[Path, Path]:
    destination.mkdir(parents=True, exist_ok=True)
    packets = capture_packets()
    pcap_path = destination / "synthetic.pcap"
    pcapng_path = destination / "synthetic.pcapng"
    pcap_path.write_bytes(classic_pcap(packets))
    pcapng_path.write_bytes(pcapng(packets))
    return pcap_path, pcapng_path


def _connect() -> bytes:
    address = bytes.fromhex(_ADDRESS.replace(":", ""))[::-1]
    parameters = b"\x01\x00" + struct.pack("<H", _HANDLE) + b"\x00\x00" + address
    return struct.pack(">I", 1) + b"\x04\x3e" + bytes([len(parameters)]) + parameters


def _write(value: bytes) -> bytes:
    att = b"\x52" + struct.pack("<H", 0x0025) + value
    l2cap = struct.pack("<HH", len(att), 4) + att
    handle_and_flags = _HANDLE | 0b10 << 12
    h4 = b"\x02" + struct.pack("<HH", handle_and_flags, len(l2cap)) + l2cap
    return struct.pack(">I", 0) + h4


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path, nargs="?", default=Path(__file__).parent)
    args = parser.parse_args()
    for path in generate(args.destination):
        sys.stdout.write(f"{path}\n")


if __name__ == "__main__":
    main()
