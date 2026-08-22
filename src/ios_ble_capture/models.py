from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final, NotRequired, TypedDict

from ios_ble_capture.errors import CaptureDataError

EVENT_SCHEMA_VERSION: Final = 1


class Direction(StrEnum):
    HOST_TO_DEVICE = "host_to_device"
    DEVICE_TO_HOST = "device_to_host"
    UNKNOWN = "unknown"


class AttEventRecord(TypedDict):
    schema_version: int
    timestamp: str
    direction: str
    connection_handle: int
    connection_epoch: int
    peer_address: str | None
    opcode: int
    attribute_handle: int | None
    value_hex: str
    value_offset: NotRequired[int | None]


@dataclass(frozen=True, slots=True)
class AttEvent:
    timestamp: datetime
    direction: Direction
    connection_handle: int
    connection_epoch: int
    peer_address: str | None
    opcode: int
    attribute_handle: int | None
    value: bytes
    value_offset: int | None = None

    def __post_init__(self) -> None:
        if self.timestamp.utcoffset() is None:
            raise CaptureDataError("timestamp must include a UTC offset")
        _require_uint(self.connection_handle, bits=12, name="connection_handle")
        if self.connection_epoch < 0:
            raise CaptureDataError("connection_epoch must be non-negative")
        _require_uint(self.opcode, bits=8, name="opcode")
        if self.attribute_handle is not None:
            _require_uint(self.attribute_handle, bits=16, name="attribute_handle")
        if self.value_offset is not None:
            _require_uint(self.value_offset, bits=16, name="value_offset")
        if self.peer_address is not None and not self.peer_address:
            raise CaptureDataError("peer_address cannot be empty")

    def to_record(self) -> AttEventRecord:
        return {
            "schema_version": EVENT_SCHEMA_VERSION,
            "timestamp": self.timestamp.isoformat(),
            "direction": self.direction,
            "connection_handle": self.connection_handle,
            "connection_epoch": self.connection_epoch,
            "peer_address": self.peer_address,
            "opcode": self.opcode,
            "attribute_handle": self.attribute_handle,
            "value_hex": self.value.hex(),
            "value_offset": self.value_offset,
        }

    @classmethod
    def from_record(cls, record: AttEventRecord) -> AttEvent:
        if record["schema_version"] != EVENT_SCHEMA_VERSION:
            raise CaptureDataError(f"unsupported event schema version: {record['schema_version']}")
        try:
            timestamp = datetime.fromisoformat(record["timestamp"])
            direction = Direction(record["direction"])
            value = bytes.fromhex(record["value_hex"])
        except (TypeError, ValueError) as error:
            raise CaptureDataError(f"invalid ATT event record: {error}") from error
        return cls(
            timestamp=timestamp,
            direction=direction,
            connection_handle=record["connection_handle"],
            connection_epoch=record["connection_epoch"],
            peer_address=record["peer_address"],
            opcode=record["opcode"],
            attribute_handle=record["attribute_handle"],
            value=value,
            value_offset=record.get("value_offset"),
        )


class RunMetadataRecord(TypedDict):
    schema_version: int
    run_id: str
    created_at: str
    source: str
    tool_version: str


@dataclass(frozen=True, slots=True)
class RunMetadata:
    run_id: str
    created_at: datetime
    source: str
    tool_version: str

    def __post_init__(self) -> None:
        for name, value in (
            ("run_id", self.run_id),
            ("source", self.source),
            ("tool_version", self.tool_version),
        ):
            if not value.strip():
                raise CaptureDataError(f"{name} cannot be empty")
        if self.created_at.utcoffset() is None:
            raise CaptureDataError("created_at must include a UTC offset")

    def to_record(self) -> RunMetadataRecord:
        return {
            "schema_version": EVENT_SCHEMA_VERSION,
            "run_id": self.run_id,
            "created_at": self.created_at.isoformat(),
            "source": self.source,
            "tool_version": self.tool_version,
        }


def _require_uint(value: int, *, bits: int, name: str) -> None:
    if not 0 <= value < 1 << bits:
        raise CaptureDataError(f"{name} must fit in an unsigned {bits}-bit integer")
