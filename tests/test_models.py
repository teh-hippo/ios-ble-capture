from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ios_ble_capture.errors import CaptureDataError
from ios_ble_capture.models import AttEvent, Direction, RunMetadata


def test_att_event_round_trips_through_record() -> None:
    event = AttEvent(
        timestamp=datetime(2026, 8, 22, 12, 34, tzinfo=UTC),
        direction=Direction.HOST_TO_DEVICE,
        connection_handle=0x04E,
        connection_epoch=2,
        peer_address="02:00:00:00:00:01",
        opcode=0x52,
        attribute_handle=0x0010,
        value=bytes.fromhex("330101"),
    )

    assert AttEvent.from_record(event.to_record()) == event


def _event(
    *,
    connection_handle: int = 1,
    connection_epoch: int = 0,
    opcode: int = 0x1B,
    attribute_handle: int | None = 1,
) -> AttEvent:
    return AttEvent(
        timestamp=datetime(2026, 8, 22, tzinfo=UTC),
        direction=Direction.DEVICE_TO_HOST,
        connection_handle=connection_handle,
        connection_epoch=connection_epoch,
        peer_address=None,
        opcode=opcode,
        attribute_handle=attribute_handle,
        value=b"",
    )


def test_att_event_rejects_out_of_range_values() -> None:
    with pytest.raises(CaptureDataError):
        _event(connection_handle=0x1000)
    with pytest.raises(CaptureDataError):
        _event(connection_epoch=-1)
    with pytest.raises(CaptureDataError):
        _event(opcode=0x100)
    with pytest.raises(CaptureDataError):
        _event(attribute_handle=0x10000)


def test_att_event_rejects_naive_timestamp() -> None:
    with pytest.raises(CaptureDataError, match="UTC offset"):
        AttEvent(
            timestamp=datetime(2026, 8, 22),
            direction=Direction.DEVICE_TO_HOST,
            connection_handle=1,
            connection_epoch=0,
            peer_address=None,
            opcode=0x1B,
            attribute_handle=None,
            value=b"",
        )


def test_run_metadata_rejects_empty_identity() -> None:
    with pytest.raises(CaptureDataError, match="run_id"):
        RunMetadata(
            run_id=" ",
            created_at=datetime(2026, 8, 22, tzinfo=UTC),
            source="fixture",
            tool_version="0.1.0",
        )
