from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ios_ble_capture.errors import CaptureDataError
from ios_ble_capture.models import AttEvent, Direction
from ios_ble_capture.segmentation import (
    ActionMark,
    dump_action_marks_jsonl,
    load_action_marks_jsonl,
    segment_events,
)

_BASE = datetime(2026, 8, 22, 12, tzinfo=UTC)


def _event(seconds: int, *, epoch: int = 1) -> AttEvent:
    return AttEvent(
        timestamp=_BASE + timedelta(seconds=seconds),
        direction=Direction.HOST_TO_DEVICE,
        connection_handle=0x40,
        connection_epoch=epoch,
        peer_address="10:20:30:40:50:60",
        opcode=0x52,
        attribute_handle=0x0025,
        value=bytes([seconds]),
    )


def test_action_marks_round_trip_and_create_timestamp_windows() -> None:
    marks = (
        ActionMark(_BASE, "first action"),
        ActionMark(_BASE + timedelta(seconds=10), "second action"),
    )
    restored = load_action_marks_jsonl(dump_action_marks_jsonl(marks).splitlines())

    segments = segment_events((_event(1), _event(11), _event(12)), restored)

    assert restored == marks
    assert [tuple(event.value for event in segment.events) for segment in segments] == [(b"\x01",), (b"\x0b", b"\x0c")]
    assert segments[1].end is None


def test_marks_require_strict_timestamp_order() -> None:
    repeated = (
        ActionMark(_BASE, "one"),
        ActionMark(_BASE, "two"),
    )

    with pytest.raises(CaptureDataError, match="strictly increasing"):
        segment_events((), repeated)
