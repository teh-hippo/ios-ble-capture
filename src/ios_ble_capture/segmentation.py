"""Segment timestamped ATT traffic without target protocol assumptions."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from typing import TypedDict

from ios_ble_capture.errors import CaptureDataError
from ios_ble_capture.models import AttEvent


class ActionMarkRecord(TypedDict):
    schema_version: int
    timestamp: str
    label: str


@dataclass(frozen=True, slots=True)
class ActionMark:
    """An operator action associated with an offset-aware timestamp."""

    timestamp: datetime
    label: str

    def __post_init__(self) -> None:
        if self.timestamp.utcoffset() is None:
            raise CaptureDataError("action mark timestamp must include a UTC offset")
        if not self.label.strip():
            raise CaptureDataError("action mark label cannot be empty")

    def to_record(self) -> ActionMarkRecord:
        """Return a JSON-compatible action-mark record."""

        return {"schema_version": 1, "timestamp": self.timestamp.isoformat(), "label": self.label}

    @classmethod
    def from_record(cls, record: ActionMarkRecord) -> ActionMark:
        """Build an action mark from a JSON-compatible record."""

        if record["schema_version"] != 1:
            raise CaptureDataError(f"unsupported action mark schema version: {record['schema_version']}")
        if not isinstance(record["timestamp"], str):
            raise CaptureDataError("action mark timestamp must be a string")
        if not isinstance(record["label"], str):
            raise CaptureDataError("action mark label must be a string")
        try:
            timestamp = datetime.fromisoformat(record["timestamp"])
        except (TypeError, ValueError) as error:
            raise CaptureDataError(f"invalid action mark timestamp: {error}") from error
        return cls(timestamp=timestamp, label=record["label"])


@dataclass(frozen=True, slots=True)
class EventSegment:
    """A time window and the events that occur in it."""

    label: str
    start: datetime
    end: datetime | None
    events: tuple[AttEvent, ...]


@dataclass(frozen=True, slots=True)
class Transaction:
    """A contiguous event group that does not cross a connection epoch."""

    ordinal: int
    events: tuple[AttEvent, ...]

    @property
    def start(self) -> datetime:
        """Return the timestamp of the first event."""

        return self.events[0].timestamp

    @property
    def end(self) -> datetime:
        """Return the timestamp of the final event."""

        return self.events[-1].timestamp


TransactionBoundary = Callable[[AttEvent, AttEvent], bool]


def load_action_marks_jsonl(lines: Iterable[str]) -> tuple[ActionMark, ...]:
    """Parse JSONL action marks, rejecting malformed records deterministically."""

    marks: list[ActionMark] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw_record = json.loads(line)
        except json.JSONDecodeError as error:
            raise CaptureDataError(f"invalid action mark JSON on line {number}: {error.msg}") from error
        if not isinstance(raw_record, dict):
            raise CaptureDataError(f"action mark on line {number} must be an object")
        try:
            record: ActionMarkRecord = {
                "schema_version": raw_record["schema_version"],
                "timestamp": raw_record["timestamp"],
                "label": raw_record["label"],
            }
        except KeyError as error:
            raise CaptureDataError(f"action mark on line {number} is missing {error.args[0]!r}") from error
        marks.append(ActionMark.from_record(record))
    _validate_mark_order(marks)
    return tuple(marks)


def dump_action_marks_jsonl(marks: Iterable[ActionMark]) -> str:
    """Serialise action marks as deterministic JSONL."""

    mark_list = tuple(marks)
    _validate_mark_order(mark_list)
    return "".join(json.dumps(mark.to_record(), sort_keys=True, separators=(",", ":")) + "\n" for mark in mark_list)


def segment_events(
    events: Iterable[AttEvent],
    marks: Iterable[ActionMark],
    *,
    final_end: datetime | None = None,
) -> tuple[EventSegment, ...]:
    """Split events into timestamp windows starting at each action mark."""

    event_list = tuple(events)
    _validate_event_order(event_list)
    mark_list = tuple(marks)
    _validate_mark_order(mark_list)
    if not mark_list:
        if not event_list:
            return ()
        return (EventSegment("whole-capture", event_list[0].timestamp, None, event_list),)

    if final_end is not None and final_end.utcoffset() is None:
        raise CaptureDataError("final segment end must include a UTC offset")
    if final_end is not None and final_end < mark_list[-1].timestamp:
        raise CaptureDataError("final segment end precedes the final action mark")

    segments: list[EventSegment] = []
    for index, mark in enumerate(mark_list):
        end = mark_list[index + 1].timestamp if index + 1 < len(mark_list) else final_end
        selected = tuple(
            event
            for event in event_list
            if event.timestamp >= mark.timestamp and (end is None or event.timestamp < end)
        )
        segments.append(EventSegment(mark.label, mark.timestamp, end, selected))
    return tuple(segments)


def segment_transactions(
    events: Iterable[AttEvent],
    *,
    boundary: TransactionBoundary | None = None,
) -> tuple[Transaction, ...]:
    """Group events until a caller boundary or a connection-epoch change."""

    event_list = tuple(events)
    _validate_event_order(event_list)
    if not event_list:
        return ()

    groups: list[list[AttEvent]] = [[event_list[0]]]
    for event in event_list[1:]:
        previous = groups[-1][-1]
        crosses_connection = (
            event.connection_handle != previous.connection_handle or event.connection_epoch != previous.connection_epoch
        )
        if crosses_connection or (boundary is not None and boundary(previous, event)):
            groups.append([event])
        else:
            groups[-1].append(event)
    return tuple(Transaction(index, tuple(group)) for index, group in enumerate(groups, start=1))


def _validate_mark_order(marks: Sequence[ActionMark]) -> None:
    if any(next_mark.timestamp <= mark.timestamp for mark, next_mark in pairwise(marks)):
        raise CaptureDataError("action marks must have strictly increasing timestamps")


def _validate_event_order(events: Sequence[AttEvent]) -> None:
    if any(next_event.timestamp < event.timestamp for event, next_event in pairwise(events)):
        raise CaptureDataError("ATT events must be ordered by timestamp")
