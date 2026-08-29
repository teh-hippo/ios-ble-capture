"""Render report-safe observations and deterministic differences."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, TypedDict, cast

from ios_ble_capture.redaction import RedactionPolicy, RenderedPayloadRecord, render_payload

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ios_ble_capture.models import AttEvent

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None


class EventReportRecord(TypedDict):
    schema_version: int
    timestamp: str
    direction: str
    connection_handle: int
    connection_epoch: int
    peer_address: str | None
    peer_address_redacted: bool
    opcode: int
    attribute_handle: int | None
    value_offset: int | None
    payload: RenderedPayloadRecord


@dataclass(frozen=True, slots=True)
class JsonDifference:
    """One deterministic difference between JSON-compatible values."""

    path: str
    before_present: bool
    before: JsonValue | None
    after_present: bool
    after: JsonValue | None

    def to_record(self) -> dict[str, JsonValue]:
        """Return a JSON-compatible difference record."""

        return cast("dict[str, JsonValue]", asdict(self))


def report_event(event: AttEvent, policy: RedactionPolicy | None = None) -> EventReportRecord:
    """Return an event record with its payload rendered under one policy."""

    effective_policy = policy or RedactionPolicy()
    peer_address, peer_address_redacted = _report_identifier(
        event.peer_address,
        effective_policy,
    )
    return {
        "schema_version": 1,
        "timestamp": event.timestamp.isoformat(),
        "direction": event.direction.value,
        "connection_handle": event.connection_handle,
        "connection_epoch": event.connection_epoch,
        "peer_address": peer_address,
        "peer_address_redacted": peer_address_redacted,
        "opcode": event.opcode,
        "attribute_handle": event.attribute_handle,
        "value_offset": event.value_offset,
        "payload": render_payload(event.value, effective_policy).to_record(),
    }


def report_events(events: Iterable[AttEvent], policy: RedactionPolicy | None = None) -> tuple[EventReportRecord, ...]:
    """Return report-safe structured records for events."""

    return tuple(report_event(event, policy) for event in events)


def render_events_text(events: Iterable[AttEvent], policy: RedactionPolicy | None = None) -> str:
    """Render report-safe events as deterministic text lines."""

    lines = []
    effective_policy = policy or RedactionPolicy()
    for event in events:
        payload = render_payload(event.value, effective_policy).to_text()
        peer_address, peer_redacted = _report_identifier(
            event.peer_address,
            effective_policy,
        )
        peer = "<withheld>" if peer_redacted else peer_address or "unattributed"
        attribute_handle = "-" if event.attribute_handle is None else f"0x{event.attribute_handle:04x}"
        value_offset = "-" if event.value_offset is None else str(event.value_offset)
        lines.append(
            " ".join(
                (
                    event.timestamp.isoformat(),
                    event.direction.value,
                    f"peer={peer}",
                    f"connection=0x{event.connection_handle:x}/{event.connection_epoch}",
                    f"opcode=0x{event.opcode:02x}",
                    f"attribute={attribute_handle}",
                    f"offset={value_offset}",
                    f"payload={payload}",
                ),
            ),
        )
    return "\n".join(lines)


def diff_decoded_json(before: JsonValue, after: JsonValue) -> tuple[JsonDifference, ...]:
    """Return structural differences between decoded JSON-compatible values."""

    differences: list[JsonDifference] = []
    _diff_json("$", before, after, differences)
    return tuple(differences)


def render_decoded_json_diff(differences: Iterable[JsonDifference]) -> str:
    """Render JSON differences as deterministic JSONL."""

    return "".join(
        json.dumps(difference.to_record(), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        for difference in differences
    )


def render_decoded_json(value: JsonValue) -> str:
    """Render decoded JSON as deterministic text."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def _diff_json(path: str, before: JsonValue, after: JsonValue, differences: list[JsonDifference]) -> None:
    if type(before) is not type(after):
        differences.append(JsonDifference(path, before_present=True, before=before, after_present=True, after=after))
        return
    if isinstance(before, dict) and isinstance(after, dict):
        _diff_mappings(path, before, after, differences)
        return
    if isinstance(before, list) and isinstance(after, list):
        _diff_lists(path, before, after, differences)
        return
    if before != after:
        differences.append(JsonDifference(path, before_present=True, before=before, after_present=True, after=after))


def _diff_mappings(
    path: str,
    before: dict[str, JsonValue],
    after: dict[str, JsonValue],
    differences: list[JsonDifference],
) -> None:
    for key in sorted(set(before) | set(after)):
        child_path = f"{path}.{key}"
        if key not in before:
            differences.append(
                JsonDifference(child_path, before_present=False, before=None, after_present=True, after=after[key])
            )
        elif key not in after:
            differences.append(
                JsonDifference(child_path, before_present=True, before=before[key], after_present=False, after=None)
            )
        else:
            _diff_json(child_path, before[key], after[key], differences)


def _diff_lists(
    path: str,
    before: list[JsonValue],
    after: list[JsonValue],
    differences: list[JsonDifference],
) -> None:
    for index in range(max(len(before), len(after))):
        child_path = f"{path}[{index}]"
        if index == len(before):
            differences.append(
                JsonDifference(child_path, before_present=False, before=None, after_present=True, after=after[index])
            )
        elif index == len(after):
            differences.append(
                JsonDifference(child_path, before_present=True, before=before[index], after_present=False, after=None)
            )
        else:
            _diff_json(child_path, before[index], after[index], differences)


def _report_identifier(
    value: str | None,
    policy: RedactionPolicy,
) -> tuple[str | None, bool]:
    if value is None or policy.include_identifiers:
        return value, False
    return None, True
