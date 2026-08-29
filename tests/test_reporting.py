from __future__ import annotations

from datetime import UTC, datetime

from ios_ble_capture.models import AttEvent, Direction
from ios_ble_capture.redaction import RedactionPolicy
from ios_ble_capture.reporting import (
    diff_decoded_json,
    render_decoded_json,
    render_decoded_json_diff,
    render_events_text,
    report_event,
)


def _event(value: bytes) -> AttEvent:
    return AttEvent(
        timestamp=datetime(2026, 8, 22, tzinfo=UTC),
        direction=Direction.DEVICE_TO_HOST,
        connection_handle=0x40,
        connection_epoch=1,
        peer_address="10:20:30:40:50:60",
        opcode=0x1B,
        attribute_handle=0x0026,
        value=value,
    )


def test_structured_and_text_event_reports_apply_the_same_redaction() -> None:
    event = _event(b"\xde\xad")

    record = report_event(event)
    text = render_events_text((event,))

    assert record["payload"]["reason"] == "raw payload"
    assert record["payload"]["value_hex"] is None
    assert record["peer_address"] is None
    assert record["peer_address_redacted"] is True
    assert "10:20:30:40:50:60" not in text
    assert "dead" not in text
    assert "<raw payload withheld>" in text
    assert "peer=<withheld>" in text


def test_identifiers_require_explicit_report_opt_in() -> None:
    policy = RedactionPolicy(include_identifiers=True)

    record = report_event(_event(b"\x01"), policy)

    assert record["peer_address"] == "10:20:30:40:50:60"
    assert record["peer_address_redacted"] is False


def test_target_predicate_applies_to_event_reports() -> None:
    policy = RedactionPolicy(
        include_raw_payloads=True,
        predicate=lambda payload: "operator secret" if payload == b"\xca\xfe" else None,
    )
    event_text = render_events_text((_event(b"\xca\xfe"),), policy)

    assert "<operator secret withheld>" in event_text
    assert "cafe" not in event_text


def test_json_differences_are_deterministic() -> None:
    json_difference = diff_decoded_json(
        {"nested": [1], "unchanged": True},
        {"nested": [2, 3], "added": "value", "unchanged": True},
    )

    assert [difference.path for difference in json_difference] == ["$.added", "$.nested[0]", "$.nested[1]"]
    assert render_decoded_json_diff(json_difference).splitlines()[0].startswith('{"after":"value"')
    assert render_decoded_json({"z": 1, "a": 2}) == '{"a":2,"z":1}\n'
