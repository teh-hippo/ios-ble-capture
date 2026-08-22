from __future__ import annotations

import pytest

from ios_ble_capture.errors import CaptureDataError
from ios_ble_capture.redaction import RedactionPolicy, render_payload


def test_raw_payloads_are_withheld_unless_explicitly_requested() -> None:
    assert render_payload(b"\x01\x02").to_record() == {
        "redacted": True,
        "reason": "raw payload",
        "value_hex": None,
    }
    assert render_payload(b"\x01\x02", RedactionPolicy(include_raw_payloads=True)).to_text() == "0102"


def test_target_predicate_withholds_payload_even_when_raw_rendering_is_enabled() -> None:
    policy = RedactionPolicy(
        include_raw_payloads=True,
        predicate=lambda payload: "target credential" if payload.startswith(b"\xaa") else None,
    )

    rendered = render_payload(b"\xaa\x01", policy)

    assert rendered.to_record() == {
        "redacted": True,
        "reason": "target credential",
        "value_hex": None,
    }
    assert rendered.to_text() == "<target credential withheld>"


def test_predicate_must_return_a_non_empty_reason_or_none() -> None:
    with pytest.raises(CaptureDataError, match="non-empty reason"):
        render_payload(b"\x01", RedactionPolicy(predicate=lambda _payload: " "))
