from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ios_ble_capture.attribution import (
    AmbiguousSourceError,
    ExpectedPeerMissingError,
    UnattributedTrafficError,
    catalogue_sources,
    resolve_source,
    select_source,
)
from ios_ble_capture.models import AttEvent, Direction


def _event(
    *,
    handle: int,
    epoch: int,
    peer: str | None,
    value: bytes = b"",
) -> AttEvent:
    return AttEvent(
        timestamp=datetime(2026, 8, 22, tzinfo=UTC),
        direction=Direction.HOST_TO_DEVICE,
        connection_handle=handle,
        connection_epoch=epoch,
        peer_address=peer,
        opcode=0x52,
        attribute_handle=0x0025,
        value=value,
    )


def test_requires_an_explicit_selection_for_multiple_peers() -> None:
    events = (
        _event(handle=0x40, epoch=1, peer="10:20:30:40:50:60", value=b"\x01"),
        _event(handle=0x41, epoch=2, peer="A0:B0:C0:D0:E0:F0", value=b"\x02"),
    )

    with pytest.raises(AmbiguousSourceError, match="contains 2 sources"):
        select_source(events)

    selection = select_source(events, expected_peer="c0:d0:e0:f0")
    assert selection.source.identifier == "A0:B0:C0:D0:E0:F0"
    assert selection.events == (events[1],)


def test_expected_peer_must_exist_in_the_capture() -> None:
    events = (_event(handle=0x40, epoch=1, peer="10:20:30:40:50:60"),)

    with pytest.raises(ExpectedPeerMissingError, match="no captured source"):
        select_source(events, expected_peer="AA:BB:CC:DD:EE:FF")


def test_unattributed_traffic_is_refused_separately_from_mixed_peers() -> None:
    named = _event(handle=0x40, epoch=1, peer="10:20:30:40:50:60")
    unnamed = _event(handle=0x41, epoch=2, peer=None)

    with pytest.raises(UnattributedTrafficError, match=r"\?conn-0x41"):
        select_source((named, unnamed), expected_peer="10:20:30:40:50:60")

    accepted = select_source(
        (named, unnamed),
        expected_peer="10:20:30:40:50:60",
        allow_unattributed=True,
    )
    assert accepted.events == (named,)


def test_reused_unattributed_handles_never_merge_epochs() -> None:
    events = (
        _event(handle=0x40, epoch=1, peer=None),
        _event(handle=0x40, epoch=2, peer=None),
    )
    sources = catalogue_sources(events)

    assert [source.identifier for source in sources] == ["?conn-0x40#1", "?conn-0x40#2"]
    assert resolve_source(sources, "?conn-0x40#2") == sources[1]
