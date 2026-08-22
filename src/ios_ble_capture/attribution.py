"""Attribute ATT events to peers without merging connection epochs."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ios_ble_capture.errors import CaptureDataError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ios_ble_capture.models import AttEvent

_UNATTRIBUTED_PREFIX = "?conn-"
_PEER_ADDRESS_HEX_LENGTH = 12


class AttributionError(CaptureDataError):
    """Raised when a capture cannot be attributed safely."""


class AmbiguousSourceError(AttributionError):
    """Raised when a selection would mix multiple capture sources."""


class ExpectedPeerMissingError(AttributionError):
    """Raised when the requested peer does not occur in the capture."""


class UnattributedTrafficError(AttributionError):
    """Raised when traffic is present without a peer identity."""


@dataclass(frozen=True, slots=True)
class Source:
    """One peer or unattributed connection epoch in a capture."""

    identifier: str
    peer_address: str | None
    connection_epochs: tuple[int, ...]
    event_count: int

    @property
    def unattributed(self) -> bool:
        """Return whether this source was not linked to a peer address."""

        return self.peer_address is None


@dataclass(frozen=True, slots=True)
class SourceSelection:
    """A safely selected source and its corresponding ATT events."""

    source: Source
    events: tuple[AttEvent, ...]


def catalogue_sources(events: Iterable[AttEvent]) -> tuple[Source, ...]:
    """Return stable source summaries for the supplied ATT events."""

    event_list = tuple(events)
    labels = _unattributed_labels(event_list)
    mutable_sources: OrderedDict[str, tuple[str | None, list[int], int]] = OrderedDict()
    for event in event_list:
        identifier = source_identifier(event, labels)
        peer_address = _canonical_peer(event.peer_address) if event.peer_address is not None else None
        source = mutable_sources.get(identifier)
        if source is None:
            mutable_sources[identifier] = (peer_address, [event.connection_epoch], 1)
            continue
        source_peer, epochs, count = source
        if event.connection_epoch not in epochs:
            epochs.append(event.connection_epoch)
        mutable_sources[identifier] = (source_peer, epochs, count + 1)
    return tuple(
        Source(identifier, peer_address, tuple(epochs), count)
        for identifier, (peer_address, epochs, count) in mutable_sources.items()
    )


def source_identifier(event: AttEvent, labels: dict[int, str] | None = None) -> str:
    """Return the peer identity or epoch-specific identifier for one event."""

    if event.peer_address is not None:
        return _canonical_peer(event.peer_address)
    if labels is None:
        labels = _unattributed_labels((event,))
    return labels[event.connection_epoch]


def resolve_source(sources: Iterable[Source], selector: str) -> Source:
    """Resolve a complete peer address, unique address tail, or source identifier."""

    known = tuple(sources)
    stripped = selector.strip()
    if not stripped:
        raise AttributionError("source selector cannot be empty")
    direct = [source for source in known if source.identifier.casefold() == stripped.casefold()]
    if len(direct) == 1:
        return direct[0]
    if len(direct) > 1:
        raise AmbiguousSourceError(
            f"source selector {selector!r} matches multiple sources: {_known(known)}",
        )

    normalised = _normalise_address_selector(stripped)
    peers = [source for source in known if source.peer_address is not None]
    exact = [
        source
        for source in peers
        if source.peer_address is not None and source.peer_address.replace(":", "") == normalised
    ]
    if len(exact) == 1:
        return exact[0]
    matches = [
        source
        for source in peers
        if source.peer_address is not None and source.peer_address.replace(":", "").endswith(normalised)
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ExpectedPeerMissingError(f"no captured source matches {selector!r}; captured: {_known(known)}")
    raise AmbiguousSourceError(f"source selector {selector!r} matches {len(matches)} peers: {_known(matches)}")


def select_source(
    events: Iterable[AttEvent],
    *,
    expected_peer: str | None = None,
    source: str | None = None,
    allow_unattributed: bool = False,
) -> SourceSelection:
    """Select one source, refusing absent peers, mixed sources, and unnamed traffic."""

    if expected_peer is not None and source is not None:
        raise AttributionError("expected_peer and source cannot be selected together")

    event_list = tuple(events)
    sources = catalogue_sources(event_list)
    if not sources:
        raise ExpectedPeerMissingError("capture contains no ATT sources")

    if expected_peer is not None:
        selected = resolve_source(sources, expected_peer)
        if selected.unattributed:
            raise ExpectedPeerMissingError(f"expected peer {expected_peer!r} is absent; captured: {_known(sources)}")
    elif source is not None:
        selected = resolve_source(sources, source)
    else:
        if len(sources) != 1:
            raise AmbiguousSourceError(
                f"capture contains {len(sources)} sources; select one explicitly: {_known(sources)}",
            )
        selected = sources[0]

    unattributed = tuple(candidate for candidate in sources if candidate.unattributed)
    if unattributed and not allow_unattributed:
        raise UnattributedTrafficError(
            f"capture contains unattributed traffic on {', '.join(item.identifier for item in unattributed)}; "
            "set allow_unattributed to accept it",
        )

    labels = _unattributed_labels(event_list)
    selected_events = tuple(event for event in event_list if source_identifier(event, labels) == selected.identifier)
    return SourceSelection(selected, selected_events)


def _unattributed_labels(events: Iterable[AttEvent]) -> dict[int, str]:
    epochs_by_handle: OrderedDict[int, list[int]] = OrderedDict()
    for event in events:
        if event.peer_address is not None:
            continue
        epochs = epochs_by_handle.setdefault(event.connection_handle, [])
        if event.connection_epoch not in epochs:
            epochs.append(event.connection_epoch)
    labels: dict[int, str] = {}
    for handle, epochs in epochs_by_handle.items():
        suffix_required = len(epochs) > 1
        for index, epoch in enumerate(epochs, start=1):
            suffix = f"#{index}" if suffix_required else ""
            labels[epoch] = f"{_UNATTRIBUTED_PREFIX}0x{handle:x}{suffix}"
    return labels


def _canonical_peer(address: str) -> str:
    octets = _normalise_address_selector(address)
    if len(octets) != _PEER_ADDRESS_HEX_LENGTH:
        raise AttributionError(f"peer address must contain 12 hexadecimal digits: {address!r}")
    return ":".join(octets[index : index + 2] for index in range(0, len(octets), 2))


def _normalise_address_selector(selector: str) -> str:
    normalised = selector.replace(":", "").replace("-", "").strip().upper()
    if not normalised or any(character not in "0123456789ABCDEF" for character in normalised):
        raise AttributionError(f"invalid peer selector: {selector!r}")
    return normalised


def _known(sources: Iterable[Source]) -> str:
    return ", ".join(source.identifier for source in sources) or "none"
