"""Control payload disclosure in public reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypedDict

from ios_ble_capture.errors import CaptureDataError


class PayloadRedactionPredicate(Protocol):
    """Classify a payload that must not be disclosed."""

    def __call__(self, payload: bytes) -> str | None:
        """Return the withholding reason, or None when the payload is disclosable."""


class RenderedPayloadRecord(TypedDict):
    redacted: bool
    reason: str | None
    value_hex: str | None


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    """The explicit disclosure policy applied to a report."""

    include_raw_payloads: bool = False
    include_identifiers: bool = False
    predicate: PayloadRedactionPredicate | None = None


@dataclass(frozen=True, slots=True)
class RenderedPayload:
    """A report-safe payload representation."""

    value_hex: str | None
    reason: str | None

    @property
    def redacted(self) -> bool:
        """Return whether the raw payload has been withheld."""

        return self.value_hex is None

    def to_record(self) -> RenderedPayloadRecord:
        """Return a JSON-compatible representation."""

        return {
            "redacted": self.redacted,
            "reason": self.reason,
            "value_hex": self.value_hex,
        }

    def to_text(self) -> str:
        """Return one text-safe representation."""

        if self.value_hex is not None:
            return self.value_hex
        return f"<{self.reason} withheld>"


def render_payload(payload: bytes, policy: RedactionPolicy | None = None) -> RenderedPayload:
    """Return a report-safe payload representation under the supplied policy."""

    effective_policy = policy or RedactionPolicy()
    reason = _classify(payload, effective_policy.predicate)
    if reason is not None:
        return RenderedPayload(value_hex=None, reason=reason)
    if effective_policy.include_raw_payloads:
        return RenderedPayload(value_hex=payload.hex(), reason=None)
    return RenderedPayload(value_hex=None, reason="raw payload")


def _classify(payload: bytes, predicate: PayloadRedactionPredicate | None) -> str | None:
    if predicate is None:
        return None
    reason = predicate(payload)
    if reason is None:
        return None
    if not isinstance(reason, str) or not reason.strip():
        raise CaptureDataError("payload redaction predicate must return a non-empty reason or None")
    return reason.strip()
