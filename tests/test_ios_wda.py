from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.ios.wda import (
    WdaAmbiguousElementError,
    WdaError,
    WdaNotDisplayedError,
    WebDriverAgentClient,
    select_named_element,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


def _source(body: str) -> str:
    return (
        '<XCUIElementTypeApplication visible="true" x="0" y="0" width="100" height="100">'
        f"{body}"
        "</XCUIElementTypeApplication>"
    )


def test_named_wda_action_refuses_ambiguous_controls() -> None:
    source = _source(
        '<XCUIElementTypeButton name="Continue" visible="true" enabled="true" x="10" y="10" width="30" height="20"/>'
        '<XCUIElementTypeButton name="Continue" visible="true" enabled="true" x="10" y="40" width="30" height="20"/>'
    )

    with pytest.raises(WdaAmbiguousElementError, match="2 accessibility elements"):
        select_named_element(source, "Continue")


def test_named_wda_action_refuses_an_offscreen_control_even_when_wda_marks_it_visible() -> None:
    source = _source(
        '<XCUIElementTypeButton name="Continue" visible="true" enabled="true" x="120" y="10" width="30" height="20"/>'
    )

    with pytest.raises(WdaNotDisplayedError, match="not displayed"):
        select_named_element(source, "Continue")


def test_named_wda_action_refuses_a_control_above_the_application_frame() -> None:
    source = _source(
        '<XCUIElementTypeButton name="Continue" visible="true" enabled="true" x="10" y="-30" width="30" height="20"/>'
    )

    with pytest.raises(WdaNotDisplayedError, match="not displayed"):
        select_named_element(source, "Continue")


def test_wda_source_rejects_entity_declarations() -> None:
    with pytest.raises(WdaError, match="prohibited XML"):
        select_named_element("<!DOCTYPE application [<!ENTITY x 'Continue'>]><application/>", "Continue")


class _Transport:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, Mapping[str, object] | None]] = []

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        timeout: float | None = None,
    ) -> Mapping[str, object]:
        del timeout
        self.requests.append((method, path, payload))
        if method == "POST" and path == "/session":
            return {"sessionId": "session-1"}
        raise AssertionError((method, path))


def test_wda_client_opens_the_explicit_bundle() -> None:
    transport = _Transport()
    client = WebDriverAgentClient(transport)

    assert client.open("com.example.app") == "session-1"
    assert client.session_id == "session-1"
    assert transport.requests == [
        (
            "POST",
            "/session",
            {
                "capabilities": {"alwaysMatch": {"bundleId": "com.example.app"}},
                "desiredCapabilities": {"bundleId": "com.example.app"},
            },
        )
    ]
