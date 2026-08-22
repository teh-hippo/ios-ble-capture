from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.ios.wda import (
    FileSessionStore,
    WdaAmbiguousElementError,
    WdaError,
    WdaNotDisplayedError,
    WebDriverAgentClient,
    select_named_element,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


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


class _Transport:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []
        self.live_sessions: set[str] = set()
        self.next_session = 1

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        timeout: float | None = None,
    ) -> Mapping[str, object]:
        del payload, timeout
        self.requests.append((method, path))
        if method == "GET" and path.endswith("/source"):
            session_id = path.split("/")[2]
            if session_id not in self.live_sessions:
                raise WdaError("session is not live")
            return {"value": _source("")}
        if method == "POST" and path == "/session":
            session_id = f"session-{self.next_session}"
            self.next_session += 1
            self.live_sessions.add(session_id)
            return {"sessionId": session_id}
        raise AssertionError((method, path))


def test_cached_wda_session_is_bound_to_target_and_bundle(tmp_path: Path) -> None:
    transport = _Transport()
    store = FileSessionStore(tmp_path / "session.json")

    first = WebDriverAgentClient(
        transport,
        sessions=store,
        target_id="phone-a",
    )
    assert first.open("com.example.one") == "session-1"

    reused = WebDriverAgentClient(
        transport,
        sessions=store,
        target_id="phone-a",
    )
    assert reused.open("com.example.one") == "session-1"

    different_bundle = WebDriverAgentClient(
        transport,
        sessions=store,
        target_id="phone-a",
    )
    assert different_bundle.open("com.example.two") == "session-2"

    different_target = WebDriverAgentClient(
        transport,
        sessions=store,
        target_id="phone-b",
    )
    assert different_target.open("com.example.two") == "session-3"
    assert [request for request in transport.requests if request == ("POST", "/session")] == [
        ("POST", "/session"),
        ("POST", "/session"),
        ("POST", "/session"),
    ]


def test_session_store_requires_an_explicit_target(tmp_path: Path) -> None:
    with pytest.raises(WdaError, match="target identifier"):
        WebDriverAgentClient(
            _Transport(),
            sessions=FileSessionStore(tmp_path / "session.json"),
        )


def test_session_store_rejects_invalid_cached_fields(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    path.write_text('{"bundle_id":null,"session_id":"one","target_id":"phone"}')

    with pytest.raises(WdaError, match="non-empty strings"):
        FileSessionStore(path).load()
