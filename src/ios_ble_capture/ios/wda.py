"""Generic WebDriverAgent transport and safe accessibility actions."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol
from xml.etree import ElementTree as ET

if TYPE_CHECKING:
    from pathlib import Path


MIN_SLIDER_WIDTH = 2


class WdaError(RuntimeError):
    """Raised when WebDriverAgent cannot safely perform a requested operation."""


class WdaNotFoundError(WdaError):
    """Raised when an exact accessibility name is absent."""


class WdaAmbiguousElementError(WdaError):
    """Raised when a named action would need to guess between elements."""


class WdaNotDisplayedError(WdaError):
    """Raised when an element is not safely displayed for actuation."""


@dataclass(frozen=True, slots=True)
class Rectangle:
    """A rectangle in WDA points."""

    x: int
    y: int
    width: int
    height: int

    def intersects(self, other: Rectangle) -> bool:
        """Return whether this rectangle overlaps another rectangle."""

        return (
            self.width > 0
            and self.height > 0
            and other.width > 0
            and other.height > 0
            and self.x < other.x + other.width
            and other.x < self.x + self.width
            and self.y < other.y + other.height
            and other.y < self.y + self.height
        )


@dataclass(frozen=True, slots=True)
class AccessibilityElement:
    """The actuation-relevant portion of one WDA source-tree node."""

    element_type: str
    name: str | None
    label: str | None
    value: str | None
    enabled: bool
    wda_visible: bool
    onscreen: bool
    rectangle: Rectangle | None

    @property
    def displayed(self) -> bool:
        """Return whether WDA and the visible application frame agree on display state."""

        return self.wda_visible and self.onscreen


def parse_accessibility_source(source: str) -> tuple[AccessibilityElement, ...]:
    """Read WDA XML into immutable accessibility elements."""

    root = _parse_source(source)
    frame = _application_frame(root)
    return tuple(_element_from_xml(element, frame) for element in root.iter())


def named_elements(source: str) -> tuple[AccessibilityElement, ...]:
    """Return named elements from a WDA XML source tree."""

    return tuple(element for element in parse_accessibility_source(source) if element.name)


def matching_elements(source: str, name: str) -> tuple[AccessibilityElement, ...]:
    """Return every element with an exact accessibility name."""

    return tuple(element for element in parse_accessibility_source(source) if element.name == name)


def select_named_element(source: str, name: str) -> AccessibilityElement:
    """Select one exact, displayed and enabled element, refusing every unsafe guess."""

    matches = matching_elements(source, name)
    if not matches:
        raise WdaNotFoundError(f"no accessibility element is named {name!r}")
    if len(matches) != 1:
        raise WdaAmbiguousElementError(
            f"{len(matches)} accessibility elements are named {name!r}; navigate until exactly one is displayed"
        )
    element = matches[0]
    if not element.displayed:
        raise WdaNotDisplayedError(f"{name!r} is present but not displayed")
    if not element.enabled:
        raise WdaError(f"{name!r} is displayed but disabled")
    return element


def _parse_source(source: str) -> ET.Element:
    if "<!doctype" in source.casefold() or "<!entity" in source.casefold():
        raise WdaError("WDA source contains a prohibited XML declaration")
    try:
        return ET.fromstring(source)  # noqa: S314
    except ET.ParseError as error:
        raise WdaError(f"WDA returned invalid accessibility XML: {error}") from error


def _application_frame(root: ET.Element) -> Rectangle | None:
    application = next((element for element in root.iter() if element.tag == "XCUIElementTypeApplication"), None)
    return _rectangle(application) if application is not None else None


def _element_from_xml(element: ET.Element, frame: Rectangle | None) -> AccessibilityElement:
    rectangle = _rectangle(element)
    onscreen = frame is None or (rectangle is not None and rectangle.intersects(frame))
    return AccessibilityElement(
        element_type=element.tag,
        name=element.get("name"),
        label=element.get("label"),
        value=element.get("value"),
        enabled=element.get("enabled") != "false",
        wda_visible=element.get("visible") == "true",
        onscreen=onscreen,
        rectangle=rectangle,
    )


def _rectangle(element: ET.Element) -> Rectangle | None:
    try:
        return Rectangle(
            x=int(element.attrib["x"]),
            y=int(element.attrib["y"]),
            width=int(element.attrib["width"]),
            height=int(element.attrib["height"]),
        )
    except (KeyError, ValueError):
        return None


class WdaTransport(Protocol):
    """The JSON-over-HTTP transport used by WebDriverAgent."""

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        timeout: float = 60.0,
    ) -> Mapping[str, object]:
        """Make a WebDriverAgent request."""


class UrllibWdaTransport:
    """A standard-library WDA transport with no import-time third-party dependency."""

    def __init__(self, base_url: str) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise WdaError("the WDA base URL must use HTTP or HTTPS")
        self._base_url = base_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        timeout: float = 60.0,
    ) -> Mapping[str, object]:
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(  # noqa: S310
            f"{self._base_url}{path}",
            data=body,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                decoded = json.loads(response.read())
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            raise WdaError(f"{method} {path} returned HTTP {error.code}: {detail[:300]}") from error
        except urllib.error.URLError as error:
            raise WdaError(f"{method} {path} failed: {error.reason}") from error
        except json.JSONDecodeError as error:
            raise WdaError(f"{method} {path} returned invalid JSON") from error
        if not isinstance(decoded, Mapping):
            raise WdaError(f"{method} {path} returned a JSON value instead of an object")
        return decoded


class WebDriverAgentClient:
    """A generic WDA client with display-safe named actions."""

    def __init__(self, transport: WdaTransport) -> None:
        self._transport = transport
        self._session_id: str | None = None

    @property
    def session_id(self) -> str | None:
        """Return the active WDA session identifier."""

        return self._session_id

    def open(self, bundle_id: str) -> str:
        """Create a WDA session for a target-supplied application ID."""

        if not bundle_id or bundle_id != bundle_id.strip():
            raise WdaError("an application bundle ID must be supplied explicitly")
        response = self._transport.request(
            "POST",
            "/session",
            {
                "capabilities": {"alwaysMatch": {"bundleId": bundle_id}},
                "desiredCapabilities": {"bundleId": bundle_id},
            },
        )
        session_id = _session_id(response)
        self._session_id = session_id
        return session_id

    def source(self) -> str:
        """Return the active application's accessibility source XML."""

        response = self._transport.request("GET", f"/session/{self._require_session()}/source")
        value = response.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a source string")
        return value

    def inspect(self) -> tuple[AccessibilityElement, ...]:
        """Return the active application's accessibility elements."""

        return parse_accessibility_source(self.source())

    def tap_named(self, name: str) -> AccessibilityElement:
        """Tap one exact displayed element, refusing ambiguous and hidden matches."""

        source = self.source()
        element = select_named_element(source, name)
        element_id = self._element_id(_class_chain(element, source))
        displayed = self._transport.request(
            "GET",
            f"/session/{self._require_session()}/element/{element_id}/displayed",
        ).get("value")
        if displayed is not True:
            raise WdaNotDisplayedError(f"{name!r} resolved but WDA does not report it displayed")
        self._transport.request("POST", f"/session/{self._require_session()}/element/{element_id}/click", {})
        return element

    def type_text(self, text: str) -> None:
        """Type text into WDA's active field without placing it in a shell command."""

        self._transport.request(
            "POST",
            f"/session/{self._require_session()}/wda/keys",
            {"value": list(text)},
        )

    def tap_point(self, x: int, y: int) -> None:
        """Tap a point in WDA coordinates."""

        self._perform_touch(
            (
                {"type": "pointerMove", "duration": 0, "x": x, "y": y},
                {"type": "pointerDown", "button": 0},
                {"type": "pause", "duration": 120},
                {"type": "pointerUp", "button": 0},
            )
        )

    def swipe(self, x1: int, y1: int, x2: int, y2: int) -> None:
        """Swipe between two WDA coordinates with a human-scale path."""

        moves = tuple(
            {
                "type": "pointerMove",
                "duration": 40,
                "x": x1 + round((x2 - x1) * step / 12),
                "y": y1 + round((y2 - y1) * step / 12),
            }
            for step in range(1, 13)
        )
        self._perform_touch(
            (
                {"type": "pointerMove", "duration": 0, "x": x1, "y": y1},
                {"type": "pointerDown", "button": 0},
                {"type": "pause", "duration": 200},
                *moves,
                {"type": "pause", "duration": 200},
                {"type": "pointerUp", "button": 0},
            )
        )

    def slide_named(self, name: str, *, start: float, end: float) -> AccessibilityElement:
        """Drag across one exact displayed element."""

        if not 0 <= start <= 1 or not 0 <= end <= 1:
            raise WdaError("slide positions must be fractions from 0 to 1")
        source = self.source()
        element = select_named_element(source, name)
        if element.rectangle is None or element.rectangle.width < MIN_SLIDER_WIDTH:
            raise WdaNotDisplayedError(f"{name!r} has no usable displayed track")
        rectangle = element.rectangle
        y = rectangle.y + rectangle.height // 2
        self.swipe(rectangle.x + round(rectangle.width * start), y, rectangle.x + round(rectangle.width * end), y)
        return element

    def screenshot(self, destination: Path) -> Path:
        """Write one PNG screenshot to a caller-supplied destination."""

        value = self._transport.request("GET", f"/session/{self._require_session()}/screenshot").get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a screenshot")
        try:
            image = base64.b64decode(value, validate=True)
        except ValueError as error:
            raise WdaError("WDA returned an invalid screenshot") from error
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(image)
        return destination

    def _perform_touch(self, actions: tuple[Mapping[str, object], ...]) -> None:
        self._transport.request(
            "POST",
            f"/session/{self._require_session()}/actions",
            {
                "actions": [
                    {
                        "type": "pointer",
                        "id": "finger1",
                        "parameters": {"pointerType": "touch"},
                        "actions": list(actions),
                    }
                ]
            },
            timeout=30.0,
        )

    def _element_id(self, chain: str) -> str:
        response = self._transport.request(
            "POST",
            f"/session/{self._require_session()}/element",
            {"using": "class chain", "value": chain},
        )
        value = response.get("value")
        if not isinstance(value, Mapping):
            raise WdaError(f"WDA found no element for {chain!r}")
        element_id = value.get("ELEMENT") or value.get("element-6066-11e4-a52e-4f735466cecf")
        if not isinstance(element_id, str) or not element_id:
            raise WdaError(f"WDA found no element ID for {chain!r}")
        return element_id

    def _require_session(self) -> str:
        if self._session_id is None:
            raise WdaError("open a WDA session before making this request")
        return self._session_id


def _session_id(response: Mapping[str, object]) -> str:
    value = response.get("value")
    nested = value.get("sessionId") if isinstance(value, Mapping) else None
    session_id = response.get("sessionId") or nested
    if not isinstance(session_id, str) or not session_id:
        raise WdaError("WDA did not return a session identifier")
    return session_id


def _class_chain(element: AccessibilityElement, source: str) -> str:
    if element.name is None:
        raise WdaError("an unnamed element cannot be actuated by name")
    if '"' in element.name or "`" in element.name:
        raise WdaError("an accessibility name containing WDA class-chain syntax cannot be actuated safely")
    matches = tuple(
        candidate
        for candidate in matching_elements(source, element.name)
        if candidate.element_type == element.element_type
    )
    if len(matches) != 1:
        raise WdaAmbiguousElementError(f"WDA class chain cannot uniquely identify {element.name!r}")
    return f'**/{element.element_type}[`name == "{element.name}"`][1]'
