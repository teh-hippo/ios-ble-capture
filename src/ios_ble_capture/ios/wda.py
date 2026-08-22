"""Generic WebDriverAgent lifecycle, signing and safe accessibility actions."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import plistlib
import shutil
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any, Protocol, cast
from xml.etree import ElementTree as ET

from ios_ble_capture.ios.config import IosTarget, RsdBackend
from ios_ble_capture.ios.process import Command, ProcessCleanupError, ProcessStarter, ProcessSupervisor
from ios_ble_capture.ios.usb import UsbMuxConfiguration

if TYPE_CHECKING:
    from collections.abc import Awaitable
    from contextlib import AbstractAsyncContextManager
    from pathlib import Path
    from types import ModuleType


MAX_TCP_PORT = 65_535
MIN_SLIDER_WIDTH = 2


class WdaError(RuntimeError):
    """Raised when WebDriverAgent cannot safely perform a requested operation."""


class WdaNotFoundError(WdaError):
    """Raised when an exact accessibility name is absent."""


class WdaAmbiguousElementError(WdaError):
    """Raised when a named action would need to guess between elements."""


class WdaNotDisplayedError(WdaError):
    """Raised when an element is not safely displayed for actuation."""


class WdaOptionalDependencyError(WdaError):
    """Raised when an optional iPhone automation dependency is unavailable."""


class _UserspaceTunnelFactory(Protocol):
    def __call__(self, *, serial: str) -> AbstractAsyncContextManager[object]: ...


class _TunneldLookup(Protocol):
    def __call__(self, udid: str) -> Awaitable[object | None]: ...


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
    parser = _defused_fromstring()
    if parser is None:
        # WDA source is local device output.  Block DTDs before the stdlib fallback is used.
        if "<!doctype" in source.casefold() or "<!entity" in source.casefold():
            raise WdaError("WDA source contains a prohibited XML declaration") from None
        try:
            return ET.fromstring(source)  # noqa: S314
        except ET.ParseError as error:
            raise WdaError(f"WDA returned invalid accessibility XML: {error}") from error
    try:
        return parser(source)
    except Exception as error:
        raise WdaError(f"WDA returned invalid accessibility XML: {error}") from error


def _defused_fromstring() -> Callable[[str], ET.Element] | None:
    try:
        module = import_module("defusedxml.ElementTree")
    except ModuleNotFoundError:
        return None
    return cast("Callable[[str], ET.Element]", _module_attribute(module, "fromstring"))


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


class SessionStore(Protocol):
    """Persists a reusable WDA session bound to one target and application."""

    def load(self) -> WdaSession | None:
        """Load a session record if one is available."""

    def save(self, session: WdaSession) -> None:
        """Persist a session record."""

    def clear(self) -> None:
        """Remove a persisted session identifier."""


@dataclass(frozen=True, slots=True)
class WdaSession:
    """A cached WDA session bound to one explicit target and bundle."""

    session_id: str
    target_id: str
    bundle_id: str

    def __post_init__(self) -> None:
        if not self.session_id or not self.target_id or not self.bundle_id:
            raise WdaError("cached WDA session fields cannot be empty")


@dataclass(frozen=True, slots=True)
class FileSessionStore:
    """An explicit local session path owned by the caller's run directory."""

    path: Path

    def load(self) -> WdaSession | None:
        """Load a complete session binding."""

        if self.path.is_symlink():
            raise WdaError(f"refusing to read WDA session through a symbolic link: {self.path}")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as error:
            raise WdaError(f"cannot read WDA session cache: {error}") from error
        if not isinstance(value, Mapping):
            raise WdaError("WDA session cache must contain an object")
        fields = {name: value.get(name) for name in ("session_id", "target_id", "bundle_id")}
        if not all(isinstance(item, str) and item for item in fields.values()):
            raise WdaError("WDA session cache fields must be non-empty strings")
        return WdaSession(
            session_id=cast("str", fields["session_id"]),
            target_id=cast("str", fields["target_id"]),
            bundle_id=cast("str", fields["bundle_id"]),
        )

    def save(self, session: WdaSession) -> None:
        """Write a private session binding."""

        if self.path.is_symlink():
            raise WdaError(f"refusing to write WDA session through a symbolic link: {self.path}")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(
                {
                    "bundle_id": session.bundle_id,
                    "session_id": session.session_id,
                    "target_id": session.target_id,
                },
                output,
                sort_keys=True,
            )
            output.write("\n")

    def clear(self) -> None:
        """Remove the cached session if it exists."""

        self.path.unlink(missing_ok=True)


class WebDriverAgentClient:
    """A generic WDA client with session reuse and display-safe named actions."""

    def __init__(
        self,
        transport: WdaTransport,
        *,
        sessions: SessionStore | None = None,
        target_id: str | None = None,
    ) -> None:
        if sessions is not None and (target_id is None or not target_id.strip()):
            raise WdaError("a target identifier is required when WDA session reuse is enabled")
        self._transport = transport
        self._sessions = sessions
        self._target_id = target_id
        self._session_id: str | None = None

    @property
    def session_id(self) -> str | None:
        """Return the active WDA session identifier."""

        return self._session_id

    def open(self, bundle_id: str) -> str:
        """Reuse a live WDA session or create one for a target-supplied application ID."""

        if not bundle_id or bundle_id != bundle_id.strip():
            raise WdaError("an application bundle ID must be supplied explicitly")
        cached = self._sessions.load() if self._sessions is not None else None
        if (
            cached is not None
            and cached.bundle_id == bundle_id
            and cached.target_id == self._target_id
            and self._session_alive(cached.session_id)
        ):
            self._session_id = cached.session_id
            return cached.session_id
        if cached is not None and self._sessions is not None:
            self._sessions.clear()
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
        if self._sessions is not None:
            self._sessions.save(
                WdaSession(
                    session_id=session_id,
                    target_id=cast("str", self._target_id),
                    bundle_id=bundle_id,
                )
            )
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

    def _session_alive(self, session_id: str) -> bool:
        try:
            response = self._transport.request("GET", f"/session/{session_id}/source", timeout=20.0)
        except WdaError:
            return False
        return isinstance(response.get("value"), str)

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


@dataclass(frozen=True, slots=True)
class WdaRunnerConfiguration:
    """Configuration for a signed, installed WDA runner on one iPhone."""

    target: IosTarget
    runner_bundle_id: str
    rsd_backend: RsdBackend
    local_port: int
    device_port: int

    def __post_init__(self) -> None:
        if not self.runner_bundle_id or self.runner_bundle_id != self.runner_bundle_id.strip():
            raise WdaError("a signed WDA runner bundle ID must be supplied explicitly")
        for name, port in (("local", self.local_port), ("device", self.device_port)):
            if not 1 <= port <= MAX_TCP_PORT:
                raise WdaError(f"{name} WDA port must be between 1 and {MAX_TCP_PORT}")

    def forwarding_command(self, *, pymobiledevice3: str = "pymobiledevice3") -> Command:
        """Forward the configured local WDA port through the current usbmuxd owner."""

        return UsbMuxConfiguration(self.target, pymobiledevice3).forward_command(
            local_port=self.local_port,
            device_port=self.device_port,
        )


@dataclass(frozen=True, slots=True)
class WdaServiceConfiguration:
    """Commands and timing for a WDA runner owned by one host-adapter session."""

    runner_command: Command
    forwarding_command: Command
    startup_timeout: float
    session_store: SessionStore | None = None

    def __post_init__(self) -> None:
        if self.startup_timeout < 0:
            raise WdaError("WDA startup timeout cannot be negative")


class WebDriverAgentService:
    """Own WDA runner and forwarding processes as one failure-atomic service."""

    def __init__(
        self,
        starter: ProcessStarter,
        *,
        configuration: WdaServiceConfiguration,
        is_ready: Callable[[], bool],
    ) -> None:
        self._configuration = configuration
        self._is_ready = is_ready
        self._processes = ProcessSupervisor(starter)

    def start(self) -> None:
        """Start runner and forwarding processes, tearing down both on every failure."""

        try:
            self._processes.start("wda-runner", self._configuration.runner_command)
            self._processes.start("wda-forward", self._configuration.forwarding_command)
            self._wait_until_ready()
        except BaseException:
            with contextlib.suppress(ProcessCleanupError):
                self.stop()
            raise

    def stop(self) -> None:
        """Stop forwarding before the runner and discard a possibly stale session."""

        try:
            try:
                self._processes.stop("wda-forward")
            finally:
                self._processes.stop("wda-runner")
        finally:
            if self._configuration.session_store is not None:
                self._configuration.session_store.clear()

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self._configuration.startup_timeout
        while not self._is_ready():
            if time.monotonic() >= deadline:
                raise WdaError("WDA did not become ready before the startup timeout")
            time.sleep(0.25)


@dataclass(frozen=True, slots=True)
class _WdaDependencies:
    """Runtime-only pymobiledevice3 objects."""

    usbmux: Any
    connection_failed_error: type[Exception]
    test_config: Any
    xcuitest_service: Any


async def run_wda_runner(configuration: WdaRunnerConfiguration, *, startup_timeout: float = 180.0) -> None:
    """Run a signed WDA XCUITest runner through userspace RSD or tunneld."""

    dependencies = _load_wda_dependencies()
    if configuration.rsd_backend is RsdBackend.USERSPACE:
        await _run_wda_with_userspace_rsd(configuration, startup_timeout, dependencies)
    else:
        await _run_wda_with_tunneld(configuration, startup_timeout, dependencies)


def _load_wda_dependencies() -> _WdaDependencies:
    root = _optional_module("pymobiledevice3", "install pymobiledevice3 to launch a WDA runner")
    exceptions = _optional_module("pymobiledevice3.exceptions", "install pymobiledevice3 to launch a WDA runner")
    xcuitest = _optional_module(
        "pymobiledevice3.services.dvt.testmanaged.xcuitest",
        "install pymobiledevice3 XCUITest support",
    )
    return _WdaDependencies(
        usbmux=_module_attribute(root, "usbmux"),
        connection_failed_error=cast(
            "type[Exception]",
            _module_attribute(exceptions, "ConnectionFailedError"),
        ),
        test_config=_module_attribute(xcuitest, "TestConfig"),
        xcuitest_service=_module_attribute(xcuitest, "XCUITestService"),
    )


async def _run_wda_with_userspace_rsd(
    configuration: WdaRunnerConfiguration,
    startup_timeout: float,
    dependencies: _WdaDependencies,
) -> None:
    userspace = _optional_module(
        "pymobiledevice3.remote.userspace_tunnel",
        "install pymobiledevice3 userspace tunnel support",
    )
    tunnel = cast(
        "_UserspaceTunnelFactory",
        _module_attribute(userspace, "UserspaceRsdTunnel"),
    )
    async with tunnel(serial=configuration.target.udid) as rsd:
        await _run_wda_for_rsd(configuration, startup_timeout, dependencies, rsd)


async def _run_wda_with_tunneld(
    configuration: WdaRunnerConfiguration,
    startup_timeout: float,
    dependencies: _WdaDependencies,
) -> None:
    tunneld = _optional_module(
        "pymobiledevice3.tunneld.api",
        "install pymobiledevice3 tunneld support",
    )
    lookup = cast(
        "_TunneldLookup",
        _module_attribute(tunneld, "get_tunneld_device_by_udid"),
    )
    rsd = await lookup(configuration.target.udid)
    if rsd is None:
        raise WdaError("tunneld has no RSD connection for the selected iPhone")
    await _run_wda_for_rsd(configuration, startup_timeout, dependencies, rsd)


async def _run_wda_for_rsd(
    configuration: WdaRunnerConfiguration,
    startup_timeout: float,
    dependencies: _WdaDependencies,
    rsd: object,
) -> None:
    test_configuration = await dependencies.test_config.create_for(rsd, runner_bundle_id=configuration.runner_bundle_id)
    task = asyncio.create_task(
        dependencies.xcuitest_service(rsd).run(test_configuration),
        name="webdriveragent-xctrunner",
    )
    deadline = asyncio.get_running_loop().time() + startup_timeout
    try:
        while True:
            if task.done():
                await task
                raise WdaError("the WDA runner exited before its port became reachable")
            if asyncio.get_running_loop().time() >= deadline:
                raise WdaError("WDA did not become reachable before the startup timeout")
            device = await dependencies.usbmux.select_device(configuration.target.udid)
            if device is None:
                raise WdaError("the selected iPhone is not visible through usbmuxd")
            try:
                await device.connect(configuration.device_port)
            except dependencies.connection_failed_error:
                await asyncio.sleep(0.5)
            else:
                break
        await task
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


def _optional_module(name: str, message: str) -> ModuleType:
    try:
        return import_module(name)
    except ModuleNotFoundError as error:
        raise WdaOptionalDependencyError(message) from error


def _module_attribute(module: ModuleType, name: str) -> object:
    return getattr(module, name)


@dataclass(frozen=True, slots=True)
class WdaSigningConfiguration:
    """Target-supplied files required to re-sign an existing WDA runner archive."""

    certificate: Path
    private_key: Path
    provisioning_profile: Path
    runner_archive: Path
    work_directory: Path
    output_ipa: Path
    runner_app: str
    xctest_info_plist: str
    zsign: str = "zsign"


def profile_entitlements(profile: bytes) -> Mapping[str, object]:
    """Extract profile entitlements from the embedded XML property list."""

    start = profile.find(b"<?xml")
    end = profile.find(b"</plist>")
    if start == -1 or end == -1:
        raise WdaError("the provisioning profile has no embedded XML property list")
    data = plistlib.loads(profile[start : end + len(b"</plist>")])
    entitlements = data.get("Entitlements") if isinstance(data, Mapping) else None
    if not isinstance(entitlements, Mapping):
        raise WdaError("the provisioning profile has no entitlement dictionary")
    return entitlements


def derive_wda_bundle_ids(application_identifier: str, *, runner_name: str) -> tuple[str, str]:
    """Derive runner and XCTest bundle IDs from an explicit development-profile identity."""

    team, separator, application_id = application_identifier.partition(".")
    if not team or not separator or not application_id:
        raise WdaError("the provisioning profile application identifier is malformed")
    suffix = ".xctrunner"
    if application_id == "*" or application_id.endswith(".*"):
        prefix = "" if application_id == "*" else f"{application_id[:-2]}."
        runner_id = f"{prefix}{runner_name}{suffix}"
    elif application_id.endswith(suffix):
        runner_id = application_id
    else:
        raise WdaError("the provisioning profile cannot name an XCUITest runner")
    return runner_id, runner_id.removesuffix(suffix)


def prepare_signing_payload(configuration: WdaSigningConfiguration, *, xctest_bundle_id: str) -> Path:
    """Extract a caller-provided WDA archive and rewrite its XCTest bundle identity."""

    payload = configuration.work_directory / "Payload"
    if payload.exists():
        shutil.rmtree(payload)
    payload.mkdir(parents=True)
    with zipfile.ZipFile(configuration.runner_archive) as archive:
        _extract_safely(archive, payload)
    for symbols in (payload / configuration.runner_app / "PlugIns").glob("*.dSYM"):
        shutil.rmtree(symbols)
    plist_path = payload / configuration.xctest_info_plist
    try:
        with plist_path.open("rb") as source:
            plist = plistlib.load(source)
    except OSError as error:
        raise WdaError("the runner archive does not contain the configured XCTest Info.plist") from error
    plist["CFBundleIdentifier"] = xctest_bundle_id
    with plist_path.open("wb") as destination:
        plistlib.dump(plist, destination)
    return payload


def build_zsign_command(
    configuration: WdaSigningConfiguration,
    *,
    runner_bundle_id: str,
    payload: Path,
) -> Command:
    """Build the zsign command without exposing signing material in defaults."""

    runner_app = payload / configuration.runner_app
    return Command(
        (
            configuration.zsign,
            "-f",
            "-c",
            str(configuration.certificate),
            "-k",
            str(configuration.private_key),
            "-m",
            str(configuration.provisioning_profile),
            "-b",
            runner_bundle_id,
            "-o",
            str(configuration.output_ipa),
            str(runner_app),
        )
    )


def _extract_safely(archive: zipfile.ZipFile, destination: Path) -> None:
    root = destination.resolve()
    for member in archive.infolist():
        target = (destination / member.filename).resolve()
        if not target.is_relative_to(root):
            raise WdaError("the runner archive contains a path outside its payload")
        archive.extract(member, destination)
