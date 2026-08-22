from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

import pytest

import ios_ble_capture.executor as executor_module
from ios_ble_capture.errors import RecipeError
from ios_ble_capture.executor import RecipeExecutor
from ios_ble_capture.recipes import Recipe, RecipeRecord, recipe_from_record
from ios_ble_capture.run import create_run_context

if TYPE_CHECKING:
    from pathlib import Path

    from ios_ble_capture.ios.process import Command

_PRIVATE_FILE_MODE = 0o600


@dataclass
class FakeProcess:
    terminated: bool = False
    returncode: int | None = None

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0

    def poll(self) -> int | None:
        return self.returncode


class FakeStarter:
    def __init__(self, *, returncode: int | None = None) -> None:
        self.processes: list[FakeProcess] = []
        self.returncode = returncode

    def start(self, command: Command) -> FakeProcess:
        assert command.argv[0] == "idevicebtlogger"
        process = FakeProcess(returncode=self.returncode)
        self.processes.append(process)
        return process


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def open(self, bundle_id: str) -> str:
        self.calls.append(("open", bundle_id))
        return "session"

    def tap_named(self, name: str) -> None:
        self.calls.append(("tap", name))

    def type_text(self, text: str) -> None:
        self.calls.append(("type", text))

    def slide_named(self, name: str, *, start: float, end: float) -> None:
        self.calls.append(("swipe", name, start, end))

    def screenshot(self, destination: Path) -> Path:
        destination.write_bytes(b"\x00")
        self.calls.append(("screenshot", destination.name))
        return destination


def _recipe(steps: list[dict[str, object]]) -> Recipe:
    return recipe_from_record(
        cast(
            "RecipeRecord",
            {
                "version": 1,
                "pre_run": None,
                "post_run": None,
                "steps": steps,
            },
        ),
    )


def test_recipe_validation_refuses_undeclared_step_arguments(tmp_path: Path) -> None:
    recipe = _recipe([{"kind": "wait", "arguments": {"seconds": 0, "shell": "not allowed"}}])

    with pytest.raises(RecipeError, match="unsupported arguments"):
        RecipeExecutor(recipe, recipe_directory=tmp_path)


def test_recipe_validation_reports_missing_assertion_value(tmp_path: Path) -> None:
    recipe = _recipe([{"kind": "assert", "arguments": {"file": "result.json"}}])

    with pytest.raises(RecipeError, match="missing arguments: equals"):
        RecipeExecutor(recipe, recipe_directory=tmp_path)


def test_dry_run_does_not_sleep_for_wait_steps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    recipe = _recipe([{"kind": "wait", "arguments": {"seconds": 1}}])
    context = create_run_context(
        source="test",
        tool_version="test",
        root=tmp_path,
        now=datetime(2026, 8, 22, tzinfo=UTC),
    )
    monkeypatch.setattr(time, "sleep", lambda _seconds: pytest.fail("dry run slept"))

    result = RecipeExecutor(recipe, recipe_directory=tmp_path, dry_run=True).execute(context)

    assert result.completed_steps == ("wait",)


def test_recipe_fails_when_capture_logger_exits_early(tmp_path: Path) -> None:
    recipe = _recipe(
        [
            {
                "kind": "capture",
                "arguments": {
                    "udid": "00000000-0000000000000000",
                    "host": "wsl",
                    "output": "capture",
                },
            }
        ]
    )
    context = create_run_context(
        source="test",
        tool_version="test",
        root=tmp_path,
        now=datetime(2026, 8, 22, tzinfo=UTC),
    )

    with pytest.raises(RuntimeError, match="exited unexpectedly"):
        RecipeExecutor(
            recipe,
            recipe_directory=tmp_path,
            process_starter=FakeStarter(returncode=2),
        ).execute(context)


def test_recipe_uses_safe_named_wda_actions_and_private_screenshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient()
    monkeypatch.setattr(executor_module, "_default_client", lambda _url: client)
    recipe = _recipe(
        [
            {"kind": "launch", "arguments": {"wda_url": "http://test", "bundle_id": "test.bundle"}},
            {"kind": "tap", "arguments": {"wda_url": "http://test", "bundle_id": "test.bundle", "name": "Continue"}},
            {
                "kind": "type",
                "arguments": {
                    "wda_url": "http://test",
                    "bundle_id": "test.bundle",
                    "name": "Input",
                    "text": "value",
                },
            },
            {
                "kind": "swipe",
                "arguments": {
                    "wda_url": "http://test",
                    "bundle_id": "test.bundle",
                    "name": "Slider",
                    "start": 0,
                    "end": 1,
                },
            },
            {"kind": "screenshot", "arguments": {"wda_url": "http://test", "bundle_id": "test.bundle"}},
        ]
    )
    context = create_run_context(
        source="test",
        tool_version="test",
        root=tmp_path,
        now=datetime(2026, 8, 22, tzinfo=UTC),
    )

    result = RecipeExecutor(recipe, recipe_directory=tmp_path).execute(context)

    assert result.completed_steps == ("launch", "tap", "type", "swipe", "screenshot")
    assert [call[0] for call in client.calls] == ["open", "tap", "tap", "type", "swipe", "screenshot"]
    assert (context.directory / "screenshot-5.png").stat().st_mode & 0o777 == _PRIVATE_FILE_MODE


def test_recipe_capture_process_is_owned_and_stopped(tmp_path: Path) -> None:
    starter = FakeStarter()
    recipe = _recipe(
        [
            {
                "kind": "capture",
                "arguments": {
                    "udid": "test-phone",
                    "host": "wsl",
                    "output": "capture",
                },
            }
        ]
    )
    context = create_run_context(
        source="test",
        tool_version="test",
        root=tmp_path,
        now=datetime(2026, 8, 22, tzinfo=UTC),
    )

    RecipeExecutor(recipe, recipe_directory=tmp_path, process_starter=starter).execute(context)

    assert len(starter.processes) == 1
    assert starter.processes[0].terminated
