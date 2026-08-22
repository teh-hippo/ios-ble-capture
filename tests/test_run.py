from __future__ import annotations

import json
import signal
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.errors import HookExecutionError, PostHookError, RunInterruptedError
from ios_ble_capture.run import (
    Hook,
    RunContext,
    RunLifecycle,
    create_run_context,
    execute_with_hooks,
    interrupt_as_error,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

_ACTION_RESULT = 7
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600


def _context(tmp_path: Path) -> RunContext:
    return RunContext(
        run_id="test-run",
        directory=tmp_path,
        created_at=datetime(2026, 8, 22, tzinfo=UTC),
    )


def test_preflight_runs_before_ownership_handoff(tmp_path: Path) -> None:
    calls: list[str] = []

    def runner(
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
    ) -> None:
        calls.append(command[0])
        assert environment["IOS_BLE_CAPTURE_RUN_ID"] == "test-run"

    def action(_context: RunContext) -> int:
        calls.append("action")
        return _ACTION_RESULT

    result = execute_with_hooks(
        action,
        lifecycle=RunLifecycle(
            context=_context(tmp_path),
            preflight=lambda: calls.append("preflight"),
            preflight_hook=Hook(("host-preflight",)),
            pre_run=Hook(("pre",)),
            post_run=Hook(("post",)),
            runner=runner,
        ),
    )

    assert result == _ACTION_RESULT
    assert calls == ["preflight", "host-preflight", "pre", "action", "post"]


def test_failed_preflight_hook_does_not_run_ownership_hooks(tmp_path: Path) -> None:
    calls: list[str] = []

    def runner(
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
    ) -> None:
        del environment
        calls.append(command[0])
        raise HookExecutionError("host preflight failed")

    with pytest.raises(HookExecutionError, match="host preflight failed"):
        execute_with_hooks(
            lambda _context: calls.append("action"),
            lifecycle=RunLifecycle(
                context=_context(tmp_path),
                preflight_hook=Hook(("host-preflight",)),
                pre_run=Hook(("pre",)),
                post_run=Hook(("post",)),
                runner=runner,
            ),
        )

    assert calls == ["host-preflight"]


def test_hook_environment_cannot_override_run_identity() -> None:
    with pytest.raises(ValueError, match="cannot override"):
        Hook(("ownership",), {"IOS_BLE_CAPTURE_RUN_DIR": "/not-a-run"})


def test_post_hook_runs_when_pre_hook_fails(tmp_path: Path) -> None:
    calls: list[str] = []

    def runner(
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
    ) -> None:
        del environment
        calls.append(command[0])
        if command[0] == "pre":
            raise HookExecutionError("handoff failed")

    with pytest.raises(HookExecutionError, match="handoff failed"):
        execute_with_hooks(
            lambda _context: None,
            lifecycle=RunLifecycle(
                context=_context(tmp_path),
                pre_run=Hook(("pre",)),
                post_run=Hook(("post",)),
                runner=runner,
            ),
        )

    assert calls == ["pre", "post"]


def test_post_hook_can_run_without_a_pre_hook(tmp_path: Path) -> None:
    calls: list[str] = []

    def runner(
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
    ) -> None:
        del environment
        calls.append(command[0])

    execute_with_hooks(
        lambda _context: calls.append("action"),
        lifecycle=RunLifecycle(
            context=_context(tmp_path),
            post_run=Hook(("post",)),
            runner=runner,
        ),
    )

    assert calls == ["action", "post"]


def test_post_hook_failure_is_distinct_and_preserves_primary_error(tmp_path: Path) -> None:
    def runner(
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
    ) -> None:
        del environment
        if command[0] == "post":
            raise HookExecutionError("restore failed")

    with pytest.raises(PostHookError, match="ownership restoration") as raised:
        execute_with_hooks(
            lambda _context: (_ for _ in ()).throw(RuntimeError("run failed")),
            lifecycle=RunLifecycle(
                context=_context(tmp_path),
                pre_run=Hook(("pre",)),
                post_run=Hook(("post",)),
                runner=runner,
            ),
        )

    assert isinstance(raised.value.__cause__, RuntimeError)


def test_post_hook_launch_failure_is_classified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_launch(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError("missing")

    monkeypatch.setattr("ios_ble_capture.run.subprocess.run", fail_launch)

    with pytest.raises(PostHookError, match="cannot launch hook"):
        execute_with_hooks(
            lambda _context: None,
            lifecycle=RunLifecycle(
                context=_context(tmp_path),
                post_run=Hook(("missing-hook",)),
            ),
        )


def test_post_hook_does_not_run_when_preflight_fails(tmp_path: Path) -> None:
    calls: list[str] = []

    def runner(
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
    ) -> None:
        del environment
        calls.append(command[0])

    with pytest.raises(RuntimeError, match="phone locked"):
        execute_with_hooks(
            lambda _context: None,
            lifecycle=RunLifecycle(
                context=_context(tmp_path),
                preflight=lambda: (_ for _ in ()).throw(RuntimeError("phone locked")),
                pre_run=Hook(("pre",)),
                post_run=Hook(("post",)),
                runner=runner,
            ),
        )

    assert calls == []


@pytest.mark.skipif(not hasattr(signal, "raise_signal"), reason="signal support required")
def test_interrupt_is_converted_to_run_error() -> None:
    with pytest.raises(RunInterruptedError, match="SIGTERM"), interrupt_as_error():
        signal.raise_signal(signal.SIGTERM)


def test_run_metadata_is_private(tmp_path: Path) -> None:
    context = create_run_context(
        source="fixture",
        tool_version="0.1.0",
        root=tmp_path,
        now=datetime(2026, 8, 22, tzinfo=UTC),
    )

    record = json.loads((context.directory / "run.json").read_text())
    assert record["source"] == "fixture"
    assert context.directory.stat().st_mode & 0o777 == _DIRECTORY_MODE
    assert (context.directory / "run.json").stat().st_mode & 0o777 == _FILE_MODE
