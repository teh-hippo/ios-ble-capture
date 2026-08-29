from __future__ import annotations

import os
import signal
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol
from uuid import uuid4

from ios_ble_capture.errors import HookExecutionError, PostHookError, RunInterruptedError
from ios_ble_capture.models import RunMetadata
from ios_ble_capture.storage import write_private_json

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence
    from types import FrameType

    type SignalHandler = Callable[[int, FrameType | None], object] | int | None

_SAFE_INHERITED_ENV: Final = (
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
)
_RESERVED_HOOK_ENV: Final = frozenset(
    {
        "IOS_BLE_CAPTURE_RUN_DIR",
        "IOS_BLE_CAPTURE_RUN_ID",
    }
)
_SIGNALS: Final = (signal.SIGINT, signal.SIGTERM)


@dataclass(frozen=True, slots=True)
class Hook:
    command: tuple[str, ...]
    environment: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if not self.command or any(not part for part in self.command):
            raise ValueError("hook command must contain non-empty arguments")
        if self.environment is None:
            return
        if any(
            not isinstance(key, str) or not key or not isinstance(value, str) or key in _RESERVED_HOOK_ENV
            for key, value in self.environment.items()
        ):
            raise ValueError("hook environment must contain string values and cannot override run identity")


@dataclass(frozen=True, slots=True)
class RunContext:
    run_id: str
    directory: Path
    created_at: datetime

    def hook_environment(self) -> dict[str, str]:
        environment = {key: value for key in _SAFE_INHERITED_ENV if (value := os.environ.get(key)) is not None}
        environment.update(
            {
                "IOS_BLE_CAPTURE_RUN_DIR": str(self.directory),
                "IOS_BLE_CAPTURE_RUN_ID": self.run_id,
            }
        )
        return environment


class HookRunner(Protocol):
    def __call__(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class RunLifecycle:
    context: RunContext
    preflight: Callable[[], None] | None = None
    preflight_hook: Hook | None = None
    pre_run: Hook | None = None
    post_run: Hook | None = None
    runner: HookRunner | None = None


def create_run_context(
    *,
    source: str,
    tool_version: str,
    root: Path | None = None,
    now: datetime | None = None,
) -> RunContext:
    created_at = now or datetime.now(tz=UTC)
    run_id = f"{created_at:%Y%m%dT%H%M%SZ}-{uuid4().hex[:8]}"
    directory = (root or _default_run_root()) / run_id
    directory.mkdir(mode=0o700, parents=True)
    directory.chmod(0o700)
    metadata = RunMetadata(
        run_id=run_id,
        created_at=created_at,
        source=source,
        tool_version=tool_version,
    )
    write_private_json(directory / "run.json", metadata.to_record())
    return RunContext(run_id=run_id, directory=directory, created_at=created_at)


def execute_with_hooks[T](
    action: Callable[[RunContext], T],
    *,
    lifecycle: RunLifecycle,
) -> T:
    if lifecycle.preflight is not None:
        lifecycle.preflight()

    run_hook = lifecycle.runner or subprocess_hook_runner
    with interrupt_as_error():
        if lifecycle.preflight_hook is not None:
            _invoke_hook(
                lifecycle.preflight_hook,
                context=lifecycle.context,
                runner=run_hook,
                post=False,
            )

    primary_error: BaseException | None = None

    try:
        with interrupt_as_error():
            if lifecycle.pre_run is not None:
                _invoke_hook(
                    lifecycle.pre_run,
                    context=lifecycle.context,
                    runner=run_hook,
                    post=False,
                )
            return action(lifecycle.context)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if lifecycle.post_run is not None:
            try:
                _invoke_hook(
                    lifecycle.post_run,
                    context=lifecycle.context,
                    runner=run_hook,
                    post=True,
                )
            except PostHookError as error:
                if primary_error is not None:
                    raise error from primary_error
                raise


def subprocess_hook_runner(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
) -> None:
    try:
        completed = subprocess.run(  # noqa: S603 - Hooks are explicit argument arrays, never shell text.
            command,
            check=False,
            env=environment,
            stdin=subprocess.DEVNULL,
            text=True,
        )
    except OSError as error:
        raise HookExecutionError(f"cannot launch hook {command[0]}: {error}") from error
    if completed.returncode != 0:
        raise HookExecutionError(f"hook exited with status {completed.returncode}: {command[0]}")


@contextmanager
def interrupt_as_error() -> Iterator[None]:
    previous: dict[signal.Signals, SignalHandler] = {}

    def interrupt(signum: int, _frame: FrameType | None) -> None:
        name = signal.Signals(signum).name
        raise RunInterruptedError(f"run interrupted by {name}")

    try:
        for signum in _SIGNALS:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupt)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _invoke_hook(
    hook: Hook,
    *,
    context: RunContext,
    runner: HookRunner,
    post: bool,
) -> None:
    environment = context.hook_environment()
    if hook.environment is not None:
        environment.update(hook.environment)
    try:
        runner(hook.command, environment=environment)
    except HookExecutionError as error:
        if post:
            raise PostHookError(f"post-run ownership restoration failed: {error}") from error
        raise


def _default_run_root() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home) / "ios-ble-capture" / "runs"
    return Path.home() / ".local" / "state" / "ios-ble-capture" / "runs"
