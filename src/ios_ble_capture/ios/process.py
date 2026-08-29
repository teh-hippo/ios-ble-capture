"""Typed command specifications and owned-process lifecycle management."""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Protocol, Self

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path
    from types import TracebackType


class ProcessError(RuntimeError):
    """Raised when a host command or a tracked process cannot complete safely."""


@dataclass(frozen=True, slots=True)
class Command:
    """An executable command with explicit arguments and optional process settings."""

    argv: tuple[str, ...]
    cwd: Path | None = None
    environment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.argv or not self.argv[0]:
            raise ProcessError("a command needs an executable")
        if any(not part for part in self.argv):
            raise ProcessError("command arguments cannot be empty")


class ManagedProcess(Protocol):
    """A process which this package owns and can stop."""

    def terminate(self) -> None:
        """Request graceful termination."""

    def kill(self) -> None:
        """Force termination."""

    def wait(self, timeout: float | None = None) -> int:
        """Wait for completion."""

    def poll(self) -> int | None:
        """Return the exit status when the process has stopped."""


class ProcessStarter(Protocol):
    """Starts a process that remains owned by the caller."""

    def start(self, command: Command) -> ManagedProcess:
        """Start a command."""


def _environment(overrides: Mapping[str, str]) -> dict[str, str]:
    return {**os.environ, **overrides}


class _OwnedSubprocess:
    """A subprocess placed in its own process group where the platform supports it."""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        self._process = process

    def terminate(self) -> None:
        if os.name == "posix":
            os.killpg(self._process.pid, signal.SIGTERM)
            return
        self._process.terminate()

    def kill(self) -> None:
        if os.name == "posix":
            os.killpg(self._process.pid, signal.SIGKILL)
            return
        self._process.kill()

    def wait(self, timeout: float | None = None) -> int:
        return self._process.wait(timeout=timeout)

    def poll(self) -> int | None:
        return self._process.poll()


class SubprocessStarter:
    """Starts process groups which can be torn down without leaking descendants."""

    def start(self, command: Command) -> ManagedProcess:
        process = subprocess.Popen(  # noqa: S603
            command.argv,
            cwd=command.cwd,
            env=_environment(command.environment),
            start_new_session=os.name == "posix",
            text=True,
        )
        return _OwnedSubprocess(process)


class ProcessCleanupError(ProcessError):
    """Raised after every owned process was given a chance to stop."""


class ProcessRunCleanupError(ProcessError):
    """Raised when a primary failure and owned-process cleanup both fail."""

    def __init__(self, primary_error: BaseException, cleanup_error: ProcessCleanupError) -> None:
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error
        super().__init__(f"owned-process cleanup failed while handling {type(primary_error).__name__}: {primary_error}")


class ProcessSupervisor:
    """Owns persistent processes and stops them in reverse startup order."""

    def __init__(self, starter: ProcessStarter, *, grace_period: float = 5.0) -> None:
        if grace_period < 0:
            raise ProcessError("the process grace period cannot be negative")
        self._starter = starter
        self._grace_period = grace_period
        self._processes: dict[str, ManagedProcess] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        try:
            self.close()
        except ProcessCleanupError as cleanup_error:
            if exception is not None:
                raise ProcessRunCleanupError(exception, cleanup_error) from exception
            raise
        return False

    def start(self, name: str, command: Command) -> ManagedProcess:
        """Start and track a process under a unique owner-local name."""

        if not name or name != name.strip():
            raise ProcessError("a tracked process needs a non-empty name")
        if name in self._processes:
            raise ProcessError(f"process {name!r} is already tracked")
        process = self._starter.start(command)
        self._processes[name] = process
        return process

    def stop(self, name: str) -> None:
        """Stop one owned process and remove it from the ownership registry."""

        process = self._processes.pop(name, None)
        if process is None:
            return
        self._stop(process)

    def require_running(self, name: str) -> None:
        """Fail if a tracked long-running process exited unexpectedly."""

        process = self._processes.get(name)
        if process is None:
            raise ProcessError(f"process {name!r} is not tracked")
        returncode = process.poll()
        if returncode is None:
            return
        self._processes.pop(name)
        raise ProcessError(f"process {name!r} exited unexpectedly with status {returncode}")

    def close(self) -> None:
        """Stop every owned process, even if an earlier process resists teardown."""

        failures: list[BaseException] = []
        for name in tuple(reversed(self._processes)):
            process = self._processes.pop(name)
            try:
                self._stop(process)
            except BaseException as error:  # noqa: BLE001
                failures.append(error)
        if failures:
            raise ProcessCleanupError(f"{len(failures)} owned process(es) did not stop") from failures[0]

    def _stop(self, process: ManagedProcess) -> None:
        try:
            process.terminate()
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=self._grace_period)
        except subprocess.TimeoutExpired:
            pass
        else:
            return
        try:
            process.kill()
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=self._grace_period)
        except subprocess.TimeoutExpired as error:
            raise ProcessCleanupError("owned process survived forced termination") from error
