from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from ios_ble_capture.ios.process import Command, ManagedProcess, ProcessStarter, ProcessSupervisor


@dataclass
class _Process:
    events: list[str]
    name: str
    returncode: int | None = None

    def terminate(self) -> None:
        self.events.append(f"terminate:{self.name}")

    def kill(self) -> None:
        self.events.append(f"kill:{self.name}")

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.events.append(f"wait:{self.name}")
        return 0

    def poll(self) -> int | None:
        return self.returncode


@dataclass
class _Starter:
    events: list[str] = field(default_factory=list)
    processes: list[_Process] = field(default_factory=list)

    def start(self, command: Command) -> ManagedProcess:
        process = _Process(self.events, command.argv[0])
        self.processes.append(process)
        self.events.append(f"start:{command.argv[0]}")
        return process


def _fail_after_starting_owned_processes(starter: ProcessStarter) -> None:
    with ProcessSupervisor(starter) as supervisor:
        supervisor.start("runner", Command(("runner",)))
        supervisor.start("forward", Command(("forward",)))
        raise RuntimeError("failure")


def test_failure_stops_every_owned_process_in_reverse_startup_order() -> None:
    starter = _Starter()

    with pytest.raises(RuntimeError, match="failure"):
        _fail_after_starting_owned_processes(starter)

    assert starter.events == [
        "start:runner",
        "start:forward",
        "terminate:forward",
        "wait:forward",
        "terminate:runner",
        "wait:runner",
    ]


def test_require_running_surfaces_an_early_exit() -> None:
    starter = _Starter()
    supervisor = ProcessSupervisor(starter)
    process = supervisor.start("capture", Command(("capture",)))
    assert isinstance(process, _Process)
    process.returncode = 3

    with pytest.raises(RuntimeError, match="status 3"):
        supervisor.require_running("capture")
