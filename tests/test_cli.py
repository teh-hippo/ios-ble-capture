from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest  # noqa: TC002

import ios_ble_capture.executor as executor_module
from ios_ble_capture import cli
from ios_ble_capture.capture import write_raw_run
from ios_ble_capture.cli import COMMANDS, run
from ios_ble_capture.models import AttEvent, Direction

if TYPE_CHECKING:
    from ios_ble_capture.ios.process import Command

_PRIVATE_FILE_MODE = 0o600


class FailingProcess:
    def terminate(self) -> None:
        return None

    def kill(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 1

    def poll(self) -> int | None:
        return None


class CaptureStarter:
    def __init__(self) -> None:
        self.created_mode: int | None = None

    def start(self, command: Command) -> FailingProcess:
        output = Path(command.argv[-1])
        with output.open("wb") as stream:
            stream.write(b"\x00")
        self.created_mode = stat.S_IMODE(output.stat().st_mode)
        return FailingProcess()


def _event(value: bytes = b"\x01\x02") -> AttEvent:
    return AttEvent(
        timestamp=datetime(2026, 8, 22, tzinfo=UTC),
        direction=Direction.DEVICE_TO_HOST,
        connection_handle=1,
        connection_epoch=1,
        peer_address=None,
        opcode=0x1B,
        attribute_handle=1,
        value=value,
    )


def test_parser_exposes_working_commands() -> None:
    assert COMMANDS == ("capture", "import", "mark", "attribute", "segment", "decode", "diff", "report", "run", "ble")


def test_capture_dry_run_builds_an_explicit_plan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    result = run(
        [
            "capture",
            "--udid",
            "test-phone",
            "--output",
            str(tmp_path / "test-phone-capture"),
            "--host",
            "wsl",
            "--dry-run",
        ]
    )

    output = capsys.readouterr().out
    plan = json.loads(output)
    assert result == 0
    assert plan["output"].endswith("<redacted-udid>-capture.pcap")
    assert plan["command"][-1] == plan["output"]
    assert "test-phone" not in output
    assert "<redacted-udid>" in plan["command"]


def test_failed_capture_creates_and_cleans_up_a_private_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starter = CaptureStarter()
    monkeypatch.setattr(cli, "SubprocessStarter", lambda: starter)
    output = tmp_path / "capture"

    result = run(
        [
            "capture",
            "--udid",
            "test-phone",
            "--output",
            str(output),
            "--host",
            "wsl",
        ]
    )

    capture = output.with_suffix(".pcap")
    assert result == 1
    assert starter.created_mode == _PRIVATE_FILE_MODE
    assert stat.S_IMODE(capture.stat().st_mode) == _PRIVATE_FILE_MODE


def test_report_withholds_raw_payloads_unless_requested(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run_directory = tmp_path / "run"
    write_raw_run(run_directory, (_event(b"\xaa\xbb"),))
    events = run_directory / "events.jsonl"

    assert run(["report", str(events), "--format", "json"]) == 0
    withheld = capsys.readouterr().out
    assert "aabb" not in withheld
    assert '"reason":"raw payload"' in withheld

    assert run(["report", str(events), "--format", "json", "--include-raw"]) == 0
    assert "aabb" in capsys.readouterr().out


def test_expected_cli_errors_are_deterministic(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    result = run(["mark", "--run-dir", str(tmp_path / "missing"), "--label", "operator action"])

    assert result == 1
    assert capsys.readouterr().err.startswith("error: run directory does not exist")


def test_decode_uses_orchestration_without_requiring_a_compiler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    schemas = target / "schemas"
    schemas.mkdir(parents=True)

    monkeypatch.setattr(cli, "compile_kaitai", lambda _request: object())
    monkeypatch.setattr(cli, "decode_kaitai", lambda _result, data: {"size": len(data)})

    result = run(
        [
            "decode",
            "--target-path",
            str(target),
            "--ksy-root",
            str(schemas),
            "--root-schema",
            str(schemas / "message.ksy"),
            "--root-identity",
            "message",
            "--module-name",
            "message",
            "--root-type-name",
            "Message",
            "--compiler",
            "not-run",
            "--cache-directory",
            str(tmp_path / "cache"),
            "--target-output-path",
            str(target / "generated" / "message.py"),
            "--data-hex",
            "0102",
            "--stdout",
        ]
    )

    assert result == 0
    assert capsys.readouterr().out == '{"size":2}\n'


def test_decode_requires_private_output_or_explicit_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "target"
    schemas = target / "schemas"
    schemas.mkdir(parents=True)

    result = run(
        [
            "decode",
            "--target-path",
            str(target),
            "--ksy-root",
            str(schemas),
            "--root-schema",
            str(schemas / "message.ksy"),
            "--root-identity",
            "message",
            "--module-name",
            "message",
            "--root-type-name",
            "Message",
            "--compiler",
            "not-run",
            "--cache-directory",
            str(tmp_path / "cache"),
            "--target-output-path",
            str(target / "generated" / "message.py"),
            "--data-hex",
            "0102",
        ]
    )

    assert result == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: decode requires --output or --stdout\n"


def test_diff_requires_private_output_or_explicit_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text('{"field":"before"}')
    after.write_text('{"field":"after"}')

    result = run(["diff", str(before), str(after)])

    assert result == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: diff requires --output or --stdout\n"

    assert run(["diff", str(before), str(after), "--stdout"]) == 0
    assert '"after":"after"' in capsys.readouterr().out


def test_run_dry_run_skips_hooks_wda_and_run_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    recipe = tmp_path / "recipe.json"
    calls: list[str] = []

    def client_factory(url: str) -> object:
        calls.append(url)
        return object()

    record = {
        "version": 1,
        "pre_run": {"command": ["false"], "environment": {}},
        "post_run": {"command": ["false"], "environment": {}},
        "steps": [
            {"kind": "launch", "arguments": {"wda_url": "http://test", "bundle_id": "test.bundle"}},
            {"kind": "wait", "arguments": {"seconds": 1}},
        ],
    }
    recipe.write_text(json.dumps(record))
    monkeypatch.setattr(executor_module, "_default_client", client_factory)
    run_root = tmp_path / "runs"

    assert run(["run", str(recipe), "--run-root", str(run_root), "--dry-run"]) == 0
    assert calls == []
    assert not run_root.exists()
    assert capsys.readouterr().out == '{"dry_run":true,"steps":["launch","wait"]}\n'
