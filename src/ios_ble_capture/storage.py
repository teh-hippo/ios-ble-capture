"""Private on-disk storage for capture runs."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ios_ble_capture.errors import CaptureDataError
from ios_ble_capture.models import AttEvent, AttEventRecord
from ios_ble_capture.segmentation import ActionMark, dump_action_marks_jsonl, load_action_marks_jsonl

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from ios_ble_capture.capture import ConnectionEvent

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


class StorageError(CaptureDataError):
    """Raised when a private run cannot be read or written safely."""


def require_private_run_directory(path: Path) -> Path:
    """Return an existing private run directory after enforcing its mode."""

    if path.is_symlink() or not path.is_dir():
        raise StorageError(f"run directory does not exist or is not a directory: {path}")
    try:
        path.chmod(PRIVATE_DIRECTORY_MODE)
    except OSError as error:
        raise StorageError(f"cannot protect run directory {path}: {error.strerror or error}") from error
    _require_mode(path, PRIVATE_DIRECTORY_MODE)
    return path


def private_child(directory: Path, name: str) -> Path:
    """Return one direct private-run child, refusing paths outside the run."""

    if not name or Path(name).name != name:
        raise StorageError("private run output must be a file name without directory components")
    return require_private_run_directory(directory) / name


def write_private_bytes(path: Path, data: bytes) -> Path:
    """Write bytes with a private file mode."""

    _write_private(path, data)
    return path


def write_private_text(path: Path, text: str) -> Path:
    """Write UTF-8 text with a private file mode."""

    _write_private(path, text.encode())
    return path


def write_private_json(path: Path, value: object) -> Path:
    """Write deterministic JSON with a private file mode."""

    return write_private_text(path, json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")


def load_events_jsonl(path: Path) -> tuple[AttEvent, ...]:
    """Load normalised ATT events from a private JSONL file."""

    lines = _read_text(path).splitlines()
    events: list[AttEvent] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as error:
            raise StorageError(f"invalid event JSON on line {number}: {error.msg}") from error
        if not isinstance(raw, dict):
            raise StorageError(f"event on line {number} must be an object")
        try:
            events.append(AttEvent.from_record(cast("AttEventRecord", raw)))
        except (CaptureDataError, KeyError, TypeError) as error:
            raise StorageError(f"invalid event on line {number}: {error}") from error
    return tuple(events)


def load_private_json(path: Path) -> object:
    """Load one JSON value while presenting file failures as capture errors."""

    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError as error:
        raise StorageError(f"invalid JSON in {path}: {error.msg}") from error


def append_action_mark(directory: Path, mark: ActionMark, *, name: str = "marks.jsonl") -> Path:
    """Append an action mark while preserving strict timestamp order."""

    path = private_child(directory, name)
    existing = load_action_marks_jsonl(_read_text(path).splitlines()) if path.exists() else ()
    return write_private_text(path, dump_action_marks_jsonl((*existing, mark)))


def load_action_marks(directory: Path, *, name: str = "marks.jsonl") -> tuple[ActionMark, ...]:
    """Load action marks from a private run."""

    return load_action_marks_jsonl(_read_text(private_child(directory, name)).splitlines())


def write_connection_metadata(
    directory: Path,
    *,
    source: Mapping[str, object],
    connections: Iterable[ConnectionEvent],
    name: str = "connections.json",
) -> Path:
    """Store selected-source connection lifecycle metadata without raw payloads."""

    records = [
        {
            "connected": connection.connected,
            "connection_epoch": connection.connection_epoch,
            "connection_handle": connection.connection_handle,
            "peer_address": connection.peer_address,
            "timestamp": connection.timestamp.isoformat(),
        }
        for connection in connections
    ]
    value = {"connections": records, "schema_version": 1, "source": source}
    return write_private_json(private_child(directory, name), value)


def _read_text(path: Path) -> str:
    if path.is_symlink():
        raise StorageError(f"refusing to read through symbolic link: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise StorageError(f"cannot read {path}: {error.strerror or error}") from error


def _write_private(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise StorageError(f"refusing to write through symbolic link: {path}")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), PRIVATE_FILE_MODE)
            stream.write(data)
    except OSError as error:
        raise StorageError(f"cannot write {path}: {error.strerror or error}") from error
    _require_mode(path, PRIVATE_FILE_MODE)


def _require_mode(path: Path, expected: int) -> None:
    try:
        actual = stat.S_IMODE(path.stat().st_mode)
    except OSError as error:
        raise StorageError(f"cannot inspect permissions for {path}: {error.strerror or error}") from error
    if actual != expected:
        raise StorageError(f"private path has mode {actual:04o}, expected {expected:04o}: {path}")
