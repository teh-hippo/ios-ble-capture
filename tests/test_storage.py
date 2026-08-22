from __future__ import annotations

import stat
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.errors import CaptureDataError
from ios_ble_capture.segmentation import ActionMark
from ios_ble_capture.storage import (
    PRIVATE_DIRECTORY_MODE,
    PRIVATE_FILE_MODE,
    StorageError,
    append_action_mark,
    load_action_marks,
    private_child,
    require_private_run_directory,
    write_private_text,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_private_storage_enforces_run_and_file_permissions(tmp_path: Path) -> None:
    directory = tmp_path / "run"
    directory.mkdir(mode=0o755)

    path = write_private_text(private_child(directory, "result.json"), "{}\n")

    assert stat.S_IMODE(require_private_run_directory(directory).stat().st_mode) == PRIVATE_DIRECTORY_MODE
    assert stat.S_IMODE(path.stat().st_mode) == PRIVATE_FILE_MODE


def test_action_marks_are_appended_in_strict_timestamp_order(tmp_path: Path) -> None:
    directory = tmp_path / "run"
    directory.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    first = ActionMark(datetime(2026, 8, 22, tzinfo=UTC), "first")
    second = ActionMark(datetime(2026, 8, 22, 0, 0, 1, tzinfo=UTC), "second")

    append_action_mark(directory, first)
    append_action_mark(directory, second)

    assert load_action_marks(directory) == (first, second)
    with pytest.raises(CaptureDataError, match="strictly increasing"):
        append_action_mark(directory, first)


def test_private_children_cannot_escape_the_run_directory(tmp_path: Path) -> None:
    directory = tmp_path / "run"
    directory.mkdir(mode=PRIVATE_DIRECTORY_MODE)

    with pytest.raises(StorageError, match="without directory components"):
        private_child(directory, "../outside.json")
