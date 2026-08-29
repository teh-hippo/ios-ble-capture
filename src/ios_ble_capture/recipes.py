from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PurePath
from typing import TYPE_CHECKING, Final, TypedDict, cast

from ios_ble_capture.errors import RecipeError
from ios_ble_capture.run import Hook

if TYPE_CHECKING:
    from pathlib import Path

STEP_ARGUMENTS: Final[dict[str, tuple[set[str], set[str]]]] = {
    "assert": ({"file", "equals"}, {"file", "equals"}),
    "capture": ({"udid", "host", "output"}, {"udid", "host", "output"}),
    "decode": (
        {
            "target_path",
            "ksy_root",
            "root_schema",
            "import_paths",
            "module_name",
            "root_type_name",
            "compiler",
            "cache_directory",
            "data_hex",
            "data_file",
            "output",
        },
        {
            "target_path",
            "ksy_root",
            "root_schema",
            "module_name",
            "root_type_name",
            "compiler",
        },
    ),
    "diff": ({"before", "after", "output"}, {"before", "after"}),
    "launch": ({"wda_url", "bundle_id"}, {"wda_url", "bundle_id"}),
    "mark": ({"label", "timestamp", "output"}, {"label"}),
    "report": ({"events", "include_identifiers", "include_raw", "output"}, set()),
    "screenshot": ({"wda_url", "bundle_id", "output"}, {"wda_url", "bundle_id"}),
    "swipe": ({"wda_url", "bundle_id", "name", "start", "end"}, {"wda_url", "bundle_id", "name", "start", "end"}),
    "tap": ({"wda_url", "bundle_id", "name"}, {"wda_url", "bundle_id", "name"}),
    "type": ({"wda_url", "bundle_id", "name", "text"}, {"wda_url", "bundle_id", "name", "text"}),
    "wait": ({"seconds"}, {"seconds"}),
}
STEP_KINDS: Final = frozenset(STEP_ARGUMENTS)
_INLINE_SHELL_FLAGS: Final = {
    "bash": frozenset({"-c"}),
    "cmd": frozenset({"/c", "/k"}),
    "cmd.exe": frozenset({"/c", "/k"}),
    "dash": frozenset({"-c"}),
    "fish": frozenset({"-c"}),
    "powershell": frozenset({"-command", "-encodedcommand"}),
    "powershell.exe": frozenset({"-command", "-encodedcommand"}),
    "pwsh": frozenset({"-command", "-encodedcommand"}),
    "pwsh.exe": frozenset({"-command", "-encodedcommand"}),
    "sh": frozenset({"-c"}),
    "zsh": frozenset({"-c"}),
}


class HookRecord(TypedDict):
    command: list[str]
    environment: dict[str, str]


class StepRecord(TypedDict):
    kind: str
    arguments: dict[str, object]


class RecipeRecord(TypedDict):
    version: int
    preflight: HookRecord | None
    pre_run: HookRecord | None
    post_run: HookRecord | None
    steps: list[StepRecord]


@dataclass(frozen=True, slots=True)
class Step:
    kind: str
    arguments: dict[str, object]


@dataclass(frozen=True, slots=True)
class Recipe:
    preflight: Hook | None
    pre_run: Hook | None
    post_run: Hook | None
    steps: tuple[Step, ...]


def load_recipe(path: Path) -> Recipe:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RecipeError(f"cannot read recipe {path}: {error}") from error
    if not isinstance(raw, dict):
        raise RecipeError("recipe root must be an object")
    return recipe_from_record(cast("RecipeRecord", raw))


def recipe_from_record(record: RecipeRecord) -> Recipe:
    if record.get("version") != 1:
        raise RecipeError("recipe version must be 1")
    steps_value = record.get("steps")
    if not isinstance(steps_value, list):
        raise RecipeError("recipe steps must be a list")
    steps: list[Step] = []
    for index, value in enumerate(steps_value):
        if not isinstance(value, dict):
            raise RecipeError(f"step {index} must be an object")
        kind = value.get("kind")
        arguments = value.get("arguments", {})
        if not isinstance(kind, str) or kind not in STEP_KINDS:
            raise RecipeError(f"step {index} has unsupported kind: {kind!r}")
        if not isinstance(arguments, dict) or not all(isinstance(key, str) for key in arguments):
            raise RecipeError(f"step {index} arguments must be an object")
        steps.append(Step(kind=kind, arguments=arguments))
    return Recipe(
        preflight=_hook_from_record(record.get("preflight"), name="preflight"),
        pre_run=_hook_from_record(record.get("pre_run"), name="pre_run"),
        post_run=_hook_from_record(record.get("post_run"), name="post_run"),
        steps=tuple(steps),
    )


def _hook_from_record(value: object, *, name: str) -> Hook | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RecipeError(f"{name} must be an object")
    command = value.get("command")
    environment = value.get("environment", {})
    if not isinstance(command, list) or not all(isinstance(part, str) and part for part in command):
        raise RecipeError(f"{name}.command must be a non-empty string array")
    if not command:
        raise RecipeError(f"{name}.command must not be empty")
    executable = PurePath(command[0]).name.casefold()
    forbidden_flags = _INLINE_SHELL_FLAGS.get(executable, frozenset())
    if any(argument.casefold() in forbidden_flags for argument in command[1:]):
        raise RecipeError(f"{name}.command cannot contain inline shell code")
    if not isinstance(environment, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in environment.items()
    ):
        raise RecipeError(f"{name}.environment must contain string values")
    return Hook(command=tuple(command), environment=cast("dict[str, str]", environment))
