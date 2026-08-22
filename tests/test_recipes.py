from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.errors import RecipeError
from ios_ble_capture.recipes import load_recipe, recipe_from_record

if TYPE_CHECKING:
    from pathlib import Path


def test_recipe_loads_builtin_steps_and_command_array_hooks(tmp_path: Path) -> None:
    path = tmp_path / "recipe.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "preflight": None,
                "pre_run": {"command": ["ownership", "disable"], "environment": {}},
                "post_run": {"command": ["ownership", "restore"], "environment": {}},
                "steps": [
                    {"kind": "mark", "arguments": {"label": "power"}},
                    {"kind": "wait", "arguments": {"seconds": 1}},
                ],
            }
        )
    )

    recipe = load_recipe(path)

    assert recipe.pre_run is not None
    assert recipe.pre_run.command == ("ownership", "disable")
    assert [step.kind for step in recipe.steps] == ["mark", "wait"]


def test_recipe_rejects_arbitrary_steps() -> None:
    with pytest.raises(RecipeError, match="unsupported kind"):
        recipe_from_record(
            {
                "version": 1,
                "preflight": None,
                "pre_run": None,
                "post_run": None,
                "steps": [{"kind": "shell", "arguments": {"command": "rm -rf /"}}],
            }
        )


def test_recipe_rejects_string_hooks() -> None:
    with pytest.raises(RecipeError, match=r"pre_run\.command"):
        recipe_from_record(
            {
                "version": 1,
                "preflight": None,
                "pre_run": {"command": "ownership disable", "environment": {}},  # type: ignore[typeddict-item]
                "post_run": None,
                "steps": [],
            }
        )


def test_recipe_rejects_inline_shell_hooks() -> None:
    with pytest.raises(RecipeError, match="inline shell"):
        recipe_from_record(
            {
                "version": 1,
                "preflight": None,
                "pre_run": {
                    "command": ["bash", "-c", "ownership disable"],
                    "environment": {},
                },
                "post_run": None,
                "steps": [],
            }
        )
