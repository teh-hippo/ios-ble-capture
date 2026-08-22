from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

from ios_ble_capture.capture import import_capture
from ios_ble_capture.cli import run

if TYPE_CHECKING:
    from types import ModuleType

    import pytest

_EXAMPLE = Path(__file__).parents[1] / "examples" / "synthetic" / "generate_capture.py"
_RECIPE = _EXAMPLE.with_name("recipe.json")


def _load_example() -> ModuleType:
    specification = importlib.util.spec_from_file_location("synthetic_capture", _EXAMPLE)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_synthetic_pcap_and_pcapng_import_identically(tmp_path: Path) -> None:
    module = _load_example()
    pcap_path, pcapng_path = module.generate(tmp_path)

    pcap_events = import_capture(pcap_path.read_bytes()).events
    pcapng_events = import_capture(pcapng_path.read_bytes()).events

    assert pcap_events == pcapng_events
    assert [event.value.hex() for event in pcap_events] == ["100332333445"]


def test_synthetic_recipe_passes_side_effect_free_validation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run(["run", str(_RECIPE), "--dry-run"]) == 0
    assert '"steps":["mark","decode","assert"]' in capsys.readouterr().out
