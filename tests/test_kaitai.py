from __future__ import annotations

import json
import sys
from types import ModuleType
from typing import TYPE_CHECKING

import pytest

from ios_ble_capture.kaitai import (
    KaitaiCompilationRequest,
    KaitaiConfigurationError,
    KaitaiFixture,
    KaitaiFixtureError,
    assert_kaitai_fixture,
    compile_kaitai,
    decode_kaitai,
)

if TYPE_CHECKING:
    from io import BytesIO
    from pathlib import Path


def test_compilation_cache_uses_schema_content_not_meta_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_runtime(monkeypatch)
    compiler = _fake_compiler(tmp_path)
    request = _request(tmp_path, compiler, target_name="target", marker="one")

    first_result = compile_kaitai(request)
    request.root_schema.write_text("meta:\n  id: shared\nmarker: two\n", encoding="utf-8")
    second_result = compile_kaitai(request)

    assert first_result.cache_key != second_result.cache_key
    assert first_result.output_path != second_result.output_path
    assert not first_result.output_path.is_relative_to(request.target_path)
    assert not second_result.output_path.is_relative_to(request.target_path)
    assert decode_kaitai(first_result, b"\x01") == {"marker": "one", "payload": "01", "size": 1}
    assert decode_kaitai(second_result, b"\x01\x02") == {"marker": "two", "payload": "0102", "size": 2}
    assert json.loads(json.dumps(first_result.to_record()))["root_identity"] == "shared-root"


def test_compilation_hashes_imported_schemas(tmp_path: Path) -> None:
    compiler = _fake_compiler(tmp_path)
    request = _request(tmp_path, compiler, target_name="target", marker="one", imported_schema=True)

    result = compile_kaitai(request)

    assert any(path.endswith("common.ksy") for path, _digest in result.schema_hashes)


def test_compilation_cache_changes_with_runtime_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiler = _fake_compiler(tmp_path)
    request = _request(tmp_path, compiler, target_name="target", marker="one")
    monkeypatch.setattr("ios_ble_capture.kaitai._runtime_version", lambda: "0.10")
    first = compile_kaitai(request)
    monkeypatch.setattr("ios_ble_capture.kaitai._runtime_version", lambda: "0.11")
    second = compile_kaitai(request)

    assert first.cache_key != second.cache_key
    assert first.runtime_version == "0.10"
    assert second.runtime_version == "0.11"


def test_fixture_checks_decoded_output_and_raw_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_runtime(monkeypatch)
    result = compile_kaitai(_request(tmp_path, _fake_compiler(tmp_path), target_name="target", marker="fixture"))

    decoded = assert_kaitai_fixture(
        result,
        KaitaiFixture(
            data=b"\x01\x02",
            expected={"marker": "fixture", "payload": "0102", "size": 2},
            round_trip_bytes=b"\x01\x02",
        ),
    )

    assert isinstance(decoded, dict)
    assert decoded["marker"] == "fixture"


def test_cache_directory_inside_target_is_refused(tmp_path: Path) -> None:
    request = _request(tmp_path, _fake_compiler(tmp_path), target_name="target", marker="one")
    invalid = KaitaiCompilationRequest(
        target_path=request.target_path,
        ksy_root=request.ksy_root,
        root_schema=request.root_schema,
        import_paths=request.import_paths,
        output_language=request.output_language,
        root_identity=request.root_identity,
        module_name=request.module_name,
        root_type_name=request.root_type_name,
        compiler_executable=request.compiler_executable,
        cache_directory=request.target_path / "cache",
        target_output_path=request.target_output_path,
    )

    with pytest.raises(KaitaiConfigurationError, match="outside the target"):
        compile_kaitai(invalid)


def _request(
    tmp_path: Path,
    compiler: Path,
    *,
    target_name: str,
    marker: str,
    imported_schema: bool = False,
) -> KaitaiCompilationRequest:
    target = tmp_path / target_name
    ksy_root = target / "schemas"
    ksy_root.mkdir(parents=True)
    imports = "imports:\n  - common\n" if imported_schema else ""
    (ksy_root / "message.ksy").write_text(
        f"meta:\n  id: shared\n{imports}marker: {marker}\n",
        encoding="utf-8",
    )
    if imported_schema:
        (ksy_root / "common.ksy").write_text("meta:\n  id: common\n", encoding="utf-8")
    return KaitaiCompilationRequest(
        target_path=target,
        ksy_root=ksy_root,
        root_schema=ksy_root / "message.ksy",
        import_paths=(),
        output_language="python",
        root_identity="shared-root",
        module_name="message",
        root_type_name="Message",
        compiler_executable=compiler,
        cache_directory=tmp_path / "cache",
        target_output_path=target / "generated" / "message.py",
    )


def _fake_compiler(tmp_path: Path) -> Path:
    compiler = tmp_path / "fake-kaitai.py"
    compiler.write_text(
        """#!/usr/bin/env python3
import sys
from pathlib import Path

arguments = sys.argv[1:]
if arguments == ["--version"]:
    print("kaitai-struct-compiler fake-1")
    raise SystemExit(0)
output = Path(arguments[arguments.index("--outdir") + 1])
root = Path(arguments[-1])
marker = next(line.split(": ", 1)[1] for line in root.read_text().splitlines() if line.startswith("marker:"))
output.joinpath("message.py").write_text(
    "class Message:\\n"
    "    def __init__(self, stream):\\n"
    f"        self.marker = {marker!r}\\n"
    "        self._stream = stream\\n"
    "    def _read(self):\\n"
    "        self.payload = self._stream._io.read()\\n"
    "        self.size = len(self.payload)\\n"
    "    def _check(self):\\n"
    "        return None\\n"
    "    def _write(self, stream):\\n"
    "        stream._io.write(self.payload)\\n"
)
""",
        encoding="utf-8",
    )
    compiler.chmod(0o755)
    return compiler


def _install_fake_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = ModuleType("kaitaistruct")

    class KaitaiStream:
        def __init__(self, stream: BytesIO) -> None:
            self._io = stream

        def to_byte_array(self) -> bytes:
            position = self._io.tell()
            self._io.seek(0)
            data = self._io.read()
            self._io.seek(position)
            return bytes(data)

    runtime.KaitaiStream = KaitaiStream  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "kaitaistruct", runtime)


def test_fixture_mismatch_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_runtime(monkeypatch)
    result = compile_kaitai(_request(tmp_path, _fake_compiler(tmp_path), target_name="target", marker="fixture"))

    with pytest.raises(KaitaiFixtureError, match="decoded fixture"):
        assert_kaitai_fixture(result, KaitaiFixture(data=b"\x01", expected={"marker": "incorrect"}))
