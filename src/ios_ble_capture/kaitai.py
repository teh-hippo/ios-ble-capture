"""Kaitai Struct compilation, decoding, and fixture support."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import importlib.util
import io
import json
import math
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast
from uuid import uuid4

type JsonValue = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"] | None

_CACHE_FORMAT_VERSION = 2
_METADATA_FILE = "result.json"
_OUTPUT_DIRECTORY = "output"


class KaitaiError(RuntimeError):
    """Raised when Kaitai orchestration cannot complete."""


class KaitaiConfigurationError(KaitaiError):
    """Raised when a compilation or decode request is invalid."""


class KaitaiCompilerError(KaitaiError):
    """Raised when the Kaitai Struct Compiler fails."""


class KaitaiDecodeError(KaitaiError):
    """Raised when a generated parser cannot decode supplied bytes."""


class KaitaiFixtureError(KaitaiDecodeError):
    """Raised when decoded output differs from a supplied fixture."""


@dataclass(frozen=True, slots=True)
class KaitaiCompilationRequest:
    """Describes one cached Kaitai Struct compilation."""

    target_path: Path
    ksy_root: Path
    root_schema: Path
    import_paths: tuple[Path, ...]
    output_language: str
    root_identity: str
    module_name: str
    root_type_name: str
    compiler_executable: Path | str
    cache_directory: Path
    target_output_path: Path


@dataclass(frozen=True, slots=True)
class KaitaiCompilationResult:
    """Records a reusable compiled parser and the inputs that produced it."""

    cache_key: str
    output_path: Path
    target_path: Path
    ksy_root: Path
    import_paths: tuple[Path, ...]
    output_language: str
    root_identity: str
    module_name: str
    root_type_name: str
    target_output_path: Path
    compiler_version: str
    runtime_version: str | None
    schema_hashes: tuple[tuple[str, str], ...]

    def to_record(self) -> dict[str, JsonValue]:
        """Return a JSON-compatible description of this compilation."""
        return {
            "cache_key": self.cache_key,
            "output_path": str(self.output_path),
            "target_path": str(self.target_path),
            "ksy_root": str(self.ksy_root),
            "import_paths": [str(path) for path in self.import_paths],
            "output_language": self.output_language,
            "root_identity": self.root_identity,
            "module_name": self.module_name,
            "root_type_name": self.root_type_name,
            "target_output_path": str(self.target_output_path),
            "compiler_version": self.compiler_version,
            "runtime_version": self.runtime_version,
            "schema_hashes": dict(self.schema_hashes),
        }


@dataclass(frozen=True, slots=True)
class KaitaiFixture:
    """Provides expected decoded output and an optional write-back assertion."""

    data: bytes
    expected: JsonValue
    round_trip_bytes: bytes | None = None


class _KaitaiStream(Protocol):
    def to_byte_array(self) -> bytes: ...


def compile_kaitai(request: KaitaiCompilationRequest) -> KaitaiCompilationResult:
    """Compile a schema into an external, content-addressed cache."""
    validated = _validate_request(request)
    compiler_version = _compiler_version(validated.compiler_executable)
    runtime_version = _runtime_version()
    schema_hashes = _schema_hashes(validated.ksy_root, validated.import_paths)
    cache_key = _cache_key(
        validated,
        compiler_version,
        runtime_version,
        schema_hashes,
    )
    cache_item = validated.cache_directory / cache_key
    metadata_path = cache_item / _METADATA_FILE

    if metadata_path.is_file() and (cache_item / _OUTPUT_DIRECTORY).is_dir():
        return _result_from_record(json.loads(metadata_path.read_text(encoding="utf-8")))

    validated.cache_directory.mkdir(parents=True, exist_ok=True)
    stage = validated.cache_directory / f".{cache_key}.stage-{uuid4().hex}"
    try:
        output_path = stage / _OUTPUT_DIRECTORY
        output_path.mkdir(parents=True)
        _run_compiler(validated, output_path)
        result = KaitaiCompilationResult(
            cache_key=cache_key,
            output_path=cache_item / _OUTPUT_DIRECTORY,
            target_path=validated.target_path,
            ksy_root=validated.ksy_root,
            import_paths=validated.import_paths,
            output_language=validated.output_language,
            root_identity=validated.root_identity,
            module_name=validated.module_name,
            root_type_name=validated.root_type_name,
            target_output_path=validated.target_output_path,
            compiler_version=compiler_version,
            runtime_version=runtime_version,
            schema_hashes=schema_hashes,
        )
        (stage / _METADATA_FILE).write_text(
            json.dumps(result.to_record(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        try:
            stage.replace(cache_item)
        except FileExistsError:
            shutil.rmtree(stage)
        return _result_from_record(json.loads(metadata_path.read_text(encoding="utf-8")))
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        raise


def load_parser(result: KaitaiCompilationResult) -> type[Any]:
    """Load the generated Python root type specified by a compilation result."""
    if result.output_language != "python":
        raise KaitaiConfigurationError(
            f"Python decoding requires output language 'python', got {result.output_language!r}"
        )

    module_path = result.output_path.joinpath(*result.module_name.split(".")).with_suffix(".py")
    if not module_path.is_file():
        raise KaitaiDecodeError(f"generated parser module is missing: {module_path}")

    previous_modules = _remove_generated_modules(result.output_path)
    sys.path.insert(0, str(result.output_path))
    specification = importlib.util.spec_from_file_location(result.module_name, module_path)
    if specification is None or specification.loader is None:
        sys.path.remove(str(result.output_path))
        _restore_modules(previous_modules)
        raise KaitaiDecodeError(f"cannot load generated parser module: {module_path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[result.module_name] = module
    try:
        specification.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(result.module_name, None)
        raise KaitaiDecodeError(f"cannot import generated parser module {result.module_name!r}: {error}") from error
    finally:
        sys.path.remove(str(result.output_path))
        _remove_generated_modules(result.output_path)
        _restore_modules(previous_modules)
    try:
        parser = getattr(module, result.root_type_name)
    except AttributeError as error:
        raise KaitaiDecodeError(
            f"generated parser type {result.root_type_name!r} is missing from module {result.module_name!r}"
        ) from error
    if not isinstance(parser, type):
        raise KaitaiDecodeError(f"generated parser type {result.root_type_name!r} is not a class")
    return cast("type[Any]", parser)


def decode_kaitai(result: KaitaiCompilationResult, data: bytes) -> JsonValue:
    """Decode bytes through a generated parser and return JSON-compatible output."""
    parsed = _parse(result, data)
    return to_json_compatible(parsed)


def assert_kaitai_fixture(result: KaitaiCompilationResult, fixture: KaitaiFixture) -> JsonValue:
    """Decode a fixture and optionally verify its generated write-back bytes."""
    parsed = _parse(result, fixture.data)
    decoded = to_json_compatible(parsed)
    if decoded != fixture.expected:
        raise KaitaiFixtureError(
            "decoded fixture does not match expected JSON: "
            f"expected {json.dumps(fixture.expected, sort_keys=True)}, got {json.dumps(decoded, sort_keys=True)}"
        )
    if fixture.round_trip_bytes is not None:
        round_trip = _write_back(parsed, len(fixture.data))
        if round_trip != fixture.round_trip_bytes:
            raise KaitaiFixtureError(
                "generated parser write-back bytes do not match fixture: "
                f"expected {fixture.round_trip_bytes.hex()}, got {round_trip.hex()}"
            )
    return decoded


def to_json_compatible(value: object) -> JsonValue:
    """Convert parsed Kaitai values into values accepted by ``json.dumps``."""
    return _to_json_compatible(value, seen=set())


def _validate_request(request: KaitaiCompilationRequest) -> KaitaiCompilationRequest:  # noqa: C901
    target_path = request.target_path.resolve()
    ksy_root = request.ksy_root.resolve()
    root_schema = (
        request.root_schema.resolve()
        if request.root_schema.is_absolute()
        else (ksy_root / request.root_schema).resolve()
    )
    import_paths = tuple(path.resolve() for path in request.import_paths)
    cache_directory = request.cache_directory.resolve()
    target_output_path = request.target_output_path.resolve()

    if not target_path.is_dir():
        raise KaitaiConfigurationError(f"target path does not exist: {target_path}")
    if not ksy_root.is_dir():
        raise KaitaiConfigurationError(f"KSY root does not exist: {ksy_root}")
    if not root_schema.is_file() or root_schema.suffix != ".ksy":
        raise KaitaiConfigurationError(f"root schema must be an existing .ksy file: {root_schema}")
    if not root_schema.is_relative_to(ksy_root):
        raise KaitaiConfigurationError("root schema must be contained by the KSY root")
    if not request.output_language.strip():
        raise KaitaiConfigurationError("output language must be explicitly provided")
    if request.output_language != "python":
        raise KaitaiConfigurationError(f"unsupported Kaitai output language: {request.output_language!r}")
    for name, value in (
        ("root identity", request.root_identity),
        ("module name", request.module_name),
        ("root type name", request.root_type_name),
    ):
        if not value.strip():
            raise KaitaiConfigurationError(f"{name} must be explicitly provided")
    for import_path in import_paths:
        if not import_path.is_dir():
            raise KaitaiConfigurationError(f"import path does not exist: {import_path}")
    if cache_directory.is_relative_to(target_path):
        raise KaitaiConfigurationError("cache directory must be outside the target path")

    return KaitaiCompilationRequest(
        target_path=target_path,
        ksy_root=ksy_root,
        root_schema=root_schema,
        import_paths=import_paths,
        output_language=request.output_language,
        root_identity=request.root_identity,
        module_name=request.module_name,
        root_type_name=request.root_type_name,
        compiler_executable=request.compiler_executable,
        cache_directory=cache_directory,
        target_output_path=target_output_path,
    )


def _compiler_version(executable: Path | str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603
            [str(executable), "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise KaitaiCompilerError(f"cannot execute Kaitai Struct Compiler: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        outcome = detail or f"exit code {completed.returncode}"
        raise KaitaiCompilerError(f"Kaitai Struct Compiler version check failed: {outcome}")
    version = completed.stdout.strip() or completed.stderr.strip()
    if not version:
        raise KaitaiCompilerError("Kaitai Struct Compiler did not report a version")
    return version


def _schema_hashes(ksy_root: Path, import_paths: Sequence[Path]) -> tuple[tuple[str, str], ...]:
    schema_paths = {path.resolve() for directory in (ksy_root, *import_paths) for path in directory.rglob("*.ksy")}
    if not schema_paths:
        raise KaitaiConfigurationError("no .ksy schemas were found in the KSY root or import paths")
    return tuple((str(path), hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(schema_paths, key=str))


def _cache_key(
    request: KaitaiCompilationRequest,
    compiler_version: str,
    runtime_version: str | None,
    schema_hashes: tuple[tuple[str, str], ...],
) -> str:
    payload = {
        "format_version": _CACHE_FORMAT_VERSION,
        "target_path": str(request.target_path),
        "ksy_root": str(request.ksy_root),
        "root_schema": str(request.root_schema),
        "import_paths": [str(path) for path in request.import_paths],
        "output_language": request.output_language,
        "root_identity": request.root_identity,
        "module_name": request.module_name,
        "root_type_name": request.root_type_name,
        "target_output_path": str(request.target_output_path),
        "compiler_version": compiler_version,
        "runtime_version": runtime_version,
        "schema_hashes": schema_hashes,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _run_compiler(request: KaitaiCompilationRequest, output_path: Path) -> None:
    command = [
        str(request.compiler_executable),
        "--target",
        request.output_language,
        "--read-write",
        "--outdir",
        str(output_path),
    ]
    for import_path in (request.ksy_root, *request.import_paths):
        command.extend(("--import-path", str(import_path)))
    command.append(str(request.root_schema))
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)  # noqa: S603
    except OSError as error:
        raise KaitaiCompilerError(f"cannot execute Kaitai Struct Compiler: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise KaitaiCompilerError(f"Kaitai Struct Compiler failed: {detail or f'exit code {completed.returncode}'}")


def _runtime_version() -> str | None:
    try:
        return importlib.metadata.version("kaitaistruct")
    except importlib.metadata.PackageNotFoundError:
        return None


def _result_from_record(record: Mapping[str, object]) -> KaitaiCompilationResult:
    try:
        hashes = cast("Mapping[str, str]", record["schema_hashes"])
        return KaitaiCompilationResult(
            cache_key=cast("str", record["cache_key"]),
            output_path=Path(cast("str", record["output_path"])),
            target_path=Path(cast("str", record["target_path"])),
            ksy_root=Path(cast("str", record["ksy_root"])),
            import_paths=tuple(Path(path) for path in cast("list[str]", record["import_paths"])),
            output_language=cast("str", record["output_language"]),
            root_identity=cast("str", record["root_identity"]),
            module_name=cast("str", record["module_name"]),
            root_type_name=cast("str", record["root_type_name"]),
            target_output_path=Path(cast("str", record["target_output_path"])),
            compiler_version=cast("str", record["compiler_version"]),
            runtime_version=cast("str | None", record["runtime_version"]),
            schema_hashes=tuple(sorted(hashes.items())),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise KaitaiError(f"invalid cached Kaitai compilation record: {error}") from error


def _remove_generated_modules(output_path: Path) -> dict[str, ModuleType]:
    module_names = {
        ".".join(path.relative_to(output_path).with_suffix("").parts)
        for path in output_path.rglob("*.py")
        if path.name != "__init__.py"
    }
    removed: dict[str, ModuleType] = {}
    for module_name in module_names:
        module = sys.modules.pop(module_name, None)
        if isinstance(module, ModuleType):
            removed[module_name] = module
    return removed


def _restore_modules(modules: Mapping[str, ModuleType]) -> None:
    sys.modules.update(modules)


def _parse(result: KaitaiCompilationResult, data: bytes) -> object:
    try:
        runtime = importlib.import_module("kaitaistruct")
        stream_type = runtime.KaitaiStream
    except (ImportError, AttributeError) as error:
        raise KaitaiDecodeError("the kaitaistruct runtime is required to decode generated parsers") from error
    try:
        parsed = load_parser(result)(stream_type(io.BytesIO(data)))
    except KaitaiError:
        raise
    except Exception as error:
        raise KaitaiDecodeError(f"generated parser failed to decode {result.root_identity!r}: {error}") from error
    reader = getattr(parsed, "_read", None)
    if not callable(reader):
        raise KaitaiDecodeError("generated parser does not support reading")
    try:
        reader()
    except Exception as error:
        raise KaitaiDecodeError(f"generated parser failed to decode {result.root_identity!r}: {error}") from error
    return parsed


def _to_json_compatible(value: object, *, seen: set[int]) -> JsonValue:  # noqa: C901, PLR0911
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise KaitaiDecodeError("decoded parser output contains a non-finite float")
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, Enum):
        return _to_json_compatible(value.value, seen=seen)
    if isinstance(value, Mapping):
        return {str(key): _to_json_compatible(item, seen=seen) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json_compatible(item, seen=seen) for item in value]
    if isinstance(value, (set, frozenset)):
        converted = [_to_json_compatible(item, seen=seen) for item in value]
        return sorted(converted, key=lambda item: json.dumps(item, sort_keys=True))

    identity = id(value)
    if identity in seen:
        raise KaitaiDecodeError("decoded parser output contains a cycle")
    try:
        attributes = vars(value)
    except TypeError as error:
        raise KaitaiDecodeError(f"unsupported decoded value type: {type(value).__name__}") from error
    seen.add(identity)
    try:
        return {
            name: _to_json_compatible(item, seen=seen) for name, item in attributes.items() if not name.startswith("_")
        }
    finally:
        seen.remove(identity)


def _write_back(parsed: object, input_length: int) -> bytes:
    try:
        runtime = importlib.import_module("kaitaistruct")
        stream_type = runtime.KaitaiStream
    except (ImportError, AttributeError) as error:
        raise KaitaiDecodeError("the kaitaistruct runtime is required to write generated parsers") from error
    writer = getattr(parsed, "_write", None)
    if not callable(writer):
        raise KaitaiDecodeError("generated parser does not support raw write-back")
    _check_tree(parsed, seen=set())
    stream = stream_type(io.BytesIO(bytes(input_length)))
    try:
        cast("Callable[[_KaitaiStream], None]", writer)(stream)
        return bytes(stream.to_byte_array())
    except Exception as error:
        raise KaitaiDecodeError(f"generated parser failed to write bytes: {error}") from error


def _check_tree(value: object, *, seen: set[int]) -> None:
    identity = id(value)
    if identity in seen:
        return
    try:
        attributes = vars(value)
    except TypeError:
        return
    seen.add(identity)
    try:
        for name, child in attributes.items():
            if name.startswith("_"):
                continue
            if isinstance(child, (list, tuple, set, frozenset)):
                for item in child:
                    _check_tree(item, seen=seen)
            elif isinstance(child, Mapping):
                for item in child.values():
                    _check_tree(item, seen=seen)
            else:
                _check_tree(child, seen=seen)
        checker = getattr(value, "_check", None)
        if callable(checker):
            checker()
    finally:
        seen.remove(identity)
