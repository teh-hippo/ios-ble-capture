"""Declarative recipe execution using package-owned operations only."""

from __future__ import annotations

import json
import math
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ios_ble_capture.errors import RecipeError
from ios_ble_capture.ios.capture import build_capture_plan
from ios_ble_capture.ios.config import HostPlatform, IosTarget
from ios_ble_capture.ios.process import ProcessStarter, ProcessSupervisor, SubprocessStarter
from ios_ble_capture.ios.wda import UrllibWdaTransport, WebDriverAgentClient
from ios_ble_capture.kaitai import KaitaiCompilationRequest, compile_kaitai, decode_kaitai
from ios_ble_capture.recipes import STEP_ARGUMENTS
from ios_ble_capture.redaction import RedactionPolicy
from ios_ble_capture.reporting import diff_decoded_json, render_decoded_json_diff, report_events
from ios_ble_capture.segmentation import ActionMark
from ios_ble_capture.storage import (
    append_action_mark,
    load_events_jsonl,
    load_private_json,
    private_child,
    write_private_json,
    write_private_text,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ios_ble_capture.recipes import Recipe, Step
    from ios_ble_capture.run import RunContext

type JsonValue = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"] | None


type _ClientFactory = Callable[[str], WebDriverAgentClient]


@dataclass(frozen=True, slots=True)
class RecipeExecution:
    """The non-sensitive outcome of one recipe run."""

    completed_steps: tuple[str, ...]
    run_directory: Path


@dataclass(slots=True)
class _CaptureState:
    processes: ProcessSupervisor
    outputs: list[Path]
    process_names: list[str]


class RecipeExecutor:
    """Execute built-in recipe steps without loading target code or shell text."""

    def __init__(
        self,
        recipe: Recipe,
        *,
        recipe_directory: Path,
        process_starter: ProcessStarter | None = None,
        client_factory: _ClientFactory | None = None,
        dry_run: bool = False,
    ) -> None:
        self._recipe = recipe
        self._recipe_directory = recipe_directory.resolve()
        self._process_starter = process_starter or SubprocessStarter()
        self._client_factory = client_factory or _default_client
        self._dry_run = dry_run
        self._validate_recipe()

    def plan(self) -> tuple[str, ...]:
        """Return the validated recipe step kinds without revealing step arguments."""

        return tuple(step.kind for step in self._recipe.steps)

    def execute(self, context: RunContext) -> RecipeExecution:
        """Execute every step and tear down every recipe-owned capture process."""

        if self._dry_run:
            return RecipeExecution(self.plan(), context.directory)

        clients: dict[tuple[str, str], WebDriverAgentClient] = {}
        completed: list[str] = []
        capture_outputs: list[Path] = []
        capture_processes: list[str] = []
        try:
            with ProcessSupervisor(self._process_starter) as processes:
                capture_state = _CaptureState(
                    processes=processes,
                    outputs=capture_outputs,
                    process_names=capture_processes,
                )
                for index, step in enumerate(self._recipe.steps, start=1):
                    self._execute_step(
                        step,
                        index=index,
                        context=context,
                        clients=clients,
                        capture_state=capture_state,
                    )
                    completed.append(step.kind)
                    for process_name in capture_processes:
                        processes.require_running(process_name)
        finally:
            for output in capture_outputs:
                if output.exists():
                    output.chmod(0o600)
        return RecipeExecution(tuple(completed), context.directory)

    def _execute_step(  # noqa: PLR0912, C901
        self,
        step: Step,
        *,
        index: int,
        context: RunContext,
        clients: dict[tuple[str, str], WebDriverAgentClient],
        capture_state: _CaptureState,
    ) -> None:
        arguments = step.arguments
        if step.kind == "assert":
            self._assert(arguments, context, index)
        elif step.kind == "capture":
            self._capture(
                arguments,
                context,
                capture_state,
                index,
            )
        elif step.kind == "decode":
            self._decode(arguments, context, index)
        elif step.kind == "diff":
            self._diff(arguments, context, index)
        elif step.kind == "launch":
            self._client(arguments, clients, index)
        elif step.kind == "mark":
            self._mark(arguments, context, index)
        elif step.kind == "report":
            self._report(arguments, context, index)
        elif step.kind == "screenshot":
            output_name = self._optional_file(arguments, "output", f"screenshot-{index}.png", index)
            output = private_child(context.directory, output_name)
            self._client(arguments, clients, index).screenshot(output)
            output.chmod(0o600)
        elif step.kind == "swipe":
            self._client(arguments, clients, index).slide_named(
                self._required_string(arguments, "name", index),
                start=self._required_fraction(arguments, "start", index),
                end=self._required_fraction(arguments, "end", index),
            )
        elif step.kind == "tap":
            self._client(arguments, clients, index).tap_named(self._required_string(arguments, "name", index))
        elif step.kind == "type":
            client = self._client(arguments, clients, index)
            client.tap_named(self._required_string(arguments, "name", index))
            client.type_text(self._required_string(arguments, "text", index, allow_empty=True))
        elif step.kind == "wait":
            if not self._dry_run:
                time.sleep(self._required_seconds(arguments, "seconds", index))
        else:
            raise RecipeError(f"step {index} has unsupported kind: {step.kind!r}")

    def _assert(self, arguments: Mapping[str, object], context: RunContext, index: int) -> None:
        actual = load_private_json(private_child(context.directory, self._required_file(arguments, "file", index)))
        try:
            expected = arguments["equals"]
        except KeyError as error:
            raise RecipeError(f"step {index} is missing argument: 'equals'") from error
        if actual != expected:
            raise RecipeError(f"step {index} assertion failed for {arguments['file']!r}")

    def _capture(
        self,
        arguments: Mapping[str, object],
        context: RunContext,
        state: _CaptureState,
        index: int,
    ) -> None:
        output = private_child(context.directory, self._required_file(arguments, "output", index))
        plan = build_capture_plan(
            target=IosTarget(self._required_string(arguments, "udid", index)),
            host=HostPlatform(self._required_string(arguments, "host", index)),
            output=output,
        )
        state.outputs.append(plan.output)
        if not self._dry_run:
            process_name = f"capture-{index}"
            state.processes.start(process_name, plan.command)
            state.process_names.append(process_name)

    def _decode(self, arguments: Mapping[str, object], context: RunContext, index: int) -> None:
        result = compile_kaitai(self._kaitai_request(arguments, index))
        decoded = decode_kaitai(result, self._decode_data(arguments, index))
        output = private_child(
            context.directory,
            self._optional_file(arguments, "output", f"decoded-{index}.json", index),
        )
        write_private_json(output, decoded)

    def _diff(self, arguments: Mapping[str, object], context: RunContext, index: int) -> None:
        before_name = self._required_file(arguments, "before", index)
        after_name = self._required_file(arguments, "after", index)
        before = _json_value(load_private_json(private_child(context.directory, before_name)))
        after = _json_value(load_private_json(private_child(context.directory, after_name)))
        output_name = self._optional_file(arguments, "output", f"diff-{index}.jsonl", index)
        output = private_child(context.directory, output_name)
        write_private_text(output, render_decoded_json_diff(diff_decoded_json(before, after)))

    def _mark(self, arguments: Mapping[str, object], context: RunContext, index: int) -> None:
        timestamp = self._optional_timestamp(arguments, "timestamp", index) or datetime.now().astimezone()
        mark = ActionMark(timestamp, self._required_string(arguments, "label", index))
        append_action_mark(context.directory, mark, name=self._optional_file(arguments, "output", "marks.jsonl", index))

    def _report(self, arguments: Mapping[str, object], context: RunContext, index: int) -> None:
        events_name = self._optional_file(arguments, "events", "events.jsonl", index)
        events = load_events_jsonl(private_child(context.directory, events_name))
        include_raw = arguments.get("include_raw", False)
        if not isinstance(include_raw, bool):
            raise RecipeError(f"step {index} argument 'include_raw' must be a boolean")
        include_identifiers = arguments.get("include_identifiers", False)
        if not isinstance(include_identifiers, bool):
            raise RecipeError(f"step {index} argument 'include_identifiers' must be a boolean")
        output_name = self._optional_file(arguments, "output", f"report-{index}.json", index)
        output = private_child(context.directory, output_name)
        write_private_json(
            output,
            report_events(
                events,
                RedactionPolicy(
                    include_raw_payloads=include_raw,
                    include_identifiers=include_identifiers,
                ),
            ),
        )

    def _client(
        self,
        arguments: Mapping[str, object],
        clients: dict[tuple[str, str], WebDriverAgentClient],
        index: int,
    ) -> WebDriverAgentClient:
        url = self._required_string(arguments, "wda_url", index)
        bundle_id = self._required_string(arguments, "bundle_id", index)
        key = (url, bundle_id)
        client = clients.get(key)
        if client is None:
            client = self._client_factory(url)
            client.open(bundle_id)
            clients[key] = client
        return client

    def _kaitai_request(self, arguments: Mapping[str, object], index: int) -> KaitaiCompilationRequest:
        target_path = self._external_path(self._required_string(arguments, "target_path", index), index)
        ksy_root = self._external_path(self._required_string(arguments, "ksy_root", index), index)
        if not ksy_root.is_relative_to(target_path):
            raise RecipeError(f"step {index} KSY root must be inside target_path")
        cache_value = arguments.get("cache_directory")
        if cache_value is None:
            cache_home = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
            cache_directory = cache_home / "ios-ble-capture" / "kaitai"
        elif isinstance(cache_value, str) and cache_value:
            cache_directory = self._external_path(cache_value, index)
        else:
            raise RecipeError(f"step {index} argument 'cache_directory' must be a non-empty string")
        return KaitaiCompilationRequest(
            target_path=target_path,
            ksy_root=ksy_root,
            root_schema=self._external_path(self._required_string(arguments, "root_schema", index), index),
            import_paths=tuple(
                self._external_path(item, index)
                for item in self._optional_string_list(arguments, "import_paths", index)
            ),
            module_name=self._required_string(arguments, "module_name", index),
            root_type_name=self._required_string(arguments, "root_type_name", index),
            compiler_executable=self._required_string(arguments, "compiler", index),
            cache_directory=cache_directory,
        )

    def _decode_data(self, arguments: Mapping[str, object], index: int) -> bytes:
        self._validate_decode_data(arguments, index)
        data_hex = arguments.get("data_hex")
        data_file = arguments.get("data_file")
        if isinstance(data_hex, str):
            return bytes.fromhex(data_hex)
        if isinstance(data_file, str):
            try:
                return self._external_path(data_file, index).read_bytes()
            except OSError as error:
                raise RecipeError(f"step {index} cannot read data_file: {error.strerror or error}") from error
        raise RecipeError(f"step {index} must provide exactly one of 'data_hex' or 'data_file'")

    @staticmethod
    def _validate_decode_data(arguments: Mapping[str, object], index: int) -> None:
        data_hex = arguments.get("data_hex")
        data_file = arguments.get("data_file")
        if (data_hex is None) == (data_file is None):
            raise RecipeError(f"step {index} must provide exactly one of 'data_hex' or 'data_file'")
        if isinstance(data_hex, str):
            try:
                bytes.fromhex(data_hex)
            except ValueError as error:
                raise RecipeError(f"step {index} argument 'data_hex' is not hexadecimal") from error
            return
        if isinstance(data_file, str) and data_file:
            return
        raise RecipeError(f"step {index} argument 'data_file' must be a non-empty string")

    def _external_path(self, value: str, index: int) -> Path:
        path = Path(value)
        if not path.is_absolute():
            path = self._recipe_directory / path
        resolved = path.resolve()
        if not resolved.is_absolute():
            raise RecipeError(f"step {index} path must be absolute after resolution")
        return resolved

    def _validate_recipe(self) -> None:  # noqa: PLR0912, C901
        for index, step in enumerate(self._recipe.steps, start=1):
            arguments = step.arguments
            try:
                allowed, required = STEP_ARGUMENTS[step.kind]
            except KeyError as error:
                raise RecipeError(f"unsupported recipe step kind: {step.kind!r}") from error
            unknown = set(arguments) - allowed
            missing = required - set(arguments)
            if unknown:
                raise RecipeError(f"step {index} has unsupported arguments: {', '.join(sorted(unknown))}")
            if missing:
                raise RecipeError(f"step {index} is missing arguments: {', '.join(sorted(missing))}")
            if step.kind == "capture":
                try:
                    IosTarget(self._required_string(arguments, "udid", index))
                    HostPlatform(self._required_string(arguments, "host", index))
                except ValueError as error:
                    raise RecipeError(f"step {index} has invalid capture configuration: {error}") from error
                self._required_file(arguments, "output", index)
            elif step.kind == "decode":
                self._validate_decode_data(arguments, index)
                self._kaitai_request(arguments, index)
            elif step.kind == "mark":
                self._required_string(arguments, "label", index)
                self._optional_timestamp(arguments, "timestamp", index)
            elif step.kind == "report":
                include_raw = arguments.get("include_raw", False)
                if not isinstance(include_raw, bool):
                    raise RecipeError(f"step {index} argument 'include_raw' must be a boolean")
                include_identifiers = arguments.get("include_identifiers", False)
                if not isinstance(include_identifiers, bool):
                    raise RecipeError(f"step {index} argument 'include_identifiers' must be a boolean")
            elif step.kind in {"launch", "screenshot", "swipe", "tap", "type"}:
                self._required_string(arguments, "wda_url", index)
                self._required_string(arguments, "bundle_id", index)
                if step.kind in {"swipe", "tap", "type"}:
                    self._required_string(arguments, "name", index)
                if step.kind == "swipe":
                    self._required_fraction(arguments, "start", index)
                    self._required_fraction(arguments, "end", index)
                if step.kind == "type":
                    self._required_string(arguments, "text", index, allow_empty=True)
            elif step.kind == "wait":
                self._required_seconds(arguments, "seconds", index)

    @staticmethod
    def _required_string(
        arguments: Mapping[str, object],
        name: str,
        index: int,
        *,
        allow_empty: bool = False,
    ) -> str:
        value = arguments.get(name)
        if not isinstance(value, str) or (not allow_empty and not value.strip()):
            raise RecipeError(f"step {index} argument {name!r} must be a non-empty string")
        return value

    def _required_file(self, arguments: Mapping[str, object], name: str, index: int) -> str:
        value = self._required_string(arguments, name, index)
        if Path(value).name != value:
            raise RecipeError(f"step {index} argument {name!r} must be a file name")
        return value

    def _optional_file(self, arguments: Mapping[str, object], name: str, default: str, index: int) -> str:
        if name not in arguments:
            return default
        return self._required_file(arguments, name, index)

    @staticmethod
    def _required_string_list(arguments: Mapping[str, object], name: str, index: int) -> tuple[str, ...]:
        value = arguments.get(name)
        if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
            raise RecipeError(f"step {index} argument {name!r} must be an array of non-empty strings")
        return tuple(cast("list[str]", value))

    def _optional_string_list(self, arguments: Mapping[str, object], name: str, index: int) -> tuple[str, ...]:
        if name not in arguments:
            return ()
        return self._required_string_list(arguments, name, index)

    @staticmethod
    def _required_fraction(arguments: Mapping[str, object], name: str, index: int) -> float:
        value = arguments.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RecipeError(f"step {index} argument {name!r} must be a fraction from 0 to 1")
        numeric = float(value)
        if not math.isfinite(numeric) or not 0 <= numeric <= 1:
            raise RecipeError(f"step {index} argument {name!r} must be a fraction from 0 to 1")
        return numeric

    @staticmethod
    def _required_seconds(arguments: Mapping[str, object], name: str, index: int) -> float:
        value = arguments.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise RecipeError(f"step {index} argument {name!r} must be a non-negative finite number")
        return float(value)

    @staticmethod
    def _optional_timestamp(arguments: Mapping[str, object], name: str, index: int) -> datetime | None:
        value = arguments.get(name)
        if value is None:
            return None
        if not isinstance(value, str):
            raise RecipeError(f"step {index} argument {name!r} must be an ISO 8601 timestamp")
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError as error:
            raise RecipeError(f"step {index} argument {name!r} must be an ISO 8601 timestamp") from error
        if timestamp.utcoffset() is None:
            raise RecipeError(f"step {index} argument {name!r} must include a UTC offset")
        return timestamp


def _default_client(wda_url: str) -> WebDriverAgentClient:
    return WebDriverAgentClient(UrllibWdaTransport(wda_url))


def _json_value(value: object) -> JsonValue:
    try:
        json.dumps(value)
    except (TypeError, ValueError) as error:
        raise RecipeError(f"JSON value is not structurally comparable: {error}") from error
    return cast("JsonValue", value)
