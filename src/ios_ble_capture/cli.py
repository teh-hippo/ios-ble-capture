"""Command-line interface for capture runs and protocol analysis."""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
import math
import os
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ios_ble_capture import ble
from ios_ble_capture.attribution import catalogue_sources, select_source
from ios_ble_capture.capture import import_capture, write_raw_run
from ios_ble_capture.errors import CaptureDataError, CaptureError
from ios_ble_capture.executor import RecipeExecutor
from ios_ble_capture.ios.capture import CaptureConfigurationError, build_capture_plan
from ios_ble_capture.ios.config import HostPlatform, IosConfigurationError, IosTarget
from ios_ble_capture.ios.process import ProcessError, ProcessSupervisor, SubprocessStarter
from ios_ble_capture.ios.wda import WdaError
from ios_ble_capture.kaitai import KaitaiCompilationRequest, KaitaiError, compile_kaitai, decode_kaitai
from ios_ble_capture.recipes import load_recipe
from ios_ble_capture.redaction import RedactionPolicy
from ios_ble_capture.reporting import (
    diff_decoded_json,
    render_decoded_json,
    render_decoded_json_diff,
    render_events_text,
    report_events,
)
from ios_ble_capture.run import RunLifecycle, create_run_context, execute_with_hooks, interrupt_as_error
from ios_ble_capture.segmentation import ActionMark, segment_events
from ios_ble_capture.storage import (
    StorageError,
    append_action_mark,
    load_action_marks,
    load_events_jsonl,
    load_private_json,
    private_child,
    require_private_run_directory,
    write_connection_metadata,
    write_private_bytes,
    write_private_json,
    write_private_text,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    from ios_ble_capture.attribution import Source
    from ios_ble_capture.reporting import JsonValue

COMMANDS = (
    "capture",
    "import",
    "mark",
    "attribute",
    "segment",
    "decode",
    "diff",
    "report",
    "run",
    "ble",
)
_SOURCE_VERSION = "0.1.0"


def build_parser() -> argparse.ArgumentParser:  # noqa: PLR0915
    """Build the public command parser."""

    parser = argparse.ArgumentParser(
        prog="ios-ble-capture",
        description="Capture and analyse BLE traffic with target-owned protocol schemas.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    capture_parser = subcommands.add_parser("capture", help="Run an explicit iPhone Bluetooth logger.")
    capture_parser.add_argument("--udid", required=True)
    capture_parser.add_argument("--output", type=Path, required=True)
    capture_parser.add_argument("--host", choices=tuple(member.value for member in HostPlatform), required=True)
    capture_parser.add_argument("--grace-period", type=_non_negative_float, default=5.0)
    capture_parser.add_argument("--dry-run", action="store_true")
    capture_parser.set_defaults(handler=_capture_command)

    import_parser = subcommands.add_parser("import", help="Import one safely selected ATT source from a capture.")
    import_parser.add_argument("capture", type=Path)
    import_parser.add_argument("--run-root", type=Path)
    import_parser.add_argument("--expected-peer")
    import_parser.add_argument("--source")
    import_parser.add_argument("--allow-unattributed", action="store_true")
    import_parser.add_argument("--allow-truncated", action="store_true")
    import_parser.add_argument(
        "--classic-pcap-timezone",
        help="IANA timezone used by an idevicebtlogger local-wall-clock pcap.",
    )
    import_parser.set_defaults(handler=_import_command)

    mark_parser = subcommands.add_parser("mark", help="Append an offset-aware action mark.")
    mark_parser.add_argument("--run-dir", type=Path, required=True)
    mark_parser.add_argument("--label", required=True)
    mark_parser.add_argument("--timestamp", "--at", dest="timestamp")
    mark_parser.set_defaults(handler=_mark_command)

    attribute_parser = subcommands.add_parser("attribute", help="Catalogue or safely select capture sources.")
    attribute_parser.add_argument("events", type=Path)
    attribute_parser.add_argument("--expected-peer")
    attribute_parser.add_argument("--source")
    attribute_parser.add_argument("--allow-unattributed", action="store_true")
    attribute_parser.set_defaults(handler=_attribute_command)

    segment_parser = subcommands.add_parser("segment", help="Segment private events with action marks.")
    segment_parser.add_argument("--run-dir", type=Path, required=True)
    segment_parser.add_argument("--marks", default="marks.jsonl")
    segment_parser.add_argument("--output", default="segments.json")
    segment_parser.add_argument("--final-end")
    segment_parser.set_defaults(handler=_segment_command)

    decode_parser = subcommands.add_parser("decode", help="Compile an explicit KSY target and decode bytes.")
    _add_kaitai_arguments(decode_parser)
    decode_data = decode_parser.add_mutually_exclusive_group(required=True)
    decode_data.add_argument("--data-hex")
    decode_data.add_argument("--data-file", type=Path)
    decode_output = decode_parser.add_mutually_exclusive_group()
    decode_output.add_argument("--output", type=Path)
    decode_output.add_argument("--stdout", action="store_true")
    decode_parser.set_defaults(handler=_decode_command)

    diff_parser = subcommands.add_parser("diff", help="Compare decoded JSON structures.")
    diff_parser.add_argument("before", type=Path)
    diff_parser.add_argument("after", type=Path)
    diff_output = diff_parser.add_mutually_exclusive_group()
    diff_output.add_argument("--output", type=Path)
    diff_output.add_argument("--stdout", action="store_true")
    diff_parser.set_defaults(handler=_diff_command)

    report_parser = subcommands.add_parser("report", help="Render events with raw payloads withheld by default.")
    report_parser.add_argument("events", type=Path)
    report_parser.add_argument("--format", choices=("text", "json"), default="text")
    report_parser.add_argument("--include-raw", action="store_true")
    report_parser.add_argument("--include-identifiers", action="store_true")
    report_parser.set_defaults(handler=_report_command)

    run_parser = subcommands.add_parser("run", help="Execute a declarative recipe with lifecycle hooks.")
    run_parser.add_argument("recipe", type=Path)
    run_parser.add_argument("--run-root", type=Path)
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.set_defaults(handler=_run_command)

    ble_parser = subcommands.add_parser("ble", help="Perform explicit active BLE operations.")
    ble_subcommands = ble_parser.add_subparsers(dest="ble_command", required=True)
    ble_scan = ble_subcommands.add_parser("scan", help="Scan without connecting.")
    ble_scan.add_argument("--timeout", type=_positive_float, required=True)
    ble_scan.set_defaults(handler=_ble_scan_command)
    ble_connect = ble_subcommands.add_parser("connect", help="Connect to one explicit address.")
    _add_active_ble_arguments(ble_connect, endpoint=False)
    ble_connect.set_defaults(handler=_ble_connect_command)
    ble_read = ble_subcommands.add_parser("read", help="Read one characteristic.")
    _add_active_ble_arguments(ble_read, endpoint=True)
    ble_read.set_defaults(handler=_ble_read_command)
    ble_write = ble_subcommands.add_parser("write", help="Write one complete characteristic frame.")
    _add_active_ble_arguments(ble_write, endpoint=True)
    ble_write.add_argument("--data-hex", required=True)
    ble_write.add_argument("--response", choices=("with-response", "without-response"), required=True)
    ble_write.set_defaults(handler=_ble_write_command)
    ble_notify = ble_subcommands.add_parser("notify", help="Receive bounded characteristic notifications.")
    _add_active_ble_arguments(ble_notify, endpoint=True)
    ble_notify.add_argument("--duration", type=_positive_float, required=True)
    ble_notify.set_defaults(handler=_ble_notify_command)

    return parser


def run(argv: Sequence[str] | None = None) -> int:
    """Run one command and convert expected tool errors into deterministic output."""

    parser = build_parser()
    args = parser.parse_args(argv)
    handler = cast("Callable[[argparse.Namespace], int]", args.handler)
    try:
        return handler(args)
    except _EXPECTED_ERRORS as error:
        sys.stderr.write(f"error: {error}\n")
        return 1


def main() -> None:
    """Exit using the command result."""

    raise SystemExit(run())


def _capture_command(args: argparse.Namespace) -> int:
    plan = build_capture_plan(
        target=IosTarget(args.udid),
        host=HostPlatform(args.host),
        output=args.output,
    )
    if args.dry_run:
        redacted_output = _redact_secret(str(plan.output), args.udid)
        _print_json(
            {
                "backend": plan.backend.value,
                "command": [_redact_secret(argument, args.udid) for argument in plan.command.argv],
                "format": plan.format,
                "output": redacted_output,
            }
        )
        return 0
    try:
        with (
            _private_umask(),
            interrupt_as_error(),
            ProcessSupervisor(SubprocessStarter(), grace_period=args.grace_period) as processes,
        ):
            process = processes.start("capture", plan.command)
            returncode = process.wait()
    finally:
        if plan.output.exists():
            plan.output.chmod(0o600)
    if returncode != 0:
        raise ProcessError(f"capture logger exited with status {returncode}")
    _write_stdout(f"{plan.output}\n")
    return 0


def _import_command(args: argparse.Namespace) -> int:
    try:
        data = args.capture.read_bytes()
    except OSError as error:
        raise StorageError(f"cannot read capture {args.capture}: {error.strerror or error}") from error
    trace = import_capture(
        data,
        allow_truncated=args.allow_truncated,
        classic_pcap_timezone=_timezone(args.classic_pcap_timezone),
    )
    selection = select_source(
        trace.events,
        expected_peer=args.expected_peer,
        source=args.source,
        allow_unattributed=args.allow_unattributed,
    )
    context = create_run_context(source="capture-import", tool_version=_version(), root=args.run_root)
    write_raw_run(context.directory, selection.events)
    suffix = ".pcapng" if data.startswith(b"\x0a\x0d\x0d\x0a") else ".pcap"
    write_private_bytes(private_child(context.directory, f"capture{suffix}"), data)
    epochs = set(selection.source.connection_epochs)
    write_connection_metadata(
        context.directory,
        source={
            "connection_epochs": list(selection.source.connection_epochs),
            "event_count": selection.source.event_count,
            "identifier": selection.source.identifier,
            "peer_address": selection.source.peer_address,
        },
        connections=(connection for connection in trace.connections if connection.connection_epoch in epochs),
    )
    _write_stdout(f"{context.directory}\n")
    return 0


def _mark_command(args: argparse.Namespace) -> int:
    timestamp = _timestamp(args.timestamp) if args.timestamp is not None else datetime.now().astimezone()
    path = append_action_mark(require_private_run_directory(args.run_dir), ActionMark(timestamp, args.label))
    _write_stdout(f"{path}\n")
    return 0


def _attribute_command(args: argparse.Namespace) -> int:
    events = load_events_jsonl(args.events)
    sources = catalogue_sources(events)
    if args.expected_peer is None and args.source is None and not args.allow_unattributed:
        _print_json({"sources": [_source_record(source) for source in sources]})
        return 0
    selected = select_source(
        events,
        expected_peer=args.expected_peer,
        source=args.source,
        allow_unattributed=args.allow_unattributed,
    )
    _print_json({"event_count": len(selected.events), "source": _source_record(selected.source)})
    return 0


def _segment_command(args: argparse.Namespace) -> int:
    directory = require_private_run_directory(args.run_dir)
    events = load_events_jsonl(private_child(directory, "events.jsonl"))
    marks = load_action_marks(directory, name=args.marks)
    final_end = _timestamp(args.final_end) if args.final_end is not None else None
    segments = segment_events(events, marks, final_end=final_end)
    records = [
        {
            "end": segment.end.isoformat() if segment.end is not None else None,
            "events": [event.to_record() for event in segment.events],
            "label": segment.label,
            "start": segment.start.isoformat(),
        }
        for segment in segments
    ]
    path = write_private_json(private_child(directory, args.output), {"schema_version": 1, "segments": records})
    _write_stdout(f"{path}\n")
    return 0


def _decode_command(args: argparse.Namespace) -> int:
    _require_safe_output(args, "decode")
    data = _decode_bytes(args.data_hex, args.data_file)
    decoded = decode_kaitai(compile_kaitai(_kaitai_request(args)), data)
    rendered = render_decoded_json(decoded)
    if args.stdout:
        _write_stdout(rendered)
    else:
        output = _safe_output(args, "decode")
        write_private_text(output, rendered)
        _write_stdout(f"{output}\n")
    return 0


def _diff_command(args: argparse.Namespace) -> int:
    _require_safe_output(args, "diff")
    before = _json_value(load_private_json(args.before))
    after = _json_value(load_private_json(args.after))
    rendered = render_decoded_json_diff(diff_decoded_json(before, after))
    if args.stdout:
        _write_stdout(rendered)
    else:
        output = _safe_output(args, "diff")
        write_private_text(output, rendered)
        _write_stdout(f"{output}\n")
    return 0


def _report_command(args: argparse.Namespace) -> int:
    events = load_events_jsonl(args.events)
    policy = RedactionPolicy(
        include_raw_payloads=args.include_raw,
        include_identifiers=args.include_identifiers,
    )
    if args.format == "text":
        _write_stdout(f"{render_events_text(events, policy)}\n")
    else:
        _print_json({"events": report_events(events, policy)})
    return 0


def _run_command(args: argparse.Namespace) -> int:
    recipe = load_recipe(args.recipe)
    executor = RecipeExecutor(
        recipe,
        recipe_directory=args.recipe.parent,
        dry_run=args.dry_run,
    )
    if args.dry_run:
        _print_json({"dry_run": True, "steps": list(executor.plan())})
        return 0
    context = create_run_context(source="recipe", tool_version=_version(), root=args.run_root)
    execution = execute_with_hooks(
        executor.execute,
        lifecycle=RunLifecycle(
            context=context,
            preflight_hook=recipe.preflight,
            pre_run=recipe.pre_run,
            post_run=recipe.post_run,
        ),
    )
    _print_json({"completed_steps": list(execution.completed_steps), "run_directory": str(execution.run_directory)})
    return 0


def _ble_scan_command(args: argparse.Namespace) -> int:
    devices = asyncio.run(ble.scan(timeout=args.timeout))
    _print_json(
        {
            "devices": [
                {
                    "address": device.address,
                    "name": device.name,
                    "rssi": device.rssi,
                    "service_uuids": list(device.service_uuids),
                }
                for device in devices
            ]
        }
    )
    return 0


def _ble_connect_command(args: argparse.Namespace) -> int:
    async def connect_once() -> None:
        async with await ble.connect(address=args.address, timeout=args.timeout):
            return

    asyncio.run(connect_once())
    _write_stdout(f"connected {args.address}\n")
    return 0


def _ble_read_command(args: argparse.Namespace) -> int:
    async def read_once() -> bytes:
        async with await ble.connect(address=args.address, timeout=args.timeout) as session:
            return await session.read(
                service_uuid=args.service_uuid,
                characteristic_uuid=args.characteristic_uuid,
                timeout=args.timeout,
                frame_size=args.frame_size,
            )

    _write_stdout(f"{asyncio.run(read_once()).hex()}\n")
    return 0


def _ble_write_command(args: argparse.Namespace) -> int:
    try:
        data = bytes.fromhex(args.data_hex)
    except ValueError as error:
        raise CaptureDataError("write data must be hexadecimal") from error
    response = {"with-response": True, "without-response": False}[args.response]

    async def write_once() -> None:
        async with await ble.connect(address=args.address, timeout=args.timeout) as session:
            await session.write(
                data,
                service_uuid=args.service_uuid,
                characteristic_uuid=args.characteristic_uuid,
                response=response,
                timeout=args.timeout,
                frame_size=args.frame_size,
            )

    asyncio.run(write_once())
    _write_stdout(f"wrote {len(data)} bytes\n")
    return 0


def _ble_notify_command(args: argparse.Namespace) -> int:
    def write_notification(payload: bytes) -> None:
        _write_stdout(f"{payload.hex()}\n")

    async def receive_notifications() -> None:
        async with await ble.connect(address=args.address, timeout=args.timeout) as session:
            await session.notify(
                write_notification,
                service_uuid=args.service_uuid,
                characteristic_uuid=args.characteristic_uuid,
                timeout=args.timeout,
                frame_size=args.frame_size,
            )
            try:
                await asyncio.sleep(args.duration)
            finally:
                await session.stop_notify(
                    service_uuid=args.service_uuid,
                    characteristic_uuid=args.characteristic_uuid,
                    timeout=args.timeout,
                )

    asyncio.run(receive_notifications())
    return 0


def _add_kaitai_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target-path", type=Path, required=True)
    parser.add_argument("--ksy-root", type=Path, required=True)
    parser.add_argument("--root-schema", type=Path, required=True)
    parser.add_argument("--import-path", type=Path, action="append", default=[])
    parser.add_argument("--root-identity", required=True)
    parser.add_argument("--module-name", required=True)
    parser.add_argument("--root-type-name", required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--cache-directory", type=Path, required=True)
    parser.add_argument("--target-output-path", type=Path, required=True)


def _add_active_ble_arguments(parser: argparse.ArgumentParser, *, endpoint: bool) -> None:
    parser.add_argument("--address", required=True)
    parser.add_argument("--timeout", type=_positive_float, required=True)
    if endpoint:
        parser.add_argument("--service-uuid", required=True)
        parser.add_argument("--characteristic-uuid", required=True)
        parser.add_argument("--frame-size", type=_positive_int)


def _kaitai_request(args: argparse.Namespace) -> KaitaiCompilationRequest:
    target_path = args.target_path.resolve()
    ksy_root = args.ksy_root.resolve()
    if not ksy_root.is_relative_to(target_path):
        raise CaptureDataError("KSY root must be contained by target path")
    target_output_path = args.target_output_path.resolve()
    if not target_output_path.is_relative_to(target_path):
        raise CaptureDataError("target output path must be contained by target path")
    return KaitaiCompilationRequest(
        target_path=target_path,
        ksy_root=ksy_root,
        root_schema=args.root_schema,
        import_paths=tuple(args.import_path),
        output_language="python",
        root_identity=args.root_identity,
        module_name=args.module_name,
        root_type_name=args.root_type_name,
        compiler_executable=args.compiler,
        cache_directory=args.cache_directory,
        target_output_path=target_output_path,
    )


def _decode_bytes(data_hex: str | None, data_file: Path | None) -> bytes:
    if data_hex is not None:
        try:
            return bytes.fromhex(data_hex)
        except ValueError as error:
            raise CaptureDataError("decode data must be hexadecimal") from error
    if data_file is None:
        raise CaptureDataError("decode data is required")
    try:
        return data_file.read_bytes()
    except OSError as error:
        raise StorageError(f"cannot read decode data {data_file}: {error.strerror or error}") from error


def _require_safe_output(args: argparse.Namespace, command: str) -> None:
    if args.stdout or args.output is not None:
        return
    raise CaptureDataError(f"{command} requires --output or --stdout")


def _safe_output(args: argparse.Namespace, command: str) -> Path:
    output = args.output
    if not isinstance(output, Path):
        raise CaptureDataError(f"{command} requires --output")
    return output


def _source_record(source: Source) -> dict[str, object]:
    return {
        "connection_epochs": list(source.connection_epochs),
        "event_count": source.event_count,
        "identifier": source.identifier,
        "peer_address": source.peer_address,
    }


def _timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as error:
        raise CaptureDataError("timestamp must be ISO 8601") from error
    if timestamp.utcoffset() is None:
        raise CaptureDataError("timestamp must include a UTC offset")
    return timestamp


def _timezone(value: str | None) -> ZoneInfo | None:
    if value is None:
        return None
    try:
        return ZoneInfo(value)
    except ZoneInfoNotFoundError as error:
        raise CaptureDataError(f"unknown IANA timezone: {value}") from error


def _json_value(value: object) -> JsonValue:
    try:
        json.dumps(value)
    except (TypeError, ValueError) as error:
        raise CaptureDataError(f"JSON value is not structurally comparable: {error}") from error
    return cast("JsonValue", value)


def _positive_float(value: str) -> float:
    try:
        result = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive finite number") from error
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return result


def _non_negative_float(value: str) -> float:
    try:
        result = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a non-negative finite number") from error
    if not math.isfinite(result) or result < 0:
        raise argparse.ArgumentTypeError("must be a non-negative finite number")
    return result


def _positive_int(value: str) -> int:
    try:
        result = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if result <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return result


def _print_json(value: object) -> None:
    _write_stdout(f"{json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)}\n")


def _write_stdout(value: str) -> None:
    sys.stdout.write(value)


def _redact_secret(value: str, secret: str) -> str:
    return value.replace(secret, "<redacted-udid>")


@contextmanager
def _private_umask() -> Iterator[None]:
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


def _version() -> str:
    try:
        return importlib.metadata.version("ios-ble-capture")
    except importlib.metadata.PackageNotFoundError:
        return _SOURCE_VERSION


_EXPECTED_ERRORS = (
    CaptureError,
    StorageError,
    ble.BleError,
    CaptureConfigurationError,
    IosConfigurationError,
    KaitaiError,
    ProcessError,
    WdaError,
)
