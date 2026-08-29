# ios-ble-capture

Vendor-neutral tools for acquiring iPhone Bluetooth logs, attributing and segmenting BLE traffic, decoding target-owned [Kaitai Struct](https://kaitai.io/) schemas and comparing structured observations.

The project contains reusable capture and analysis mechanisms.  It does not contain vendor protocol schemas, vendor application recipes, product-specific integration logic, real captures, device identity or credentials.

## Capabilities

- `idevicebtlogger` classic pcap and `pymobiledevice3` pcapng acquisition;
- WebDriverAgent HTTP sessions, accessibility inspection, gestures and screenshots;
- pcap and pcapng import with HCI, ACL, L2CAP and ATT normalisation;
- connection-epoch and peer attribution with unsafe ambiguity refusal;
- timestamped action marks and vendor-neutral event segmentation;
- official Kaitai compiler orchestration for target-owned schemas;
- generic BLE scan, connect, read, write and notify operations through [Bleak](https://bleak.readthedocs.io/);
- declarative JSON recipes with controlled pre-run and guaranteed post-run hooks;
- private run directories, deterministic JSON output and explicit report redaction.

## Install

The package requires Python 3.12 or later.  [`uv tool install`](https://docs.astral.sh/uv/guides/tools/) can install the CLI with the optional live BLE and iPhone dependencies:

```bash
uv tool install 'ios-ble-capture[all]'
```

Install the official [Kaitai Struct Compiler](https://kaitai.io/#download) separately for schema compilation.

## Capture and import

Capture is a native-host operation.  Review the command without exposing the configured UDID:

```bash
ios-ble-capture capture \
  --udid "$PHONE_UDID" \
  --host wsl \
  --output "$HOME/.local/state/ios-ble-capture/capture" \
  --dry-run
```

Import safely selects one source and creates a private run directory:

```bash
ios-ble-capture import capture.pcap \
  --expected-peer 02:00:00:00:00:01 \
  --classic-pcap-timezone Australia/Brisbane
```

`idevicebtlogger` classic pcap can store local wall-clock values without timezone metadata, so its IANA timezone is explicit at import.  Omit the option for conventional pcap timestamps and pcapng.

Use `mark`, `attribute`, `segment` and `report` against the resulting run files.  Reports withhold raw payloads unless `--include-raw` is explicit, and withhold peer identifiers unless `--include-identifiers` is explicit.

## Decode and compare

Schemas stay in the target repository.  Decode requires an explicit schema, generated module and type, compiler and cache:

```bash
ios-ble-capture decode \
  --target-path "$PWD" \
  --ksy-root "$PWD/protocol" \
  --root-schema message.ksy \
  --module-name message \
  --root-type-name Message \
  --compiler kaitai-struct-compiler \
  --cache-directory "$HOME/.cache/ios-ble-capture/kaitai" \
  --data-file body.bin \
  --output decoded.json
```

`decode` and `diff` require a private output path unless `--stdout` explicitly accepts disclosure.

## Active BLE

Active operations require an explicit address.  Read, write and notify also require explicit service and characteristic UUIDs, while writes require an explicit response mode:

```bash
ios-ble-capture ble scan --timeout 10
ios-ble-capture ble read \
  --address 02:00:00:00:00:01 \
  --service-uuid 12345678-1234-5678-1234-56789abcdef0 \
  --characteristic-uuid 12345678-1234-5678-1234-56789abcdef1 \
  --timeout 10
```

No vendor UUID, frame length, name prefix or checksum is a framework default.

## Method

Use the [capture-to-schema methodology](docs/methodology.md) when deriving or revising a protocol.  [Host support](docs/host-support.md) describes capture constraints and external prerequisites.  The [recipe reference](docs/recipes.md) documents built-in automation.  Complete the [hardware validation checklist](docs/hardware-validation.md) before replacing an existing physical rig.

The [`pymobiledevice3` project](https://github.com/doronz88/pymobiledevice3) is authoritative for its iOS service and tunnel support.  Physical capture remains outside the development container.

## Privacy

Run directories are unredacted evidence and default outside the repository with mode `0700`; contained files use `0600`.  Raw payloads enter rendered output only through explicit opt-in.

Targets can supply a library-level redaction predicate that classifies payloads with a reason.  The framework ships no vendor secret heuristics.

Packet captures, signing material, provisioning profiles, device identifiers and local configuration are ignored.  Published fixtures must be synthetic or independently sanitised.

## Development

```bash
uv sync --locked --all-groups
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
uv run pytest -q
uv build
```

The development container supports implementation and deterministic tests.  It does not represent physical iPhone capture.
