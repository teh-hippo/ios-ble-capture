# Host support

Physical iPhone capture runs on the native host.  The development container supports package development and deterministic tests only.

Install [Apple's Bluetooth Logging profile](https://secure-appldnld.apple.com/iOSProfiles/BluetoothLogging.mobileconfig) on the phone before expecting HCI frames, then restart Bluetooth after profile changes.

| Capability | Native Linux | WSL with Windows host |
| --- | --- | --- |
| `idevicebtlogger` capture | Supported | Supported after USB/IP ownership transfers to WSL |
| `pymobiledevice3` pcapng capture | Supported | Supported when usbmuxd is reachable from the selected ownership mode |
| WebDriverAgent gestures | Supported with an externally launched and forwarded WDA service | Supported with an externally launched and forwarded WDA service |
| Direct host BLE | Supported with an attached controller | Supported with an attached Linux controller or an explicit Windows helper |

The [`pymobiledevice3` documentation](https://doronz88.github.io/pymobiledevice3/) is authoritative for supported iOS services and tunnel requirements.  [`usbipd-win`](https://github.com/dorssel/usbipd-win) documents attaching Windows USB devices to WSL.

Host-specific ownership transfer, WDA startup and recovery belong in recipe `preflight`, `pre_run` and `post_run` hooks.  The package executes those commands as explicit argument arrays and guarantees the post-run hook after an attempted run.

## Required external tools

- `pymobiledevice3` for usbmuxd, developer services and pcapng operations;
- `idevicebtlogger` for classic iPhone Bluetooth logging where available;
- WebDriverAgent built, signed, launched and forwarded for the target device;
- `usbipd.exe` when an external WSL ownership hook transfers the phone.

Tool paths, phone identity, signing identity and application identity are local configuration.  They are never repository defaults.
