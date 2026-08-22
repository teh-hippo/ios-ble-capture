# Host support

Physical iPhone capture runs on the native host.  The development container supports package development and deterministic tests only.

Install [Apple's Bluetooth Logging profile](https://secure-appldnld.apple.com/iOSProfiles/BluetoothLogging.mobileconfig) on the phone before expecting HCI frames, then restart Bluetooth after profile changes.

| Capability | Native Linux | WSL with Windows host |
| --- | --- | --- |
| `idevicebtlogger` capture | Supported | Supported after USB/IP ownership transfers to WSL |
| `pymobiledevice3` pcapng capture | Supported | Supported when usbmuxd is reachable from the selected ownership mode |
| Userspace RSD | Supported | Supported |
| WebDriverAgent forwarding and gestures | Supported | Supported through native or Windows assistance |
| DDI inspection and mounting | Supported | Supported |
| Direct host BLE | Supported with an attached controller | Supported with an attached Linux controller or an explicit Windows helper |

The [`pymobiledevice3` documentation](https://doronz88.github.io/pymobiledevice3/) is authoritative for supported iOS services and tunnel requirements.  [`usbipd-win`](https://github.com/dorssel/usbipd-win) documents attaching Windows USB devices to WSL.

## Required external tools

- `pymobiledevice3` for usbmuxd, CoreDevice, DDI, DVT and pcapng operations;
- `idevicebtlogger` for classic iPhone Bluetooth logging where available;
- WebDriverAgent built and signed for the target device;
- `zsign` when using the migrated signing workflow;
- `usbipd.exe` for WSL USB ownership transfer.

Tool paths, phone identity, signing identity and application identity are local configuration.  They are never repository defaults.
