# Hardware validation checklist

Run this checklist before removing an existing capture rig.  Record the tool versions, host, iOS version and result outside the repository if they contain device identity.

## Native Linux

- Confirm the explicit UDID resolves through usbmuxd.
- Confirm the selected DDI state is recognised without an unnecessary upload.
- Start the `pymobiledevice3` pcapng backend and verify HCI frames arrive before driving the application.
- Start WebDriverAgent, open the target-supplied bundle ID and reuse the session on a second command.
- Confirm named actuation refuses an ambiguous element and a non-displayed element.
- Stop the run and confirm every owned process exits.

## WSL

- Transfer the explicit iPhone hardware ID from Windows to WSL through `usbipd.exe`.
- Confirm native usbmuxd sees the explicit UDID.
- Confirm the backend selects `idevicebtlogger` and writes classic pcap.
- Start a userspace RSD session, forward WebDriverAgent and complete one screenshot plus one safe named tap.
- Interrupt the run and confirm the phone is detached from WSL and visible to Windows again.

## Windows assistance

- Confirm the configured Windows Python can run `pymobiledevice3`.
- Exercise start, status and stop command construction for tunneld, port forwarding and WebDriverAgent.
- Exercise DDI handoff in both directions.
- Confirm direct BLE operations receive explicit address, service UUID, characteristic UUID and response mode.

## Ownership failure path

- Complete all phone and DDI preflight before the target's BLE owner is asked to release it.
- Run a pre-run ownership hook that performs the handoff and then exits unsuccessfully.
- Confirm the guaranteed post-run hook executes exactly once.
- Confirm the target's normal owner reports the device loaded and available again.
- Repeat restoration to prove it is idempotent.

Do not remove the previous rig until the applicable host sections and the ownership failure path pass on real hardware.
