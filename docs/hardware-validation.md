# Hardware validation checklist

Run this checklist before removing an existing capture rig.  Record the tool versions, host, iOS version and result outside the repository if they contain device identity.

## Native Linux

- Confirm the explicit UDID resolves through usbmuxd.
- Start the `pymobiledevice3` pcapng backend and verify HCI frames arrive before driving the application.
- Start and forward WebDriverAgent externally, then open the target-supplied bundle ID.
- Confirm named actuation refuses an ambiguous element and a non-displayed element.
- Stop the run and confirm every owned process exits.

## WSL

- Transfer the explicit iPhone hardware ID from Windows to WSL through a recipe ownership hook.
- Confirm native usbmuxd sees the explicit UDID.
- Confirm the backend selects `idevicebtlogger` and writes classic pcap.
- Start and forward WebDriverAgent externally, then complete one screenshot plus one safe named tap.
- Interrupt the recipe and confirm its post-run hook returns the phone to Windows.

## External host assistance

- Confirm each configured ownership and WDA command works before placing it in a recipe hook.
- Exercise acquisition, failure recovery and restoration independently.
- Confirm direct BLE operations receive explicit address, service UUID, characteristic UUID and response mode.

## Ownership failure path

- Complete all phone preflight before the target's BLE owner is asked to release it.
- Run a pre-run ownership hook that performs the handoff and then exits unsuccessfully.
- Confirm the guaranteed post-run hook executes exactly once.
- Confirm the target's normal owner reports the device loaded and available again.
- Repeat restoration to prove it is idempotent.

Do not remove the previous rig until the applicable host sections and the ownership failure path pass on real hardware.
