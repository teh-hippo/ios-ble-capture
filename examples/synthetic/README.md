# Synthetic example

This target-owned example contains no captured device data.  It demonstrates the boundary between generic capture preparation and a target-owned Kaitai schema.

The example message is `10 03 32 33 34 45`: one command byte, one payload length, three payload bytes and one checksum byte.  `protocol.ksy` describes only that wire structure.  `recipe.json` selects built-in framework steps and contains no inline Python or shell.

Run `uv run python examples/synthetic/generate_capture.py` to create neutral classic pcap and pcapng inputs.  Both contain the same synthetic ATT write and must produce the same normalised event.

Use the example when validating import, attribution, Kaitai compilation, decode, JSON comparison and report rendering without a phone.
