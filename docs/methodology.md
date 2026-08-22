# Capture-to-schema methodology

This method separates evidence acquisition from protocol ownership.  The capture repository extracts attributed byte bodies; the target repository owns its schemas, findings, fixtures and product-specific interpretation.

## 1. Define one observable question

Choose one action whose effect can be recognised independently, such as changing a single setting from one known value to another.  Record the starting state, the exact action and the expected device-side result before capturing.

Avoid sessions that combine unrelated actions.  A short session gives action marks, connection events and packet changes one plausible interpretation.

## 2. Isolate the intended peer

Record the expected Bluetooth address or another explicit selector before capture.  Start capture before reconnecting the target so the connection event is present.

Do not infer identity from packet shape.  An absent peer, unattributed traffic and traffic from multiple peers are different outcomes and must remain distinct.

## 3. Capture and mark actions

Use an iPhone logger supported by the host adapter, then record a timestamped mark immediately before each controlled action.  [`pymobiledevice3`](https://github.com/doronz88/pymobiledevice3) exposes iOS device discovery, packet capture and developer services on Linux and Windows.

Keep the raw pcap or pcapng private.  A capture can contain device identifiers, application traffic and payload secrets unrelated to the protocol under study.

## 4. Import and attribute

Import the capture into normalised ATT events.  Attribution follows connection epochs rather than connection handles alone because a controller can reuse a handle after disconnect.

Require the expected peer when evidence will support a protocol claim.  Refuse an ambiguous multi-peer result rather than selecting whichever traffic looks familiar.

## 5. Segment candidate transactions

Use action marks, ATT direction, attribute handle and explicit byte-boundary rules to select candidate bodies.  Segmentation prepares bytes for a target schema; it must not silently add vendor framing rules to the capture framework.

Retain both the selected bytes and the normalised events that produced them.  This keeps the interpretation auditable when a schema changes.

## 6. Author the schema in the target repository

Create or revise the target-owned `.ksy` file beside its protocol tests.  The [Kaitai Struct user guide](https://doc.kaitai.io/user_guide.html) documents declarative types, substreams, validation and generated parser behaviour.

Express wire structure in Kaitai.  Keep semantic transforms, checksums and transport orchestration in target code only when the schema cannot express them clearly.

Compile with the official Kaitai Struct Compiler.  Record the compiler version, runtime version, schema hashes, import paths and selected root with the run so another contributor can reproduce the decode.

## 7. Compare controlled observations

Decode at least two observations that differ in one controlled input.  Compare raw bodies and decoded JSON together.

A field name is a hypothesis until repeated captures support it.  Preserve unknown values without naming them after an assumed meaning.

## 8. Retain findings, not private sessions

Keep sanitised byte fixtures, schemas, direct protocol tests and concise findings in the target repository.  Do not publish raw captures, signing material, phone identifiers or application accessibility trees.

Document fixture provenance without including private identity.  State which controlled action produced the bytes and which independent observation confirmed the result.

## 9. Revisit safely

When adding another model or firmware family, repeat the method from peer isolation onward.  Do not reuse a model-specific segmentation rule merely because packet lengths or leading bytes look similar.

The target repository should continue to build and test without this tool.  This project is contributor methodology and evidence tooling, not a runtime dependency.
