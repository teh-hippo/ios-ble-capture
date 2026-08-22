meta:
  id: synthetic_message
  endian: le
seq:
  - id: command
    type: u1
  - id: payload_length
    type: u1
  - id: payload
    size: payload_length
  - id: checksum
    type: u1
