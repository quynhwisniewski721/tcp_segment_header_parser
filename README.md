# tcp_segment_header_parser

Decodes the fixed 20-byte prefix of a TCP segment header into a typed object exposing source and destination ports, sequence and acknowledgment numbers, data offset, flags, window size, checksum, and urgent pointer.

```python
from tcp_segment_header_parser import parse_header, TCPHeader, Flag

# `seg` is the raw bytes of a TCP segment, e.g. from a pcap record.
import struct
off_res = (5 << 4)  # data_offset=5 words (20 bytes), no options
seg = struct.pack(">HHIIBBHHH", 443, 5000, 1, 0, off_res, int(Flag.SYN), 64240, 0xABCD, 0)
header = parse_header(seg)
print(header.source_port, header.destination_port)
print(header.sequence_number, header.acknowledgment_number)
print(header.flags)              # an IntFlag, e.g. Flag.SYN|Flag.ACK
print(header.data_offset)       # in 32-bit words; multiply by 4 for bytes
print(header.window_size)

if header.flags & Flag.ACK:
    ...
```

## Why this exists

Reading a TCP header by hand is a `struct.unpack` one-liner, but doing it over and over in packet-analysis scripts invites off-by-one mistakes (the data-offset nibble, the reserved bits, the minimum 5-word floor). This library centralizes that logic with validation so callers get a typed result and clear errors for malformed input.

The trade-off: we parse only the fixed 20-byte prefix. TCP options (Timestamps, SACK, Window Scale, MSS) are validated for length but not decoded. If you need option values, read `header.data_offset * 4` bytes of options from the buffer yourself. Keeping the surface small means no third-party dependencies and a tiny, auditable core.

## Edge you will hit

`parse_header` accepts `bytes`, `bytearray`, or `memoryview`, but the input must start at the TCP header. If you have an IP-layer packet, strip the IP header first. A `ValueError` is raised if fewer than 20 bytes are supplied, if the Data Offset field is below the legal minimum of 5 words, or if the declared header length exceeds the buffer. A `TypeError` is raised for non-buffer inputs such as `str`.

## Run the tests

```
PYTHONPATH=src python -m unittest discover -s tests
```

## Exports

- `parse_header(data)` — returns a `TCPHeader`.
- `TCPHeader` — the result type with `source_port`, `destination_port`, `sequence_number`, `acknowledgment_number`, `data_offset`, `flags`, `window_size`, `checksum`, and `urgent_pointer` attributes.
- `Flag` — an `enum.IntFlag` with members `FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, `ECE`, `CWR`.
