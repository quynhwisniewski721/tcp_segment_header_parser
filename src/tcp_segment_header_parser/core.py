"""Decode raw TCP segment headers into a typed structure.

The TCP header is documented in RFC 9293 (formerly RFC 793). A minimal
header is 20 bytes; the Data Offset field (the high nibble of byte 12)
gives the total header length in 32-bit words, so the byte length is
``data_offset * 4``. We only parse the fixed 20-byte prefix; options
are validated for length but not decoded, which keeps the surface area
small and the dependency count at zero.
"""

import enum
import struct


class Flag(enum.IntFlag):
    """TCP control flags, exposed as an IntFlag for cheap bitwise tests.

    Using IntFlag (rather than a plain namedtuple of booleans) lets callers
    write ``if header.flags & Flag.ACK`` without us hand-rolling masking
    helpers, and it still pretty-prints as a union of names.
    """

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


class TCPHeader:
    """Parsed view of a TCP segment header.

    Attributes are plain ints (and one Flag) so the object is trivial to
    serialize or log. We deliberately do not store the raw bytes: the
    caller already has them, and holding a reference would keep a potentially
    large packet buffer alive.
    """

    __slots__ = (
        "source_port",
        "destination_port",
        "sequence_number",
        "acknowledgment_number",
        "data_offset",
        "flags",
        "window_size",
        "checksum",
        "urgent_pointer",
    )

    def __init__(
        self,
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer,
    ):
        self.source_port = source_port
        self.destination_port = destination_port
        self.sequence_number = sequence_number
        self.acknowledgment_number = acknowledgment_number
        self.data_offset = data_offset
        self.flags = flags
        self.window_size = window_size
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer

    def __repr__(self):
        return (
            "TCPHeader("
            f"source_port={self.source_port}, "
            f"destination_port={self.destination_port}, "
            f"sequence_number={self.sequence_number}, "
            f"acknowledgment_number={self.acknowledgment_number}, "
            f"data_offset={self.data_offset}, "
            f"flags={self.flags!r}, "
            f"window_size={self.window_size}, "
            f"checksum={self.checksum}, "
            f"urgent_pointer={self.urgent_pointer})"
        )

    def __eq__(self, other):
        if not isinstance(other, TCPHeader):
            return NotImplemented
        return (
            self.source_port == other.source_port
            and self.destination_port == other.destination_port
            and self.sequence_number == other.sequence_number
            and self.acknowledgment_number == other.acknowledgment_number
            and self.data_offset == other.data_offset
            and int(self.flags) == int(other.flags)
            and self.window_size == other.window_size
            and self.checksum == other.checksum
            and self.urgent_pointer == other.urgent_pointer
        )

    def __hash__(self):
        return hash(
            (
                self.source_port,
                self.destination_port,
                self.sequence_number,
                self.acknowledgment_number,
                self.data_offset,
                int(self.flags),
                self.window_size,
                self.checksum,
                self.urgent_pointer,
            )
        )


def parse_header(data):
    """Parse a TCP segment header from ``data`` (a bytes-like object).

    ``data`` may be the full segment or a slice that starts at the TCP
    header; we never look past ``data_offset * 4`` bytes. We accept any
    object supporting the buffer protocol (bytes, bytearray, memoryview)
    because packet captures routinely hand us each of those.

    Returns a :class:`TCPHeader`. Raises ValueError if there are fewer than
    20 bytes, if the Data Offset field indicates fewer than 5 words (the
    minimum legal value), or if the declared header length exceeds the
    supplied buffer.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes, bytearray, or memoryview")

    if len(data) < 20:
        raise ValueError(
            f"need at least 20 bytes for the fixed TCP header, got {len(data)}"
        )

    # The fixed 20-byte prefix is two big-endian unsigned shorts, two
    # unsigned ints, then a byte holding the data offset and reserved
    # bits, a flag byte, and three more shorts. struct's '>HHIIBBHHH'
    # reads exactly 20 bytes.
    src, dst, seq, ack, off_res, flg, win, csum, urg = struct.unpack_from(
        ">HHIIBBHHH", data, 0
    )

    data_offset = (off_res >> 4) & 0x0F

    # Per RFC 9293 the Data Offset must be at least 5 (20 bytes). A smaller
    # value is malformed; a larger value means options are present and we
    # must have enough bytes to cover them.
    if data_offset < 5:
        raise ValueError(f"data_offset must be >= 5 words, got {data_offset}")

    declared = data_offset * 4
    if declared > len(data):
        raise ValueError(
            f"declared header length {declared} exceeds buffer length {len(data)}"
        )

    flags = Flag(flg)

    return TCPHeader(
        source_port=src,
        destination_port=dst,
        sequence_number=seq,
        acknowledgment_number=ack,
        data_offset=data_offset,
        flags=flags,
        window_size=win,
        checksum=csum,
        urgent_pointer=urg,
    )
