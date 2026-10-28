"""Tests for the TCP segment header parser.

We build raw byte buffers by hand so the tests are fully deterministic
and depend on nothing but the standard library.
"""

import struct
import unittest

from tcp_segment_header_parser import Flag, TCPHeader, parse_header


def _build_segment(
    *, src_port=443, dst_port=5000, seq=1, ack=0, data_offset=5,
    flags=Flag.SYN, window=64240, checksum=0xABCD, urgent=0,
    options=b"", payload=b"",
):
    """Assemble a raw TCP segment with the given fixed-header fields.

    Options and payload are appended verbatim so callers can exercise
    buffers that are larger than the declared header, exactly as a real
    capture would.
    """
    off_res = ((data_offset & 0x0F) << 4) | 0
    fixed = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, seq, ack, off_res, int(flags),
        window, checksum, urgent,
    )
    return fixed + options + payload


class ParseHeaderTests(unittest.TestCase):
    def test_parses_minimal_syn(self):
        seg = _build_segment()
        h = parse_header(seg)
        self.assertEqual(h.source_port, 443)
        self.assertEqual(h.destination_port, 5000)
        self.assertEqual(h.sequence_number, 1)
        self.assertEqual(h.acknowledgment_number, 0)
        self.assertEqual(h.data_offset, 5)
        self.assertEqual(h.window_size, 64240)
        self.assertEqual(h.checksum, 0xABCD)
        self.assertEqual(h.urgent_pointer, 0)
        self.assertEqual(h.flags, Flag.SYN)

    def test_returns_tcp_header_instance(self):
        h = parse_header(_build_segment())
        self.assertIsInstance(h, TCPHeader)

    def test_flag_combination(self):
        seg = _build_segment(flags=Flag.SYN | Flag.ACK)
        h = parse_header(seg)
        self.assertEqual(h.flags, Flag.SYN | Flag.ACK)
        self.assertTrue(bool(h.flags & Flag.ACK))
        self.assertFalse(bool(h.flags & Flag.FIN))

    def test_all_flag_bits_set(self):
        seg = _build_segment(flags=Flag.FIN | Flag.SYN | Flag.RST | Flag.PSH
                             | Flag.ACK | Flag.URG | Flag.ECE | Flag.CWR)
        h = parse_header(seg)
        self.assertEqual(int(h.flags), 0xFF)

    def test_accepts_bytearray(self):
        seg = bytearray(_build_segment())
        h = parse_header(seg)
        self.assertEqual(h.source_port, 443)

    def test_accepts_memoryview(self):
        seg = memoryview(_build_segment())
        h = parse_header(seg)
        self.assertEqual(h.destination_port, 5000)

    def test_short_buffer_raises(self):
        with self.assertRaises(ValueError):
            parse_header(b"\x00" * 19)

    def test_empty_buffer_raises(self):
        with self.assertRaises(ValueError):
            parse_header(b"")

    def test_data_offset_below_minimum_raises(self):
        # Data offset of 4 words (16 bytes) is illegal; force byte 12 to 0x40.
        seg = bytearray(_build_segment(data_offset=5))
        seg[12] = 0x40
        with self.assertRaises(ValueError):
            parse_header(bytes(seg))

    def test_declared_header_longer_than_buffer_raises(self):
        # Declare 8 words (32 bytes) but provide only 20.
        seg = _build_segment(data_offset=8)
        # Truncate back to 20 bytes so the declared length exceeds it.
        with self.assertRaises(ValueError):
            parse_header(seg[:20])

    def test_options_present_are_not_parsed_but_length_is_validated(self):
        # 8-word header with 12 bytes of option padding; total 32 bytes.
        seg = _build_segment(data_offset=8, options=b"\x00" * 12)
        h = parse_header(seg)
        self.assertEqual(h.data_offset, 8)

    def test_max_port_values(self):
        seg = _build_segment(src_port=65535, dst_port=0)
        h = parse_header(seg)
        self.assertEqual(h.source_port, 65535)
        self.assertEqual(h.destination_port, 0)

    def test_max_sequence_and_ack_numbers(self):
        seg = _build_segment(seq=0xFFFFFFFF, ack=0xFFFFFFFF)
        h = parse_header(seg)
        self.assertEqual(h.sequence_number, 0xFFFFFFFF)
        self.assertEqual(h.acknowledgment_number, 0xFFFFFFFF)

    def test_payload_after_header_is_ignored(self):
        seg = _build_segment(payload=b"hello, world")
        h = parse_header(seg)
        self.assertEqual(h.data_offset, 5)
        self.assertEqual(h.source_port, 443)

    def test_non_bytes_raises_type_error(self):
        with self.assertRaises(TypeError):
            parse_header("not bytes")

    def test_repr_contains_key_fields(self):
        h = parse_header(_build_segment())
        text = repr(h)
        self.assertIn("source_port=443", text)
        self.assertIn("destination_port=5000", text)
        self.assertIn("data_offset=5", text)

    def test_equality(self):
        a = parse_header(_build_segment())
        b = parse_header(_build_segment())
        self.assertEqual(a, b)
        self.assertFalse(a != b)

    def test_inequality_when_flags_differ(self):
        a = parse_header(_build_segment(flags=Flag.SYN))
        b = parse_header(_build_segment(flags=Flag.SYN | Flag.ACK))
        self.assertNotEqual(a, b)

    def test_reserved_low_nibble_of_byte_12_ignored(self):
        # Reserved bits should not affect data_offset.
        seg = bytearray(_build_segment(data_offset=5))
        seg[12] = 0x5F  # data_offset=5, reserved bits set
        h = parse_header(bytes(seg))
        self.assertEqual(h.data_offset, 5)

    def test_window_zero(self):
        seg = _build_segment(window=0)
        h = parse_header(seg)
        self.assertEqual(h.window_size, 0)


if __name__ == "__main__":
    unittest.main()
