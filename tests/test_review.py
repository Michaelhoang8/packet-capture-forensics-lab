"""Independent literal envelope and DNS wire-length boundary checks."""
import struct
import unittest

from pcaplab.core import ParseError, dns_name, parse_capture


class ReviewTests(unittest.TestCase):
    def test_maximum_second_and_fraction_are_exact_for_all_magic_variants(self):
        packet = bytes.fromhex(
            '00112233445566778899aabb0800'
            '4500001c1234000040117c66c0000201c6336402'
            '04d2000900080000'
        )
        variants = [
            (bytes.fromhex('d4c3b2a1'), '<', 1_000_000),
            (bytes.fromhex('a1b2c3d4'), '>', 1_000_000),
            (bytes.fromhex('4d3cb2a1'), '<', 1_000_000_000),
            (bytes.fromhex('a1b23c4d'), '>', 1_000_000_000),
        ]
        for magic, endian, resolution in variants:
            header = magic + struct.pack(endian + 'HHiIII', 2, 4, 0, 0, 65535, 1)
            record = struct.pack(endian + '4I', 0xffffffff, resolution - 1, len(packet), len(packet))
            parsed = parse_capture(header + record + packet)
            self.assertTrue(parsed.scan_complete)
            self.assertFalse(parsed.issues)
            self.assertEqual(parsed.records[0].timestamp_ns,
                             4_294_967_296_000_000_000 - 1_000_000_000 // resolution)
            self.assertIs(type(parsed.records[0].timestamp_ns), int)

    def test_expanded_dns_name_limit_is_inclusive_with_compression(self):
        labels = [b'A' * 63, b'B' * 63, b'C' * 63, b'D' * 61]
        wire = b''.join(bytes([len(label)]) + label for label in labels) + b'\0'
        self.assertEqual(len(wire), 255)
        message = bytes(12) + wire + bytes.fromhex('c00c')
        direct = dns_name(message, 12, base=100)
        compressed = dns_name(message, 267, base=100)
        self.assertEqual(direct[:2], compressed[:2])
        self.assertEqual(direct[2], 267)
        self.assertEqual(compressed[2], 269)
        self.assertEqual(bytes.fromhex(direct[1]), wire.lower())
        oversized = bytes(12) + wire[:-63] + bytes([62]) + b'D' * 62 + b'\0'
        with self.assertRaises(ParseError) as error:
            dns_name(oversized, 12, base=100)
        self.assertEqual(error.exception.code, 'dns_name_length')


if __name__ == '__main__':
    unittest.main()
