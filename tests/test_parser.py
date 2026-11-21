"""Literal wire vectors, independent arithmetic and bounded corruption tests."""

import random
import struct
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pcaplab.core import (
    ParseError,
    checksum,
    decode_packet,
    dns_name,
    parse_capture,
    parse_dns,
)
from scripts.fixtures import (
    dns_message,
    packet,
    pcap,
    response_packet,
    synthetic_fixtures,
)

# Explicit Ethernet + IPv4(total length28, id0x1234, UDP, checksum0x7c66)
# + UDP(1234 -> 9, length8, omitted IPv4 UDP checksum). No generator call.
HAND_PACKET = bytes.fromhex(
    "00112233445566778899aabb0800 4500001c1234000040117c66c0000201c6336402 04d2000900080000"
)
HAND_CAPTURE = (
    bytes.fromhex(
        "d4c3b2a1 0200 0400 00000000 00000000 ffff0000 01000000 01000000 02000000 2a000000 2a000000"
    )
    + HAND_PACKET
)


def independent_sum(data):
    total = 0
    for index in range(0, len(data), 2):
        pair = data[index : index + 2]
        total += int.from_bytes(pair.ljust(2, b"\0"), "big")
        total = (total & 65535) + (total >> 16)
    return 65535 - total


class ParserTests(unittest.TestCase):
    def test_literal_pcap_and_ipv4_udp_vector(self):
        capture = parse_capture(HAND_CAPTURE)
        self.assertTrue(capture.scan_complete)
        self.assertFalse(capture.issues)
        record = capture.records[0]
        self.assertEqual((record.record_offset, record.data_offset), (24, 40))
        self.assertEqual(record.timestamp_ns, 1_000_002_000)
        self.assertEqual(record.status, "udp")
        self.assertEqual(record.layers["ipv4"]["source"], "192.0.2.1")
        self.assertEqual(record.layers["udp"]["checksum"], "not_present_ipv4")
        self.assertEqual(independent_sum(HAND_PACKET[14:34]), 0)

    def test_all_endian_and_timestamp_precision_variants(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                capture = parse_capture(
                    pcap([(123_456_789, HAND_PACKET, None)], endian, nano)
                )
                expected = 1_700_000_000_000_000_000 + (
                    123_456_789 if nano else 123_456_000
                )
                self.assertEqual(capture.records[0].timestamp_ns, expected)
                self.assertEqual(
                    capture.metadata["endianness"], "little" if endian == "<" else "big"
                )
        broken = bytearray(HAND_CAPTURE)
        broken[28:32] = struct.pack("<I", 1_000_000)
        parsed = parse_capture(bytes(broken))
        self.assertIsNone(parsed.records[0].timestamp_ns)
        self.assertEqual(parsed.issues[0].byte_offset, 28)

    def test_internet_checksum_odd_even_and_encoded_zero(self):
        rng = random.Random(1071)
        for length in range(100):
            data = rng.randbytes(length)
            self.assertEqual(checksum(data), independent_sum(data))
        # Solve the final two payload bytes so the calculated UDP checksum is
        # zero, whose on-wire representation must be 0xffff rather than absent.
        first = packet(b"\0\0", destination_port=9, udp_checksum=False)
        ip, udp = first[14:34], first[34:]
        pseudo = ip[12:20] + b"\0\x11\0\x0a"
        patch = independent_sum(pseudo + udp).to_bytes(2, "big")
        fixed = packet(patch, destination_port=9)
        self.assertEqual(fixed[40:42], b"\xff\xff")
        layers, error = decode_packet(fixed)
        self.assertIsNone(error)
        self.assertEqual(layers["udp"]["checksum"], "valid")
        odd = packet(b"12345", destination_port=9)
        self.assertIsNone(decode_packet(odd)[1])
        damaged = bytearray(odd)
        damaged[-1] ^= 1
        self.assertEqual(decode_packet(bytes(damaged))[1].code, "udp_checksum")

    def test_ipv4_padding_udp_declared_length_and_fragment_policy(self):
        wire = packet(
            b"abc",
            destination_port=9,
            ip_trailing=b"extra",
            ethernet_padding=b"padding",
        )
        layers, error = decode_packet(wire)
        self.assertIsNone(error)
        self.assertEqual(layers["udp"]["payload_length"], 3)
        self.assertEqual(layers["udp"]["ip_trailing_bytes"], 5)
        self.assertEqual(layers["ipv4"]["ethernet_padding_bytes"], 7)
        for fragment in (1, 0x2000, 0x2001):
            self.assertEqual(
                decode_packet(packet(b"", fragment=fragment))[1].code, "ipv4_fragment"
            )
        self.assertEqual(
            decode_packet(packet(b"", fragment=0x8000))[1].code, "ipv4_reserved_flag"
        )

    def test_dns_compression_case_and_binary_label_boundaries(self):
        # Independent DNS response for a.test, compressed answer owner at0x0c.
        response = bytes.fromhex(
            "123481800001000100000000 016104746573740000010001 c00c000100010000003c0004cb007109"
        )
        parsed = parse_dns(response, base=100)
        self.assertEqual(parsed["name"], "a.test.")
        self.assertEqual(parsed["a_records"][0]["address"], "203.0.113.9")
        self.assertEqual(parsed["question_offset"], 112)
        upper = parse_dns(dns_message("EXAMPLE.TEST"))
        lower = parse_dns(dns_message("example.test"))
        self.assertEqual(upper["name_key"], lower["name_key"])
        dotted = b"\0" * 12 + b"\x03a.b\0"
        split = b"\0" * 12 + b"\x01a\x01b\0"
        self.assertNotEqual(dns_name(dotted, 12)[1], dns_name(split, 12)[1])
        self.assertEqual(dns_name(dotted, 12)[0], "a\\046b.")

    def test_dns_name_and_record_corruptions_are_bounded(self):
        cases = [
            (b"\0" * 12 + b"\xc0\x0c", "dns_pointer_loop"),
            (b"\0" * 12 + b"\xff\xff", "dns_pointer_bounds"),
            (b"\0" * 12 + b"\xc0\x0e\0", "dns_forward_pointer"),
            (b"\0" * 12 + b"\x40", "dns_label_type"),
            (b"\0" * 12 + b"\x03a", "dns_label_bounds"),
            (b"\0" * 12 + (b"\x3f" + b"a" * 63) * 4 + b"\0", "dns_name_length"),
        ]
        for data, reason in cases:
            with self.assertRaises(ParseError) as error:
                dns_name(data, 12)
            self.assertEqual(error.exception.code, reason)
        for cut in range(len(dns_message(response=True))):
            with self.assertRaises(ParseError):
                parse_dns(dns_message(response=True)[:cut])
        with self.assertRaises(ParseError) as error:
            parse_dns(dns_message() + b"x")
        self.assertEqual(error.exception.code, "dns_trailing_bytes")

    def test_envelope_bounds_quarantine_offsets_and_stop_policy(self):
        for cut in range(24):
            with self.assertRaises(ParseError):
                parse_capture(HAND_CAPTURE[:cut])
        for cut in range(25, 40):
            capture = parse_capture(HAND_CAPTURE[:cut])
            self.assertFalse(capture.scan_complete)
            self.assertEqual(capture.issues[0].byte_offset, 24)
        short = parse_capture(HAND_CAPTURE[:-1])
        self.assertEqual(short.records[0].available_length, 41)
        self.assertEqual(short.issues[0].byte_offset, len(HAND_CAPTURE) - 1)
        self.assertFalse(short.scan_complete)
        bad = bytearray(HAND_CAPTURE)
        bad[36:40] = struct.pack("<I", 41)
        self.assertEqual(parse_capture(bytes(bad)).issues[0].code, "record_lengths")
        snap = bytearray(HAND_CAPTURE)
        snap[16:20] = struct.pack("<I", 20)
        self.assertEqual(parse_capture(bytes(snap)).issues[0].code, "record_lengths")
        with self.assertRaises(ParseError):
            parse_capture(b"x" * (4 * 1024 * 1024 + 1))
        limited = parse_capture(HAND_CAPTURE[:24] + bytes(16) * 4097)
        self.assertEqual(len(limited.records), 4096)
        self.assertEqual(limited.issues[-1].code, "record_limit")
        self.assertFalse(limited.scan_complete)

    def test_seeded_mutations_never_escape_structured_parse_failures(self):
        rng = random.Random(20261121)
        valid = synthetic_fixtures()["dns-observations.pcap"]
        for _ in range(500):
            mutated = bytearray(valid)
            for _ in range(rng.randint(1, 6)):
                mutated[rng.randrange(len(mutated))] = rng.randrange(256)
            try:
                capture = parse_capture(bytes(mutated))
                self.assertLessEqual(len(capture.records), 4096)
                self.assertTrue(
                    all(0 <= i.byte_offset <= len(mutated) for i in capture.issues)
                )
            except ParseError:
                pass


if __name__ == "__main__":
    unittest.main()
