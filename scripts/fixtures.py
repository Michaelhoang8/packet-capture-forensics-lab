"""Construct owned packet bytes; never open a socket or capture traffic."""

import ipaddress
import random
import struct

EPOCH_SECONDS = 1_700_000_000  # Synthetic timeline origin, not a claimed capture date.


def wire_checksum(data):
    """Generator implementation separate from the parser's byte-wise sum."""
    padded = data + bytes(len(data) % 2)
    words = struct.unpack("!" + "H" * (len(padded) // 2), padded)
    value = sum(words)
    while value > 65535:
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


def dns_message(name="example.test", ident=100, response=False, address="203.0.113.10"):
    question = (
        b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
        )
        + b"\0\0\1\0\1"
    )
    header = struct.pack(
        "!6H", ident, 0x8180 if response else 0x0100, 1, int(response), 0, 0
    )
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + ipaddress.IPv4Address(address).packed
        if response
        else b""
    )
    return header + question + answer


def packet(
    payload,
    source="192.0.2.10",
    destination="198.51.100.53",
    source_port=53000,
    destination_port=53,
    udp_checksum=True,
    fragment=0,
    protocol=17,
    ip_trailing=b"",
    ethernet_padding=b"",
):
    src, dst = (
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    )
    length = 8 + len(payload)
    udp = struct.pack("!4H", source_port, destination_port, length, 0) + payload
    if udp_checksum:
        value = wire_checksum(src + dst + b"\0\x11" + struct.pack("!H", length) + udp)
        udp = udp[:6] + struct.pack("!H", value or 65535) + udp[8:]
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp) + len(ip_trailing),
        0x1234,
        fragment,
        64,
        protocol,
        0,
        src,
        dst,
    )
    ip = ip[:10] + struct.pack("!H", wire_checksum(ip)) + ip[12:]
    return (
        bytes.fromhex("00112233445566778899aabb0800")
        + ip
        + udp
        + ip_trailing
        + ethernet_padding
    )


def response_packet(name="example.test", ident=100, client="192.0.2.10", port=53000):
    return packet(
        dns_message(name, ident, True),
        source="198.51.100.53",
        destination=client,
        source_port=53,
        destination_port=port,
    )


def pcap(records, endian="<", nanos=False, snaplen=65535):
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    output = bytearray(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, 1))
    resolution = 1_000_000_000 if nanos else 1_000_000
    for time_ns, data, original in records:
        seconds, fraction_ns = divmod(time_ns, 1_000_000_000)
        fraction = fraction_ns if nanos else fraction_ns // 1000
        output += struct.pack(
            endian + "4I",
            EPOCH_SECONDS + seconds,
            fraction,
            len(data),
            len(data) if original is None else original,
        )
        output += data
    return bytes(output)


def synthetic_fixtures():
    traffic = [
        (0, packet(dns_message()), None),
        (35_000_000, response_packet(), None),
        (100_000_000, packet(dns_message("unanswered.test", 101)), None),
        (180_000_000, response_packet("orphan.test", 999), None),
    ]
    for index in range(12):
        time = 300_000_000 + index * 20_000_000
        traffic.extend(
            [
                (
                    time,
                    packet(
                        dns_message("repeated.test", 200 + index),
                        source="192.0.2.20",
                        source_port=54000 + index,
                    ),
                    None,
                ),
                (
                    time + 10_000_000,
                    response_packet(
                        "repeated.test", 200 + index, "192.0.2.20", 54000 + index
                    ),
                    None,
                ),
            ]
        )
    traffic.extend(
        [
            (800_000_000, packet(dns_message("duplicate.test", 300)), None),
            (820_000_000, packet(dns_message("duplicate.test", 300)), None),
            (850_000_000, response_packet("duplicate.test", 300), None),
            (3_400_000_000, packet(dns_message("end.test", 400)), None),
            (
                3_500_000_000,
                packet(random.Random(20261121).randbytes(17), destination_port=9000),
                None,
            ),
        ]
    )
    traffic.sort(key=lambda row: row[0])
    valid = packet(dns_message())
    bad_ip = bytearray(valid)
    bad_ip[24] ^= 1
    bad_udp = bytearray(valid)
    bad_udp[40] ^= 1
    loop_dns = struct.pack("!6H", 100, 0x0100, 1, 0, 0, 0) + bytes.fromhex(
        "c00c00010001"
    )
    bad_udp_length = bytearray(valid)
    bad_udp_length[38:40] = b"\0\x07"
    wrong_ip_length = bytearray(valid)
    wrong_ip_length[16:18] = b"\xff\xff"
    invalid_ihl = bytearray(valid)
    invalid_ihl[14] = 0x44
    malformed = [
        (0, valid, None),
        (10_000_000, bytes(bad_ip), None),
        (20_000_000, bytes(bad_udp), None),
        (30_000_000, packet(loop_dns), None),
        (40_000_000, valid[:-7], len(valid)),
        (50_000_000, packet(dns_message(), fragment=0x2000), None),
        (60_000_000, packet(b"opaque", protocol=6), None),
        (70_000_000, valid[:12] + b"\x86\xdd" + valid[14:], None),
        (80_000_000, packet(struct.pack("!6H", 1, 0x8180, 0, 0, 0, 0)), None),
        (90_000_000, bytes(bad_udp_length), None),
        (100_000_000, bytes(wrong_ip_length), None),
        (110_000_000, bytes(invalid_ihl), None),
        (120_000_000, valid, len(valid) - 1),
    ]
    corrupted = bytearray(pcap(malformed))
    # A complete record with an invalid fraction, followed by a partial final payload.
    corrupted += (
        struct.pack("<4I", EPOCH_SECONDS, 1_000_000, len(valid), len(valid)) + valid
    )
    corrupted += struct.pack("<4I", EPOCH_SECONDS + 1, 0, 64, 64) + b"partial"
    pair = [(123_456_000, valid, None), (123_456_789, response_packet(), None)]
    return {
        "dns-observations.pcap": pcap(traffic),
        "corruption-cases.pcap": bytes(corrupted),
        "big-endian-micro.pcap": pcap(pair, endian=">"),
        "little-endian-nano.pcap": pcap(pair, nanos=True),
        "big-endian-nano.pcap": pcap(pair, endian=">", nanos=True),
    }
