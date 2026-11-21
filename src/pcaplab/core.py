"""Bounded classic-PCAP, Ethernet/IPv4/UDP and selected DNS decoding."""

from dataclasses import dataclass, asdict
import hashlib
import ipaddress
from pathlib import Path
import struct

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 4096
MAX_PACKET_BYTES = 65535
MAX_DNS_BYTES = 4096
MAX_DNS_RECORDS = 32
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


class ParseError(ValueError):
    def __init__(self, code, offset, detail, category="malformed"):
        self.code, self.offset, self.detail, self.category = (
            code,
            offset,
            detail,
            category,
        )
        super().__init__(f"{code} at byte {offset}: {detail}")


@dataclass(frozen=True)
class Issue:
    record_index: int | None
    record_offset: int | None
    byte_offset: int
    code: str
    category: str
    detail: str


@dataclass(frozen=True)
class Record:
    index: int
    record_offset: int
    data_offset: int
    timestamp_ns: int | None
    captured_length: int
    original_length: int
    available_length: int
    sha256: str
    status: str
    layers: dict


@dataclass(frozen=True)
class Capture:
    metadata: dict
    records: tuple[Record, ...]
    issues: tuple[Issue, ...]
    scan_complete: bool

    def as_dict(self):
        return asdict(self)


def checksum(data):
    """Internet checksum: one's-complement sum with a zero byte for odd length."""
    if len(data) % 2:
        data += b"\0"
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def dns_name(message, start, base=0):
    """Decode a bounded name; compression targets must precede the pointer."""
    cursor, end, expanded = start, None, 1
    labels, visited = [], set()
    hops = 0
    while True:
        if cursor in visited:
            raise ParseError(
                "dns_pointer_loop", base + cursor, "Name traversal revisits an offset"
            )
        visited.add(cursor)
        if cursor >= len(message):
            raise ParseError(
                "dns_name_bounds", base + cursor, "Name is outside the DNS message"
            )
        size = message[cursor]
        if size & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise ParseError(
                    "dns_pointer_bounds",
                    base + cursor,
                    "Incomplete compression pointer",
                )
            target = ((size & 0x3F) << 8) | message[cursor + 1]
            if target in visited:
                raise ParseError(
                    "dns_pointer_loop", base + cursor, "Pointer revisits a name offset"
                )
            if target < 12 or target >= len(message):
                raise ParseError(
                    "dns_pointer_bounds",
                    base + cursor,
                    "Pointer target is outside the name area",
                )
            if target >= cursor:
                raise ParseError(
                    "dns_forward_pointer",
                    base + cursor,
                    "Subset requires a prior name occurrence",
                )
            hops += 1
            if hops > 32:
                raise ParseError(
                    "dns_pointer_limit",
                    base + cursor,
                    "More than 32 compression pointers",
                    "limit",
                )
            if end is None:
                end = cursor + 2
            cursor = target
            continue
        if size & 0xC0:
            raise ParseError("dns_label_type", base + cursor, "Reserved label encoding")
        cursor += 1
        if size == 0:
            if end is None:
                end = cursor
            break
        if cursor + size > len(message):
            raise ParseError(
                "dns_label_bounds", base + cursor - 1, "Label exceeds message"
            )
        expanded += 1 + size
        if expanded > 255:
            raise ParseError(
                "dns_name_length",
                base + cursor - 1,
                "Expanded wire name exceeds 255 bytes",
            )
        labels.append(message[cursor : cursor + size])
        cursor += size
    display = (
        ".".join(
            "".join(
                chr(b) if 33 <= b <= 126 and b not in (46, 92) else f"\\{b:03d}"
                for b in label
            )
            for label in labels
        )
        + "."
    )
    # Length-delimited bytes avoid conflating an escaped dot within a label
    # with a real label boundary. Only ASCII A-Z case is folded.
    canonical = (
        b"".join(bytes([len(label)]) + label.lower() for label in labels) + b"\0"
    )
    return display, canonical.hex(), end


def parse_dns(message, base=0):
    if len(message) < 12:
        raise ParseError("dns_header_short", base, "DNS header needs 12 bytes")
    if len(message) > MAX_DNS_BYTES:
        raise ParseError(
            "dns_size_limit", base, "DNS message exceeds 4096-byte policy", "limit"
        )
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", message)
    if (flags >> 11) & 15 or qd != 1:
        raise ParseError(
            "dns_subset",
            base + 2,
            "Only opcode 0 with exactly one question is analyzed",
            "unsupported",
        )
    if flags & 0x0200:
        raise ParseError(
            "dns_truncated_flag",
            base + 2,
            "TC=1 response requires unsupported follow-up/reassembly",
            "unsupported",
        )
    if an + ns + ar > MAX_DNS_RECORDS:
        raise ParseError(
            "dns_record_limit", base + 6, "More than 32 resource records", "limit"
        )
    name, canonical, cursor = dns_name(message, 12, base)
    if cursor + 4 > len(message):
        raise ParseError(
            "dns_question_short", base + cursor, "Question type/class missing"
        )
    qtype, qclass = struct.unpack_from("!HH", message, cursor)
    cursor += 4
    if qtype != 1 or qclass != 1:
        raise ParseError(
            "dns_question_subset",
            base + cursor - 4,
            "Only IN/A questions are analyzed",
            "unsupported",
        )
    answers, opaque = [], 0
    for section, count in [("answer", an), ("authority", ns), ("additional", ar)]:
        for _ in range(count):
            owner, _, cursor = dns_name(message, cursor, base)
            if cursor + 10 > len(message):
                raise ParseError(
                    "dns_rr_header_short",
                    base + cursor,
                    "Resource-record fixed header missing",
                )
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", message, cursor)
            cursor += 10
            if cursor + rdlen > len(message):
                raise ParseError(
                    "dns_rdata_bounds", base + cursor, "Resource data exceeds message"
                )
            if rtype == 1 and rclass == 1:
                if rdlen != 4:
                    raise ParseError(
                        "dns_a_length",
                        base + cursor - 2,
                        "IN/A RDATA must contain four bytes",
                    )
                answers.append(
                    {
                        "section": section,
                        "owner": owner,
                        "address": str(
                            ipaddress.IPv4Address(message[cursor : cursor + 4])
                        ),
                        "ttl": ttl,
                    }
                )
            else:
                # Unknown RDATA is length-checked, never interpreted as a name.
                opaque += 1
            cursor += rdlen
    if cursor != len(message):
        raise ParseError(
            "dns_trailing_bytes",
            base + cursor,
            "Bytes remain after declared DNS sections",
        )
    return {
        "id": ident,
        "response": bool(flags & 0x8000),
        "flags": flags,
        "rcode_low4": flags & 15,
        "name": name,
        "name_key": canonical,
        "qtype": qtype,
        "qclass": qclass,
        "a_records": answers,
        "opaque_records": opaque,
        "question_offset": base + 12,
        "message_offset": base,
    }


def decode_packet(data, base=0):
    layers = {}
    try:
        if len(data) < 14:
            raise ParseError(
                "ethernet_header_short", base, "Ethernet header needs 14 bytes"
            )
        ethertype = int.from_bytes(data[12:14], "big")
        layers["ethernet"] = {
            "destination": data[:6].hex(":"),
            "source": data[6:12].hex(":"),
            "ethertype": ethertype,
        }
        if ethertype != 0x0800:
            raise ParseError(
                "ethernet_subset",
                base + 12,
                "Only untagged Ethernet IPv4 is supported",
                "unsupported",
            )
        ip = data[14:]
        if len(ip) < 20:
            raise ParseError(
                "ipv4_header_short", base + 14, "IPv4 header needs at least 20 bytes"
            )
        version, ihl = ip[0] >> 4, (ip[0] & 15) * 4
        if version != 4 or ihl < 20:
            raise ParseError(
                "ipv4_version_ihl", base + 14, "Invalid IPv4 version/header length"
            )
        if len(ip) < ihl:
            raise ParseError(
                "ipv4_options_short", base + 14, "Declared IPv4 header exceeds capture"
            )
        total = int.from_bytes(ip[2:4], "big")
        if total < ihl or total > len(ip):
            raise ParseError(
                "ipv4_total_length",
                base + 16,
                "Declared IPv4 length is outside captured packet",
            )
        if checksum(ip[:ihl]) != 0:
            raise ParseError("ipv4_checksum", base + 24, "Invalid IPv4 header checksum")
        fragment = int.from_bytes(ip[6:8], "big")
        if fragment & 0x8000:
            raise ParseError(
                "ipv4_reserved_flag", base + 20, "Reserved IPv4 flag is set"
            )
        layers["ipv4"] = {
            "source": str(ipaddress.IPv4Address(ip[12:16])),
            "destination": str(ipaddress.IPv4Address(ip[16:20])),
            "header_length": ihl,
            "total_length": total,
            "protocol": ip[9],
            "ttl": ip[8],
            "fragment_field": fragment,
            "checksum": "valid",
            "ethernet_padding_bytes": len(ip) - total,
        }
        if fragment & 0x3FFF:
            raise ParseError(
                "ipv4_fragment",
                base + 20,
                "Fragment reassembly is outside scope",
                "unsupported",
            )
        if ihl != 20:
            raise ParseError(
                "ipv4_options",
                base + 14,
                "IPv4 options are outside scope",
                "unsupported",
            )
        if ip[9] != 17:
            raise ParseError(
                "ipv4_protocol",
                base + 23,
                "Only UDP payloads are decoded",
                "unsupported",
            )
        udp = ip[ihl:total]
        udp_base = base + 14 + ihl
        if len(udp) < 8:
            raise ParseError(
                "udp_header_short", udp_base, "UDP header needs eight bytes"
            )
        source, destination, length, stored = struct.unpack_from("!4H", udp)
        if length < 8 or length > len(udp):
            raise ParseError(
                "udp_length", udp_base + 4, "UDP length lies outside IPv4 payload"
            )
        pseudo = ip[12:20] + bytes([0, 17]) + length.to_bytes(2, "big")
        if stored and checksum(pseudo + udp[:length]) != 0:
            raise ParseError(
                "udp_checksum", udp_base + 6, "Invalid nonzero UDP checksum"
            )
        layers["udp"] = {
            "source_port": source,
            "destination_port": destination,
            "length": length,
            "checksum": "valid" if stored else "not_present_ipv4",
            "ip_trailing_bytes": len(udp) - length,
            "payload_offset": udp_base + 8,
            "payload_length": length - 8,
        }
        if 53 in (source, destination):
            layers["dns"] = parse_dns(udp[8:length], udp_base + 8)
        return layers, None
    except ParseError as error:
        return layers, error


def parse_capture(data):
    if not isinstance(data, bytes):
        raise TypeError("Capture input must be bytes")
    if len(data) > MAX_FILE_BYTES:
        raise ParseError("file_size_limit", 0, "Capture exceeds 4 MiB", "limit")
    if len(data) < 24:
        raise ParseError(
            "global_header_short", 0, "Classic PCAP global header needs 24 bytes"
        )
    if data[:4] not in MAGICS:
        raise ParseError(
            "pcap_magic",
            0,
            "Unsupported PCAP magic (PCAPNG is outside scope)",
            "unsupported",
        )
    endian, resolution = MAGICS[data[:4]]
    major, minor, zone, accuracy, snaplen, linktype = struct.unpack_from(
        endian + "HHiIII", data, 4
    )
    if (major, minor) != (2, 4):
        raise ParseError(
            "pcap_version",
            4,
            "Only classic PCAP version 2.4 is supported",
            "unsupported",
        )
    if not 1 <= snaplen <= MAX_PACKET_BYTES:
        raise ParseError(
            "pcap_snaplen", 16, "Snap length must lie in 1..65535", "limit"
        )
    if linktype != 1:
        raise ParseError(
            "pcap_linktype",
            20,
            "Only Ethernet link type 1 without FCS flags is supported",
            "unsupported",
        )
    if zone or accuracy:
        raise ParseError(
            "pcap_reserved",
            8,
            "Only zero legacy timezone/accuracy fields are supported",
            "unsupported",
        )
    metadata = {
        "endianness": "little" if endian == "<" else "big",
        "timestamp_resolution": resolution,
        "snaplen": snaplen,
        "linktype": linktype,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    records, issues = [], []
    offset, complete = 24, True
    while offset < len(data):
        index = len(records)
        if index >= MAX_RECORDS:
            issues.append(
                Issue(
                    None,
                    offset,
                    offset,
                    "record_limit",
                    "limit",
                    "Stopped at 4096 records",
                )
            )
            complete = False
            break
        if len(data) - offset < 16:
            issues.append(
                Issue(
                    None,
                    offset,
                    offset,
                    "record_header_short",
                    "truncated",
                    "Incomplete final record header; no resynchronization attempted",
                )
            )
            complete = False
            break
        seconds, fraction, included, original = struct.unpack_from(
            endian + "4I", data, offset
        )
        start = offset + 16
        available = min(included, len(data) - start)
        packet = data[start : start + available]
        timestamp = (
            seconds * 1_000_000_000 + fraction * (1_000_000_000 // resolution)
            if fraction < resolution
            else None
        )
        layers, error = {}, None
        if available != included:
            error = ParseError(
                "record_data_short",
                start + available,
                "Declared record data exceeds file; parsing stops",
                "truncated",
            )
            complete = False
        elif fraction >= resolution:
            error = ParseError(
                "timestamp_fraction",
                offset + 4,
                "Timestamp fraction exceeds declared resolution",
            )
        elif included > snaplen or included > original:
            error = ParseError(
                "record_lengths",
                offset + 8,
                "Captured length exceeds snap length or original length",
            )
        elif included < original:
            error = ParseError(
                "capture_truncated",
                start + included,
                "Captured bytes are shorter than original frame",
                "truncated",
            )
        else:
            layers, error = decode_packet(packet, start)
        status = (
            "dns"
            if "dns" in layers and error is None
            else "udp" if "udp" in layers and error is None else "quarantined"
        )
        if error:
            status = "unsupported" if error.category == "unsupported" else "quarantined"
            issues.append(
                Issue(
                    index,
                    offset,
                    error.offset,
                    error.code,
                    error.category,
                    error.detail,
                )
            )
        records.append(
            Record(
                index,
                offset,
                start,
                timestamp,
                included,
                original,
                available,
                hashlib.sha256(packet).hexdigest(),
                status,
                layers,
            )
        )
        offset = start + included
        if not complete:
            break
    return Capture(metadata, tuple(records), tuple(issues), complete)


def read_capture(path):
    with Path(path).open("rb") as stream:
        return parse_capture(stream.read(MAX_FILE_BYTES + 1))
