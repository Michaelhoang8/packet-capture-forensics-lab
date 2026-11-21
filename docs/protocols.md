# Protocol subset and primary references

## Classic PCAP

The reader recognizes the four magic byte sequences for classic PCAP with either byte order and either microsecond or nanosecond fractions. It supports version 2.4 and Ethernet link type 1 without extra FCS flags. Integer seconds and fractions are converted to integer nanoseconds, avoiding floating-point timestamp loss. These fields follow the [libpcap savefile documentation maintained by the tcpdump project](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in).

The implemented subset requires both legacy reserved timezone/accuracy fields to be zero and snapshot length in `1..65535`. Nonzero reserved metadata, alternate link types/flags, PCAPNG and other versions are reported as unsupported, not asserted to be globally invalid formats. A packet's included length must not exceed snapshot length or original length. A shorter included length than original length is a captured truncation, excluded from protocol matching.

Each record begins with a 16-byte header. If that header or its declared data is incomplete, scanning stops at the exact boundary and does not search for a plausible next header. Complete invalid records are quarantined; scanning continues at the next declared record boundary. This does not repair a damaged file or guarantee synchronization after arbitrary length-field corruption.

## Ethernet and IPv4

Only untagged Ethernet with EtherType `0x0800` is decoded. MAC addresses are displayed as bytes; there is no vendor or device inference. The captured Ethernet FCS is not validated or interpreted.

IPv4 version, IHL, total length, header checksum and reserved fragment flag are checked. Header length is used safely before accessing subsequent fields. Valid options, non-UDP protocol numbers and fragmented datagrams are explicitly unsupported. Ethernet bytes beyond the IPv4 total length are counted separately as padding/extra captured bytes. The header layout and checksum scope follow [RFC 791, section 3.1](https://www.rfc-editor.org/rfc/rfc791).

The fixtures use documentation address blocks, not discovered hosts. [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) reserves `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` for examples. Domain names use `.test`, reserved by [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606).

## UDP over IPv4

UDP length includes its eight-byte header and must fit inside the IPv4 payload. If IPv4 carries additional bytes beyond that length, they are counted and excluded from UDP checksum/DNS interpretation. Source port zero is permitted.

The checksum is the one's-complement checksum of the IPv4 pseudoheader, UDP header and declared UDP data. Odd byte counts receive an arithmetic zero pad, which is not a captured byte. A zero transmitted checksum means it was not supplied for IPv4; it is reported as `not_present_ipv4`. A nonzero checksum must verify. A checksum calculation yielding zero is represented on the wire as `0xffff`. These distinctions follow [RFC 768](https://www.rfc-editor.org/rfc/rfc768.txt). This project does not extend the IPv4 zero-checksum rule to IPv6.

The fixture generator uses a separate 16-bit-word checksum implementation from the parser's byte-pair implementation. Tests also retain a literal IPv4 header with checksum `0x7c66`, an omitted UDP checksum, odd-length data and a payload deliberately yielding encoded checksum `0xffff`.

## Selected DNS

UDP source or destination port 53 triggers bounded DNS parsing. The analyzed subset is opcode 0, exactly one IN/A question, and no TC truncation flag. The header, question, resource-record framing and compressed owner names follow [RFC 1035, sections 4.1.1–4.1.4](https://www.rfc-editor.org/rfc/rfc1035). IN/A resource data must be exactly four bytes; other RDATA is only length-checked and counted as opaque. The response code is deliberately named `rcode_low4`: EDNS extended response-code semantics are not interpreted.

Names allow ordinary labels up to 63 bytes and at most 255 bytes when expanded, including length octets and the final root octet. Compression traversal checks bounds, repeated offsets, forward offsets and a 32-pointer policy limit. It requires a target byte offset before the pointer and structurally decodes from there. **It does not track all earlier name/label boundaries or prove a pointer refers to a previously parsed name occurrence.** Therefore it is not a full DNS-message validator.

Canonical comparison folds ASCII `A..Z` only, preserves label lengths and distinguishes a literal dot inside a label from a label separator. Display names escape nonprintable, dot and backslash octets. The case rule follows [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343.txt). There is no DNSSEC validation, internationalized-name conversion, name resolution or cache behavior.
