# Analysis and provenance

## Owned fixtures

The generator builds Ethernet, IPv4, UDP and DNS bytes directly and writes five classic-PCAP files. No socket or capture API is called. Fixed packet fields define most content; seed `20261121` determines only the 17 opaque bytes of the final non-DNS packet. The synthetic epoch is `1700000000` seconds, selected as a convenient timeline origin, not evidence of capture activity on that date.

The main fixture contains a normal query/response, an unanswered query, an unmatched response, twelve closely spaced queries with distinct IDs and their responses, two identical outstanding query keys followed by one ambiguous response, a late query and a final non-DNS observation. The corruption fixture intentionally changes checksums, lengths, name pointers and envelope fields and includes unsupported protocol cases. Three small files compare byte order and timestamp precision.

The study writes each PCAP, reads those actual bytes back, then records decoded results. It preserves a raw SHA256 for the entire file and for each available packet-byte slice. Issue offsets are absolute file offsets; an EOF/truncation offset can identify the boundary immediately after the last available byte, rather than an existing byte.

## Exact-key matching

Only successfully decoded selected-DNS records participate. Events are ordered by their exact integer timestamp and then record index. A response is eligible for a query only if:

1. Client/server IPv4 addresses and UDP ports reverse exactly.
2. The transaction ID, canonical length-delimited question name, QTYPE and QCLASS agree.
3. The query timestamp is strictly earlier than the response timestamp.
4. The elapsed interval is at most `2,000,000,000` ns, including the endpoint.
5. Exactly one unmatched query satisfies the preceding conditions.

One eligible query produces a unique observed match. Multiple candidates produce an ambiguous response and leave queries unresolved. No candidate produces an unmatched response. A second response to a query already matched is unmatched; the analysis does not assume it is an attack, duplicate delivery, spoofing or a retransmission. Case-insensitive matching is limited to ASCII DNS case rules. Record order does not override conflicting timestamp order, and timestamp ties do not establish causality.

Every ambiguous response records its candidate count and up to eight candidate indices. Each query counts ambiguous observations and retains up to eight response indices. These bounded contexts prevent unbounded duplication in the evidence output; counts remain complete.

## Observation limits and censoring

The last complete, length-consistent record envelope with a valid timestamp defines the observed end of the file, even if its packet protocol is unsupported or malformed. An incomplete final payload, impossible envelope lengths or an invalid fractional timestamp cannot extend that observation interval.

An unresolved query is `unanswered_within_window` when the observed end reaches its two-second deadline; otherwise it is `right_censored`. These are file-level evidence labels, not proof that a server received a request, a response never existed, a resolver timed out or capture coverage was complete. Queries associated with ambiguous responses retain that evidence alongside their unresolved status. Missing traffic and incorrect clocks would limit any real-world use further.

## Repeated-query windows

For each client address, server address and canonical question, a sliding inclusive 500 ms window counts observed query records. Source ports and transaction IDs do not split this descriptive grouping. The highest-count window is retained when it reaches at least five queries. These are repeated records, not deduplicated user actions. The report's main window contains twelve unique-ID queries over 220 ms; all have unique matched responses. No malicious intent, actor identity or service-impact claim is inferred.

## Resource and protocol limits

| Resource | Bound |
|---|---:|
| Input file | 4 MiB |
| Packet records scanned | 4,096 |
| Snapshot/packet bytes accepted | 65,535 |
| DNS message | 4,096 bytes |
| Resource records per DNS message | 32 |
| Compression-pointer hops per name | 32 |
| Expanded DNS wire name | 255 bytes |
| Saved ambiguity indices per observation | 8 |

The file reader requests at most the file limit plus one byte. Exceeding the record limit stops scanning explicitly. Packet and name limits are policy bounds rather than claims that larger valid protocol data cannot exist. Correlation is bounded by the record cap; repeated identical keys can still incur quadratic candidate comparisons within that cap. The implementation is not intended for streaming or large production captures.

## Measurements and reproducibility

The study records five complete parse-and-analysis calls per fixture after one warmup, for 25 actual timings. File I/O, generation and rendering are outside the timer. Fixture order is fixed; no timing confidence interval, general throughput or comparative speed claim is made. Tiny inputs and one interpreter run are inadequate for a production benchmark.

The published execution records actual UTC start/end, Python/platform and pre-execution source hashes. Source hashes normalize CRLF/CR to LF. Generated CSV/JSON/HTML use explicit LF before byte hashing, and `.pcap` files are binary. `manifest.json` covers every run artifact except itself. Figure/inspector provenance links all source artifacts and the renderer hash to the rendered outputs. Tests reparse original bytes and reconcile all decoded records, hashes and summary counts.

Fresh runs require a new empty directory. CI generates independent output and compares deterministic captures, decoded JSON and evidence CSVs with the published run. Timings and execution timestamps are allowed to differ. Browser captures, when added, are actual automated report reviews, not footage of a person manually performing packet analysis.
