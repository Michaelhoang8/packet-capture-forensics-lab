# Findings

The five owned synthetic files total 5,049 bytes and contain 54 record envelopes. The main capture is 3,183 bytes; the corruption fixture is 1,218 bytes; each precision fixture is 216 bytes. Parsing and analysis operated on those saved bytes.

## Main observation file

Seventeen queries and fifteen responses produce thirteen unique matches, one unmatched response and one ambiguous response. The normal first response appears 35 ms after its query. Twelve responses in the repeated-query interval appear 10 ms after their queries. These are differences between synthetic capture timestamps, not physical network latency measurements.

The repeated interval contains twelve queries for `repeated.test.` from `192.0.2.20` to `198.51.100.53` over 220 ms. Each uses a distinct transaction ID and source port, and each receives a uniquely matching response in the file. A burst count alone does not justify a malicious-activity label.

Two `duplicate.test.` queries share the same flow, transaction ID and question, at 800 and 820 ms. The response at 850 ms has two candidates. Selecting the nearest or oldest query would make an unsupported attribution; this analyzer records the ambiguity. Both queries remain without a unique response match, with the ambiguous response index attached.

The `end.test.` query appears at 3.4 seconds and the file's final complete observation at 3.5 seconds. Only 100 ms of its two-second window is visible, so it is right-censored. The main file contains three unresolved queries whose complete observation window is visible: one deliberately unanswered query and the two ambiguous duplicate-key queries.

## Invalid and unsupported bytes

The corruption fixture contains one valid DNS packet, ten quarantined records and four unsupported records. Unsupported cases include an IPv4 fragment, a non-UDP IPv4 protocol, a non-IPv4 Ethernet type and a DNS question-count outside the selected subset. They are not counted as corrupt simply because the parser does not implement them.

Quarantine reasons cover IPv4 and UDP checksum failure, a self-referential DNS pointer, captured truncation, invalid UDP/IP/header lengths, inconsistent record lengths, an invalid timestamp fraction and the final incomplete payload. The final payload has seven available bytes against 64 declared, so scanning stops at file offset 1,218. There is no attempt to salvage later bytes as a guessed record.

## Precision changes the available evidence

The precision pair is constructed 789 ns apart. Both nanosecond variants preserve a unique match and the exact interval. Microsecond storage truncates both fractional times to `123456` microseconds, yielding a tie. The analyzer returns no unique match for that file because order is not available at its stored precision.

This example motivates exact integer timestamp handling and explicit temporal assumptions. It does not show that PCAP capture hardware has nanosecond accuracy: file representation precision and measurement accuracy are different quantities.

## Limits

All fixtures are tiny and intentionally selected to exercise implementation behavior. Checks include two independent review tests, literal wire vectors, bounded mutations and artifact reconciliation; these do not constitute exhaustive protocol conformance or security fuzzing. The parser does not validate that every DNS compression target begins at a previously parsed label boundary, and opaque DNS RDATA receives no semantic validation. There are no claims about production traffic coverage, malicious actors, live packet loss, real capture-clock accuracy, IDS quality or hardware performance.
