import unittest
from pcaplab.core import parse_capture
from pcaplab.analysis import analyze
from scripts.fixtures import (
    dns_message,
    packet,
    pcap,
    response_packet,
    synthetic_fixtures,
)


def observations(records):
    return analyze(
        parse_capture(pcap([(t, data, None) for t, data in records], nanos=True))
    )


class AnalysisTests(unittest.TestCase):
    def test_declared_fixture_counts_and_no_attribution(self):
        result = analyze(parse_capture(synthetic_fixtures()["dns-observations.pcap"]))
        self.assertEqual(len(result["queries"]), 17)
        self.assertEqual(len(result["responses"]), 15)
        self.assertEqual(len(result["matches"]), 13)
        self.assertEqual(
            sum(r["status"] == "unmatched" for r in result["responses"]), 1
        )
        self.assertEqual(
            sum(r["status"] == "ambiguous" for r in result["responses"]), 1
        )
        self.assertEqual(
            sum(q["status"] == "unanswered_within_window" for q in result["queries"]), 3
        )
        self.assertEqual(
            sum(q["status"] == "right_censored" for q in result["queries"]), 1
        )
        self.assertEqual(result["burst_windows"][0]["count"], 12)
        self.assertEqual(
            result["burst_windows"][0]["last_ns"]
            - result["burst_windows"][0]["first_ns"],
            220_000_000,
        )

    def test_strict_causality_inclusive_timeout_and_capture_censoring(self):
        query, response = packet(dns_message()), response_packet()
        self.assertEqual(
            len(observations([(0, query), (2_000_000_000, response)])["matches"]), 1
        )
        late = observations([(0, query), (2_000_000_001, response)])
        self.assertFalse(late["matches"])
        self.assertEqual(late["queries"][0]["status"], "unanswered_within_window")
        for records in [[(0, query), (0, response)], [(0, response), (1, query)]]:
            result = observations(records)
            self.assertFalse(result["matches"])
            self.assertEqual(result["queries"][0]["status"], "right_censored")
        for name in ("little-endian-nano.pcap", "big-endian-nano.pcap"):
            result = analyze(parse_capture(synthetic_fixtures()[name]))
            self.assertEqual(result["matches"][0]["latency_ns"], 789)
        micro = analyze(parse_capture(synthetic_fixtures()["big-endian-micro.pcap"]))
        self.assertFalse(micro["matches"])

    def test_flow_question_and_ambiguity_boundaries(self):
        query = packet(dns_message())
        wrong = [
            response_packet(ident=101),
            response_packet(name="other.test"),
            response_packet(port=53001),
            response_packet(client="192.0.2.11"),
        ]
        for response in wrong:
            self.assertFalse(observations([(0, query), (1, response)])["matches"])
        self.assertEqual(
            len(
                observations([(0, query), (1, response_packet(name="EXAMPLE.TEST"))])[
                    "matches"
                ]
            ),
            1,
        )
        ambiguous = observations([(0, query), (1, query), (2, response_packet())])
        self.assertFalse(ambiguous["matches"])
        self.assertEqual(ambiguous["responses"][0]["candidate_indices"], [0, 1])
        duplicates = observations(
            [(0, query), (1, response_packet()), (2, response_packet())]
        )
        self.assertEqual(
            [r["status"] for r in duplicates["responses"]], ["matched", "unmatched"]
        )

    def test_no_bad_envelope_time_extension_and_analysis_bounds(self):
        wire = pcap([(0, packet(dns_message()), None)], nanos=True)
        import struct

        wire += struct.pack("<4I", 1700000010, 0, 1000, 1000) + b"short"
        result = analyze(parse_capture(wire))
        self.assertEqual(result["queries"][0]["status"], "right_censored")
        for invalid in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                analyze(parse_capture(pcap([])), timeout_ns=invalid)


if __name__ == "__main__":
    unittest.main()
