"""Verify exact capture bytes, decoded evidence, provenance and CLI behavior."""

import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pcaplab.core import parse_capture
from pcaplab.analysis import analyze
from scripts.fixtures import synthetic_fixtures

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/published"


class EvidenceTests(unittest.TestCase):
    def test_original_bytes_decoded_offsets_aggregate_counts_and_hashes(self):
        generated = synthetic_fixtures()
        with (RUN / "summary.csv").open(newline="", encoding="utf-8") as stream:
            summaries = {row["capture"]: row for row in csv.DictReader(stream)}
        with (RUN / "packets.csv").open(newline="", encoding="utf-8") as stream:
            packets = list(csv.DictReader(stream))
        with (RUN / "issues.csv").open(newline="", encoding="utf-8") as stream:
            issues = list(csv.DictReader(stream))
        with (RUN / "measurements.csv").open(newline="", encoding="utf-8") as stream:
            timings = list(csv.DictReader(stream))
        self.assertEqual(len(timings), 25)
        self.assertTrue(all(int(t["elapsed_ns"]) > 0 for t in timings))
        for name, expected in generated.items():
            data = (RUN / "captures" / name).read_bytes()
            self.assertEqual(data, expected)
            capture = parse_capture(data)
            analysis = analyze(capture)
            stored = json.loads(
                (RUN / "decoded" / (Path(name).stem + ".json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                stored,
                json.loads(
                    json.dumps({"capture": capture.as_dict(), "analysis": analysis})
                ),
            )
            summary = summaries[name]
            self.assertEqual(int(summary["records"]), len(capture.records))
            self.assertEqual(int(summary["bytes"]), len(data))
            self.assertEqual(int(summary["issues"]), len(capture.issues))
            self.assertEqual(int(summary["matches"]), len(analysis["matches"]))
            for status in ("dns", "udp", "quarantined", "unsupported"):
                self.assertEqual(
                    int(summary[status]),
                    sum(r.status == status for r in capture.records),
                )
            self.assertEqual(
                len([i for i in issues if i["capture"] == name]), len(capture.issues)
            )
            for record in capture.records:
                row = next(
                    p
                    for p in packets
                    if p["capture"] == name and int(p["record_index"]) == record.index
                )
                actual = data[
                    record.data_offset : record.data_offset + record.available_length
                ]
                self.assertEqual(
                    hashlib.sha256(actual).hexdigest(), row["packet_sha256"]
                )
                self.assertEqual(int(row["data_offset"]), record.data_offset)
                self.assertEqual(row["status"], record.status)
        for item in json.loads((RUN / "manifest.json").read_text(encoding="utf-8")):
            data = (RUN / item["path"]).read_bytes()
            self.assertEqual(len(data), item["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])
            if item["path"].endswith((".csv", ".json")):
                self.assertNotIn(b"\r", data)
        environment = json.loads((RUN / "environment.json").read_text(encoding="utf-8"))
        for name, expected in environment["source_sha256_lf"].items():
            data = (
                (ROOT / name).read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            )
            self.assertEqual(hashlib.sha256(data).hexdigest(), expected)

    def test_cli_preserves_exclusive_output_and_rejects_bad_global_header(self):
        capture = RUN / "captures/dns-observations.pcap"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decoded.json"
            command = [
                sys.executable,
                "-m",
                "pcaplab",
                str(capture),
                "--output",
                str(output),
            ]
            first = subprocess.run(command, capture_output=True, text=True, timeout=15)
            self.assertEqual(first.returncode, 0, first.stderr)
            original = output.read_bytes()
            self.assertEqual(len(json.loads(original)["analysis"]["matches"]), 13)
            self.assertEqual(
                subprocess.run(command, capture_output=True, timeout=15).returncode, 2
            )
            self.assertEqual(output.read_bytes(), original)
            bad = Path(directory) / "invalid.pcap"
            bad.write_bytes(b"not pcap")
            self.assertEqual(
                subprocess.run(
                    [sys.executable, "-m", "pcaplab", str(bad)],
                    capture_output=True,
                    timeout=15,
                ).returncode,
                2,
            )

    def test_report_source_inputs_and_rendered_assets_match(self):
        metadata = json.loads(
            (ROOT / "docs/assets/provenance.json").read_text(encoding="utf-8")
        )
        for collection in ("inputs", "outputs"):
            for name, digest in metadata[collection].items():
                self.assertEqual(
                    hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest
                )
        source = (
            (ROOT / "scripts/build_report.py")
            .read_bytes()
            .replace(b"\r\n", b"\n")
            .replace(b"\r", b"\n")
        )
        self.assertEqual(
            hashlib.sha256(source).hexdigest(), metadata["source_sha256_lf"]
        )


if __name__ == "__main__":
    unittest.main()
