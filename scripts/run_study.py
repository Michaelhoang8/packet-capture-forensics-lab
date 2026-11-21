"""Generate synthetic PCAPs, parse actual bytes and preserve decoded evidence."""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time
from dataclasses import asdict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcaplab.core import parse_capture
from pcaplab.analysis import analyze
from fixtures import synthetic_fixtures


def write_json(path, value):
    path.write_text(
        json.dumps(value, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_csv(path, records, columns):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)


def run(output):
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(
            "Choose an empty output directory; stored evidence is preserved"
        )
    for directory in (output, output / "captures", output / "decoded"):
        directory.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    sources = [
        "src/pcaplab/core.py",
        "src/pcaplab/analysis.py",
        "scripts/fixtures.py",
        "scripts/run_study.py",
    ]
    hashes = {
        name: hashlib.sha256(
            (ROOT / name).read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        ).hexdigest()
        for name in sources
    }
    records, issues, measurements, summaries = [], [], [], []
    for name, original in synthetic_fixtures().items():
        path = output / "captures" / name
        path.write_bytes(original)
        data = path.read_bytes()  # Parse the exact committed artifact bytes.
        capture = parse_capture(data)
        analysis = analyze(capture)
        write_json(
            output / "decoded" / (path.stem + ".json"),
            {"capture": capture.as_dict(), "analysis": analysis},
        )
        for record in capture.records:
            ip, udp, dns = (record.layers.get(k, {}) for k in ("ipv4", "udp", "dns"))
            records.append(
                {
                    "capture": name,
                    "record_index": record.index,
                    "record_offset": record.record_offset,
                    "data_offset": record.data_offset,
                    "timestamp_ns": record.timestamp_ns,
                    "captured_length": record.captured_length,
                    "available_length": record.available_length,
                    "status": record.status,
                    "source": ip.get("source", ""),
                    "destination": ip.get("destination", ""),
                    "source_port": udp.get("source_port", ""),
                    "destination_port": udp.get("destination_port", ""),
                    "udp_checksum": udp.get("checksum", ""),
                    "dns_id": dns.get("id", ""),
                    "dns_response": dns.get("response", ""),
                    "dns_name": dns.get("name", ""),
                    "packet_sha256": record.sha256,
                }
            )
        issues.extend({"capture": name, **asdict(issue)} for issue in capture.issues)
        summaries.append(
            {
                "capture": name,
                "bytes": len(data),
                "records": len(capture.records),
                "dns": sum(r.status == "dns" for r in capture.records),
                "udp": sum(r.status == "udp" for r in capture.records),
                "quarantined": sum(r.status == "quarantined" for r in capture.records),
                "unsupported": sum(r.status == "unsupported" for r in capture.records),
                "issues": len(capture.issues),
                "scan_complete": capture.scan_complete,
                "matches": len(analysis["matches"]),
                "unmatched_responses": sum(
                    r["status"] == "unmatched" for r in analysis["responses"]
                ),
                "ambiguous_responses": sum(
                    r["status"] == "ambiguous" for r in analysis["responses"]
                ),
                "unanswered_queries": sum(
                    q["status"] == "unanswered_within_window"
                    for q in analysis["queries"]
                ),
                "censored_queries": sum(
                    q["status"] == "right_censored" for q in analysis["queries"]
                ),
                "burst_windows": len(analysis["burst_windows"]),
            }
        )
        # One warmup above, followed by five actual complete parse+analysis calls.
        for repetition in range(5):
            begin = time.perf_counter_ns()
            decoded = parse_capture(data)
            analyze(decoded)
            elapsed = time.perf_counter_ns() - begin
            measurements.append(
                {"capture": name, "repetition": repetition, "elapsed_ns": elapsed}
            )
    write_csv(output / "packets.csv", records, list(records[0]))
    write_csv(output / "issues.csv", issues, list(issues[0]))
    write_csv(output / "summary.csv", summaries, list(summaries[0]))
    write_csv(output / "measurements.csv", measurements, list(measurements[0]))
    write_json(
        output / "environment.json",
        {
            "started_utc": started,
            "completed_utc": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "source_sha256_lf": hashes,
            "fixtures": "Owned deterministic byte construction; no socket, network capture or third-party data",
            "random_seed": 20261121,
            "random_scope": "17 opaque non-DNS payload bytes only",
            "synthetic_epoch_seconds": 1700000000,
            "epoch_note": "Chosen timeline origin, not a real capture date",
            "timing": "Five warmed parse+analysis calls per file; excludes file I/O; fixed file order, no throughput claim",
        },
    )
    write_json(
        output / "manifest.json",
        [
            {
                "path": path.relative_to(output).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in sorted(output.rglob("*"))
            if path.is_file()
        ],
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "captures": len(summaries),
                "records": len(records),
                "issues": len(issues),
                "timings": len(measurements),
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "outputs/latest")
    run(parser.parse_args().out)
