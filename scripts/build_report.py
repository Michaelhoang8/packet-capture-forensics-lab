"""Build a byte inspector and timeline from actual preserved capture bytes."""

import csv
from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/published"
DOCS = ROOT / "docs"
ASSETS = DOCS / "assets"
INK, GREEN, BLUE, ORANGE = "#142d2d", "#087f6b", "#3e65b9", "#b3522e"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def timeline(decoded):
    records, analysis = decoded["capture"]["records"], decoded["analysis"]
    first = min(r["timestamp_ns"] for r in records)
    by_index = {r["index"]: r for r in records}
    response_status = {r["record_index"]: r["status"] for r in analysis["responses"]}
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "figure.facecolor": "#f7f8f4",
            "axes.facecolor": "#f7f8f4",
            "text.color": INK,
            "axes.labelcolor": INK,
            "xtick.color": "#526b68",
            "ytick.color": "#526b68",
        }
    )
    fig, axes = plt.subplots(2, 1, figsize=(12.4, 6.4), layout="constrained")
    for ax, limits, title in zip(
        axes,
        [(-0.05, 3.55), (0.285, 0.545)],
        [
            "Complete synthetic observation window",
            "Repeated-query interval: 12 distinct IDs, all with matched responses",
        ],
    ):
        for row in records:
            layers = row["layers"]
            dns, ip = layers.get("dns"), layers.get("ipv4")
            time = (row["timestamp_ns"] - first) / 1e9
            if not dns:
                if ip:
                    ax.scatter(time, 2, color="#84928d", marker="s", s=25)
                continue
            lane = 0 if dns["response"] else 2 if ip["source"] == "192.0.2.10" else 1
            color = (
                GREEN
                if not dns["response"]
                else BLUE if response_status[row["index"]] == "matched" else ORANGE
            )
            marker = "o" if not dns["response"] else "v"
            ax.scatter(time, lane, color=color, marker=marker, s=43, zorder=4)
        for match in analysis["matches"]:
            query, response = (
                by_index[match["query_index"]],
                by_index[match["response_index"]],
            )
            lane = 2 if match["client"] == "192.0.2.10" else 1
            ax.plot(
                [
                    (query["timestamp_ns"] - first) / 1e9,
                    (response["timestamp_ns"] - first) / 1e9,
                ],
                [lane, 0],
                color="#a8beb8",
                linewidth=1,
                zorder=1,
            )
        ax.set(
            xlim=limits,
            ylim=(-0.35, 2.35),
            yticks=[0, 1, 2],
            yticklabels=[
                "Responses from\n198.51.100.53",
                "Queries from\n192.0.2.20",
                "Queries from\n192.0.2.10",
            ],
            xlabel="Seconds after the first record (integer timestamp differences)",
        )
        ax.set_title(title, loc="left", fontsize=12, pad=15)
        ax.grid(axis="x", color="#dce3da", linewidth=0.8)
    axes[0].annotate(
        "Unmatched",
        (0.18, 0),
        xytext=(0.55, -0.18),
        fontsize=9,
        color=ORANGE,
        arrowprops={"arrowstyle": "-", "color": ORANGE},
    )
    axes[0].annotate(
        "Ambiguous",
        (0.85, 0),
        xytext=(1.08, 0.28),
        fontsize=9,
        color=ORANGE,
        arrowprops={"arrowstyle": "-", "color": ORANGE},
    )
    axes[0].annotate(
        "End query: censored",
        (3.4, 2),
        xytext=(2.2, 1.6),
        fontsize=9,
        color=INK,
        arrowprops={"arrowstyle": "-", "color": INK},
    )
    fig.savefig(ASSETS / "timeline.png", dpi=160)
    plt.close(fig)


def inspector_data():
    result = []
    for name in ["dns-observations", "corruption-cases"]:
        decoded = read_json(RUN / "decoded" / (name + ".json"))
        data = (RUN / "captures" / (name + ".pcap")).read_bytes()
        records = []
        for record in decoded["capture"]["records"]:
            offset, length = record["data_offset"], record["available_length"]
            layers = record["layers"]
            ranges = []
            if "ethernet" in layers:
                ranges.append(
                    {"start": 0, "end": 14, "name": "Ethernet", "className": "ethernet"}
                )
            if "ipv4" in layers:
                ranges.append(
                    {
                        "start": 14,
                        "end": 14 + layers["ipv4"]["header_length"],
                        "name": "Validated IPv4 header",
                        "className": "ipv4",
                    }
                )
            if "udp" in layers:
                udp_start = layers["udp"]["payload_offset"] - offset - 8
                ranges.append(
                    {
                        "start": udp_start,
                        "end": udp_start + 8,
                        "name": "Validated UDP header",
                        "className": "udp",
                    }
                )
            if "dns" in layers:
                ranges.append(
                    {
                        "start": layers["dns"]["message_offset"] - offset,
                        "end": length,
                        "name": "Selected DNS message",
                        "className": "dns",
                    }
                )
            records.append(
                {
                    "index": record["index"],
                    "offset": offset,
                    "status": record["status"],
                    "timestamp_ns": (
                        str(record["timestamp_ns"])
                        if record["timestamp_ns"] is not None
                        else "invalid"
                    ),
                    "hex": data[offset : offset + length].hex(),
                    "name": layers.get("dns", {}).get("name", ""),
                    "ranges": ranges,
                    "issues": [
                        i
                        for i in decoded["capture"]["issues"]
                        if i["record_index"] == record["index"]
                    ],
                }
            )
        result.append(
            {
                "name": name + ".pcap",
                "sha256": decoded["capture"]["metadata"]["sha256"],
                "records": records,
            }
        )
    return result


def build():
    ASSETS.mkdir(parents=True, exist_ok=True)
    decoded = read_json(RUN / "decoded/dns-observations.json")
    timeline(decoded)
    data = inspector_data()
    (ASSETS / "inspector-data.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    with (RUN / "issues.csv").open(encoding="utf-8", newline="") as stream:
        issues = list(csv.DictReader(stream))
    rows = "".join(
        f"<tr><td>{row['record_index']}</td><td>{row['byte_offset']}</td><td><code>{html.escape(row['code'])}</code></td><td>{html.escape(row['category'])}</td></tr>"
        for row in issues
    )
    report = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Packet capture forensics lab</title>
<style>
:root{--ink:#142d2d;--green:#087f6b;--muted:#59716b;--line:#cfd8cc;--paper:#f7f8f4}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.65 system-ui,Segoe UI,sans-serif}nav{position:relative;background:#132c2a;color:#d4e0cf;padding:17px 4vw;display:flex;gap:26px;overflow:auto;white-space:nowrap;font:12px ui-monospace,Consolas,monospace}nav a{color:#d4e0cf;text-decoration:none}nav span{color:#b9e372;margin-right:auto}main{max-width:1300px;margin:auto;padding:0 44px}section{padding:68px 0;border-bottom:1px solid var(--line);scroll-margin-top:45px}h1{font-size:clamp(46px,6.6vw,86px);font-weight:520;line-height:1.02;letter-spacing:-.055em;margin:20px 0 28px}h2{font-size:34px;font-weight:530;line-height:1.15;letter-spacing:-.03em;margin:0 0 24px}h3{font-size:18px;font-weight:600}p{max-width:850px;margin:12px 0 20px}.kicker{font:12px ui-monospace,Consolas,monospace;color:var(--green);letter-spacing:.1em}.lead{font-size:21px;max-width:850px}.counts{display:flex;flex-wrap:wrap;gap:44px;margin:36px 0 20px;padding:26px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.counts b{font:37px ui-monospace,Consolas,monospace;display:block}.counts small{font-size:12px;color:var(--muted)}.columns{display:grid;grid-template-columns:1.7fr 1fr;gap:60px}.columns>*{min-width:0}.aside{font-size:14px;color:var(--muted);padding-left:22px;border-left:2px solid var(--line)}a{color:var(--green);text-underline-offset:4px}.links{display:flex;gap:22px;flex-wrap:wrap;margin:28px 0;font-size:14px}.inspector{background:#102a29;color:#d6e2d7;padding:26px;border:1px solid #1a3d38;border-radius:4px}.controls{display:grid;grid-template-columns:1fr 1.4fr;gap:20px}.controls>*{min-width:0}label{font-size:12px;color:#afc6b7;display:block}select{width:100%;max-width:100%;min-width:0;background:#1c3935;color:#eff4e9;border:1px solid #456357;border-radius:3px;padding:11px;font:14px ui-monospace,Consolas,monospace;margin-top:7px}.legend{display:flex;gap:17px;flex-wrap:wrap;font:12px ui-monospace,Consolas,monospace;margin:25px 0}.legend span{padding:3px 7px;border-radius:2px}.ethernet{background:#324c4d;color:#e0ece8}.ipv4{background:#18544b;color:#b1e8d7}.udp{background:#3b4565;color:#d4dcff}.dns{background:#476735;color:#dcf3ae}.unverified{background:#343d3c;color:#a9bab1}.bytebox{max-width:100%;overflow:auto;padding:14px 0;border-top:1px solid #355149;border-bottom:1px solid #355149}.hexdump{min-width:660px}.hexrow{display:grid;grid-template-columns:85px repeat(16,1fr);gap:4px;margin:4px 0}.offset{font:12px/30px ui-monospace,Consolas,monospace;color:#91b2a1}.byte{border:1px solid transparent;padding:0;cursor:pointer;font:14px/30px ui-monospace,Consolas,monospace;border-radius:2px}.byte:hover,.byte:focus-visible{border-color:#f1f5d5;outline:none}.bytebox:focus-visible,.table-scroll:focus-visible{outline:2px solid #92b95b;outline-offset:4px}.detail{min-height:62px;padding:20px 0 8px;font:14px ui-monospace,Consolas,monospace;overflow-wrap:anywhere;color:#c1e48b}.packetmeta{font:12px/1.8 ui-monospace,Consolas,monospace;overflow-wrap:anywhere;color:#a6c2af}.notice{font-size:13px;color:var(--muted)}.inspector .notice{color:#afc4b6}.table-scroll{max-width:100%;overflow-x:auto;overscroll-behavior-inline:contain}table{width:100%;border-collapse:collapse;font-size:14px;margin:22px 0}th,td{padding:12px 14px;border-bottom:1px solid var(--line);text-align:left}th{font:12px ui-monospace,Consolas,monospace;color:var(--muted)}.wide-table{min-width:650px}code{font:13px ui-monospace,Consolas,monospace;overflow-wrap:anywhere}pre{background:#e9eee5;padding:22px;white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.8 ui-monospace,Consolas,monospace}img{display:block;width:100%;height:auto}figure{margin:30px 0}figcaption{font-size:13px;color:var(--muted);margin-top:14px}.rule{font:22px/1.7 ui-monospace,Consolas,monospace;padding:18px 0;color:var(--green)}footer{max-width:1300px;margin:auto;padding:30px 44px 60px;font-size:12px;color:var(--muted)}@media(max-width:800px){main{padding:0 18px}section{padding:48px 0}.columns{grid-template-columns:1fr;gap:24px}.controls{grid-template-columns:1fr;gap:14px}.inspector{padding:16px}.counts{gap:25px}nav{gap:23px}.wide-table{font-size:14px}footer{padding:28px 18px}.aside{padding-left:16px}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
</style></head><body><nav aria-label="Report navigation"><span>PCAP / OFFLINE</span><a href="#overview">Capture</a><a href="#bytes">Bytes</a><a href="#timeline">Timeline</a><a href="#exceptions">Exceptions</a><a href="#precision">Precision</a><a href="#validation">Validation</a></nav><main>
<section id="overview"><div class="kicker">ETHERNET / IPv4 / UDP / SELECTED DNS</div><h1>Packet capture<br>analysis</h1><p class="lead">A bounded reader for classic PCAP files, with byte-level provenance, checksum verification and conservative DNS observation matching.</p><div class="counts"><div><b>5</b><small>owned synthetic capture files</small></div><div><b>54</b><small>packet records</small></div><div><b>14</b><small>explicit decoding issues</small></div><div><b>0</b><small>live network operations</small></div></div><div class="columns"><p>Every result links back to the original PCAP bytes. Malformed records are quarantined; valid but unsupported protocols are identified separately. No resynchronization is attempted after an incomplete record envelope.</p><aside class="aside">All traffic is constructed offline using documentation address ranges and <code>.test</code> names. Timestamps are synthetic. No external traffic, user browsing or physical network capture is included.</aside></div><div class="links"><a href="../README.md">Repository guide</a><a href="../results/published/captures/dns-observations.pcap">Original observation PCAP</a><a href="../results/published/packets.csv">Decoded packet CSV</a></div></section>
<section id="bytes"><h2>Packet byte inspector</h2><p>Select a record and inspect its exact bytes. Colors identify successfully decoded regions; bytes beyond a failed validation remain unverified. Offsets refer to the original PCAP file, not a reconstructed packet.</p><div class="inspector"><div class="controls"><label>Capture file<select id="capture-select"></select></label><label>Packet record<select id="record-select"></select></label></div><div class="legend"><span class="ethernet">Ethernet</span><span class="ipv4">IPv4</span><span class="udp">UDP</span><span class="dns">DNS</span><span class="unverified">Unverified / opaque</span></div><div class="bytebox" role="region" aria-label="Packet bytes, scroll horizontally" tabindex="0"><div class="hexdump" id="hex-grid"></div></div><div class="detail" id="byte-detail" aria-live="polite">Select a byte for its absolute offset.</div><div class="packetmeta" id="packet-meta"></div><p class="notice">Hex rows contain 16 actual bytes. Integer nanosecond timestamps are displayed as strings to preserve their precision in the browser.</p></div><noscript><p>The interactive inspector requires JavaScript. <a href="assets/inspector-data.json">The same bytes and offsets are available as JSON.</a></p></noscript></section>
<section id="timeline"><div class="columns"><div><h2>DNS observations</h2><p>The main capture contains 17 queries and 15 responses. Thirteen responses have one eligible prior query with the exact reversed flow, transaction ID and canonical question. One response is unmatched; another has two eligible queries and remains ambiguous.</p></div><aside class="aside">A maximum window contains 12 queries for <code>repeated.test.</code> over 220 ms. All 12 have matched responses. This is a descriptive count, with no claim of malicious intent.</aside></div><figure><img src="assets/timeline.png" alt="Actual packet timestamps across three source and response lanes, with a detailed view of the repeated-query interval"><figcaption>Green circles: queries. Blue triangles: uniquely matched responses. Orange triangles: unmatched or ambiguous responses. Gray square: the final non-DNS observation. Lines connect matched observations; they do not show actual transit paths.</figcaption></figure><p>Three queries have no unique response match within the two-second observation window. The final query is right-censored because the captured evidence ends after only 100 ms. These labels describe this file; they do not establish a resolver timeout or packet delivery failure.</p></section>
<section id="exceptions"><h2>Quarantined and unsupported records</h2><p>The corruption fixture contains one valid DNS record, ten quarantined records and four unsupported records. Every issue below retains the record index and exact fault offset. The final partial payload stops further record parsing.</p><div class="table-scroll" role="region" aria-label="Decoding issue offsets, scroll horizontally" tabindex="0"><table class="wide-table"><thead><tr><th>RECORD</th><th>FILE BYTE OFFSET</th><th>REASON</th><th>CATEGORY</th></tr></thead><tbody>@@ISSUES@@</tbody></table></div><div class="links"><a href="../results/published/captures/corruption-cases.pcap">Original corruption fixture</a><a href="../results/published/issues.csv">Issue CSV with detailed reasons</a></div><p class="notice">A checksum failure in these intentionally modified fixtures is a byte-validation result. Real capture checksum offloading is outside this study; invalid checksums alone would not establish hostile traffic.</p></section>
<section id="precision"><div class="columns"><div><h2>Timestamp precision and checksum policy</h2><p>The small endian/precision fixtures contain a query and response 789 ns apart. Nanosecond PCAP preserves the interval. Microsecond PCAP stores both at the same timestamp, so the strict-prior matching rule declines to infer order.</p><div class="table-scroll" role="region" aria-label="Timestamp precision comparison, scroll horizontally" tabindex="0"><table class="wide-table"><thead><tr><th>FORMAT</th><th>STORED DIFFERENCE</th><th>UNIQUE MATCH</th></tr></thead><tbody><tr><td>Big-endian microseconds</td><td>0 ns</td><td>No</td></tr><tr><td>Little-endian nanoseconds</td><td>789 ns</td><td>Yes</td></tr><tr><td>Big-endian nanoseconds</td><td>789 ns</td><td>Yes</td></tr></tbody></table></div></div><aside class="aside"><strong>IPv4 UDP checksum rules</strong><p>Zero on the wire means no checksum was supplied. A nonzero checksum is verified over the IPv4 pseudoheader and declared UDP datagram, padding odd length only for arithmetic.</p><p>A calculated checksum of zero is transmitted as <code>0xffff</code>. The parser tests both cases independently.</p><strong>Declared lengths</strong><p>UDP bytes beyond the declared UDP length and Ethernet padding beyond the IPv4 total length are counted separately, never fed into DNS.</p></aside></div><div class="rule">record offset + 16 = first packet byte<br>integer seconds × 10⁹ + fraction = timestamp ns</div></section>
<section id="validation"><h2>Validation and scope</h2><div class="columns"><div><h3>Independent byte checks</h3><p>Literal Ethernet/IPv4/UDP and compressed-DNS vectors, independent checksum arithmetic, all four PCAP magic variants, odd-length UDP, encoded-zero checksum, pointer loops/bounds, 500 seeded mutations, exact correlation boundaries and full artifact reconciliation.</p><h3>Bounded subset</h3><p>4 MiB per file, 4,096 records, 65,535 captured bytes per packet, 4,096 DNS bytes, 32 resource records and 32 compression pointers per name. Expanded names cannot exceed 255 bytes. Unknown DNS RDATA is length-checked and counted as opaque.</p></div><aside class="aside"><strong>Outside scope</strong><p>PCAPNG, VLANs, IPv6, TCP, IP reassembly/options, nonstandard PCAP metadata, DNSSEC validation, EDNS semantics, name resolution and live traffic.</p><p>Five warmed parse-and-analysis timings per fixture are preserved. The tiny study makes no production parser, IDS or throughput claim.</p></aside></div><pre>python -m pip install -e .
python -m unittest discover -s tests -v
python -m pcaplab results/published/captures/dns-observations.pcap
python scripts/run_study.py --out outputs/my-run</pre><div class="links"><a href="protocols.md">Protocol references</a><a href="methodology.md">Matching and provenance</a><a href="findings.md">Findings</a><a href="../results/published/manifest.json">File hashes</a><a href="../results/published/measurements.csv">Measured timings</a></div><p class="notice">AI-assisted code, fixtures and documentation. All source traffic is synthetic and owned. Primary protocol specifications and precise unsupported cases are linked in the protocol notes.</p></section></main><footer>Packet capture forensics lab · Offline analysis of generated packet bytes</footer>
<script id="capture-data" type="application/json">@@DATA@@</script><script>
const captures=JSON.parse(document.getElementById('capture-data').textContent);
const captureSelect=document.getElementById('capture-select'), recordSelect=document.getElementById('record-select');
const grid=document.getElementById('hex-grid'), detail=document.getElementById('byte-detail'), meta=document.getElementById('packet-meta');
captures.forEach((capture,i)=>{const option=document.createElement('option');option.value=i;option.textContent=capture.name;captureSelect.append(option)});
function renderRecord(){const capture=captures[Number(captureSelect.value)],record=capture.records[Number(recordSelect.value)];grid.replaceChildren();const bytes=record.hex.match(/.{1,2}/g)||[];for(let start=0;start<bytes.length;start+=16){const row=document.createElement('div');row.className='hexrow';const offset=document.createElement('span');offset.className='offset';offset.textContent=(record.offset+start).toString(16).padStart(8,'0');row.append(offset);bytes.slice(start,start+16).forEach((value,j)=>{const index=start+j,range=record.ranges.find(r=>index>=r.start&&index<r.end);const button=document.createElement('button');button.type='button';button.className='byte '+(range?range.className:'unverified');button.textContent=value;button.setAttribute('aria-label','File byte '+(record.offset+index)+', hex '+value+', '+(range?range.name:'unverified or opaque'));button.addEventListener('click',()=>{detail.textContent='File byte '+(record.offset+index)+' / 0x'+(record.offset+index).toString(16)+' · value 0x'+value+' / '+parseInt(value,16)+' · '+(range?range.name:'Unverified or opaque bytes')});row.append(button)});grid.append(row)}detail.textContent=record.issues.length?record.issues.map(i=>i.code+' at file byte '+i.byte_offset).join(' · '):'Select a byte for its absolute file offset and decoded region.';meta.textContent='Record '+record.index+' · '+record.status+' · timestamp ns '+record.timestamp_ns+'\nPCAP SHA256 '+capture.sha256;meta.style.whiteSpace='pre-wrap'}
function renderCapture(){recordSelect.replaceChildren();captures[Number(captureSelect.value)].records.forEach((record,i)=>{const option=document.createElement('option');option.value=i;option.textContent=String(record.index).padStart(2,'0')+' · '+record.status+(record.name?' · '+record.name:'');recordSelect.append(option)});renderRecord()}
captureSelect.addEventListener('change',renderCapture);recordSelect.addEventListener('change',renderRecord);renderCapture();
</script></body></html>"""
    report = report.replace("@@ISSUES@@", rows).replace(
        "@@DATA@@", json.dumps(data).replace("</", "<\\/")
    )
    (DOCS / "report.html").write_text(report, encoding="utf-8", newline="\n")
    outputs = [
        DOCS / "report.html",
        ASSETS / "timeline.png",
        ASSETS / "inspector-data.json",
    ]
    provenance = {
        "rendered_utc": datetime.now(timezone.utc).isoformat(),
        "numpy": np.__version__,
        "matplotlib": matplotlib.__version__,
        "source_sha256_lf": hashlib.sha256(
            Path(__file__).read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        ).hexdigest(),
        "inputs": {
            p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(RUN.rglob("*"))
            if p.is_file()
        },
        "outputs": {
            p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in outputs
        },
    }
    (ASSETS / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(DOCS / "report.html")


if __name__ == "__main__":
    build()
