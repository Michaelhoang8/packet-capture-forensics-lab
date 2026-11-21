"""Conservative DNS observation matching; no malicious-activity attribution."""

from collections import defaultdict, deque


def analyze(
    capture, timeout_ns=2_000_000_000, burst_window_ns=500_000_000, burst_threshold=5
):
    for value in (timeout_ns, burst_window_ns, burst_threshold):
        if type(value) is not int or value <= 0:
            raise ValueError("Analysis thresholds must be positive integers")
    valid_times = [
        r.timestamp_ns
        for r in capture.records
        if r.timestamp_ns is not None
        and r.available_length == r.captured_length
        and r.captured_length <= min(r.original_length, capture.metadata["snaplen"])
    ]
    end = max(valid_times, default=None)
    records = sorted(
        (r for r in capture.records if r.status == "dns"),
        key=lambda r: (r.timestamp_ns, r.index),
    )
    pending = defaultdict(list)
    queries, responses, matches = [], [], []
    windows, peaks = defaultdict(deque), {}
    for record in records:
        ip, udp, dns = (record.layers[name] for name in ("ipv4", "udp", "dns"))
        question = (dns["id"], dns["name_key"], dns["qtype"], dns["qclass"])
        if not dns["response"]:
            key = (
                ip["source"],
                udp["source_port"],
                ip["destination"],
                udp["destination_port"],
                *question,
            )
            query = {
                "record_index": record.index,
                "timestamp_ns": record.timestamp_ns,
                "name": dns["name"],
                "client": ip["source"],
                "server": ip["destination"],
                "status": "pending",
                "ambiguous_response_indices": [],
                "ambiguous_response_count": 0,
            }
            pending[key].append(query)
            queries.append(query)
            burst_key = (
                ip["source"],
                ip["destination"],
                dns["name_key"],
                dns["qtype"],
                dns["qclass"],
            )
            window = windows[burst_key]
            while (
                window
                and record.timestamp_ns - window[0].timestamp_ns > burst_window_ns
            ):
                window.popleft()
            window.append(record)
            if len(window) >= burst_threshold and len(window) > peaks.get(
                burst_key, {}
            ).get("count", 0):
                peaks[burst_key] = {
                    "client": ip["source"],
                    "server": ip["destination"],
                    "name": dns["name"],
                    "count": len(window),
                    "first_ns": window[0].timestamp_ns,
                    "last_ns": record.timestamp_ns,
                    "record_indices": [r.index for r in window],
                }
        else:
            key = (
                ip["destination"],
                udp["destination_port"],
                ip["source"],
                udp["source_port"],
                *question,
            )
            candidates = [
                q
                for q in pending[key]
                if q["status"] == "pending"
                and 0 < record.timestamp_ns - q["timestamp_ns"] <= timeout_ns
            ]
            response = {
                "record_index": record.index,
                "timestamp_ns": record.timestamp_ns,
                "name": dns["name"],
                "status": "unmatched",
                "candidate_count": len(candidates),
                "candidate_indices": [q["record_index"] for q in candidates[:8]],
            }
            if len(candidates) == 1:
                query = candidates[0]
                query["status"] = "matched"
                response["status"] = "matched"
                matches.append(
                    {
                        "query_index": query["record_index"],
                        "response_index": record.index,
                        "name": dns["name"],
                        "client": query["client"],
                        "server": query["server"],
                        "latency_ns": record.timestamp_ns - query["timestamp_ns"],
                        "rcode_low4": dns["rcode_low4"],
                    }
                )
            elif len(candidates) > 1:
                response["status"] = "ambiguous"
                for query in candidates:
                    query["ambiguous_response_count"] += 1
                    if len(query["ambiguous_response_indices"]) < 8:
                        query["ambiguous_response_indices"].append(record.index)
            responses.append(response)
    for query in queries:
        if query["status"] == "pending":
            query["status"] = (
                "unanswered_within_window"
                if end - query["timestamp_ns"] >= timeout_ns
                else "right_censored"
            )
    return {
        "timeout_ns": timeout_ns,
        "burst_window_ns": burst_window_ns,
        "burst_threshold": burst_threshold,
        "capture_end_ns": end,
        "queries": queries,
        "responses": responses,
        "matches": matches,
        "burst_windows": list(peaks.values()),
        "scope": "Observed exact-key matches only; no server receipt, resolver timeout, attack or intent inference",
    }
