"""The soft lab's packet broker: rules from input ports to output ports, on real frames.

Inputs P1, P2 (TAP legs), P3 (SPAN), P4 (ERSPAN); outputs P5 (the tool, i.e. the capture
laptop's NIC 1) and P6 (a lossless copy of the TAP legs, NIC 2). Per input: VLAN tagging, and
for counter tests, loss on the link into the port or damaged frames (counted as input errors).
Per rule: slicing, VLAN stripping, deduplication, ERSPAN header stripping. Output ports send at
their configured line rate with a buffer, and discard when it overflows.

Configuration: <state>/broker.json, re-read when it changes:
    {"inputs": {"p1": {"vlan": 10}, "p3": {"loss": 0.03, "errors": 0}},
     "rules": [{"name": "tool", "inputs": ["p1", "p2"], "output": "p5", "slice": null,
                "strip_vlan": false, "dedup": false, "strip_erspan": false}, ...],
     "rates": {"p5": 150}}
Counters: served over SNMP v2c on the management address (P1-P6, as this broker counts them).

Run inside the broker namespace:
    python -m lab.softlab.brokerd --state lab/softlab/state --mgmt 172.30.0.6
"""
import argparse
import hashlib
import os
import random
import struct
import time

from lab.softlab.ports import STALLS, Config, Port, loop, write_json
from lab.softlab.snmp_agent import serve

DEDUP_WINDOW = 0.05          # seconds: copies of the same frame closer than this are duplicates


def tag(frame, vlan):
    return frame[:12] + struct.pack("!HH", 0x8100, vlan & 0x0FFF) + frame[12:]


def untag(frame):
    while frame[12:14] in (b"\x81\x00", b"\x88\xa8"):
        frame = frame[:12] + frame[16:]
    return frame


def strip_erspan(frame):
    """Remove Ethernet / IPv4 / GRE / ERSPAN type II, leaving the mirrored frame."""
    if frame[12:14] != b"\x08\x00" or frame[23] != 47:
        return frame
    ihl = (frame[14] & 0x0F) * 4
    gre = 14 + ihl
    flags, proto = struct.unpack("!HH", frame[gre:gre + 4])
    if proto != 0x88BE:
        return frame
    glen = 4 + 4 * bool(flags & 0x8000) + 4 * bool(flags & 0x2000) + 4 * bool(flags & 0x1000)
    return frame[gre + glen + 8:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--mgmt", default="172.30.0.6")
    ap.add_argument("--community", default="visiloop-ro")
    a = ap.parse_args()
    cfg = Config(os.path.join(a.state, "broker.json"))
    ins = {f"p{i}": Port(f"p{i}", f"P{i}", i, 1000 if i == 4 else 100, rx=True) for i in (1, 2, 3, 4)}
    outs = {"p5": Port("p5", "P5", 5, 150, rate_mbps=150, buffer_bytes=512 * 1024, stamp=True),
            "p6": Port("p6", "P6", 6, 1000, rate_mbps=1000, buffer_bytes=2 << 20, stamp=True)}
    state = {"inputs": {}, "by_input": {}, "seen": {}}

    def on_frame(port, frame, outgoing, ts, wire):
        if outgoing:
            return
        opts = state["inputs"].get(port.iface, {})
        if opts.get("loss") and random.random() < opts["loss"]:
            return                                        # lost on the link: never reaches the port
        if opts.get("errors") and random.random() < opts["errors"]:
            port.count("in_errors", 1, wire)                # damaged frame (bad CRC): counted and dropped
            return
        port.count("in_pkts", 1, wire)
        port.count("in_octets", len(frame), wire)
        if opts.get("vlan"):
            frame = tag(frame, opts["vlan"])
        for rule in state["by_input"].get(port.iface, []):
            f = frame
            if rule.get("strip_erspan"):
                f = strip_erspan(f)
            if rule.get("strip_vlan"):
                f = untag(f)
            if rule.get("dedup"):
                seen = state["seen"].setdefault(rule["name"], {})
                key = hashlib.blake2b(untag(f), digest_size=12).digest()
                if ts - seen.get(key, -1.0) < DEDUP_WINDOW:    # by arrival time, not when it was read
                    continue
                seen[key] = ts
            if rule.get("slice") and len(f) > rule["slice"]:
                f = f[:rule["slice"]]
            outs[rule["output"]].enqueue(f, ts, wire)

    def housekeeping():
        for p in list(ins.values()) + list(outs.values()):
            p.counters()                                 # file the counts that have passed the horizon
        if cfg.changed():
            d = cfg.data
            state["inputs"] = d.get("inputs", {})
            by = {}
            for rule in d.get("rules", []):
                for i in rule["inputs"]:
                    by.setdefault(i, []).append(rule)
            state["by_input"] = by
            for name, rate in (d.get("rates") or {}).items():
                outs[name].rate_mbps = outs[name].speed_mbps = rate
        now = time.time()
        for seen in state["seen"].values():
            for k in [k for k, t in seen.items() if now - t > 1.0]:
                del seen[k]
        write_json(os.path.join(a.state, "broker_health.json"),
                   {"fell_behind": sum(p.kernel_drops() for p in ins.values()),
                    "stalls_ms": dict(STALLS), "late": sum(p.late for p in outs.values())})

    def rows():
        now = time.time()                                 # one moment for every port in this answer
        return {p.index: {"name": p.name, "speed_mbps": p.speed_mbps, **p.counters(now)}
                for p in list(ins.values()) + list(outs.values())}

    housekeeping()
    serve(a.mgmt, 161, a.community, rows)
    # Frames are held 150 ms and handled in the order of the switch's timestamps (see ports.loop)
    loop(list(ins.values()), list(outs.values()), on_frame, housekeeping, hold=0.15)


if __name__ == "__main__":
    main()
