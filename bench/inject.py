"""Create one damaged capture per fault type from a healthy baseline.

Writes bench/cases/*.pcap and bench/cases/manifest.json (the answer key).
"""
import json
import os
import random

from scapy.all import IP, TCP, rdpcap, wrpcap

from make_clean import generate

CASES = os.path.join(os.path.dirname(__file__), "cases")


def _flow_key(p):
    ip, tcp = p[IP], p[TCP]
    a, b = (ip.src, tcp.sport), (ip.dst, tcp.dport)
    return tuple(sorted([a, b]))


def _save(name, pkts):
    path = os.path.join(CASES, name + ".pcap")
    wrpcap(path, pkts)
    return path


def inject_duplicates(pkts, rng, share=0.15):
    out = []
    for p in pkts:
        out.append(p)
        if rng.random() < share:
            d = p.copy()
            d.time = p.time + 0.000001
            out.append(d)
    return out


def inject_one_way(pkts, rng, share=0.4):
    flows = sorted({_flow_key(p) for p in pkts if p.haslayer(TCP)})
    chosen = set(rng.sample(flows, int(len(flows) * share)))
    out = []
    for p in pkts:
        if p.haslayer(TCP) and _flow_key(p) in chosen and p[TCP].sport in (80, 443):
            continue  # drop the server-to-client direction
        out.append(p)
    return out


def inject_drops(pkts, rng, share=0.08):
    out = []
    for p in pkts:
        if p.haslayer(TCP) and len(p[TCP].payload) > 0 and rng.random() < share:
            continue  # data segment lost before reaching the tool
        out.append(p)
    return out


def inject_overload(pkts, window=0.002):
    t0 = float(pkts[0].time)
    span = float(pkts[-1].time) - t0
    for p in pkts:
        p.time = t0 + (float(p.time) - t0) / span * window
    return pkts


def main():
    os.makedirs(CASES, exist_ok=True)
    rng = random.Random(42)
    clean = os.path.join(CASES, "clean.pcap")
    generate(clean)
    base = lambda: rdpcap(clean)

    manifest = {"profile": "IDS", "required_vlans": [10, 20], "cases": []}

    def add(name, faults, path):
        manifest["cases"].append({"name": name, "file": os.path.basename(path), "faults": faults})
        print(f"  {name:<16} -> {os.path.basename(path)}  expected: {faults or ['none']}")

    add("clean", [], clean)
    add("duplicates", ["duplicates"], _save("duplicates", inject_duplicates(base(), rng)))
    add("one_way", ["one_way"], _save("one_way", inject_one_way(base(), rng)))
    add("packet_drops", ["packet_drops"], _save("packet_drops", inject_drops(base(), rng)))
    add("tool_overload", ["tool_overload"], _save("tool_overload", inject_overload(base())))
    enc = os.path.join(CASES, "encrypted_share.pcap")
    generate(enc, tls_share=0.85, seed=2)
    add("encrypted_share", ["encrypted_share"], enc)
    nov = os.path.join(CASES, "missing_vlan.pcap")
    generate(nov, vlans=False, seed=3)
    add("missing_vlan", ["missing_vlan"], nov)

    with open(os.path.join(CASES, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Wrote {len(manifest['cases'])} cases and manifest.json to {CASES}")


if __name__ == "__main__":
    main()
