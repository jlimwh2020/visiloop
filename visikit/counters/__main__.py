"""Measure a feed's path once and report where packets are lost.

    python -m visikit.counters --path demo/counters/span_oversubscribed.yaml          # simulated
    python -m visikit.counters --path my_path.yaml --snmp --seconds 60 --tool IDS      # real devices over SNMP
"""
import argparse

import yaml

from visikit.core.schema import FeedContext
from visikit.counters import Hop
from visikit.loop import check_all
from visikit.profiles import load_profile


def source_for(path_file, snmp):
    if snmp:
        from visikit.counters.snmp import SnmpSource
        with open(path_file) as f:
            spec = yaml.safe_load(f)
        return SnmpSource([Hop(**h) for h in spec["path"]]), spec.get("feed", "feed-1")
    from visikit.counters.simulator import Simulator
    sim = Simulator(path_file)
    return sim, sim.feed


def main():
    ap = argparse.ArgumentParser(description="Locate packet loss along a feed's path from interface counters")
    ap.add_argument("--path", required=True, help="path file (YAML): hops, and SNMP details or a simulated scenario")
    ap.add_argument("--snmp", action="store_true", help="read real devices over SNMP (default: simulate)")
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--tool", default="IDS")
    a = ap.parse_args()
    src, feed = source_for(a.path, a.snmp)
    print(f"Measuring {feed} for {a.seconds:g} s ...")
    pc = src.measure(a.seconds)
    for h in pc.hops:
        d = pc.delta(h)
        if d is None:
            continue
        print(f"  {h.name:<42} in {d.in_pkts:>12,}  out {d.out_pkts:>12,}  discards {d.in_discards + d.out_discards:>9,}"
              f"  errors {d.in_errors:>6,}  {pc.gbps(max(d.in_octets, d.out_octets)):.2f} Gbps")
    findings = check_all(FeedContext(feed, None, load_profile(a.tool, []), counters=pc))
    if not findings:
        print("No loss or errors along the path.")
    for f in findings:
        print(f"\n{f.fault} at {f.location} ({f.metric:.2%}): {f.detail}")


if __name__ == "__main__":
    main()
