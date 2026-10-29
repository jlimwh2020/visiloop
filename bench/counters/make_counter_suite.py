"""Generate the counter benchmark: 100 simulated feed paths with known faults and locations.

Each scenario is a random but realistic path (SPAN or TAP into a broker, with or without
counters from the tool's interface, 1G or 10G ports), carrying traffic, with 0-2 faults:

  span_oversubscribed  more mirrored than the SPAN destination port can send
  broker_congestion    more than the broker tool port can send (TAP path or a fast SPAN port)
  crc_errors           damaged frames arriving at a hop (bad cable or optic)
  nic_overrun          the tool's capture interface dropping what it receives
  link_loss            packets lost on the link between two hops

Plus below-threshold "mild" versions that must not alarm. The answer key records each
fault's expected check (path_loss or link_errors) and where it is: the device and port.
Levels avoid a no-label zone around every threshold, so labels are unambiguous.

Usage (from the repo root):  python bench/counters/make_counter_suite.py [--n 100] [--seed 7]
"""
import argparse
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
KINDS = ["span_oversubscribed", "broker_congestion", "crc_errors", "nic_overrun", "link_loss"]
CHECK = {"span_oversubscribed": "path_loss", "broker_congestion": "path_loss", "nic_overrun": "path_loss",
         "link_loss": "path_loss", "crc_errors": "link_errors"}


def make_path(rng, span, tool_counters, speeds):
    sw = rng.choice(["CORE-SW-01", "DC-CORE-1", "DIST-SW-02", "LEAF-07"])
    npb = rng.choice(["NPB-01", "VF-1", "BROKER-A"])
    tool = rng.choice(["IDS", "NDR", "SIEM", "APM"])
    in_port, out_port = rng.choice(["1", "1/1", "3"]), rng.choice(["5", "1/5", "12"])
    hops = []
    if span:
        hops.append({"name": f"{sw} Gi1/0/1 (mirrored)", "role": "span_source", "device": sw, "port": "Gi1/0/1",
                     "speed_gbps": 10, "mirrors": rng.choice(["both", "both", "rx"])})
        hops.append({"name": f"{sw} Gi1/0/48 (SPAN destination)", "role": "span_dest", "device": sw, "port": "Gi1/0/48",
                     "speed_gbps": speeds["span"]})
    else:
        hops.append({"name": "TAP-01", "role": "tap", "device": "TAP-01", "port": ""})
    hops.append({"name": f"{npb} port {in_port} (input)", "role": "broker_in", "device": npb, "port": in_port, "speed_gbps": 10})
    hops.append({"name": f"{npb} port {out_port} (to {tool})", "role": "broker_out", "device": npb, "port": out_port,
                 "speed_gbps": speeds["tool"]})
    if tool_counters:
        hops.append({"name": f"{tool} eth1", "role": "tool_in", "device": tool, "port": "eth1", "speed_gbps": speeds["tool"]})
    return hops, tool


def loc(h):
    return f"{h['device']} {h['port']}".strip()


def build(i, rng):
    n_faults = rng.choice([0, 0, 1, 1, 1, 2, 2])
    mild_only = n_faults == 0 and rng.random() < 0.5
    for _ in range(50):
        kinds = rng.sample(KINDS, n_faults)
        if {"span_oversubscribed", "broker_congestion"} <= set(kinds):
            continue
        span = "span_oversubscribed" in kinds or ("broker_congestion" not in kinds and rng.random() < 0.6)
        tool_counters = "nic_overrun" in kinds or rng.random() < 0.6
        speeds = {"tool": rng.choice([1, 1, 10]), "span": rng.choice([1, 1, 10])}
        if "broker_congestion" in kinds and span:
            speeds["span"] = 10                       # the SPAN port is fast enough; the bottleneck is the broker
        if "span_oversubscribed" in kinds:
            speeds["span"] = 1
            speeds["tool"] = rng.choice([1, 10])
        hops, tool = make_path(rng, span, tool_counters, speeds)
        roles = {h["role"]: h for h in hops}
        bottleneck = min(roles["broker_out"]["speed_gbps"], roles["span_dest"]["speed_gbps"] if span else 99)
        events, faults = [], []
        # traffic: clearly under every port speed unless a congestion fault is planned
        gbps = rng.uniform(0.15, 0.8) * bottleneck
        if "span_oversubscribed" in kinds:
            gbps = rng.uniform(1.1, 3.0) * roles["span_dest"]["speed_gbps"]
            faults.append({"kind": "span_oversubscribed", "check": "path_loss", "where": [loc(roles["span_dest"])]})
        if "broker_congestion" in kinds:
            gbps = rng.uniform(1.1, 3.0) * roles["broker_out"]["speed_gbps"]
            faults.append({"kind": "broker_congestion", "check": "path_loss", "where": [loc(roles["broker_out"])]})
        if "crc_errors" in kinds:
            h = rng.choice([roles["broker_in"]] + ([roles["tool_in"]] if tool_counters else []))
            events.append({"at": 0, "kind": "crc_errors", "hop": h["name"], "rate": rng.uniform(1e-4, 5e-3)})
            faults.append({"kind": "crc_errors", "check": "link_errors", "where": [loc(h)]})
        if "nic_overrun" in kinds:
            events.append({"at": 0, "kind": "nic_overrun", "hop": roles["tool_in"]["name"], "rate": rng.uniform(0.005, 0.05)})
            faults.append({"kind": "nic_overrun", "check": "path_loss", "where": [loc(roles["tool_in"])]})
        if "link_loss" in kinds:
            pairs = ([(roles["span_dest"], roles["broker_in"])] if span else []) + \
                    ([(roles["broker_out"], roles["tool_in"])] if tool_counters else [])
            if not pairs:
                continue
            a, b = rng.choice(pairs)
            events.append({"at": 0, "kind": "link_loss", "hop": a["name"], "rate": rng.uniform(0.003, 0.05)})
            faults.append({"kind": "link_loss", "check": "path_loss", "where": [loc(a), loc(b)]})
        mild = []
        if mild_only or (n_faults and rng.random() < 0.4):
            m = rng.choice(["crc_errors", "link_loss", "nic_overrun"])
            if m == "crc_errors" and "crc_errors" not in kinds:
                events.append({"at": 0, "kind": "crc_errors", "hop": roles["broker_in"]["name"], "rate": rng.uniform(0, 3e-6)})
                mild.append(m)
            elif m == "link_loss" and "link_loss" not in kinds and span:
                events.append({"at": 0, "kind": "link_loss", "hop": roles["span_dest"]["name"], "rate": rng.uniform(0, 0.0004)})
                mild.append(m)
            elif m == "nic_overrun" and tool_counters and "nic_overrun" not in kinds:
                events.append({"at": 0, "kind": "nic_overrun", "hop": roles["tool_in"]["name"], "rate": rng.uniform(0, 0.0004)})
                mild.append(m)
        name = f"c{i:03d}_" + ("_".join(k.split("_")[0] for k in kinds) if kinds else ("mild" if mild else "healthy"))
        return {"name": name, "tool": tool, "seconds": 60,
                "scenario": {"feed": name, "traffic": {"gbps": round(gbps, 3), "avg_packet_bytes": rng.choice([400, 700, 1000])},
                             "path": hops, "events": events},
                "faults": faults, "expected": sorted({f["check"] for f in faults}), "mild": mild}
    raise RuntimeError(f"could not build scenario {i}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    cases = [build(i, rng) for i in range(1, a.n + 1)]
    with open(os.path.join(HERE, "cases.json"), "w") as f:
        json.dump({"version": 1, "seed": a.seed, "cases": cases}, f, indent=1)
    from collections import Counter
    print(f"Wrote {len(cases)} scenarios to bench/counters/cases.json")
    print("  faults:", dict(Counter(f["kind"] for c in cases for f in c["faults"])))
    print("  healthy:", sum(not c["faults"] and not c["mild"] for c in cases), " mild only:",
          sum(not c["faults"] and bool(c["mild"]) for c in cases))


if __name__ == "__main__":
    main()
