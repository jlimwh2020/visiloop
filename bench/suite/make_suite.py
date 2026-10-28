"""Generate the VisiLoop benchmark suite: 200 varied, seeded test cases.

Each case varies the tool (IDS, NDR, APM, SIEM), its required VLANs, the traffic mix
and size, and injects 0-3 faults at clear or near-threshold levels, often with a
below-threshold "mild" fault as noise. Some cases test tool awareness: heavy TLS on a
tool that tolerates it, untagged traffic on a tool that needs no VLANs, or one-way
traffic on a SIEM (which does not need both directions), must NOT alarm.

The answer key is computed by this script directly from the packets it wrote (pure
Python, no tshark), so it is independent of VisiLoop's checks. Cases whose true value
lands too close to a threshold (a "no-label zone") are regenerated, so every label is
unambiguous.

Writes bench/suite/cases/<case>.pcap, <case>_ingress.pcap (when it differs) and
manifest.json. Deterministic: the same --seed always gives the same suite.

Usage (from the repo root):
    python bench/suite/make_suite.py               # 200 cases
    python bench/suite/make_suite.py --n 40        # smaller suite (same mix, scaled)
"""
import argparse
import hashlib
import json
import os
import random
import sys
import tempfile
from collections import defaultdict, deque

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))                       # bench/ (make_clean)
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))      # repo root (visikit)

from scapy.all import IP, TCP, UDP, Dot1Q, Ether, rdpcap, wrpcap   # noqa: E402

from make_clean import generate                                  # noqa: E402
from visikit.profiles import load_profile                        # noqa: E402

CASES = os.path.join(HERE, "cases")
FAULTS = ["duplicates", "one_way", "packet_drops", "tool_overload", "encrypted_share", "missing_vlan"]
TOOLS = ["IDS"] * 8 + ["NDR"] * 5 + ["APM"] * 3 + ["SIEM"] * 4

# Labels. VisiLoop's packet-drop threshold (1% of TCP packets flagged) corresponds to
# about 0.67% true loss: each lost packet is flagged about 1.5 times (measured).
LIMITS = {"duplicates": 0.05, "one_way": 0.10, "packet_drops": 0.0067, "tool_overload": 0.8, "untagged": 0.05}
GRAY = {"duplicates": (0.035, 0.07), "one_way": (0.07, 0.14), "packet_drops": (0.004, 0.011),
        "tool_overload": (0.6, 1.05), "untagged": (0.03, 0.08), "encrypted_margin": 0.06}


# ---------------------------------------------------------------- injections
def flow_key(p):
    ip, l4 = p[IP], p[TCP]
    return tuple(sorted([(ip.src, l4.sport), (ip.dst, l4.dport)]))


def add_duplicates(pkts, rng, share):
    out = []
    for p in pkts:
        out.append(p)
        if rng.random() < share:
            d = p.copy()
            d.time = p.time + 0.000001
            out.append(d)
    return out


def make_one_way(pkts, rng, share):
    flows = sorted({flow_key(p) for p in pkts if p.haslayer(TCP)})
    chosen = set(rng.sample(flows, round(len(flows) * share)))
    return [p for p in pkts if not (p.haslayer(TCP) and flow_key(p) in chosen and p[TCP].sport in (80, 443))]


def make_drops(pkts, rng, share):
    return [p for p in pkts if not (p.haslayer(TCP) and len(p[TCP].payload) > 0 and rng.random() < share)]


def compress(pkts, target_gbps):
    """Squeeze the whole capture into a window that averages target_gbps (a burst)."""
    total = sum(len(bytes(p)) for p in pkts)
    window = total * 8 / (target_gbps * 1e9)
    t0, span = float(pkts[0].time), float(pkts[-1].time) - float(pkts[0].time)
    for p in pkts:
        p.time = t0 + (float(p.time) - t0) / span * window
    return pkts


def untag(p):
    if not p.haslayer(Dot1Q):
        return p
    q = Ether(src=p[Ether].src, dst=p[Ether].dst) / p[Dot1Q].payload
    q.time = p.time
    return q


def strip_vlans(pkts, rng, mode, share=0.0):
    if mode == "all":                       # broker strips every tag
        return [untag(p) for p in pkts]
    if mode == "server_leg":                # one input leg arrives untagged (VLAN 20 disappears)
        return [untag(p) if p.haslayer(Dot1Q) and p[Dot1Q].vlan == 20 else p for p in pkts]
    return [untag(p) if rng.random() < share else p for p in pkts]     # "some": a few untagged frames


# ---------------------------------------------------------------- answer key (independent of tshark)
def truth(feed, injected_loss, profile):
    lens = [len(bytes(p)) for p in feed]
    total = sum(lens)

    # duplicates: identical frame bytes seen within the last 500 frames
    recent, seen_in_window, dups = deque(), defaultdict(int), 0
    for p in feed:
        h = hashlib.md5(bytes(p)).digest()
        if seen_in_window[h]:
            dups += 1
        recent.append(h)
        seen_in_window[h] += 1
        if len(recent) > 500:
            seen_in_window[recent.popleft()] -= 1
    dup_rate = dups / len(feed)

    # one-way: TCP sessions with packets from only one side
    senders = defaultdict(set)
    for p in feed:
        if p.haslayer(TCP):
            senders[flow_key(p)].add(p[IP].src)
    one_way = sum(len(s) == 1 for s in senders.values()) / max(1, len(senders))

    tcp_pkts = sum(p.haslayer(TCP) for p in feed)
    loss = injected_loss / max(1, tcp_pkts)

    # peak load in 1 ms intervals, relative to the first frame
    t0, bins = float(feed[0].time), defaultdict(int)
    for p, n in zip(feed, lens):
        bins[int((float(p.time) - t0) / 0.001)] += n
    load = max(bins.values()) * 8 / 0.001 / 1e9 / profile.max_rate_gbps

    def encrypted(p):
        l4 = p[TCP] if p.haslayer(TCP) else p[UDP] if p.haslayer(UDP) else None
        return l4 is not None and 443 in (l4.sport, l4.dport)
    enc = sum(n for p, n in zip(feed, lens) if encrypted(p)) / total

    tags = [p[Dot1Q].vlan if p.haslayer(Dot1Q) else None for p in feed]
    untagged = tags.count(None) / len(feed)
    missing = sorted(set(profile.required_vlans) - {t for t in tags if t is not None})

    metrics = {"duplicates": dup_rate, "one_way": one_way, "packet_drops": loss, "tool_overload": load,
               "encrypted_share": enc, "untagged": untagged, "missing_vlans": missing}
    labels = {
        "duplicates": dup_rate > LIMITS["duplicates"],
        "one_way": profile.needs_both_directions and one_way > LIMITS["one_way"],
        "packet_drops": loss > LIMITS["packet_drops"],
        "tool_overload": load > LIMITS["tool_overload"],
        "encrypted_share": enc > profile.max_encrypted_share,
        "missing_vlan": bool(profile.required_vlans) and (bool(missing) or untagged > LIMITS["untagged"]),
    }
    gray = [k for k in ("duplicates", "one_way", "packet_drops", "tool_overload")
            if GRAY[k][0] < metrics[k] < GRAY[k][1] and (k != "one_way" or profile.needs_both_directions)]
    if profile.max_encrypted_share < 1 and abs(enc - profile.max_encrypted_share) < GRAY["encrypted_margin"]:
        gray.append("encrypted_share")
    if profile.required_vlans and not missing and GRAY["untagged"][0] < untagged < GRAY["untagged"][1]:
        gray.append("missing_vlan")
    return labels, {k: (round(v, 4) if isinstance(v, float) else v) for k, v in metrics.items()}, gray


# ---------------------------------------------------------------- case plan
def plan(n, rng):
    """Case mix for a 200-case suite, scaled to n."""
    mix = [("clean", 20), ("mild", 30), ("single", 60), ("double", 50), ("triple", 25), ("tool_aware", 15)]
    out = []
    for kind, count in mix:
        out += [kind] * max(1, round(count * n / 200))
    out = out[:n]
    while len(out) < n:
        out.append("double")
    singles = [FAULTS[i % len(FAULTS)] for i in range(out.count("single"))]
    rng.shuffle(singles)
    result = []
    for kind in out:
        if kind == "single":
            result.append((kind, [singles.pop()]))
        elif kind == "double":
            result.append((kind, rng.sample(FAULTS, 2)))
        elif kind == "triple":
            result.append((kind, rng.sample(FAULTS, 3)))
        else:
            result.append((kind, []))
    return result


def pick_tool(rng, faults):
    """A tool type on which every requested fault is possible."""
    options = TOOLS
    if "encrypted_share" in faults:
        options = [t for t in options if t in ("IDS", "NDR")]    # APM and SIEM tolerate 100% TLS
    if "one_way" in faults:
        options = [t for t in options if t != "SIEM"]            # a SIEM does not need both directions
    return rng.choice(options)


def levels(rng, faults, mild, kind, profile):
    """Injection settings. 'near' levels sit just outside the no-label zone."""
    lv = {}
    for f in faults:
        near = rng.random() < 0.3
        if f == "duplicates":
            lv[f] = rng.uniform(0.085, 0.11) if near else rng.uniform(0.11, 0.40)
        elif f == "one_way":
            lv[f] = rng.uniform(0.17, 0.22) if near else rng.uniform(0.22, 0.80)
        elif f == "packet_drops":
            lv[f] = rng.uniform(0.03, 0.04) if near else rng.uniform(0.04, 0.15)
        elif f == "tool_overload":
            lv[f] = rng.uniform(1.15, 1.4) if near else rng.uniform(1.4, 5.0)
        elif f == "encrypted_share":
            lim = profile.max_encrypted_share
            lv[f] = min(0.995, lim + (rng.uniform(0.08, 0.12) if near else rng.uniform(0.12, 0.35)))
        elif f == "missing_vlan":
            lv[f] = rng.choice(["all", "server_leg"])
    for f in mild:
        if f == "duplicates":
            lv[f] = rng.uniform(0.0, 0.025)
        elif f == "one_way":
            lv[f] = rng.uniform(0.0, 0.05)
        elif f == "packet_drops":
            lv[f] = rng.uniform(0.0, 0.006)
        elif f == "tool_overload":
            lv[f] = rng.uniform(0.15, 0.5)
        elif f == "encrypted_share":
            lv[f] = max(0.02, profile.max_encrypted_share - rng.uniform(0.15, 0.4))
        elif f == "missing_vlan":
            lv[f] = ("some", rng.uniform(0.0, 0.02))
    return lv


def build_case(idx, kind, faults, rng, workdir):
    """Returns (case dict, feed packets, ingress packets or None) with an unambiguous key."""
    for attempt in range(12):
        tool = "SIEM" if kind == "tool_aware" and rng.random() < 0.5 else ("APM" if kind == "tool_aware" else pick_tool(rng, faults))
        need_vlans = "missing_vlan" in faults or rng.random() < 0.7
        if kind == "tool_aware":
            need_vlans = False
        vlans_req = [10, 20] if need_vlans else []
        profile = load_profile(tool, vlans_req)

        others = [f for f in FAULTS if f not in faults]
        if kind == "clean":
            mild = []
        elif kind == "mild":
            mild = rng.sample(others, rng.randint(1, 3))
        elif kind == "tool_aware":
            mild = []
        else:
            mild = rng.sample(others, 1) if rng.random() < 0.5 else []
        if "missing_vlan" in mild and not vlans_req:
            mild.remove("missing_vlan")
        lv = levels(rng, faults, mild, kind, profile)
        if kind == "tool_aware" and tool == "SIEM":
            lv["one_way"] = rng.uniform(0.2, 0.6)        # one-way traffic on a SIEM: must not alarm

        # traffic
        big = "tool_overload" in faults and profile.max_rate_gbps >= 10
        sessions = rng.randint(450, 600) if big else rng.randint(100, 220)
        if "encrypted_share" in lv:
            tls = lv["encrypted_share"]
        elif kind == "tool_aware":
            tls = rng.uniform(0.75, 0.98)
        else:
            tls = rng.uniform(0.05, max(0.06, min(0.5, profile.max_encrypted_share - 0.2)))
        seed = rng.randint(1, 10**9)
        base = os.path.join(workdir, "base.pcap")
        generate(base, sessions=sessions, dns=rng.randint(20, 80), tls_share=tls,
                 duration=rng.uniform(5, 15), seed=seed)
        prng = random.Random(seed)

        # ingress: what the broker receives (overlapping TAPs -> duplicates, bursts -> overload)
        ingress = list(rdpcap(base))
        if "duplicates" in lv:
            ingress = add_duplicates(ingress, prng, lv["duplicates"])
        if "tool_overload" in lv:
            ingress = compress(ingress, lv["tool_overload"] * profile.max_rate_gbps)

        # feed: what the tool receives after SPAN / broker mistakes
        feed = list(ingress)
        changed = False
        if "one_way" in lv and lv["one_way"] > 0:
            feed, changed = make_one_way(feed, prng, lv["one_way"]), True
        before = len(feed)
        if "packet_drops" in lv:
            feed, changed = make_drops(feed, prng, lv["packet_drops"]), True
        lost = before - len(feed)
        if kind == "tool_aware" and rng.random() < 0.6:
            feed, changed = strip_vlans(feed, prng, "all"), True          # no VLANs required: must not alarm
        if "missing_vlan" in lv:
            mode = lv["missing_vlan"]
            feed = strip_vlans(feed, prng, mode[0], mode[1]) if isinstance(mode, tuple) else strip_vlans(feed, prng, mode)
            changed = True

        labels, metrics, gray = truth(feed, lost, profile)
        expected = sorted(f for f, v in labels.items() if v)
        if gray or set(expected) != set(faults):
            continue                                                       # ambiguous or off-plan: try again
        name = f"s{idx:03d}_{kind}"
        case = {"name": name, "kind": kind, "tool": tool, "required_vlans": vlans_req,
                "faults": expected, "injected": sorted(faults), "mild": sorted(mild),
                "levels": {k: (round(v, 4) if isinstance(v, float) else v) for k, v in lv.items()},
                "near_threshold": False, "truth": metrics, "sessions": sessions, "tls_share": round(tls, 3),
                "attempts": attempt + 1, "file": name + ".pcap",
                "ingress": name + ("_ingress.pcap" if changed else ".pcap")}
        return case, feed, (ingress if changed else None)
    raise RuntimeError(f"could not build an unambiguous case {idx} ({kind} {faults})")


def near(case):
    """Flag cases whose fault sits close to its threshold (harder)."""
    t, lim = case["truth"], LIMITS
    checks = {"duplicates": t["duplicates"] < 0.1, "one_way": t["one_way"] < 0.2,
              "packet_drops": t["packet_drops"] < 0.015, "tool_overload": t["tool_overload"] < 1.4}
    return any(checks.get(f, False) for f in case["faults"])


def main():
    ap = argparse.ArgumentParser(description="Generate the VisiLoop benchmark suite")
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    os.makedirs(CASES, exist_ok=True)
    rng = random.Random(a.seed)
    manifest = {"version": 2, "seed": a.seed, "limits": LIMITS, "gray_zones": GRAY, "cases": []}
    work = tempfile.mkdtemp(prefix="suite_")
    for i, (kind, faults) in enumerate(plan(a.n, rng), start=1):
        case, feed, ingress = build_case(i, kind, faults, rng, work)
        case["near_threshold"] = near(case)
        wrpcap(os.path.join(CASES, case["file"]), feed)
        if ingress is not None:
            wrpcap(os.path.join(CASES, case["ingress"]), ingress)
        manifest["cases"].append(case)
        print(f"  {case['name']:<18}{case['tool']:<6}{', '.join(case['faults']) or 'none':<50}"
              f"{'mild: ' + ', '.join(case['mild']) if case['mild'] else ''}", flush=True)
    with open(os.path.join(CASES, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    kinds = defaultdict(int)
    for c in manifest["cases"]:
        kinds[c["kind"]] += 1
    print(f"Wrote {len(manifest['cases'])} cases to {CASES}: " + ", ".join(f"{k} {v}" for k, v in kinds.items()))


if __name__ == "__main__":
    main()
