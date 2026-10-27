"""Benchmark the full loop: does every fix actually make the feed healthy?

Usage (from the repo root):
    python bench/run_loop_bench.py            # free: detectors + fixes + simulator
    python bench/run_loop_bench.py --agent    # also ask Muse Spark (uses API credits)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from visikit.core.schema import FeedContext     # noqa: E402
from visikit.loop import run_loop               # noqa: E402
from visikit.profiles import load_profile       # noqa: E402

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")


def main():
    use_agent = "--agent" in sys.argv
    with open(os.path.join(CASES, "manifest.json")) as f:
        manifest = json.load(f)
    profile = load_profile(manifest["profile"], manifest["required_vlans"])
    verified = fixable = advice = broken = 0
    cost = 0.0
    print(f"{'case':<17}{'faults before':<32}{'fixes applied':<44}{'result'}")
    print("-" * 115)
    for case in manifest["cases"]:
        ctx = FeedContext(case["name"], os.path.join(CASES, case["file"]), profile,
                          os.path.join(CASES, case["ingress"]))
        r = run_loop(ctx, use_agent=use_agent)
        before = sorted({f["fault"] for f in r["before"]})
        fixes = [f"{x['action']}" + (f"({x['params']['ports']} ports)" if x["action"] == "load_balance" else "")
                 for x in r["fixes"]]
        for x in r["fixes"]:
            if x["status"] == "verified fixed":
                verified += 1
            elif x["status"].startswith("advice"):
                advice += 1
            if not x["status"].startswith("advice"):
                fixable += 1
        if r["result"] == "still broken":
            broken += 1
        if "agent_meta" in r:
            cost += r["agent_meta"]["cost_usd"]
        print(f"{case['name']:<17}{', '.join(before) or 'none':<32}{', '.join(fixes) or '-':<44}{r['result']}")
        for x in r["fixes"]:
            line = f"    - {x['action']}: {x['status']}"
            if x["action"] == "load_balance":
                line += f" | peak {x['params']['measured_peak_gbps']} Gbps -> max {max(x['params']['per_port_peak_gbps'])} Gbps per port"
            if use_agent and x.get("agent_action"):
                line += f" | agent suggested: {x['agent_action']}"
            print(line)
    print("-" * 115)
    print(f"Fixes verified by simulation: {verified}/{fixable}")
    print(f"Advice-only items (cannot be simulated offline): {advice}")
    print(f"Cases still broken after fixes: {broken}")
    if use_agent:
        print(f"Agent cost: US${cost:.4f}")


if __name__ == "__main__":
    main()
