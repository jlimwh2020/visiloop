"""Score the Muse Spark diagnosis agent on the benchmark cases.

Checks, per case: did the agent report exactly the injected faults, and did it
pick a sensible broker fix for each? Also reports cost and any ungrounded claims.

Usage (from the repo root):
    python bench/run_agent_bench.py                 # all cases
    python bench/run_agent_bench.py one_way clean   # selected cases only
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from visikit.agent.diagnose import diagnose     # noqa: E402
from visikit.core.schema import FeedContext     # noqa: E402
from visikit.profiles import load_profile       # noqa: E402

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")

# Fix actions a senior engineer would accept for each fault
GOOD_FIXES = {
    "duplicates": {"dedup"},
    "one_way": {"aggregate"},
    "packet_drops": {"load_balance", "filter", "slice"},
    "tool_overload": {"load_balance", "filter", "slice"},
    "encrypted_share": {"decrypt_advice", "filter"},
    "missing_vlan": {"vlan"},
}


def run(selected=None, client=None):
    with open(os.path.join(CASES, "manifest.json")) as f:
        manifest = json.load(f)
    profile = load_profile(manifest["profile"], manifest["required_vlans"])
    cases = [c for c in manifest["cases"] if not selected or c["name"] in selected]

    faults_ok = fixes_ok = fixes_total = ungrounded = 0
    cost = 0.0
    print(f"{'case':<17}{'expected':<32}{'agent reported':<36}{'faults':<8}{'fixes'}")
    print("-" * 100)
    for case in cases:
        ctx = FeedContext(case["name"], os.path.join(CASES, case["file"]), profile)
        try:
            d = diagnose(ctx, client=client)
        except Exception as e:  # keep going so one bad case doesn't stop the run
            print(f"{case['name']:<17}ERROR: {e}")
            continue
        meta = d["_meta"]
        cost += meta["cost_usd"]
        ungrounded += len(meta["ungrounded_dropped"])
        reported = {f["fault"]: f for f in d["findings"]}
        expected = set(case["faults"])
        f_ok = set(reported) == expected
        faults_ok += f_ok
        good = 0
        for fault in expected & set(reported):
            fixes_total += 1
            action = reported[fault].get("recommended_fix", {}).get("action")
            if action in GOOD_FIXES.get(fault, set()):
                good += 1
                fixes_ok += 1
        fix_txt = f"{good}/{len(expected & set(reported))}" if expected else "-"
        print(f"{case['name']:<17}{', '.join(sorted(expected)) or 'none':<32}"
              f"{', '.join(sorted(reported)) or 'none':<36}{'PASS' if f_ok else 'FAIL':<8}{fix_txt}")
        for fault, f in reported.items():
            print(f"    - {fault}: {f.get('root_cause', '')[:110]}")
            fix = f.get("recommended_fix", {})
            print(f"      fix: {fix.get('action')} {json.dumps(fix.get('params', {}))[:80]}")

    print("-" * 100)
    print(f"Fault diagnosis correct: {faults_ok}/{len(cases)} cases")
    print(f"Fix choice sensible:     {fixes_ok}/{fixes_total}")
    print(f"Ungrounded claims removed by guard: {ungrounded}")
    print(f"Total cost: US${cost:.4f}")


if __name__ == "__main__":
    run(sys.argv[1:] or None)
