"""Breach story: Suricata misses a test alert on the broken feed and catches it after the fix.

The capture contains a harmless test signature in a server response. The feed reaches the IDS
through an RX-only SPAN, so that response never arrives. VisiLoop diagnoses one-way traffic,
aggregates both TAP legs, and Suricata is run again on the fixed feed.

Usage (from the repo root):  python bench/run_breach_demo.py [--agent]
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from visikit.core.schema import FeedContext     # noqa: E402
from visikit.loop import run_loop               # noqa: E402
from visikit.profiles import load_profile       # noqa: E402
from visikit.proof.ids import prove_detection   # noqa: E402

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")


def main():
    manifest = json.load(open(os.path.join(CASES, "manifest.json")))
    case = next(c for c in manifest["cases"] if c["name"] == "breach")
    ctx = FeedContext("ids-1", os.path.join(CASES, case["file"]),
                      load_profile(manifest["profile"], manifest["required_vlans"]),
                      os.path.join(CASES, case["ingress"]))
    r = run_loop(ctx, use_agent="--agent" in sys.argv, workdir=tempfile.mkdtemp(prefix="visiloop_breach_"))
    print("Diagnosis:", ", ".join(f"{f['fault']} ({f['detail']})" for f in r["before"]))
    for fx in r["fixes"]:
        print(f"Fix: {fx['action']} -> {fx['status']}")
    proof = prove_detection(ctx.pcap, r["after_pcaps"])
    print(f"\nSuricata alerts on the broken feed: {proof['before']}")
    print(f"Suricata alerts after VisiLoop's fix: {proof['after']}")
    for a in proof["after_alerts"]:
        print(f"  ALERT: {a['signature']}  {a['src']} -> {a['dst']}")
    exp = case.get("ids_alerts_expected", {})
    ok = proof["before"] == exp.get("before") and proof["after"] == exp.get("after")
    print("\nDetection proof:", "PASS" if ok else "FAIL")


if __name__ == "__main__":
    main()
