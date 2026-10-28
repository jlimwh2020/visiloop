"""Run VisiLoop's checks and the full diagnose -> fix -> prove loop on the suite (free).

For every case: run all six checks on the tool feed and compare with the answer key,
then plan the fixes, apply them in the simulated broker and re-check every tool port.
Writes bench/suite/results/checks.json; make_report.py turns it into RESULTS.md.

Usage (from the repo root):
    python bench/suite/run_suite.py              # all cases, 2 workers
    python bench/suite/run_suite.py --workers 4
"""
import argparse
import json
import os
import sys
import tempfile
import time
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from visikit.core.schema import FeedContext    # noqa: E402
from visikit.loop import check_all, remediate  # noqa: E402
from visikit.profiles import load_profile      # noqa: E402

CASES = os.path.join(HERE, "cases")
RESULTS = os.path.join(HERE, "results")


def one(case):
    profile = load_profile(case["tool"], case["required_vlans"])
    ctx = FeedContext(case["name"], os.path.join(CASES, case["file"]), profile,
                      os.path.join(CASES, case["ingress"]))
    t = time.time()
    findings = check_all(ctx)
    check_s = time.time() - t
    found = sorted({f.fault for f in findings})
    out = {"name": case["name"], "expected": case["faults"], "found": found,
           "metrics": {f.fault: f.metric for f in findings}, "check_seconds": round(check_s, 2)}
    if findings:
        with tempfile.TemporaryDirectory() as work:
            r = remediate(ctx, findings, work)
        out["loop"] = {"fixes": [{"fault": x["fault"], "action": x["action"], "status": x["status"],
                                  **({"ports": x["params"]["ports"]} if x["action"] == "load_balance" else {})}
                                 for x in r["fixes"]],
                       "after": {p: sorted({f["fault"] for f in fs}) for p, fs in r["after"].items()},
                       "new_faults": r["new_faults"], "unresolved": r["unresolved"], "result": r["result"],
                       "tool_ports_after": r["tool_ports_after"]}
    else:
        out["loop"] = {"fixes": [], "result": "healthy (no faults found)"}
    out["seconds"] = round(time.time() - t, 2)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("cases", nargs="*")
    a = ap.parse_args()
    with open(os.path.join(CASES, "manifest.json")) as f:
        manifest = json.load(f)
    cases = [c for c in manifest["cases"] if not a.cases or c["name"] in a.cases]
    os.makedirs(RESULTS, exist_ok=True)
    results = []
    with Pool(a.workers) as pool:
        for r in pool.imap(one, cases):
            ok = set(r["found"]) == set(r["expected"])
            print(f"  {r['name']:<18}{'PASS' if ok else 'FAIL':<6}expected {', '.join(r['expected']) or 'none':<45}"
                  f"found {', '.join(r['found']) or 'none':<45}{r['loop']['result']}", flush=True)
            results.append(r)
    with open(os.path.join(RESULTS, "checks.json"), "w") as f:
        json.dump({"generated": time.strftime("%Y-%m-%d %H:%M"), "results": results}, f, indent=1)
    exact = sum(set(r["found"]) == set(r["expected"]) for r in results)
    print(f"Checks exactly right on {exact}/{len(results)} cases. Saved to {RESULTS}/checks.json")


if __name__ == "__main__":
    main()
