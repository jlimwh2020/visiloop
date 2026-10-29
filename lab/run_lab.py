"""Run VisiLoop on the recorded lab captures and score it against the plan.

For each recorded test: run every check on the tool-port capture, compare with what the
plan expects, then plan the fixes and prove them in the simulated broker (verified on real
traffic where a broker-input capture was recorded). Optionally ask Muse Spark too.

Usage (from the repo root):
    python lab/run_lab.py              # checks + fixes (free)
    python lab/run_lab.py --agent      # also Muse Spark diagnosis (about US$0.01 per test)

Writes lab/RESULTS.md and lab/results.json.
"""
import argparse
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from visikit.core.schema import FeedContext      # noqa: E402
from visikit.loop import check_all, remediate    # noqa: E402
from visikit.profiles import load_profile        # noqa: E402

CAPS = os.path.join(HERE, "captures")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", action="store_true", help="also run the Muse Spark diagnosis (uses API credits)")
    a = ap.parse_args()
    with open(os.path.join(CAPS, "manifest.json")) as f:
        tests = json.load(f)["tests"]
    client = None
    if a.agent:
        from visikit.agent.diagnose import diagnose, make_client
        client = make_client()

    rows, out = [], []
    for tid in sorted(tests):
        t = tests[tid]
        feed = os.path.join(CAPS, t["file"])
        ingress = os.path.join(CAPS, t["ingress"]) if t.get("ingress") else None
        ctx = FeedContext(tid, feed, load_profile(t["tool"], t["vlans"]), ingress)
        findings = check_all(ctx)
        found = sorted({f.fault for f in findings})
        ok = set(found) == set(t["expect"])
        rec = {"test": tid, "tool": t["tool"], "expect": t["expect"], "found": found, "pass": ok,
               "findings": [f.to_dict() for f in findings], "laptop_drops": t.get("laptop_drops", 0),
               "packets": t.get("packets")}
        if findings:
            with tempfile.TemporaryDirectory() as work:
                r = remediate(ctx, findings, work)
            rec["fixes"] = [{"action": x["action"], "status": x["status"], "round": x.get("round", 1)} for x in r["fixes"]]
            rec["result"] = r["result"]
            # Without a broker-input capture, fixes that rebuild the feed cannot be verified on real traffic
            rec["verified_on_real_traffic"] = bool(ingress)
        if a.agent and findings:
            d = diagnose(ctx, client=client)
            rec["muse_spark"] = {"summary": d.get("summary"), "reported": sorted(x["fault"] for x in d["findings"]),
                                 "fixes": {x["fault"]: (x.get("recommended_fix") or {}).get("action") for x in d["findings"]},
                                 "cost_usd": d["_meta"]["cost_usd"]}
        out.append(rec)
        warn = " (laptop dropped packets: redo)" if rec["laptop_drops"] else ""
        print(f"  {tid:<28}{'PASS' if ok else 'FAIL':<6}expected {', '.join(t['expect']) or 'healthy':<26}"
              f"found {', '.join(found) or 'healthy':<26}{rec.get('result', '')}{warn}", flush=True)
        rows.append(rec)

    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump({"generated": time.strftime("%Y-%m-%d %H:%M"), "results": out}, f, indent=1)
    write_md(out)
    passed = sum(r["pass"] for r in out)
    print(f"\nChecks right on {passed}/{len(out)} lab tests. Report: lab/RESULTS.md")


def write_md(out):
    passed = sum(r["pass"] for r in out)
    md = ["# VisiLoop lab results: real traffic", "",
          f"**{passed}/{len(out)} lab tests** gave exactly the expected result. Each test set up one fault on purpose "
          "on lab equipment (see `plan.yaml`); the laptop recorded what the security tool would receive. "
          "Lab traffic only.", "",
          "| Test | Tool | Expected | VisiLoop found | Fix result | Muse Spark |", "|---|---|---|---|---|---|"]
    for r in out:
        ms = r.get("muse_spark")
        ms_txt = (", ".join(f"{k}: {v}" for k, v in ms["fixes"].items()) if ms else "-")
        res = r.get("result", "healthy")
        if r.get("fixes") and not r.get("verified_on_real_traffic"):
            res += " (simulated; no broker-input capture)"
        md.append(f"| {r['test']} | {r['tool']} | {', '.join(r['expect']) or 'healthy'} | "
                  f"{'✅ ' if r['pass'] else '❌ '}{', '.join(r['found']) or 'healthy'} | {res} | {ms_txt} |")
    issues = [r for r in out if r["laptop_drops"]]
    if issues:
        md += ["", "Tests where the capture laptop itself dropped packets (results unreliable; record again):",
               ""] + [f"- {r['test']}: {r['laptop_drops']} packets" for r in issues]
    md += ["", "## Details", ""]
    for r in out:
        md.append(f"**{r['test']}**")
        for f in r["findings"]:
            md.append(f"- {f['fault']}: {f['detail']}")
        if not r["findings"]:
            md.append("- no faults found")
        if r.get("muse_spark"):
            md.append(f"- Muse Spark: {r['muse_spark']['summary']}")
        md.append("")
    with open(os.path.join(HERE, "RESULTS.md"), "w") as f:
        f.write("\n".join(md))


if __name__ == "__main__":
    main()
