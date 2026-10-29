"""Score VisiLoop's counter checks (and optionally Muse Spark) on the counter benchmark.

For each scenario: simulate 60 s of counters along the path, run the counter checks, and
compare with the answer key: the right faults, at the right place, with a fix that suits
where the problem is. With --agent, Muse Spark diagnoses each path from the counter checks
(about US$0.01 each; resumable, with a spending cap).

Usage (from the repo root):
    python bench/counters/run_counter_suite.py                 # checks and fixes (free)
    python bench/counters/run_counter_suite.py --agent         # also Muse Spark (about US$1)

Writes bench/counters/RESULTS.md and results/.
"""
import argparse
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from visikit.core.schema import FeedContext                 # noqa: E402
from visikit.counters.simulator import Simulator            # noqa: E402
from visikit.loop import check_all, remediate               # noqa: E402
from visikit.profiles import load_profile                   # noqa: E402

RES = os.path.join(HERE, "results")
# Fixes a visibility engineer would accept, by kind of problem
GOOD = {"span_oversubscribed": {"replace_span_with_tap", "filter"},
        "broker_congestion": {"load_balance", "filter", "slice", "upgrade_port"},
        "nic_overrun": {"tool_capacity", "load_balance"},
        "link_loss": {"check_link"},
        "crc_errors": {"check_link"}}


def context(case):
    sim = Simulator(case["scenario"])
    pc = sim.measure(case["seconds"])
    return FeedContext(case["name"], None, load_profile(case["tool"], []), counters=pc)


def where_ok(case, check, location):
    return any(location in f["where"] for f in case["faults"] if f["check"] == check)


def good_fix(case, check, action):
    return any(action in GOOD[f["kind"]] for f in case["faults"] if f["check"] == check)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", action="store_true")
    ap.add_argument("--max-usd", type=float, default=3.0)
    a = ap.parse_args()
    with open(os.path.join(HERE, "cases.json")) as f:
        cases = json.load(f)["cases"]
    os.makedirs(os.path.join(RES, "agent"), exist_ok=True)
    client = None
    if a.agent:
        from visikit.agent.diagnose import diagnose, make_client
        # Only needed for paths without a recorded result; re-scoring recorded results needs no key
        client = make_client() if os.environ.get("MODEL_API_KEY") else "no-key"

    rows, spent = [], 0.0
    for c in cases:
        ctx = context(c)
        findings = check_all(ctx)
        found = sorted({f.fault for f in findings})
        exact = found == c["expected"]
        located = all(where_ok(c, f.fault, f.location) for f in findings) if exact else False
        with tempfile.TemporaryDirectory() as work:
            r = remediate(ctx, findings, work) if findings else {"fixes": []}
        fixes_ok = all(good_fix(c, x["fault"], x["action"]) for x in r["fixes"]) if exact else False
        row = {"name": c["name"], "expected": c["expected"], "found": found, "exact": exact, "located": located,
               "locations": {f.fault: f.location for f in findings}, "fixes": [(x["fault"], x["action"]) for x in r["fixes"]],
               "fixes_ok": fixes_ok, "faults": [f["kind"] for f in c["faults"]], "mild": c["mild"]}
        if client and findings:
            path = os.path.join(RES, "agent", c["name"] + ".json")
            if os.path.exists(path):
                with open(path) as f:
                    d = json.load(f)
            elif client == "no-key":
                sys.exit("MODEL_API_KEY is not set and some paths have no recorded result. Run set_key.py first.")
            elif spent + 0.03 <= a.max_usd:
                d = diagnose(ctx, client=client)
                d["_meta"]["recorded_at"] = time.strftime("%Y-%m-%d")
                with open(path, "w") as f:
                    json.dump(d, f, indent=1)
            else:
                d = None
            if d:
                spent += d["_meta"]["cost_usd"]
                rep = sorted({x["fault"] for x in d["findings"]})
                acts = {x["fault"]: (x.get("recommended_fix") or {}).get("action") for x in d["findings"]}
                row["agent"] = {"reported": rep, "exact": rep == c["expected"],
                                "fixes": acts, "fixes_ok": rep == c["expected"] and all(good_fix(c, k, v) for k, v in acts.items()),
                                "cost": d["_meta"]["cost_usd"], "seconds": d["_meta"]["seconds"],
                                "ungrounded": len(d["_meta"]["ungrounded_dropped"]), "summary": d.get("summary", "")}
        rows.append(row)
        ag = row.get("agent")
        print(f"  {c['name']:<34}{'PASS' if exact and located else 'FAIL':<6}expected {', '.join(c['expected']) or 'none':<24}"
              f"found {', '.join(f'{k}@{v}' for k, v in row['locations'].items()) or 'none':<44}"
              f"{'fix ok' if fixes_ok or not findings else 'fix ?'}"
              + (f" | Muse Spark {'PASS' if ag['exact'] and ag['fixes_ok'] else 'FAIL'}" if ag else ""), flush=True)
    with open(os.path.join(RES, "results.json"), "w") as f:
        json.dump({"generated": time.strftime("%Y-%m-%d %H:%M"), "rows": rows}, f, indent=1)
    write_md(rows)
    print(open(os.path.join(HERE, "RESULTS.md")).read())


def pct(x, n):
    return f"{x}/{n} ({x / n:.0%})" if n else "-"


def write_md(rows):
    n = len(rows)
    with_f = [r for r in rows if r["expected"]]
    by_kind = {}
    for r in rows:
        for k in r["faults"]:
            by_kind.setdefault(k, [0, 0])
            by_kind[k][1] += 1
            by_kind[k][0] += r["exact"] and r["located"]
    quiet = [r for r in rows if not r["expected"]]
    md = ["# Counter benchmark: results", "",
          f"**{n} simulated feed paths** (SPAN or TAP into a broker, with or without tool counters, 1G or 10G), each "
          "with 0-2 faults from: SPAN oversubscription, broker congestion, damaged frames, tool capture overrun and "
          "loss on a link, plus below-threshold noise that must not alarm. The answer key records each fault and "
          "where it is. See `make_counter_suite.py`.", "",
          "## Counter checks (free)", "",
          "| Measure | Result |", "|---|---|",
          f"| Right faults, at the right place | **{pct(sum(r['exact'] and r['located'] for r in rows), n)}** |",
          f"| Healthy or below-threshold paths kept quiet | {pct(sum(r['exact'] for r in quiet), len(quiet))} |",
          f"| Fix suited to where the problem is | {pct(sum(r['fixes_ok'] for r in with_f), len(with_f))} |", "",
          "| Fault | Found at the right place |", "|---|---|"]
    md += [f"| {k.replace('_', ' ')} | {pct(v[0], v[1])} |" for k, v in sorted(by_kind.items())]
    fails = [r for r in rows if not (r["exact"] and r["located"])]
    if fails:
        md += ["", "Not right:", ""] + [f"- `{r['name']}`: expected {r['expected']}, found {r['locations']}" for r in fails]
    ag = [r for r in rows if r.get("agent")]
    if ag:
        cost = sum(r["agent"]["cost"] for r in ag)
        md += ["", "## Muse Spark diagnosis from counters", "",
               "| Measure | Result |", "|---|---|",
               f"| Exactly the right faults | **{pct(sum(r['agent']['exact'] for r in ag), len(ag))}** |",
               f"| Fix suited to where the problem is | **{pct(sum(r['agent']['fixes_ok'] for r in ag), len(ag))}** |",
               f"| Ungrounded claims removed by the guard | {sum(r['agent']['ungrounded'] for r in ag)} |",
               f"| Cost | US${cost:.2f} for {len(ag)} paths (US${cost / len(ag):.4f} each) |"]
        bad = [r for r in ag if not (r["agent"]["exact"] and r["agent"]["fixes_ok"])]
        if bad:
            md += ["", "Where Muse Spark differed:", ""] + [
                f"- `{r['name']}` ({', '.join(r['faults'])}): reported {r['agent']['reported']}, fixes {r['agent']['fixes']}"
                for r in bad]
    md += ["", "Reproduce: `python bench/counters/make_counter_suite.py` then "
               "`python bench/counters/run_counter_suite.py [--agent]`.", ""]
    with open(os.path.join(HERE, "RESULTS.md"), "w") as f:
        f.write("\n".join(md))


if __name__ == "__main__":
    main()
