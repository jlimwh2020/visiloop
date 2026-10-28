"""Run the Muse Spark diagnosis agent on every suite case (uses Meta Model API credits).

About US$0.01 and 9 seconds per case: roughly US$2 for 200 cases. Each result is saved
as soon as it arrives, so the run can be stopped and resumed; finished cases are
skipped. A spending cap stops the run before it costs more than --max-usd.

Usage (from the repo root, with MODEL_API_KEY set):
    python bench/suite/run_suite_agent.py --limit 5        # try 5 cases first
    python bench/suite/run_suite_agent.py                  # the rest (resumes)
    python bench/suite/run_suite_agent.py --max-usd 3 --workers 3
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from visikit.agent.diagnose import diagnose, make_client   # noqa: E402
from visikit.core.schema import FeedContext                 # noqa: E402
from visikit.profiles import load_profile                   # noqa: E402

CASES = os.path.join(HERE, "cases")


def out_dir(manifest):
    """Each suite version keeps its own results (version 1 used results/agent)."""
    v = manifest.get("version", 1)
    return os.path.join(HERE, "results", "agent" if v == 1 else f"agent-v{v}")


OUT = None


def spent():
    total = 0.0
    for name in os.listdir(OUT):
        with open(os.path.join(OUT, name)) as f:
            total += json.load(f).get("_meta", {}).get("cost_usd", 0)
    return total


def run_case(case, client):
    ctx = FeedContext(case["name"], os.path.join(CASES, case["file"]),
                      load_profile(case["tool"], case["required_vlans"]))
    last = None
    for attempt in range(3):
        try:
            d = diagnose(ctx, client=client)
            d["_meta"]["recorded_at"] = time.strftime("%Y-%m-%d")
            with open(os.path.join(OUT, case["name"] + ".json"), "w") as f:
                json.dump(d, f, indent=1)
            return case["name"], d, None
        except Exception as e:      # rate limits, timeouts, unparseable answers: retry, then record
            last = e
            time.sleep(5 * (attempt + 1))
    return case["name"], None, f"{type(last).__name__}: {last}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="run at most this many new cases")
    ap.add_argument("--max-usd", type=float, default=5.0, help="stop before total spend passes this")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("cases", nargs="*")
    a = ap.parse_args()
    if not os.environ.get("MODEL_API_KEY"):
        sys.exit("MODEL_API_KEY is not set. Run set_key.py first, then open a new terminal.")
    global OUT
    with open(os.path.join(CASES, "manifest.json")) as f:
        manifest = json.load(f)
    cases = manifest["cases"]
    OUT = OUT or out_dir(manifest)
    os.makedirs(OUT, exist_ok=True)
    print(f"Suite version {manifest.get('version', 1)}; results go to {OUT}")
    todo = [c for c in cases if (not a.cases or c["name"] in a.cases)
            and not os.path.exists(os.path.join(OUT, c["name"] + ".json"))]
    if a.limit:
        todo = todo[:a.limit]
    total = spent()
    print(f"{len(todo)} cases to run, US${total:.4f} already spent, cap US${a.max_usd:.2f}")
    client = make_client()
    errors = []
    done = 0
    with ThreadPoolExecutor(a.workers) as pool:
        pending = {}
        queue = list(todo)
        while queue or pending:
            # leave room for the cases already in flight (about US$0.02 each at most)
            while queue and len(pending) < a.workers and total + 0.02 * (len(pending) + 1) <= a.max_usd:
                c = queue.pop(0)
                pending[pool.submit(run_case, c, client)] = c
            if not pending:
                print(f"Stopped: spend cap reached (US${total:.4f})")
                break
            fut = next(as_completed(pending))
            case = pending.pop(fut)
            name, d, err = fut.result()
            done += 1
            if err:
                errors.append((name, err))
                print(f"  [{done}/{len(todo)}] {name:<18} ERROR {err[:90]}", flush=True)
                continue
            total += d["_meta"]["cost_usd"]
            reported = sorted(f["fault"] for f in d["findings"])
            ok = set(reported) == set(case["faults"])
            print(f"  [{done}/{len(todo)}] {name:<18}{'PASS' if ok else 'FAIL':<6}"
                  f"expected {', '.join(case['faults']) or 'none':<40} agent {', '.join(reported) or 'none':<40}"
                  f"US${d['_meta']['cost_usd']:.4f} {d['_meta']['seconds']}s", flush=True)
    print(f"Done. Total spend US${total:.4f}. Errors: {len(errors)}")
    for name, err in errors:
        print(f"  {name}: {err}")
    print("Next: python bench/suite/make_report.py")


if __name__ == "__main__":
    main()
