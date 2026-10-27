"""Run every detector on every test case and score against the answer key.

Usage (from the repo root):  python bench/run_bench.py [--detail]
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from visikit.core.registry import load_plugins          # noqa: E402
from visikit.core.schema import FeedContext             # noqa: E402
from visikit.profiles import load_profile               # noqa: E402

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")


def main():
    with open(os.path.join(CASES, "manifest.json")) as f:
        manifest = json.load(f)
    detectors, _ = load_plugins()
    profile = load_profile(manifest["profile"], manifest["required_vlans"])

    ready, todo = [], []
    for name, cls in sorted(detectors.items()):
        try:
            cls().run(FeedContext("probe", os.path.join(CASES, "clean.pcap"), profile))
            ready.append(name)
        except NotImplementedError:
            todo.append(name)

    tp = fp = fn = 0
    show_detail = "--detail" in sys.argv
    print(f"{'case':<17}{'expected':<32}{'found':<48}result")
    print("-" * 105)
    for case in manifest["cases"]:
        ctx = FeedContext(case["name"], os.path.join(CASES, case["file"]), profile)
        found, details = [], []
        for name in ready:
            for finding in detectors[name]().run(ctx):
                found.append(f"{finding.fault} ({finding.metric:.1%})")
                details.append(f"    - [{finding.severity}] {finding.detail}")
        found_faults = {f.split(" ")[0] for f in found}
        expected = set(case["faults"])
        # Only score faults whose detector exists
        expected_ready = expected & set(ready)
        tp += len(found_faults & expected_ready)
        fp += len(found_faults - expected)
        fn += len(expected_ready - found_faults)
        if expected and not expected_ready:
            result = "skip (detector not built)"
        elif found_faults == expected_ready and not (found_faults - expected):
            result = "PASS"
        else:
            result = "FAIL"
        print(f"{case['name']:<17}{', '.join(sorted(expected)) or 'none':<32}{', '.join(found) or '-':<48}{result}")
        if show_detail:
            for d in details:
                print(d)

    print("-" * 105)
    print(f"Detectors built: {len(ready)}/{len(detectors)} ({', '.join(ready)})")
    if todo:
        print(f"Still to build:  {', '.join(todo)}")
    print(f"Correct detections: {tp}   Missed: {fn}   False alarms: {fp}")


if __name__ == "__main__":
    main()
