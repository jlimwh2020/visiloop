"""Run SAM 3.1 and Muse Spark on every stress-test diagram (uses Meta Model API credits).

For each diagram: SAM 3.1 is called once per shape prompt and every prompt's boxes are
saved, then Muse Spark reads the diagram once per variant:
  baseline  - the original prompts ("rounded rectangle box", "ellipse")
  extended  - the original prompts plus seven more shape names
  improved  - VisiLoop's current prompts (baseline + "hexagon", chosen from the first run)
              and the current reader, which also lists devices that have no tag
Results are saved per diagram as they arrive, so the run can be stopped and resumed.
A diagram that already has results only gets the variants it is missing, re-using the
SAM boxes already recorded. First run: about US$2. Adding "improved": about US$1.50.

Usage (from the repo root, with MODEL_API_KEY set):
    python bench/diagrams/run_diagrams.py --limit 2      # try two diagrams first
    python bench/diagrams/run_diagrams.py                # the rest (resumes)
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))

from PIL import Image                                                     # noqa: E402

from visikit.vision.diagram import (SAM_PROMPTS, _client, _data_url,      # noqa: E402
                                    merge_boxes, read_inventory, sam_prompt_boxes)

BASELINE = ["rounded rectangle box", "ellipse"]
EXTRA_PROMPTS = ["rectangle", "hexagon", "cylinder", "octagon", "trapezoid", "parallelogram", "circle"]
VARIANTS = {"baseline": BASELINE, "extended": BASELINE + EXTRA_PROMPTS, "improved": SAM_PROMPTS}
SAM_PRICE = 2.50 / 1000                     # US$ per image request
PRICE_IN, PRICE_OUT = 1.25 / 1e6, 4.25 / 1e6
OUT = os.path.join(HERE, "results")


def run_one(d, client):
    img = Image.open(os.path.join(HERE, "images", d["file"])).convert("RGB")
    url = _data_url(img)
    path = os.path.join(OUT, d["name"] + ".json")
    rec = {"name": d["name"], "style": d["style"], "sam": {}, "variants": {}, "cost_usd": 0}
    if os.path.exists(path):
        with open(path) as f:
            rec = json.load(f)
    t = time.time()
    cost = 0.0
    for p in dict.fromkeys(p for ps in VARIANTS.values() for p in ps):
        if p not in rec["sam"]:
            rec["sam"][p] = sam_prompt_boxes(img, p, client, url)
            cost += SAM_PRICE
    rec.setdefault("sam_seconds", round(time.time() - t, 1))
    for name, prompts in VARIANTS.items():
        if name in rec["variants"]:
            continue
        boxes = merge_boxes([rec["sam"][p] for p in prompts])
        t = time.time()
        inv = read_inventory(img, boxes, client) if boxes else {"devices": [], "links": [], "capture_points": [],
                                                                "boxes": [], "_usage": {"tokens_in": 0, "tokens_out": 0}}
        u = inv.get("_usage", {})
        cost += u.get("tokens_in", 0) * PRICE_IN + u.get("tokens_out", 0) * PRICE_OUT
        rec["variants"][name] = {"prompts": prompts, "inventory": inv, "seconds": round(time.time() - t, 1)}
    rec["cost_usd"] = round(rec.get("cost_usd", 0) + cost, 5)
    rec["recorded_at"] = time.strftime("%Y-%m-%d")
    rec["_last_cost"] = round(cost, 5)
    with open(path, "w") as f:
        json.dump(rec, f, indent=1)
    return rec


def complete(name):
    path = os.path.join(OUT, name + ".json")
    if not os.path.exists(path):
        return False
    with open(path) as f:
        return set(VARIANTS) <= set(json.load(f).get("variants", {}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--max-usd", type=float, default=6.0, help="cap on total spend, including earlier runs")
    ap.add_argument("names", nargs="*")
    a = ap.parse_args()
    if not os.environ.get("MODEL_API_KEY"):
        sys.exit("MODEL_API_KEY is not set. Run set_key.py first, then open a new terminal.")
    with open(os.path.join(HERE, "truth.json")) as f:
        diagrams = json.load(f)["diagrams"]
    os.makedirs(OUT, exist_ok=True)
    spent = 0.0
    for n in os.listdir(OUT):
        if n.endswith(".json"):
            with open(os.path.join(OUT, n)) as f:
                spent += json.load(f).get("cost_usd", 0)
    todo = [d for d in diagrams if (not a.names or d["name"] in a.names)
            and not complete(d["name"])]
    if a.limit:
        todo = todo[:a.limit]
    print(f"{len(todo)} diagrams to run, US${spent:.4f} already spent, cap US${a.max_usd:.2f}")
    client = _client()
    errors, done = [], 0
    with ThreadPoolExecutor(a.workers) as pool:
        pending, queue = {}, list(todo)
        while queue or pending:
            while queue and len(pending) < a.workers and spent + 0.08 * (len(pending) + 1) <= a.max_usd:
                d = queue.pop(0)
                pending[pool.submit(run_one, d, client)] = d
            if not pending:
                print(f"Stopped: spend cap reached (US${spent:.4f})")
                break
            fut = next(as_completed(pending))
            d = pending.pop(fut)
            done += 1
            try:
                rec = fut.result()
            except Exception as e:          # keep going; the diagram can be re-run later
                errors.append((d["name"], f"{type(e).__name__}: {e}"))
                print(f"  [{done}/{len(todo)}] {d['name']:<20} ERROR {str(e)[:100]}", flush=True)
                continue
            spent += rec["_last_cost"]
            boxes = {v: len(rec["variants"][v]["inventory"]["boxes"]) for v in VARIANTS}
            untagged = len(rec["variants"]["improved"]["inventory"].get("untagged", []))
            print(f"  [{done}/{len(todo)}] {d['name']:<20} {len(d['devices']):>3} devices | SAM boxes: "
                  + ", ".join(f"{v} {n}" for v, n in boxes.items())
                  + f" | untagged flagged: {untagged} | US${rec['_last_cost']:.4f}", flush=True)
    print(f"Done. Total spend US${spent:.4f}. Errors: {len(errors)}")
    for n, e in errors:
        print(f"  {n}: {e}")
    print("Next: python bench/diagrams/score_diagrams.py")


if __name__ == "__main__":
    main()
