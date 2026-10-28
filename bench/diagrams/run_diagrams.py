"""Run SAM 3.1 and Muse Spark on every stress-test diagram (uses Meta Model API credits).

For each diagram: SAM 3.1 is called once per shape prompt and every prompt's boxes are
saved, then Muse Spark reads the diagram twice:
  baseline  - boxes from VisiLoop's current prompts ("rounded rectangle box", "ellipse")
  extended  - boxes from the current prompts plus more shape names
Results are saved per diagram as they arrive, so the run can be stopped and resumed.
Expected cost: about US$2 for 36 diagrams (SAM 3.1 is called 9 times per diagram).

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

EXTRA_PROMPTS = ["rectangle", "hexagon", "cylinder", "octagon", "trapezoid", "parallelogram", "circle"]
VARIANTS = {"baseline": SAM_PROMPTS, "extended": SAM_PROMPTS + EXTRA_PROMPTS}
SAM_PRICE = 2.50 / 1000                     # US$ per image request
PRICE_IN, PRICE_OUT = 1.25 / 1e6, 4.25 / 1e6
OUT = os.path.join(HERE, "results")


def run_one(d, client):
    img = Image.open(os.path.join(HERE, "images", d["file"])).convert("RGB")
    url = _data_url(img)
    rec = {"name": d["name"], "style": d["style"], "sam": {}, "variants": {}}
    t = time.time()
    for p in VARIANTS["extended"]:
        rec["sam"][p] = sam_prompt_boxes(img, p, client, url)
    rec["sam_seconds"] = round(time.time() - t, 1)
    cost = SAM_PRICE * len(rec["sam"])
    for name, prompts in VARIANTS.items():
        boxes = merge_boxes([rec["sam"][p] for p in prompts])
        t = time.time()
        inv = read_inventory(img, boxes, client) if boxes else {"devices": [], "links": [], "capture_points": [],
                                                                "boxes": [], "_usage": {"tokens_in": 0, "tokens_out": 0}}
        u = inv.get("_usage", {})
        cost += u.get("tokens_in", 0) * PRICE_IN + u.get("tokens_out", 0) * PRICE_OUT
        rec["variants"][name] = {"prompts": prompts, "inventory": inv, "seconds": round(time.time() - t, 1)}
    rec["cost_usd"] = round(cost, 5)
    rec["recorded_at"] = time.strftime("%Y-%m-%d")
    with open(os.path.join(OUT, d["name"] + ".json"), "w") as f:
        json.dump(rec, f, indent=1)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--max-usd", type=float, default=4.0)
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
            and not os.path.exists(os.path.join(OUT, d["name"] + ".json"))]
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
            spent += rec["cost_usd"]
            b = len(rec["variants"]["baseline"]["inventory"]["boxes"])
            x = len(rec["variants"]["extended"]["inventory"]["boxes"])
            print(f"  [{done}/{len(todo)}] {d['name']:<20} {len(d['devices']):>3} devices | SAM boxes: baseline {b:>3}, "
                  f"extended {x:>3} | US${rec['cost_usd']:.4f}", flush=True)
    print(f"Done. Total spend US${spent:.4f}. Errors: {len(errors)}")
    for n, e in errors:
        print(f"  {n}: {e}")
    print("Next: python bench/diagrams/score_diagrams.py")


if __name__ == "__main__":
    main()
