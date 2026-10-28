"""Score the diagram stress test and write bench/diagrams/RESULTS.md.

SAM 3.1 boxes are matched to the answer-key device boxes (overlap IoU >= 0.5). For every
matched device, Muse Spark's inventory is checked: the label it read, the device type,
and for capture points the kind (TAP/SPAN) and mirror direction, and for tools the port
speed. A diagram is "ready to pin findings on" when every capture point, the packet
broker and every tool were found and read correctly.

Also draws overlays (green = found, red = missed by SAM) into results/overlays/.

Usage (from the repo root):  python bench/diagrams/score_diagrams.py
"""
import difflib
import json
import os
import re
import statistics
from collections import defaultdict

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
STYLE_NOTES = {
    "clean_tb": "rounded boxes, top to bottom", "clean_lr": "rounded boxes, left to right",
    "visio_mono": "sharp black-and-white rectangles", "shapes_mixed": "hexagons, cylinders, octagons, trapezoids",
    "organic": "force-directed layout", "dark": "dark background", "dense": "16-23 devices, small text",
    "whiteboard": "handwriting, photographed at an angle", "scan": "grey printout scanned crooked",
}


def iou(a, b):
    ix = max(0, min(a[2], b[2]) - max(a[0], b[0]))
    iy = max(0, min(a[3], b[3]) - max(a[1], b[1]))
    inter = ix * iy
    union = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / union if union else 0


def norm(s):
    return " ".join(re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).split())


def label_ok(truth, read):
    t, r = norm(truth), norm(read)
    if not t or not r:
        return False
    if difflib.SequenceMatcher(None, t, r).ratio() >= 0.8:
        return True
    tt = [w for w in t.split() if len(w) > 1]
    return bool(tt) and all(w in r.split() for w in tt)


def speed(s):
    m = re.search(r"(\d+)\s*g", (s or "").lower())
    return f"{m.group(1)}G" if m else ""


def match(truth_boxes, sam_boxes):
    """Greedy one-to-one match by IoU. Returns {truth index: sam index}."""
    pairs = sorted(((iou(t, s), i, j) for i, t in enumerate(truth_boxes) for j, s in enumerate(sam_boxes)), reverse=True)
    used_t, used_s, out = set(), set(), {}
    for v, i, j in pairs:
        if v < 0.5:
            break
        if i not in used_t and j not in used_s:
            out[i] = j
            used_t.add(i)
            used_s.add(j)
    return out


def score(d, inv):
    devs = d["devices"]
    boxes = inv["boxes"]
    m = match([x["box"] for x in devs], boxes)
    by_box = {x["box"]: x for x in inv.get("devices", [])}
    idx = {x["id"]: i for i, x in enumerate(devs)}
    r = {"devices": len(devs), "sam_found": len(m), "sam_boxes": len(boxes),
         "sam_extra": len(boxes) - len(m), "label_ok": 0, "type_ok": 0, "read": 0}
    for i, j in m.items():
        got = by_box.get(j)
        if not got:
            continue
        r["read"] += 1
        r["label_ok"] += label_ok(devs[i]["label"], got.get("label"))
        r["type_ok"] += got.get("type") == devs[i]["type"]
    caps = {c["box"]: c for c in inv.get("capture_points", [])}
    r["caps"] = len(d["capture_points"])
    r["cap_found"] = r["cap_kind_ok"] = r["cap_dir_ok"] = 0
    r["cap_detail"] = []
    for c in d["capture_points"]:
        j = m.get(idx[c["id"]])
        got = caps.get(j) if j is not None else None
        ok_kind = bool(got) and got.get("kind") == c["kind"]
        ok_dir = bool(got) and got.get("direction") == c["direction"]
        r["cap_found"] += bool(got)
        r["cap_kind_ok"] += ok_kind
        r["cap_dir_ok"] += ok_dir
        r["cap_detail"].append({"label": c["label"], "truth": f"{c['kind']} {c['direction']}", "wording": c["wording"],
                                "written_on": c["written_on"], "sam_found": j is not None,
                                "read": f"{got.get('kind')} {got.get('direction')}" if got else None})
    r["tools"] = len(d["tools"])
    r["tool_speed_ok"] = 0
    links = inv.get("links", [])
    for t in d["tools"]:
        j = m.get(idx[t["id"]])
        sp = {speed(l.get("speed")) for l in links if j is not None and j in (l.get("from"), l.get("to"))}
        r["tool_speed_ok"] += t["speed"] in sp
    broker = [i for i, x in enumerate(devs) if x["type"] == "packet_broker"]
    broker_ok = all(m.get(i) is not None and (by_box.get(m[i]) or {}).get("type") == "packet_broker" for i in broker)
    tools_ok = all(m.get(idx[t["id"]]) is not None and (by_box.get(m[idx[t["id"]]]) or {}).get("type") == "security_tool"
                   for t in d["tools"])
    # SAM misses that Muse Spark flagged as "on the diagram but untagged"
    untagged = [u.get("label", "") for u in inv.get("untagged", [])]
    missed = [x for i, x in enumerate(devs) if i not in m]
    r["missed"] = len(missed)
    r["missed_flagged"] = sum(any(label_ok(x["label"], u) for u in untagged) for x in missed)
    r["untagged_false"] = sum(not any(label_ok(x["label"], u) for x in missed) for u in untagged)
    r["pin_ready"] = broker_ok and tools_ok and r["cap_dir_ok"] == r["caps"] and r["cap_kind_ok"] == r["caps"]
    r["matched"] = m
    return r


def pct(a, b):
    return f"{a}/{b} ({a / b:.0%})" if b else "-"


def overlay(d, r, path):
    im = Image.open(os.path.join(HERE, "images", d["file"])).convert("RGB")
    dr = ImageDraw.Draw(im)
    for i, dv in enumerate(d["devices"]):
        dr.rectangle(dv["box"], outline=(20, 160, 60) if i in r["matched"] else (220, 30, 30), width=3)
    im.save(path)


def main():
    with open(os.path.join(HERE, "truth.json")) as f:
        truth = {d["name"]: d for d in json.load(f)["diagrams"]}
    recs = {}
    for n in sorted(truth):
        p = os.path.join(RES, n + ".json")
        if os.path.exists(p):
            with open(p) as f:
                recs[n] = json.load(f)
    if not recs:
        raise SystemExit("No results yet: run python bench/diagrams/run_diagrams.py")
    variants = [v for v in ("baseline", "extended", "improved") if all(v in r["variants"] for r in recs.values())]
    keys = ["devices", "sam_found", "sam_boxes", "sam_extra", "read", "label_ok", "type_ok", "caps", "cap_found",
            "cap_kind_ok", "cap_dir_ok", "tools", "tool_speed_ok", "missed", "missed_flagged", "untagged_false"]
    scored = {v: {n: score(truth[n], recs[n]["variants"][v]["inventory"]) for n in recs} for v in variants}
    os.makedirs(os.path.join(RES, "overlays"), exist_ok=True)
    for n in recs:
        overlay(truth[n], scored["baseline"][n], os.path.join(RES, "overlays", n + "_baseline.png"))

    def totals(rows):
        t = {k: sum(r[k] for r in rows) for k in keys}
        t["pin_ready"] = sum(r["pin_ready"] for r in rows)
        t["n"] = len(rows)
        return t

    summary = {"diagrams": len(recs), "cost_usd": round(sum(r["cost_usd"] for r in recs.values()), 4),
               "recorded": max(r.get("recorded_at", "") for r in recs.values()), "variants": {}}
    for v in variants:
        rows = scored[v]
        by_style = defaultdict(list)
        for n, r in rows.items():
            by_style[truth[n]["style"]].append(r)
        summary["variants"][v] = {"all": totals(rows.values()),
                                  "by_style": {s: totals(rs) for s, rs in by_style.items()},
                                  "prompts": recs[next(iter(recs))]["variants"][v]["prompts"]}
    # direction mistakes, by wording and placement
    last = variants[-1]
    misses = []
    for n, r in scored[last].items():
        for c in r["cap_detail"]:
            if c["read"] != c["truth"]:
                misses.append({"diagram": n, **c})
    summary["capture_point_misses"] = {"variant": last, "misses": misses}
    summary["read_seconds_median"] = statistics.median(rec["variants"]["baseline"]["seconds"] for rec in recs.values())
    with open(os.path.join(RES, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    write_md(summary, truth)
    print(open(os.path.join(HERE, "RESULTS.md")).read())


def write_md(s, truth):
    md = ["# Diagram stress test: results", "",
          f"**{s['diagrams']} generated network diagrams in 9 styles**, from clean vendor-style drawings to whiteboard "
          "photos and crooked scans, with an exact answer key: every device's position, label and type, every capture "
          "point's kind and mirror direction (in varied wording, on the mirror line or in the label), and every tool's "
          f"port speed. Recorded {s['recorded']}; total cost US${s['cost_usd']:.2f}.", "",
          "SAM 3.1 boxes are matched to the answer key by overlap (IoU 0.5 or more); Muse Spark's reading is checked "
          "for every device SAM found. \"Ready to pin\" means every capture point (kind and direction), the packet "
          "broker and every tool were found and read correctly: what VisiLoop needs to pin findings on the diagram.", ""]
    for v, data in s["variants"].items():
        a = data["all"]
        md += [f"## {v.capitalize()} ({len(data['prompts'])} SAM prompts: {', '.join(data['prompts'])})", "",
               "| Measure | Result |", "|---|---|",
               f"| SAM 3.1 devices found | {pct(a['sam_found'], a['devices'])} |",
               f"| SAM extra boxes (not a device) | {a['sam_extra']} |",
               f"| Muse Spark labels read correctly (of found) | {pct(a['label_ok'], a['sam_found'])} |",
               f"| Muse Spark device types correct (of found) | {pct(a['type_ok'], a['sam_found'])} |",
               f"| Capture points: kind correct | {pct(a['cap_kind_ok'], a['caps'])} |",
               f"| Capture points: mirror direction correct | {pct(a['cap_dir_ok'], a['caps'])} |",
               f"| Tool port speeds correct | {pct(a['tool_speed_ok'], a['tools'])} |",
               *([f"| SAM misses flagged by Muse Spark as untagged | {pct(a['missed_flagged'], a['missed'])}"
                  f" ({a['untagged_false']} false flags) |"] if v == "improved" else []),
               f"| **Diagrams ready to pin findings on** | **{pct(a['pin_ready'], a['n'])}** |", "",
               "| Style | SAM found | Labels | Types | Direction | Ready to pin |", "|---|---|---|---|---|---|"]
        for style, t in data["by_style"].items():
            md.append(f"| {style} ({STYLE_NOTES.get(style, '')}) | {pct(t['sam_found'], t['devices'])} | "
                      f"{pct(t['label_ok'], t['sam_found'])} | {pct(t['type_ok'], t['sam_found'])} | "
                      f"{pct(t['cap_dir_ok'], t['caps'])} | {pct(t['pin_ready'], t['n'])} |")
        md.append("")
    cm = s["capture_point_misses"]
    if cm["misses"]:
        md += [f"## Capture points read wrongly or missed ({cm['variant']})", "",
               "| Diagram | Capture point | Truth | Written as | Where | Muse Spark read |", "|---|---|---|---|---|---|"]
        for m in cm["misses"]:
            read = m["read"] or ("not found by SAM" if not m["sam_found"] else "not listed as a capture point")
            md.append(f"| {m['diagram']} | {m['label']} | {m['truth']} | \"{m['wording']}\" | {m['written_on']} | {read} |")
        md.append("")
    md += ["Overlays of what SAM 3.1 found (green) and missed (red): `results/overlays/`.", "",
           "## Reproduce", "", "```",
           "python bench/diagrams/make_diagrams.py   # 36 diagrams + answer key (needs Graphviz; images are committed)",
           "python bench/diagrams/run_diagrams.py    # SAM 3.1 + Muse Spark (about US$2, resumable)",
           "python bench/diagrams/score_diagrams.py  # this file", "```", ""]
    with open(os.path.join(HERE, "RESULTS.md"), "w") as f:
        f.write("\n".join(md))


if __name__ == "__main__":
    main()
