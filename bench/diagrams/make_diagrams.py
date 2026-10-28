"""Generate the diagram stress test: varied network diagrams with an exact answer key.

Each diagram is a random but realistic visibility topology (internet, firewalls,
switches, zones, TAPs and SPAN sessions, a packet broker, security tools), drawn in one
of nine styles, from clean vendor-style drawings to whiteboard photos and scans:

  clean_tb      rounded boxes, top to bottom (like the demo diagram)
  clean_lr      rounded boxes, left to right
  visio_mono    sharp rectangles, black and white, no fill
  shapes_mixed  a different shape per device type (hexagons, cylinders, octagons...)
  organic       force-directed layout instead of layers
  dark          dark background, light text
  dense         16-20 devices, small text
  whiteboard    handwriting font on a whiteboard, photographed at an angle
  scan          a printout, scanned crooked in grey with noise

The answer key (truth.json) records every device's pixel box, label and type, every
capture point's kind (TAP or SPAN), mirror direction and the broker it feeds, and the
port speed of every tool. Mirror directions are written in varied wording ("RX only",
"ingress only", "A+B", "both directions"...), on the mirror line or in the device label.

Needs Graphviz (dot, neato) and the Caveat and Kalam fonts for the whiteboard style.
The generated images are committed, so running the test does not need Graphviz.

Usage (from the repo root):  python bench/diagrams/make_diagrams.py [--per-style 4] [--seed 11]
"""
import argparse
import json
import math
import os
import random
import subprocess
import tempfile

import cv2
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "images")
STYLES = ["clean_tb", "clean_lr", "visio_mono", "shapes_mixed", "organic", "dark", "dense", "whiteboard", "scan"]
MAX_SIDE = 1600

DIRECTION_WORDS = {
    "both": ["mirror (both)", "both directions", "RX+TX", "mirror A+B", "bidirectional"],
    "rx_only": ["mirror (RX only)", "RX only", "ingress only", "mirror: inbound only"],
    "tx_only": ["mirror (TX only)", "TX only", "egress only", "mirror: outbound only"],
}
TOOLS = [("NDR", "10G"), ("IDS", "1G"), ("SIEM", "1G"), ("APM", "10G"), ("DLP", "1G"),
         ("Forensics Recorder", "40G"), ("Sandbox", "1G"), ("IPS", "10G")]


# ---------------------------------------------------------------- topology
def topology(rng, dense=False):
    nodes, edges, caps = [], [], []          # edges: (a, b, kind, label)

    def node(nid, label, typ):
        nodes.append({"id": nid, "label": label, "type": typ})
        return nid

    node("internet", rng.choice(["Internet", "ISP", "WAN", "Internet (ISP-A)"]), "internet")
    n_fw = rng.choice([1, 1, 2])
    fws = [node(f"fw{i}", rng.choice(["Firewall\nFW-0%d", "Perimeter FW\nPFW-%d", "NGFW-EDGE-%d"]).replace("%d", str(i + 1)),
                "firewall") for i in range(n_fw)]
    prev = "internet"
    if rng.random() < 0.4 or dense:
        prev = node("rtr", rng.choice(["Edge Router\nRTR-01", "Border Router", "WAN Router R1"]), "router")
        edges.append(("internet", prev, "production", ""))
    for f in fws:
        edges.append((prev, f, "production", rng.choice(["", "10G", "1G"])))
    n_core = 2 if dense else rng.choice([1, 1, 2])
    cores = [node(f"core{i}", rng.choice(["Core Switch\nCORE-SW-0%d", "DC Core %d", "Core-%d"]).replace("%d", str(i + 1)),
                  "switch") for i in range(n_core)]
    links = []                               # production links a TAP could sit on
    for i in range(max(len(fws), len(cores))):
        fw, c = fws[i % len(fws)], cores[i % len(cores)]
        links.append((fw, c))
        edges.append((fw, c, "production", rng.choice(["", "10G"])))
    if len(cores) == 2:
        edges.append((cores[0], cores[1], "production", rng.choice(["40G", "100G", "10G"])))
    access_names = ["Access Switch\nACC-SW-0%d", "Server Switch\nSRV-SW-0%d", "Distribution SW %d", "DMZ Switch %d",
                    "Leaf-%d", "Floor %d Switch"]
    zones = ["User LAN\n(PCs)", "Server Zone\n(File, Web App)", "DMZ\n(Web, Mail)", "Guest Wi-Fi", "OT Network\n(PLCs)",
             "Database Servers", "VDI Farm", "Branch VPN"]
    n_acc = rng.randint(3, 5) if dense else rng.randint(1, 3)
    rng.shuffle(zones)
    accs = []
    for i in range(n_acc):
        a = node(f"acc{i}", rng.choice(access_names).replace("%d", str(i + 1)), "switch")
        accs.append(a)
        c = cores[i % len(cores)]
        edges.append((c, a, "production", rng.choice(["", "10G", "1G", "25G"])))
        z = node(f"zone{i}", zones[i], "zone")
        edges.append((a, z, "production", ""))

    broker = node("npb", rng.choice(["Packet Broker\nNPB-01", "NPB-01", "Visibility Fabric\nVF-1",
                                     "Network Packet Broker", "Packet Broker"]), "packet_broker")

    # capture points
    n_caps = rng.randint(2, 3) if dense else rng.randint(1, 3)
    kinds = ["tap", "span"] + [rng.choice(["tap", "span"]) for _ in range(n_caps - 2)] if n_caps >= 2 else [rng.choice(["tap", "span"])]
    span_on = [c for c in cores + accs]
    rng.shuffle(span_on)
    tap_links = list(links)
    rng.shuffle(tap_links)
    n_tap = n_span = 0
    for k in kinds:
        if k == "tap" and tap_links:
            a, b = tap_links.pop()
            n_tap += 1
            direction = "both" if rng.random() < 0.8 else rng.choice(["rx_only", "tx_only"])
            label = f"TAP-0{n_tap}" + rng.choice(["\n(10G fiber)", "\n(copper)", "", "\n(passive)"])
            t = node(f"tap{n_tap}", label, "tap")
            edges[:] = [e for e in edges if not (e[0] == a and e[1] == b)]
            edges.append((a, t, "production", rng.choice(["", "10G"])))
            edges.append((t, b, "production", rng.choice(["", "10G"])))
            caps.append({"node": t, "kind": "tap", "direction": direction, "feeds": broker})
        else:
            on = span_on.pop() if span_on else cores[0]
            n_span += 1
            on_label = next(n["label"] for n in nodes if n["id"] == on).split("\n")[-1]
            direction = rng.choice(["rx_only", "rx_only", "tx_only", "both"])
            label = rng.choice([f"SPAN port\non {on_label}", f"SPAN-{n_span}", f"SPAN session {n_span}",
                                f"Mirror port\n({on_label})"])
            s = node(f"span{n_span}", label, "span")
            edges.append((on, s, "attach", ""))
            caps.append({"node": s, "kind": "span", "direction": direction, "feeds": broker})
    for c in caps:
        words = rng.choice(DIRECTION_WORDS[c["direction"]])
        c["wording"] = words
        c["where"] = "edge" if rng.random() < 0.75 else "label"
        if c["where"] == "label":
            n = next(n for n in nodes if n["id"] == c["node"])
            n["label"] += f"\n[{words}]"
            edges.append((c["node"], broker, "mirror", ""))
        else:
            edges.append((c["node"], broker, "mirror", words))

    # tools
    pool = list(TOOLS)
    rng.shuffle(pool)
    n_tools = rng.randint(3, 5) if dense else rng.randint(1, 4)
    tools = []
    for i, (name, speed) in enumerate(pool[:n_tools]):
        speed = rng.choice([speed, speed, "1G", "10G", "25G"])
        label = name + rng.choice(["", f"\n{name.split()[0].upper()}-01", " (primary)"]) if rng.random() < 0.5 else name
        t = node(f"tool{i}", label, "security_tool")
        edges.append((broker, t, "tool", speed))
        tools.append({"node": t, "speed": speed})
    return nodes, edges, caps, tools


# ---------------------------------------------------------------- drawing
def style_attrs(style, rng):
    font = {"whiteboard": rng.choice(["Kalam", "Caveat"]), "visio_mono": "Carlito", "scan": "DejaVu Serif"}.get(style, "Inter")
    g = {"bgcolor": "white", "pad": "0.3", "nodesep": "0.45", "ranksep": "0.6", "fontname": font, "dpi": "96"}
    n = {"shape": "box", "style": "rounded,filled", "fillcolor": "#EAF2FB", "color": "#1F3864",
         "fontname": font, "fontsize": "12", "penwidth": "1.4", "margin": "0.15,0.08"}
    e = {"fontname": font, "fontsize": "10", "color": "#555555", "fontcolor": "#333333"}
    if style == "clean_lr" or style == "dense":
        g["rankdir"] = "LR"
    if style == "visio_mono":
        n.update(style="solid", fillcolor="white", color="black", penwidth="1.2")
        e.update(color="black", fontcolor="black")
    if style == "dark":
        g["bgcolor"] = "#1E1E24"
        n.update(fillcolor="#2E3A4F", color="#8FB3FF", fontcolor="#F0F0F0")
        e.update(color="#A0A0B0", fontcolor="#E0E0E0")
    if style == "dense":
        n["fontsize"] = "9"
        e["fontsize"] = "8"
        g.update(nodesep="0.2", ranksep="0.45")
    if style == "whiteboard":
        g["bgcolor"] = "#F7F7F2"
        n.update(style="rounded", color="#1A3D8F", fontcolor="#1A3D8F", penwidth="2.6", fontsize="17")
        e.update(color="#222222", fontcolor="#B01E1E", penwidth="2.0", fontsize="14")
    if style == "scan":
        n.update(style="filled", fillcolor="#F4F4F4", color="black")
        e.update(color="black", fontcolor="black")
    if style == "organic":
        g.update(overlap="false", splines="true", sep="+18")
    return g, n, e


TYPE_FILL = {"internet": "#F2F2F2", "zone": "#F2F2F2", "tap": "#FFF2CC", "span": "#FFF2CC",
             "packet_broker": "#E2F0D9", "security_tool": "#FCE4D6"}
TYPE_SHAPE = {"internet": "ellipse", "firewall": "octagon", "router": "circle", "switch": "box",
              "zone": "folder", "tap": "invtrapezium", "span": "parallelogram", "packet_broker": "hexagon",
              "security_tool": "cylinder"}


def dot_source(nodes, edges, style, rng):
    g, n, e = style_attrs(style, rng)
    q = lambda s: '"' + s.replace('"', "'").replace("\n", "\\n") + '"'
    attrs = lambda d: ", ".join(f'{k}={q(v)}' for k, v in d.items())
    lines = ["digraph G {", f"  graph [{attrs(g)}];", f"  node [{attrs(n)}];", f"  edge [{attrs(e)}];"]
    for nd in nodes:
        a = {"label": nd["label"]}
        if style in ("clean_tb", "clean_lr", "organic", "dense"):
            a["fillcolor"] = TYPE_FILL.get(nd["type"], "#EAF2FB")
        if nd["type"] == "internet":
            a["shape"] = "ellipse"
        if style == "shapes_mixed":
            a.update(shape=TYPE_SHAPE.get(nd["type"], "box"), style="filled", fillcolor=TYPE_FILL.get(nd["type"], "#EAF2FB"))
        lines.append(f"  {nd['id']} [{attrs(a)}];")
    for a, b, kind, label in edges:
        ea = {"dir": "none"}
        if label:
            ea["label"] = " " + label
        if kind == "mirror":
            ea.update(style="dashed", dir="forward", color="#BF9000" if style not in ("visio_mono", "scan", "whiteboard") else "black")
        if kind == "attach":
            ea["style"] = "dotted"
        if kind == "tool":
            ea["dir"] = "forward"
        lines.append(f"  {a} -> {b} [{attrs(ea)}];")
    caps = [nd["id"] for nd in nodes if nd["type"] in ("tap", "span")]
    tools = [nd["id"] for nd in nodes if nd["type"] == "security_tool"]
    if style not in ("organic",):
        if len(tools) > 1:
            lines.append("  {rank=same; " + "; ".join(tools) + "}")
    lines.append("}")
    return "\n".join(lines)


def render(src, style, work):
    engine = "neato" if style == "organic" else "dot"
    dot_path = os.path.join(work, "g.dot")
    with open(dot_path, "w") as f:
        f.write(src)
    png = os.path.join(work, "g.png")
    subprocess.run([engine, "-Tpng", dot_path, "-o", png], check=True, capture_output=True)
    js = json.loads(subprocess.run([engine, "-Tjson", dot_path], check=True, capture_output=True, text=True).stdout)
    img = Image.open(png).convert("RGB")
    W, H = img.size
    bb = [float(v) for v in js["bb"].split(",")]            # points: x0, y0, x1, y1
    sx, sy = W / (bb[2] - bb[0]), H / (bb[3] - bb[1])        # bb already includes pad in the PNG? (checked below)
    boxes = {}
    pad = float(js.get("pad", 0.3)) * 72 if "pad" in js else 0.3 * 72
    # Graphviz PNG = (bb + 2*pad) * dpi/72
    scale = 96 / 72
    for o in js["objects"]:
        if "pos" not in o or "width" not in o:
            continue
        x, y = map(float, o["pos"].split(","))
        w, h = float(o["width"]) * 72, float(o["height"]) * 72
        x1 = (x - w / 2 - bb[0] + pad) * scale
        x2 = (x + w / 2 - bb[0] + pad) * scale
        y1 = (bb[3] - (y + h / 2) + pad) * scale
        y2 = (bb[3] - (y - h / 2) + pad) * scale
        boxes[o["name"]] = [x1, y1, x2, y2]
    return img, boxes


# ---------------------------------------------------------------- photo / scan effects
def warp(img, boxes, M, size):
    out = cv2.warpPerspective(np.array(img), M, size, borderMode=cv2.BORDER_REPLICATE)
    nb = {}
    for k, (x1, y1, x2, y2) in boxes.items():
        pts = np.float32([[x1, y1], [x2, y1], [x2, y2], [x1, y2]]).reshape(-1, 1, 2)
        t = cv2.perspectiveTransform(pts, M).reshape(-1, 2)
        nb[k] = [float(t[:, 0].min()), float(t[:, 1].min()), float(t[:, 0].max()), float(t[:, 1].max())]
    return Image.fromarray(out), nb


def photo(img, boxes, rng):
    """Whiteboard photographed with a phone: margin, tilt, perspective, uneven light, blur, noise, JPEG."""
    a = np.array(img)
    h, w = a.shape[:2]
    m = int(0.08 * max(w, h))
    board = np.full((h + 2 * m, w + 2 * m, 3), (238, 238, 232), np.uint8)
    board[m:m + h, m:m + w] = a
    boxes = {k: [x1 + m, y1 + m, x2 + m, y2 + m] for k, (x1, y1, x2, y2) in boxes.items()}
    H, W = board.shape[:2]
    j = lambda s: rng.uniform(-s, s)
    src = np.float32([[0, 0], [W, 0], [W, H], [0, H]])
    d = 0.06
    dst = np.float32([[j(d) * W + d * W, j(d) * H + d * H], [W - d * W + j(d) * W, j(d) * H + d * H],
                      [W - d * W + j(d) * W, H - d * H + j(d) * H], [d * W + j(d) * W, H - d * H + j(d) * H]])
    M = cv2.getPerspectiveTransform(src, dst)
    img, boxes = warp(Image.fromarray(board), boxes, M, (W, H))
    a = np.array(img).astype(np.float32)
    yy, xx = np.mgrid[0:H, 0:W]
    cx, cy = rng.uniform(0.2, 0.8) * W, rng.uniform(0.2, 0.8) * H
    light = 1.05 - 0.28 * (np.hypot(xx - cx, yy - cy) / np.hypot(W, H))
    a = a * light[..., None] * np.array([1.0, 0.98, 0.93])
    a = cv2.GaussianBlur(a, (0, 0), rng.uniform(0.6, 1.2))
    a = a + np.random.default_rng(rng.randint(0, 9999)).normal(0, 6, a.shape)
    img = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))
    return jpeg(img, 62), boxes


def scan(img, boxes, rng):
    """Printout scanned crooked: grey, rotated 1-3 degrees, speckle, lower resolution."""
    W, H = img.size
    angle = rng.uniform(1, 3) * rng.choice([-1, 1])
    M2 = cv2.getRotationMatrix2D((W / 2, H / 2), angle, 1.0)
    M = np.vstack([M2, [0, 0, 1]]).astype(np.float64)
    img, boxes = warp(img.convert("L").convert("RGB"), boxes, M, (W, H))
    a = np.array(img).astype(np.float32) * 0.93 + 8
    rs = np.random.default_rng(rng.randint(0, 9999))
    a += rs.normal(0, 9, a.shape)
    speck = rs.random(a.shape[:2]) < 0.0015
    a[speck] = 40
    img = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))
    f = 0.7
    img = img.resize((int(W * f), int(H * f)), Image.BILINEAR)
    boxes = {k: [v * f for v in b] for k, b in boxes.items()}
    return jpeg(img, 70), boxes


def jpeg(img, q):
    import io
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=q)
    return Image.open(io.BytesIO(buf.getvalue())).convert("RGB")


def fit(img, boxes):
    s = min(1.0, MAX_SIDE / max(img.size))
    if s < 1:
        img = img.resize((int(img.width * s), int(img.height * s)), Image.LANCZOS)
        boxes = {k: [v * s for v in b] for k, b in boxes.items()}
    return img, boxes


# ---------------------------------------------------------------- main
def make(name, style, rng, work):
    nodes, edges, caps, tools = topology(rng, dense=(style == "dense"))
    img, boxes = render(dot_source(nodes, edges, style, rng), style, work)
    if style == "whiteboard":
        img, boxes = photo(img, boxes, rng)
    elif style == "scan":
        img, boxes = scan(img, boxes, rng)
    img, boxes = fit(img, boxes)
    ext = ".jpg" if style in ("whiteboard", "scan") else ".png"
    path = os.path.join(OUT, name + ext)
    img.save(path, quality=90) if ext == ".jpg" else img.save(path)
    label = lambda nid: next(n["label"] for n in nodes if n["id"] == nid)
    return {
        "name": name, "style": style, "file": os.path.basename(path), "size": list(img.size),
        "devices": [{"id": n["id"], "label": n["label"].replace("\n", " "), "type": n["type"],
                     "box": [round(v, 1) for v in boxes[n["id"]]]} for n in nodes],
        "capture_points": [{"id": c["node"], "label": label(c["node"]).replace("\n", " "), "kind": c["kind"],
                            "direction": c["direction"], "wording": c["wording"], "written_on": c["where"],
                            "feeds": c["feeds"]} for c in caps],
        "tools": [{"id": t["node"], "label": label(t["node"]).replace("\n", " "), "speed": t["speed"]} for t in tools],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-style", type=int, default=4)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--check", action="store_true", help="also write images with the answer-key boxes drawn on")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    rng = random.Random(a.seed)
    work = tempfile.mkdtemp(prefix="diag_")
    truth = {"version": 1, "seed": a.seed, "diagrams": []}
    for style in STYLES:
        for i in range(a.per_style):
            name = f"d{len(truth['diagrams']) + 1:02d}_{style}"
            t = make(name, style, rng, work)
            truth["diagrams"].append(t)
            print(f"  {name:<20}{len(t['devices']):>3} devices, {len(t['capture_points'])} capture points "
                  f"({', '.join(c['kind'] + ':' + c['direction'] for c in t['capture_points'])}), {len(t['tools'])} tools",
                  flush=True)
            if a.check:
                from PIL import ImageDraw
                im = Image.open(os.path.join(OUT, t["file"])).convert("RGB")
                d = ImageDraw.Draw(im)
                for dv in t["devices"]:
                    d.rectangle(dv["box"], outline=(255, 0, 0), width=2)
                os.makedirs(os.path.join(HERE, "check"), exist_ok=True)
                im.save(os.path.join(HERE, "check", name + ".png"))
    with open(os.path.join(HERE, "truth.json"), "w") as f:
        json.dump(truth, f, indent=1)
    print(f"Wrote {len(truth['diagrams'])} diagrams to {OUT} and truth.json")


if __name__ == "__main__":
    main()
