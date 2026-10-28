"""Read a network diagram and pin VisiLoop findings onto it.

1. SAM 3.1 finds every device box on the diagram (precise pixel positions).
2. The boxes are numbered on a copy of the image, and Muse Spark reads that
   numbered image into an inventory: devices, links, speeds and capture points
   (TAP / SPAN, and which direction each mirrors).
3. Each finding is pinned to the devices that explain it, using rules over the
   inventory (e.g. one-way traffic -> the capture point that mirrors one direction).
4. The diagram is redrawn with the faulty devices outlined and labelled.

Usage (from the repo root):
    python -m visikit.vision.diagram demo/diagram.png --pcap bench/cases/one_way.pcap --tool IDS
"""
import argparse
import base64
import io
import json
import os
import re

from PIL import Image, ImageDraw, ImageFont

from visikit.agent.diagnose import BASE_URL, _parse_json

SAM_MODEL = "sam-3.1"
VISION_MODEL = os.environ.get("VISILOOP_MODEL", "muse-spark-1.2")
SAM_PROMPTS = ["rounded rectangle box", "ellipse"]

DEVICE_TYPES = ["internet", "firewall", "router", "switch", "tap", "span", "packet_broker",
                "security_tool", "zone", "other"]

SYSTEM = (
    "You are VisiLoop, a network visibility assistant used by the network owner's own engineers. "
    "You read their own network diagrams so their security monitoring tools get complete traffic. "
    "Reply with ONLY a JSON object."
)


# ---------- helpers ----------
def _client():
    from openai import OpenAI
    return OpenAI(base_url=BASE_URL, api_key=os.environ["MODEL_API_KEY"])


def _data_url(img: Image.Image) -> str:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _font(size):
    for name in ("arialbd.ttf", "arial.ttf", "DejaVuSans-Bold.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _iou(a, b):
    ix = max(0, min(a[2], b[2]) - max(a[0], b[0]))
    iy = max(0, min(a[3], b[3]) - max(a[1], b[1]))
    inter = ix * iy
    union = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / union if union else 0


# ---------- step 1: SAM 3.1 boxes ----------
def sam_prompt_boxes(img: Image.Image, prompt: str, client=None, url=None):
    """Boxes SAM 3.1 returns for one text prompt: [[x1, y1, x2, y2], ...]."""
    client = client or _client()
    resp = client.responses.create(model=SAM_MODEL, input=[{
        "type": "message", "role": "user",
        "content": [{"type": "input_text", "text": prompt}, {"type": "input_image", "image_url": url or _data_url(img)}]}])
    return [list(map(int, m)) for m in re.findall(r"<\|box;x1=(\d+);y1=(\d+);x2=(\d+);y2=(\d+)", resp.output_text or "")]


def merge_boxes(lists):
    """Combine boxes from several prompts, dropping overlaps, in reading order."""
    boxes = []
    for found in lists:
        for box in found:
            if all(_iou(box, b) < 0.5 for b in boxes):
                boxes.append(box)
    boxes.sort(key=lambda b: (b[1] // 40, b[0]))      # reading order: top to bottom, left to right
    return boxes


def sam_boxes(img: Image.Image, client=None, prompts=SAM_PROMPTS):
    """Return [[x1, y1, x2, y2], ...] for every device shape SAM 3.1 finds."""
    client = client or _client()
    url = _data_url(img)
    return merge_boxes([sam_prompt_boxes(img, p, client, url) for p in prompts])


def numbered(img: Image.Image, boxes):
    """Copy of the diagram with a small numbered tag on each box (set-of-marks prompting)."""
    out = img.convert("RGB").copy()
    d, f = ImageDraw.Draw(out), _font(16)
    for i, (x1, y1, x2, y2) in enumerate(boxes):
        d.rectangle([x1, y1, x2, y2], outline=(0, 90, 255), width=2)
        tag = str(i)
        tw = d.textlength(tag, font=f)
        d.rectangle([x1, max(0, y1 - 20), x1 + tw + 8, max(20, y1)], fill=(0, 90, 255))
        d.text((x1 + 4, max(0, y1 - 20) + 1), tag, fill="white", font=f)
    return out


# ---------- step 2: Muse Spark inventory ----------
def read_inventory(img: Image.Image, boxes, client=None):
    client = client or _client()
    prompt = (
        "Each device box on this network diagram has a blue numbered tag. Build an inventory.\n"
        f"Box coordinates (id: x1,y1,x2,y2): {json.dumps({i: b for i, b in enumerate(boxes)})}\n"
        f"Device types: {', '.join(DEVICE_TYPES)}.\n"
        "Return JSON: {\"devices\": [{\"box\": int, \"label\": str, \"type\": str}], "
        "\"links\": [{\"from\": int, \"to\": int, \"speed\": str, \"kind\": \"production\"|\"mirror\"|\"tool\"}], "
        "\"capture_points\": [{\"box\": int, \"kind\": \"tap\"|\"span\", \"mirrors\": str, "
        "\"direction\": \"both\"|\"rx_only\"|\"tx_only\"|\"unknown\", \"feeds\": int}]}\n"
        "Use the labels written on the diagram, including any mirror direction written on dashed lines."
    )
    resp = client.chat.completions.create(model=VISION_MODEL, temperature=0, messages=[
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": [{"type": "text", "text": prompt},
                                     {"type": "image_url", "image_url": {"url": _data_url(numbered(img, boxes))}}]}])
    inv = _parse_json(resp.choices[0].message.content)
    valid = set(range(len(boxes)))
    inv["devices"] = [d for d in inv.get("devices", []) if d.get("box") in valid]
    inv["links"] = [l for l in inv.get("links", []) if l.get("from") in valid and l.get("to") in valid]
    inv["capture_points"] = [c for c in inv.get("capture_points", []) if c.get("box") in valid]
    inv["boxes"] = boxes
    u = getattr(resp, "usage", None)
    inv["_usage"] = {"tokens_in": getattr(u, "prompt_tokens", 0), "tokens_out": getattr(u, "completion_tokens", 0)}
    return inv


def load_or_read(image_path, client=None, refresh=False):
    """Inventory is cached next to the image (diagram.inventory.json) so it's read once."""
    cache = os.path.splitext(image_path)[0] + ".inventory.json"
    if os.path.exists(cache) and not refresh:
        with open(cache) as f:
            return json.load(f)
    img = Image.open(image_path)
    client = client or _client()
    boxes = sam_boxes(img, client)
    inv = read_inventory(img, boxes, client)
    with open(cache, "w") as f:
        json.dump(inv, f, indent=2)
    return inv


# ---------- step 3: pin findings to devices ----------
def pin_findings(inv, findings, tool_type):
    by_box = {d["box"]: d for d in inv["devices"]}
    of_type = lambda t: [d["box"] for d in inv["devices"] if d.get("type") == t]
    label = lambda b: by_box.get(b, {}).get("label", f"box {b}")
    tools = [d["box"] for d in inv["devices"] if d.get("type") == "security_tool"
             and tool_type.lower() in d.get("label", "").lower()] or of_type("security_tool")[:1]
    tool = tools[0] if tools else None
    brokers = of_type("packet_broker")
    caps = inv.get("capture_points", [])
    spans = [c["box"] for c in caps if c.get("kind") == "span"] or of_type("span")

    pins = []
    for f in findings:
        fault = f["fault"] if isinstance(f, dict) else f.fault
        detail = f["detail"] if isinstance(f, dict) else f.detail
        boxes, reason = [], ""
        if fault == "one_way":
            one_dir = [c["box"] for c in caps if c.get("direction") in ("rx_only", "tx_only")]
            boxes = one_dir or [c["box"] for c in caps]
            reason = (f"{', '.join(label(b) for b in boxes)} mirrors only one direction"
                      if one_dir else "capture points may not deliver both directions")
        elif fault == "duplicates":
            feeding = [c["box"] for c in caps if c.get("feeds") in brokers]
            boxes = brokers + (feeding if len(feeding) > 1 else [])
            reason = (f"{label(brokers[0]) if brokers else 'broker'} receives overlapping inputs "
                      f"({', '.join(label(b) for b in feeding)}) without dedup" if len(feeding) > 1
                      else "broker forwards duplicate copies without dedup")
        elif fault == "packet_drops":
            boxes = spans or brokers
            reason = (f"{label(boxes[0])} is a SPAN session, which drops mirrored packets under load"
                      if spans else "broker egress is dropping packets")
        elif fault == "tool_overload":
            boxes = [b for b in brokers[:1] + [tool] if b is not None]
            reason = f"bursts exceed the {label(tool)} tool port speed"
        elif fault == "missing_vlan":
            boxes = brokers[:1] or [c["box"] for c in caps]
            reason = f"VLAN tags are stripped before reaching {label(tool)}"
        elif fault == "encrypted_share":
            boxes = [tool] if tool is not None else []
            reason = f"{label(tool)} cannot inspect most of its traffic"
        if tool is not None and tool not in boxes and fault != "encrypted_share":
            boxes.append(tool)           # always show which tool is affected
        pins.append({"fault": fault, "boxes": boxes, "reason": reason, "detail": detail})
    return pins


# ---------- step 4: draw ----------
FAULT_COLOUR = (220, 30, 30)
STATUS_COLOUR = {
    "fault": (220, 30, 30),
    "verified fixed": (20, 150, 70),
    "advice (cannot be verified offline)": (230, 140, 0),
    "not fixed": (220, 30, 30),
}


def _colour(pin):
    return STATUS_COLOUR.get(pin.get("status", "fault"), FAULT_COLOUR)


def render(image_path, inv, pins, out_path=None, title=None):
    """Draw pins on the diagram. Each pin may carry a "status" that sets its colour:
    fault (red), verified fixed (green), advice (amber), not fixed (red).
    Returns the saved path, or the PIL image when out_path is None."""
    img = Image.open(image_path).convert("RGB")
    W, H = img.size
    legend_h = 44 + 32 * max(1, len(pins))
    canvas = Image.new("RGB", (W, H + legend_h), "white")
    canvas.paste(img, (0, 0))
    d, f, fb, fl = ImageDraw.Draw(canvas), _font(15), _font(22), _font(19)
    boxes = inv["boxes"]
    tags_on = {}
    for n, pin in enumerate(pins, 1):
        col = _colour(pin)
        for b in pin["boxes"]:
            x1, y1, x2, y2 = boxes[b]
            d.rectangle([x1 - 4, y1 - 4, x2 + 4, y2 + 4], outline=col, width=4)
            k = tags_on.get(b, 0)
            tags_on[b] = k + 1
            cx = x2 + 6 - 28 * k            # several findings on one box: tags side by side
            tag = str(n)
            d.ellipse([cx - 12, y1 - 18, cx + 12, y1 + 6], fill=col)
            d.text((cx - d.textlength(tag, font=f) / 2, y1 - 16), tag, fill="white", font=f)
    y = H + 10
    d.text((10, y), title or ("Feed healthy" if not pins else "VisiLoop findings"), fill="black", font=fb)
    y += 4
    for n, pin in enumerate(pins, 1):
        y += 32
        col = _colour(pin)
        d.ellipse([10, y, 34, y + 24], fill=col)
        d.text((22 - d.textlength(str(n), font=f) / 2, y + 3), str(n), fill="white", font=f)
        status = pin.get("status")
        text = f"{pin['fault']}: {pin['reason']}" if status in (None, "fault") else f"{pin['fault']}: {status}"
        while d.textlength(text, font=fl) > W - 50 and len(text) > 20:
            text = text[:-4] + "..."
        d.text((44, y + 1), text, fill="black", font=fl)
    if out_path is None:
        return canvas
    try:
        canvas.save(out_path)
    except OSError:
        # On Windows the old image may still be open in a viewer, which blocks overwriting it
        import time
        root, ext = os.path.splitext(out_path)
        out_path = f"{root}_{time.strftime('%H%M%S')}{ext}"
        canvas.save(out_path)
    return out_path


def main():
    ap = argparse.ArgumentParser(description="Pin VisiLoop findings onto a network diagram")
    ap.add_argument("image")
    ap.add_argument("--pcap", required=True, help="capture from the tool's feed")
    ap.add_argument("--tool", default="IDS")
    ap.add_argument("--vlans", default="10,20")
    ap.add_argument("--refresh", action="store_true", help="re-read the diagram instead of using the cache")
    a = ap.parse_args()

    from visikit.core.schema import FeedContext
    from visikit.loop import check_all
    from visikit.profiles import load_profile

    inv = load_or_read(a.image, refresh=a.refresh)
    print(f"Diagram: {len(inv['boxes'])} boxes, {len(inv['devices'])} devices, "
          f"{len(inv['capture_points'])} capture points")
    for c in inv["capture_points"]:
        lab = next((d["label"] for d in inv["devices"] if d["box"] == c["box"]), c["box"])
        print(f"  capture point: {lab} ({c.get('kind')}, {c.get('direction')})")
    ctx = FeedContext("feed-1", a.pcap, load_profile(a.tool, [int(v) for v in a.vlans.split(",") if v]))
    findings = check_all(ctx)
    pins = pin_findings(inv, [f.to_dict() for f in findings], a.tool)
    for p in pins:
        print(f"  {p['fault']}: {p['reason']}")
    out = os.path.splitext(a.pcap)[0] + "_on_diagram.png"
    out = render(a.image, inv, pins, out)
    print(f"Saved {out}")


if __name__ == "__main__":
    main()
