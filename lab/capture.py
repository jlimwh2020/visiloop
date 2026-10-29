"""Record the lab tests in plan.yaml, one capture per test, with Wireshark's dumpcap.

The laptop plays the security tool: plug it into the broker tool port. For tests marked
`ingress: true`, a second interface can record the lossless broker input (a TAP output),
so VisiLoop can verify its fixes on real traffic.

LAB TRAFFIC ONLY. You are asked to confirm this before anything is recorded.

Usage (from the repo root, in a terminal with Wireshark installed):
    python lab/capture.py --list                         # show capture interfaces
    python lab/capture.py --iface 5                      # run every test, tool port on interface 5
    python lab/capture.py --iface 5 --ingress-iface 6    # also record broker input where useful
    python lab/capture.py --iface 5 --only L02_span_rx_only L07_slicing
    python lab/capture.py --iface 5 --redo L05_burst     # record a test again

Captures go to lab/captures/ (not committed to git by default), with manifest.json.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import yaml                                          # noqa: E402

from visikit.core.tools import find_tool             # noqa: E402

OUT = os.path.join(HERE, "captures")


def load_plan():
    with open(os.path.join(HERE, "plan.yaml")) as f:
        plan = yaml.safe_load(f)
    tests = []
    for t in plan["tests"]:
        tests.append({**{k: v for k, v in plan["defaults"].items()}, **t})
    return tests


def start(iface, seconds, path):
    """Start dumpcap in the background: classic pcap, stop after `seconds`."""
    return subprocess.Popen([find_tool("dumpcap"), "-i", str(iface), "-a", f"duration:{seconds}", "-P",
                             "-w", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def finish(proc):
    """Wait for dumpcap; return (packets captured, packets the laptop itself dropped)."""
    out, err = proc.communicate()
    text = (out or "") + (err or "")
    if proc.returncode not in (0, None):
        raise RuntimeError(f"dumpcap failed: {text.strip()[-300:]}")
    captured = re.search(r"Packets captured:\s*(\d+)", text)
    dropped = re.search(r"received/dropped on interface[^:]*:\s*\d+/(\d+)", text)
    return (int(captured.group(1)) if captured else None, int(dropped.group(1)) if dropped else 0)


def wrap(text, indent="    "):
    import textwrap
    return textwrap.fill(" ".join(str(text).split()), 96, initial_indent=indent, subsequent_indent=indent)


def main():
    ap = argparse.ArgumentParser(description="Record the VisiLoop lab tests")
    ap.add_argument("--list", action="store_true", help="list capture interfaces and exit")
    ap.add_argument("--iface", help="interface on the broker tool port (number or name from --list)")
    ap.add_argument("--ingress-iface", help="optional interface on the lossless broker input (TAP output)")
    ap.add_argument("--only", nargs="*", help="run only these test ids")
    ap.add_argument("--redo", nargs="*", default=[], help="record these tests again")
    ap.add_argument("--seconds", type=int, help="override every test's capture length (for a quick dry run)")
    a = ap.parse_args()

    if a.list:
        print(subprocess.run([find_tool("dumpcap"), "-D"], capture_output=True, text=True).stdout)
        return
    if not a.iface:
        sys.exit("Choose the tool-port interface with --iface (see --list).")

    print("\nVisiLoop lab capture. Record LAB TRAFFIC ONLY: no customer, production or personal traffic.")
    if input('Type LAB to confirm this laptop only sees lab traffic: ').strip() != "LAB":
        sys.exit("Not confirmed. Nothing was recorded.")

    os.makedirs(OUT, exist_ok=True)
    mpath = os.path.join(OUT, "manifest.json")
    manifest = {"tests": {}}
    if os.path.exists(mpath):
        with open(mpath) as f:
            manifest = json.load(f)

    tests = [t for t in load_plan() if not a.only or t["id"] in a.only]
    for n, t in enumerate(tests, 1):
        tid = t["id"]
        if tid in manifest["tests"] and tid not in a.redo:
            print(f"\n[{n}/{len(tests)}] {tid}: already recorded (use --redo {tid} to record again)")
            continue
        seconds = a.seconds or t["seconds"]
        print(f"\n[{n}/{len(tests)}] {tid}   expect: {', '.join(t['expect']) or 'healthy'}   tool: {t['tool']}")
        print("  SET UP:")
        print(wrap(t["setup"]))
        print("  TRAFFIC (start it when the capture starts):")
        print(wrap(t["traffic"]))
        if input(f"  Press Enter to capture {seconds} s, or type s to skip: ").strip().lower() == "s":
            continue
        feed = os.path.join(OUT, f"{tid}.pcap")
        ingress = os.path.join(OUT, f"{tid}_ingress.pcap") if t.get("ingress") and a.ingress_iface else None
        procs = [start(a.iface, seconds, feed)]
        if ingress:
            procs.append(start(a.ingress_iface, seconds, ingress))
        print(f"  Capturing... start the traffic now ({seconds} s)")
        t0 = time.time()
        results = [finish(p) for p in procs]
        packets, laptop_drops = results[0]
        print(f"  Done in {time.time() - t0:.0f} s: {packets} packets"
              + (f", ingress {results[1][0]} packets" if ingress else ""))
        if laptop_drops:
            print(f"  WARNING: the laptop itself dropped {laptop_drops} packets. Lower the traffic rate "
                  "or use a faster capture card, then --redo this test.")
        if not packets:
            print("  WARNING: nothing was captured. Check the cable and interface, then --redo this test.")
        manifest["tests"][tid] = {
            "file": os.path.basename(feed), "ingress": os.path.basename(ingress) if ingress else None,
            "tool": t["tool"], "vlans": t.get("vlans") or [], "expect": t["expect"], "seconds": seconds,
            "packets": packets, "laptop_drops": laptop_drops, "recorded": time.strftime("%Y-%m-%d %H:%M")}
        with open(mpath, "w") as f:
            json.dump(manifest, f, indent=1)
        print("  RESTORE:")
        print(wrap(t["restore"]))
    print(f"\nManifest: {mpath}\nNext: python lab/run_lab.py")


if __name__ == "__main__":
    main()
