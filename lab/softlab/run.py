"""Run the VisiLoop lab tests on the soft lab: a virtual switch, TAP and packet broker on real Linux
network interfaces, with real traffic, real captures and real SNMP. No equipment needed.

    sudo python3 -m lab.softlab.run                    # everything: about 15 minutes
    sudo python3 -m lab.softlab.run --only L02_span_rx_only C04_link_loss --skip-monitor
    sudo python3 -m lab.softlab.run --down             # remove the virtual lab

Needs Linux (or WSL 2 on Windows) as root, with iproute2, ethtool, iperf3, openssl and Wireshark's
dumpcap/tshark/editcap. Builds the network (net.py), starts the switch and broker daemons, then for
each test in plan.yaml: sets up the fault, records the tool port (and the lossless copy) while lab
traffic runs, and finally runs VisiLoop on every recording (lab/run_lab.py). Counter tests read the
switch and broker over SNMP; the monitor test runs VisiLoop's continuous mode while faults come and go.

Writes lab/softlab/RESULTS.md and results.json; recordings go to lab/softlab/captures/ (not in git).
"""
import argparse
import copy
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from lab.softlab import net                                   # noqa: E402

STATE, CAPS = os.path.join(HERE, "state"), os.path.join(HERE, "captures")
COMMUNITY = "visiloop-ro"


def write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


class Lab:
    def __init__(self, plan):
        self.plan, self.procs = plan, []
        self.env = {**os.environ, "PYTHONPATH": ROOT}

    def start(self, ns, *args, log):
        p = subprocess.Popen(["ip", "netns", "exec", ns, *args], env=self.env, cwd=ROOT, start_new_session=True,
                             stdout=open(os.path.join(STATE, log), "w"), stderr=subprocess.STDOUT)
        self.procs.append(p)
        return p

    def up(self):
        os.makedirs(STATE, exist_ok=True)
        os.makedirs(CAPS, exist_ok=True)
        net.up()
        self.configure({})
        # The forwarding daemons get real-time priority where allowed, so traffic tools do not delay them
        rt = ["chrt", "-f", "10"] if os.environ.get("SOFTLAB_RT") and shutil.which("chrt") else []
        self.start("vl-switch", *rt, sys.executable, "-m", "lab.softlab.switchd", "--state", STATE, "--mgmt",
                   net.SWITCH_MGMT, "--community", COMMUNITY, log="switchd.log")
        self.start("vl-broker", *rt, sys.executable, "-m", "lab.softlab.brokerd", "--state", STATE, "--mgmt",
                   net.BROKER_MGMT, "--community", COMMUNITY, log="brokerd.log")
        self.start("vl-server", sys.executable, "-m", "lab.softlab.traffic", "serve", "--state", STATE, log="server.log")
        self.start("vl-server", "iperf3", "-s", log="iperf3.log")
        time.sleep(3)
        for p in self.procs:
            if p.poll() is not None:
                sys.exit(f"A lab process stopped at start: see {STATE}/*.log")

    def down(self):
        for p in self.procs:
            try:
                os.killpg(p.pid, 15)
            except ProcessLookupError:
                pass
        net.down()

    def configure(self, test):
        """Baseline plus the test's changes, written for the daemons to pick up."""
        base = self.plan["baseline"]
        sw = {**base["switch"], **(test.get("switch") or {})}
        br = copy.deepcopy(base["broker"])
        br["inputs"] = copy.deepcopy(test.get("inputs") or {})
        br["rules"][0].update(test.get("tool_rule") or {})
        br["rates"] = {"p5": test.get("p5_mbps", self.plan["defaults"]["p5_mbps"])}
        if test.get("path") == "span" or test.get("span_path_only"):
            # Counter and monitor tests on the SPAN path: no TAP copies and no clean-copy rule, so the Python
            # broker is not doing work nobody measures (it cannot keep up with every port at once under load)
            sw["tap"] = False
            br["rules"] = br["rules"][:1]
        net.set_host_mtu(test.get("host_mtu", 1500))
        write(os.path.join(STATE, "switch.json"), sw)
        write(os.path.join(STATE, "broker.json"), br)
        time.sleep(1.5)                                   # the daemons re-read their settings twice a second

    def traffic(self, steps, seconds):
        """Start the test's traffic from the lab client; returns the processes."""
        ps = []
        for step in steps:
            if step == "mix":
                cmd = [sys.executable, "-m", "lab.softlab.traffic", "mix", "--seconds", str(seconds)]
            elif step == "https":
                cmd = [sys.executable, "-m", "lab.softlab.traffic", "mix", "--seconds", str(seconds), "--https-only"]
            elif step == "bursts":                      # 2 s of both directions at once, every 5 s
                cmd = ["sh", "-c", f"end=$(($(date +%s)+{int(seconds)})); while [ $(date +%s) -lt $end ]; do "
                       f"iperf3 -c {net.SERVER} -t 2 --bidir >/dev/null 2>&1; sleep 3; done"]
            elif step == "jumbo":                       # TCP with a 9000-byte MTU sends jumbo frames
                cmd = ["iperf3", "-c", net.SERVER, "-t", str(int(seconds)), "-b", "8M"]
            elif isinstance(step, dict) and step.get("iperf") == "bidir":
                cmd = ["iperf3", "-c", net.SERVER, "-t", str(int(seconds)), "--bidir"]
            else:
                raise ValueError(f"unknown traffic step {step!r}")
            ps.append(subprocess.Popen(["ip", "netns", "exec", "vl-client", *cmd], env=self.env, cwd=ROOT,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        return ps

    def health(self):
        behind = 0
        for name in ("switch_health.json", "broker_health.json"):
            try:
                with open(os.path.join(STATE, name)) as f:
                    h = json.load(f)
                behind += h.get("fell_behind", 0)   # frames the daemons could not read in time (lost)
            except (OSError, ValueError):
                pass
        return behind


def capture_test(lab, t, seconds):
    from lab.capture import finish
    lab.configure(t)
    feed = os.path.join(CAPS, f"{t['id']}.pcap")
    ingress = os.path.join(CAPS, f"{t['id']}_ingress.pcap") if t.get("ingress") else None
    caps = [("nic1", feed)] + ([("nic2", ingress)] if ingress else [])
    behind = lab.health()
    procs = [subprocess.Popen(["ip", "netns", "exec", "vl-tool", "dumpcap", "-i", nic, "-a", f"duration:{seconds + 3}",
                               "-P", "-w", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for nic, path in caps]
    time.sleep(1)
    for p in lab.traffic(t.get("traffic") or ["mix"], seconds):
        p.wait()
    results = [finish(p) for p in procs]
    lab.configure({})
    from lab.softlab.retime import retime
    kept = [retime(path) for _, path in caps]           # broker timestamps, trailers removed
    return {"file": os.path.basename(feed), "ingress": os.path.basename(ingress) if ingress else None,
            "tool": t.get("tool", "IDS"), "vlans": t.get("vlans") or [], "expect": t["expect"], "seconds": seconds,
            "packets": kept[0][0], "not_from_broker": kept[0][1], "laptop_drops": results[0][1],
            "note": t.get("note", ""),
            "lab_fell_behind": lab.health() - behind,
            "tool_port_gbps": t.get("p5_mbps", 150) / 1000, "recorded": time.strftime("%Y-%m-%d %H:%M")}


def hops(kind, p5_mbps):
    sw = {"host": net.SWITCH_MGMT, "community": COMMUNITY}
    npb = {"host": net.BROKER_MGMT, "community": COMMUNITY}
    out = {"name": "LAB-NPB P5 (to the tool)", "role": "broker_out", "device": "LAB-NPB", "port": "P5",
           "speed_gbps": p5_mbps / 1000, "source": {**npb, "if_name": "P5"}}
    if kind == "span":
        return [{"name": "LAB-SW Gi1/0/1 (mirrored)", "role": "span_source", "device": "LAB-SW", "port": "Gi1/0/1",
                 "speed_gbps": 0.1, "mirrors": "both", "source": {**sw, "if_name": "Gi1/0/1"}},
                {"name": "LAB-SW Gi1/0/24 (SPAN destination)", "role": "span_dest", "device": "LAB-SW",
                 "port": "Gi1/0/24", "speed_gbps": 0, "source": {**sw, "if_name": "Gi1/0/24"}},   # speed read over SNMP
                {"name": "LAB-NPB P3 (SPAN input)", "role": "broker_in", "device": "LAB-NPB", "port": "P3",
                 "speed_gbps": 0.1, "source": {**npb, "if_name": "P3"}}, out]
    return [{"name": "TAP on the client link", "role": "tap", "device": "LAB-TAP"},
            {"name": "LAB-NPB P1 (TAP A)", "role": "broker_in", "device": "LAB-NPB", "port": "P1", "speed_gbps": 0.1,
             "source": {**npb, "if_name": "P1"}},
            {"name": "LAB-NPB P2 (TAP B)", "role": "broker_in", "device": "LAB-NPB", "port": "P2", "speed_gbps": 0.1,
             "source": {**npb, "if_name": "P2"}}, out]


def counter_test(lab, t, seconds):
    from visikit.core.schema import FeedContext
    from visikit.counters import Hop, PathCounters
    from visikit.counters.snmp import SnmpSource
    from visikit.loop import check_all, remediate
    from visikit.profiles import load_profile
    p5 = t.get("p5_mbps", 150)
    path = [Hop(**h) for h in hops(t["path"], p5)]
    lab.configure(t)
    src = SnmpSource(path)
    before = src.snapshot()
    t0 = time.time()
    for p in lab.traffic(t.get("traffic") or ["mix"], seconds):
        p.wait()
    elapsed = time.time() - t0
    # Counters are served HORIZON seconds back on the wire clock; wait until every daemon has counted the whole test
    # (under heavy load the Python broker can be a few seconds behind)
    from lab.softlab.ports import HORIZON
    time.sleep(HORIZON + 5)
    after = src.snapshot()
    lab.configure({})
    pc = PathCounters(path, before, after, elapsed)
    profile = dataclasses.replace(load_profile("IDS", []), max_rate_gbps=p5 / 1000)
    ctx = FeedContext(t["id"], None, profile, counters=pc)
    findings = check_all(ctx)
    with tempfile.TemporaryDirectory() as work:
        fixes = remediate(ctx, findings, work)["fixes"] if findings else []
    found = {f.fault: f.location for f in findings}
    return {"test": t["id"], "path": t["path"], "expect": t["expect"], "found": found,
            "pass": found == t["expect"], "details": {f.fault: f.detail for f in findings},
            "fixes": [{"fault": x["fault"], "action": x["action"], "status": x["status"]} for x in fixes],
            "hops": {h.name: vars(pc.delta(h)) for h in path if pc.delta(h)}}


def monitor_test(lab, spec):
    results = os.path.join(HERE, "results")
    os.makedirs(results, exist_ok=True)
    db, log = os.path.join(results, "monitor.db"), os.path.join(results, "alerts.log")
    for f in (db, log):
        if os.path.exists(f):
            os.remove(f)
    path_file = os.path.join(STATE, "monitor_path.yaml")
    with open(path_file, "w") as f:
        yaml.safe_dump({"feed": "softlab-ids", "path": hops("span", 150)}, f, sort_keys=False)
    cfg = os.path.join(STATE, "monitor.yaml")
    with open(cfg, "w") as f:
        yaml.safe_dump({"interval_seconds": spec["interval_seconds"], "database": db,
                        "alerts": {"console": True, "log_file": log},
                        "feeds": [{"name": "softlab-ids", "tool": "IDS", "path": path_file, "snmp": True}]}, f)
    span = {"switch": {"span": {"sources": [["gi1", "both"]], "dest_rate_mbps": 40}}, "tool_rule": {"inputs": ["p3"]},
            "span_path_only": True}
    lab.configure(span)
    total = spec["phase_seconds"] * len(spec["phases"])
    cycles = int(total / spec["interval_seconds"]) + 1
    mon = subprocess.Popen([sys.executable, "-m", "visikit.monitor", "--config", cfg, "--cycles", str(cycles)],
                           env=lab.env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    timeline = []
    start = time.time()
    for ph in spec["phases"]:
        lab.configure({**span, "inputs": ph.get("inputs") or {}, "switch": ph.get("switch") or span["switch"]})
        timeline.append((round(time.time() - start), ph["name"]))
        print(f"    {timeline[-1][0]:>4} s  {ph['name']}", flush=True)
        for p in lab.traffic(ph.get("traffic") or ["mix"], spec["phase_seconds"]):
            p.wait()
    out, _ = mon.communicate(timeout=120)
    lab.configure({})
    alerts = [line for line in out.splitlines() if "DEGRADED" in line or "RECOVERED" in line]
    return {"timeline": timeline, "alerts": alerts, "cycles": cycles, "interval": spec["interval_seconds"]}


def report(cap_out, counters, monitor, partial=False):
    from lab.run_lab import write_md
    if partial and os.path.exists(os.path.join(HERE, "results.json")):
        # a run of some tests only: keep the earlier results of the counter and monitor tests it did not run
        with open(os.path.join(HERE, "results.json")) as f:
            old = json.load(f)
        ran = {r["test"] for r in counters}
        counters = [r for r in old.get("counters") or [] if r["test"] not in ran] + counters
        counters.sort(key=lambda r: r["test"])
        monitor = monitor or old.get("monitor")
    passed = sum(r["pass"] for r in cap_out)
    md = write_md(cap_out, os.path.join(HERE, "RESULTS.md"), "VisiLoop soft lab results: real packets, no equipment",
                  intro=("Each test set up one fault on purpose on the soft lab: a virtual switch, TAP and packet "
                         "broker on real Linux network interfaces, carrying real TCP, HTTP, HTTPS, DNS and iperf3 "
                         "traffic between a lab client and server. The tool port was recorded with dumpcap, as the "
                         "laptop would in the real lab (see `README.md` and `plan.yaml`)."))
    if counters:
        ok = sum(r["pass"] for r in counters)
        md += ["", "## Counter tests: real SNMP", "",
               f"**{ok}/{len(counters)}** located correctly. VisiLoop read the virtual switch and broker over SNMP v2c "
               "(IF-MIB) before and after the traffic, as it reads a Catalyst and an EXA.", "",
               "| Test | Path | Expected | VisiLoop found | Fix |", "|---|---|---|---|---|"]
        for r in counters:
            exp = ", ".join(f"{k} at {v}" for k, v in r["expect"].items()) or "healthy"
            got = ", ".join(f"{k} at {v}" for k, v in r["found"].items()) or "healthy"
            fx = ", ".join(f"{x['action']} ({x['status']})" for x in r["fixes"]) or "-"
            md.append(f"| {r['test']} | {r['path']} | {exp} | {'✅ ' if r['pass'] else '❌ '}{got} | {fx} |")
        md += [""] + [f"- **{r['test']}**: {d}" for r in counters for d in r["details"].values()]
    if monitor:
        md += ["", "## Continuous monitoring", "",
               f"VisiLoop's monitor polled the SPAN path over SNMP every {monitor['interval']} s while faults were "
               "switched on and off:", "", "| Time | Phase |", "|---|---|"]
        md += [f"| {s} s | {n} |" for s, n in monitor["timeline"]]
        md += ["", "Alerts it raised:", "", "```"] + [a.split("] ", 1)[-1] for a in monitor["alerts"]] + ["```"]
    with open(os.path.join(HERE, "RESULTS.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump({"generated": time.strftime("%Y-%m-%d %H:%M"), "captures": cap_out, "counters": counters,
                   "monitor": monitor}, f, indent=1)
    return passed


def main():
    ap = argparse.ArgumentParser(description="VisiLoop soft lab")
    ap.add_argument("--only", nargs="*", help="run only these test ids")
    ap.add_argument("--seconds", type=int, help="override each test's traffic time")
    ap.add_argument("--skip-counters", action="store_true")
    ap.add_argument("--skip-monitor", action="store_true")
    ap.add_argument("--monitor-only", action="store_true", help="run only the continuous-monitoring test")
    ap.add_argument("--agent", action="store_true", help="also ask Muse Spark (needs MODEL_API_KEY; about US$0.01 a test)")
    ap.add_argument("--down", action="store_true", help="remove the virtual lab and exit")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("The soft lab builds network namespaces: run it as root (sudo).")
    if a.down:
        net.down()
        return
    with open(os.path.join(HERE, "plan.yaml")) as f:
        plan = yaml.safe_load(f)
    d = plan["defaults"]
    tests = [{**d, **t} for t in plan["tests"] if (not a.only or t["id"] in a.only) and not a.monitor_only]
    ctests = [{**d, **t} for t in plan["counter_tests"]
              if not a.skip_counters and not a.monitor_only and (not a.only or t["id"] in a.only)]
    lab = Lab(plan)
    print("Building the soft lab...", flush=True)
    lab.up()
    try:
        mpath = os.path.join(CAPS, "manifest.json")
        manifest = {"tests": {}}
        if a.only and os.path.exists(mpath):
            with open(mpath) as f:
                manifest = json.load(f)
        for n, t in enumerate(tests, 1):
            print(f"[{n}/{len(tests)}] {t['id']}  expect {', '.join(t['expect']) or 'healthy'}", flush=True)
            manifest["tests"][t["id"]] = capture_test(lab, t, a.seconds or t["seconds"])
            m = manifest["tests"][t["id"]]
            print(f"    {m['packets']} packets recorded" + (f", lab fell behind by {m['lab_fell_behind']}"
                                                            if m["lab_fell_behind"] else ""), flush=True)
            write(mpath, manifest)
        counters = []
        for t in ctests:
            print(f"[counters] {t['id']}", flush=True)
            counters.append(counter_test(lab, t, a.seconds or t["seconds"]))
            r = counters[-1]
            print(f"    {'PASS' if r['pass'] else 'FAIL'}  found {r['found'] or 'healthy'}", flush=True)
        monitor = None
        if not a.skip_monitor and not a.only:
            print("[monitor] continuous mode while faults come and go", flush=True)
            monitor = monitor_test(lab, plan["monitor"])
            print("\n".join("    " + x for x in monitor["alerts"]), flush=True)
    finally:
        lab.down()
    if a.monitor_only:
        return
    print("\nRunning VisiLoop on the recordings...", flush=True)
    from lab.run_lab import evaluate
    cap_out = evaluate(CAPS, a.agent) if manifest["tests"] else []
    passed = report(cap_out, counters, monitor, partial=bool(a.only))
    print(f"\nCapture tests right: {passed}/{len(cap_out)}"
          + (f"; counter tests right: {sum(r['pass'] for r in counters)}/{len(counters)}" if counters else "")
          + f". Report: {os.path.join(HERE, 'RESULTS.md')}")


if __name__ == "__main__":
    main()
