"""Continuous mode: check every feed on a schedule, keep history, alert when a feed degrades.

Each cycle, for every feed in the config:
  1. read the interface counters along its path (SNMP, or a simulated scenario) and run the
     counter checks over the interval since the last reading;
  2. every N cycles, optionally record a short capture from the tool port and run the
     capture checks;
  3. compare with the previous cycle: a new fault raises DEGRADED, a cleared one RECOVERED;
  4. store everything in SQLite, for the dashboard's Monitor page.

Usage (from the repo root):
    python -m visikit.monitor --config demo/monitor.yaml --fast        # replay a simulated day in seconds
    python -m visikit.monitor --config my_monitor.yaml                 # real devices, runs until stopped

Config (YAML):
    interval_seconds: 60
    database: monitor.db
    alerts: {console: true, log_file: monitor_alerts.log, webhook: "https://...", webhook_format: teams}
    explain: false                    # true: add a Muse Spark explanation to DEGRADED alerts (needs MODEL_API_KEY)
    feeds:
      - name: ids-1
        tool: IDS
        vlans: [10, 20]
        path: demo/counters/path.yaml     # hops; with snmp: true, each hop's SNMP details
        snmp: false                       # false: simulate the path file's scenario
        capture: {iface: 5, seconds: 10, every: 10}   # optional
"""
import argparse
import json
import os
import sqlite3
import subprocess
import tempfile
import time
import urllib.request

import yaml

from visikit.core.schema import FeedContext
from visikit.counters import Hop, PathCounters
from visikit.loop import check_all
from visikit.profiles import load_profile

SCHEMA = """
CREATE TABLE IF NOT EXISTS cycles (ts REAL, feed TEXT, healthy INTEGER, faults TEXT, offered_gbps REAL,
                                   delivered_gbps REAL, source TEXT);
CREATE TABLE IF NOT EXISTS findings (ts REAL, feed TEXT, fault TEXT, metric REAL, severity TEXT, location TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS alerts (ts REAL, feed TEXT, kind TEXT, fault TEXT, message TEXT);
"""


class Feed:
    def __init__(self, spec, base_dir):
        self.spec = spec
        self.name = spec["name"]
        self.profile = load_profile(spec.get("tool", "IDS"), spec.get("vlans") or [])
        self.source = None
        self.last = None              # (time, snapshot)
        self.active = {}              # fault -> finding
        self.cycle = 0
        if spec.get("path"):
            path = os.path.join(base_dir, spec["path"]) if not os.path.isabs(spec["path"]) else spec["path"]
            if spec.get("snmp"):
                from visikit.counters.snmp import SnmpSource
                with open(path) as f:
                    self.source = SnmpSource([Hop(**h) for h in yaml.safe_load(f)["path"]])
            else:
                from visikit.counters.simulator import Simulator
                self.source = Simulator(path)

    def read_counters(self, interval, fast):
        """Counter readings since the last cycle (None on the first cycle)."""
        if self.source is None:
            return None
        if fast and hasattr(self.source, "advance"):
            if self.last is None:
                self.last = (self.source.t, self.source.snapshot())
                return None
            self.source.advance(interval)
            now = (self.source.t, self.source.snapshot())
        else:
            now = (time.time(), self.source.snapshot())
            if self.last is None:
                self.last = now
                return None
        pc = PathCounters(self.source.hops, self.last[1], now[1], now[0] - self.last[0])
        self.last = now
        return pc

    def capture(self, workdir):
        cap = self.spec.get("capture")
        if not cap or self.cycle % int(cap.get("every", 10)):
            return None
        from visikit.core.tools import find_tool
        path = os.path.join(workdir, f"{self.name}_{int(time.time())}.pcap")
        subprocess.run([find_tool("dumpcap"), "-i", str(cap["iface"]), "-a", f"duration:{cap.get('seconds', 10)}",
                        "-P", "-q", "-w", path], capture_output=True)
        return path if os.path.exists(path) else None


class Alerter:
    def __init__(self, cfg):
        self.cfg = cfg or {"console": True}

    def send(self, feed, kind, fault, message, ts=None):
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts or time.time()))}] {kind} {feed}: {message}"
        if self.cfg.get("console", True):
            print(line, flush=True)
        if self.cfg.get("log_file"):
            with open(self.cfg["log_file"], "a") as f:
                f.write(line + "\n")
        if self.cfg.get("webhook"):
            text = f"**VisiLoop {kind}** {feed}: {message}"
            body = {"text": text} if self.cfg.get("webhook_format", "generic") in ("teams", "slack") else \
                {"source": "visiloop", "kind": kind, "feed": feed, "fault": fault, "message": message}
            try:
                req = urllib.request.Request(self.cfg["webhook"], data=json.dumps(body).encode(),
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=10).read()
            except Exception as e:           # an alert channel failing must not stop monitoring
                print(f"  (webhook failed: {e})", flush=True)


def traffic(pc):
    """(Gbps that should reach the tool, Gbps that did): mirrored at the source vs. received at the last hop."""
    offered = delivered = 0.0
    for h in pc.hops:
        d = pc.delta(h)
        if d is None:
            continue
        if h.role == "span_source":
            offered = pc.gbps({"rx": d.in_octets, "tx": d.out_octets}.get(h.mirrors, d.in_octets + d.out_octets))
        elif h.role in ("broker_in", "tool_in"):
            delivered = pc.gbps(d.in_octets)
            offered = offered or delivered
        elif h.role in ("span_dest", "broker_out"):
            delivered = pc.gbps(d.out_octets)
            offered = offered or pc.gbps(d.out_octets + 0)
    return round(offered, 3), round(delivered, 3)


def explain(ctx):
    """One-line Muse Spark explanation for an alert, if a key is available."""
    if not os.environ.get("MODEL_API_KEY"):
        return ""
    try:
        from visikit.agent.diagnose import diagnose
        return diagnose(ctx).get("summary", "")
    except Exception as e:
        return f"(Muse Spark unavailable: {e})"


def run(config_path, cycles=None, fast=False, database=None):
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    base = os.path.dirname(os.path.abspath(config_path))
    root = os.path.dirname(base) if os.path.basename(base) == "demo" else base
    feeds = [Feed(s, root) for s in cfg["feeds"]]
    interval = float(cfg.get("interval_seconds", 60))
    db = sqlite3.connect(database or cfg.get("database", "monitor.db"))
    db.executescript(SCHEMA)
    alerter = Alerter(cfg.get("alerts"))
    workdir = tempfile.mkdtemp(prefix="visiloop_monitor_")
    clock = time.time() if not fast else cfg.get("start_epoch", 1793232000)   # fast mode: a simulated day
    n = 0
    print(f"Monitoring {len(feeds)} feed(s) every {interval:g} s" + (" (fast replay)" if fast else ""), flush=True)
    while cycles is None or n < cycles:
        for feed in feeds:
            pc = feed.read_counters(interval, fast)
            pcap = None if fast else feed.capture(workdir)
            feed.cycle += 1
            if pc is None and pcap is None:
                continue
            ctx = FeedContext(feed.name, pcap, feed.profile, counters=pc)
            findings = check_all(ctx)
            now = {f.fault: f for f in findings}
            ts = clock if fast else time.time()
            offered, delivered = traffic(pc) if pc else (0, 0)
            db.execute("INSERT INTO cycles VALUES (?,?,?,?,?,?,?)", (ts, feed.name, int(not findings),
                       ",".join(sorted(now)), offered, delivered, "counters" + ("+capture" if pcap else "")))
            for f in findings:
                db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?)",
                           (ts, feed.name, f.fault, f.metric, f.severity, f.location, f.detail))
            for fault in sorted(set(now) - set(feed.active)):
                f = now[fault]
                msg = f"{fault} at {f.location or 'the tool port'} ({f.metric:.2%}): {f.detail}"
                if cfg.get("explain"):
                    note = explain(ctx)
                    msg += f" | Muse Spark: {note}" if note else ""
                alerter.send(feed.name, "DEGRADED", fault, msg, ts)
                db.execute("INSERT INTO alerts VALUES (?,?,?,?,?)", (ts, feed.name, "DEGRADED", fault, msg))
            for fault in sorted(set(feed.active) - set(now)):
                msg = f"{fault} cleared; {'feed healthy' if not now else 'still open: ' + ', '.join(sorted(now))}"
                alerter.send(feed.name, "RECOVERED", fault, msg, ts)
                db.execute("INSERT INTO alerts VALUES (?,?,?,?,?)", (ts, feed.name, "RECOVERED", fault, msg))
            feed.active = now
            if pcap:
                os.remove(pcap)                          # captures are not kept
        db.commit()
        n += 1
        if fast:
            clock += interval
        elif cycles is None or n < cycles:
            time.sleep(interval)
    db.close()


def main():
    ap = argparse.ArgumentParser(description="VisiLoop continuous monitoring")
    ap.add_argument("--config", required=True)
    ap.add_argument("--cycles", type=int, help="stop after this many cycles (default: run until stopped)")
    ap.add_argument("--fast", action="store_true", help="replay simulated feeds without waiting (demo and testing)")
    ap.add_argument("--database", help="override the config's database file")
    a = ap.parse_args()
    run(a.config, a.cycles, a.fast, a.database)


if __name__ == "__main__":
    main()
