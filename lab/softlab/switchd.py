"""The soft lab's switch: a Linux bridge between client and server, plus the copies a real switch
and TAP would make, done here in software on real frames.

  TAP legs   every frame on the client link (gi1): client-to-server to tapa (TAP monitor A),
             server-to-client to tapb (monitor B). Always on, like a passive TAP.
  SPAN       copies of the chosen source ports and directions to gi24 (Gi1/0/24), which sends at
             its own line rate and discards when its buffer is full, like a real SPAN destination.
  ERSPAN     copies wrapped in IPv4 + GRE + ERSPAN type II headers, sent on te1 (Te1/1/1).

Configuration: <state>/switch.json, re-read when it changes:
    {"span":   {"sources": [["gi1", "both"]], "dest_rate_mbps": 40},     # or null
     "erspan": {"sources": [["gi1", "both"]], "id": 10}}                 # or null
Counters: served over SNMP v2c on the management address (Gi1/0/1, Gi1/0/2: the interfaces' own
frames seen on them; Gi1/0/24, Te1/1/1: frames sent and discarded by this switch), on the lab's wire clock
(ports.Port.count).

Run inside the switch namespace:
    python -m lab.softlab.switchd --state lab/softlab/state --mgmt 172.30.0.2
"""
import argparse
import os
import struct
import time

from lab.softlab.ports import STALLS, Config, Port, loop, write_json
from lab.softlab.snmp_agent import serve

INDEX = {"gi1": (1, "Gi1/0/1", 100), "gi2": (2, "Gi1/0/2", 100), "gi24": (24, "Gi1/0/24", None),
         "te1": (25, "Te1/1/1", 1000)}
ERSPAN_SRC, ERSPAN_DST = bytes([192, 168, 250, 1]), bytes([192, 168, 250, 2])


def checksum(header):
    s = sum(struct.unpack("!10H", header))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


class Erspan:
    def __init__(self, session_id):
        self.session_id, self.seq, self.ip_id = session_id, 0, 0

    def wrap(self, frame):
        """Type II ERSPAN: Ethernet / IPv4 (protocol 47) / GRE (sequence, 0x88BE) / ERSPAN / original frame."""
        self.seq, self.ip_id = (self.seq + 1) & 0xFFFFFFFF, (self.ip_id + 1) & 0xFFFF
        erspan = struct.pack("!HHI", (1 << 12), (3 << 11) | (self.session_id & 0x3FF), 0)
        gre = struct.pack("!HHI", 0x1000, 0x88BE, self.seq)
        total = 20 + len(gre) + len(erspan) + len(frame)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, self.ip_id, 0x4000, 64, 47, 0, ERSPAN_SRC, ERSPAN_DST)
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        eth = bytes.fromhex("02000000fe02") + bytes.fromhex("02000000fe01") + b"\x08\x00"
        return eth + ip + gre + erspan + frame


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--mgmt", default="172.30.0.2")
    ap.add_argument("--community", default="visiloop-ro")
    a = ap.parse_args()
    cfg = Config(os.path.join(a.state, "switch.json"))
    gi1 = Port("gi1", "Gi1/0/1", 1, 100, rx=True)
    gi2 = Port("gi2", "Gi1/0/2", 2, 100, rx=True)
    # Passive TAP legs: no rate of their own. Each frame keeps its arrival timing on the link (pacing a leg
    # would delay a data frame behind the previous one while its ACK, on the other leg, overtook it)
    tapa = Port("tapa", "TAP A", 0, 100, stamp=True)
    tapb = Port("tapb", "TAP B", 0, 100, stamp=True)
    gi24 = Port("gi24", "Gi1/0/24", 24, 40, rate_mbps=40, buffer_bytes=256 * 1024, stamp=True)   # ~50 ms at 40 Mbit/s
    te1 = Port("te1", "Te1/1/1", 25, 1000, rate_mbps=1000, stamp=True)
    state = {"span": None, "erspan": None, "wrap": None, "tap": True}

    def directions(sources, port):
        for p, d in sources:
            if p == port:
                return d
        return None

    other = {gi1: gi2, gi2: gi1}

    def on_frame(port, frame, outgoing, ts, wire):
        # Only frames arriving at a port are used. With two ports, what the bridge sends out of one is exactly
        # what arrived at the other, and arrival times are exact: Linux stamps a received frame as it arrives,
        # but stamps an outgoing one only when the bridge forwards it, in batches when the machine is busy.
        if outgoing:
            return
        out_port = other[port]
        port.count("in_pkts", 1, ts)
        port.count("in_octets", len(frame), ts)
        out_port.count("out_pkts", 1, ts)
        out_port.count("out_octets", len(frame), ts)
        # passive TAP on the client link: A = into the switch from the client, B = from the switch to the client
        if state["tap"]:
            (tapa if port is gi1 else tapb).enqueue(frame, ts)
        for key, out in (("span", gi24), ("erspan", te1)):
            sess = state[key]
            if not sess:
                continue
            # rx = what the switch received on a source port, tx = what it sent out of it
            if directions(sess["sources"], port.iface) in ("rx", "both") or \
                    directions(sess["sources"], out_port.iface) in ("tx", "both"):
                out.enqueue(state["wrap"].wrap(frame) if key == "erspan" else frame, ts)

    def housekeeping():
        for p in (gi1, gi2, tapa, tapb, gi24, te1):
            p.counters()                                 # file the counts that have passed the horizon
        if cfg.changed():
            state["span"] = cfg.data.get("span")
            state["erspan"] = cfg.data.get("erspan")
            state["tap"] = cfg.data.get("tap", True)
            if state["span"]:
                gi24.rate_mbps = gi24.speed_mbps = state["span"].get("dest_rate_mbps", 40)
            state["wrap"] = Erspan(state["erspan"].get("id", 10)) if state["erspan"] else None
        write_json(os.path.join(a.state, "switch_health.json"),
                   {"fell_behind": gi1.kernel_drops() + gi2.kernel_drops(),
                    "stalls_ms": dict(STALLS), "late": sum(p.late for p in (tapa, tapb, gi24, te1))})

    def rows():
        now = time.time()                                 # one moment for every port in this answer
        return {p.index: {"name": p.name, "speed_mbps": p.speed_mbps, **p.counters(now)} for p in (gi1, gi2, gi24, te1)}

    housekeeping()
    serve(a.mgmt, 161, a.community, rows)
    loop([gi1, gi2], [tapa, tapb, gi24, te1], on_frame, housekeeping)


if __name__ == "__main__":
    main()
