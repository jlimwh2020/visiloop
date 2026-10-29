"""Spread the feed across several tool ports with symmetric flow hashing.

The number of ports is calculated: start from the measured 1 ms peak divided by
70% of the port speed, then add ports until every port's own peak is under the
overload threshold. Symmetric hashing keeps both directions of a flow together.

Sizing reads the capture once (each packet's time, length and flow) and works out every
group size from that, so it stays fast on large captures. A flow hashing keeps on one port,
so when a single flow on its own bursts above the threshold, no number of ports can fix it:
the fix says so and recommends a faster tool port instead.
"""
from collections import defaultdict
import math
import os
import zlib

from scapy.all import IP, IPv6, TCP, UDP, PcapReader, PcapWriter

from visikit.core.registry import fix
from visikit.core.schema import Fix
from visikit.core.tools import fields
from visikit.detectors.tool_overload import INTERVAL, THRESHOLD, peak_gbps

TARGET = 0.7
MAX_PORTS = 32


def _innermost_ip(pkt):
    """The innermost IP header, so tunnelled traffic is spread by its real flows."""
    ip, layer = None, pkt
    while layer is not None and layer.__class__.__name__ != "NoPayload":
        if isinstance(layer, (IP, IPv6)):
            ip = layer
        layer = layer.payload
    return ip


def _port_of(pkt, n):
    ip = _innermost_ip(pkt)
    if ip is None:
        return 0
    l4 = ip[TCP] if TCP in ip else ip[UDP] if UDP in ip else None
    sp, dp = (l4.sport, l4.dport) if l4 else (0, 0)
    a, b = sorted([(ip.src, sp), (ip.dst, dp)])
    return zlib.crc32(f"{a}{b}{getattr(ip, 'proto', getattr(ip, 'nh', 0))}".encode()) % n


def _flow_key(src, dst, sport, dport, proto):
    """The same symmetric flow key as _port_of, from tshark fields."""
    a, b = sorted([(src, sport), (dst, dport)])
    return zlib.crc32(f"{a}{b}{proto}".encode())


def flow_bins(pcap):
    """Bytes per 1 ms interval for each flow: {flow key: {interval: bytes}} (non-IP traffic under key None)."""
    names = ["frame.time_relative", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport",
             "tcp.dstport", "udp.srcport", "udp.dstport", "ip.proto", "ipv6.nxt"]
    flows = defaultdict(lambda: defaultdict(int))
    for r in fields(pcap, names, occurrence="l"):
        r += [""] * (len(names) - len(r))
        t, length, s4, d4, s6, d6, ts, td, us, ud, p4, p6 = r
        src, dst = s4 or s6, d4 or d6
        if not src:
            key = None
        else:
            sport, dport = (int(ts), int(td)) if ts else (int(us), int(ud)) if us else (0, 0)
            key = _flow_key(src, dst, sport, dport, int(p4 or p6 or 0))
        flows[key][int(float(t) / INTERVAL)] += int(length)
    return flows


def peaks_for(flows, n):
    """Each port's 1 ms peak (Gbps) when the flows are hashed over n ports."""
    ports = [defaultdict(int) for _ in range(n)]
    for key, bins in flows.items():
        port = ports[0 if key is None else key % n]
        for b, v in bins.items():
            port[b] += v
    return [round(max(p.values()) * 8 / INTERVAL / 1e9, 3) if p else 0.0 for p in ports]


def split(pcap, n, workdir, tag="lb"):
    paths = [os.path.join(workdir, f"{tag}_port{i + 1}.pcap") for i in range(n)]
    writers = [PcapWriter(p, sync=True) for p in paths]
    for pkt in PcapReader(pcap):
        writers[_port_of(pkt, n)].write(pkt)
    for w in writers:
        w.close()
    return paths


@fix
class LoadBalance:
    fault = "tool_overload"
    action = "load_balance"
    stage = 30

    def config(self, ctx, finding, workdir=None):
        speed = ctx.profile.max_rate_gbps
        peak = peak_gbps(ctx.ingress or ctx.pcap)
        n = max(2, math.ceil(peak / (TARGET * speed)))
        per_port, flow_peak = [], 0.0
        if workdir:
            flows = flow_bins(ctx.ingress or ctx.pcap)
            flow_peak = max((max(b.values()) for k, b in flows.items() if k is not None and b), default=0)
            flow_peak = flow_peak * 8 / INTERVAL / 1e9
            if flow_peak / speed > THRESHOLD:
                n = 2                     # hashing cannot split one flow: no group size helps
                per_port = peaks_for(flows, n)
            else:
                while n <= MAX_PORTS:
                    per_port = peaks_for(flows, n)
                    if max(per_port) / speed <= THRESHOLD:
                        break
                    n += 1
                # Confirm on the real split, as the simulation will measure it (each port's own capture);
                # at the margin the two can differ by a port
                while n <= MAX_PORTS:
                    parts = split(ctx.ingress or ctx.pcap, n, workdir, tag=f"size{n}")
                    per_port = [round(peak_gbps(p), 3) for p in parts]
                    if max(per_port) / speed <= THRESHOLD:
                        break
                    n += 1
        faster = math.ceil(peak / TARGET / 10) * 10 if peak > 1 else round(peak / TARGET, 2)
        params = {"ports": n, "port_speed_gbps": speed, "measured_peak_gbps": round(peak, 3),
                  "target_utilization": TARGET, "per_port_peak_gbps": per_port, "hash": "symmetric_5tuple",
                  "alternative": f"one {faster:g} Gbps tool port"}
        if flow_peak / speed > THRESHOLD:
            params["single_flow_peak_gbps"] = round(flow_peak, 3)
            params["note"] = (f"One flow alone bursts to {flow_peak:.3f} Gbps, {flow_peak / speed:.0%} of a "
                              f"{speed:g} Gbps port. Flow hashing keeps a flow on one port, so load balancing "
                              f"cannot fix this: use a faster tool port ({params['alternative']}).")
        return Fix(self.fault, self.action,
                   params=params,
                   broker_config={"tool_group": {"name": f"{ctx.feed}-group", "ports": n,
                                                 "hash": "symmetric_5tuple"}})

    def simulate(self, pcaps, ctx, fix, workdir):
        out = []
        for i, p in enumerate(pcaps):
            out += split(p, fix.params["ports"], workdir, tag=f"lb{i}")
        return out
