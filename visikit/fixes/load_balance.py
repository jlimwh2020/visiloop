"""Spread the feed across several tool ports with symmetric flow hashing.

The number of ports is calculated: start from the measured 1 ms peak divided by
70% of the port speed, then add ports until every port's own peak is under the
overload threshold. Symmetric hashing keeps both directions of a flow together.
"""
import math
import os
import zlib

from scapy.all import IP, IPv6, TCP, UDP, PcapReader, PcapWriter

from visikit.core.registry import fix
from visikit.core.schema import Fix
from visikit.detectors.tool_overload import THRESHOLD, peak_gbps

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
        per_port = []
        if workdir:
            while n <= MAX_PORTS:
                parts = split(ctx.ingress or ctx.pcap, n, workdir, tag=f"size{n}")
                per_port = [round(peak_gbps(p), 3) for p in parts]
                if max(per_port) / speed <= THRESHOLD:
                    break
                n += 1
        return Fix(self.fault, self.action,
                   params={"ports": n, "port_speed_gbps": speed, "measured_peak_gbps": round(peak, 3),
                           "target_utilization": TARGET, "per_port_peak_gbps": per_port,
                           "hash": "symmetric_5tuple",
                           "alternative": f"one {math.ceil(peak / TARGET / 10) * 10:g} Gbps tool port"},
                   broker_config={"tool_group": {"name": f"{ctx.feed}-group", "ports": n,
                                                 "hash": "symmetric_5tuple"}})

    def simulate(self, pcaps, ctx, fix, workdir):
        out = []
        for i, p in enumerate(pcaps):
            out += split(p, fix.params["ports"], workdir, tag=f"lb{i}")
        return out
