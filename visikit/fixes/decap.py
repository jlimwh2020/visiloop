"""Strip tunnel headers (ERSPAN, GRE, VXLAN) on the broker before the tool port.

The simulation really decapsulates every packet, so the result is verified on the
traffic the tool would receive.
"""
import os

from scapy.all import GRE, Ether, PcapReader, PcapWriter
from scapy.layers.vxlan import VXLAN
from scapy.contrib.erspan import ERSPAN_II, ERSPAN_III

from visikit.core.registry import fix
from visikit.core.schema import Fix

TEB = 0x6558          # GRE carrying Ethernet frames


def inner_frame(pkt):
    """The original Ethernet frame inside a tunnelled packet, or the packet itself."""
    for layer in (VXLAN, ERSPAN_II, ERSPAN_III):
        if layer in pkt:
            return pkt[layer].payload
    if GRE in pkt and pkt[GRE].proto == TEB:
        return pkt[GRE].payload
    return None


def decapsulate(src, dst):
    w = PcapWriter(dst, sync=True, linktype=1)
    for pkt in PcapReader(src):
        inner = inner_frame(pkt)
        if inner is not None:
            new = Ether(bytes(inner))
            new.time = pkt.time
            pkt = new
        w.write(pkt)
    w.close()
    return dst


@fix
class StripTunnel:
    fault = "tunnel"
    action = "strip_tunnel"
    stage = 15            # after rebuilding the feed from broker ingress, before dedup and load balancing

    def config(self, ctx, finding):
        return Fix(self.fault, self.action,
                   params={"tunnelled_share": finding.metric, "tunnels": finding.detail.split("(")[-1].rstrip(")"),
                           "where": "broker ingress (tunnel termination) before the tool port"},
                   broker_config={"tool_port": ctx.feed, "tunnel_termination": {"strip": ["erspan", "gre", "vxlan"]}})

    def simulate(self, pcaps, ctx, fix, workdir):
        return [decapsulate(p, os.path.join(workdir, f"decap_{i}.pcap")) for i, p in enumerate(pcaps)]
