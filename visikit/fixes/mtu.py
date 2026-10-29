"""Oversize frames: make frames fit the tool, tool-aware.

- A tool that does not need the payload (SIEM, APM): the broker trims frames to the tool's
  maximum frame size ("slice"). Verified in the simulation.
- A tool that needs the full payload (IDS, NDR): trimming would cut what it inspects, so the
  fix is to raise the MTU on the broker egress and the tool. That needs a change on the tool,
  so it cannot be verified offline and is reported as advice.
"""
import os

from scapy.all import Ether, PcapReader, PcapWriter

from visikit.core.registry import fix
from visikit.core.schema import Fix


@fix
class OversizeFix:
    fault = "oversize"
    action = "mtu_advice"
    stage = 25            # trim before load balancing (30), like a broker egress pipeline

    def config(self, ctx, finding):
        limit = ctx.profile.max_frame_bytes
        if not ctx.profile.needs_full_payload:
            return Fix(self.fault, "slice",
                       params={"oversize_share": finding.metric, "slice_to_bytes": limit,
                               "why": f"this {ctx.profile.tool_type} does not need the payload",
                               "alternative": "set MTU 9216 on the broker egress port and the tool"},
                       broker_config={"tool_port": ctx.feed, "packet_slicing": {"enabled": True, "length": limit}})
        return Fix(self.fault, "mtu_advice",
                   params={"oversize_share": finding.metric, "tool_max_frame_bytes": limit,
                           "recommended": "set MTU 9216 on the broker egress port and the tool's capture interface",
                           "alternative": "move jumbo traffic to a tool port that accepts jumbo frames"},
                   broker_config={"tool_port": ctx.feed, "mtu": 9216})

    def simulate(self, pcaps, ctx, fix, workdir):
        if fix.action != "slice":
            return None
        limit = fix.params["slice_to_bytes"]
        out = []
        for i, src in enumerate(pcaps):
            dst = os.path.join(workdir, f"slice_fit_{i}.pcap")
            w = PcapWriter(dst, sync=True, linktype=1)
            for pkt in PcapReader(src):
                raw = bytes(pkt)
                if len(raw) > limit:
                    new = Ether(raw[:limit])
                    new.time = pkt.time
                    pkt = new
                w.write(pkt)
            w.close()
            out.append(dst)
        return out
