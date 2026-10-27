"""Packet drops: the capture is missing packets the endpoints clearly exchanged.

Signal: tshark flags ACKs for data never seen in the capture (ack_lost_segment)
and sequence gaps (lost_segment). On a monitoring feed these usually mean the
SPAN port, broker or tool dropped packets, not the network itself.
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding
from visikit.core.tools import fields

THRESHOLD = 0.01      # more than 1% of TCP packets flagged is a fault
FILTER = "tcp.analysis.ack_lost_segment or tcp.analysis.lost_segment"


@detector
class PacketDrops:
    fault = "packet_drops"

    def run(self, ctx: FeedContext) -> list[Finding]:
        tcp_total = len(fields(ctx.pcap, ["frame.number"], "tcp"))
        if tcp_total == 0:
            return []
        flagged = [int(r[0]) for r in fields(ctx.pcap, ["frame.number"], FILTER)]
        share = len(flagged) / tcp_total
        if share <= THRESHOLD:
            return []
        return [Finding(
            fault=self.fault, feed=ctx.feed,
            severity="high" if share > 0.03 else "medium",
            metric=round(share, 4), threshold=THRESHOLD,
            evidence=flagged[:20],
            detail=f"{len(flagged)} of {tcp_total} TCP packets show evidence of missing data ({share:.1%})",
        )]
