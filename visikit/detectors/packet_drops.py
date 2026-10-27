"""Packet drops: ACKs for data never seen in the capture (tshark tcp.analysis.ack_lost_segment / lost_segment).

Day 2: implement run().
"""
from visikit.core.registry import detector
from visikit.core.schema import FeedContext, Finding


@detector
class PacketDrops:
    fault = "packet_drops"

    def run(self, ctx: FeedContext) -> list[Finding]:
        raise NotImplementedError
